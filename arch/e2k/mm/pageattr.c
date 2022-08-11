#include <linux/memblock.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <asm/l-iommu.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

static void modify_pte_page(pte_t *ptep, enum sma_mode mode)
{
	pte_t new;

	switch (mode) {
	case SMA_RO:
		new = pte_wrprotect(*ptep);
		break;
	case SMA_RW:
		new = pte_mkwrite(*ptep);
		break;
	case SMA_NX:
		new = pte_mknotexec(*ptep);
		break;
	case SMA_X:
		new = pte_mkexec(*ptep);
		break;
	case SMA_P:
		new = pte_mk_present_valid(*ptep);
		break;
	case SMA_NP:
		new = pte_mknot_present_valid(*ptep);
		break;
	case SMA_WB_MT:
		new = pte_mk_wb(*ptep);
		break;
	case SMA_WC_MT:
		new = pte_mk_wc(*ptep);
		break;
	case SMA_UC_MT:
		new = pte_mk_uc(*ptep);
		break;
	default:
		BUG();
	};

	native_set_pte(ptep, new, false);
}

static int pte_modified(pte_t pte, enum sma_mode mode)
{
	switch (mode) {
	case SMA_RO:
		return !pte_write(pte);
	case SMA_RW:
		return pte_write(pte);
	case SMA_NX:
		return !pte_exec(pte);
	case SMA_X:
		return pte_exec(pte);
	case SMA_P:
		return pte_present(pte);
	case SMA_NP:
		return !pte_present(pte);
	case SMA_WB_MT:
		return pte_wb(pte);
	case SMA_WC_MT:
		return pte_wc(pte);
	case SMA_UC_MT:
		return pte_uc(pte);
	default:
		BUG();
	};

	return -EINVAL;
}

static int walk_pte_level(pmd_t *pmd, unsigned long addr, unsigned long end,
			  enum sma_mode mode, int *need_flush)
{
	pte_t *ptep;

	ptep = pte_offset_kernel(pmd, addr);
	do {
		if (pte_none(*ptep))
			return -EINVAL;
		if (!pte_modified(*ptep, mode)) {
			*need_flush = 1;
			modify_pte_page(ptep, mode);
		}
		ptep++;
		addr += PAGE_SIZE;
	} while (addr < end);

	return 0;
}

static __ref void *sma_alloc_page(int node)
{
	void *addr = NULL;

	if (slab_is_available()) {
		struct page *page = alloc_pages_node(node,
				GFP_KERNEL|__GFP_NOWARN, 0);
		if (page)
			addr = page_address(page);
	} else {
		addr = memblock_alloc_node(PAGE_SIZE, PAGE_SIZE, node);
	}

	return addr;
}

static __ref void sma_free_page(int node, void *addr)
{
	if (slab_is_available())
		free_page((unsigned long) addr);
	else
		memblock_free(__pa(addr), PAGE_SIZE);
}

DEFINE_RAW_SPINLOCK(sma_lock);

static void
map_pmd_huge_page_to_ptes(pte_t *pte_page, e2k_addr_t phys_page,
				pgprot_t pgprot)
{
	int i;

	for (i = 0; i < PTRS_PER_PTE; i++) {
		pte_page[i] = mk_pte_phys(phys_page, pgprot);
		phys_page += PTE_SIZE;
	}
}

static void
split_one_pmd_page(pmd_t *pmdp, e2k_addr_t phys_page, pte_t *pte_page)
{
	pgprot_t pgprot;
	pmd_t new;

	BUG_ON(pte_page == NULL);
	pgprot_val(pgprot) = _PAGE_CLEAR(pmd_val(*pmdp),
						UNI_PAGE_HUGE | UNI_PAGE_PFN);
	map_pmd_huge_page_to_ptes(pte_page, phys_page, pgprot);
	smp_wmb(); /* make pte visible before page table entry */
	new = mk_pmd_phys(__pa(pte_page), PAGE_KERNEL_PTE);
	native_set_pmd(pmdp, new);
}
void split_simple_pmd_page(pgprot_t *ptp, pte_t *ptes[MAX_NUM_HUGE_PTES])
{
	const pt_level_t *pmd_level = get_pt_level_on_id(E2K_PMD_LEVEL_NUM);
	pte_t *ptep;
	pte_t *pte_page;
	e2k_addr_t phys_page;

	if (pmd_level->get_huge_pte != NULL) {
		ptep = pmd_level->get_huge_pte(0, ptp);
	} else {
		ptep = (pte_t *)ptp;
	}
	phys_page = pte_pfn(*ptep) << PAGE_SHIFT;
	pte_page = *ptes;
	split_one_pmd_page((pmd_t *)ptep, phys_page, pte_page);
}
void split_multiple_pmd_page(pgprot_t *ptp, pte_t *ptes[MAX_NUM_HUGE_PTES])
{
	const pt_level_t *pmd_level = get_pt_level_on_id(E2K_PMD_LEVEL_NUM);
	pte_t *ptep;
	pte_t *pte_page;
	e2k_addr_t phys_page;
	int ptes_num;
	int no;

	ptes_num = get_pt_level_huge_ptes_num(pmd_level);
	if (pmd_level->get_huge_pte != NULL) {
		ptep = pmd_level->get_huge_pte(0, ptp);
	} else {
		/* first pte is always multiple ptes size */
		ptep = (pte_t *)(((e2k_addr_t)ptp) &
					~((sizeof(*ptp) * ptes_num) - 1));
	}
	phys_page = pte_pfn(*ptep) << PAGE_SHIFT;
	for (no = 0; no < ptes_num; no++) {
		pte_page = ptes[no];
		split_one_pmd_page((pmd_t *)ptep, phys_page, pte_page);
		/* next page table entry */
		ptep++;
		phys_page += PMD_SIZE;
	}
}

static inline void
free_pmd_huge_ptes_pages(int node, pte_t *ptes[MAX_NUM_HUGE_PTES], int ptes_num)
{
	int no;

	for (no = 0; no < ptes_num; no++) {
		sma_free_page(node, ptes[no]);
		ptes[no] = NULL;
	}
}
static inline int
alloc_pmd_huge_ptes_pages(int node, pte_t *ptes[MAX_NUM_HUGE_PTES])
{
	int ptes_num;
	int no;

	ptes_num = get_e2k_pt_level_huge_ptes_num(E2K_PMD_LEVEL_NUM);
	BUG_ON(ptes_num > MAX_NUM_HUGE_PTES);
	for (no = 0; no < ptes_num; no++) {
		pte_t *ptep;

		ptep = sma_alloc_page(node);
		if (unlikely(ptep == NULL))
			break;
		ptes[no] = ptep;
	}
	if (likely(no >= ptes_num))
		return ptes_num;

	free_pmd_huge_ptes_pages(node, ptes, no);
	return -ENOMEM;
}

/* FIXME; split is not fully implemented for guest kernel */
/* Guest kernel should register spliting on host */
static int split_pmd_page(int node, pmd_t *pmdp)
{
	pte_t *ptes[MAX_NUM_HUGE_PTES];
	const pt_level_t *pmd_level = get_pt_level_on_id(E2K_PMD_LEVEL_NUM);
	int ptes_num;
	bool was_updated = false;

	ptes_num = alloc_pmd_huge_ptes_pages(node, ptes);
	if (unlikely(ptes_num < 0))
		return ptes_num;

	/* Re-read `*pmdp' again under spinlock */
	raw_spin_lock(&sma_lock);
	if (!kernel_pmd_huge(*pmdp)) {
		was_updated = true;
	} else {

		if (pmd_level->split_pt_page != NULL) {
			pmd_level->split_pt_page((pgprot_t *)pmdp, ptes);
		} else {
			split_simple_pmd_page((pgprot_t *)pmdp, ptes);
		}
	}
	raw_spin_unlock(&sma_lock);

	if (was_updated)
		free_pmd_huge_ptes_pages(node, ptes, ptes_num);

	return 0;
}

static void modify_pmd_page(pmd_t *pmdp, enum sma_mode mode)
{
	pmd_t new;

	switch (mode) {
	case SMA_RO:
		new = pmd_wrprotect(*pmdp);
		break;
	case SMA_RW:
		new = pmd_mkwrite(*pmdp);
		break;
	case SMA_NX:
		new = pmd_mknotexec(*pmdp);
		break;
	case SMA_X:
		new = pmd_mkexec(*pmdp);
		break;
	case SMA_P:
		new = pmd_mk_present_valid(*pmdp);
		break;
	case SMA_NP:
		new = pmd_mknot_present_valid(*pmdp);
		break;
	case SMA_WB_MT:
		new = pmd_mk_wb(*pmdp);
		break;
	case SMA_WC_MT:
		new = pmd_mk_wc(*pmdp);
		break;
	case SMA_UC_MT:
		new = pmd_mk_uc(*pmdp);
		break;
	default:
		BUG();
	};

	native_set_pmd(pmdp, new);
}

static int pmd_modified(pmd_t pmd, enum sma_mode mode)
{
	switch (mode) {
	case SMA_RO:
		return !pmd_write(pmd);
	case SMA_RW:
		return pmd_write(pmd);
	case SMA_NX:
		return !pmd_exec(pmd);
	case SMA_X:
		return pmd_exec(pmd);
	case SMA_P:
		return pmd_present(pmd);
	case SMA_NP:
		return !pmd_present(pmd);
	case SMA_WB_MT:
		return pmd_wb(pmd);
	case SMA_WC_MT:
		return pmd_wc(pmd);
	case SMA_UC_MT:
		return pmd_uc(pmd);
	default:
		BUG();
	};

	return -EINVAL;
}

static int walk_pmd_level(int node, pud_t *pud, unsigned long addr,
			unsigned long end, enum sma_mode mode, int *need_flush)
{
	unsigned long next;
	pmd_t *pmdp;
	e2k_size_t page_size;
	int ret = 0;

	pmdp = pmd_offset(pud, addr);
	do {
		if (pmd_none(*pmdp))
			return -EINVAL;
		next = pmd_addr_end(addr, end);
		if (!kernel_pmd_huge(*pmdp)) {
			ret = walk_pte_level(pmdp, addr, next, mode,
					     need_flush);
		} else if (!pmd_modified(*pmdp, mode)) {
			page_size = get_pmd_level_page_size();
			if (addr & (page_size - 1) ||
					addr + page_size > next) {
				ret = split_pmd_page(node, pmdp);
				continue;
			}
			*need_flush = 1;
			modify_pmd_page(pmdp, mode);
		}
		++pmdp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

void map_pud_huge_page_to_simple_pmds(pgprot_t *pmd_page, e2k_addr_t phys_page,
					pgprot_t pgprot)
{
	int i;

	for (i = 0; i < PTRS_PER_PMD; i++) {
		((pmd_t *)pmd_page)[i] = mk_pmd_phys(phys_page, pgprot);
		phys_page += PMD_SIZE;
	}
}
void map_pud_huge_page_to_multiple_pmds(pgprot_t *pmd_page,
			e2k_addr_t phys_page, pgprot_t pgprot)
{
	int ptes_num = get_e2k_pt_level_huge_ptes_num(E2K_PMD_LEVEL_NUM);
	pmd_t pmd;
	int i, no;

	for (i = 0; i < PTRS_PER_PMD; i += ptes_num) {
		pmd = mk_pmd_phys(phys_page, pgprot);
		for (no = 0; no < ptes_num; no++) {
			((pmd_t *)pmd_page)[i + no] = pmd;
		}
		phys_page += (PMD_SIZE * ptes_num);
	}
}
static void
split_one_pud_page(pud_t *pudp, pmd_t *pmd_page)
{
	const pt_level_t *pud_level = get_pt_level_on_id(E2K_PUD_LEVEL_NUM);
	e2k_addr_t phys_page;
	pgprot_t pgprot;
	pud_t new;

	phys_page = pud_pfn(*pudp) << PAGE_SHIFT;
	pgprot_val(pgprot) = _PAGE_CLEAR(pud_val(*pudp), UNI_PAGE_PFN);
	if (pud_level->map_pt_huge_page_to_prev_level != NULL)
		pud_level->map_pt_huge_page_to_prev_level((pgprot_t *)pmd_page,
							phys_page, pgprot);
	else
		map_pud_huge_page_to_simple_pmds((pgprot_t *)pmd_page,
							phys_page, pgprot);

	smp_wmb(); /* make pmd visible before pud */
	new = mk_pud_phys(__pa(pmd_page), PAGE_KERNEL_PMD);
	native_set_pud(pudp, new);
}

/* FIXME; split is not fully implemented for guest kernel. */
/* Guest kernel should register spliting on host */
static int split_pud_page(int node, pud_t *pudp)
{
	pmd_t *pmdp;
	bool was_updated = false;

	pmdp = sma_alloc_page(node);
	if (!pmdp)
		return -ENOMEM;

	/* Re-read `*pudp' again under spinlock */
	raw_spin_lock(&sma_lock);
	if (!kernel_pud_huge(*pudp)) {
		was_updated = true;
	} else {
		split_one_pud_page(pudp, pmdp);
	}
	raw_spin_unlock(&sma_lock);

	if (was_updated)
		sma_free_page(node, pmdp);

	return 0;
}

static void modify_pud_page(pud_t *pudp, enum sma_mode mode)
{
	pud_t new;

	switch (mode) {
	case SMA_RO:
		new = pud_wrprotect(*pudp);
		break;
	case SMA_RW:
		new = pud_mkwrite(*pudp);
		break;
	case SMA_NX:
		new = pud_mknotexec(*pudp);
		break;
	case SMA_X:
		new = pud_mkexec(*pudp);
		break;
	case SMA_P:
		new = pud_mk_present_valid(*pudp);
		break;
	case SMA_NP:
		new = pud_mknot_present_valid(*pudp);
		break;
	case SMA_WB_MT:
		new = pud_mk_wb(*pudp);
		break;
	case SMA_WC_MT:
		new = pud_mk_wc(*pudp);
		break;
	case SMA_UC_MT:
		new = pud_mk_uc(*pudp);
		break;
	default:
		BUG();
	}

	native_set_pud(pudp, new);
}

static int pud_modified(pud_t pud, enum sma_mode mode)
{
	switch (mode) {
	case SMA_RO:
		return !pud_write(pud);
	case SMA_RW:
		return pud_write(pud);
	case SMA_NX:
		return !pud_exec(pud);
	case SMA_X:
		return pud_exec(pud);
	case SMA_P:
		return pud_present(pud);
	case SMA_NP:
		return !pud_present(pud);
	case SMA_WB_MT:
		return pud_wb(pud);
	case SMA_WC_MT:
		return pud_wc(pud);
	case SMA_UC_MT:
		return pud_uc(pud);
	default:
		BUG();
	};

	return -EINVAL;
}
static int walk_pud_level(int node, pgd_t *pgd, unsigned long addr,
		  unsigned long end, enum sma_mode mode, int *need_flush)
{
	unsigned long next;
	pud_t *pudp;
	e2k_size_t page_size;
	int ret = 0;

	pudp = pud_offset(pgd, addr);
	do {
		if (pud_none(*pudp))
			return -EINVAL;
		next = pud_addr_end(addr, end);
		if (!kernel_pud_huge(*pudp)) {
			ret = walk_pmd_level(node, pudp, addr, next, mode,
					     need_flush);
		} else if (!pud_modified(*pudp, mode)) {
			page_size = get_pud_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next) {
				ret = split_pud_page(node, pudp);
				continue;
			}
			*need_flush = 1;
			modify_pud_page(pudp, mode);
		}
		++pudp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static void sma_flush_tlb_ipi(void *unused)
{
	__flush_tlb_all();
}

static int set_memory_attr(unsigned long start, unsigned long end,
			   enum sma_mode mode)
{
	unsigned long addr, next;
	int node, ret, need_flush = 0;
	pgd_t *pgdp;

	if (end > E2K_MODULES_END && (start < VMALLOC_START ||
				     end > VMALLOC_END))
		return -EINVAL;

	if (start >= end)
		return 0;

	if (WARN_ON(!IS_ALIGNED(start, PAGE_SIZE)))
		start = round_down(start, PAGE_SIZE);
	if (WARN_ON(!IS_ALIGNED(end, PAGE_SIZE)))
		end = round_up(end, PAGE_SIZE);

	/*
	 * Get rid of potentially aliasing lazily unmapped vm areas that may
	 * have permissions set that deviate from the ones we are setting here.
	 */
	vm_unmap_aliases();

	for_each_node_has_dup_kernel(node) {
		addr = start;
		pgdp = node_pgd_offset_kernel(node, addr);
		do {
			if (pgd_none(*pgdp))
				return -EINVAL;
			/* FIXME: should be implemented, */
			/* if pgd level can have PTEs */
			BUG_ON(kernel_pgd_huge(*pgdp));
			next = pgd_addr_end(addr, end);
			ret = walk_pud_level(node, pgdp, addr, next, mode,
					     &need_flush);
			if (ret)
				return ret;
		} while (pgdp++, addr = next, addr < end);
	}

	if (IS_ENABLED(CONFIG_KVM_GUEST_MODE) &&
			!IS_ENABLED(CONFIG_KVM_SHADOW_PT) || need_flush) {
		/*
		 * Sometimes allocators are called under closed
		 * interrupts, so do not use on_each_cpu() here.
		 */
		nmi_on_each_cpu(sma_flush_tlb_ipi, NULL, 1, 0);

		/*
		 * gpu-imgtec expects the caches to be dropped when remapping
		 * to WC/UC (see _ApplyOSPagesAttribute()).
		 *
		 * Also (#134896):
		 * 1) When remapping memory from General/WB/WC to External/UC
		 * we must flush previous cache contents so that they won't
		 * overwrite RAM contents later.
		 * 2) When remapping memory from External/UC to General/WB/WC
		 * it is possible that hardware prefetcher has loaded some of
		 * its older contents into cache so it must be flushed.
		 */
		if (mode == SMA_UC_MT || mode == SMA_WC_MT ||
				cpu_has(CPU_FEAT_HW_PREFETCHER) && mode == SMA_WB_MT)
			write_back_cache_range(start, end - start);
	}

	return 0;
}

int set_memory_ro(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_RO);
}

int set_memory_rw(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_RW);
}

int set_memory_nx(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_NX);
}

int set_memory_x(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_X);
}


#ifdef CONFIG_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long addr = (unsigned long) page_address(page);

	set_memory_attr(addr, addr + numpages * PAGE_SIZE,
			(enable) ? SMA_P : SMA_NP);
}

# ifdef CONFIG_HIBERNATION
/*
 * When built with CONFIG_DEBUG_PAGEALLOC and CONFIG_HIBERNATION, this function
 * is used to determine if a linear map page has been marked as not-valid by
 * CONFIG_DEBUG_PAGEALLOC.
 */
bool kernel_page_present(struct page *page)
{
	unsigned long addr, entry_val;
	probe_entry_t entry;

	addr = (unsigned long) page_address(page);
	entry = get_MMU_DTLB_ENTRY(addr);
	entry_val = probe_entry_val(entry);

	if ((entry_val & ~DTLB_EP_RES) || !(entry_val & DTLB_ENTRY_VVA))
		return false;

	return true;
}
# endif
#endif

#define CPA_PAGES_ARRAY 1

static int change_page_attr(unsigned long addr, int numpages,
		enum sma_mode mode, int flags, struct page **pages)
{
	int i = 0;

	if (!(flags & CPA_PAGES_ARRAY)) {
		if (addr & ~PAGE_MASK) {
			addr &= PAGE_MASK;
			WARN_ON_ONCE(1);
		}

		return set_memory_attr(addr, addr + numpages * PAGE_SIZE, mode);
	}

	for (i; i < numpages; i++) {
		int err;

		addr = (unsigned long)page_address(pages[i]);

		if (err = set_memory_attr(addr, addr + PAGE_SIZE, mode)) {
			WARN_ON_ONCE(1);
			return err;
		}
	}

	return 0;
}

/* Mapping device memory as UC disables cache coherency since v6.
 *
 * Mapping RAM as UC keeps cache coherency on but beware that
 * there must not exist any aliases for the remapped memory,
 * otherwise speculative access at an alias address could load
 * data into cache and consequent stores and loads will work with
 * cache instead of memory.
 *
 * set_memory_uc() itself does NOT take care of cache flushing as
 * on e2k everything is coherent including DMA, thus the flush is
 * needed on one device only: Imagination video card on e2c3. */
int set_memory_uc(unsigned long addr, int numpages)
{
	return change_page_attr(addr, numpages, SMA_UC_MT, 0, NULL);
}
EXPORT_SYMBOL(set_memory_uc);

int set_pages_uc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_uc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_uc);

int set_pages_array_uc(struct page **pages, int addrinarray)
{
	return change_page_attr(0, addrinarray, SMA_UC_MT,
				CPA_PAGES_ARRAY, pages);
}
EXPORT_SYMBOL(set_pages_array_uc);

/* Mapping device memory as WC disables cache coherency since v6.
 *
 * Mapping RAM as WC keeps cache coherency on but beware that
 * there must not exist any aliases for the remapped memory,
 * otherwise speculative access at an alias address could load
 * data into cache and consequent stores and loads will work with
 * cache instead of memory.
 *
 * set_memory_wc() itself does NOT take care of cache flushing as
 * on e2k everything is coherent including DMA, thus the flush is
 * needed on one device only: Imagination video card on e2c3. */
int set_memory_wc(unsigned long addr, int numpages)
{
	return change_page_attr(addr, numpages, SMA_WC_MT, 0, NULL);
}
EXPORT_SYMBOL(set_memory_wc);

int set_pages_wc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wc);

int set_pages_array_wc(struct page **pages, int addrinarray)
{
	return change_page_attr(0, addrinarray, SMA_WC_MT,
				CPA_PAGES_ARRAY, pages);
}
EXPORT_SYMBOL(set_pages_array_wc);

int set_memory_wb(unsigned long addr, int numpages)
{
	return change_page_attr(addr, numpages, SMA_WB_MT, 0, NULL);
}
EXPORT_SYMBOL(set_memory_wb);

int set_pages_wb(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wb(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wb);

int set_pages_array_wb(struct page **pages, int addrinarray)
{
	return change_page_attr(0, addrinarray, SMA_WB_MT,
				CPA_PAGES_ARRAY, pages);
}
EXPORT_SYMBOL(set_pages_array_wb);
