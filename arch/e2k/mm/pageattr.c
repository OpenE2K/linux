/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/memblock.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/pgtable.h>

#include <asm/l-iommu.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/topology.h>

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

static __ref void *sma_alloc_page(int node, enum e2k_pt_levels level)
{
	void *addr = NULL;

	if (slab_is_available()) {
		switch (level) {
		case PT_LEVEL_PGD:
			addr = pgd_alloc_node(&init_mm, node);
			break;
		case PT_LEVEL_PUD:
			addr = pud_alloc_one_node(&init_mm, node);
			break;
		case PT_LEVEL_PMD:
			addr = pmd_alloc_one_node(&init_mm, node);
			break;
		case PT_LEVEL_PTE:
			addr = pte_alloc_one_kernel_node(&init_mm, node);
			break;
		case PT_LEVEL_PAGES: {
			struct page *page;
			gfp_t gfp = GFP_KERNEL|__GFP_NOWARN;

			if (node != NUMA_NO_NODE)
				gfp |= __GFP_THISNODE;
			page = alloc_pages_node(node, gfp, 0);
			if (page)
				addr = page_address(page);
			break;
		}
		}
	} else {
		addr = memblock_alloc_node(PAGE_SIZE, PAGE_SIZE, node);
		if (addr && level == PT_LEVEL_PGD)
			pgd_ctor(&init_mm, node, (pgd_t *) addr);
	}

	return addr;
}

static __ref void sma_free_page(enum e2k_pt_levels level, void *addr)
{
	if (slab_is_available()) {
		switch (level) {
		case PT_LEVEL_PGD:
			pgd_free(&init_mm, addr);
			break;
		case PT_LEVEL_PUD:
			pud_free(&init_mm, addr);
			break;
		case PT_LEVEL_PMD:
			pmd_free(&init_mm, addr);
			break;
		case PT_LEVEL_PTE:
			pte_free_kernel(&init_mm, addr);
			break;
		case PT_LEVEL_PAGES:
			free_page((unsigned long) addr);
			break;
		}
	} else {
		memblock_free(__pa(addr), PAGE_SIZE);
	}
}

static DEFINE_RAW_SPINLOCK(sma_lock);

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
void split_simple_pmd_page(pgprot_t *ptp, pte_t *ptes)
{
	const pt_level_t *pmd_level = get_pt_level_on_id(PT_LEVEL_PMD);
	pte_t *ptep;
	e2k_addr_t phys_page;

	if (pmd_level->get_huge_pte != NULL) {
		ptep = pmd_level->get_huge_pte(0, ptp);
	} else {
		ptep = (pte_t *)ptp;
	}
	phys_page = pte_pfn(*ptep) << PAGE_SHIFT;
	split_one_pmd_page((pmd_t *)ptep, phys_page, ptes);
}

static inline void
free_pmd_huge_ptes_pages(int node, pte_t *ptes)
{
	sma_free_page(PT_LEVEL_PTE, ptes);
	ptes = NULL;
}
static inline pte_t *
alloc_pmd_huge_ptes_pages(int node)
{
	return sma_alloc_page(node, PT_LEVEL_PTE);
}

/* FIXME; split is not fully implemented for guest kernel */
/* Guest kernel should register spliting on host */
static int split_pmd_page(int node, pmd_t *pmdp)
{
	pte_t *ptes;
	bool was_updated = false;
	unsigned long flags;

	ptes = alloc_pmd_huge_ptes_pages(node);
	if (unlikely(!ptes))
		return -ENOMEM;

	/* Re-read `*pmdp' again under spinlock */
	raw_spin_lock_irqsave(&sma_lock, flags);
	if (!kernel_pmd_huge(*pmdp))
		was_updated = true;
	else
		split_simple_pmd_page((pgprot_t *)pmdp, ptes);
	raw_spin_unlock_irqrestore(&sma_lock, flags);

	if (was_updated)
		free_pmd_huge_ptes_pages(node, ptes);

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
		pmd_t pmdval = pmd_read_atomic(pmdp);
		barrier();
		if (pmd_none(pmdval))
			return -EINVAL;
		next = pmd_addr_end(addr, end);
		if (!kernel_pmd_huge(pmdval)) {
			ret = walk_pte_level(pmdp, addr, next, mode,
					     need_flush);
		} else if (!pmd_modified(pmdval, mode)) {
			unsigned long flags;

			/* Protect against concurrent split */
			raw_spin_lock_irqsave(&sma_lock, flags);

			/* Check again under spinlock */
			if (!kernel_pmd_huge(*pmdp)) {
				raw_spin_unlock_irqrestore(&sma_lock, flags);
				continue;
			}

			if (!pmd_modified(*pmdp, mode)) {
				page_size = get_pmd_level_page_size();
				if (addr & (page_size - 1) || addr + page_size > next) {
					/* Have to unlock spinlock before
					 * allocating memory */
					raw_spin_unlock_irqrestore(&sma_lock, flags);
					if ((ret = split_pmd_page(node, pmdp)))
						return ret;
					continue;
				}
				*need_flush = 1;
				modify_pmd_page(pmdp, mode);
			}

			raw_spin_unlock_irqrestore(&sma_lock, flags);
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

static void
split_one_pud_page(pud_t *pudp, pmd_t *pmd_page)
{
	e2k_addr_t phys_page;
	pgprot_t pgprot;
	pud_t new;

	phys_page = pud_pfn(*pudp) << PAGE_SHIFT;
	pgprot_val(pgprot) = _PAGE_CLEAR(pud_val(*pudp), UNI_PAGE_PFN);
	map_pud_huge_page_to_simple_pmds((pgprot_t *)pmd_page, phys_page, pgprot);

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
	unsigned long flags;

	pmdp = sma_alloc_page(node, PT_LEVEL_PMD);
	if (!pmdp)
		return -ENOMEM;

	/* Re-read `*pudp' again under spinlock */
	raw_spin_lock_irqsave(&sma_lock, flags);
	if (!kernel_pud_huge(*pudp)) {
		was_updated = true;
	} else {
		split_one_pud_page(pudp, pmdp);
	}
	raw_spin_unlock_irqrestore(&sma_lock, flags);

	if (was_updated)
		sma_free_page(PT_LEVEL_PMD, pmdp);

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
		pud_t pudval = *pudp;
		barrier();
		if (pud_none(pudval))
			return -EINVAL;
		next = pud_addr_end(addr, end);
		if (!kernel_pud_huge(pudval)) {
			ret = walk_pmd_level(node, pudp, addr, next, mode,
					     need_flush);
		} else if (!pud_modified(pudval, mode)) {
			unsigned long flags;

			/* Protect against concurrent split */
			raw_spin_lock_irqsave(&sma_lock, flags);

			/* Check again under spinlock */
			if (!kernel_pud_huge(*pudp)) {
				raw_spin_unlock_irqrestore(&sma_lock, flags);
				continue;
			}

			if (!pud_modified(*pudp, mode)) {
				page_size = get_pud_level_page_size();
				if (addr & (page_size - 1) || addr + page_size > next) {
					/* Have to unlock spinlock before
					 * allocating memory */
					raw_spin_unlock_irqrestore(&sma_lock, flags);
					if ((ret = split_pud_page(node, pudp)))
						return ret;
					continue;
				}
				*need_flush = 1;
				modify_pud_page(pudp, mode);
			}

			raw_spin_unlock_irqrestore(&sma_lock, flags);
		}
		++pudp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static int set_memory_attr(unsigned long start, unsigned long end,
			   enum sma_mode mode)
{
	unsigned long addr, next;
	int node, ret, need_flush = 0;
	pgd_t *pgdp;

	if (WARN_ON_ONCE(end > KERNEL_END &&
			 (start < VMALLOC_START || end > VMALLOC_END)))
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
	if (mode == SMA_WB_MT || mode == SMA_WC_MT || mode == SMA_UC_MT)
		vm_unmap_aliases();

	for_each_node_state(node, N_MEMORY) {
		addr = start;
		pgdp = node_pgd_offset_k(node, addr);
		do {
			if (WARN_ON_ONCE(pgd_none(*pgdp)))
				return -EINVAL;
			/* FIXME: should be implemented, */
			/* if pgd level can have PTEs */
			BUG_ON(kernel_pgd_huge(*pgdp));
			next = pgd_addr_end(addr, end);
			ret = walk_pud_level(node, pgdp, addr, next, mode,
					     &need_flush);
			if (WARN_ON_ONCE(ret))
				return ret;
		} while (pgdp++, addr = next, addr < end);
	}

	if (IS_ENABLED(CONFIG_KVM_GUEST_MODE) &&
			!IS_ENABLED(CONFIG_KVM_SHADOW_PT) || need_flush) {
		/* Sometimes allocators are called under closed interrupts
		 * so use NMI version of flush_tlb_kernel_range() here. */
		flush_tlb_kernel_range_nmi(start, end);
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

int set_memory_np(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_NP);
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
	unsigned long addr = (unsigned long) page_address(page);
	probe_entry_t entry = get_MMU_DTLB_ENTRY(addr);
	return DTLB_ENTRY_TEST_SUCCESSFUL(entry) && DTLB_ENTRY_TEST_VVA(entry);
}
# endif
#endif

#define CPA_PAGES_ARRAY 1

typedef int (*set_memory_attr_fn)(unsigned long addr, int numpages);

static int change_page_attr(struct page **pages, int numpages,
		enum sma_mode mode, set_memory_attr_fn handler)
{
	unsigned long batch_addr;
	int i, batch_size = 0;

	for (i = 0; i < numpages; i++) {
		unsigned long addr = (unsigned long) page_address(pages[i]);

		if (batch_size == 0) {
			/* Start a new batch of physically contiguous pages */
			batch_addr = addr;
			batch_size = 1;
		} else if (addr == batch_addr + batch_size * PAGE_SIZE) {
			/* Add another page to the batch */
			batch_size += 1;
		} else {
			/* Next page is not physically contiguous with current
			 * batch, so process the batch and start a new one */
			int ret = handler(batch_addr, batch_size);
			if (ret)
				return ret;
			batch_addr = addr;
			batch_size = 1;
		}
	}

	if (batch_size)
		return handler(batch_addr, batch_size);

	return 0;
}

static struct page **vmalloc_to_pages(unsigned long addr, int numpages)
{
	int i;

	struct page **pages = kvmalloc_array(numpages, sizeof(struct page *), GFP_KERNEL);
	if (!pages)
		return NULL;

	for (i = 0; i < numpages; ++i)
		pages[i] = vmalloc_to_page((const void *) (addr + PAGE_SIZE * i));

	return pages;
}

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_memory_uc(unsigned long addr, int numpages)
{
	bool cache_flush_needed;
	int ret;

	if (addr >= VMALLOC_START && addr + numpages * PAGE_SIZE <= VMALLOC_END) {
		struct page **pages = vmalloc_to_pages(addr, numpages);
		if (WARN_ON_ONCE(!pages))
			return -ENOMEM;
		ret = set_pages_array_uc(pages, numpages);
		kvfree(pages);
		return ret;
	}

	if (addr < PAGE_OFFSET || addr >= PAGE_OFFSET + MAX_PM_SIZE) {
		WARN_ONCE(1, "set_memory_uc() expects a contiguous physical area or VMALLOC area.\n"
			"Otherwise please use set_pages_array_uc()\n");
		return -EINVAL;
	}

	ret = memtype_reserve(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
				  PCM_UC, &cache_flush_needed);
	if (ret)
		return ret;

	ret = set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_UC_MT);
	if (ret)
		memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

	if (cache_flush_needed)
		write_back_cache_range(addr, numpages * PAGE_SIZE);

	return 0;
}
EXPORT_SYMBOL(set_memory_uc);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_pages_uc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_uc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_uc);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_pages_array_uc(struct page **pages, int numpages)
{
	return change_page_attr(pages, numpages, SMA_UC_MT, &set_memory_uc);
}
EXPORT_SYMBOL(set_pages_array_uc);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_memory_wc(unsigned long addr, int numpages)
{
	bool cache_flush_needed;
	int ret;

	if (addr >= VMALLOC_START && addr + numpages * PAGE_SIZE <= VMALLOC_END) {
		struct page **pages = vmalloc_to_pages(addr, numpages);
		if (WARN_ON_ONCE(!pages))
			return -ENOMEM;
		ret = set_pages_array_wc(pages, numpages);
		kvfree(pages);
		return ret;
	}

	if (addr < PAGE_OFFSET || addr >= PAGE_OFFSET + MAX_PM_SIZE) {
		WARN_ONCE(1, "set_memory_wc() expects a contiguous physical area or VMALLOC area.\n"
			"Otherwise please use set_pages_array_wc()\n");
		return -EINVAL;
	}

	ret = memtype_reserve(__pa(addr), __pa(addr) + numpages * PAGE_SIZE,
				  PCM_WC, &cache_flush_needed);
	if (ret)
		return ret;

	ret = set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_WC_MT);
	if (ret)
		memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);

	if (cache_flush_needed)
		write_back_cache_range(addr, numpages * PAGE_SIZE);

	return 0;
}
EXPORT_SYMBOL(set_memory_wc);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_pages_wc(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wc(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wc);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_pages_array_wc(struct page **pages, int numpages)
{
	return change_page_attr(pages, numpages, SMA_WC_MT, &set_memory_wc);
}
EXPORT_SYMBOL(set_pages_array_wc);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_memory_wb(unsigned long addr, int numpages)
{
	bool call_memtype_free;
	int ret;

	if (addr >= VMALLOC_START && addr + numpages * PAGE_SIZE <= VMALLOC_END) {
		struct page **pages = vmalloc_to_pages(addr, numpages);
		if (WARN_ON_ONCE(!pages))
			return -ENOMEM;
		ret = set_pages_array_wb(pages, numpages);
		kvfree(pages);
		return ret;
	}

	if (addr < PAGE_OFFSET || addr >= PAGE_OFFSET + MAX_PM_SIZE) {
		WARN_ONCE(1, "set_memory_wb() expects a contiguous physical area or VMALLOC area.\n"
			"Otherwise please use set_pages_array_wb()\n");
		return -EINVAL;
	}

	call_memtype_free = memtype_free_cacheflush(__pa(addr),
					__pa(addr) + numpages * PAGE_SIZE);

	ret = set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_WB_MT);
	if (ret)
		return ret;

	if (call_memtype_free)
		memtype_free(__pa(addr), __pa(addr) + numpages * PAGE_SIZE);
	return 0;
}
EXPORT_SYMBOL(set_memory_wb);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_pages_wb(struct page *page, int numpages)
{
	unsigned long addr = (unsigned long)page_address(page);

	return set_memory_wb(addr, numpages);
}
EXPORT_SYMBOL(set_pages_wb);

/* For usage see comment before PAGE_UNCACHED/PAGE_COHERENT in pgtable.c */
int set_pages_array_wb(struct page **pages, int numpages)
{
	return change_page_attr(pages, numpages, SMA_WB_MT, &set_memory_wb);
}
EXPORT_SYMBOL(set_pages_array_wb);

#ifdef HAVE_ARCH_FREE_PAGE
/* Check that the freed page has WB cache attribute set in linear mapping */
void arch_free_page(struct page *page, int order)
{
	pte_mem_type_t mt;
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;
	unsigned long address = (unsigned long) page_address(page);

	pgdp = pgd_offset_k(address);
	if (pgd_none(*pgdp))
		return;
	if (kernel_pgd_huge(*pgdp)) {
		mt = _PAGE_GET_MEM_TYPE(pgd_val(*pgdp));
		goto check_mt;
	}

	pudp = pud_offset(pgdp, address);
	if (pud_none(*pudp))
		return;
	if (kernel_pud_huge(*pudp)) {
		mt = _PAGE_GET_MEM_TYPE(pud_val(*pudp));
		goto check_mt;
	}

	pmdp = pmd_offset(pudp, address);
	if (pmd_none(*pmdp))
		return;
	if (kernel_pmd_huge(*pmdp)) {
		mt = _PAGE_GET_MEM_TYPE(pmd_val(*pmdp));
		goto check_mt;
	}

	ptep = pte_offset_kernel(pmdp, address);
	if (pte_none(*ptep))
		return;
	mt = _PAGE_GET_MEM_TYPE(pte_val(*ptep));

check_mt:
	WARN_ONCE(mt != GEN_CACHE_MT, "The freed page is mapped with %d memory type instead of writeback. Did you forget to call set_memory_wb()/set_pages_array_wb() before freeing it?\n",
			mt);
}
#endif


#ifdef CONFIG_NUMA
/* Protect simultaneous access to the last level (PT_LEVEL_PAGES) */
static DEFINE_SPINLOCK(duplication_lock);

static int kernel_duplicate_pte_page(int node, const pte_t *pte, pmd_t *pmd)
{
	int pte_node;

	BUG_ON((unsigned long) pte & (PTE_TABLE_SIZE - 1));

	pte_node = page_to_nid(phys_to_page(__pa(pte)));
	if (pte_node != node) {
		/* This pte has not been duplicated yet */
		pmd_t *dup_pte = sma_alloc_page(node, PT_LEVEL_PTE);
		if (!dup_pte) {
			pr_info("Could not allocate pud from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pte, pte, PTE_TABLE_SIZE);
		smp_wmb(); /* See comment in __pte_alloc */

		spin_lock(&init_mm.page_table_lock);
		if (pte == (pte_t *) pmd_page_vaddr(*pmd)) {
			pmd_set_k(pmd, dup_pte);
		} else {
			/* Someone has just duplicated it */
			sma_free_page(PT_LEVEL_PTE, dup_pte);
		}
		spin_unlock(&init_mm.page_table_lock);
	}

	return 0;
}

static int kernel_duplicate_one_page(int node, pte_t *ptep)
{
	int page_node = page_to_nid(pte_page(*ptep));

	if (page_node != node) {
		void *dup_addr = sma_alloc_page(node, PT_LEVEL_PAGES);
		if (!dup_addr)
			return -ENOMEM;

		tagged_memcpy_8(dup_addr, (void *) pte_page_vaddr(*ptep),
				PTE_SIZE);

		spin_lock(&duplication_lock);
		if (node != page_to_nid(pte_page(*ptep))) {
			set_pte(ptep, mk_pte_phys(__pa(dup_addr),
						  pte_pgprot(*ptep)));
		} else {
			/* Someone has just duplicated it */
			free_page((unsigned long) dup_addr);
		}
		spin_unlock(&duplication_lock);
	}

	return 0;
}

static int kernel_duplicate_pte_range(int node, enum e2k_pt_levels level,
		pmd_t *pmd, unsigned long addr, unsigned long end)
{
	pte_t *ptep, *base_pte;
	int ret = 0;

	base_pte = (pte_t *) pmd_page_vaddr(*pmd);
	ret = kernel_duplicate_pte_page(node, base_pte, pmd);
	if (ret)
		return ret;

	if (level == PT_LEVEL_PTE)
		return 0;

	ptep = base_pte + pte_index(addr);
	do {
		if (pte_none(*ptep))
			return -EINVAL;

		ret = kernel_duplicate_one_page(node, ptep);
		if (ret)
			return ret;
	} while (ptep++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static int kernel_duplicate_huge_pmd(int node, pmd_t *pmd,
		unsigned long addr, unsigned long end)
{
	int hpage_node;

	BUG_ON((end - addr) != PMD_SIZE || !IS_ALIGNED(addr, PMD_SIZE));

	hpage_node = page_to_nid(pmd_page(*pmd));

	if (hpage_node != node) {
		phys_addr_t dup_phys;
		struct page *dup_hpage = alloc_pages_node(node, GFP_KERNEL |
				__GFP_RETRY_MAYFAIL | __GFP_THISNODE,
				get_order(PMD_SIZE));
		if (!dup_hpage)
			return -ENOMEM;

		dup_phys = page_to_phys(dup_hpage);
		tagged_memcpy_8(__va(dup_phys), (void *) pmd_page_vaddr(*pmd),
				PMD_SIZE);

		spin_lock(&duplication_lock);
		if (node != page_to_nid(pmd_page(*pmd))) {
			BUG_ON(!IS_ALIGNED(dup_phys, PMD_SIZE));
			set_pmd(pmd, pmd_mkhuge(mk_pmd_phys(dup_phys,
							    pmd_pgprot(*pmd))));
		} else {
			/* Someone has just duplicated it */
			__free_pages(dup_hpage, get_order(PMD_SIZE));
		}
		spin_unlock(&duplication_lock);
	}

	return 0;
}

static int kernel_duplicate_pmd_page(int node, const pmd_t *pmd, pud_t *pud)
{
	int pmd_node;

	BUG_ON((unsigned long) pmd & (PMD_TABLE_SIZE - 1));

	pmd_node = page_to_nid(phys_to_page(__pa(pmd)));
	if (pmd_node != node) {
		/* This pmd has not been duplicated yet */
		pmd_t *dup_pmd = sma_alloc_page(node, PT_LEVEL_PMD);
		if (!dup_pmd) {
			pr_info("Could not allocate pud from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pmd, pmd, PMD_TABLE_SIZE);
		smp_wmb(); /* See comment in __pte_alloc */

		spin_lock(&init_mm.page_table_lock);
		if (pmd == pud_pgtable(*pud)) {
			pud_set_k(pud, dup_pmd);
		} else {
			/* Someone has just duplicated it */
			sma_free_page(PT_LEVEL_PMD, dup_pmd);
		}
		spin_unlock(&init_mm.page_table_lock);
	}

	return 0;
}

static int kernel_duplicate_pmd_range(int node, enum e2k_pt_levels level, pud_t *pud,
		unsigned long addr, unsigned long end)
{
	pmd_t *pmdp, *base_pmd;
	unsigned long next;
	e2k_size_t page_size;
	int ret = 0;

	base_pmd = pud_pgtable(*pud);
	ret = kernel_duplicate_pmd_page(node, base_pmd, pud);
	if (ret)
		return ret;

	if (level == PT_LEVEL_PMD)
		return 0;

	pmdp = base_pmd + pmd_index(addr);
	do {
		if (pmd_none(*pmdp))
			return -EINVAL;

		next = pmd_addr_end(addr, end);

		if (!kernel_pmd_huge(*pmdp)) {
			ret = kernel_duplicate_pte_range(node, level, pmdp,
					addr, next);
		} else {
			page_size = get_pmd_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next) {
				ret = split_pmd_page(node, pmdp);
				continue;
			}
			if (level == PT_LEVEL_PAGES) {
				ret = kernel_duplicate_huge_pmd(node, pmdp,
						addr, next);
			}
		}
		++pmdp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static int kernel_duplicate_pud_page(int node, const pud_t *pud, pgd_t *pgd)
{
	int pud_node;

	BUG_ON((unsigned long) pud & (PUD_TABLE_SIZE - 1));

	pud_node = page_to_nid(phys_to_page(__pa(pud)));
	if (pud_node != node) {
		/* This pud has not been duplicated yet */
		pud_t *dup_pud = sma_alloc_page(node, PT_LEVEL_PUD);
		if (!dup_pud) {
			pr_info("Could not allocate pud from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pud, pud, PUD_TABLE_SIZE);
		smp_wmb(); /* See comment in __pte_alloc */

		spin_lock(&init_mm.page_table_lock);
		if (pud == (pud_t *) pgd_page_vaddr(*pgd)) {
			pgd_set_k(pgd, dup_pud);
		} else {
			/* Someone has just duplicated it */
			sma_free_page(PT_LEVEL_PUD, dup_pud);
		}
		spin_unlock(&init_mm.page_table_lock);
	}

	return 0;
}

static int kernel_duplicate_pud_range(int node, enum e2k_pt_levels level,
		pgd_t *pgd, unsigned long addr, unsigned long end)
{
	unsigned long next;
	pud_t *pudp, *base_pud;
	e2k_size_t page_size;
	int ret = 0;

	base_pud = (pud_t *) pgd_page_vaddr(*pgd);
	ret = kernel_duplicate_pud_page(node, base_pud, pgd);
	if (ret)
		return ret;

	if (level == PT_LEVEL_PUD)
		return 0;

	pudp = base_pud + pud_index(addr);
	do {
		if (pud_none(*pudp))
			return -EINVAL;

		next = pud_addr_end(addr, end);

		if (!kernel_pud_huge(*pudp)) {
			ret = kernel_duplicate_pmd_range(node, level, pudp,
					addr, next);
		} else {
			page_size = get_pud_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next) {
				ret = split_pud_page(node, pudp);
				continue;
			}
			if (level == PT_LEVEL_PAGES) {
				/* No way we can allocate 1GB of contiguous
				 * memory, so warn user. */
				WARN_ON_ONCE(1);
				ret = -EINVAL;
			}
		}
		++pudp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static int kernel_duplicate_pgd_page(int node, const pgd_t *pgd)
{
	int pgd_node;

	BUG_ON((unsigned long) pgd & (PGD_TABLE_SIZE - 1));

	/* We use virt_to_page() because it can work with addresses
	 * from linear mapping as well with &swapper_pg_dir. */
	pgd_node = page_to_nid(virt_to_page(pgd));
	if (pgd_node != node) {
		/* This pgd has not been duplicated yet */
		pgd_t *dup_pgd = sma_alloc_page(node, PT_LEVEL_PGD);
		if (!dup_pgd) {
			pr_info("Could not allocate pud from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pgd, pgd, PGD_TABLE_SIZE);
		smp_wmb(); /* See comment in __pte_alloc */

		spin_lock(&init_mm.page_table_lock);
		if (init_mm.context.node_pgds[node] == pgd) {
			init_mm.context.node_pgds[node] = dup_pgd;
			node_set(node, init_mm.context.pgds_nodemask);
		} else {
			/* Someone has just duplicated it */
			sma_free_page(PT_LEVEL_PGD, dup_pgd);
		}
		spin_unlock(&init_mm.page_table_lock);
	}

	return 0;
}

static int kernel_duplicate_pgd_range(int node, enum e2k_pt_levels level,
		unsigned long addr, unsigned long end)
{
	pgd_t *pgd, *base_pgd;
	unsigned long next;
	int ret = 0;

	base_pgd = init_mm.context.node_pgds[node];
	ret = kernel_duplicate_pgd_page(node, base_pgd);
	if (ret)
		return ret;

	if (level == PT_LEVEL_PGD)
		return 0;

	pgd = base_pgd + pgd_index(addr);
	BUG_ON(pgd_none(*pgd));
	do {
		if (unlikely(pgd_none(*pgd) || kernel_pgd_huge(*pgd)))
			return -EINVAL;

		next = pgd_addr_end(addr, end);

		ret = kernel_duplicate_pud_range(node, level, pgd, addr, next);
		if (ret)
			break;
	} while (pgd++, addr = next, addr != end);

	return ret;
}

static int call_duplication_for_each_memory_node(enum e2k_pt_levels level,
		unsigned long addr, unsigned long end)
{
	int ret, node;

	for_each_node_state(node, N_MEMORY) {
		ret = kernel_duplicate_pgd_range(node, level, addr, end);
		if (ret)
			return ret;
	}

	return 0;
}


static void reload_pgd_and_flush(void *unused)
{
	/* Update root PT to point to the duplicated image */
	set_root_pt(mm_node_pgd(&init_mm, numa_node_id()));
	local_flush_tlb_all();
}

/**
 * kernel_image_duplicate_page_range - duplicate memory across NUMA nodes
 * @_addr - start address
 * @_end - end address
 * @page_tables_only - duplicate page tables but keep only one copy of data
 *
 * Will also update init_mm.context.node_pgds and pgds_nodemask as necessary.
 * Prints a warning if duplication failed.
 */
int kernel_image_duplicate_page_range(void *_addr, size_t size,
		bool page_tables_only)
{
	unsigned long addr = (unsigned long) _addr;
	unsigned long end = addr + size;
	int ret;

	/* It seems that duplication does not make sense
	 * on guest where memory nodes are virtual */
	if (IS_ENABLED(CONFIG_KVM_GUEST_KERNEL) || size == 0)
		return 0;

	might_sleep();
	BUG_ON(addr > end || !PAGE_ALIGNED(addr) || !PAGE_ALIGNED(size));

	BUILD_BUG_ON(E2K_PT_LEVELS_NUM != 4);

	/* page_to_nid() for memblock allocated pages will not work for
	 * deferred pages (see CONFIG_DEFERRED_STRUCT_PAGE_INIT), so
	 * avoid calling this function too early in the boot process. */
	BUG_ON(!slab_is_available());

	/* There can be complex cases, e.g. pgd was already allocated
	 * on node 1, pud was allocatead on node 0 and pmd on node 2.
	 * To handle these we do the duplication one step at a time:
	 * 1) Duplicate all PGDs in range.
	 * 2) Duplicate all PUDs in range.
	 * 3) Duplicate all PMDs in range.
	 * 4) Duplicate all PTEs in range.
	 * 5) Duplicate actual data. */
	ret = call_duplication_for_each_memory_node(PT_LEVEL_PGD, addr, end);
	ret = ret ?: call_duplication_for_each_memory_node(PT_LEVEL_PUD, addr, end);
	ret = ret ?: call_duplication_for_each_memory_node(PT_LEVEL_PMD, addr, end);
	ret = ret ?: call_duplication_for_each_memory_node(PT_LEVEL_PTE, addr, end);
	if (!ret && !page_tables_only)
		ret = call_duplication_for_each_memory_node(PT_LEVEL_PAGES, addr, end);

	if (!ret)
		on_each_cpu(&reload_pgd_and_flush, NULL, 1);

	WARN(ret, "Failed to duplicate 0x%lx - 0x%lx with error %d\n",
			addr, end, ret);

	return ret;
}
#endif
