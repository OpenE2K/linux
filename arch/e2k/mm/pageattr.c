/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/memblock.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/pgtable.h>
#include <linux/interval_tree.h>
#include <linux/cleanup.h>
#include <linux/kfence.h>

#include <asm/l-iommu.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/set_memory.h>
#include <asm/tlbflush.h>
#include <asm/topology.h>
#include <asm/pool.h>
#include <asm/kfence.h>
#include <linux/crash_dump.h>

bool arch_kfence_initialized;

static inline size_t pt_pages_nr(unsigned long start, unsigned long end, unsigned long shift)
{
	unsigned long page_size = 1UL << shift;

	return (round_up(end, page_size) - round_down(start, page_size)) >> shift;
}

static inline size_t split_pool_pages(unsigned long start, unsigned long end)
{
	size_t pmd_nr = pt_pages_nr(start, end, E2K_LARGE_PAGE_SHIFT);
	size_t pud_nr = pt_pages_nr(start, end, E2K_GIANT_PAGE_SHIFT);

	return pmd_nr + pud_nr;
}

/* Assume 'start' and 'end' are page-aligned */
static inline size_t duplication_pool_pages(unsigned long start, unsigned long end,
					    bool page_table_only)
{
	size_t pte_pages = pt_pages_nr(start, end, E2K_LARGE_PAGE_SHIFT);
	size_t pmd_pages = pt_pages_nr(start, end, E2K_GIANT_PAGE_SHIFT);
	size_t pud_pages = pt_pages_nr(start, end, P4D_SHIFT);
#ifdef __PAGETABLE_P4D_FOLDED
	size_t p4d_pages = 0;
#else
# error "specify number of pgd entries within the range [start, end)"
#endif
	size_t pgd_pages = 1;
	size_t pages_nr = (page_table_only) ? 0 : ((end - start) >> PAGE_SHIFT);

	return pte_pages + pmd_pages + pud_pages + p4d_pages + pgd_pages + pages_nr;
}

static inline size_t duplication_pool_huge_pages(unsigned long start, unsigned long end,
						 bool page_table_only)
{
	size_t up = round_up(start, LARGE_PAGE_SIZE);
	size_t down = round_down(end, LARGE_PAGE_SIZE);

	return (page_table_only || up >= down) ? 0 : ((down - up) >> E2K_LARGE_PAGE_SHIFT);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
/*
 * Since e2k debug kernel now supports huge pages, calling set_memory_*()
 * on a part of a huge page will require to split it. The process of splitting
 * in its turn do require allocating new pages for the page table. When
 * CONFIG_DEBUG_PAGEALLOC is enabled, default allocator calls
 * __kernel_map_pages(), which is a wrapper upon set_memory_attr(). So there is
 * a recursion:
 * set_memory_*() -> alloc_page() -> set_memory_*() -> ...
 * To break the loop, set_memory_*() code obtains memory from sma_page_pool.
 * This pool provides preallocated memory and eliminates the need to call
 * alloc_page().
 */
static struct pool *sma_page_pool[MAX_NUMNODES];

/*
 * Total number of pages that can be needed for splitting the whole RAM.
 * It's a rough approximation, but good enough for the debug kernel.
 */
static inline unsigned long sma_page_pool_capacity(void)
{
	unsigned long pte_pages_num = totalram_real_pages / PTRS_PER_PTE;
	unsigned long pmd_pages_num = pte_pages_num / PTRS_PER_PMD;

	return pte_pages_num + pmd_pages_num;
}

static inline bool sma_pools_allocated(void)
{
	int node;

	for_each_node_state(node, N_MEMORY)
		if (!sma_page_pool[node])
			return false;

	return true;
}

/*
 * Allocate sma_page_pool with enough memory for any possible split. Do
 * it once at kernel startup because later there can be problems with
 * atomic allocation on the debug kernel.
 *
 * init_sma_page_pool() can not be defined as arch initcall because it must
 * be called before the first call to set_memory_*(). That's why this function
 * is called directly from mem_init().
 */
void __init init_sma_page_pool(void)
{
	int node;

	for_each_node_state(node, N_MEMORY) {
		/* Use memblock allocator because buddy can be unavailable yet */
		sma_page_pool[node] = pool_create_memblock(sma_page_pool_capacity(),
							   PAGE_SIZE, node);
	}

	/*
	 * Kernel with CONFIG_DEBUG_PAGEALLOC enabled won't work without
	 * sma_page_pool; see comment before sma_page_pool definition.
	 */
	BUG_ON(!sma_pools_allocated());
}
#endif /* CONFIG_DEBUG_PAGEALLOC */

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
	case SMA_PV:
		new = pte_mk_present_valid(*ptep);
		break;
	case SMA_NPV:
		new = pte_mknot_present_valid(*ptep);
		break;
	case SMA_P:
		new = pte_mkpresent(*ptep);
		break;
	case SMA_NP:
		new = pte_mknotpresent(*ptep);
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
	case SMA_SPLIT:
		break;
	default:
		BUG();
	};

	set_pte(ptep, new);
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
	case SMA_PV:
		return pte_present_valid(pte);
	case SMA_P:
		return pte_present_only(pte);
	case SMA_NPV:
		return !pte_present_valid(pte);
	case SMA_NP:
		return !pte_present_only(pte);
	case SMA_WB_MT:
		return pte_wb(pte);
	case SMA_WC_MT:
		return pte_wc(pte);
	case SMA_UC_MT:
		return pte_uc(pte);
	case SMA_SPLIT:
		return true;
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

#ifdef CONFIG_DEBUG_PAGEALLOC
/*
 * Flag PG_arch_2 is used to mark pages obtained from sma_page_pool
 * on kernels build with CONFIG_DEBUG_PAGEALLOC. To avoid page leaking
 * from sma_page_pool, all pages with PG_arch_2 flag set should be returned
 * back to this pool instead of freeing.
 */
static void set_page_allocator_pool(struct page *page)
{
	set_bit(PG_arch_2, &page->flags);
}

static bool test_and_clear_page_allocator_pool(struct page *page)
{
	return test_and_clear_bit(PG_arch_2, &page->flags);
}
#endif /* CONFIG_DEBUG_PAGEALLOC */

static __ref void *sma_alloc_page__pool(struct pool *pool, int node,
					enum e2k_pt_levels level)
{
	void *page = pool_get(pool);

	if (unlikely(!page))
		return NULL;

	/* Check that pool returned a page from correct node */
	VM_BUG_ON(page_to_nid(virt_to_page(page)) != node);

#ifdef CONFIG_DEBUG_PAGEALLOC
	/* Mark pages obtained from sma_page_pool */
	if (pool == sma_page_pool[node])
		set_page_allocator_pool(virt_to_page(page));
#endif

	if (level == PT_LEVEL_PGD) {
		pgd_ctor(&init_mm, node, (pgd_t *) page);
	} else if (level == PT_LEVEL_PMD) {
		/*
		 * Both USE_SPLIT_PMD_PTLOCKS and ALLOC_SPLIT_PTLOCKS can not be defined
		 * due to Kconfig restrictions, but check them anyway. An allocation of
		 * a page table lock in pgtable_pmd_page_ctor() may cause a deadlock
		 * on kernel_pt_lock.
		 */
		BUILD_BUG_ON(USE_SPLIT_PMD_PTLOCKS && ALLOC_SPLIT_PTLOCKS);

		if (!pgtable_pmd_page_ctor(virt_to_page(page))) {
			pool_put(pool, page);
			return NULL;
		}
	} else if (level == PT_LEVEL_PTE) {
		/*
		 * Note: we do not call pgtable_pte_page_ctor()
		 * because it is used for user PT only.
		 */
	}

	return page;
}

static __ref void sma_free_page__no_pool(enum e2k_pt_levels level, void *addr)
{
	if (!memblock_is_reserved(__pa(addr))) {
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
		memblock_free(addr, PAGE_SIZE);
	}
}

/*
 * This spinlock is used by the following operations:
 *
 * 1) set_memory_*();
 * 2) kernel memory duplication across NUMA nodes;
 * 3) page collapse;
 * 4) page split (which is internally used by set_memory_*() and kernel memory duplication);
 * 5) duplication and deduplication of module pages;
 * 6) duplication of preallocated PUD pages.
 *
 * Whenever we traverse kernel PT during one of these operations, kernel_pt_lock
 * must be acquired. Using the single spinlock for all these operations simplifies
 * synchronization a lot.
 */
static DEFINE_RAW_SPINLOCK(kernel_pt_lock);

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
	set_pmd(pmdp, new);
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

/* FIXME; split is not fully implemented for guest kernel */
/* Guest kernel should register spliting on host */
static int split_pmd_page(int node, pmd_t *pmdp, struct pool *pool)
{
	pte_t *ptes;

	ptes = sma_alloc_page__pool(pool, node, PT_LEVEL_PTE);
	if (unlikely(!ptes))
		return -ENOMEM;

	split_simple_pmd_page((pgprot_t *)pmdp, ptes);

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
	case SMA_PV:
		new = pmd_mk_present_valid(*pmdp);
		break;
	case SMA_NPV:
		new = pmd_mknot_present_valid(*pmdp);
		break;
	case SMA_P:
		new = pmd_mkpresent(*pmdp);
		break;
	case SMA_NP:
		new = pmd_mknotpresent(*pmdp);
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
	case SMA_SPLIT:
		break;
	default:
		BUG();
	};

	set_pmd(pmdp, new);
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
	case SMA_PV:
		return pmd_present_valid(pmd);
	case SMA_P:
		return pmd_present_only(pmd);
	case SMA_NPV:
		return !pmd_present_valid(pmd);
	case SMA_NP:
		return !pmd_present_only(pmd);
	case SMA_WB_MT:
		return pmd_wb(pmd);
	case SMA_WC_MT:
		return pmd_wc(pmd);
	case SMA_UC_MT:
		return pmd_uc(pmd);
	case SMA_SPLIT:
		return false;
	default:
		BUG();
	};

	return -EINVAL;
}

static inline bool split_mode(enum sma_mode mode)
{
	return mode == SMA_SPLIT;
}

static int walk_pmd_level(int node, pud_t *pud, unsigned long addr,
		unsigned long end, enum sma_mode mode, int *need_flush,
		struct pool *pool)
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
			if (addr & (page_size - 1) || addr + page_size > next || split_mode(mode)) {
				ret = split_pmd_page(node, pmdp, pool);
				if (ret)
					return ret;
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
	set_pud(pudp, new);
}

/* FIXME; split is not fully implemented for guest kernel. */
/* Guest kernel should register spliting on host */
static int split_pud_page(int node, pud_t *pudp, struct pool *pool)
{
	pmd_t *pmdp;

	pmdp = sma_alloc_page__pool(pool, node, PT_LEVEL_PMD);
	if (!pmdp)
		return -ENOMEM;

	split_one_pud_page(pudp, pmdp);

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
	case SMA_PV:
		new = pud_mk_present_valid(*pudp);
		break;
	case SMA_NPV:
		new = pud_mknot_present_valid(*pudp);
		break;
	case SMA_P:
		new = pud_mkpresent(*pudp);
		break;
	case SMA_NP:
		new = pud_mknotpresent(*pudp);
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
	case SMA_SPLIT:
		break;
	default:
		BUG();
	}

	set_pud(pudp, new);
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
	case SMA_PV:
		return pud_present_valid(pud);
	case SMA_P:
		return pud_present(pud);
	case SMA_NPV:
		return !pud_present_valid(pud);
	case SMA_NP:
		return !pud_present(pud);
	case SMA_WB_MT:
		return pud_wb(pud);
	case SMA_WC_MT:
		return pud_wc(pud);
	case SMA_UC_MT:
		return pud_uc(pud);
	case SMA_SPLIT:
		return false;
	default:
		BUG();
	};

	return -EINVAL;
}

static int walk_pud_level(int node, p4d_t *p4dp, unsigned long addr, unsigned long end,
			  enum sma_mode mode, int *need_flush, struct pool *pool)
{
	unsigned long next;
	pud_t *pudp;
	e2k_size_t page_size;

	pudp = pud_offset(p4dp, addr);
	do {
		if (pud_none(*pudp))
			return -EINVAL;

		next = pud_addr_end(addr, end);
		if (!kernel_pud_huge(*pudp)) {
			int ret = walk_pmd_level(node, pudp, addr, next, mode,
						 need_flush, pool);
			if (ret)
				return ret;
		} else if (!pud_modified(*pudp, mode)) {

			page_size = get_pud_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next || split_mode(mode)) {
				int ret = split_pud_page(node, pudp, pool);
				if (ret)
					return ret;
				continue;
			}
			*need_flush = 1;
			modify_pud_page(pudp, mode);
		}
		++pudp;
		addr = next;
	} while (addr < end);

	return 0;
}

static int walk_p4d_level(int node, pgd_t *pgd, unsigned long addr, unsigned long end,
			  enum sma_mode mode, int *need_flush, struct pool *pool)
{
	unsigned long next;
	int ret = 0;
	p4d_t *p4dp = p4d_offset(pgd, addr);

	do {
		if (p4d_none(*p4dp))
			return -EINVAL;

		/* FIXME: should be implemented, if pgd level can have PTEs */
		BUG_ON(kernel_p4d_huge(*p4dp));
		next = p4d_addr_end(addr, end);
		ret = walk_pud_level(node, p4dp, addr, next, mode, need_flush, pool);
		++p4dp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static pmdval_t clear_pmd_unused_flags(pmd_t pmdp)

{
	return _PAGE_CLEAR(pmd_flags(pmdp), UNI_PAGE_ACCESSED | UNI_PAGE_DIRTY);
}

static pteval_t clear_pte_unused_flags(pte_t ptep)
{
	return _PAGE_CLEAR(pte_flags(ptep), UNI_PAGE_ACCESSED | UNI_PAGE_DIRTY);
}

static bool cmp_pmd_relevant_flags(pmd_t pmdp1, pmd_t pmdp2)
{
	return clear_pmd_unused_flags(pmdp1) == clear_pmd_unused_flags(pmdp2);
}

static bool cmp_pte_relevant_flags(pte_t ptep1, pte_t ptep2)
{
	return clear_pte_unused_flags(ptep1) == clear_pte_unused_flags(ptep2);
}

struct collapse_tlb_range {
	unsigned long begin;
	unsigned long end;
};

struct free_page_info {
	struct list_head list;
	void *page;
	enum e2k_pt_levels level;
	int node;
};

struct collapse_data {
	struct pool *pool;
	struct list_head free_pages_list;
	struct collapse_tlb_range tlb_range;
};

static void add_free_page_to_list(void *page, enum e2k_pt_levels level, int node,
				  struct collapse_data *collapse_data)
{
	struct free_page_info *info;

	info = (struct free_page_info *)pool_get(collapse_data->pool);

	if (!info) {
		/* Pool should have enough space. Page 'page' will leak */
		WARN_ON_ONCE(1);
		return;
	}

	info->page = page;
	info->level = level;
	info->node = node;

	list_add(&info->list, &collapse_data->free_pages_list);
}

static void free_pages_after_collapse(struct list_head *free_pages)
{
	struct free_page_info *info, *tmp;

	list_for_each_entry_safe(info, tmp, free_pages, list) {
#ifdef CONFIG_DEBUG_PAGEALLOC
		if (test_and_clear_page_allocator_pool(virt_to_page(info->page))) {
			if (info->level == PT_LEVEL_PMD)
				pgtable_pmd_page_dtor(virt_to_page(info->page));

			pool_put(sma_page_pool[info->node], info->page);

			list_del(&info->list);
			kfree(info);
			continue;
		}
#endif
		sma_free_page__no_pool(info->level, info->page);

		list_del(&info->list);
		kfree(info);
	}
}

static pte_t *set_collapsed_pmd(pmd_t *pmdp, unsigned long start)
{
	pgprot_t prot;
	pte_t *ptep = pte_offset_kernel(pmdp, start);
	e2k_addr_t phys_addr = pte_pfn(*ptep) << PAGE_SHIFT;

	pgprot_val(prot) = _PAGE_SET(_PAGE_CLEAR(pmd_val(*pmdp), UNI_PAGE_PFN),
		UNI_PAGE_HUGE | UNI_PAGE_GLOBAL);

	pmd_t new = mk_pmd_phys(phys_addr, prot);
	set_pmd(pmdp, new);
	return ptep;
}

static pmd_t *set_collapsed_pud(pud_t *pudp, unsigned long start)
{
	pgprot_t prot;
	pmd_t *pmdp = pmd_offset(pudp, start);
	e2k_addr_t phys_addr = pmd_pfn(*pmdp) << PAGE_SHIFT;

	pgprot_val(prot) = _PAGE_SET(_PAGE_CLEAR(pud_val(*pudp), UNI_PAGE_PFN),
		UNI_PAGE_HUGE | UNI_PAGE_GLOBAL);

	pud_t new = mk_pud_phys(phys_addr, prot);
	set_pud(pudp, new);
	return pmdp;
}

static bool is_last_pmd_interval(struct interval_tree_node *itp, unsigned long end)
{
	unsigned long pmd_up = round_up(end, HPAGE_SIZE);

	return end == pmd_up ? true : !interval_tree_iter_next(itp, end + 1, pmd_up - 1);
}

static bool pmd_check_loop(pmd_t *pmdp, unsigned long pmd_down)
{
	pte_t *ptep = pte_offset_kernel(pmdp, pmd_down);
	pte_t old_ptep = *ptep;

	if (kernel_pmd_huge(*pmdp))
		return false;

	if (pte_none(old_ptep))
		return false;

	for (int i = 1; i < PTRS_PER_PMD; i++)
		if (!cmp_pte_relevant_flags(ptep[i], old_ptep))
			return false;

	return true;
}

static void collapse_pmd(pmd_t *pmdp, unsigned long pmd_down,
			 struct collapse_data *collapse_data)
{
	int node = page_to_nid(pmd_page(*pmdp));
	pte_t *ptep = set_collapsed_pmd(pmdp, pmd_down);

	BUG_ON(!ptep);

	/* Update range for TLB flush */
	collapse_data->tlb_range.begin = min(collapse_data->tlb_range.begin, pmd_down);
	collapse_data->tlb_range.end = max(collapse_data->tlb_range.end, pmd_down + PMD_SIZE);

	/*
	 * We can't free the page here because kernel_pt_lock is acquired.
	 * Instead, put the page into list to free it after kernel_pt_lock
	 * is released and TLBs are flushed.
	 */
	add_free_page_to_list(ptep, PT_LEVEL_PTE, node, collapse_data);
}

/* Check is the interval we want collapse don't intersects areas
 * that forced to map by 4k pages */
static bool collapse_allowed(unsigned long addr, unsigned long size)
{
	return !intersects_kfence(addr, size);
}

static bool collapse_pmd_try(pmd_t *pmdp, struct interval_tree_node *itp,
			     unsigned long start, unsigned long end,
			     struct collapse_data *collapse_data)
{
	unsigned long pmd_down = round_down(start, HPAGE_SIZE);
	bool collapse_flag = true;
	bool is_last = itp->last != end || is_last_pmd_interval(itp, end);

	if (is_last) {
		if (!collapse_allowed(pmd_down, HPAGE_SIZE))
			return false;

		collapse_flag = pmd_check_loop(pmdp, pmd_down);

		if (collapse_flag)
			collapse_pmd(pmdp, pmd_down, collapse_data);
	}

	return collapse_flag;
}

/*
 * collapse_flag here and in other similar functions indicates that current
 * page or page area can be collapsed.
 */
static bool collapse_pmd_area(pud_t *pudp, struct interval_tree_node *itp,
			      unsigned long start, unsigned long end,
			      struct collapse_data *collapse_data)
{
	unsigned long pmd_start, pmd_end;
	pmd_t *pmdp;
	bool collapse_flag = true;

	pmdp = pmd_offset(pudp, start);

	pmd_start = start;
	pmd_end = pmd_addr_end(start, end);

	while (pmd_start < end) {
		if (pmd_none(*pmdp))
			return false;
		if (!kernel_pmd_huge(*pmdp)) {
			collapse_flag = collapse_pmd_try(pmdp, itp, pmd_start,
							 pmd_end, collapse_data) &&
					collapse_flag;
		}

		pmdp++;
		pmd_start = pmd_end;
		pmd_end = pmd_addr_end(pmd_end, end);
	}

	return collapse_flag;
}

static bool is_last_pud_interval(struct interval_tree_node *itp, unsigned long end)
{
	unsigned long pud_up = round_up(end, GIANT_PAGE_SIZE);

	return pud_up == end ? true : !interval_tree_iter_next(itp, end + 1, pud_up - 1);
}

static bool pud_check_loop(pud_t *pudp, unsigned long pud_down)
{
	pmd_t *pmdp = pmd_offset(pudp, pud_down);
	pmd_t old_pmdp = *pmdp;

	if (kernel_pud_huge(*pudp))
		return false;

	if (pmd_none(old_pmdp))
		return false;

	for (int i = 1; i < PTRS_PER_PMD; i++)
		if (!cmp_pmd_relevant_flags(pmdp[i], old_pmdp))
			return false;

	return true;
}

static void collapse_pud(pud_t *pudp, unsigned long pud_down,
			 struct collapse_data *collapse_data)
{
	int node = page_to_nid(pud_page(*pudp));
	pmd_t *pmdp = set_collapsed_pud(pudp, pud_down);

	BUG_ON(!pmdp);

	/* Update range for TLB flush */
	collapse_data->tlb_range.begin = min(collapse_data->tlb_range.begin, pud_down);
	collapse_data->tlb_range.end = max(collapse_data->tlb_range.end, pud_down + PUD_SIZE);

	/*
	 * We can't free the page here because kernel_pt_lock is acquired.
	 * Instead, put the page into list to free it after kernel_pt_lock
	 * is released and TLBs are flushed.
	 */
	add_free_page_to_list(pmdp, PT_LEVEL_PMD, node, collapse_data);
}

/*
 * makes_sense variable is a flag for optimizing search for potential huge
 * pages. It initially sets true for every PUD, and when PMD that cannot be
 * collapsed is detected, there's no need to collapse PUD, so PMDs out
 * of requested range can be ignored.
 */
static void collapse_pud_try(pud_t *pudp, struct interval_tree_node *itp,
			     unsigned long start, unsigned long end,
			     bool *makes_sense, struct collapse_data *collapse_data)
{
	unsigned long pud_down = round_down(start, GIANT_PAGE_SIZE);
	bool is_last = itp->last != end || is_last_pud_interval(itp, end);

	*makes_sense = collapse_pmd_area(pudp, itp, start, end, collapse_data) && *makes_sense;

	if (cpu_has(CPU_FEAT_ISET_V5) && is_last && *makes_sense) {
		if (pud_check_loop(pudp, pud_down))
			collapse_pud(pudp, pud_down, collapse_data);
	}

	/* if all areas for this pud checked, set *makes_sense true for next pud */
	*makes_sense = is_last || *makes_sense;
}

static void collapse_pud_area(p4d_t *p4dp, struct interval_tree_node *itp,
			      unsigned long start, unsigned long end,
			      struct collapse_data *collapse_data)
{
	unsigned long pud_start, pud_end;
	pud_t *pudp;
	bool makes_sense = true;

	pudp = pud_offset(p4dp, start);

	pud_start = start;
	pud_end = pud_addr_end(start, end);

	while (pud_start < end) {
		if (WARN_ON_ONCE(pud_none(*pudp)))
			return;
		if (!kernel_pud_huge(*pudp)) {
			collapse_pud_try(pudp, itp, pud_start, pud_end,
					 &makes_sense, collapse_data);
		}

		pudp++;
		pud_start = pud_end;
		pud_end = pud_addr_end(pud_end, end);
	}
}

static void collapse_p4d_area(pgd_t *pgdp, struct interval_tree_node *itp,
			      unsigned long start, unsigned long end,
			      struct collapse_data *collapse_data)
{
	unsigned long p4d_start, p4d_end;
	p4d_t *p4dp;

	p4dp = p4d_offset(pgdp, start);

	p4d_start = start;
	p4d_end = p4d_addr_end(start, end);

	while (p4d_start < end) {
		if (WARN_ON_ONCE(p4d_none(*p4dp)))
			return;
		collapse_pud_area(p4dp, itp, p4d_start, p4d_end, collapse_data);

		p4dp++;
		p4d_start = p4d_end;
		p4d_end = pgd_addr_end(p4d_end, end);
	}
}

static void collapse_pgd_area(const int node, struct interval_tree_node *itp,
			      struct collapse_data *collapse_data)
{
	unsigned long pgd_start, pgd_end;
	pgd_t *pgdp;

	pgdp = node_pgd_offset_k(node, itp->start);

	pgd_start = itp->start;
	pgd_end = pgd_addr_end(itp->start, itp->last);

	while (pgd_start < itp->last) {
		if (WARN_ON_ONCE(pgd_none(*pgdp)))
			return;
		collapse_p4d_area(pgdp, itp, pgd_start, pgd_end, collapse_data);

		pgdp++;
		pgd_start = pgd_end;
		pgd_end = pgd_addr_end(pgd_end, itp->last);
	}
}

static unsigned long collapse_pool_capacity(unsigned long start, unsigned long end)
{
	/*
	 * Page collapse for range [start, end) can free no more pages than
	 * split for this range requires.
	 */
	return split_pool_pages(start, end) * MAX_NUMNODES;
}

static int schedule_collapse(unsigned long start, unsigned long end);

static void collapse_pages_interval(struct interval_tree_node *itp)
{
	int node;
	unsigned long flags;
	struct collapse_data collapse_data;
	unsigned long pool_capacity = collapse_pool_capacity(itp->start, itp->last);

	collapse_data.pool = pool_create(pool_capacity, sizeof(struct free_page_info),
					 POOL_SLAB, GFP_KERNEL, NUMA_NO_NODE);
	if (!collapse_data.pool) {
		/* Print a warning and reschedule collapse for this interval */
		WARN_ON_ONCE(1);
		schedule_collapse(itp->start, itp->last);
		return;
	}

	INIT_LIST_HEAD(&collapse_data.free_pages_list);
	collapse_data.tlb_range.begin = ULONG_MAX;
	collapse_data.tlb_range.end = 0;

	raw_spin_lock_irqsave(&kernel_pt_lock, flags);

	for_each_node_state(node, N_MEMORY)
		collapse_pgd_area(node, itp, &collapse_data);

	raw_spin_unlock_irqrestore(&kernel_pt_lock, flags);

	/* Flush TLB after kernel_pt_lock is released */
	if (collapse_data.tlb_range.end > collapse_data.tlb_range.begin)
		flush_tlb_kernel_range(collapse_data.tlb_range.begin, collapse_data.tlb_range.end);

	/*
	 * Free pages after kernel_pt_lock is released because freeing can call
	 * set_memory_*() and cause a deadlock on kernel_pt_lock. Also, free these
	 * pages after TLB flush because these pages can be accessed via old
	 * TLB entries before the flush.
	 */
	free_pages_after_collapse(&collapse_data.free_pages_list);

	pool_destroy(collapse_data.pool);
}

static void collapse_pages(struct rb_root_cached *itree_root)
{
	struct rb_node *rb_nodep = rb_first_cached(itree_root);
	struct interval_tree_node *itp;

	while (rb_nodep) {
		itp = container_of(rb_nodep, struct interval_tree_node, rb);

		collapse_pages_interval(itp);

		rb_nodep = rb_next(rb_nodep);
	}
}

#ifdef CONFIG_DEBUG_PAGEALLOC
static struct pool *collapse_cache;
#else
static struct kmem_cache *collapse_cache;
#endif
static DEFINE_RAW_SPINLOCK(collapse_lock);
static bool collapse_scheduled = false;

static struct rb_root_cached itree_root = RB_ROOT_CACHED;

static void destroy_itree(struct rb_root_cached *itree)
{
	struct rb_node *node, *next;
	struct interval_tree_node *itree_node;

	while (!RB_EMPTY_ROOT(&itree->rb_root)) {
		node = rb_first_cached(itree);
		next = rb_erase_cached(node, itree);
		itree_node = container_of(node, struct interval_tree_node, rb);
#ifdef CONFIG_DEBUG_PAGEALLOC
		pool_put(collapse_cache, itree_node);
#else
		kmem_cache_free(collapse_cache, itree_node);
#endif
		node = next;
	}
}

static void collapse_work_handler(struct work_struct *work)
{
	unsigned long flags;
	struct rb_root_cached local_itree_root;

	raw_spin_lock_irqsave(&collapse_lock, flags);
	local_itree_root = itree_root;
	itree_root = RB_ROOT_CACHED;
	collapse_scheduled = false;
	raw_spin_unlock_irqrestore(&collapse_lock, flags);

	collapse_pages(&local_itree_root);
	destroy_itree(&local_itree_root);
}

static DECLARE_DELAYED_WORK(collapse_work, collapse_work_handler);

static int __init init_collapse_cache(void)
{
	WARN_ON_ONCE(!slab_is_available());

#ifdef CONFIG_DEBUG_PAGEALLOC
	/*
	 * Preallocate pool for debug kernel to avoid recursion:
	 * set_memory_attr() -> schedule_collapse() -> kmem_cache_alloc() ->
	 * -> alloc_pages() -> set_memory_attr().
	 *
	 * Since all collapse requests are rounded to PMD_SIZE (see schedule_collapse()),
	 * collapse interval tree won't have more nodes than a half of huge pages
	 * available in the system.
	 */
	size_t nr_pmds = totalram_real_pages * PAGE_SIZE / PMD_SIZE;

	collapse_cache = pool_create(nr_pmds / 2, sizeof(struct interval_tree_node),
				     POOL_SLAB, GFP_ATOMIC, NUMA_NO_NODE);
#else
	/*
	 * A deadlock can happen when set_memory_attr() calls schedule_collapse()
	 * which acquires collapse_lock and frees collapse_cache item in
	 * insert_interval(). Use SLAB_TYPESAFE_BY_RCU flag here so that freeing
	 * cache item does not result in a new call to set_memory_attr()
	 * with an attempt to recursively acquire collapse_lock.
	 */
	collapse_cache = kmem_cache_create("collapse_cache", sizeof(struct interval_tree_node),
					   0, SLAB_TYPESAFE_BY_RCU, NULL);
#endif
	if (!collapse_cache) {
		WARN(1, "Failed to allocate collapse_cache. Page collapse won't work.");
		return -ENOMEM;
	}

	return 0;
}
arch_initcall(init_collapse_cache)

static void insert_interval(struct interval_tree_node *node)
{
	struct interval_tree_node *isect_node;
	while ((isect_node = interval_tree_iter_first(&itree_root, node->start, node->last))) {
		node->start = min(node->start, isect_node->start);
		node->last = max(node->last, isect_node->last);

		interval_tree_remove(isect_node, &itree_root);
#ifdef CONFIG_DEBUG_PAGEALLOC
		pool_put(collapse_cache, isect_node);
#else
		kmem_cache_free(collapse_cache, isect_node);
#endif
	}

	interval_tree_insert(node, &itree_root);
}

static int schedule_collapse(unsigned long start, unsigned long end)
{
	unsigned long flags;
	struct interval_tree_node *node;

	if (IS_ENABLED(CONFIG_PREEMPT_RT))
		return 0;

	if (!collapse_cache)
		return 0;

	if (start < PAGE_OFFSET || end >= PAGE_OFFSET + MAX_PM_SIZE)
		return 0;

#ifdef CONFIG_DEBUG_PAGEALLOC
	node = pool_get(collapse_cache);
#else
	node = kmem_cache_alloc(collapse_cache, GFP_ATOMIC);
#endif
	if (unlikely(!node))
		return -ENOMEM;

	/*
	 * Round start and end to huge page borders. It allows us to reduce the
	 * size of collapse_cache for the kernel with CONFIG_DEBUG_PAGEALLOC.
	 * For the kernel without CONFIG_DEBUG_PAGEALLOC, it has no impact because
	 * collapse algorithm always passes over a range of at least PMD_SIZE.
	 */
	start = round_down(start, PMD_SIZE);
	end = round_up(end, PMD_SIZE);

	node->start = start;
	node->last = end;

	raw_spin_lock_irqsave(&collapse_lock, flags);

	insert_interval(node);
	if (!collapse_scheduled) {
		collapse_scheduled = true;
		raw_spin_unlock_irqrestore(&collapse_lock, flags);
		queue_delayed_work(system_power_efficient_wq, &collapse_work, HZ);
	} else {
		raw_spin_unlock_irqrestore(&collapse_lock, flags);
	}

	return 0;
}

#if defined(CONFIG_NUMA) || !defined(CONFIG_DEBUG_PAGEALLOC)
static void destroy_pools(struct pool *pools[MAX_NUMNODES])
{
	int node;

	for (node = 0; node < MAX_NUMNODES; node++) {
		if (pools[node]) {
			pool_destroy(pools[node]);
			pools[node] = NULL;
		}
	}
}
#endif /* CONFIG_NUMA || !CONFIG_DEBUG_PAGEALLOC */

#ifndef CONFIG_DEBUG_PAGEALLOC
static int alloc_split_pools(struct pool *pools[MAX_NUMNODES],
			     unsigned long start, unsigned long end)
{
	int node;
	unsigned long pool_capacity = split_pool_pages(start, end);

	/* Zero pool pointers */
	for (node = 0; node < MAX_NUMNODES; node++)
		pools[node] = NULL;

	for_each_node_mm_pgdmask(node, &init_mm) {
		if (pool_capacity) {
			/*
			 * Note that flag GFP_ATOMIC is used because set_memory_*()
			 * can be called from atomic context.
			 */
			pools[node] = pool_create(pool_capacity, 0, POOL_BUDDY,
				GFP_ATOMIC, is_kdump_kernel() ? NUMA_NO_NODE : node);
			if (!pools[node])
				goto alloc_err;
		}
	}

	return 0;

alloc_err:
	destroy_pools(pools);

	return -ENOMEM;
}
#endif /* !CONFIG_DEBUG_PAGEALLOC */

static int sma_main(unsigned long start, unsigned long end,
			   enum sma_mode mode, bool dontflush)
{
	unsigned long addr, next;
	int node, ret = 0, need_flush = 0;
	pgd_t *pgdp;
	unsigned long flags;

	/*
	 * Get rid of potentially aliasing lazily unmapped vm areas that may
	 * have permissions set that deviate from the ones we are setting here.
	 */
	if (mode == SMA_WB_MT || mode == SMA_WC_MT || mode == SMA_UC_MT)
		vm_unmap_aliases();

	/*
	 * In order to set memory attributes, we sometimes need to split huge pages
	 * in the range [addr, end) on every node. Splitting requires new pages for
	 * the page table. Since the whole work is done under spinlock kernel_pt_lock,
	 * before the spinlock acquisition we must allocate a pool to get memory from.
	 *
	 * If CONFIG_DEBUG_PAGEALLOC is disabled, we allocate the pool right here.
	 * If CONFIG_DEBUG_PAGEALLOC is enabled, we use preallocated pool, see comment
	 * before sma_page_pool definition.
	 *
	 * For kfence we can't allocate memory, see comment
	 * before arch_kfence_init_pool.
	 */

#ifndef CONFIG_DEBUG_PAGEALLOC
	struct pool *pools[MAX_NUMNODES];

	if (!is_kfence_address((void *)start) || !arch_kfence_initialized) {
		ret = alloc_split_pools(pools, start, end);
		if (ret) {
			pr_info("Failed to allocate pools for split\n");
			return ret;
		}
	}
#else
	struct pool **pools = sma_page_pool;

	/*
	 * We must have checked that pools in sma_page_pool were successfully allocated in
	 * init_sma_page_pool(). Check it here jist in case.
	 */
	BUG_ON(!sma_pools_allocated());
#endif

	raw_spin_lock_irqsave(&kernel_pt_lock, flags);

	for_each_node_mm_pgdmask(node, &init_mm) {
		addr = start;
		pgdp = node_pgd_offset_k(node, addr);
		do {
			BUG_ON(pgd_none(*pgdp));
			next = pgd_addr_end(addr, end);
			ret = walk_p4d_level(node, pgdp, addr, next, mode,
					     &need_flush, pools[node]);
			if (WARN_ON_ONCE(ret))
				goto unlock;

		} while (pgdp++, addr = next, addr < end);
	}

unlock:
	raw_spin_unlock_irqrestore(&kernel_pt_lock, flags);

	if (dontflush)
		need_flush = 0;

	if (IS_ENABLED(CONFIG_KVM_GUEST_MODE) && !IS_ENABLED(CONFIG_KVM_SHADOW_PT) || need_flush) {
		/* Sometimes allocators are called under closed interrupts so use NMI version of
		 * flush_tlb_kernel_range() here. We can't call flush under disabled NMIs
		 * because of a deadlock. */
		flush_tlb_kernel_range_nmi(start, end);
	}

#ifndef CONFIG_DEBUG_PAGEALLOC
	destroy_pools(pools);
#endif

	return ret;
}

static int set_memory_attr(unsigned long start, unsigned long end, enum sma_mode mode,
			   bool dontflush)
{
	int ret;

	if (WARN_ON_ONCE(end > KERNEL_END &&
			 (start < VMALLOC_START || end > VMALLOC_END)))
		return -EINVAL;

	if (start >= end)
		return 0;

	if (WARN_ON(!IS_ALIGNED(start, PAGE_SIZE)))
		start = round_down(start, PAGE_SIZE);
	if (WARN_ON(!IS_ALIGNED(end, PAGE_SIZE)))
		end = round_up(end, PAGE_SIZE);

	if (unlikely((ret = sma_main(start, end, mode, dontflush))))
		return ret;

	if (!is_kdump_kernel() && !is_kfence_address((void *)start))
		WARN_ON_ONCE(schedule_collapse(start, end));

	return 0;
}

int set_memory_4k(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_SPLIT, 0);
}
EXPORT_SYMBOL(set_memory_4k);

int set_memory_ro(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_RO, 0);
}
EXPORT_SYMBOL(set_memory_ro);

int set_memory_rw(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_RW, 0);
}
EXPORT_SYMBOL(set_memory_rw);

int set_memory_nx(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_NX, 0);
}
#ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(set_memory_nx);
#endif

int set_memory_x(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_X, 0);
}
#ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(set_memory_x);
#endif

int set_memory_p(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;

	/* See comment in set_memory_np() */
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_PV, 0);
}
#ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(set_memory_p);
#endif

int set_memory_p_noflush(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;

	/* See comment in set_memory_np() */
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_PV, 1);
}
#ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(set_memory_p_noflush);
#endif

int set_memory_np(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;

	/* Clearing only present bit without valid is dangerous - any
	 * semi-speculative load can cause an unexpected page fault and
	 * kernel panic.  So we clear both present and valid bit, doing
	 * so is closer to how other arch-es implement set_memory_[n]p() */
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_NPV, 0);
}

int set_memory_np_noflush(unsigned long addr, int numpages)
{
	addr &= PAGE_MASK;

	/* Clearing only present bit without valid is dangerous - any
	 * semi-speculative load can cause an unexpected page fault and
	 * kernel panic.  So we clear both present and valid bit, doing
	 * so is closer to how other arch-es implement set_memory_[n]p() */
	return set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_NPV, 1);
}

#ifdef CONFIG_DEBUG_PAGEALLOC
void __kernel_map_pages(struct page *page, int numpages, int enable)
{
	unsigned long addr = (unsigned long) page_address(page);

	set_memory_attr(addr, addr + numpages * PAGE_SIZE, (enable) ? SMA_P : SMA_NP, 0);
}
#endif

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

	ret = set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_UC_MT, 0);
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

	ret = set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_WC_MT, 0);
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

	ret = set_memory_attr(addr, addr + numpages * PAGE_SIZE, SMA_WB_MT, 0);
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
	p4d_t *p4dp;
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

	p4dp = p4d_offset(pgdp, address);
	if (p4d_none(*p4dp))
		return;
	if (kernel_p4d_huge(*p4dp)) {
		mt = _PAGE_GET_MEM_TYPE(p4d_val(*p4dp));
		goto check_mt;
	}

	pudp = pud_offset(p4dp, address);
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
static int kernel_duplicate_pte_page(int node, const pte_t *pte, pmd_t *pmd, struct pool *pool)
{
	int pte_node;
	pmd_t *dup_pte;

	BUG_ON((unsigned long) pte & (PTE_TABLE_SIZE - 1));

	pte_node = page_to_nid(phys_to_page(__pa(pte)));
	if (pte_node != node) {
		/* This pte has not been duplicated yet */
		dup_pte = sma_alloc_page__pool(pool, node, PT_LEVEL_PTE);
		if (!dup_pte) {
			pr_info("Could not allocate pte from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pte, pte, PTE_TABLE_SIZE);
		smp_wmb(); /* See comment in pmd_install() */

		pmd_set_k(pmd, dup_pte);
	}

	return 0;
}

static int kernel_duplicate_one_page(int node, pte_t *ptep, struct pool *pool)
{
	int page_node = page_to_nid(pte_page(*ptep));
	void *dup_addr;

	if (page_node != node) {
		dup_addr = sma_alloc_page__pool(pool, node, PT_LEVEL_PAGES);
		if (!dup_addr)
			return -ENOMEM;

		tagged_memcpy_8(dup_addr, (void *) pte_page_vaddr(*ptep), PTE_SIZE);
		smp_wmb(); /* See comment in pmd_install() */

		set_pte(ptep, mk_pte_phys(__pa(dup_addr), pte_pgprot(*ptep)));
	}

	return 0;
}

static int kernel_duplicate_pte_range(int node, enum e2k_pt_levels level, pmd_t *pmd,
				      unsigned long addr, unsigned long end, struct pool *pool)
{
	pte_t *ptep, *base_pte;
	int ret = 0;

	base_pte = (pte_t *) pmd_page_vaddr(*pmd);
	ret = kernel_duplicate_pte_page(node, base_pte, pmd, pool);
	if (ret)
		return ret;

	if (level == PT_LEVEL_PTE)
		return 0;

	ptep = base_pte + pte_index(addr);
	do {
		if (pte_none(*ptep))
			return -EINVAL;

		ret = kernel_duplicate_one_page(node, ptep, pool);
		if (ret)
			return ret;
	} while (ptep++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static int kernel_duplicate_huge_pmd(int node, pmd_t *pmd, unsigned long addr,
				     unsigned long end, struct pool *hpool)
{
	int hpage_node;
	void *dup_addr;

	BUG_ON((end - addr) != PMD_SIZE || !IS_ALIGNED(addr, PMD_SIZE));

	hpage_node = page_to_nid(pmd_page(*pmd));

	if (hpage_node != node) {
		dup_addr = sma_alloc_page__pool(hpool, node, PT_LEVEL_PAGES);
		if (!dup_addr)
			return -ENOMEM;

		tagged_memcpy_8(dup_addr, (void *) pmd_page_vaddr(*pmd), PMD_SIZE);
		smp_wmb(); /* See comment in pmd_install() */

		BUG_ON(!IS_ALIGNED(__pa(dup_addr), PMD_SIZE));
		set_pmd(pmd, pmd_mkhuge(mk_pmd_phys(__pa(dup_addr), pmd_pgprot(*pmd))));
	}

	return 0;
}

static int kernel_duplicate_pmd_page(int node, const pmd_t *pmd, pud_t *pud, struct pool *pool)
{
	int pmd_node;
	pmd_t *dup_pmd;

	BUG_ON((unsigned long) pmd & (PMD_TABLE_SIZE - 1));

	pmd_node = page_to_nid(phys_to_page(__pa(pmd)));
	if (pmd_node != node) {
		/* This pmd has not been duplicated yet */
		dup_pmd = sma_alloc_page__pool(pool, node, PT_LEVEL_PMD);
		if (!dup_pmd) {
			pr_info("Could not allocate pmd from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pmd, pmd, PMD_TABLE_SIZE);
		smp_wmb(); /* See comment in pmd_install() */

		pud_set_k(pud, dup_pmd);
	}

	return 0;
}

static int kernel_duplicate_pmd_range(int node, enum e2k_pt_levels level, pud_t *pud,
				      unsigned long addr, unsigned long end,
				      struct pool *pool, struct pool *hpool)
{
	pmd_t *pmdp, *base_pmd;
	unsigned long next;
	e2k_size_t page_size;
	int ret = 0;

	base_pmd = (pmd_t *) pud_page_vaddr(*pud);
	ret = kernel_duplicate_pmd_page(node, base_pmd, pud, pool);
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
					addr, next, pool);
		} else {
			page_size = get_pmd_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next) {
				ret = split_pmd_page(node, pmdp, pool);
				continue;
			}
			if (level == PT_LEVEL_PAGES) {
				ret = kernel_duplicate_huge_pmd(node, pmdp,
						addr, next, hpool);
			}
		}
		++pmdp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static int kernel_duplicate_pud_page(int node, const pud_t *pud, p4d_t *p4d, struct pool *pool)
{
	int pud_node;
	pud_t *dup_pud;

	BUG_ON((unsigned long) pud & (PUD_TABLE_SIZE - 1));

	pud_node = page_to_nid(phys_to_page(__pa(pud)));
	if (pud_node != node) {
		/* This pud has not been duplicated yet */
		dup_pud = sma_alloc_page__pool(pool, node, PT_LEVEL_PUD);
		if (!dup_pud) {
			pr_info("Could not allocate pud from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pud, pud, PUD_TABLE_SIZE);
		smp_wmb(); /* See comment in pmd_install() */

		p4d_set_k(p4d, dup_pud);
	}

	return 0;
}

static int kernel_duplicate_pud_range(int node, enum e2k_pt_levels level, p4d_t *p4d,
				      unsigned long addr, unsigned long end,
				      struct pool *pool, struct pool *hpool)
{
	unsigned long next;
	pud_t *pudp, *base_pud;
	e2k_size_t page_size;
	int ret = 0;

	base_pud = (pud_t *) p4d_page_vaddr(*p4d);
	ret = kernel_duplicate_pud_page(node, base_pud, p4d, pool);
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
			ret = kernel_duplicate_pmd_range(node, level, pudp, addr, next,
							 pool, hpool);
		} else {
			page_size = get_pud_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next) {
				ret = split_pud_page(node, pudp, pool);
				continue;
			}
			if (level == PT_LEVEL_PAGES) {
				/* No way we can allocate 1GB of contiguous memory, so warn user */
				WARN_ON_ONCE(1);
				ret = -EINVAL;
			}
		}
		++pudp;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static int kernel_duplicate_pgd_page(int node, const pgd_t *pgd, struct pool *pool)
{
	int pgd_node;
	pgd_t *dup_pgd;

	BUG_ON((unsigned long) pgd & (PGD_TABLE_SIZE - 1));

	/* We use virt_to_page() because it can work with addresses
	 * from linear mapping as well with &swapper_pg_dir. */
	pgd_node = page_to_nid(virt_to_page(pgd));
	if (pgd_node != node) {
		/* This pgd has not been duplicated yet */
		dup_pgd = sma_alloc_page__pool(pool, node, PT_LEVEL_PGD);
		if (!dup_pgd) {
			pr_info("Could not allocate pgd from node %d\n", node);
			return -ENOMEM;
		}
		memcpy(dup_pgd, pgd, PGD_TABLE_SIZE);
		smp_wmb(); /* See comment in pmd_install() */

		init_mm.context.node_pgds[node] = dup_pgd;
		node_set(node, init_mm.context.pgds_nodemask);
	}

	return 0;
}

static int kernel_duplicate_p4d_range(int node, enum e2k_pt_levels level, pgd_t *pgd,
				      unsigned long addr, unsigned long end,
				      struct pool *pool, struct pool *hpool)
{
	p4d_t *p4d = p4d_offset(pgd, addr);
	unsigned long next;
	int ret = 0;

	do {
		if (unlikely(p4d_none(*p4d) || kernel_p4d_huge(*p4d)))
			return -EINVAL;

		next = p4d_addr_end(addr, end);

		ret = kernel_duplicate_pud_range(node, level, p4d, addr, next, pool, hpool);

		++p4d;
		addr = next;
	} while (addr < end && !ret);

	return ret;
}

static int kernel_duplicate_pgd_range(int node, enum e2k_pt_levels level,
		unsigned long addr, unsigned long end, struct pool *pool, struct pool *hpool)
{
	pgd_t *pgd, *base_pgd;
	unsigned long next;
	int ret = 0;

	base_pgd = init_mm.context.node_pgds[node];
	ret = kernel_duplicate_pgd_page(node, base_pgd, pool);
	if (ret)
		return ret;

	if (level == PT_LEVEL_PGD)
		return 0;

	pgd = base_pgd + pgd_index(addr);

	do {
		BUG_ON(pgd_none(*pgd));

		next = pgd_addr_end(addr, end);

		ret = kernel_duplicate_p4d_range(node, level, pgd, addr, next, pool, hpool);
		if (ret)
			break;
	} while (pgd++, addr = next, addr != end);

	return ret;
}

static int call_duplication_for_each_memory_node(enum e2k_pt_levels level,
						 unsigned long addr, unsigned long end,
						 struct pool *pools[MAX_NUMNODES],
						 struct pool *hpools[MAX_NUMNODES],
						 unsigned long *node_mask)
{
	int ret, node;

	for_each_node_state(node, N_MEMORY) {
		if (!test_bit(node, node_mask))
			continue;

		ret = kernel_duplicate_pgd_range(node, level, addr, end, pools[node], hpools[node]);
		if (ret)
			return ret;
	}

	return 0;
}

static int alloc_duplication_pools(struct pool *pools[MAX_NUMNODES],
				   struct pool *hpools[MAX_NUMNODES],
				   unsigned long start, unsigned long end,
				   bool page_tables_only, unsigned long *node_mask)
{
	int node;
	unsigned long pool_capacity = duplication_pool_pages(start, end, page_tables_only);
	unsigned long hpool_capacity = duplication_pool_huge_pages(start, end, page_tables_only);

	/* Zero pool pointers */
	for (node = 0; node < MAX_NUMNODES; node++) {
		pools[node] = NULL;
		hpools[node] = NULL;
	}

	for_each_node_state(node, N_MEMORY) {
		if (!test_bit(node, node_mask))
			continue;

		if (pool_capacity) {
			pools[node] = pool_create(pool_capacity, 0, POOL_BUDDY, GFP_KERNEL, node);
			if (!pools[node])
				goto alloc_err;
		}

		if (hpool_capacity) {
			hpools[node] = pool_create(hpool_capacity,
						   E2K_LARGE_PAGE_SHIFT - PAGE_SHIFT,
						   POOL_BUDDY, GFP_KERNEL, node);
			if (!hpools[node])
				goto alloc_err;
		}
	}

	return 0;

alloc_err:
	destroy_pools(pools);
	destroy_pools(hpools);

	return -ENOMEM;
}

static void reload_pgd_and_flush(void *unused)
{
	/* Update PT root to point to the duplicated image */
	set_root_pt(mm_node_pgd(&init_mm, numa_node_id()));
	local_flush_tlb_all();
}

/*
 * Do some checks before running kernel memory duplication, preallocated PUD pages
 * duplication or duplication/deduplication of module pages.
 *
 * Returns true if we can continue [de]duplication, false if
 * we need to skip it.
 */
static bool check_duplication(unsigned long addr, size_t size)
{
	unsigned long end = addr + size;

	/*
	 * It seems that duplication does not make sense
	 * on guest where memory nodes are virtual.
	 */
	if (IS_ENABLED(CONFIG_KVM_GUEST_KERNEL) || size == 0)
		return false;

	might_sleep();
	BUG_ON(addr > end || !PAGE_ALIGNED(addr) || !PAGE_ALIGNED(size));

	/*
	 * page_to_nid() for memblock allocated pages will not work for
	 * deferred pages (see CONFIG_DEFERRED_STRUCT_PAGE_INIT), so
	 * avoid calling this function too early in the boot process.
	 */
	BUG_ON(!slab_is_available());

	return true;
}

static bool exceeds_threshold(unsigned long need_pages, unsigned long total_pages,
			      unsigned long free_pages)
{
	/* Set threshold to 1/8 of node memory size */
	unsigned long threshold = total_pages / 8;

	/*
	 * If there are not enough free pages for the new pages allocation
	 * to be under the threshold, reject the allocation.
	 */
	if (free_pages < (total_pages - threshold) + need_pages)
		return true;

	return false;
}

/*
 * Note: deferred initialization of page structures should be already completed,
 * otherwise there may be not enough free memory and threshold check will fail.
 */
static void calculate_duplication_thresholds(unsigned long addr, unsigned long end,
					     bool duplicate_pt, bool duplicate_pages,
					     unsigned long *node_mask)
{
	int node, z;
	unsigned long nr_free_pages, alloc_pages;
	struct zone *zone;
	pg_data_t *cur_node;

	BUG_ON(!duplicate_pt && !duplicate_pages);

	if (!duplicate_pt)
		alloc_pages = (end - addr) >> PAGE_SHIFT;
	else
		alloc_pages = duplication_pool_pages(addr, end, !duplicate_pages);

	for_each_node_state(node, N_MEMORY) {
		nr_free_pages = 0;
		cur_node = NODE_DATA(node);

		for (z = 0; z < MAX_NR_ZONES; z++) {
			zone = cur_node->node_zones + z;

# ifdef CONFIG_ZONE_DEVICE
			if (z == ZONE_DEVICE)
				continue;
# endif

			if (!populated_zone(zone))
				continue;

			nr_free_pages += zone_page_state(zone, NR_FREE_PAGES);
		}

		if (exceeds_threshold(alloc_pages, cur_node->node_present_pages, nr_free_pages))
			pr_alert_once("System has no memory for duplication on node %d\n", node);
		else
			__set_bit(node, node_mask);
	}
}

/**
 * kernel_image_duplicate_page_range - duplicate memory region across NUMA nodes.
 * @_addr - start address
 * @size - size of memory area in bytes
 * @page_tables_only - duplicate page tables but keep only one copy of data
 *
 * Will also update init_mm.context.node_pgds and pgds_nodemask as necessary.
 * Prints a warning if duplication failed.
 */
int kernel_image_duplicate_page_range(void *_addr, size_t size, bool page_tables_only)
{
	unsigned long addr = (unsigned long) _addr;
	unsigned long end = addr + size;
	int ret;
	struct pool *pools[MAX_NUMNODES], *hpools[MAX_NUMNODES];
	unsigned long flags;
	DECLARE_BITMAP(duplication_node_mask, MAX_NUMNODES);

	bitmap_clear(duplication_node_mask, 0, MAX_NUMNODES);

	if (num_node_state(N_MEMORY) < 2)
		return 0;

	if (!check_duplication(addr, size))
		return 0;

	calculate_duplication_thresholds(addr, end, true, !page_tables_only, duplication_node_mask);
	if (find_first_bit(duplication_node_mask, MAX_NUMNODES) == MAX_NUMNODES) {
		pr_alert_once("System has no memory for kernel duplication\n");
		/* No memory can be duplicated; nothing critical, so do not return error */
		return 0;
	}

	ret = alloc_duplication_pools(pools, hpools, addr, end, page_tables_only,
				      duplication_node_mask);
	if (ret) {
		pr_info("Failed to allocate pools for duplication\n");
		return ret;
	}

	raw_spin_lock_irqsave(&kernel_pt_lock, flags);

	/* There can be complex cases, e.g. pgd was already allocated
	 * on node 1, pud was allocatead on node 0 and pmd on node 2.
	 * To handle these we do the duplication one step at a time:
	 * 1) Duplicate all PGDs in range.
	 * 2) Duplicate all PUDs in range.
	 * 3) Duplicate all PMDs in range.
	 * 4) Duplicate all PTEs in range.
	 * 5) Duplicate actual data if requested. */
	ret = call_duplication_for_each_memory_node(PT_LEVEL_PGD, addr, end, pools, hpools,
						    duplication_node_mask);
	ret = ret ?: call_duplication_for_each_memory_node(PT_LEVEL_PUD, addr, end, pools, hpools,
							   duplication_node_mask);
	ret = ret ?: call_duplication_for_each_memory_node(PT_LEVEL_PMD, addr, end, pools, hpools,
							   duplication_node_mask);
	ret = ret ?: call_duplication_for_each_memory_node(PT_LEVEL_PTE, addr, end, pools, hpools,
							   duplication_node_mask);
	if (!ret && !page_tables_only)
		ret = call_duplication_for_each_memory_node(PT_LEVEL_PAGES, addr, end,
							    pools, hpools, duplication_node_mask);

	raw_spin_unlock_irqrestore(&kernel_pt_lock, flags);

	/*
	 * Error may occur during duplications of lower PT levels while upper ones
	 * were duplicated successfully, so update PT root pointers and flush TLBs
	 * regardless of whether there is an error.
	 */
	on_each_cpu(&reload_pgd_and_flush, NULL, 1);

	WARN(ret, "Failed to duplicate 0x%lx - 0x%lx with error %d\n",
			addr, end, ret);

	destroy_pools(pools);
	destroy_pools(hpools);

	WARN_ON_ONCE(schedule_collapse(addr, end));

	return ret;
}
# ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(kernel_image_duplicate_page_range);
# endif
#endif /* CONFIG_NUMA */

#ifdef CONFIG_E2K_MODULES_DUPLICATION
static int alloc_pgd_pools(struct pool *pools[MAX_NUMNODES], unsigned long start, unsigned long end)
{
	int node;
	unsigned long pool_capacity = 1; /* there is only one PGD page */

	/* Zero pool pointers */
	for (node = 0; node < MAX_NUMNODES; node++)
		pools[node] = NULL;

	for_each_node_state(node, N_MEMORY) {
		pools[node] = pool_create(pool_capacity, 0, POOL_BUDDY, GFP_KERNEL, node);
		if (!pools[node])
			goto alloc_err;
	}

	return 0;

alloc_err:
	destroy_pools(pools);

	return -ENOMEM;
}

/*
 * This function duplicates PGD pages. It should be done before anything
 * is mapped into modules area, because mapping to modules area relies on
 * init_mm.context.pgds_nodemask bitmask.
 */
int duplicate_pgds_for_modules_area(void)
{
	unsigned long start = MODULES_VADDR, end = MODULES_END, size = end - start;
	int ret = 0;
	struct pool *pools[MAX_NUMNODES];
	struct pool *hpools[MAX_NUMNODES] = {0};
	unsigned long flags;
	DECLARE_BITMAP(all_nodes, MAX_NUMNODES);

	bitmap_set(all_nodes, 0, MAX_NUMNODES);

	BUG_ON(MODULES_VADDR >= MODULES_END);

	if (!check_duplication(start, size))
		return 0;

	ret = alloc_pgd_pools(pools, start, end);
	if (ret) {
		pr_info("Failed to allocate pools for duplication of PGD pages\n");
		return ret;
	}

	raw_spin_lock_irqsave(&kernel_pt_lock, flags);

	ret = call_duplication_for_each_memory_node(PT_LEVEL_PGD, start, end,
						    pools, hpools, all_nodes);

	raw_spin_unlock_irqrestore(&kernel_pt_lock, flags);

	on_each_cpu(&reload_pgd_and_flush, NULL, 1);

	flush_tlb_kernel_range(start, end);

	destroy_pools(pools);

	return ret;
}

static int duplicate_preallocated_pud_range(int node, p4d_t *p4d, unsigned long addr,
					    unsigned long end, struct pool *pool)
{
	unsigned long next;
	pud_t *pudp, *base_pud;
	int ret = 0;

	base_pud = (pud_t *) p4d_page_vaddr(*p4d);
	ret = kernel_duplicate_pud_page(node, base_pud, p4d, pool);
	if (ret)
		return ret;

	pudp = base_pud + pud_index(addr);
	do {
		if (!pud_none(*pudp)) {
			/* We expect nothing to be mapped into modules area at the moment */
			WARN(1, "Preallocated PUD page have not-none entry");
			return -EINVAL;
		}

		next = pud_addr_end(addr, end);

		++pudp;
		addr = next;
	} while (addr < end);

	return 0;
}

static int duplicate_preallocated_p4d_range(int node, pgd_t *pgd, unsigned long addr,
					    unsigned long end, struct pool *pool)
{
	p4d_t *p4d = p4d_offset(pgd, addr);
	unsigned long next;
	int ret;

	do {
		if (unlikely(p4d_none(*p4d) || kernel_p4d_huge(*p4d)))
			return -EINVAL;

		next = p4d_addr_end(addr, end);

		ret = duplicate_preallocated_pud_range(node, p4d, addr, next, pool);
		if (ret)
			return ret;

		++p4d;
		addr = next;
	} while (addr < end);

	return 0;
}

static int duplicate_preallocated_pgd_range(int node, unsigned long addr, unsigned long end,
					    struct pool *pool)
{
	pgd_t *pgd, *base_pgd;
	unsigned long next;
	int ret;

	base_pgd = init_mm.context.node_pgds[node];
	if (node != page_to_nid(virt_to_page(base_pgd))) {
		WARN(1, "PGD page must be already duplicated");
		return -EINVAL;
	}

	pgd = base_pgd + pgd_index(addr);
	do {
		BUG_ON(pgd_none(*pgd));

		next = pgd_addr_end(addr, end);

		ret = duplicate_preallocated_p4d_range(node, pgd, addr, next, pool);
		if (ret)
			return ret;
	} while (pgd++, addr = next, addr != end);

	return 0;
}

static int alloc_preallocated_pgd_pools(struct pool *pools[MAX_NUMNODES],
					unsigned long start, unsigned long end)
{
	int node;
	unsigned long pool_capacity = pt_pages_nr(start, end, P4D_SHIFT);

	/* Zero pool pointers */
	for (node = 0; node < MAX_NUMNODES; node++)
		pools[node] = NULL;

	for_each_node_state(node, N_MEMORY) {
		if (pool_capacity) {
			pools[node] = pool_create(pool_capacity, 0, POOL_BUDDY, GFP_KERNEL, node);
			if (!pools[node])
				goto alloc_err;
		}
	}

	return 0;

alloc_err:
	destroy_pools(pools);

	return -ENOMEM;
}

int duplicate_preallocated_pgds_for_modules_area(void)
{
	unsigned long start = MODULES_VADDR, end = MODULES_END, size = end - start;
	int node, ret = 0;
	struct pool *pools[MAX_NUMNODES];
	unsigned long flags;

	BUG_ON(MODULES_VADDR >= MODULES_END);

	if (!check_duplication(start, size))
		return 0;

	/* No problem of preallocated pgds if kernel and user have separate PTs */
	if (MMU_IS_SEPARATE_PT())
		return 0;

	ret = alloc_preallocated_pgd_pools(pools, start, end);
	if (ret) {
		pr_info("Failed to allocate pools for duplication of preallocated pgds\n");
		return ret;
	}

	raw_spin_lock_irqsave(&kernel_pt_lock, flags);

	/*
	 * duplicate_preallocated_pgd_range() function assumes that PGD pages
	 * are already duplicated. They are duplicated earlier, see
	 * duplicate_pgds_for_modules_area().
	 */

	for_each_node_mm_pgdmask(node, &init_mm) {
		ret = duplicate_preallocated_pgd_range(node, start, end, pools[node]);
		if (ret)
			break;
	}

	raw_spin_unlock_irqrestore(&kernel_pt_lock, flags);

	/*
	 * Error may occur during duplications of PUD level while PGD level
	 * was duplicated successfully, so update PT root pointers and flush TLBs
	 * regardless of whether there is an error.
	 */
	on_each_cpu(&reload_pgd_and_flush, NULL, 1);

	flush_tlb_kernel_range(start, end);

	destroy_pools(pools);

	return ret;
}

struct module_pages {
	/*
	 * If true, module pages duplication is going on;
	 * otherwise deduplication is going on.
	 */
	bool is_duplicate;
	/*
	 * List of page_duplication structures that describe original pages
	 * and their copies. New entries are added to this list during the
	 * duplication of module pages and removed during deduplication.
	 */
	struct list_head *duplicated_pages;

	union {
		/* Use when is_duplicate == true */
		struct {
			/* pool of small pages */
			struct pool *pool;
			/* pool of huge pages */
			struct pool *hpool;
			/* pool of page_duplication structures */
			struct pool *pdpool;
		};
		/* Use when is_duplicate == false */
		struct {
			/*
			 * List of data to be freed after kernel_pt_lock is released.
			 * List entries are page_duplication structures removed from
			 * 'duplicated_pages' with a pointer to small or huge page
			 * that also must be freed after kernel_pt_lock is released.
			 */
			struct list_head *pdlist;
		};
	};
};

static int module_duplicate_one_page(int node, pte_t *ptep, struct module_pages *module_pages)
{
	int page_node = page_to_nid(pte_page(*ptep));
	void *dup_addr;
	struct page_duplication *item;

	BUG_ON(!module_pages->is_duplicate);

	if (page_node != node) {
		dup_addr = sma_alloc_page__pool(module_pages->pool, node, PT_LEVEL_PAGES);
		if (!dup_addr)
			return -ENOMEM;

		item = pool_get(module_pages->pdpool);
		if (!item) {
			pool_put(module_pages->pool, dup_addr);
			return -ENOMEM;
		}

		tagged_memcpy_8(dup_addr, (void *) pte_page_vaddr(*ptep), PTE_SIZE);

		smp_wmb(); /* See comment in pmd_install() */

		item->orig = pte_page(*ptep);
		item->copy = virt_to_page(dup_addr);
		item->is_huge = false;
		set_pte(ptep, mk_pte_phys(__pa(dup_addr), pte_pgprot(*ptep)));

		list_add(&item->list, module_pages->duplicated_pages);
	}

	return 0;
}

static int module_deduplicate_one_page(pte_t *ptep, struct module_pages *module_pages)
{
	struct page_duplication *item;

	BUG_ON(module_pages->is_duplicate);

	item = find_page_in_duplicated_pages_list(module_pages->duplicated_pages, pte_page(*ptep));
	if (item) {
		BUG_ON(item->is_huge);

		set_pte(ptep, mk_pte_phys(page_to_phys(item->orig), pte_pgprot(*ptep)));

		list_move(&item->list, module_pages->pdlist);
	}

	return 0;
}

static int handle_module_pages_pte_range(int node, pmd_t *pmd, unsigned long addr,
					 unsigned long end, struct module_pages *module_pages)
{
	pte_t *ptep, *base_pte;
	int ret;

	base_pte = (pte_t *) pmd_page_vaddr(*pmd);
	if (node != page_to_nid(virt_to_page(base_pte))) {
		WARN(1, "PTE page is located on incorrect node");
		return -EINVAL;
	}

	ptep = base_pte + pte_index(addr);
	do {
		if (pte_none(*ptep))
			return -EINVAL;

		if (module_pages->is_duplicate)
			ret = module_duplicate_one_page(node, ptep, module_pages);
		else
			ret = module_deduplicate_one_page(ptep, module_pages);
		if (ret)
			return ret;
	} while (ptep++, addr += PAGE_SIZE, addr < end);

	return 0;
}

static int module_duplicate_huge_pmd(int node, pmd_t *pmd, struct module_pages *module_pages)
{
	int hpage_node = page_to_nid(pmd_page(*pmd));
	void *dup_addr;
	struct page_duplication *item;

	BUG_ON(!module_pages->is_duplicate);

	if (hpage_node != node) {
		dup_addr = sma_alloc_page__pool(module_pages->hpool, node, PT_LEVEL_PAGES);
		if (!dup_addr)
			return -ENOMEM;

		BUG_ON(!IS_ALIGNED((unsigned long)dup_addr, PMD_SIZE));

		item = pool_get(module_pages->pdpool);
		if (!item) {
			pool_put(module_pages->hpool, dup_addr);
			return -ENOMEM;
		}

		tagged_memcpy_8(dup_addr, (void *) pmd_page_vaddr(*pmd), PMD_SIZE);

		smp_wmb(); /* See comment in pmd_install() */

		item->orig = pmd_page(*pmd);
		item->copy = dup_addr;
		item->is_huge = true;
		set_pmd(pmd, pmd_mkhuge(mk_pmd_phys(__pa(dup_addr), pmd_pgprot(*pmd))));

		list_add(&item->list, module_pages->duplicated_pages);
	}

	return 0;
}

static int module_deduplicate_huge_pmd(pmd_t *pmdp, struct module_pages *module_pages)
{
	struct page_duplication *item;

	BUG_ON(module_pages->is_duplicate);

	item = find_page_in_duplicated_pages_list(module_pages->duplicated_pages, pmd_page(*pmdp));
	if (item) {
		BUG_ON(!item->is_huge);

		set_pmd(pmdp, pmd_mkhuge(mk_pmd_phys(page_to_phys(item->orig), pmd_pgprot(*pmdp))));

		list_move(&item->list, module_pages->pdlist);
	}

	return 0;
}

static int handle_module_pages_pmd_range(int node, pud_t *pud, unsigned long addr,
					 unsigned long end, struct module_pages *module_pages)
{
	pmd_t *pmdp, *base_pmd;
	unsigned long next;
	e2k_size_t page_size;
	int ret;

	base_pmd = (pmd_t *) pud_page_vaddr(*pud);
	if (node != page_to_nid(virt_to_page(base_pmd))) {
		WARN(1, "PMD page is located on incorrect node");
		return -EINVAL;
	}

	pmdp = base_pmd + pmd_index(addr);
	do {
		if (pmd_none(*pmdp))
			return -EINVAL;

		next = pmd_addr_end(addr, end);

		if (!kernel_pmd_huge(*pmdp)) {
			ret = handle_module_pages_pte_range(node, pmdp, addr, next, module_pages);
		} else {
			page_size = get_pmd_level_page_size();
			if (!IS_ALIGNED(addr, page_size) || addr + page_size > next) {
				WARN(1, "Huge PMD page should be split already");
				return -EINVAL;
			}
			if (module_pages->is_duplicate)
				ret = module_duplicate_huge_pmd(node, pmdp, module_pages);
			else
				ret = module_deduplicate_huge_pmd(pmdp, module_pages);
		}
		if (ret)
			return ret;

		++pmdp;
		addr = next;
	} while (addr < end);

	return 0;
}

static int handle_module_pages_pud_range(int node, p4d_t *p4d, unsigned long addr,
					 unsigned long end, struct module_pages *module_pages)
{
	unsigned long next;
	pud_t *pudp, *base_pud;
	e2k_size_t page_size;

	base_pud = (pud_t *) p4d_page_vaddr(*p4d);
	if (node != page_to_nid(virt_to_page(base_pud))) {
		WARN(1, "PUD page is located on incorrect node");
		return -EINVAL;
	}

	pudp = base_pud + pud_index(addr);
	do {
		if (pud_none(*pudp))
			return -EINVAL;

		next = pud_addr_end(addr, end);

		if (!kernel_pud_huge(*pudp)) {
			int ret = handle_module_pages_pmd_range(node, pudp, addr, next,
								module_pages);

			if (ret)
				return ret;
		} else {
			page_size = get_pud_level_page_size();
			if (addr & (page_size - 1) || addr + page_size > next) {
				WARN(1, "Huge PUD page should be split already");
				return -EINVAL;
			}

			/*
			 * Huge PUD pages are not duplicated. Getting here is a bug for
			 * modules area, because it should be fully duplicated.
			 */
			BUG();
		}
		++pudp;
		addr = next;
	} while (addr < end);

	return 0;
}
static int handle_module_pages_p4d_range(int node, pgd_t *pgd, unsigned long addr,
					 unsigned long end, struct module_pages *module_pages)
{
	p4d_t *p4d = p4d_offset(pgd, addr);
	unsigned long next;
	int ret;

	do {
		if (unlikely(p4d_none(*p4d) || kernel_p4d_huge(*p4d)))
			return -EINVAL;

		next = p4d_addr_end(addr, end);

		ret = handle_module_pages_pud_range(node, p4d, addr, next, module_pages);
		if (ret)
			return ret;
	} while (p4d++, addr = next, addr < end);

	return 0;
}

static int handle_module_pages_pgd_range(int node, unsigned long addr, unsigned long end,
					 struct module_pages *module_pages)
{
	pgd_t *pgd, *base_pgd;
	unsigned long next;
	int ret;

	base_pgd = init_mm.context.node_pgds[node];
	if (node != page_to_nid(virt_to_page(base_pgd))) {
		WARN(1, "PGD page is located on incorrect node");
		return -EINVAL;
	}

	pgd = base_pgd + pgd_index(addr);

	do {
		BUG_ON(pgd_none(*pgd));

		next = pgd_addr_end(addr, end);

		ret = handle_module_pages_p4d_range(node, pgd, addr, next, module_pages);
		if (ret)
			return ret;
	} while (pgd++, addr = next, addr != end);

	return 0;
}

static int alloc_module_pages_pools(struct pool *pools[MAX_NUMNODES],
				    struct pool *hpools[MAX_NUMNODES],
				    unsigned long start, unsigned long end,
				    unsigned long *node_mask)
{
	int node;
	unsigned long pool_capacity = (end - start) >> PAGE_SHIFT;
	unsigned long hpool_capacity = duplication_pool_huge_pages(start, end, false);

	/* Zero pool pointers */
	for (node = 0; node < MAX_NUMNODES; node++) {
		pools[node] = NULL;
		hpools[node] = NULL;
	}

	for_each_node_mm_pgdmask(node, &init_mm) {
		if (!test_bit(node, node_mask))
			continue;

		if (pool_capacity) {
			pools[node] = pool_create(pool_capacity, 0, POOL_BUDDY, GFP_KERNEL, node);
			if (!pools[node])
				goto alloc_err;
		}

		if (hpool_capacity) {
			hpools[node] = pool_create(hpool_capacity,
						   E2K_LARGE_PAGE_SHIFT - PAGE_SHIFT,
						   POOL_BUDDY, GFP_KERNEL, node);
			if (!hpools[node])
				goto alloc_err;
		}
	}

	return 0;

alloc_err:
	destroy_pools(pools);
	destroy_pools(hpools);

	return -ENOMEM;
}

static void free_pdlist(struct list_head *pdlist)
{
	struct page_duplication *item, *tmp;

	list_for_each_entry_safe(item, tmp, pdlist, list) {
		if (item->is_huge)
			__free_pages(item->copy, get_order(PMD_SIZE));
		else
			sma_free_page__no_pool(PT_LEVEL_PAGES, page_to_virt(item->copy));

		list_del(&item->list);
		kfree(item);
	}
}

static unsigned int handle_module_pages(unsigned long addr, unsigned long end,
					bool duplicate, struct list_head *duplicated_pages,
					unsigned long *node_mask)
{
	int node, ret = 0;
	struct pool *pools[MAX_NUMNODES], *hpools[MAX_NUMNODES], *pdpool;
	LIST_HEAD(pdlist);
	unsigned long flags;

	if (duplicate) {
		ret = alloc_module_pages_pools(pools, hpools, addr, end, node_mask);
		if (ret) {
			pr_info("Failed to allocate pools for module pages\n");
			return ret;
		}

		/*
		 * No problem if we don't take into account the node_mask and allocate
		 * a bit more page_duplication structures than we actually need.
		 */
		pdpool = pool_create(((end - addr) >> PAGE_SHIFT) * num_node_state(N_MEMORY),
				     sizeof(struct page_duplication), POOL_SLAB, GFP_KERNEL,
				     NUMA_NO_NODE);
		if (!pdpool) {
			pr_info("Failed to allocate pools for module pages\n");
			destroy_pools(pools);
			destroy_pools(hpools);
			return -ENOMEM;
		}
	}

	raw_spin_lock_irqsave(&kernel_pt_lock, flags);

	for_each_node_mm_pgdmask(node, &init_mm) {
		struct module_pages module_pages;

		if (duplicate && !test_bit(node, node_mask))
			continue;

		module_pages.is_duplicate = duplicate;
		module_pages.duplicated_pages = duplicated_pages;

		if (duplicate) {
			module_pages.pool = pools[node];
			module_pages.hpool = hpools[node];
			module_pages.pdpool = pdpool;
		} else {
			module_pages.pdlist = &pdlist;
		}

		ret = handle_module_pages_pgd_range(node, addr, end, &module_pages);
		if (ret)
			break;
	}

	raw_spin_unlock_irqrestore(&kernel_pt_lock, flags);

	/* Flush TLB before freeing deduplicated pages */
	flush_tlb_kernel_range(addr, end);

	if (duplicate) {
		destroy_pools(pools);
		destroy_pools(hpools);
		pool_destroy(pdpool);
	} else {
		/*
		 * Free pages and page_duplication structures after kernel_pt_lock
		 * is released because freeing can call set_memory_*() and cause
		 * a deadlock on kernel_pt_lock.
		 */
		free_pdlist(&pdlist);
	}

	return ret;
}

/**
 * duplicate_module_pages - duplicate pages in given module memory range.
 * @_addr - start address
 * @size - size of memory area in bytes
 * @duplicated_pages - module's list of duplicated pages
 *
 * Page table for the module was duplicated while mapping. This function
 * is used to duplicate module's pages. Also, we have to save pairs
 * (page copy, original page) for each duplicated page to the list
 * 'duplicated_pages'.
 */
int duplicate_module_pages(void *_addr, size_t size, struct list_head *duplicated_pages)
{
	unsigned long addr = (unsigned long) _addr;
	unsigned long end = addr + size;
	int ret;
	DECLARE_BITMAP(duplication_node_mask, MAX_NUMNODES);

	memset(duplication_node_mask, 0, sizeof(duplication_node_mask));

	if (kernel_duplicated_nodes_num() < 2)
		return 0;

	if (!check_duplication(addr, size))
		return 0;

	calculate_duplication_thresholds(addr, end, false, true, duplication_node_mask);
	if (find_first_bit(duplication_node_mask, MAX_NUMNODES) == MAX_NUMNODES) {
		pr_alert_once("System has no memory for modules duplication\n");
		/* No memory can be duplicated; nothing critical, so do not return error */
		return 0;
	}

	/* This function should be called only on modules area */
	if (addr < MODULES_VADDR || end > MODULES_END) {
		WARN(1, "Incorrect range for duplication: [0x%lx, 0x%lx)", addr, end);
		return -EINVAL;
	}

	ret = handle_module_pages(addr, end, true, duplicated_pages, duplication_node_mask);

	return ret;
}
# ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(duplicate_module_pages);
# endif

/**
 * deduplicate_module_pages - deduplicate pages in given module memory range.
 * @_addr - start address
 * @size - size of memory area in bytes
 * @duplicated_pages - module's list of duplicated pages
 *
 * This function traverses module's page table, finds PTE entries pointing to
 * duplicated pages and makes them point to original pages. Page is assumed
 * to be duplicated if it is found in list of duplicated pages in 'mod'.
 * Duplicated pages are then freed. Original pages are unmapped and freed
 * later when module memory is vfree()'ed.
 */
void deduplicate_module_pages(void *_addr, size_t size, struct list_head *duplicated_pages)
{
	unsigned long addr = (unsigned long) _addr, end = addr + size;

	if (kernel_duplicated_nodes_num() < 2)
		return;

	if (!check_duplication(addr, size))
		return;

	/* This function should be called only on modules area */
	if (addr < MODULES_VADDR || end > MODULES_END) {
		WARN(1, "Incorrect range for deduplication: [0x%lx, 0x%lx)", addr, end);
		return;
	}

	handle_module_pages(addr, end, false, duplicated_pages, NULL);
}
# ifdef CONFIG_TEST_KERNEL_PT_SYNC_MODULE
EXPORT_SYMBOL(deduplicate_module_pages);
# endif
#endif /* CONFIG_E2K_MODULES_DUPLICATION */

#ifdef CONFIG_ARCH_HAS_SET_DIRECT_MAP
int set_direct_map_invalid_noflush(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);
	return set_memory_np_noflush(addr, 1);
}

int set_direct_map_default_noflush(struct page *page)
{
	unsigned long addr = (unsigned long)page_address(page);

	if (IS_ENABLED(CONFIG_SEMI_SPECULATIVE_KERNEL)) {
		/*
		 * We cannot fully support this API without flushes
		 * because semi-speculative loads will:
		 * - PTE.valid=0: cache in TLB
		 * - PTE.valid=1 & PTE.present=0: trigger page fault
		 *
		 * So there is no invalid PTE value without side effects.
		 */
		return set_memory_p(addr, 1);
	} else {
		return set_memory_p_noflush(addr, 1);
	}
}

/*
 * Used:
 *
 * 1) When built with CONFIG_DEBUG_PAGEALLOC and CONFIG_HIBERNATION, this
 * function is used to determine if a linear map page has been marked as
 * not-valid by CONFIG_DEBUG_PAGEALLOC.
 *
 * 2) By hibernation to skip kfence's guard pages.
 */
bool kernel_page_present(struct page *page)
{
	unsigned long addr = (unsigned long) page_address(page);
	probe_entry_t entry = get_MMU_DTLB_ENTRY(addr);
	return DTLB_ENTRY_TEST_SUCCESSFUL(entry) && DTLB_ENTRY_TEST_VVA(entry);
}
#endif
