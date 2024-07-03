/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * The functions and defines necessary to allocate page tables.
 */

#ifndef _E2K_PGALLOC_H
#define _E2K_PGALLOC_H

#include <linux/mm.h>
#include <linux/threads.h>
#include <linux/vmalloc.h>

#include <asm/types.h>
#include <asm/errors_hndl.h>
#include <asm/processor.h>
#include <asm/head.h>
#include <asm/page.h>
#include <asm/pgtable_def.h>
#include <asm/mman.h>
#include <asm/mmu_context.h>
#include <asm/mmu_types.h>
#include <asm/console.h>
#include <asm/smp.h>
#include <asm/tlbflush.h>
#include <asm/e2k_debug.h>
#include <asm/mmzone.h>
#include <asm/kvm/gmmu_context.h>

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* page table */
#define	DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

extern struct cpuinfo_e2k cpu_data[NR_CPUS];

static inline void pgd_ctor(const struct mm_struct *mm, int node, pgd_t *pgd)
{
	int root_pt_index;

	if (!MMU_IS_SEPARATE_PT() && mm != &init_mm) {
		const pgd_t *kernel_pgd;

		/* Although we manually switch kernel and user page tables,
		 * there is a small window between entering kernel and writing
		 * %root_ptb (and same window on exit and also in get_user())
		 * where user task will access kernel memory and page tables
		 * are not switched yet.
		 * So we initialize user's root page table with kernel's pgds.
		 *
		 * Also this is needed for fast system calls to work. */
		if (node == NUMA_NO_NODE)
			node = numa_node_id();
		kernel_pgd = mm_node_pgd(&init_mm, node);
		memcpy(&pgd[USER_PTRS_PER_PGD], &kernel_pgd[USER_PTRS_PER_PGD],
				KERNEL_PTRS_PER_PGD * sizeof(pgd_t));
	}

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (!cpu_has(CPU_FEAT_ISET_V6)) {
		root_pt_index = pgd_index(MMU_UNITED_USER_VPTB);

		/* One PGD entry is the VPTB self-map. */
		vmlpt_pgd_set(&pgd[root_pt_index], pgd);
	}
}

static inline pgd_t *pgd_alloc_node(struct mm_struct *mm, int node)
{
	pgd_t *pgd;
	struct page *page;
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;

	if (node != NUMA_NO_NODE) {
		/* We need __GFP_THISNODE because kernel_image_duplicate_page_range()
		 * will work only when every N_MEMORY node uses it's own memory,
		 * otherwise there will be a memory leak: the checks for node on which
		 * page table is allocated could return another node in which case
		 * the function assumes that page hasn't been duplicated, and this
		 * assumption works only when each node's duplicated page tables
		 * reside strictly on that node's memory. */
		gfp |= __GFP_THISNODE;
		page = alloc_pages_node(node, gfp, 0);
	} else {
		page = alloc_page(gfp);
	}
	if (unlikely(!page))
		return NULL;

	pgd = (pgd_t *) page_address(page);
	pgd_ctor(mm, node, pgd);
	return pgd;
}

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	return pgd_alloc_node(mm, NUMA_NO_NODE);
}

static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	BUILD_BUG_ON(PTRS_PER_PGD * sizeof(pgd_t) != PAGE_SIZE);
	free_page((unsigned long) pgd);
}

static inline pud_t *pud_alloc_one_node(struct mm_struct *mm, int node)
{
	struct page *page;
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;

	if (node != NUMA_NO_NODE) {
		gfp |= __GFP_THISNODE;
		page = alloc_pages_node(node, gfp, 0);
	} else {
		page = alloc_page(gfp);
	}
	if (unlikely(!page))
		return NULL;

	return (pud_t *) page_address(page);
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	return pud_alloc_one_node(mm, NUMA_NO_NODE);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	BUILD_BUG_ON(PTRS_PER_PUD * sizeof(pud_t) != PAGE_SIZE);
	free_page((unsigned long) pud);
}

static inline pmd_t *pmd_alloc_one_node(const struct mm_struct *mm, int node)
{
	struct page *page;
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;

	if (node != NUMA_NO_NODE) {
		gfp |= __GFP_THISNODE;
		page = alloc_pages_node(node, gfp, 0);
	} else {
		page = alloc_page(gfp);
	}
	if (unlikely(!page))
		return NULL;

	if (unlikely(!pgtable_pmd_page_ctor(page))) {
		__free_page(page);
		return NULL;
	}

	return (pmd_t *) page_address(page);
}

static inline pmd_t *pmd_alloc_one(const struct mm_struct *mm,
		unsigned long addr)
{
	return pmd_alloc_one_node(mm, NUMA_NO_NODE);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	struct page *page = phys_to_page(__pa(pmd));

	BUILD_BUG_ON(PTRS_PER_PMD * sizeof(pmd_t) != PAGE_SIZE);
	pgtable_pmd_page_dtor(page);
	__free_page(page);
}

static inline pte_t *pte_alloc_one_kernel_node(
		const struct mm_struct *mm, int node)
{
	struct page *page;
	gfp_t gfp = GFP_KERNEL | __GFP_ZERO;

	if (node != NUMA_NO_NODE) {
		gfp |= __GFP_THISNODE;
		page = alloc_pages_node(node, gfp, 0);
	} else {
		page = alloc_page(gfp);
	}
	if (unlikely(!page))
		return NULL;

	return (pte_t *) page_address(page);
}

static inline pte_t *pte_alloc_one_kernel(const struct mm_struct *mm)
{
	return pte_alloc_one_kernel_node(mm, NUMA_NO_NODE);
}

static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	__free_page(phys_to_page(__pa(pte)));
}

static inline pgtable_t pte_alloc_one(struct mm_struct *mm)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (unlikely(!page))
		return NULL;

	if (unlikely(!pgtable_pte_page_ctor(page))) {
		__free_page(page);
		return NULL;
	}

	return page;
}

static inline void pte_free(struct mm_struct *mm, pgtable_t pte_page)
{
	BUILD_BUG_ON(PTRS_PER_PTE * sizeof(pte_t) != PAGE_SIZE);
	pgtable_pte_page_dtor(pte_page);
	__free_page(pte_page);
}

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
static inline void
pud_page_validate(pgd_t *pgdp, pud_t *pudp)
{
	int i;

	if (pgd_val(*pgdp) != _PAGE_INIT_VALID)
		return;
	trace_pt_update("Validating pud page at 0x%lx (pgd at 0x%lx = 0x%lx)\n",
			pudp, pgdp, pgd_val(*pgdp));
	for (i = 0; i < PTRS_PER_PUD; i++, pudp++) {
		WARN_ON(pud_val(*pudp));
		*pudp = __pud(_PAGE_INIT_VALID);
	}
}
#else	/* ! CONFIG_MAKE_ALL_PAGES_VALID */
static inline void
pud_page_validate(pgd_t *pgdp, pud_t *pudp)
{
	/* nothing to do */
}
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

static inline void
pgd_populate_kernel(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	BUG_ON(mm != &init_mm);

#ifdef CONFIG_NUMA
	int node, index;

	/* Set all pgds (one for each node) */
	index = pgd - mm->pgd;
	for_each_node_mm_pgdmask(node, mm) {
		pgd_t *node_pgd = mm->context.node_pgds[node] + index;
		pgd_set_k(node_pgd, pud);
		virt_kernel_pgd_populate(mm, node_pgd);
	}
#else
	pgd_set_k(pgd, pud);
	virt_kernel_pgd_populate(mm, pgd);
#endif
}

static inline void kvm_pgd_populate_user(pgd_t *pgd, pud_t *pud)
{
	pud_page_validate(pgd, pud);
	pgd_set_u(pgd, pud);
}

static inline void pgd_populate_user(struct mm_struct *mm,
		pgd_t *pgd, pud_t *pud)
{
	pud_page_validate(pgd, pud);

#ifdef CONFIG_NUMA
	if (!MMU_IS_SEPARATE_PT()) {
		int node, index;

		/* Set all pgds (one for each node) */
		index = pgd - mm->pgd;
		for_each_node_mm_pgdmask(node, mm) {
			pgd_t *node_pgd = mm->context.node_pgds[node] + index;
			pgd_set_u(node_pgd, pud);
			virt_kernel_pgd_populate(mm, node_pgd);
		}

		return;
	}
#endif

	pgd_set_u(pgd, pud);
	virt_kernel_pgd_populate(mm, pgd);
}

static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	BUG_ON(!mm);

	if (unlikely(mm == &init_mm))
		pgd_populate_kernel(mm, pgd, pud);
	else
		pgd_populate_user(mm, pgd, pud);
}

static inline void pgd_populate_user_not_present(struct mm_struct *mm,
		e2k_addr_t addr, pgd_t *pgd)
{
#ifdef CONFIG_NUMA
	if (!MMU_IS_SEPARATE_PT()) {
		int node, index;

		/* Set all pgds (one for each node) */
		index = pgd - mm->pgd;
		for_each_node_mm_pgdmask(node, mm) {
			pgd_t *node_pgd = mm->context.node_pgds[node] + index;
			validate_pgd_at(mm, addr, node_pgd);
		}

		return;
	}
#endif
	validate_pgd_at(mm, addr, pgd);
}

static inline void
pud_populate_kernel(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set_k(pud, pmd);
}

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
static inline void
pmd_page_validate(pud_t *pudp, pmd_t *pmdp)
{
	int	i;

	if (pud_val(*pudp) != _PAGE_INIT_VALID)
		return;

	trace_pt_update("Validating pmd page at 0x%lx (pud at 0x%lx = 0x%lx)\n",
			pmdp, pudp, pud_val(*pudp));
	for (i = 0; i < PTRS_PER_PMD; i++, pmdp++) {
		WARN_ON(pmd_val(*pmdp));
		*pmdp = __pmd(_PAGE_INIT_VALID);
	}
}
#else	/* ! CONFIG_MAKE_ALL_PAGES_VALID */
static inline void
pmd_page_validate(pud_t *pudp, pmd_t *pmdp)
{
	/* nothing to do */
}
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

static inline void
pud_populate_user(pud_t *pud, pmd_t *pmd)
{
	pmd_page_validate(pud, pmd);
	pud_set_u(pud, pmd);
}

static inline void
pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	BUG_ON(mm == NULL);
	if (unlikely(mm == &init_mm)) {
		pud_set_k(pud, pmd);
		return;
	}
	pud_populate_user(pud, pmd);
}

static inline void
pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
{
	pmd_set_k(pmd, pte);
}

#ifdef CONFIG_MAKE_ALL_PAGES_VALID
static inline void
pte_page_validate(pmd_t *pmdp, pte_t *ptep)
{
	int	i;

	if (pmd_val(*pmdp) != _PAGE_INIT_VALID)
		return;

	trace_pt_update("Validating pte page at 0x%lx (pmd at 0x%lx = 0x%lx)\n",
			ptep, pmdp, pmd_val(*pmdp));
	for (i = 0; i < PTRS_PER_PTE; i++, ptep++)
		*ptep = pte_mkvalid(*ptep);
}
#else	/* ! CONFIG_MAKE_ALL_PAGES_VALID */
static inline void
pte_page_validate(pmd_t *pmdp, pte_t *ptep)
{
	/* nothing to do */
}
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */

#define pmd_pgtable(pmd) pmd_page(pmd)

static inline void
pmd_populate_user(pmd_t *pmd, pte_t *pte)
{
	pte_page_validate(pmd, pte);
	pmd_set_u(pmd, pte);
}
static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmd, pgtable_t pte)
{
	BUG_ON(mm == NULL);

	if (unlikely(mm == &init_mm)) {
		pmd_set_k(pmd, (pte_t *)page_address(pte));
		return;
	}
	pmd_populate_user(pmd, page_address(pte));
}

#endif /* _E2K_PGALLOC_H */
