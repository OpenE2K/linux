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
	void *address;
	gfp_t gfp = GFP_KERNEL_ACCOUNT;

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

	address = page_address(page);
	memset64(address, (mm != &init_mm) ? _PAGE_INIT_VALID : 0, PTRS_PER_PUD);
	return address;
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
	void *address;
	gfp_t gfp = GFP_KERNEL_ACCOUNT;

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

	address = page_address(page);
	memset64(address, (mm != &init_mm) ? _PAGE_INIT_VALID : 0, PTRS_PER_PUD);
	return address;
}

static inline pmd_t *pmd_alloc_one(const struct mm_struct *mm,
		unsigned long addr)
{
	return pmd_alloc_one_node(mm, NUMA_NO_NODE);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	struct page *page = virt_to_page(pmd);

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
	__free_page(virt_to_page(pte));
}

static inline pgtable_t pte_alloc_one(struct mm_struct *mm)
{
	struct page *page = alloc_page(GFP_KERNEL_ACCOUNT);
	if (unlikely(!page))
		return NULL;

	if (unlikely(!pgtable_pte_page_ctor(page))) {
		__free_page(page);
		return NULL;
	}

	memset64(page_address(page), _PAGE_INIT_VALID, PTRS_PER_PTE);
	return page;
}

static inline void pte_free(struct mm_struct *mm, pgtable_t pte_page)
{
	BUILD_BUG_ON(PTRS_PER_PTE * sizeof(pte_t) != PAGE_SIZE);
	pgtable_pte_page_dtor(pte_page);
	__free_page(pte_page);
}

static inline void p4d_populate_kernel(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	BUG_ON(mm != &init_mm);

#ifdef CONFIG_NUMA
	int node, index;
	pgd_t *pgd = p4dp_to_pgdp(p4d);

	/* Set all pgds (one for each node) */
	index = pgd - mm->pgd;
	for_each_node_mm_pgdmask(node, mm) {
		pgd_t *node_pgd = mm->context.node_pgds[node] + index;
		p4d_set_k(pgdp_to_p4dp(node_pgd), pud);
		virt_kernel_p4d_populate(mm, pgdp_to_p4dp(node_pgd));
	}
#else
	p4d_set_k(p4d, pud);
	virt_kernel_p4d_populate(mm, p4d);
#endif
}

static inline void p4d_populate_user(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
#ifdef CONFIG_NUMA
	if (!MMU_IS_SEPARATE_PT()) {
		int node, index;
		pgd_t *pgd = p4dp_to_pgdp(p4d);

		/* Set all pgds (one for each node) */
		index = pgd - mm->pgd;
		for_each_node_mm_pgdmask(node, mm) {
			pgd_t *node_pgd = mm->context.node_pgds[node] + index;
			p4d_set_u(pgdp_to_p4dp(node_pgd), pud);
			virt_kernel_p4d_populate(mm, pgdp_to_p4dp(node_pgd));
		}

		return;
	}
#endif

	p4d_set_u(p4d, pud);
	virt_kernel_p4d_populate(mm, p4d);
}

static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	BUG_ON(!mm);

	if (unlikely(mm == &init_mm))
		p4d_populate_kernel(mm, p4d, pud);
	else
		p4d_populate_user(mm, p4d, pud);
}

static inline void p4d_populate_user_not_present(struct mm_struct *mm, e2k_addr_t addr, p4d_t *p4d)
{
#ifdef CONFIG_NUMA
	if (!MMU_IS_SEPARATE_PT()) {
		int node, index;

		/* Set all pgds (one for each node) */
		index = p4dp_to_pgdp(p4d) - mm->pgd;
		for_each_node_mm_pgdmask(node, mm) {
			pgd_t *node_pgd = mm->context.node_pgds[node] + index;
			validate_p4d_at(mm, addr, pgdp_to_p4dp(node_pgd));
		}

		return;
	}
#endif
	validate_p4d_at(mm, addr, p4d);
}

static inline void
pud_populate_kernel(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set_k(pud, pmd);
}

static inline void
pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	BUG_ON(mm == NULL);
	if (unlikely(mm == &init_mm)) {
		pud_set_k(pud, pmd);
	} else {
		pud_set_u(pud, pmd);
	}
}

static inline void
pmd_populate_kernel(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
{
	pmd_set_k(pmd, pte);
}

#define pmd_pgtable(pmd) pmd_page(pmd)

static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmdp, pgtable_t pte_page)
{
	pte_t *ptep = (pte_t *)page_address(pte_page);
	if (unlikely(mm == &init_mm)) {
		pmd_set_k(pmdp, ptep);
	} else {
		pmd_set_u(pmdp, ptep);
	}
}

#endif /* _E2K_PGALLOC_H */
