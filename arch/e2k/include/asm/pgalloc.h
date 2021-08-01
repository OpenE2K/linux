/*
 * pgalloc.h: the functions and defines necessary to allocate
 * page tables.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
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

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* page table */
#define	DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

#undef	DEBUG_PA_MODE
#undef	DebugPA
#define	DEBUG_PA_MODE		0	/* page table allocation */
#define DebugPA(...)		DebugPrint(DEBUG_PA_MODE ,##__VA_ARGS__)

extern struct cpuinfo_e2k cpu_data[NR_CPUS];

extern void __init *node_early_get_zeroed_page(int nid);

extern int mem_init_done;

static inline void pgd_ctor(pgd_t *pgd)
{
	int root_pt_index;
	pgd_t *init_pgd;

	init_pgd = node_pgd_offset_kernel(numa_node_id(), 0UL);

	if (MMU_IS_SEPARATE_PT()) {
		root_pt_index = pgd_index(USER_VPTB_BASE_ADDR);
	} else {
		/*
		 * Check for whether we use mm->pgd to store kernel's pgd.
		 * If (COPY_USER_PGD_TO_KERNEL_ROOT_PT && THERE_IS_DUP_KERNEL),
		 * then kernel's pgd are kept in per-cpu pagetables.
		 */
		if (!IS_ENABLED(CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT) ||
		    !THERE_IS_DUP_KERNEL)
			copy_kernel_pgd_range(pgd, init_pgd);
		root_pt_index = pgd_index(MMU_UNITED_USER_VPTB);
	}
	/* One PGD entry is the VPTB self-map. */
	vmlpt_pgd_set(&pgd[root_pt_index], pgd);
}

static inline pgd_t *pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;
	gfp_t gfp = GFP_KERNEL_ACCOUNT;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;

	pgd = (pgd_t *) get_zeroed_page(gfp);
	if (!pgd)
		return NULL;

	pgd_ctor(pgd);

	return pgd;
}

static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	BUILD_BUG_ON(PTRS_PER_PGD * sizeof(pgd_t) != PAGE_SIZE);
	free_page((unsigned long) pgd);
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;

	return (pud_t *) get_zeroed_page(gfp);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	BUILD_BUG_ON(PTRS_PER_PUD * sizeof(pud_t) != PAGE_SIZE);
	free_page((unsigned long) pud);
}

static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	struct page *page;
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;
	page = alloc_page(gfp);
	if (unlikely(!page))
		return NULL;
	if (unlikely(!pgtable_pmd_page_ctor(page))) {
		__free_page(page);
		return NULL;
	}

	return (pmd_t *) page_address(page);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	struct page *page = phys_to_page(__pa(pmd));

	BUILD_BUG_ON(PTRS_PER_PMD * sizeof(pmd_t) != PAGE_SIZE);
	pgtable_pmd_page_dtor(page);
	__free_page(page);
}

static inline pte_t *pte_alloc_one_kernel(struct mm_struct *mm)
{
	struct page *page;

	page = alloc_page(GFP_KERNEL | __GFP_ZERO);
	if (unlikely(!page))
		return NULL;

	return (pte_t *) page_address(page);
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
	int	i;

	if (pgd_val(*pgdp) != _PAGE_INIT_VALID)
		return;
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
	pgd_set_k(pgd, pud);
	virt_kernel_pgd_populate(mm, pgd);
}

static inline void
pgd_populate_user(pgd_t *pgd, pud_t *pud)
{
	pud_page_validate(pgd, pud);
	pgd_set_u(pgd, pud);
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
static inline bool
pgd_populate_cpu_root_pt(struct mm_struct *mm, pgd_t *pgd)
{
	unsigned long pgd_ind;
	pgd_t *cpu_pgd;
	bool only_populate;

	if (MMU_IS_SEPARATE_PT())
		return false;
	if (!THERE_IS_DUP_KERNEL)
		return false;
	if (current->active_mm != mm)
		return false;

	preempt_disable();
	pgd_ind = pgd_to_index(pgd);
	cpu_pgd = &cpu_kernel_root_pt[pgd_ind];
	only_populate = (pgd_none(*cpu_pgd) && !pgd_none(*pgd));
	/*
	 * FIXME: follow two IFs only for debug purpose to detect
	 * case of user PGD updating
	 */
	if (!pgd_none(*cpu_pgd) &&
			(_PAGE_CLEAR_ACCESSED(pgd_val(*pgd)) !=
				_PAGE_CLEAR_ACCESSED(pgd_val(*cpu_pgd)))) {
		pr_err("%s(): updated CPU #%d kernel root pgd %px "
			"from 0x%lx to 0x%lx\n",
			__func__, raw_smp_processor_id(),
			cpu_pgd, pgd_val(*cpu_pgd), pgd_val(*pgd));
		dump_stack();
	}
	if (pgd_none_full(*pgd)) {
		pr_err("%s(): cleared CPU #%d kernel root pgd %px "
			"from 0x%lx to 0x%lx\n",
			__func__, raw_smp_processor_id(),
			cpu_pgd, pgd_val(*cpu_pgd), pgd_val(*pgd));
		dump_stack();
	}
	if (pgd_val(*cpu_pgd) != pgd_val(*pgd)) {
		*cpu_pgd = *pgd;
		__flush_tlb_page(mm, (e2k_addr_t) cpu_pgd);
	}
	DebugPT("CPU #%d set kernel root pgd %px to 0x%lx\n",
		smp_processor_id(), cpu_pgd, pgd_val(*cpu_pgd));
	preempt_enable();

	return only_populate;
}
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define	pgd_populate_cpu_root_pt(mm, pgd)	false
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
static inline void
pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	unsigned long mask;

	BUG_ON(mm == NULL);
	if (unlikely(mm == &init_mm)) {
		pgd_populate_kernel(mm, pgd, pud);
		return;
	}

	/*
	 * PGD should be set into two root page tables (main and
	 * CPU's) and in atomic style, so close interrupts to preserve
	 * from smp call for flush_tlb_all() between two settings,
	 * while the CPU restore CPU's root PGD from main. In this case
	 * CPU's PGD will be restored as populated when we wait for not
	 * yet populated state (see above pgd_populate_cpu_root_pt())
	 */
	raw_local_irq_save(mask);
	pgd_populate_user(pgd, pud);		/* order of setting is */
	pgd_populate_cpu_root_pt(mm, pgd);	/* significant, if IRQs */
	virt_kernel_pgd_populate(mm, pgd);	/* do not close and flush */
						/* of TLB can restore */
						/* second PGD from first */
	raw_local_irq_restore(mask);
}

static inline void
pgd_populate_not_present(struct mm_struct *mm, e2k_addr_t addr, pgd_t *pgd)
{
	unsigned long mask;

	/* See comment in pgd_populate() */
	raw_local_irq_save(mask);
	validate_pgd_at(mm, addr, pgd);
	pgd_populate_cpu_root_pt(mm, pgd);
	raw_local_irq_restore(mask);
}

#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

static inline void
pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
#ifdef	CONFIG_VIRTUALIZATION
	unsigned long mask;
#endif	/* CONFIG_VIRTUALIZATION */

	BUG_ON(mm == NULL);
	if (unlikely(mm == &init_mm)) {
		pgd_populate_kernel(mm, pgd, pud);
		return;
	}

#ifdef	CONFIG_VIRTUALIZATION
	/* see comment above: pgd_populate() */
	/* for CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	raw_local_irq_save(mask);
#endif	/* CONFIG_VIRTUALIZATION */

	pgd_populate_user(pgd, pud);

#ifdef	CONFIG_VIRTUALIZATION
	virt_kernel_pgd_populate(mm, pgd);
	raw_local_irq_restore(mask);
#endif	/* CONFIG_VIRTUALIZATION */
}

static inline void
pgd_populate_not_present(struct mm_struct *mm, e2k_addr_t addr, pgd_t *pgd)
{
	validate_pgd_at(mm, addr, pgd);
}

#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

static inline void
node_pgd_populate_kernel(int nid, struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	node_pgd_set_k(nid, pgd, pud);
}

extern pud_t *node_pud_alloc_kernel(int nid, pgd_t *pgd, e2k_addr_t address);
extern pmd_t *node_pmd_alloc_kernel(int nid, pud_t *pud, e2k_addr_t address);
extern pte_t *node_pte_alloc_kernel(int nid, pmd_t *pmd, e2k_addr_t address);

static inline pud_t *
node_early_pud_alloc(int nid, pgd_t *pgd, unsigned long address)
{
	pud_t *pud;

	if (!pgd_none(*pgd)) {
		DebugPT("pud was allocated already "
			"at addr 0x%lx\n", pgd_val(*pgd));
		return pud_offset(pgd, address);
	}
	pud = (pud_t *) node_early_get_zeroed_page(nid);
	DebugPT("allocated pud at addr 0x%px\n", pud);
	node_pgd_populate_kernel(nid, (&init_mm), pgd, pud);
	return pud_offset(pgd, address);
}

static inline pud_t *
early_pud_alloc(pgd_t *pgd, unsigned long address)
{
	return node_early_pud_alloc(numa_node_id(), pgd, address);
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

static inline pmd_t *
node_early_pmd_alloc(int nid, pud_t *pud, unsigned long address)
{
	pmd_t *pmd;

	if (!pud_none(*pud)) {
		DebugPT("pmd was allocated already "
			"at addr 0x%lx\n", pud_val(*pud));
		return pmd_offset(pud, address);
	}
	pmd = (pmd_t *) node_early_get_zeroed_page(nid);
	DebugPT("allocated pmd at addr 0x%px\n", pmd);
	pud_populate_kernel((&init_mm), pud, pmd);
	return pmd_offset(pud, address);
}

static inline pmd_t *
early_pmd_alloc(pud_t *pud, unsigned long address)
{
	return node_early_pmd_alloc(numa_node_id(), pud, address);
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

static inline pte_t *
node_early_pte_alloc(int nid, pmd_t *pmd, unsigned long address)
{
	pte_t *pte = (pte_t *) node_early_get_zeroed_page(nid);

	if (!pmd_none(*pmd)) {
		DebugPT("pte was allocated already "
			"at addr 0x%lx\n", pmd_val(*pmd));
		return pte_offset_kernel(pmd, address);
	}
	pte = (pte_t *) node_early_get_zeroed_page(nid);
	DebugPT("allocated pte at addr 0x%px\n", pte);
	pmd_populate_kernel(&init_mm, pmd, pte);
	return pte_offset_kernel(pmd, address);
}

static inline pte_t *
early_pte_alloc(pmd_t *pmd, unsigned long address)
{
	return node_early_pte_alloc(numa_node_id(), pmd, address);
}

#ifdef	CONFIG_NUMA
extern int node_map_vm_area(int nid_from, nodemask_t nodes_to,
			unsigned long address, unsigned long size);

static inline int
all_nodes_map_vm_area(int nid_from, unsigned long address, unsigned long size)
{
	return node_map_vm_area(nid_from, node_has_dup_kernel_map,
							address, size);
}

static inline int
all_other_nodes_map_vm_area(int nid_from, unsigned long address,
						unsigned long size)
{
	return node_map_vm_area(nid_from, node_has_dup_kernel_map,
							address, size);
}

extern void node_unmap_kernel_vm_area_noflush(nodemask_t nodes,
				unsigned long address, unsigned long end);
extern void node_unmap_vm_area_noflush(nodemask_t nodes,
				struct vm_struct *area);

static inline void
all_nodes_unmap_kernel_vm_area_noflush(unsigned long start, unsigned long end)
{
	node_unmap_kernel_vm_area_noflush(node_has_dup_kernel_map, start, end);
}

static inline void
all_nodes_unmap_vm_area_noflush(struct vm_struct *area)
{
	node_unmap_vm_area_noflush(node_has_dup_kernel_map, area);
}

static inline nodemask_t
get_node_has_dup_kernel_map(int nid_to_clear)
{
	nodemask_t nodes_map = node_has_dup_kernel_map;
	int dup_nid = node_dup_kernel_nid(nid_to_clear);

	if (nid_to_clear != dup_nid) {
		node_clear(dup_nid, nodes_map);
	} else {
		node_clear(nid_to_clear, nodes_map);
	}
	return nodes_map;
}

static inline void
all_other_nodes_unmap_vm_area_noflush(int the_nid, struct vm_struct *area)
{
	nodemask_t nodes_map = get_node_has_dup_kernel_map(the_nid);

	node_unmap_vm_area_noflush(nodes_map, area);
}
extern void node_unmap_kmem_area(nodemask_t nodes,
				unsigned long address, unsigned long size);

static inline void
all_nodes_unmap_kmem_area(unsigned long address, unsigned long size)
{
	node_unmap_kmem_area(node_has_dup_kernel_map, address, size);
}

static inline void
all_other_nodes_unmap_kmem_area(int the_nid, unsigned long address,
						unsigned long size)
{
	nodemask_t nodes_map = get_node_has_dup_kernel_map(the_nid);

	node_unmap_kmem_area(nodes_map, address, size);
}
#else /* ! CONFIG_NUMA */
static inline int
all_other_nodes_map_vm_area(int nid_from, unsigned long address,
						unsigned long size)
{
	return 0;
}
#endif	/* CONFIG_NUMA */

#endif /* _E2K_PGALLOC_H */
