/* $Id: pgalloc.h,v 1.35 2009/11/11 10:54:28 thay_k Exp $
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
#include <asm/pgtable.h>
#include <asm/mman.h>
#include <asm/console.h>
#include <asm/smp.h>
#include <asm/tlbflush.h>
#include <asm/e2k_debug.h>

#undef	DEBUG_PA_MODE
#undef	DebugPA
#define	DEBUG_PA_MODE		0	/* page table allocation */
#define DebugPA(...)		DebugPrint(DEBUG_PA_MODE ,##__VA_ARGS__)

#define	CHECK_ON_NODE_ALLOC		1
#define	CHECK_USER_ON_NODE_ALLOC	0
#if	CHECK_ON_NODE_ALLOC
#if	CHECK_USER_ON_NODE_ALLOC
#define	is_kernel_thread(task)	(0)
#else	/* ! CHECK_USER_ON_NODE_ALLOC */
#define	is_kernel_thread(task)		\
		(((task)->mm == NULL || (task)->mm == &init_mm) && \
			!(task)->flags & PF_EXITING)
#endif	/* CHECK_USER_ON_NODE_ALLOC */
#endif	/* CHECK_ON_NODE_ALLOC */

#include <asm/secondary_space.h>
/*
 * Very stupidly, we used to get new pgd's and pmd's, init their contents
 * to point to the NULL versions of the next level page table, later on
 * completely re-init them the same way, then free them up.  This wasted
 * a lot of work and caused unnecessary memory traffic.  How broken...
 * We fix this by caching them.
 */
extern struct cpuinfo_e2k cpu_data[NR_CPUS];
#ifdef CONFIG_SMP

#define pgd_quicklist		(my_cpu_data.pgd_quick)
#define pud_quicklist		(my_cpu_data.pud_quick)
#define pmd_quicklist		(my_cpu_data.pmd_quick)
#define pte_quicklist		(my_cpu_data.pte_quick)
#define pgtable_cache_size	(my_cpu_data.pgtable_cache_sz)

/* Versions that do not check preemption */
#define raw_pgd_quicklist	(raw_my_cpu_data.pgd_quick)
#define raw_pud_quicklist	(raw_my_cpu_data.pud_quick)
#define raw_pmd_quicklist	(raw_my_cpu_data.pmd_quick)
#define raw_pte_quicklist	(raw_my_cpu_data.pte_quick)
#define raw_pgtable_cache_size	(raw_my_cpu_data.pgtable_cache_sz)

#else	/* ! (CONFIG_SMP) */

typedef struct pgtable_cache_struct {
	e2k_addr_t	*pgd_cache;
	e2k_addr_t	*pud_cache;
	e2k_addr_t	*pmd_cache;
	e2k_addr_t	*pte_cache;
	unsigned int	pgtable_cache_sz;
} pgtable_cache_struct_t;
extern pgtable_cache_struct_t	pgt_quicklists;

#define pgd_quicklist		(pgt_quicklists.pgd_cache)
#define pud_quicklist		(pgt_quicklists.pud_cache)
#define pmd_quicklist		(pgt_quicklists.pmd_cache)
#define pte_quicklist		(pgt_quicklists.pte_cache)
#define pgtable_cache_size	(pgt_quicklists.pgtable_cache_sz)

#define raw_pgd_quicklist	pgd_quicklist
#define raw_pud_quicklist	pud_quicklist
#define raw_pmd_quicklist	pmd_quicklist
#define raw_pte_quicklist	pte_quicklist
#define raw_pgtable_cache_size	pgtable_cache_size

#endif	/* CONFIG_SMP */

extern void __init *early_get_page(void);
extern void __init *node_early_get_zeroed_page(int nid);

extern int mem_init_done;
extern int init_bootmem_done;

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
static inline void
copy_one_user_pgd_to_kernel_pgd(pgd_t *kernel_pgd, pgd_t *user_pgd, int index)
{
	BUG_ON(index >= USER_PTRS_PER_PGD);
	kernel_pgd[index] = user_pgd[index];
	DebugPA("CPU #%d copy one user pgd "
		"#%d 0x%p = 0x%lx to kernel root pt 0x%p\n",
		smp_processor_id(), index,
		&user_pgd[index], pgd_val(user_pgd[index]),
		&kernel_pgd[index]);
}
static inline void
copy_user_pgd_to_kernel_pgd_addr(pgd_t *kernel_pgd, pgd_t *user_pgd,
							e2k_addr_t addr)
{
	copy_one_user_pgd_to_kernel_pgd(kernel_pgd, user_pgd,
						pgd_index(addr));
}
static inline void
copy_user_pgd_to_kernel_root_pt_addr(pgd_t *user_pgd, e2k_addr_t addr)
{
	copy_user_pgd_to_kernel_pgd_addr(cpu_kernel_root_pt, user_pgd,
						addr);
}

static inline void
copy_user_pgd_to_kernel_pgd_range(pgd_t *kernel_pgd, pgd_t *user_pgd,
		int start_index, int end_index)
{
#if DEBUG_PA_MODE
	int index;
#endif
	BUG_ON(start_index >= USER_PTRS_PER_PGD);
	BUG_ON(end_index > USER_PTRS_PER_PGD);
	BUG_ON(start_index >= end_index);
#if DEBUG_PA_MODE
	for (index = start_index; index < end_index; index++)
		DebugPA("CPU #%d copy user pgd #%d 0x%p = 0x%lx to kernel root pt 0x%p\n",
				smp_processor_id(), index,
				&user_pgd[index], pgd_val(user_pgd[index]),
				&kernel_pgd[index]);
#endif
	memcpy(&kernel_pgd[start_index], &user_pgd[start_index],
			sizeof(pgd_t) * (end_index - start_index));
}
static inline void
copy_user_pgd_to_kernel_pgd_addr_range(pgd_t *kernel_pgd, pgd_t *user_pgd,
		e2k_addr_t start_addr, e2k_addr_t end_addr)
{
	copy_user_pgd_to_kernel_pgd_range(kernel_pgd, user_pgd,
			pgd_index(start_addr),
			pgd_index(_PAGE_ALIGN_DOWN(end_addr, PGDIR_SIZE)));
}
static inline void
copy_user_pgd_to_kernel_root_pt_addr_range(pgd_t *user_pgd,
		e2k_addr_t start_addr, e2k_addr_t end_addr)
{
	copy_user_pgd_to_kernel_pgd_addr_range(cpu_kernel_root_pt, user_pgd,
						start_addr, end_addr);
}

static inline void
copy_user_pgd_to_kernel_pgd(pgd_t *kernel_pgd, pgd_t *user_pgd)
{
	copy_user_pgd_to_kernel_pgd_range(kernel_pgd, user_pgd,
						0, USER_PTRS_PER_PGD);
}
 
static inline void
copy_user_pgd_to_kernel_root_pt(pgd_t *user_pgd)
{
	copy_user_pgd_to_kernel_pgd(cpu_kernel_root_pt, user_pgd);
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

static inline pgd_t*
node_pgd_alloc_slow(int nid)
{
	int root_pt_index;
	struct page *page = alloc_pages_node(nid,
				GFP_KERNEL | __GFP_REPEAT |  __GFP_ZERO, 0);
	pgd_t	*pgd;
	pgd_t	*init;

	if (page == NULL)
		return NULL;
	pgd = page_address(page);
	init = node_pgd_offset_kernel(nid, 0UL);
	if (pgd) {
		(void) memcpy(pgd + USER_PTRS_PER_PGD, init + USER_PTRS_PER_PGD,
			(PTRS_PER_PGD - USER_PTRS_PER_PGD) * sizeof (pgd_t));

		/* One PGD entry is the VPTB self-map. */
		root_pt_index = pgd_index(KERNEL_VMLPT_BASE_ADDR);
		vmlpt_pgd_set(&pgd[root_pt_index], pgd);
		DebugPT("allocated pgd at addr 0x%p\n", pgd);
	}
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pgd &&
			kvaddr_to_nid(pgd) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_pgd_alloc_slow() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pgd, kvaddr_to_nid(pgd),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pgd;
}

static inline pgd_t*
pgd_alloc_slow(void)
{
	return node_pgd_alloc_slow(numa_node_id());
}

/* Caller must disable irq */
static inline pgd_t*
pgd_alloc_fast(void)
{
	e2k_addr_t *pgd;

	pgd = pgd_quicklist;

	if (pgd != NULL) {
		pgd_quicklist = (e2k_addr_t *)(*pgd);
		pgd[0] = (e2k_addr_t)0;
		-- pgtable_cache_size;
	}
	if (pgd != NULL) {
		DebugPT("get pgd at addr 0x%p\n", pgd);
	} else {
		DebugPT("could not get pgd\n");
	}
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pgd &&
		kvaddr_to_nid(pgd) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: pgd_alloc_fast() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pgd, kvaddr_to_nid(pgd),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	return (pgd_t *)pgd;
}

static inline void
free_pgd_slow(pgd_t *pgd)
{
	free_page((e2k_addr_t)pgd);
	DebugPT("freed pgd page at addr 0x%p\n", pgd);
}

static inline void
free_pgd_fast(pgd_t *pgd)
{
	unsigned long flags;

#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pgd &&
		kvaddr_to_nid(pgd) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: free_pgd_fast() "
			"try to free 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pgd, kvaddr_to_nid(pgd),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
		free_pgd_slow(pgd);
		return;
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	local_irq_save(flags);
	*(e2k_addr_t *)pgd = (e2k_addr_t)pgd_quicklist;
	pgd_quicklist = (e2k_addr_t *)pgd;
	++ pgtable_cache_size;
	local_irq_restore(flags);

	DebugPT("freed pgd at addr 0x%p\n", pgd);
}

static inline void
node_free_pgd(int nid, pgd_t *pgd)
{
	if (nid == numa_node_id())
		free_pgd_fast(pgd);
	else
		free_pgd_slow(pgd);
}

static inline pgd_t*
node_pgd_alloc(int nid, struct mm_struct *mm)
{
	pgd_t *pgd;

	pgd = node_pgd_alloc_slow(nid);
	DebugPT("get pgd at addr 0x%p\n", pgd);
	return pgd;
}

static inline pgd_t*
pgd_alloc(struct mm_struct *mm)
{
	pgd_t *pgd;
	unsigned long flags;

	local_irq_save(flags);
	pgd = pgd_alloc_fast();
	local_irq_restore(flags);
	if (!pgd)
		pgd = pgd_alloc_slow();
	DebugPT("get pgd at addr 0x%p\n", pgd);
	return pgd;
}
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
static inline int
pgd_populate_cpu_root_pt(struct mm_struct *mm, pgd_t *pgd)
{
	unsigned long pgd_ind;
	pgd_t *cpu_pgd;
	int only_populate;

	if (!THERE_IS_DUP_KERNEL)
		return 0;
	if (current->active_mm != mm)
		return 0;

	preempt_disable();
	pgd_ind = (pgd - mm->pgd) /*/ sizeof (pgd_t)*/;
	cpu_pgd = &cpu_kernel_root_pt[pgd_ind];
	only_populate = (pgd_none(*cpu_pgd) && !pgd_none(*pgd));
	/*
	 * FIXME: follow two IFs only for debug purpose to detect
	 * case of user PGD updating
	 */
	if (!pgd_none(*cpu_pgd) && ((pgd_val(*pgd) & ~_PAGE_A) !=
					(pgd_val(*cpu_pgd) & ~_PAGE_A))) {
		printk("pgd_populate_cpu_root_pt() updated CPU #%d "
			"kernel root pgd %p from 0x%lx to 0x%lx\n",
			smp_processor_id(),
			cpu_pgd, pgd_val(*cpu_pgd), pgd_val(*pgd));
		print_stack(current);
	}
	if (pgd_none(*pgd)) {
		printk("pgd_populate_cpu_root_pt() cleared CPU #%d "
			"kernel root pgd %p from 0x%lx to 0x%lx\n",
			smp_processor_id(),
			cpu_pgd, pgd_val(*cpu_pgd), pgd_val(*pgd));
		print_stack(current);
	}
	*cpu_pgd = *pgd;
	__flush_tlb_page(mm, (e2k_addr_t) cpu_pgd);
	DebugPT("CPU #%d set kernel root "
		"pgd %p to 0x%lx\n",
		smp_processor_id(), cpu_pgd, pgd_val(*cpu_pgd));
	preempt_enable();

	return only_populate;
}

static inline void
pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	unsigned long mask;

	/*
	 * PGD should be set into two root page tables (main and
	 * CPU's) and in atomic style, so close interrupts to preserve
	`* from smp call for flush_tlb_all() between two settings,
	 * while the CPU restore CPU's root PGD from main. In this case
	 * CPU's PGD will be restored as populated when we wait for not
	 * yet populated state (see above pgd_populate_cpu_root_pt())
	 */
	raw_local_irq_save(mask);
	pgd_set_u(pgd, pud);			/* order of setting is */
	pgd_populate_cpu_root_pt(mm, pgd);	/* significant, if IRQs */
						/* do not close and flush */
						/* of TLB can restore */
						/* second PGD from first */
	raw_local_irq_restore(mask);
}
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#define	pgd_populate_cpu_root_pt(mm, pgd)	0

static inline void
pgd_populate(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	pgd_set_u(pgd, pud);
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

static inline void
pgd_populate_kernel(struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	pgd_set_k(pgd, pud);
}

static inline void
node_pgd_populate_kernel(int nid, struct mm_struct *mm, pgd_t *pgd, pud_t *pud)
{
	node_pgd_set_k(nid, pgd, pud);
}

static inline pud_t *
node_pud_alloc_one_slow(int nid)
{
	struct page *page = alloc_pages_node(nid,
				GFP_KERNEL | __GFP_REPEAT |  __GFP_ZERO, 0);
	pud_t *pud;

	if (page == NULL)
		return NULL;
	pud = page_address(page);
	DebugPT("allocated pud at addr 0x%p\n", pud);
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pud &&
			kvaddr_to_nid(pud) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_pud_alloc_one_slow() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pud, kvaddr_to_nid(pud),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pud;
}

static inline pud_t *
pud_alloc_one_slow(void)
{
	return node_pud_alloc_one_slow(numa_node_id());
}

/* Caller must disable irq */
static inline pud_t *
pud_alloc_one_fast(void)
{
	e2k_addr_t *pud;

	pud = (e2k_addr_t *)pud_quicklist;

	if (pud != NULL) {
		pud_quicklist = (e2k_addr_t *)(*pud);
		pud[0] = (e2k_addr_t)0;
		-- pgtable_cache_size;
	}
	if (pud != NULL) {
		DebugPT("get pud at addr 0x%p\n", pud);
	} else {
		DebugPT("could not get pud\n");
	}
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pud &&
		kvaddr_to_nid(pud) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: pud_alloc_one_fast() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pud, kvaddr_to_nid(pud),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	return (pud_t *)pud;
}

static inline void
free_pud_slow(pud_t *pud)
{
	free_page((e2k_addr_t)pud);
	DebugPT("freed pud page at addr 0x%p\n", pud);
}

static inline void
free_pud_fast(pud_t *pud)
{
	unsigned long flags;

#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pud &&
		kvaddr_to_nid(pud) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: free_pud_fast() "
			"try to free 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pud, kvaddr_to_nid(pud),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
		free_pud_slow(pud);
		return;
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	local_irq_save(flags);
	*(e2k_addr_t *)pud = (e2k_addr_t)pud_quicklist;
	pud_quicklist = (e2k_addr_t *)pud;
	++ pgtable_cache_size;
	local_irq_restore(flags);

	DebugPT("freed pud at addr 0x%p\n", pud);
}

static inline void
node_free_pud(int nid, pud_t *pud)
{
	if (nid == numa_node_id())
		free_pud_fast(pud);
	else
		free_pud_slow(pud);
}

extern pud_t *pud_alloc_kernel(struct mm_struct *mm, pgd_t *pgd,
						e2k_addr_t address);
extern pud_t *node_pud_alloc_kernel(int nid, pgd_t *pgd,
						e2k_addr_t address);

static inline pud_t*
node_pud_alloc_one_kernel(int nid, struct mm_struct *mm, e2k_addr_t vmaddr)
{
	pud_t *pud_page = NULL;

	if (nid == numa_node_id()) {
		unsigned long flags;
		local_irq_save(flags);
		pud_page = pud_alloc_one_fast();
		local_irq_restore(flags);
	}
	if (pud_page == NULL)
		pud_page = node_pud_alloc_one_slow(nid);
	if (pud_page != NULL) {
		DebugPT("allocated pud page at "
			"0x%p for mm 0x%p and virt addr 0x%lx\n",
			pud_page, mm, vmaddr);
	} else {
		DebugPT("could not allocate pud "
			"page for mm 0x%p and virt addr 0x%lx\n",
			mm, vmaddr);
	}
	return pud_page;
}

static inline pud_t*
pud_alloc_one_kernel(struct mm_struct *mm, e2k_addr_t vmaddr)
{
	return node_pud_alloc_one_kernel(numa_node_id(), mm, vmaddr);
}

static inline pud_t*
node_pud_alloc_one(int nid, struct mm_struct *mm, e2k_addr_t vmaddr)
{
	return node_pud_alloc_one_kernel(nid, mm, vmaddr);
}

static inline pud_t*
pud_alloc_one(struct mm_struct *mm, e2k_addr_t vmaddr)
{
	return pud_alloc_one_kernel(mm, vmaddr);
}

static inline pud_t *
node_early_pud_alloc(int nid, pgd_t *pgd, unsigned long address)
{
	pud_t *pud;

	if (!pgd_none(*pgd)) {
		DebugPT("pud was allocated already "
			"at addr 0x%lx\n", pgd_val(*pgd));
		return pud_offset_kernel(pgd, address);
	}
	pud = (pud_t *) node_early_get_zeroed_page(nid);
	DebugPT("allocated pud at addr 0x%p\n", pud);
	node_pgd_populate_kernel(nid, (&init_mm), pgd, pud);
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pud &&
			kvaddr_to_nid(pud) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_early_pud_alloc() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pud, kvaddr_to_nid(pud),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pud_offset_kernel(pgd, address);
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

static inline void
pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set_u(pud, pmd);
}

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static inline void
pud_populate_sec(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	pud_set_s(pud, pmd);
}
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

static inline pmd_t *
node_pmd_alloc_one_slow(int nid)
{
	struct page *page = alloc_pages_node(nid,
				GFP_KERNEL | __GFP_REPEAT |  __GFP_ZERO, 0);
	pmd_t *pmd;

	if (page == NULL)
		return NULL;
	pmd = page_address(page);
	DebugPT("allocated pmd at addr 0x%p\n", pmd);
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pmd &&
			kvaddr_to_nid(pmd) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_pmd_alloc_one_slow() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pmd, kvaddr_to_nid(pmd),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pmd;
}

static inline pmd_t *
pmd_alloc_one_slow(void)
{
	return node_pmd_alloc_one_slow(numa_node_id());
}

/* Caller must disable irq */
static inline pmd_t *
pmd_alloc_one_fast(void)
{
	e2k_addr_t *pmd;

	pmd = (e2k_addr_t *)pmd_quicklist;

	if (pmd != NULL) {
		pmd_quicklist = (e2k_addr_t *)(*pmd);
		pmd[0] = (e2k_addr_t)0;
		-- pgtable_cache_size;
	}
	if (pmd != NULL) {
		DebugPT("get pmd at addr 0x%p\n", pmd);
	} else {
		DebugPT("could not get pmd\n");
	}
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pmd &&
		kvaddr_to_nid(pmd) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: pmd_alloc_one_fast() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pmd, kvaddr_to_nid(pmd),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	return (pmd_t *)pmd;
}

static inline void
free_pmd_slow(pmd_t *pmd)
{
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && is_sec_table(pmd) && !IS_UPT_E3S) {
		DebugPT("free_pmd_slow()SECONDARY pmd:%p v:0x%lx\n",
			pmd, pmd_val(*pmd));
		BUG();
	}
#endif

	free_page((e2k_addr_t)pmd);
	DebugPT("freed pmd page at addr 0x%p\n", pmd);
}

static inline void
free_pmd_fast(pmd_t *pmd)
{
	unsigned long flags;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && is_sec_table(pmd) && !IS_UPT_E3S) {
		/* Do nothing for secondary pmd page */
		SET_TBL_FREE(pmd);
		DebugSS("free_pmd_fast()SECONDARY pmd:%p v:0x%lx\n",
			pmd, pmd_val(*pmd));
		return;
	}
#endif

#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pmd &&
		kvaddr_to_nid(pmd) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: free_pmd_fast() "
			"try to free 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pmd, kvaddr_to_nid(pmd),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
		free_pmd_slow(pmd);
		return;
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	local_irq_save(flags);
	*(e2k_addr_t *)pmd = (e2k_addr_t)pmd_quicklist;
	pmd_quicklist = (e2k_addr_t *)pmd;
	++ pgtable_cache_size;
	local_irq_restore(flags);

	DebugPT("freed pmd at addr 0x%p\n", pmd);
}

static inline void
node_free_pmd(int nid, pmd_t *pmd)
{
	if (nid == numa_node_id())
		free_pmd_fast(pmd);
	else
		free_pmd_slow(pmd);
}

extern pmd_t *pmd_alloc_kernel(struct mm_struct *mm, pud_t *pud,
						e2k_addr_t address);
extern pmd_t *node_pmd_alloc_kernel(int nid, pud_t *pud,
						e2k_addr_t address);

static inline pmd_t*
node_pmd_alloc_one_kernel(int nid, struct mm_struct *mm, e2k_addr_t vmaddr)
{
	pmd_t *pmd_page = NULL;

	if (nid == numa_node_id()) {
		unsigned long flags;
		local_irq_save(flags);
		pmd_page = pmd_alloc_one_fast();
		local_irq_restore(flags);
	}
	if (pmd_page == NULL) {
		pmd_page = node_pmd_alloc_one_slow(nid);
	}
	if (pmd_page != NULL) {
		DebugPT("allocated pmd page at "
			"0x%p for mm 0x%p and virt addr 0x%lx\n",
			pmd_page, mm, vmaddr);
	} else {
		DebugPT("could not allocate pmd "
			"page for mm 0x%p and virt addr 0x%lx\n",
			mm, vmaddr);
	}
	return pmd_page;
}

static inline pmd_t*
pmd_alloc_one_kernel(struct mm_struct *mm, e2k_addr_t vmaddr)
{
	return node_pmd_alloc_one_kernel(numa_node_id(), mm, vmaddr);
}

static inline pmd_t*
pmd_alloc_one(struct mm_struct *mm, unsigned long vmaddr)
{
	return pmd_alloc_one_kernel(mm, vmaddr);
}

static inline pmd_t *
node_early_pmd_alloc(int nid, pud_t *pud, unsigned long address)
{
	pmd_t *pmd;

	if (!pud_none(*pud)) {
		DebugPT("pmd was allocated already "
			"at addr 0x%lx\n", pud_val(*pud));
		return pmd_offset_kernel(pud, address);
	}
	pmd = (pmd_t *) node_early_get_zeroed_page(nid);
	DebugPT("allocated pmd at addr 0x%p\n", pmd);
	pud_populate_kernel((&init_mm), pud, pmd);
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pmd &&
			kvaddr_to_nid(pmd) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_early_pmd_alloc() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pmd, kvaddr_to_nid(pmd),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pmd_offset_kernel(pud, address);
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

static inline void
pmd_populate(struct mm_struct *mm, pmd_t *pmd, pgtable_t pte)
{
	pmd_set_u(pmd, (pte_t *)page_address(pte));
}

#define pmd_pgtable(pmd) pmd_page(pmd)

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static inline void
pmd_populate_sec(struct mm_struct *mm, pmd_t *pmd, pte_t *pte)
{
	pmd_set_s(pmd, pte);
}
#endif

extern pte_t *node_pte_alloc_kernel(int nid, pmd_t *pmd,
							e2k_addr_t address);

static inline pte_t *
node_pte_alloc_one_slow(int nid)
{
	struct page *page = alloc_pages_node(nid,
				GFP_KERNEL | __GFP_REPEAT |  __GFP_ZERO, 0);
	pte_t *pte = NULL;

	if (page == NULL)
		return NULL;
	pte = page_address(page);
	pgtable_page_ctor(page);
	DebugPT("allocated pte at addr 0x%p\n", pte);
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pte &&
			kvaddr_to_nid(pte) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_pte_alloc_one_slow() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pte, kvaddr_to_nid(pte),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pte;
}

static inline pte_t *
pte_alloc_one_slow(void)
{
	return node_pte_alloc_one_slow(numa_node_id());
}

/* Caller must disable irq */
static inline pte_t *
pte_alloc_one_fast(void)
{
	e2k_addr_t *ret;
	
	ret = (e2k_addr_t *)pte_quicklist;

	if (ret != NULL) {
		pte_quicklist = (e2k_addr_t *)(*ret);
		ret[0] = 0;
		-- pgtable_cache_size;
	}
	if (ret != NULL) {
		DebugPT("get pte page at addr 0x%p\n", ret);
	} else {
		DebugPT("could not get pte page\n");
	}
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && ret &&
		kvaddr_to_nid(ret) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: pte_alloc_one_fast() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			ret, kvaddr_to_nid(ret),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	return (pte_t *)ret;
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
	DebugPT("allocated pte at addr 0x%p\n", pte);
	pmd_populate_kernel(&init_mm, pmd, pte);
#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pte &&
			kvaddr_to_nid(pte) != node_dup_kernel_nid(nid)) {
		printk("Node #%d CPU #%d: WARNING: node_early_pte_alloc() "
			"allocated 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pte, kvaddr_to_nid(pte),
			nid, node_dup_kernel_nid(nid));
	}
#endif	/* CHECK_ON_NODE_ALLOC */
	return pte_offset_kernel(pmd, address);
}

static inline pte_t *
early_pte_alloc(pmd_t *pmd, unsigned long address)
{
	return node_early_pte_alloc(numa_node_id(), pmd, address);
}

#define pmd_free_kernel(pte)		free_pmd_fast(pte)
#define pud_free_kernel(pud)		free_pud_fast(pud)

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	free_pud_fast(pud);
}
static inline void pgd_free(struct mm_struct *mm, pgd_t *pgd)
{
	free_pgd_fast(pgd);
}
#define node_pte_free_kernel(nid, pte)	node_free_pte(nid, pte)
#define node_pmd_free_kernel(nid, pmd)	node_free_pmd(nid, pmd)
#define node_pud_free_kernel(nid, pud)	node_free_pud(nid, pud)
extern	void check_pgt_cache(void);

static inline void
pte_check_and_free(pte_t *pte)
{

#if defined(_PMD_ACCESS_DEBUG_) || defined(CONFIG_MAKE_ALL_PAGES_VALID)
	int	ptr;
	pte_t	*cur_pte;
#endif /* defined(_PMD_ACCESS_DEBUG_) || defined(CONFIG_MAKE_ALL_PAGES_VALID) */

#if defined(_PMD_ACCESS_DEBUG_) || defined(CONFIG_MAKE_ALL_PAGES_VALID)
	DebugPT("start pte 0x%lx = 0x%lx\n",
		(u64) pte, (u64) pte_val(*pte));
	for (ptr = 0; ptr < PTRS_PER_PTE ; ptr ++) {
		cur_pte = pte + ptr;
		DebugPT("current pte 0x%llx = 0x%llx\n",
			(u64) cur_pte, (u64) pte_val(*cur_pte));
#ifdef	_PMD_ACCESS_DEBUG_
		if (!pte_none(*cur_pte)) {
			pte_ERROR(*cur_pte);
			BUG();
		}
#endif	/* _PMD_ACCESS_DEBUG_ */
		set_pte(cur_pte, __pte(0));
	}
#endif /* defined(_PMD_ACCESS_DEBUG_) || defined(CONFIG_MAKE_ALL_PAGES_VALID) */

}

static inline void
free_pte_slow(pte_t *pte)
{
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && is_sec_table(pte) && !IS_UPT_E3S) {
		/* Do nothing for secondary pte page */
		SET_TBL_FREE(pte);
		DebugSS("free_pte_slow()SECONDARY (hmm...) pte:%p v:0x%lx\n",
		pte, pte_val(*pte));
		return;
	}
#endif

	pgtable_page_dtor(virt_to_page(pte));
	free_page((e2k_addr_t)pte);
	DebugPT("freed pte page at addr 0x%p\n", pte);
}

static inline void
free_pte_fast(pte_t *pte)
{
	unsigned long flags;

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
	if (TASK_IS_BINCO(current) && is_sec_table(pte) && !IS_UPT_E3S) {
		/* Do nothing for secondary pte page */
		SET_TBL_FREE(pte);
		DebugSS("free_pte_fast()SECONDARY pte:%p v:0x%lx\n",
					pte, pte_val(*pte));
		return;
	}
#endif

	pte_check_and_free(pte);

#if	CHECK_ON_NODE_ALLOC
	if (is_kernel_thread(current) && pte &&
		kvaddr_to_nid(pte) != node_dup_kernel_nid(numa_node_id())) {
		printk("Node #%d CPU #%d: WARNING: free_pte_fast() "
			"try to free 0x%p on node #%d while should on node "
			"#%d (dup #%d)\n",
			numa_node_id(), smp_processor_id(),
			pte, kvaddr_to_nid(pte),
			numa_node_id(), node_dup_kernel_nid(numa_node_id()));
		free_pte_slow(pte);
		return;
	}
#endif	/* CHECK_ON_NODE_ALLOC */

	local_irq_save(flags);
	*(e2k_addr_t *)pte = (e2k_addr_t) pte_quicklist;
	pte_quicklist = (e2k_addr_t *) pte;
	++ pgtable_cache_size;
	local_irq_restore(flags);

	DebugPT("freed pte page at addr 0x%p\n", pte);
}

static inline void
node_free_pte(int nid, pte_t *pte)
{
	if (nid == numa_node_id()) {
		free_pte_fast(pte);
	} else {
		free_pte_slow(pte);
	}
}

#ifndef CONFIG_SECONDARY_SPACE_SUPPORT

static inline void pte_free_kernel(struct mm_struct *mm, pte_t *pte)
{
	free_pte_fast(pte);
}

static inline void pte_free(struct mm_struct *mm, pgtable_t pte_page)
{
	free_pte_fast(page_address(pte_page));
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	free_pmd_fast(pmd);
}
#else

extern void pte_free_kernel(struct mm_struct *mm, pte_t *pte);
extern void pte_free(struct mm_struct *mm, pgtable_t pte_page);
extern void pmd_free(struct mm_struct *mm, pmd_t *pmd);

#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */

/*
 * This function should be used if page tables have 4 levels:
 *	pgd	pud	pmd	pte
 */
static inline pte_t*
node_pte_alloc_one_kernel(int nid, struct mm_struct *mm, unsigned long vmaddr)
{
	pte_t *pte_page = NULL;

	if (nid == numa_node_id()) {
		unsigned long flags;
		local_irq_save(flags);
		pte_page = pte_alloc_one_fast();
		local_irq_restore(flags);
	}
	if (pte_page == NULL) {
		pte_page = node_pte_alloc_one_slow(nid);
	}
	if (pte_page != NULL) {
		DebugPT("allocated pte page at "
			"0x%p for mm 0x%p and virt addr 0x%lx\n",
			pte_page, mm, vmaddr);
	} else {
		DebugPT("could not allocate pte "
			"page for mm 0x%p and virt addr 0x%lx\n",
			mm, vmaddr);
	}
	return pte_page;
}
static inline pte_t*
pte_alloc_one_kernel(struct mm_struct *mm, unsigned long vmaddr)
{
	return node_pte_alloc_one_kernel(numa_node_id(), mm, vmaddr);
}

static inline pgtable_t
pte_alloc_one(struct mm_struct *mm, unsigned long vmaddr)
{
	pte_t *pte = pte_alloc_one_kernel(mm, vmaddr);
	if (pte)
		return virt_to_page(pte);
	return NULL;
}

static inline int
is_pte_freed_fast(pte_t *pte)
{
	e2k_addr_t	*cur_pte;
	unsigned long	flags;

	local_irq_save(flags);

	cur_pte = pte_quicklist;
	while (cur_pte != NULL) {
		if (cur_pte == (e2k_addr_t *)pte) {
			INIT_WARNING_POINT("is_pte_freed_fast()");
			INIT_WARNING("PTE 0x%lx == 0x%lx has been freed fast",
					(u64) pte, (u64) pte_val(*pte));
			local_irq_restore(flags);
			return 1;
		}
		cur_pte = (e2k_addr_t *)(*cur_pte);
	}

	local_irq_restore(flags);
	
	return 0;
}

static inline int
is_page_freed(struct page *page)
{
	if (page_count(page) == 0) {
		return 1;
#ifdef	_PMD_ACCESS_DEBUG_
	} else if (page_count(page) > 1) {
		BUG();
#endif	/* _PMD_ACCESS_DEBUG_ */
	}
	return 0;
}

static inline int
is_pte_freed_slow(pte_t *pte)
{
	if (is_page_freed(virt_to_page(pte))) {
		INIT_WARNING_POINT("is_pte_freed_slow()");
		INIT_WARNING("PTE 0x%lx == 0x%lx has been freed slow",
				(u64) pte, (u64) pte_val(*pte));
		return 1;
	} else {
		return 0;
	}
}

static inline int
is_pte_freed(pte_t *pte)
{
	if (is_pte_freed_fast(pte))
		return 1;
	if (is_pte_freed_slow(pte))
		return 1;

	return 0;
}

static inline int
is_pmd_freed_fast(pmd_t *pmd)
{
	e2k_addr_t	*cur_pmd;
	unsigned long	flags;

	local_irq_save(flags);

	cur_pmd = pmd_quicklist;
	while (cur_pmd != NULL) {
		if (cur_pmd == (e2k_addr_t *)pmd) {
			INIT_WARNING_POINT("is_pmd_freed_fast()");
			INIT_WARNING("pmd 0x%lx == 0x%lx has been freed fast",
					(u64) pmd, (u64) pmd_val(*pmd));
			local_irq_restore(flags);
			return 1;
		}
		cur_pmd = (e2k_addr_t *)(*cur_pmd);
	}

	local_irq_restore(flags);

	return 0;
}

static inline int
is_pmd_freed_slow(pmd_t *pmd)
{
	if (is_page_freed(virt_to_page(pmd))) {
		INIT_WARNING_POINT("is_pmd_freed_slow()");
		INIT_WARNING("pmd 0x%lx == 0x%lx has been freed slow",
				(u64) pmd, (u64) pmd_val(*pmd));
		return 1;
	} else {
		return 0;
	}
}

static inline int
is_pmd_freed(pmd_t *pmd)
{
	if (is_pmd_freed_fast(pmd))
		return 1;
	if (is_pmd_freed_slow(pmd))
		return 1;

	return 0;
}

static inline void
free_one_pmd(pmd_t *pmd)
{
	pte_t *pte;

	DebugPT("pmd 0x%llx = 0x%llx\n",
		(u64) pmd, (u64) pmd_val(*pmd));
	if (pmd_none(*pmd))
		return;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}
	pte = pte_offset_kernel((pmd_t *)pmd, 0);
	DebugPT("pte 0x%llx = 0x%llx\n",
		(u64) pte, (u64) pte_val(*pte));

#ifdef	_PMD_ACCESS_DEBUG_
	if (!is_pte_freed(pte))
#endif	/* _PMD_ACCESS_DEBUG_ */
		pte_free_kernel(&init_mm, pte);
	pmd_clear(pmd);
	DebugPT("cleared pmd 0x%llx = 0x%llx\n",
		(u64) pmd, (u64) pmd_val(*pmd));
}

static inline void
free_one_pud(pud_t *pud)
{
	DebugPT("puh 0x%llx = 0x%llx\n",
		(u64) pud, (u64) pud_val(*pud));
	if (pud_none(*pud)) {
		pud_clear(pud);
		return;
	}
	if (pud_bad(*pud)) {
		pud_ERROR(*pud);
		pud_clear(pud);
		return;
	}
	pud_clear(pud);
	DebugPT("cleared pud 0x%llx = 0x%llx\n",
		(u64) pud, (u64) pud_val(*pud));
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
#endif	/* CONFIG_NUMA */

#if	CHECK_ON_NODE_ALLOC
#undef is_kernel_thread
#endif	/* CHECK_ON_NODE_ALLOC */

#endif /* _E2K_PGALLOC_H */
