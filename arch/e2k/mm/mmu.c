/*  $Id: mmu.c,v 1.21 2009/08/05 16:11:10 kravtsunov_e Exp $
 *  arch/e2k/mm/init.c
 *
 * MMU menegement (Instruction and Data caches, TLB, registers)
 *
 * Derived heavily from Linus's Alpha/AXP ASN code...
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
 
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/sizes.h>

#include <asm/types.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/secondary_space.h>
#include <asm/sic_regs.h>
#include <asm/p2v/boot_map.h>

#undef	DEBUG_IC_MODE
#undef	DebugIC
#define	DEBUG_IC_MODE		0	/* Instruction Caches */
#define DebugIC(...)		DebugPrint(DEBUG_IC_MODE ,##__VA_ARGS__)

#undef	DEBUG_PT_MODE
#undef	DebugPT
#define	DEBUG_PT_MODE		0	/* Data Caches */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

#ifndef CONFIG_SMP
unsigned long	mmu_last_context = CTX_FIRST_VERSION;
#endif /* !CONFIG_SMP */

/*
 * Hardware MMUs page tables have some differences from one ISET to other
 * moreover each MMU supports a few different page tables:
 *	native (primary)
 *	secondary page tables for sevral modes (VA32, VA48, PA32, PA48 ...)
 * The follow structure presents native page table structure
 *
 * Warning .boot_*() entries should be updated dinamicaly to point to
 * physical addresses of functions for arch/e2k/p2v/
 */
pt_struct_t __nodedata pgtable_struct = {
	.type		= E2K_PT_TYPE,
	.pt_v6		= false,	/* as default for compatibility */
	.pfn_mask	= _PAGE_PFN_V2,
	.accessed_mask	= _PAGE_A_HW_V2,
	.dirty_mask	= _PAGE_D_V2,
	.present_mask	= _PAGE_P_V2,
	.user_mask	= 0ULL,
	.priv_mask	= _PAGE_PV_V2,
	.non_exec_mask	= _PAGE_NON_EX_V2,
	.exec_mask	= 0ULL,
	.sw_bit1_mask	= _PAGE_AVAIL_BIT_V2,
	.sw_bit2_mask	= _PAGE_A_SW_V2,
	.levels_num	= E2K_PT_LEVELS_NUM,
	.levels		= {
		[E2K_PAGES_LEVEL_NUM] = {
			.id		= E2K_PAGES_LEVEL_NUM,
			.page_size	= PAGE_SIZE,
		},
		[E2K_PTE_LEVEL_NUM] = {
			.id		= E2K_PTE_LEVEL_NUM,
			.pt_size	= PTE_SIZE,
			.page_size	= PAGE_SIZE,
			.pt_shift	= PTE_SHIFT,
			.page_shift	= PTE_SHIFT,
			.pt_mask	= PTE_MASK & _PAGE_PFN_V2,
			.pt_offset	= ~PTE_MASK & _PAGE_PFN_V2,
			.pt_index_mask	= PTE_MASK ^ PMD_MASK,
			.page_mask	= PTE_MASK,
			.page_offset	= ~PTE_MASK,
			.ptrs_per_pt	= PTRS_PER_PTE,
			.is_pte		= true,
			.is_huge	= false,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PMD_LEVEL_NUM] = {
			.id		= E2K_PMD_LEVEL_NUM,
			.pt_size	= PMD_SIZE,
			.pt_shift	= PMD_SHIFT,
			.pt_mask	= PMD_MASK & _PAGE_PFN_V2,
			.pt_offset	= ~PMD_MASK & _PAGE_PFN_V2,
			.pt_index_mask	= PMD_MASK ^ PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PMD,
#if	CONFIG_CPU_ISET >= 3
			.page_size	= E2K_2M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT,
			.page_offset	= ~PMD_MASK,
			.huge_ptes	= 1,
#elif	CONFIG_CPU_ISET >= 1
			.page_size	= E2K_4M_PAGE_SIZE,
			.page_shift	= PMD_SHIFT + 1,
			.page_offset	= (E2K_4M_PAGE_SIZE - 1),
			.huge_ptes	= 2,
			.boot_set_pte	= &boot_set_double_pte,
			.init_pte_clear	= &init_double_pte_clear,
			.boot_get_huge_pte = &boot_get_double_huge_pte,
			.init_get_huge_pte = &init_get_double_huge_pte,
			.split_pt_page	= &split_multiple_pmd_page,
#elif	CONFIG_CPU_ISET == 0
			/* page size and functions should be set dinamicaly */
			.page_size	= -1,
#else	/* CONFIG_CPU_ISET undefined or negative */
# warning "Undefined CPU ISET VERSION #, PAGE SIZE not defined"
			.page_size	= -1,
#endif	/* CONFIG_CPU_ISET 0-6 */
			.is_pte		= false,
			.is_huge	= true,
			.dtlb_type	= COMMON_DTLB_TYPE,
		},
		[E2K_PUD_LEVEL_NUM] = {
			.id		= E2K_PUD_LEVEL_NUM,
			.pt_size	= PUD_SIZE,
			.page_size	= PAGE_PUD_SIZE,
			.pt_shift	= PUD_SHIFT,
			.page_shift	= PUD_SHIFT,
			.pt_mask	= PUD_MASK & _PAGE_PFN_V2,
			.pt_offset	= ~PUD_MASK & _PAGE_PFN_V2,
			.pt_index_mask	= PUD_MASK ^ PGDIR_MASK,
			.page_mask	= PUD_MASK,
			.page_offset	= ~PUD_MASK,
			.ptrs_per_pt	= PTRS_PER_PUD,
			.is_pte		= false,
#if	CONFIG_CPU_ISET >= 5
			.is_huge	= true,
			.huge_ptes	= 1,
			.dtlb_type	= FULL_ASSOCIATIVE_DTLB_TYPE,
#elif	CONFIG_CPU_ISET >= 1
			.is_huge	= false,
#elif	CONFIG_CPU_ISET == 0
			/* huge page enable should be set dinamicaly */
			.is_huge	= false,
#else	/* CONFIG_CPU_ISET undefined or negative */
# warning "Undefined CPU ISET VERSION #, huge page enable not defined"
			.is_huge	= false,
#endif	/* CONFIG_CPU_ISET 0-6 */

#if	CONFIG_CPU_ISET == 1 || CONFIG_CPU_ISET == 2
			.map_pt_huge_page_to_prev_level =
				&map_pud_huge_page_to_multiple_pmds,
#endif	/* CONFIG_CPU_ISET 1-2 */
		},
		[E2K_PGD_LEVEL_NUM] = {
			.id		= E2K_PGD_LEVEL_NUM,
			.pt_size	= PGDIR_SIZE,
			.page_size	= PAGE_PGD_SIZE,
			.pt_shift	= PGDIR_SHIFT,
			.page_shift	= PGDIR_SHIFT,
			.pt_mask	= PGDIR_MASK & E2K_VA_MASK,
			.pt_offset	= ~PGDIR_MASK & E2K_VA_MASK,
			.pt_index_mask	= PGDIR_MASK & E2K_VA_MASK,
			.page_mask	= PGDIR_MASK,
			.page_offset	= ~PGDIR_MASK,
			.ptrs_per_pt	= PTRS_PER_PGD,
			.is_pte		= false,
			.is_huge	= false,
		},
	},
};
EXPORT_SYMBOL(pgtable_struct);
/*
 * TLB flushing:
 */

/*
 *  Flush all processes TLBs of the processor
 */
void
__flush_tlb_all(void)
{
	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
	flush_TLB_all();
}

/*
 * Flush just one specified address of current process.
 */
void __flush_tlb_address(e2k_addr_t addr)
{
	unsigned long context;

	context = current->active_mm->context.cpumsk[raw_smp_processor_id()];

	if (unlikely(context == 0)) {
		/* See comment in __flush_tlb_range(). */
		__flush_tlb_mm(current->active_mm);
	} else {
		count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ONE);
		flush_TLB_page(addr, CTX_HARDWARE(context));
	}
}

/*
 * Flush the TLB entries mapping the virtually mapped linear page
 * table corresponding to specified address of current process.
 */
void __flush_tlb_address_pgtables(e2k_addr_t addr)
{
	unsigned long context;

	context = current->active_mm->context.cpumsk[raw_smp_processor_id()];

	if (unlikely(context == 0)) {
		/* See comment in __flush_tlb_range(). */
		__flush_tlb_mm(current->active_mm);
	} else {
		flush_TLB_page_begin();
		/* flush virtual mapping of PTE entry (third level) */
		__flush_TLB_page(pte_virt_offset(_PAGE_ALIGN_UP(addr,
								PTE_SIZE)),
				 CTX_HARDWARE(context));
		/* flush virtual mapping of PMD entry (second level) */
		__flush_TLB_page(pmd_virt_offset(_PAGE_ALIGN_UP(addr,
								PMD_SIZE)),
				 CTX_HARDWARE(context));
		/* flush virtual mapping of PUD entry (first level) */
		__flush_TLB_page(pud_virt_offset(_PAGE_ALIGN_UP(addr,
								PUD_SIZE)),
				 CTX_HARDWARE(context));
		flush_TLB_page_end();
	}
}

/*
 * Flush just one page of a specified user.
 */
void
__flush_tlb_page(struct mm_struct *mm, e2k_addr_t addr)
{
	unsigned long context;
	
	context = mm->context.cpumsk[raw_smp_processor_id()];

	if (unlikely(context == 0)) {
		/* See comment in __flush_tlb_range(). */
		__flush_tlb_mm(mm);
		return;
	}

	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ONE);

	flush_TLB_page_begin();
	__flush_TLB_page(addr, CTX_HARDWARE(context));
	/* flush virtual mapping of PTE entry (third level) */
	__flush_TLB_page(pte_virt_offset(addr), CTX_HARDWARE(context));
	flush_TLB_page_end();
}

/*
 * Flush a specified user mapping on the processor
 */
void
__flush_tlb_mm(struct mm_struct *mm)
{
	int cpu;

	count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);

	if (mm == current->active_mm) {
		unsigned long ctx, flags;

		/* Should update right now */
		DebugPT("mm context will be reloaded\n");
		raw_all_irq_save(flags);
		cpu = smp_processor_id();
		ctx = get_new_mmu_context(mm, cpu);
		reload_context_mask(ctx);
		raw_all_irq_restore(flags);

		DebugPT("CPU #%d new mm context is 0x%lx\n",
				cpu, mm->context.cpumsk[cpu]);
	} else {
		cpu = raw_smp_processor_id();
#ifdef CONFIG_SMP
		/* Remove this cpu from mm_cpumask. This might be
		 * needed, for example, after sys_io_setup() if the
		 * kernel thread which was using this mm received
		 * flush ipi (unuse_mm() does not clear mm_cpumask).
		 * And maybe there are other such places where
		 * a kernel thread uses user mm. */
		cpumask_clear_cpu(cpu, mm_cpumask(mm));
#endif
		mm->context.cpumsk[cpu] = 0;
	}
}


/*
 * Flush a specified range of pages
 */

/* If the number of pages to be flushed is below this value,
 * then only those pages will be flushed.
 *
 * Flushing one page takes ~150 cycles, flushing the whole mm
 * takes ~400 cycles. Also note that __flush_tlb_range() may
 * be called repeatedly for the same process so high values
 * are bad. */
#define FLUSH_TLB_RANGE_MAX_PAGES 8

void __flush_tlb_range(struct mm_struct *const mm,
		const e2k_addr_t start, const e2k_addr_t end)
{
	const long pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;

	BUG_ON(start > end);

	DebugPT("range start 0x%lx end 0x%lx context 0x%lx mm 0x%px cnt 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		mm, mm->context.cpumsk[raw_smp_processor_id()],
		raw_smp_processor_id());

	if (pages_num <= FLUSH_TLB_RANGE_MAX_PAGES) {
		unsigned long page, pmd_start, pmd_end;
		unsigned long ctx = CTX_HARDWARE(
				mm->context.cpumsk[raw_smp_processor_id()]);

		if (unlikely(ctx == 0)) {
			/* We were trying to flush a range of pages,
			 * but someone is flushing the whole mm.
			 * Now we cannot flush pages (we do not know
			 * the context) so we have to flush the whole mm.
			 *
			 * Even if we will receive the flush ipi we will
			 * just end up flushing mm twice - which is OK
			 * considering how rare this case is. */
			goto flush_mm;
		}

		count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, pages_num);

		flush_TLB_page_begin();
		for (page = PAGE_ALIGN_UP(start); page < end;
				page += PAGE_SIZE)
			__flush_TLB_page(page, ctx);
		/*
		 * flush virtual mapping of PTE entry (third level)
		 *
		 * Needed because Linux assumes that flush_tlb_*()
		 * interfaces flush both pte and pmd levels (this
		 * may be changed in future versions, in which case
		 * this flush can be removed).
		 */
		pmd_start = pte_virt_offset(round_down(start, PMD_SIZE));
		pmd_end = pte_virt_offset(round_up(end, PMD_SIZE));
		for (page = round_down(pmd_start, PAGE_SIZE);
				page < pmd_end; page += PAGE_SIZE)
			__flush_TLB_page(page, ctx);
		flush_TLB_page_end();
	} else {
flush_mm:
		/* Too many pages to flush.
		 * It is faster to change the context instead.
		 * If mm != current->active_mm then setting this
		 * CPU's mm context to 0 will do the trick,
		 * otherwise we duly increment it. */
		__flush_tlb_mm(mm);
	}
}

void __flush_pmd_tlb_range(struct mm_struct *mm,
		unsigned long start, unsigned long end)
{
	long pages_num;

	BUG_ON(start > end);

	end = round_up(end, PMD_SIZE);
	start = round_down(start, PMD_SIZE);

	pages_num = (end - start) / PMD_SIZE;

	if (pages_num <= FLUSH_TLB_RANGE_MAX_PAGES) {
		unsigned long pmd_start, pmd_end;
		e2k_addr_t page;
		unsigned long ctx = CTX_HARDWARE(
				mm->context.cpumsk[raw_smp_processor_id()]);

		if (unlikely(ctx == 0)) {
			/* We were trying to flush a range of pages,
			 * but someone is flushing the whole mm.
			 * Now we cannot flush pages (we do not know
			 * the context) so we have to flush the whole mm.
			 *
			 * Even if we will receive the flush ipi we will
			 * just end up flushing mm twice - which is OK
			 * considering how rare this case is. */
			goto flush_mm;
		}

		count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE,
				pages_num * (PMD_SIZE / PTE_SIZE));

		flush_TLB_page_begin();
		for (page = start; page < end; page += PMD_SIZE)
			__flush_TLB_page(page, ctx);
		/*
		 * flush virtual mapping of PTE entry (third level).
		 *
		 * When flushing high order page table entries,
		 * we must also flush all links below it. E.g. when
		 * flushing PMD, also flush PMD->PTE link (i.e. DTLB
		 * entry for address 0xff8000000000|(address >> 9)).
		 *
		 * Otherwise the following can happen:
		 * 1) High-order page is allocated.
		 * 2) Someone accesses the PMD->PTE link (e.g. half-spec. load)
		 * and creates invalid entry in DTLB.
		 * 3) High-order page is split into 4 Kb pages.
		 * 4) Someone accesses the PMD->PTE link address (e.g. DTLB
		 * entry probe) and reads the invalid entry created earlier.
		 */
		pmd_start = pte_virt_offset(round_down(start, PMD_SIZE));
		pmd_end = pte_virt_offset(round_up(end, PMD_SIZE));
		for (page = round_down(pmd_start, PAGE_SIZE);
				page < pmd_end; page += PAGE_SIZE)
			__flush_TLB_page(page, ctx);
		flush_TLB_page_end();
	} else {
flush_mm:
		/* Too many pages to flush.
		 * It is faster to change the context instead.
		 * If mm != current->active_mm then setting this
		 * CPU's mm context to 0 will do the trick,
		 * otherwise we duly increment it. */
		__flush_tlb_mm(mm);
	}
}

/*
 * Flush the TLB entries mapping the virtually mapped linear page
 * table corresponding to address range [start : end].
 */
void __flush_tlb_pgtables(struct mm_struct *mm, e2k_addr_t start,
			  e2k_addr_t end)
{
	const long pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;

	BUG_ON(start > end);

	DebugPT("range start 0x%lx end 0x%lx context 0x%lx mm 0x%px cnt 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		mm, mm->context.cpumsk[raw_smp_processor_id()],
		raw_smp_processor_id());

	if (pages_num <= FLUSH_TLB_RANGE_MAX_PAGES) {
		e2k_addr_t page;
		unsigned long range_begin, range_end;
		unsigned long ctx = CTX_HARDWARE(
				mm->context.cpumsk[raw_smp_processor_id()]);

		if (unlikely(ctx == 0)) {
			/* We were trying to flush a range of pages,
			 * but someone is flushing the whole mm.
			 * Now we cannot flush pages (we do not know
			 * the context) so we have to flush the whole mm.
			 *
			 * Even if we will receive the flush ipi we will
			 * just end up flushing mm twice - which is OK
			 * considering how rare this case is. */
			goto flush_mm;
		}

		flush_TLB_page_begin();

		/* flush virtual mapping of PTE entries (third level) */
		range_begin = pte_virt_offset(_PAGE_ALIGN_UP(start, PTE_SIZE));
		range_end = pte_virt_offset(_PAGE_ALIGN_DOWN(end, PTE_SIZE));
		for (page = PAGE_ALIGN_UP(range_begin); page < range_end;
				page += PAGE_SIZE)
			__flush_TLB_page(page, ctx);

		/* flush virtual mapping of PMD entries (second level) */
		range_begin = pmd_virt_offset(_PAGE_ALIGN_UP(start, PMD_SIZE));
		range_end = pmd_virt_offset(_PAGE_ALIGN_DOWN(end, PMD_SIZE));
		for (page = PAGE_ALIGN_UP(range_begin); page < range_end;
				page += PAGE_SIZE)
			__flush_TLB_page(page, ctx);

		/* flush virtual mapping of PUD entries (first level) */
		range_begin = pud_virt_offset(_PAGE_ALIGN_UP(start, PUD_SIZE));
		range_end = pud_virt_offset(_PAGE_ALIGN_DOWN(end, PUD_SIZE));
		for (page = PAGE_ALIGN_UP(range_begin); page < range_end;
				page += PAGE_SIZE)
			__flush_TLB_page(page, ctx);

		flush_TLB_page_end();
	} else {
flush_mm:
		/* Too many pages to flush.
		 * It is faster to change the context instead.
		 * If mm != current->active_mm then setting this
		 * CPU's mm context to 0 will do the trick,
		 * otherwise we duly increment it. */
		__flush_tlb_mm(mm);
	}
}

/*
 * Flush a specified range of pages and the TLB entries mapping the virtually
 * mapped linear page table corresponding to address range [start : end].
 */
void
__flush_tlb_range_and_pgtables(struct mm_struct *mm, e2k_addr_t start,
								e2k_addr_t end)
{
	__flush_tlb_range(mm, start, end);
	__flush_tlb_pgtables(mm, start, end);
}

void __flush_tlb_page_and_pgtables(struct mm_struct *mm, unsigned long address)
{
	unsigned long page;
	unsigned long start = address, end = address + E2K_MAX_FORMAT;
	unsigned long range_begin, range_end;
	unsigned long context = mm->context.cpumsk[raw_smp_processor_id()];

	if (unlikely(context == 0)) {
		/* See comment in __flush_tlb_range(). */
		__flush_tlb_mm(mm);
		return;
	}

	context = CTX_HARDWARE(context);

	flush_TLB_page_begin();

	/* flush virtual mapping of PUD entries (first level) */
	range_begin = pud_virt_offset(_PAGE_ALIGN_UP(start, PUD_SIZE));
	range_end = pud_virt_offset(_PAGE_ALIGN_DOWN(end, PUD_SIZE));
	for (page = PAGE_ALIGN_UP(range_begin); page < range_end;
			page += PAGE_SIZE)
		__flush_TLB_page(page, context);

	/* flush virtual mapping of PMD entries (second level) */
	range_begin = pmd_virt_offset(_PAGE_ALIGN_UP(start, PMD_SIZE));
	range_end = pmd_virt_offset(_PAGE_ALIGN_DOWN(end, PMD_SIZE));
	for (page = PAGE_ALIGN_UP(range_begin); page < range_end;
			page += PAGE_SIZE)
		__flush_TLB_page(page, context);

	/* flush virtual mapping of PTE entries (third level) */
	range_begin = pte_virt_offset(_PAGE_ALIGN_UP(start, PTE_SIZE));
	range_end = pte_virt_offset(_PAGE_ALIGN_DOWN(end, PTE_SIZE));
	for (page = PAGE_ALIGN_UP(range_begin); page < range_end;
			page += PAGE_SIZE)
		__flush_TLB_page(page, context);

	for (page = PAGE_ALIGN_UP(start); page < end; page += PAGE_SIZE)
		__flush_TLB_page(page, context);

	flush_TLB_page_end();
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
/*
 * Update all user PGD entries of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void
__flush_cpu_root_pt_mm(struct mm_struct *mm)
{
	if (MMU_IS_SEPARATE_PT())
		return;
	if (!THERE_IS_DUP_KERNEL)
		return;
	if (current->active_mm != mm)
		return;
	copy_user_pgd_to_kernel_root_pt(mm->pgd);
}
/*
 * Update all user PGD entries of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void
__flush_cpu_root_pt(void)
{
	if (MMU_IS_SEPARATE_PT())
		return;
	if (!THERE_IS_DUP_KERNEL)
		return;
	if (current->active_mm == &init_mm || !current->active_mm)
		return;
	copy_user_pgd_to_kernel_root_pt(current->active_mm->pgd);
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

/*
 * CACHES flushing:
 */

static void __write_back_cache_L3(void)
{
	unsigned long flags;
	l3_ctrl_t l3_ctrl;
	int node;

	raw_all_irq_save(flags);
	node = numa_node_id();

	/* Set bit of L3 control register to flush L3 */
	AW(l3_ctrl) = sic_read_node_nbsr_reg(node, SIC_l3_ctrl);
	AS(l3_ctrl).fl = 1;
	sic_write_node_nbsr_reg(node, SIC_l3_ctrl, AW(l3_ctrl));

	/* Wait for flush completion */
	if (cpu_has(CPU_FEAT_ISET_V5)) {
		do {
			AW(l3_ctrl) = sic_read_node_nbsr_reg(node, SIC_l3_ctrl);
		} while (AS(l3_ctrl).fl);
	} else {
		l3_reg_t l3_diag;

		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b0_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b1_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b2_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b3_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b4_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b5_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b6_diag_dw);
		l3_diag = sic_read_node_nbsr_reg(node, SIC_l3_b7_diag_dw);

		__E2K_WAIT_ALL;
	}

	raw_all_irq_restore(flags);
}

static void write_back_cache_all_ipi(void *unused)
{
	int cpu, node;

	write_back_CACHE_L12();

	cpu = smp_processor_id();
	node = numa_node_id();
	if (machine.L3_enable && cpu == cpumask_first(cpumask_of_node(node)))
		__write_back_cache_L3();
}

/*
 * Write Back and Invalidate all caches in the system
 */
void write_back_cache_all(void)
{
	/*
	 * This is rather low-level function
	 * so do not use on_each_cpu() here.
	 */
	nmi_on_each_cpu(write_back_cache_all_ipi, NULL, 1, 0);
}
EXPORT_SYMBOL(write_back_cache_all);

void write_back_cache_range(unsigned long start, size_t size)
{
	/* Some arbitrary condition */
	if (size < SZ_64K)
		flush_DCACHE_range((void *) start, size);
	else
		write_back_cache_all();
}


/*
 * Write Back and Invalidate all caches for current cpu
 */
void local_write_back_cache_all(void)
{
	migrate_disable();
	write_back_CACHE_L12();
	__write_back_cache_L3();
	migrate_enable();
}

void local_write_back_cache_range(unsigned long start, size_t size)
{
	/* Some arbitrary condition */
	if (size < SZ_64K)
		flush_DCACHE_range((void *) start, size);
	else
		local_write_back_cache_all();
}

/*
 *  Invalidate all ICACHES of the host processor
 */
void native_flush_icache_all(void)
{
	DebugIC("started flush_icache_all()\n");
	flush_ICACHE_all();
}

/*
 * Flush a specified range of addresses of specified context
 * from ICACHE of the processor
 */
void
flush_icache_other_range(e2k_addr_t start, e2k_addr_t end,
	unsigned long context)
{
	e2k_addr_t addr;

	preempt_disable();
	DebugIC("started: start 0x%lx end 0x%lx context 0x%lx\n",
		start, end, context);

	/*
	 * It is better to flush_ICACHE_all() if flush range is very big.
	 */
	if ((end - start) / E2K_ICACHE_SET_SIZE > E2K_ICACHE_LINES_NUM) {
		DebugIC("will flush_ICACHE_all()\n");
		flush_ICACHE_all();
		preempt_enable();
		return;
	}

	flush_ICACHE_line_begin();
	for (addr = round_down(start, E2K_ICACHE_SET_SIZE);
			addr < round_up(end, E2K_ICACHE_SET_SIZE);
			addr += E2K_ICACHE_SET_SIZE) {
		DebugIC("will flush_ICACHE_line_sys() 0x%lx\n",
			addr);
		__flush_ICACHE_line_sys(addr, CTX_HARDWARE(context));
	}
	flush_ICACHE_line_end();

	DebugIC("finished: start 0x%lx end 0x%lx context 0x%lx\n",
		start, end, context);
	preempt_enable();
}

/*
 * Flush a specified range of addresses of kernel from ICACHE
 * of the processor
 */

void native_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	e2k_addr_t addr;

	DebugIC("started: start 0x%lx end 0x%lx\n", start, end);

	start = round_down(start, E2K_ICACHE_SET_SIZE);
	end = round_up(end, E2K_ICACHE_SET_SIZE);

	if (cpu_has(CPU_FEAT_FLUSH_DC_IC)) {
		flush_DCACHE_line_begin();
		for (addr = start; addr < end; addr += E2K_ICACHE_SET_SIZE) {
			DebugIC("will flush_DCACHE_line() 0x%lx\n", addr);
			__flush_DCACHE_line(addr);
		}
		flush_DCACHE_line_end();
	} else {
		flush_ICACHE_line_begin();
		for (addr = start; addr < end; addr += E2K_ICACHE_SET_SIZE) {
			DebugIC("will flush_ICACHE_line_sys() 0x%lx\n", addr);
			__flush_ICACHE_line_sys(addr, E2K_KERNEL_CONTEXT);
		}
		flush_ICACHE_line_end();
	}

	DebugIC("finished: start 0x%lx end 0x%lx\n", start, end);
}
EXPORT_SYMBOL(native_flush_icache_range);

/*
 * Flush an array of a specified range of addresses of specified context from
 * ICACHE of the processor
 */

void native_flush_icache_range_array(icache_range_array_t *icache_range_arr)
{
	int i;
	unsigned long context;
	int cpu = smp_processor_id();

	context = icache_range_arr->mm->context.cpumsk[cpu];

	DebugIC("started: icache_range_arr "
		"0x%lx\n",
		icache_range_arr);
	if (context) {
		for (i = 0; i < icache_range_arr->count; i++) {
			icache_range_t icache_range =
				icache_range_arr->ranges[i];
			flush_icache_other_range(
					icache_range.start,
					icache_range.end,
					context);
		}
	} else if (icache_range_arr->mm == current->active_mm) {
		unsigned long ctx, flags;

		raw_all_irq_save(flags);
		ctx = get_new_mmu_context(icache_range_arr->mm, cpu);
		reload_context_mask(ctx);
		raw_all_irq_restore(flags);
	}
	DebugIC("finished: icache_range_arr "
		"0x%lx\n",
		icache_range_arr);
}

/*
 * Flush just one specified page from ICACHE of all processors
 */
void native_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	/*
	 * icache on all cpus can be flushed from current cpu
	 * on E2S
	 */
	if (cpu_has(CPU_FEAT_FLUSH_DC_IC)) {
		unsigned long start = (e2k_addr_t) page_address(page);

		BUILD_BUG_ON(PAGE_SIZE != 16 * E2K_ICACHE_SET_SIZE);
		flush_DCACHE_line_begin();
		__flush_DCACHE_line(start);
		__flush_DCACHE_line_offset(start, E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 2 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 3 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 4 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 5 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 6 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 7 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 8 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 9 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 10 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 11 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 12 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 13 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 14 * E2K_ICACHE_SET_SIZE);
		__flush_DCACHE_line_offset(start, 15 * E2K_ICACHE_SET_SIZE);
		flush_DCACHE_line_end();

		return;
	}

	preempt_disable();
	DebugIC("started: VMA 0x%px page 0x%px\n",
		vma, page);
	if (vma->vm_flags & VM_EXEC) {
		struct mm_struct *mm = vma->vm_mm;
		/*
		 * invalid context will update
		 * while activating or switching to
		 */
		mm->context.cpumsk[raw_smp_processor_id()] = 0;
		if (mm == current->active_mm) {
                        int num_cpu = raw_smp_processor_id();
			unsigned long ctx, flags;

			/* This is called, e.g., as a result of exec().  */
			/* Should update right now */
			DebugIC("mm context will be "
				"reload\n");
			raw_all_irq_save(flags);
			ctx = get_new_mmu_context(mm, num_cpu);
			reload_context_mask(ctx);
			raw_all_irq_restore(flags);
		} else {
			DebugIC("mm context will be "
				"invalidate\n");
		}
	}
	DebugIC("finished: VMA 0x%px page 0x%px\n",
		vma, page);
	preempt_enable();
}

int arch_dup_mmap(struct mm_struct *oldmm, struct mm_struct *mm)
{
	mm_context_t *mmu, *oldmmu;
	struct sival_ptr_list *oldlink;

	if (!oldmm)
		return 0;
	if (!mm)
		return -EINVAL;

	oldmmu = &oldmm->context;
	mmu = &mm->context;

	init_rwsem(&mmu->sival_ptr_list_sem);
	INIT_LIST_HEAD(&mmu->sival_ptr_list_head);

	/* Duplicating oldmmu->sival_ptr_list: */
	down_read(&oldmmu->sival_ptr_list_sem);
	list_for_each_entry(oldlink, &oldmmu->sival_ptr_list_head, link) {
		struct sival_ptr_list *newlink;

		newlink = kmalloc(sizeof(*newlink), GFP_KERNEL);
		if (!newlink) {
			up_read(&oldmmu->sival_ptr_list_sem);
			return -ENOMEM;
		}
		*newlink = *oldlink;
		list_add(&newlink->link, &mmu->sival_ptr_list_head);
	}
	up_read(&oldmmu->sival_ptr_list_sem);
	DebugIC(": sival_ptr_list duplicated 0x%px --> 0x%px\n",
		oldmm, mm);

	mmu->pm_sc_debug_mode = oldmmu->pm_sc_debug_mode;

	return 0;
}

void arch_exit_mmap(struct mm_struct *mm)
{
	struct sival_ptr_list *sival_ptr, *tmp;

	if (mm == NULL)
		return;

	/* Release mmu->sival_ptr_list */
	list_for_each_entry_safe(sival_ptr, tmp,
			&mm->context.sival_ptr_list_head, link) {
		DebugIC(": kfree(%px)\n", sival_ptr);
		list_del(&sival_ptr->link);
		kfree(sival_ptr);
	}

	/* Release hw_contexts */
	hw_contexts_destroy(&mm->context);
}

/*
 * Initialize a new mmu context.  This is invoked when a new
 * address space instance (unique or shared) is instantiated.
 * This just needs to set mm->context[] to an invalid context.
 */
int __init_new_context(struct task_struct *p, struct mm_struct *mm,
		mm_context_t *context)
{
	bool is_fork = p && (p != current);
	int ret;

	memset(&context->cpumsk, 0, nr_cpu_ids * sizeof(context->cpumsk[0]));

	if (is_fork) {
		/*
		 * Copy data on user fork
		 */
		mm_context_t *curr_context = &current->mm->context;

		/*
		 * Copy cut mask from the context of parent process
		 * to the context of new process
		 */
		mutex_lock(&curr_context->cut_mask_lock);
		bitmap_copy((unsigned long *) &context->cut_mask,
				(unsigned long *) &curr_context->cut_mask,
				USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
		mutex_unlock(&curr_context->cut_mask_lock);
	} else {
		/*
		 * Initialize by zero cut_mask of new process
		 */
		mutex_init(&context->cut_mask_lock);
		bitmap_zero((unsigned long *) &context->cut_mask,
				USER_CUT_AREA_SIZE/sizeof(e2k_cute_t));
	}

	atomic_set(&context->tstart, 1);

	init_rwsem(&context->sival_ptr_list_sem);
	INIT_LIST_HEAD(&context->sival_ptr_list_head);

	INIT_LIST_HEAD(&context->delay_free_stacks);
	init_rwsem(&context->core_lock);

	INIT_LIST_HEAD(&context->cached_stacks);
	spin_lock_init(&context->cached_stacks_lock);
	context->cached_stacks_size = 0;

	if (mm == NULL)
		return 0;

	ret = hw_contexts_init(p, context, is_fork);
	return ret;
}
