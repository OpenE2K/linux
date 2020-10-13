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

#include <asm/types.h>
#include <asm/mmu_regs.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/mmu_context.h>
#include <asm/secondary_space.h>

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

	flush_TLB_page(addr, CTX_HARDWARE(context));

	if (TASK_IS_BINCO(current) && ADDR_IN_SS(addr) && !IS_UPT_E3S) {
		/* flush Intel address */
		flush_TLB_ss_page(addr - SS_ADDR_START, CTX_HARDWARE(context));
	}
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
		flush_secondary_context(mm); /* flush secondary TLB */
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
	const int pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;

	BUG_ON(start > end);

	DebugPT("range start 0x%lx end 0x%lx context 0x%lx mm 0x%p cnt 0x%lx CPU #%d\n",
		PAGE_ALIGN_UP(start), PAGE_ALIGN_DOWN(end),
		CTX_HARDWARE(mm->context.cpumsk[raw_smp_processor_id()]),
		mm, mm->context.cpumsk[raw_smp_processor_id()],
		raw_smp_processor_id());

	if (pages_num <= FLUSH_TLB_RANGE_MAX_PAGES) {
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

		count_vm_tlb_events(NR_TLB_LOCAL_FLUSH_ONE, pages_num);

		flush_TLB_page_begin();
		for (page = PAGE_ALIGN_UP(start); page < end;
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
 * Flush the TLB entries mapping the virtually mapped linear page
 * table corresponding to address range [start : end].
 */
void __flush_tlb_pgtables(struct mm_struct *mm, e2k_addr_t start,
			  e2k_addr_t end)
{
	const int pages_num = (PAGE_ALIGN_DOWN(end) - PAGE_ALIGN_UP(start))
			/ PAGE_SIZE;

	BUG_ON(start > end);

	DebugPT("range start 0x%lx end 0x%lx context 0x%lx mm 0x%p cnt 0x%lx CPU #%d\n",
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

	/* flush Intel address */
	if (TASK_IS_BINCO(current) && ADDR_IN_SS(address) && !IS_UPT_E3S)
		__flush_TLB_ss_page(address - SS_ADDR_START, context);

	flush_TLB_page_end();
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
/*
 * Update just one specified address of current active mm.
 * PGD is updated into CPU root page table from main user PGD table
 */
void
__flush_cpu_root_pt_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	if (!THERE_IS_DUP_KERNEL) {
		return;
	}
	if (current->active_mm != vma->vm_mm) {
		return;
	}
	copy_user_pgd_to_kernel_root_pt_addr(vma->vm_mm->pgd, addr);
}
/*
 * Update user PGD entries from address range of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void
__flush_cpu_root_pt_range(struct mm_struct *mm, e2k_addr_t start,
							e2k_addr_t end)
{
	if (!THERE_IS_DUP_KERNEL) {
		return;
	}
	if (current->active_mm != mm) {
		return;
	}
	copy_user_pgd_to_kernel_root_pt_addr_range(mm->pgd, start, end);
}
/*
 * Update all user PGD entries of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void
__flush_cpu_root_pt_mm(struct mm_struct *mm)
{
	if (!THERE_IS_DUP_KERNEL) {
		return;
	}
	if (current->active_mm != mm) {
		return;
	}
	copy_user_pgd_to_kernel_root_pt(mm->pgd);
}
/*
 * Update all user PGD entries of current active mm.
 * PGDs are updated into CPU root page table from main user PGD table
 */
void
__flush_cpu_root_pt(void)
{
	if (!THERE_IS_DUP_KERNEL) {
		return;
	}
	if (current->active_mm == &init_mm) {
		return;
	}
	copy_user_pgd_to_kernel_root_pt(current->active_mm->pgd);
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

/*
 * CACHES flushing:
 */

/*
 *  Invalidate all CACHES of the host processor
 */
void
__invalidate_cache_all(void)
{
	invalidate_CACHE_all();
}

/*
 *  Write Back and Invalidate all CACHES of the host processor
 */
void
__write_back_cache_all(void)
{
	write_back_CACHE_all();
}

/*
 *  Invalidate all ICACHES of the host processor
 */
void
__flush_icache_all(void)
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
	DebugIC("started: start 0x%lx end 0x%lx "
		"context 0x%lx\n",
		start, end, context);

	/*
	 * It is better to flush_ICACHE_all() if flush range is very big.
	 */
	if ((end - start) / E2K_ICACHE_SET_SIZE > E2K_ICACHE_LINES_NUM) {
		DebugIC("will "
			"flush_ICACHE_all()\n");
		flush_ICACHE_all();
		preempt_enable();
		return;
	}

	for (addr = round_down(start, E2K_ICACHE_SET_SIZE);
			addr < round_up(end, E2K_ICACHE_SET_SIZE);
			addr += E2K_ICACHE_SET_SIZE) {
		DebugIC("will "
			"flush_ICACHE_line_sys() 0x%lx\n",
			addr);
		flush_ICACHE_line_sys(addr, CTX_HARDWARE(context));
	}

	DebugIC("finished: start 0x%lx end 0x%lx "
		"context 0x%lx\n",
		start, end, context);
	preempt_enable();
}

/*
 * Flush a specified range of addresses of kernel from ICACHE
 * of the processor
 */

void
__flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	e2k_addr_t addr;

	DebugIC("started: start 0x%lx end 0x%lx\n", start, end);

	start = round_down(start, E2K_ICACHE_SET_SIZE);
	end = round_up(end, E2K_ICACHE_SET_SIZE);

	/*
	 * icache on all cpus can be flushed from current cpu since E2S
	 */
	if (machine.iset_ver >= E2K_ISET_V3) {
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
EXPORT_SYMBOL(__flush_icache_range);

/*
 * Flush an array of a specified range of addresses of specified context from
 * ICACHE of the processor
 */

void
__flush_icache_range_array(icache_range_array_t *icache_range_arr)
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
		flush_secondary_context(icache_range_arr->mm);
		raw_all_irq_restore(flags);
	}
	DebugIC("finished: icache_range_arr "
		"0x%lx\n",
		icache_range_arr);
}

/*
 * Flush just one specified page from ICACHE of all processors
 */
void
__flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	/*
	 * icache on all cpus can be flushed from current cpu
	 * on E2S
	 */
	if (machine.iset_ver >= E2K_ISET_V3) {
		e2k_addr_t start = (e2k_addr_t) page_address(page);
		__flush_icache_range(start, start + PAGE_SIZE);
		return;
	}

	preempt_disable();
	DebugIC("started: VMA 0x%p page 0x%p\n",
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
			flush_secondary_context(mm); /* flush secondary TLB */
			raw_all_irq_restore(flags);
		} else {
			DebugIC("mm context will be "
				"invalidate\n");
		}
	}
	DebugIC("finished: VMA 0x%p page 0x%p\n",
		vma, page);
	preempt_enable();
}
