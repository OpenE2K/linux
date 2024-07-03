/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/hardirq.h>
#include <linux/mm.h>
#include <linux/preempt.h>

#include <asm/mmu_context.h>
#include <asm/nmi.h>
#include <asm/tlbflush.h>
#include <asm/trace-tlb-flush.h>

#include "trace-tlb-flush.h"

#define	DEBUG_PT_MODE		0	/* Data Caches */
#define DebugPT(...)		DebugPrint(DEBUG_PT_MODE ,##__VA_ARGS__)

void mmu_pid_flush_tlb_mm(mm_context_t *context, bool is_active,
		cpumask_t *mm_cpumask, int cpu, bool trace_enabled)
{
	unsigned long old_pid = context->cpumsk[cpu];

	if (is_active) {
		/* Should update right now */
		flush_mmu_pid(context);
		DebugPT("CPU #%d new mm context is 0x%llx\n", raw_smp_processor_id(),
				context->cpumsk[raw_smp_processor_id()]);
	} else {
#ifdef CONFIG_SMP
		/* Remove this cpu from mm_cpumask. This might be
		 * needed, for example, after sys_io_setup() if the
		 * kernel thread which was using this mm received
		 * flush ipi (unuse_mm() does not clear mm_cpumask).
		 * And maybe there are other such places where
		 * a kernel thread uses user mm. */
		if (likely(mm_cpumask)) {
			cpumask_clear_cpu(cpu, mm_cpumask);
		}
#endif
		context->cpumsk[cpu] = 0;
	}

	if (unlikely(trace_enabled))
		trace_mmu_pid_flush_tlb_mm(cpu, context, is_active, old_pid,
				context->cpumsk[cpu]);
}

struct mm_args {
	struct mm_struct *mm;
	mm_context_t *context;
	cpumask_t *mm_cpumask;
};

struct flush_tlb_args {
	struct mm_struct *mm;
	mm_context_t *context;
	cpumask_t *mm_cpumask;
	bool trace_enabled;
};

static void flush_tlb_mm_ipi(void *info)
{
	struct flush_tlb_args *args = (struct flush_tlb_args *) info;
	struct mm_struct *mm = args->mm;

#ifdef CONFIG_SMP
	inc_irq_stat(irq_tlb_count);
#endif
	mmu_pid_flush_tlb_mm(args->context, mm ? (mm == current->active_mm) : false,
			args->mm_cpumask, smp_processor_id(), args->trace_enabled);
}

/*
 * Flush a specified user mapping on the calling CPU.
 */
void native_local_flush_tlb_mm(struct mm_struct *mm)
{
	int cpu = get_cpu();
	mmu_pid_flush_tlb_mm(&mm->context, mm == current->active_mm,
			mm_cpumask(mm), cpu, trace_native_flush_tlb_enabled());
	put_cpu();
}

/*
 * Flush a specified user mapping
 */
void generic_flush_tlb_mm(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, bool trace_enabled)
{
	int cpu = get_cpu();

	clear_mm_remote_context(context, cpu);

	mmu_pid_flush_tlb_mm(context, mm ? mm == current->active_mm : false,
			     mm_cpumask, cpu, trace_enabled);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	/* Check that mm_cpumask() has some other CPU set and
	 * send flush ipi to all other cpus in mm_cpumask(). */
	if (cpumask_any_but(mm_cpumask, cpu) < nr_cpu_ids) {
		struct flush_tlb_args args = {
			.mm = mm,
			.context = context,
			.mm_cpumask = mm_cpumask,
			.trace_enabled = trace_enabled
		};
		smp_call_function_many(mm_cpumask, flush_tlb_mm_ipi, &args, 1);
	}

	put_cpu();
}

void native_flush_tlb_mm(struct mm_struct *mm)
{
	generic_flush_tlb_mm(mm, &mm->context, mm_cpumask(mm),
			     trace_native_flush_tlb_enabled());
}

void mmu_pid_flush_tlb_page(mm_context_t *context, bool is_active,
		cpumask_t *mm_cpumask, unsigned long addr, int cpu,
		bool trace_enabled)
{
	unsigned long pid = context->cpumsk[cpu];

	if (unlikely(pid == 0)) {
		/* See comment in mmu_pid_flush_tlb_range(). */
		mmu_pid_flush_tlb_mm(context, is_active, mm_cpumask,
				     cpu, trace_enabled);
	} else {
		flush_TLB_page(addr, CTX_HARDWARE(pid));
	}

	if (unlikely(trace_enabled)) {
		trace_mmu_pid_flush_tlb_page(cpu, context, addr, pid, pid);
	}
}

/*
 * Flush a single user page from TLB.
 *
 * Note that this operation only invalidates a single, last-level
 * page-table entry and therefore does not affect any walk-caches.
 */
void generic_flush_tlb_page(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, unsigned long addr, bool trace_enabled)
{
	int cpu = get_cpu();

	clear_mm_remote_context(context, cpu);

	mmu_pid_flush_tlb_page(context, mm ? mm == current->active_mm : false,
			       mm_cpumask, addr, cpu, trace_enabled);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	/* Check that mm_cpumask() has some other CPU set and
	 * send flush ipi to all other cpus in mm_cpumask(). */
	if (cpumask_any_but(mm_cpumask, cpu) < nr_cpu_ids) {
		struct flush_tlb_args args = {
			.mm = mm,
			.context = context,
			.mm_cpumask = mm_cpumask,
			.trace_enabled = trace_enabled
		};
		smp_call_function_many(mm_cpumask, flush_tlb_mm_ipi, &args, 1);
	}

	put_cpu();
}

/*
 * Flush a single user page from TLB on the calling CPU.
 *
 * Note that this operation only invalidates a single, last-level
 * page-table entry and therefore does not affect any walk-caches.
 */
void native_local_flush_tlb_page(struct mm_struct *mm, unsigned long addr)
{
	int cpu = get_cpu();
	mmu_pid_flush_tlb_page(&mm->context, mm == current->active_mm, mm_cpumask(mm),
			       addr, cpu, trace_native_flush_tlb_enabled());
	put_cpu();
}

void native_flush_tlb_page(struct mm_struct *mm, unsigned long addr)
{
	generic_flush_tlb_page(mm, &mm->context, mm_cpumask(mm), addr,
			       trace_native_flush_tlb_enabled());
}
EXPORT_SYMBOL(native_flush_tlb_page);

static void mmu_pid_flush_tlb_all(void)
{
	flush_TLB_all();
	if (trace_native_flush_tlb_enabled())
		trace_mmu_pid_flush_tlb_all(smp_processor_id());
}

static void flush_tlb_all_ipi(void *info)
{
#ifdef CONFIG_SMP
	inc_irq_stat(irq_tlb_count);
#endif
	mmu_pid_flush_tlb_all();
}


/*
 *  Flush all TLBs of the calling CPU.
 */
void native_local_flush_tlb_all(void)
{
	preempt_disable();
	mmu_pid_flush_tlb_all();
	preempt_enable();
}

/*
 * Flush all TLBs
 */
void native_flush_tlb_all(void)
{
	preempt_disable();
	mmu_pid_flush_tlb_all();
	smp_call_function(flush_tlb_all_ipi, NULL, 1);
	preempt_enable();
}
EXPORT_SYMBOL(native_flush_tlb_all);

/* If the number of pages to be flushed is less or equal to
 * this value then only those pages will be flushed.
 *
 * Flushing takes ~150 cycles for a page and ~400 cycles for
 * whole mm.  Also note that mmu_pid_flush_tlb_range() may be called
 * repeatedly for the same process so high values are bad. */
#define FLUSH_TLB_RANGE_MAX_PAGES(has_context) ((has_context) ? 16 : 32)

void mmu_pid_flush_tlb_range(mm_context_t *context, bool is_active,
		cpumask_t *mm_cpumask, unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask, int cpu, bool trace_enabled)
{
	unsigned long page;
	u64 pid = context ? context->cpumsk[cpu] : 0;

	BUG_ON(start > end);

	start = round_down(start, stride);
	end = round_up(end, stride);
	(end == start) ? end += stride : end;

	DebugPT("range start 0x%lx end 0x%lx context 0x%px pid 0x%llx CPU #%d\n",
			start, end, context, pid, cpu);

	/* If (context && pid == 0) it means that we were trying to
	 * flush a range of pages, but someone is flushing the whole mm.
	 * Now we cannot flush just requested pages (we do not know the
	 * context) so we have to flush the whole mm.
	 *
	 * Even if we will receive the flush ipi we will just end up
	 * flushing mm twice - which is OK considering how rare this
	 * case is. */
	if (end - start > FLUSH_TLB_RANGE_MAX_PAGES(!!context) * stride ||
	    context && unlikely(CTX_HARDWARE(pid) == E2K_KERNEL_CONTEXT)) {
		/* Too many pages to flush.  It is faster to change
		 * the context instead.  If mm != current->active_mm
		 * then setting this CPU's mm context to 0 will do
		 * the trick, otherwise we duly increment it. */
		if (context) {
			mmu_pid_flush_tlb_mm(context, is_active, mm_cpumask, cpu,
					     trace_native_flush_tlb_enabled());
		} else {
			mmu_pid_flush_tlb_all();
		}
		if (unlikely(trace_enabled)) {
			trace_mmu_pid_flush_tlb_range(cpu, context,
					start, end, pid,
					context->cpumsk[cpu]);
		}
		return;
	}

	flush_TLB_page_begin();

	/*
	 * 1) Flush the last level
	 */
	if (levels_mask & E2K_PAGES_LEVEL_MASK) {
		for (page = start; page < end; page += stride)
			__flush_TLB_page(page, CTX_HARDWARE(pid));
		if (unlikely(trace_enabled)) {
			trace_mmu_pid_flush_tlb_range(cpu, context,
					start, end, pid, pid);
		}
	}

	/*
	 * 2) Check if we are asked to flush intermediate page table
	 * levels (or if we have to flush them because of united
	 * TLB design on !CPU_FEAT_SEPARATE_TLU_CACHE cpus).
	 */
	if (!cpu_has(CPU_FEAT_SEPARATE_TLU_CACHE)) {
		if (stride > PAGE_SIZE)
			levels_mask |= E2K_PTE_LEVEL_MASK;
		if (stride > PMD_SIZE)
			levels_mask |= E2K_PMD_LEVEL_MASK;
		if (stride > PUD_SIZE)
			levels_mask |= E2K_PUD_LEVEL_MASK;
	}
	if ((levels_mask & ~E2K_PAGES_LEVEL_MASK) == 0)
		goto out;

	/*
	 * 3) Flush intermediate levels.
	 *
	 * On iset v6 make use of a new flush_page_tlu_cache instruction.
	 */
	if (cpu_has(CPU_FEAT_ISET_V6)) {
		unsigned long pt_stride = max(stride, PMD_SIZE);
		u64 type;

		if (hweight32(levels_mask & ~E2K_PAGES_LEVEL_MASK) != 1) {
			type = 0; /* Flush all intermediate levels */
		} else if (levels_mask & E2K_PTE_LEVEL_MASK) {
			type = 1;
		} else if (levels_mask & E2K_PMD_LEVEL_MASK) {
			type = 2;
			pt_stride = max(stride, PUD_SIZE);
		} else /* E2K_PUD_LEVEL_MASK */ {
			type = 3;
			pt_stride = max(stride, PGDIR_SIZE);
		}

		page = start;
		do {
			__flush_TLB_page_tlu_cache(page, CTX_HARDWARE(pid), type);
		} while (page += pt_stride,
			 unlikely(page < round_up(end, pt_stride)));

		goto out;
	}

	if (levels_mask & E2K_PTE_LEVEL_MASK) {
		unsigned long pmd_start, pmd_end;

		/* flush virtual mapping of PTE entries (2nd PT level) */
		pmd_start = pte_virt_offset(round_down(start, PTE_SIZE));
		pmd_end = PAGE_ALIGN(pte_virt_offset(round_up(end, PTE_SIZE)));

		page = pmd_start;
		do {
			__flush_TLB_page(page, CTX_HARDWARE(pid));
		} while (page += PAGE_SIZE, unlikely(page < pmd_end));

		if (unlikely(trace_enabled)) {
			trace_mmu_pid_flush_tlb_range(cpu, context,
					pmd_start, pmd_end, pid, pid);
		}
	}

	if (levels_mask & E2K_PMD_LEVEL_MASK) {
		unsigned long pud_start, pud_end;

		/* flush virtual mapping of PMD entries (3rd PT level) */
		pud_start = pmd_virt_offset(round_down(start, PMD_SIZE));
		pud_end = PAGE_ALIGN(pmd_virt_offset(round_up(end, PMD_SIZE)));

		page = pud_start;
		do {
			__flush_TLB_page(page, CTX_HARDWARE(pid));
		} while (page += PAGE_SIZE, unlikely(page < pud_end));

		if (unlikely(trace_enabled)) {
			trace_mmu_pid_flush_tlb_range(cpu, context,
					pud_start, pud_end, pid, pid);
		}
	}

	if (levels_mask & E2K_PUD_LEVEL_MASK) {
		unsigned long pgd_start, pgd_end;

		/* flush virtual mapping of PUD entries (4th PT level) */
		pgd_start = pud_virt_offset(round_down(start, PUD_SIZE));
		pgd_end = pud_virt_offset(round_up(end, PUD_SIZE));

		page = pgd_start;
		do {
			__flush_TLB_page(page, CTX_HARDWARE(pid));
		} while (page += PAGE_SIZE, unlikely(page < pgd_end));

		if (unlikely(trace_enabled)) {
			trace_mmu_pid_flush_tlb_range(cpu, context,
					pgd_start, pgd_end, pid, pid);
		}
	}

out:
	flush_TLB_page_end();
}

/*
 * Flush a range of user pages on the calling CPU.
 */
void native_local_flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
		unsigned long end, unsigned long stride, u32 levels_mask)
{
	int cpu = get_cpu();
	mmu_pid_flush_tlb_range(&mm->context, mm == current->active_mm,
				mm_cpumask(mm), start, end, stride, levels_mask,
				cpu, trace_native_flush_tlb_enabled());
	put_cpu();
}

/*
 * Local Flush a range of user pages on the calling CPU.
 */
void generic_local_flush_tlb_mm_range(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask, bool trace_enabled)
{
	int cpu = get_cpu();
	mmu_pid_flush_tlb_range(context, mm ? mm == current->active_mm : false,
				mm_cpumask, start, end, stride, levels_mask,
				cpu, trace_enabled);
	put_cpu();
}

/*
 * Flush a range of pages
 */
void generic_flush_tlb_mm_range(struct mm_struct *mm, mm_context_t *context,
		cpumask_t *mm_cpumask, unsigned long start, unsigned long end,
		unsigned long stride, u32 levels_mask, bool trace_enabled)
{
	int cpu = get_cpu();

	clear_mm_remote_context(context, cpu);

	mmu_pid_flush_tlb_range(context, mm ? mm == current->active_mm : false,
				mm_cpumask, start, end, stride, levels_mask,
				cpu, trace_enabled);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	/* Check that mm_cpumask() has some other CPU set
	 * send flush ipi to all other cpus in mm_cpumask(). */
	if (cpumask_any_but(mm_cpumask, cpu) < nr_cpu_ids) {
		struct flush_tlb_args args = {
			.mm = mm,
			.context = context,
			.mm_cpumask = mm_cpumask,
			.trace_enabled = trace_enabled
		};
		smp_call_function_many(mm_cpumask, flush_tlb_mm_ipi, &args, 1);
	}

	put_cpu();
}

void native_flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
		unsigned long end, unsigned long stride, u32 levels_mask)
{
	generic_flush_tlb_mm_range(mm, &mm->context, mm_cpumask(mm), start, end,
			stride, levels_mask, trace_native_flush_tlb_enabled());
}
EXPORT_SYMBOL(native_flush_tlb_mm_range);

struct flush_tlb_info {
	unsigned long start;
	unsigned long end;
};

static void flush_tlb_kernel_range_info(void *arg)
{
	struct flush_tlb_info *info = arg;

#ifdef CONFIG_SMP
	inc_irq_stat(irq_tlb_count);
#endif
	mmu_pid_flush_tlb_range(NULL, true /* unused */, NULL, info->start, info->end,
			PAGE_SIZE, FLUSH_TLB_LEVELS_ALL, smp_processor_id(), false);
}

void native_flush_tlb_kernel_range(unsigned long start, unsigned long end)
{
	struct flush_tlb_info info = {
		start = start,
		end = end
	};

	on_each_cpu(flush_tlb_kernel_range_info, &info, 1);
}
EXPORT_SYMBOL(native_flush_tlb_kernel_range);

/**
 * native_flush_tlb_kernel_range_nmi - IRQ-safe version of
 *				       native_flush_tlb_kernel_range()
 * @start - start of area to flush
 * @end - end of area to flush
 *
 * This version uses internally non-maskable interrupts (NMIs) so it
 * can be used with disabled interrupts (but not with disabled NMIs).
 */
void native_flush_tlb_kernel_range_nmi(unsigned long start, unsigned long end)
{
	struct flush_tlb_info info = {
		start = start,
		end = end
	};

	nmi_on_each_cpu(flush_tlb_kernel_range_info, &info, 1, 0);
}
