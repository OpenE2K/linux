/*
 * SMP Support
 *
 * Lots of stuff stolen from arch/i386/kernel/smp.c
 */

#include <linux/init.h>

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/spinlock.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/cache.h>
#include <linux/interrupt.h>
#include <linux/cpu.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/notifier.h>

#include <asm/e2k_debug.h>
#include <asm/mtrr.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/console.h>

#include <asm/regs_state.h>

#undef	DEBUG_SMP_MODE
#undef	DebugSMP
#define DEBUG_SMP_MODE		0	
#define DebugSMP(...)		DebugPrint(DEBUG_SMP_MODE ,##__VA_ARGS__)


extern void enable_local_APIC(void);

int refresh_processor;


/*
 * Flush a specified user mapping
 */

static void
flush_tlb_mm_ipi(void* info)
{
	struct mm_struct *mm = (struct mm_struct *)info;

	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);
	inc_irq_stat(irq_tlb_count);

	__flush_cpu_root_pt_mm(mm);
	__flush_tlb_mm(mm);
}

void
smp_flush_tlb_mm(struct mm_struct *const mm)
{
	int i;

	preempt_disable();

	/* Signal to all users of this mm that it has been flushed.
	 * Invalid context will be updated while activating or switching to. */
	for (i = 0; i < nr_cpu_ids; i++)
		mm->context.cpumsk[i] = 0;

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	__flush_tlb_mm(mm);

	/* Check that mm_cpumask() has some other CPU set */
	if (cpumask_any_but(mm_cpumask(mm), smp_processor_id()) < nr_cpu_ids) {
		/* Send flush ipi to all other cpus in mm_cpumask(). */
		count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
		smp_call_function_many(mm_cpumask(mm), flush_tlb_mm_ipi, mm, 1);
	}

	preempt_enable();
}


/*
 * Flush a single page from TLB
 */

void smp_flush_tlb_page(struct vm_area_struct *const vma,
		const e2k_addr_t addr)
{
	struct mm_struct *const mm = vma->vm_mm;
	int i, cpu;

	preempt_disable();

	cpu = smp_processor_id();

	/* See comment in smp_flush_tlb_range() */
	for (i = 0; i < nr_cpu_ids; i++) {
		if (i == cpu)
			continue;
		mm->context.cpumsk[i] = 0;
	}

	__flush_tlb_page(mm, addr);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	/* Check that mm_cpumask() has some other CPU set */
	if (cpumask_any_but(mm_cpumask(mm), cpu) < nr_cpu_ids) {
		/* Send flush ipi to all other cpus in mm_cpumask(). */
		count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
		smp_call_function_many(mm_cpumask(mm), flush_tlb_mm_ipi,
				vma->vm_mm, 1);
	}

	preempt_enable();
}
EXPORT_SYMBOL(smp_flush_tlb_page);

/*
 * Flush all processes TLBs 
 */

static void flush_tlb_all_ipi(void* info)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH_RECEIVED);
	inc_irq_stat(irq_tlb_count);

	__flush_tlb_all();
	__flush_cpu_root_pt();
}

void smp_flush_tlb_all(void)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	smp_call_function(flush_tlb_all_ipi, NULL, 1);
	__flush_tlb_all();
}
EXPORT_SYMBOL(smp_flush_tlb_all);


/*
 * Flush a range of pages
 */

void smp_flush_tlb_range(struct mm_struct *const mm,
		const e2k_addr_t start, const e2k_addr_t end)
{
	int cpu, i;

	//TODO in smp_flush_tlb_*() migrate_disable() will be enough
	//instead of preempt_disable() after move to 3.0-rt
	preempt_disable();

	cpu = smp_processor_id();

	/* Signal to all users of this mm that it has been flushed.
	 * Invalid context will be updated while activating or switching to.
	 *
	 * Things to consider:
	 *
	 * 1) Clearing the whole context for CPUs to which we send the flush
	 * ipi looks unnecessary, but is needed to avoid race conditions. The
	 * problem is that there is a window between reading mm_cpumask() and
	 * deciding which context should be set to 0. In that window situation
	 * could have changed, so the only safe way is to set mm context on
	 * ALL cpus to 0.
	 *
	 * 2) Setting it to 0 essentially means that the cpus which receive the
	 * flush ipis cannot flush only a range of pages because they do not
	 * know the context, so they will flush the whole mm. 
	 *
	 * 3) TODO FIXME This way of doing things is OK for 2 CPUs, for 4 CPUs,
	 * but it may become a problem for e2s with its 64 CPUs if there is a
	 * really-multi-threaded application running. If this is the case it
	 * would be better to implement scheme which will remember pending TLB
	 * flush requests. But such a scheme will greatly increase struct mm
	 * size (64 * 4 * 32 = 8 Kb for 64-processors system with a maximum
	 * of 4 simultaneously pending flushes each taking up 32 bytes).
	 *
	 * This problem (3) only gets worse when we are making all pages valid
	 * since EVERY mmap/sys_brk and some other calls will end up sending
	 * 63 flush ipis which will flush all the TLBs. Until a migrate_disable()
	 * is implemented they will have to do it under preempt_disable()...
	 * Assuming the process uses malloc a lot this can become a problem. */
	for (i = 0; i < nr_cpu_ids; i++) {
		if (i == cpu)
			/* That being said, current CPU can still
			 * flush only the given range of pages. */
			continue;
		mm->context.cpumsk[i] = 0;
	}

	__flush_tlb_range(mm, start, end);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	/* Check that mm_cpumask() has some other CPU set */
	if (cpumask_any_but(mm_cpumask(mm), cpu) < nr_cpu_ids) {
		/* Send flush ipi to all other cpus in mm_cpumask(). */
		count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
		smp_call_function_many(mm_cpumask(mm), flush_tlb_mm_ipi, mm, 1);
	}

	preempt_enable();
}
EXPORT_SYMBOL(smp_flush_tlb_range);


/*
 * Flush a range of pages and page tables.
 */

void smp_flush_tlb_range_and_pgtables(struct mm_struct *const mm,
		const e2k_addr_t start, const e2k_addr_t end)
{
	int i, cpu;

	preempt_disable();

	cpu = smp_processor_id();

	/* See comment in smp_flush_tlb_range() */
	for (i = 0; i < nr_cpu_ids; i++) {
		if (i == cpu)
			continue;
		mm->context.cpumsk[i] = 0;
	}

	__flush_tlb_range_and_pgtables(mm, start, end);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	/* Check that mm_cpumask() has some other CPU set */
	if (cpumask_any_but(mm_cpumask(mm), cpu) < nr_cpu_ids) {
		/* Send flush ipi to all other cpus in mm_cpumask(). */
		count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
		smp_call_function_many(mm_cpumask(mm), flush_tlb_mm_ipi, mm, 1);
	}

	preempt_enable();
}

static void smp_flush_icache_range_ipi(void *info)
{
	icache_range_t *icache_range = (icache_range_t *)info;

	__flush_icache_range(icache_range->start, icache_range->end);
}

void smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	icache_range_t icache_range;

	icache_range.start = start;
	icache_range.end = end;

	preempt_disable();
	smp_call_function(smp_flush_icache_range_ipi, &icache_range, 1);
	__flush_icache_range(start, end);
	preempt_enable();
}
EXPORT_SYMBOL(smp_flush_icache_range);

static void smp_flush_icache_range_array_ipi(void *info)
{
	icache_range_array_t *icache_range_arr = (icache_range_array_t *)info;

	__flush_icache_range_array(icache_range_arr);
}

void smp_flush_icache_range_array(icache_range_array_t *icache_range_arr)
{
	preempt_disable();
	smp_call_function(
		smp_flush_icache_range_array_ipi, icache_range_arr, 1);
	__flush_icache_range_array(icache_range_arr);
	preempt_enable();
}

static void smp_flush_icache_kernel_line_ipi(void *info)
{
	flush_ICACHE_kernel_line(*((e2k_addr_t *)info));
}

void smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	smp_call_function(smp_flush_icache_kernel_line_ipi, &addr, 1);
	flush_ICACHE_kernel_line(addr);
}

static void smp_flush_icache_page_ipi(void* info)
{
	icache_page_t *icache_page = (icache_page_t *)info;

	__flush_icache_page(icache_page->vma, icache_page->page);
}

void smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	icache_page_t icache_page;
	struct mm_struct *mm = vma->vm_mm;
	int cpu, i;

	preempt_disable();

	cpu = smp_processor_id();

	/* See comment in smp_flush_tlb_range() */
	for (i = 0; i < nr_cpu_ids; i++) {
		if (i == cpu)
			continue;
		mm->context.cpumsk[i] = 0;
	}

	__flush_icache_page(vma, page);

	/* See comment about memory barriers in do_switch_mm(). */
	smp_mb();

	icache_page.vma = vma;
	icache_page.page = page;

	/* Check that mm_cpumask() has some other CPU set */
	if (cpumask_any_but(mm_cpumask(mm), cpu) < nr_cpu_ids)
		smp_call_function(smp_flush_icache_page_ipi, &icache_page, 1);

	preempt_enable();
}

void smp_flush_icache_all_ipi(void *info)
{
	__flush_icache_all();
}

void smp_flush_icache_all(void)
{
	smp_call_function(smp_flush_icache_all_ipi, NULL, 1);
	__flush_icache_all();
}


static void stop_this_cpu (void * dummy)
{
	/*
	 * Remove this CPU:
	 */

	set_cpu_online(smp_processor_id(), false);
	local_irq_disable();
#ifdef CONFIG_L_LOCAL_APIC
	disable_local_APIC();
#endif /* CONFIG_L_LOCAL_APIC */
	refresh_processor = refresh_processor & ~(1U << (NR_CPUS - smp_processor_id() - 1));
	for (;;){
		if (refresh_processor & (1U << (NR_CPUS - smp_processor_id() - 1)))
			break;
		barrier();
	}
	refresh_processor = refresh_processor & ~(1U << (NR_CPUS - smp_processor_id() - 1));
	local_irq_enable();
#ifdef CONFIG_L_LOCAL_APIC
	enable_local_APIC();
#endif /* CONFIG_L_LOCAL_APIC */
}

/*
 * this function calls the 'stop' function on all other CPUs in the system.
 */

void smp_send_refresh(void)
{
	refresh_processor = refresh_processor | ~(0U);

}


void smp_send_stop(void)
{
	smp_call_function(stop_this_cpu, NULL, 0);

	local_irq_disable();
#ifdef CONFIG_L_LOCAL_APIC
	disable_local_APIC();
#endif /* CONFIG_L_LOCAL_APIC */
	local_irq_enable();
}

