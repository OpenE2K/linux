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
#include <linux/export.h>
#include <linux/kthread.h>
#include <linux/notifier.h>
#include <linux/processor.h>

#include <asm/pic.h>
#include <asm/e2k_debug.h>
#include <asm/pgalloc.h>
#include <asm/mmu_context.h>
#include <asm/console.h>

#include <asm/regs_state.h>

#undef	DEBUG_SMP_MODE
#undef	DebugSMP
#define DEBUG_SMP_MODE		0
#define DebugSMP(...)	DebugPrint(DEBUG_SMP_MODE, ##__VA_ARGS__)

#undef	DEBUG_DATA_BREAKPOINT_MODE
#undef	DebugDBP
#define	DEBUG_DATA_BREAKPOINT_MODE	0	/* data breakpoint debugging */
#define DebugDBP(...)	DebugPrint(DEBUG_DATA_BREAKPOINT_MODE, ##__VA_ARGS__)

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
native_smp_flush_tlb_mm(struct mm_struct *const mm)
{
	preempt_disable();

	/* Signal to all users of this mm that it has been flushed.
	 * Invalid context will be updated while activating or switching to. */
	memset(mm->context.cpumsk, 0, nr_cpu_ids * sizeof(mm->context.cpumsk[0]));

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

void native_smp_flush_tlb_page(struct vm_area_struct *const vma,
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
EXPORT_SYMBOL(native_smp_flush_tlb_page);

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

void native_smp_flush_tlb_all(void)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	smp_call_function(flush_tlb_all_ipi, NULL, 1);
	__flush_tlb_all();
}
EXPORT_SYMBOL(native_smp_flush_tlb_all);


/*
 * Flush a range of pages
 */

void native_smp_flush_tlb_range(struct mm_struct *const mm,
		const e2k_addr_t start, const e2k_addr_t end)
{
	int cpu, i;

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
	 * 63 flush ipis which will flush all the TLBs.
	 */
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
EXPORT_SYMBOL(native_smp_flush_tlb_range);

/*
 * As native_smp_flush_tlb_range() but for pmd's
 */
void native_smp_flush_pmd_tlb_range(struct mm_struct *const mm,
		const e2k_addr_t start, const e2k_addr_t end)
{
	int cpu, i;

	preempt_disable();

	cpu = smp_processor_id();

	/* See comment in smp_flush_tlb_range() */
	for (i = 0; i < nr_cpu_ids; i++) {
		if (i == cpu)
			/* That being said, current CPU can still
			 * flush only the given range of pages. */
			continue;
		mm->context.cpumsk[i] = 0;
	}

	__flush_pmd_tlb_range(mm, start, end);

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

/*
 * Flush a range of pages and page tables.
 */

void native_smp_flush_tlb_range_and_pgtables(struct mm_struct *const mm,
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

void native_smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	icache_range_t icache_range;

	icache_range.start = start;
	icache_range.end = end;

	migrate_disable();
	smp_call_function(smp_flush_icache_range_ipi, &icache_range, 1);
	__flush_icache_range(start, end);
	migrate_enable();
}
EXPORT_SYMBOL(native_smp_flush_icache_range);

static void smp_flush_icache_range_array_ipi(void *info)
{
	icache_range_array_t *icache_range_arr = (icache_range_array_t *)info;

	__flush_icache_range_array(icache_range_arr);
}

void native_smp_flush_icache_range_array(icache_range_array_t *icache_range_arr)
{
	migrate_disable();
	smp_call_function(
		smp_flush_icache_range_array_ipi, icache_range_arr, 1);
	__flush_icache_range_array(icache_range_arr);
	migrate_enable();
}

static void smp_flush_icache_kernel_line_ipi(void *info)
{
	flush_ICACHE_kernel_line(*((e2k_addr_t *)info));
}

void native_smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	smp_call_function(smp_flush_icache_kernel_line_ipi, &addr, 1);
	flush_ICACHE_kernel_line(addr);
}

static void smp_flush_icache_page_ipi(void* info)
{
	icache_page_t *icache_page = (icache_page_t *)info;

	__flush_icache_page(icache_page->vma, icache_page->page);
}

void native_smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	icache_page_t icache_page;
	struct mm_struct *mm = vma->vm_mm;
	int cpu, i;

	migrate_disable();

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

	migrate_enable();
}

static void smp_flush_icache_all_ipi(void *info)
{
	__flush_icache_all();
}

void smp_flush_icache_all(void)
{
	smp_call_function(smp_flush_icache_all_ipi, NULL, 1);
	__flush_icache_all();
}
EXPORT_SYMBOL(smp_flush_icache_all);

void smp_send_refresh(void)
{
	refresh_processor = refresh_processor | ~(0U);

}


static void stop_this_cpu_ipi(void *dummy)
{
	raw_all_irq_disable();

	set_cpu_online(smp_processor_id(), false);

	spin_begin();

#ifdef CONFIG_KVM_GUEST_KERNEL
	//TODO Why is this needed?
	refresh_processor = refresh_processor & ~(1U << smp_processor_id());
	for (;;) {
		if (refresh_processor & (1U << smp_processor_id()))
			break;
		spin_cpu_relax();
	}
	refresh_processor = refresh_processor & ~(1U << smp_processor_id());
#else
	while (1)
		spin_cpu_relax();
#endif
}

void smp_send_stop(void)
{
	unsigned long timeout;

	/*
	 * NMI may stop other CPU holding printk ringbuffer lock, causing panicking CPU to
	 * hang on next printk (bug 128863).
	 * As a workaround, use MI to stop other CPUs.
	 *
	 * nmi_call_function(stop_this_cpu_ipi, NULL, 0, 1000);
	 */
	smp_call_function(stop_this_cpu_ipi, NULL, 0);

	/* Interrupt delivery may take a while, wait for up to 30 seconds for other CPUs to stop */
	timeout = 30 * USEC_PER_SEC;
	while (num_online_cpus() > 1 && timeout--)
		udelay(1);
}

#ifdef	CONFIG_DATA_BREAKPOINT

static void smp_set_data_breakpoint_ipi(void *info)
{
	hw_data_bp_t *data_bp = (hw_data_bp_t *)info;

	set_hardware_data_breakpoint(data_bp->address, data_bp->size,
		data_bp->write, data_bp->read, data_bp->stop, data_bp->cp_num);
	DebugDBP("set data breakpoint: CPU #%d address %px size %d bytes "
		"write %d read %d stop %d BAR #%d\n",
		smp_processor_id(), data_bp->address, data_bp->size,
		data_bp->write != 0, data_bp->read != 0, data_bp->stop != 0,
		data_bp->cp_num);
}

void smp_set_data_breakpoint(void *address, u64 size,
		bool write, bool read, bool stop, const int cp_num)
{
	hw_data_bp_t data_bp;

	data_bp.address = address;
	data_bp.size = size;
	data_bp.write = write;
	data_bp.read = read;
	data_bp.stop = stop;
	data_bp.cp_num = cp_num;

	smp_call_function(smp_set_data_breakpoint_ipi, &data_bp, 1);

	smp_set_data_breakpoint_ipi(&data_bp);
}

static int smp_reset_data_breakpoint_ipi(void *info)
{
	void *address = info;
	int cp_num;

	cp_num = reset_hardware_data_breakpoint(address);
	if (cp_num >= 0 && cp_num < 4) {
		DebugDBP("reset data breakpoint: CPU #%d address %px BAR #%d\n",
			smp_processor_id(), address, cp_num);
	} else if (cp_num < 0) {
		DebugDBP("reset data breakpoint failed on CPU #%d "
			"address %px, error %d\n",
			smp_processor_id(), address, cp_num);
	} else {
		DebugDBP("reset data breakpoint: could not find on CPU #%d "
			"address %px\n",
			smp_processor_id(), address);
	}
	return cp_num;
}

int smp_reset_data_breakpoint(void *address)
{
	smp_call_function((void (*)(void *))smp_reset_data_breakpoint_ipi,
				address, 1	/* wait */);
	return smp_reset_data_breakpoint_ipi(address);
}
#endif	/* CONFIG_DATA_BREAKPOINT */

