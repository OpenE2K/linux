/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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

#include "../mm/trace-tlb-flush.h"
#include <asm/trace-tlb-flush.h>

#undef	DEBUG_SMP_MODE
#undef	DebugSMP
#define DEBUG_SMP_MODE		0
#define DebugSMP(...)	DebugPrint(DEBUG_SMP_MODE, ##__VA_ARGS__)

#undef	DEBUG_DATA_BREAKPOINT_MODE
#undef	DebugDBP
#define	DEBUG_DATA_BREAKPOINT_MODE	0	/* data breakpoint debugging */
#define DebugDBP(...)	DebugPrint(DEBUG_DATA_BREAKPOINT_MODE, ##__VA_ARGS__)

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

	cpu = get_cpu_light();

	/* See comment in flush_tlb_range() */
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

	put_cpu_light();
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

void native_stop_this_cpu_ipi(void *dummy)
{
	raw_all_irq_disable();

	set_cpu_online(smp_processor_id(), false);

	spin_begin();

	do {
		spin_cpu_relax();
	} while (true);

	spin_end();
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

