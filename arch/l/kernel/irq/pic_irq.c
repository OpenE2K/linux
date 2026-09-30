/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/bug.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/kernel_stat.h>
#include <linux/export.h>
#include <linux/percpu.h>
#include <linux/seq_file.h>
#include <linux/types.h>
#include <linux/sysfs.h>
#include <linux/cpu.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/msi.h>
#include <linux/el_posix.h>

#include <asm/pic.h>
#include <asm/irq_regs.h>
#include <asm/console.h>
#include <asm/hw_irq.h>
#include <asm/nmi.h>

#include <trace/events/irq.h>
#include <asm-l/l_timer.h>
#include <../../../kernel/time/tick-internal.h>

#include "pic.h"

/*
 * This file holds code that is common for 1) e2k APIC, 2) e90s APIC and
 * 3) e2k EPIC implementations.
 *
 * Corresponding declarations can be found in asm-l/hw_irq.h and asm-l/pic.h
 */

DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = VECTOR_UNUSED
};

DEFINE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat) ____cacheline_internodealigned_in_smp;
EXPORT_PER_CPU_SYMBOL(irq_stat);
#define irq_stats(cpu)		(&per_cpu(irq_stat, cpu))

/*
 * /proc/interrupts printing:
 */
int arch_show_interrupts(struct seq_file *p, int prec)
{
	int j;

	seq_printf(p, "%*s: ", prec, "RTR");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->icr_read_retry_count);
	seq_printf(p, "  read retries\n");
#ifdef CONFIG_SMP
# ifdef CONFIG_E2K
	seq_printf(p, "%*s: ", prec, "TLB");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_tlb_count);
	seq_printf(p, "  TLB shootdowns\n");
# endif
#endif
	seq_printf(p, "%*s: %10u\n", prec, "MIS", atomic_read(&irq_mis_count));
	return 0;
}

/*
 * do_IRQ handles all normal device IRQ's (the special
 * SMP cross-CPU interrupts have their own specific
 * handlers).
 */
void do_IRQ(struct pt_regs * regs, unsigned int vector)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
	struct irq_desc *desc;
	int irq = -1;


#ifdef CONFIG_E2K
	/*It works under CONFIG_PROFILING flag only */
	store_do_irq_ticks();
#endif

	l_irq_enter();

	desc = __this_cpu_read(vector_irq[vector]);


	if (likely(desc)) {
		generic_handle_irq_desc(desc);
		irq = desc->irq_data.irq;
	} else {
		ack_pic_irq();
		if (printk_ratelimit())
			pr_emerg("%s:cpu %d: No irq handler for vector "
					"0x%x (irq %d)\n", __func__,
					smp_processor_id(), vector, irq);
	}

#ifdef CONFIG_E2K
	/*It works under CONFIG_PROFILING flag only */
	define_time_of_do_irq(irq);
#endif

	l_irq_exit();

	set_irq_regs(old_regs);
}

void ack_bad_irq(unsigned int irq)
{
	pr_err_ratelimited("unexpected IRQ trap at vector %02x\n", irq);
	/*
	 * Currently unexpected vectors happen only on SMP and APIC.
	 * We _must_ ack these because every local APIC has only N
	 * irq slots per priority level, and a 'hanging, unacked' IRQ
	 * holds up an irq slot - in excessive cases (when multiple
	 * unexpected vectors occur) that might lock up the APIC
	 * completely.
	 */
	ack_pic_irq();
}

/*
 * /proc/stat helpers
 */
u64 arch_irq_stat(void)
{
	return atomic_read(&irq_mis_count);
}

noinline notrace void do_nmi(u32 nmi_reason)
{
	if (cpu_has_epic())
		epic_do_nmi(nmi_reason);
	else
		apic_do_nmi(nmi_reason);
}

void __ref do_postpone_tick(int to_next_rt_ns)
{
	int cpu;
	long long cur_time = ktime_to_ns(ktime_get());
	long long next_tm;
	unsigned long	flags;
	struct pt_regs regs_new;
	struct pt_regs *old_regs;
	int next_cpu;

	local_irq_save(flags);
	cpu = smp_processor_id();
	if (nr_cpu_ids > 1 && tick_do_timer_cpu == cpu) {
		next_cpu = cpumask_next(raw_smp_processor_id(), cpu_online_mask);
		if (next_cpu >= nr_cpu_ids)
			next_cpu = cpumask_first(cpu_online_mask);
		tick_do_timer_cpu = next_cpu;
	}
	next_tm = per_cpu(next_rt_intr, cpu);
	if (to_next_rt_ns) {
		per_cpu(next_rt_intr, cpu) = cur_time + to_next_rt_ns;
	} else {
		per_cpu(next_rt_intr, cpu) = 0;
		per_cpu(must_do_timer, cpu) = 0;
	}
#if 0
	trace_printk("DOPOSTP old_nx-cur=%lld cur=%lld nx=%lld\n",
		next_tm - cur_time, cur_time, cur_time + to_next_rt_ns);
#endif
	if (per_cpu(must_do_timer, cpu)) {
		/* FIXME next line has long run time and may be deleted */
		memset(&regs_new, 0, sizeof(struct pt_regs));
		/* need to get answer to user_mod() only */
#ifdef CONFIG_E90S
		regs_new.tstate = TSTATE_PRIV;
#else
		regs_new.stacks.top = native_read_SBR_reg().base;
		regs_new.next = NULL;
#endif
		old_regs = set_irq_regs(&regs_new);
		l_irq_enter();
		local_pic_timer_interrupt();
		l_irq_exit();
		set_irq_regs(old_regs);
	}
	local_irq_restore(flags);
}
EXPORT_SYMBOL(do_postpone_tick);

notrace_on_host int hard_smp_processor_id(void)
{
	return read_pic_id();
}
/*
 * The number of allocated logical CPU IDs. Since logical CPU IDs are allocated
 * contiguously, it equals to current allocated max logical CPU ID plus 1.
 * All allocated CPU IDs should be in the [0, nr_logical_cpuids) range,
 * so the maximum of nr_logical_cpuids is nr_cpu_ids.
 *
 * NOTE: Reserve 0 for BSP.
 */
int nr_logical_cpuids __ro_after_init = 1;

/*
 * Used to store mapping between logical CPU IDs and APIC/short EPIC IDs.
 */
int cpuid_to_picid[] __ro_after_init = {
	[0 ... NR_CPUS - 1] = -1,
};

/*
 * Should use this API to allocate logical CPU IDs to keep nr_logical_cpuids
 * and cpuid_to_picid[] synchronized.
 */
int __init allocate_logical_cpuid(int picid)
{
	/*
	 * cpuid <-> picid mapping is persistent, so when a cpu is up,
	 * check if the kernel has allocated a cpuid for it.
	 */
	for (int i = 0; i < nr_logical_cpuids; i++) {
		if (cpuid_to_picid[i] == picid)
			return i;
	}

	/* Allocate a new cpuid. */
	if (nr_logical_cpuids >= nr_cpu_ids) {
		WARN_ONCE(1, "PIC: NR_CPUS/possible_cpus limit of %u reached. Processor %d/0x%x and the rest are ignored.\n",
			     nr_cpu_ids, nr_logical_cpuids, picid);
		return -EINVAL;
	}

	cpuid_to_picid[nr_logical_cpuids] = picid;
	return nr_logical_cpuids++;
}
