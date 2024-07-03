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
#include <asm/irq_regs.h>

#include <trace/events/irq.h>

#include <asm/console.h>
#include <asm/hw_irq.h>
#include <asm/io_apic.h>
#include <asm/nmi.h>

#include <asm-l/l_timer.h>
#include <asm-l/pic.h>
#include <asm-l/io_pic.h>
#include <../../../kernel/time/tick-internal.h>

/*
 * This file holds code that is common for 1) e2k APIC, 2) e90s APIC and
 * 3) e2k EPIC implementations.
 *
 * Corresponding declarations can be found in asm-l/hw_irq.h and asm-l/pic.h
 */

DEFINE_PER_CPU(vector_irq_t, vector_irq) = {
	[0 ... NR_VECTORS - 1] = -1
};

/*
 * Array of handlers for system interrupts (local timer, IPI, etc).
 */
void (*interrupt[NR_VECTORS])(struct pt_regs *regs) = {
	[0 ... NR_VECTORS - 1] = NULL
};

atomic_t irq_err_count;
DEFINE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat) ____cacheline_internodealigned_in_smp;
EXPORT_PER_CPU_SYMBOL(irq_stat);

int first_system_vector = NR_VECTORS - 1;

__init_recv
void setup_PIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name)
{
	if (test_bit(vector, used_vectors) || interrupt[vector])
		BUG();

	set_bit(vector, used_vectors);
	if (system && first_system_vector > vector)
		first_system_vector = vector;
	interrupt[vector] = handler;
}

#define irq_stats(cpu)		(&per_cpu(irq_stat, cpu))

/*
 * /proc/interrupts printing:
 */
int arch_show_interrupts(struct seq_file *p, int prec)
{
	int j;

	seq_printf(p, "%*s: ", prec, "NMI");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->__nmi_count);
	seq_printf(p, "  Non-maskable interrupts\n");
	seq_printf(p, "%*s: ", prec, "LOC");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->apic_timer_irqs);
	seq_printf(p, "  Local timer interrupts\n");

	seq_printf(p, "%*s: ", prec, "SPU");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_spurious_count);
	seq_printf(p, "  Spurious interrupts\n");
//TODO
#if 0
	seq_printf(p, "%*s: ", prec, "IWI");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->apic_irq_work_irqs);
	seq_printf(p, "  IRQ work interrupts\n");
#endif
	seq_printf(p, "%*s: ", prec, "RTR");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->icr_read_retry_count);
	seq_printf(p, "  read retries\n");
#ifdef CONFIG_SMP
	seq_printf(p, "%*s: ", prec, "RES");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_resched_count);
	seq_printf(p, "  Rescheduling interrupts\n");
# ifdef CONFIG_E2K
	seq_printf(p, "%*s: ", prec, "CAL");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_call_count -
					irq_stats(j)->irq_tlb_count);
	seq_printf(p, "  Function call interrupts\n");
	seq_printf(p, "%*s: ", prec, "TLB");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_tlb_count);
	seq_printf(p, "  TLB shootdowns\n");
# else
	seq_printf(p, "%*s: ", prec, "CAL");
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_call_count);
	seq_printf(p, "  Function call interrupts\n");
# endif
#endif
#ifdef CONFIG_E2K
# if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC)
	seq_printf(p, "v%*d: ", prec - 1, RDMA_INTERRUPT_VECTOR);
	for_each_online_cpu(j)
		seq_printf(p, "%10u ", irq_stats(j)->irq_rdma_count);
	seq_printf(p, "  RDMA interrupts\n");
# endif
#endif
	seq_printf(p, "%*s: %10u\n", prec, "ERR", atomic_read(&irq_err_count));
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
	int irq;

	irq = __this_cpu_read(vector_irq[vector]);

#ifdef CONFIG_E2K
	/*It works under CONFIG_PROFILING flag only */
	store_do_irq_ticks();
#endif

	l_irq_enter();

	desc = irq_to_desc(irq);

	if (likely(desc)) {
		generic_handle_irq_desc(desc);
	} else {
		ack_pic_irq();
		if (printk_ratelimit())
			pr_emerg("%s: %d No irq handler for vector "
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
	printk("unexpected IRQ trap at vector %02x\n", irq);
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
u64 arch_irq_stat_cpu(unsigned int cpu)
{
	u64 sum = irq_stats(cpu)->__nmi_count;

	sum += irq_stats(cpu)->apic_timer_irqs;
	sum += irq_stats(cpu)->irq_spurious_count;
#ifdef CONFIG_SMP
	sum += irq_stats(cpu)->irq_resched_count;
	sum += irq_stats(cpu)->irq_call_count;
#endif
#ifdef CONFIG_E2K
# if IS_ENABLED(CONFIG_RDMA) || IS_ENABLED(CONFIG_RDMA_SIC) || \
     IS_ENABLED(CONFIG_RDMA_NET)
	sum += irq_stats(cpu)->irq_rdma_count;
# endif
#endif

	return sum;
}

u64 arch_irq_stat(void)
{
	u64 sum = atomic_read(&irq_err_count) + atomic_read(&irq_mis_count);

	return sum;
}

static ssize_t show_irq_table(struct device *dev, struct device_attribute *attr,
				char *buf)
{
	u64 ret = 0;
	int *vector_table = per_cpu(vector_irq, dev->id);
	int i;

	for (i = 0; i < NR_VECTORS; i++) {
		if (i % 16 == 0) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					"0x%02x   ", i);
		}

		if (*interrupt[i]) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, " *    ");
		} else {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret,
					"%3d   ", vector_table[i]);
		}

		if (i % 16 == 15) {
			ret += scnprintf(buf + ret, PAGE_SIZE - ret, "\n");
		}
	}


	return ret;
}

const struct device_attribute irq_dev_attr = {
	.attr = {
		.name = "irq",
		.mode = S_IRUGO,

	},
	.show = show_irq_table,
	.store = NULL,
};

static int __init irq_sysfs_init(void)
{
	int ret = 0;
	int cpu;

	for_each_online_cpu(cpu) {
		ret = device_create_file(get_cpu_device(cpu), &irq_dev_attr);

		if (ret)
			return ret;
	}

	return ret;
}
late_initcall(irq_sysfs_init);

#ifdef CONFIG_IRQ_WORK
void arch_irq_work_raise(void)
{
	pic_irq_work_raise();
}
#endif

#ifdef CONFIG_SMP
void arch_send_call_function_ipi_mask(const struct cpumask *mask)
{
	pic_send_call_function_ipi_mask(mask);
}

void arch_send_call_function_single_ipi(int cpu)
{
	pic_send_call_function_single_ipi(cpu);
}

void smp_send_reschedule(int cpu)
{
	if (likely(!cpu_is_offline(cpu))) {
		pic_send_reschedule(cpu);
	}
}

void irq_force_complete_move(struct irq_desc *desc)
{
	pic_irq_force_complete_move(desc);
}
#endif

noinline notrace void do_nmi(struct pt_regs *regs)
{
	pic_do_nmi(regs);
}

DEFINE_PER_CPU(long long, next_rt_intr) = 0;
EXPORT_SYMBOL(next_rt_intr);

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
	} else{
		per_cpu(next_rt_intr, cpu) = 0;
	}
#if 0
	trace_printk("DOPOSTP old_nx-cur=%lld cur=%lld nx=%lld\n",
		next_tm - cur_time, cur_time, cur_time + to_next_rt_ns);
#endif
	if (next_tm == 1) {
		/* FIXME next line has long run time and may be deleted */
		memset(&regs_new, 0, sizeof(struct pt_regs));
		/* need to get answer to user_mod() only */
#ifdef CONFIG_E90S
		regs_new.tstate = TSTATE_PRIV;
#else
		regs_new.stacks.top = NATIVE_NV_READ_SBR_REG_VALUE();
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

static int print_ICs(void)
{
	/* print_local_pics() returns 1, if apic/epic verbosity is off */
	if (print_local_pics(false))
		return 0;

	print_IO_PICs();

	return 0;
}
late_initcall(print_ICs);

/* MSI arch specific hooks */
int arch_setup_msi_irqs(struct pci_dev *dev, int nvec, int type)
{
	return setup_msi_irqs_pic(dev, nvec, type);
}

void arch_teardown_msi_irq(unsigned int irq)
{
	teardown_msi_irq_pic(irq);
}

notrace_on_host int hard_smp_processor_id(void)
{
	return read_pic_id();
}

void __setup_vector_irq(int cpu)
{
	__pic_setup_vector_irq(cpu);
}

/*
 * The number of allocated logical CPU IDs. Since logical CPU IDs are allocated
 * contiguously, it equals to current allocated max logical CPU ID plus 1.
 * All allocated CPU IDs should be in the [0, nr_logical_cpuids) range,
 * so the maximum of nr_logical_cpuids is nr_cpu_ids.
 *
 * NOTE: Reserve 0 for BSP.
 */
int nr_logical_cpuids = 1;

/*
 * Used to store mapping between logical CPU IDs and APIC/short EPIC IDs.
 */
int cpuid_to_picid[] = {
	[0 ... NR_CPUS - 1] = -1,
};

/*
 * Should use this API to allocate logical CPU IDs to keep nr_logical_cpuids
 * and cpuid_to_picid[] synchronized.
 */
int allocate_logical_cpuid(int picid)
{
	int i;

	/*
	 * cpuid <-> picid mapping is persistent, so when a cpu is up,
	 * check if the kernel has allocated a cpuid for it.
	 */
	for (i = 0; i < nr_logical_cpuids; i++) {
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
