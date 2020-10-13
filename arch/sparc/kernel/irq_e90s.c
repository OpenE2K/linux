/* $Id: irq_e90.c,v 1.14 2009/02/24 16:12:16 atic Exp $
 * irq.c: UltraSparc IRQ handling/init/registry.
 *
 * Copyright (C) 1997  David S. Miller  (davem@caip.rutgers.edu)
 * Copyright (C) 1998  Eddie C. Dost    (ecd@skynet.be)
 * Copyright (C) 1998  Jakub Jelinek    (jj@ultra.linux.cz)
 */

#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/irq.h>
#include <linux/kernel_stat.h>
#include <linux/pci.h>
#include <linux/kdebug.h>
#include <asm/e90s.h>
#include <asm/pcr.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/perf_event.h>

#include "kstack.h"

#define	DEBUG_IRQ_MODE		0	/* interrupts */
#if DEBUG_IRQ_MODE
# define DebugIRQ(...)		printk(__VA_ARGS__)
#else
# define DebugIRQ(...)
#endif

atomic_t nmi_active = ATOMIC_INIT(0);
EXPORT_SYMBOL(nmi_active);

void *hardirq_stack[NR_CPUS];
void *softirq_stack[NR_CPUS];

unsigned long ivector_table_pa;

notrace __kprobes void perfctr_irq(int irq, struct pt_regs *regs)
{
	void *orig_sp;
	unsigned long pcr;
	clear_softint(1 << irq);

	rd_pcr(pcr);
	if(!(pcr & E90S_PCR_OVF)) {
		do_nmi(regs);
		return;
	}

	nmi_enter();
	inc_irq_stat(__nmi_count);

	orig_sp = set_hardirq_stack();

#ifdef CONFIG_PERF_EVENTS
	if (perf_event_nmi_handler(regs) != NOTIFY_STOP)
		pcr_ops->write_pcr(0, pcr_ops->pcr_nmi_disable);
#endif

	restore_hardirq_stack(orig_sp);

	nmi_exit();
}

struct e90s_irq_pending e90s_irq_pending[NR_CPUS];

void handler_irq(int irq, struct pt_regs * regs)
{
	struct pt_regs *old_regs;
	void *orig_sp;
	unsigned vector, apicid = hard_smp_processor_id();
#ifdef CONFIG_MCST
	struct thread_info *ti = current_thread_info();
	ti->irq_enter_clk = get_cycles();
	per_cpu(prev_intr_clock, smp_processor_id()) =
				__get_cpu_var(last_intr_clock);
	per_cpu(last_intr_clock, smp_processor_id()) = get_cycles();
#endif

	clear_softint(1 << irq);
	old_regs = set_irq_regs(regs);
	orig_sp = set_hardirq_stack();

	vector = e90s_irq_pending[apicid].vector;

	DebugIRQ("CPU #%d (%d) will start %pS on vector %02x (IRQ %d) (task %d %s)\n",
			smp_processor_id(), apicid, interrupt[vector],
			vector, __raw_get_cpu_var(vector_irq)[vector],
			current->pid, current->comm);
	BUG_ON(!irqs_disabled());
	if (*interrupt[vector]) 
		(*interrupt[vector])(regs);
	else
		do_IRQ(regs, vector);

	restore_hardirq_stack(orig_sp);
	set_irq_regs(old_regs);
}

#ifndef CONFIG_PREEMPT_RT_FULL
void do_softirq_own_stack(void)
{
	void *orig_sp, *sp = softirq_stack[smp_processor_id()];

	sp += THREAD_SIZE - 192 - STACK_BIAS;

	__asm__ __volatile__("mov %%sp, %0\n\t"
			     "mov %1, %%sp"
			     : "=&r" (orig_sp)
			     : "r" (sp));
	__do_softirq();
	__asm__ __volatile__("mov %0, %%sp"
			     : : "r" (orig_sp));
}
#endif

void __init init_IRQ(void)
{
	init_bsp_APIC();

	/* Initialize interrupt[] array of system interrupts' handlers. */
	l_init_system_handlers_table();

#ifdef CONFIG_X86_X2APIC
	enable_IR_x2apic();
#endif

	default_setup_apic_routing();

	if (!verify_local_APIC())
		pr_emerg("Your LAPIC is broken, trying to continue...\n");

	connect_bsp_APIC();

	setup_local_APIC();

	/* Enable IO APIC before setting up error vector. */
	enable_IO_APIC();

	end_local_APIC_setup();

	if (apic->setup_portio_remap)
		apic->setup_portio_remap();

	setup_IO_APIC();
}

void start_nmi_watchdog(void *unused)
{
}

void stop_nmi_watchdog(void *unused)
{
}
