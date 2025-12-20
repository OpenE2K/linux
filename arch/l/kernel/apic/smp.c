/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * SMP IPI Support
 */

#include <linux/cpumask.h>
#include <linux/irq.h>
#include <linux/sched.h>

#include <asm/apic.h>

/*
 * the following functions deal with sending IPIs between CPUs.
 *
 * We use 'broadcast', CPU->CPU IPIs and self-IPIs too.
 */

void apic_send_call_function_ipi_mask(const struct cpumask *mask)
{
	apic->send_IPI_mask(mask, CALL_FUNCTION_VECTOR);
}

void apic_send_call_function_single_ipi(int cpu)
{
	apic->send_IPI_mask(cpumask_of(cpu), CALL_FUNCTION_SINGLE_VECTOR);
}

/*
 * this function sends a 'reschedule' IPI to another CPU.
 * it goes straight through and wastes no time serializing
 * anything. Worst case is that we lose a reschedule ...
 */
void apic_smp_send_reschedule(int cpu)
{
	if (unlikely(cpu_is_offline(cpu))) {
		WARN_ON(1);
		return;
	}
	current->intr_sc = get_cycles();
	apic->send_IPI_mask(cpumask_of(cpu), RESCHEDULE_VECTOR);
}


/*
 * Reschedule call back. Nothing to do,
 * all the work is done automatically when
 * we return from the interrupt.
 */
static inline void __smp_reschedule_interrupt(void)
{
	inc_irq_stat(irq_resched_count);
	scheduler_ipi();
}

__visible void smp_reschedule_interrupt(struct pt_regs *regs)
{
	l_irq_enter();
	ack_APIC_irq();
	__smp_reschedule_interrupt();
	l_irq_exit();
}

static inline void smp_entering_irq(void)
{
	l_irq_enter();
	ack_APIC_irq();
}

static inline void __smp_call_function_interrupt(void)
{
	generic_smp_call_function_interrupt();
	inc_irq_stat(irq_call_count);
}

__visible void smp_call_function_interrupt(struct pt_regs *regs)
{
	smp_entering_irq();
	__smp_call_function_interrupt();
	exiting_irq();
}

static inline void __smp_call_function_single_interrupt(void)
{
	generic_smp_call_function_single_interrupt();
	inc_irq_stat(irq_call_count);
}

__visible void smp_call_function_single_interrupt(struct pt_regs *regs)
{
	smp_entering_irq();
	__smp_call_function_single_interrupt();
	exiting_irq();
}
