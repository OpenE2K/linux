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

#include <asm/epic.h>

/*
 * the following functions deal with sending IPIs between CPUs.
 *
 * We use 'broadcast', CPU->CPU IPIs and self-IPIs too.
 */

void epic_send_call_function_ipi_mask(const struct cpumask *mask)
{
	epic_send_IPI_mask(mask, EPIC_CALL_FUNCTION_VECTOR);
}

void epic_send_call_function_single_ipi(int cpu)
{
	epic_send_IPI(cpu, EPIC_CALL_FUNCTION_SINGLE_VECTOR);
}

/*
 * this function sends a 'reschedule' IPI to another CPU.
 * it goes straight through and wastes no time serializing
 * anything. Worst case is that we lose a reschedule ...
 */
void epic_smp_send_reschedule(int cpu)
{
	if (unlikely(cpu_is_offline(cpu))) {
		WARN_ON(1);
		return;
	}
	current->intr_sc = get_cycles();
	epic_send_IPI(cpu, EPIC_RESCHEDULE_VECTOR);
}

/*
 * Reschedule call back. Nothing to do,
 * all the work is done automatically when
 * we return from the interrupt.
 */
static inline void __epic_smp_reschedule_interrupt(void)
{
	inc_irq_stat(irq_resched_count);
	scheduler_ipi();
}

__visible void epic_smp_reschedule_interrupt(struct pt_regs *regs)
{
	ack_epic_irq();
	__epic_smp_reschedule_interrupt();
}

static inline void __epic_smp_call_function_interrupt(void)
{
	generic_smp_call_function_interrupt();
	inc_irq_stat(irq_call_count);
}

__visible void epic_smp_call_function_interrupt(struct pt_regs *regs)
{
	ack_epic_irq();
	l_irq_enter();
	__epic_smp_call_function_interrupt();
	l_irq_exit();
}

static inline void __epic_smp_call_function_single_interrupt(void)
{
	generic_smp_call_function_single_interrupt();
	inc_irq_stat(irq_call_count);
}

__visible void epic_smp_call_function_single_interrupt(struct pt_regs *regs)
{
	ack_epic_irq();
	l_irq_enter();
	__epic_smp_call_function_single_interrupt();
	l_irq_exit();
}
