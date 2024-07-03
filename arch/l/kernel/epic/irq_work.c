/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/irq.h>
#include <linux/irq_work.h>
#include <linux/hardirq.h>
#include <asm/epic.h>
#include <asm/irq_vectors.h>

static inline void __epic_smp_irq_work_interrupt(void)
{
	inc_irq_stat(apic_irq_work_irqs);
	irq_work_run();
}

__visible void epic_smp_irq_work_interrupt(struct pt_regs *regs)
{
	l_irq_enter();
	ack_epic_irq();
	__epic_smp_irq_work_interrupt();
	l_irq_exit();
}

void epic_irq_work_raise(void)
{
	epic_send_IPI_self(EPIC_IRQ_WORK_VECTOR);
	epic_wait_icr_idle();
}
