/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	__E2K_IRQ_GUEST_H_
#define	__E2K_IRQ_GUEST_H_

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/kvm_host.h>
#include <linux/err.h>

#include <asm/kvm/guest/irq.h>

#include "cpu.h"

static inline atomic_t *
kvm_get_virqs_atomic_counter(int virq_id)
{
	switch (virq_id) {
	case KVM_VIRQ_TIMER:
		return kvm_get_timer_virqs_num();
	case KVM_VIRQ_HVC:
		return kvm_get_hvc_virqs_num();
	case KVM_VIRQ_LAPIC:
		return kvm_get_lapic_virqs_num();
	case KVM_VIRQ_CEPIC:
		return kvm_get_cepic_virqs_num();
	default:
		return ERR_PTR(-EINVAL);
	}
}

/*
 * FIXME: all VIRQ should be registered at a list or table and
 * need implement function to free all VIRQs
 *
 * based on Xen model of interrupts (driver/xen/events.c)
 * There are a few kinds of interrupts which should be mapped to an event
 * channel:
 *
 * 1. Inter-domain notifications.  This includes all the virtual
 *    device events, since they're driven by front-ends in another domain
 *    (typically dom0). Not supported at present.
 * 2. VIRQs, typically used for timers.  These are per-cpu events.
 * 3. IPIs. Not supported at present.
 * 4. Hardware interrupts. Not supported at present.
 */

extern kvm_irq_info_t irq_info[KVM_NR_IRQS];
extern int kvm_nr_irqs;

/*
 * Accessors for packed IRQ information.
 */
static inline kvm_irq_info_t *info_for_irq(unsigned irq)
{
	return &irq_info[irq];
}
static inline kvm_virq_info_t *virq_info_from_irq(unsigned irq)
{
	kvm_irq_info_t *info = info_for_irq(irq);

	BUG_ON(info == NULL);
	BUG_ON(info->type != IRQT_VIRQ);

	return &info->u.virq;
}
static inline unsigned virq_from_irq(unsigned irq)
{
	kvm_virq_info_t *info = virq_info_from_irq(irq);

	return info->virq_nr;
}

static inline unsigned gpid_from_irq(unsigned irq)
{
	kvm_virq_info_t *info = virq_info_from_irq(irq);

	return info->gpid_nr;
}

static inline struct task_struct *virq_task_from_irq(unsigned irq)
{
	kvm_virq_info_t *info = virq_info_from_irq(irq);

	return info->task;
}

static inline kvm_irq_type_t type_from_irq(unsigned irq)
{
	return info_for_irq(irq)->type;
}

static inline unsigned cpu_from_irq(unsigned irq)
{
	return info_for_irq(irq)->cpu;
}

static inline bool is_irq_active(unsigned irq)
{
	return info_for_irq(irq)->active;
}

extern __init void kvm_virqs_init(int cpu);

#endif  /* __E2K_IRQ_GUEST_H_ */
