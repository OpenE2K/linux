/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#ifndef	__E2K_ASM_KVM_IRQ_H_
#define	__E2K_ASM_KVM_IRQ_H_

#include <linux/types.h>
#include <asm/kvm/threads.h>

/*
 * VIRTUAL INTERRUPTS
 *
 * Virtual interrupts that a guest OS may receive from KVM.
 */
enum {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	KVM_VIRQ_TIMER,  /* timer interrupt */
	KVM_VIRQ_HVC,  /* HyperVisor Console interrupt */
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	KVM_VIRQ_LAPIC,  /* virtual local APIC interrupt */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	KVM_VIRQ_CEPIC,  /* virtual CEPIC interrupt */
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	KVM_NR_VIRQS
};

#define KVM_MAX_NR_VIRQS	(KVM_MAX_VIRQ_VCPUS * KVM_NR_VIRQS)

static inline const char *kvm_get_virq_name(int virq_id)
{
	switch (virq_id) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	case KVM_VIRQ_TIMER:
		return "early_timer";
	case KVM_VIRQ_HVC:
		return "hvc_virq";
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	case KVM_VIRQ_LAPIC:
		return "lapic";
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	case KVM_VIRQ_CEPIC:
		return "cepic";
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	default:
		return "???";
	}
}

typedef int (*irq_thread_t)(void *);
extern int debug_guest_virqs;

#endif  /* __E2K_ASM_KVM_IRQ_H_ */
