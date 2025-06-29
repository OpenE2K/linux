/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest kernel virtual space context support
 */

#ifndef _E2K_KVM_MMU_CONTEXT_H
#define _E2K_KVM_MMU_CONTEXT_H

#include <linux/types.h>
#include <asm/kvm/thread_info.h>

/*
 * Virtualization support
 */

#if	!defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_MODE)
/* it is native kernel without any virtualization */
/* it is host kernel with virtualization support */

/* mm_alloc()/mmdrop() defined at include/linux/sched.h */

#define uaccess_enable	native_uaccess_enable
#define uaccess_enable_irqs_off	native_uaccess_enable_irqs_off
#define uaccess_disable	native_uaccess_disable
#define uaccess_restore native_uaccess_restore

#define activate_mm(__active_mm, __mm)	\
		native_activate_mm(__active_mm, __mm)
static inline void
deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm)
{
	native_deactivate_mm(dead_task, mm);
}
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/mmu_context.h>
#endif	/* !CONFIG_VIRTUALIZATION || CONFIG_KVM_HOST_MODE */

#endif /* !(_E2K_KVM_MMU_CONTEXT_H) */
