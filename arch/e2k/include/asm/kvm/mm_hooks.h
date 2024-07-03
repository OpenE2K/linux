/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest mm hooks support
 */

#ifndef _E2K_KVM_MM_HOOKS_H
#define _E2K_KVM_MM_HOOKS_H

#include <linux/mm_types.h>

/*
 * Virtualization support
 */

#if	!defined(CONFIG_VIRTUALIZATION) || defined(CONFIG_KVM_HOST_MODE)
/* it is native kernel without any virtualization */
/* it is host kernel with virtualization support */
static inline int
get_mm_notifier_locked(struct mm_struct *mm)
{
	/* Do not need mmu notifier in native mode */
	return 0;
}
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is virtualized guest kernel */
#include <asm/kvm/guest/mm_hooks.h>
#endif	/* !CONFIG_VIRTUALIZATION || CONFIG_KVM_HOST_MODE */

#endif /* !(_E2K_KVM_MM_HOOKS_H) */
