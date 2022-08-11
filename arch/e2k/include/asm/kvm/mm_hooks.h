/*
 * KVM guest mm hooks support
 * Copyright 2021 Andrey I. Alekhin (alekhin_a@mcst.ru)
 */

#ifndef _E2K_KVM_MM_HOOKS_H
#define _E2K_KVM_MM_HOOKS_H

#include <linux/mm.h>

/*
 * Virtualization support
 */

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* it is native host kernel with virtualization support */
static inline void
get_mm_notifier_locked(struct mm_struct *mm)
{
	/* Do not need mmu notifier in native mode */
}
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/mm_hooks.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/mm_hooks.h>
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif /* !(_E2K_KVM_MM_HOOKS_H) */
