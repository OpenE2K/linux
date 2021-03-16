/*
 * KVM guest kernel virtual space context support
 * Copyright 2011 Salavat S. Gilyazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_MMU_CONTEXT_H
#define _E2K_KVM_MMU_CONTEXT_H

#include <linux/types.h>
#include <asm/kvm/thread_info.h>
#include <asm/kvm/gmmu_context.h>

/*
 * Virtualization support
 */

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* it is native host kernel with virtualization support */
/* mm_alloc()/mmdrop() defined at include/linux/sched.h */

#define activate_mm(__active_mm, __mm)	\
		native_activate_mm(__active_mm, __mm)
static inline void
deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm)
{
	native_deactivate_mm(dead_task, mm);
}
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/mmu_context.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/mmu_context.h>
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif /* !(_E2K_KVM_MMU_CONTEXT_H) */
