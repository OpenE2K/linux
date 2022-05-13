#ifndef __ASM_KVM_GUEST_MMU_CONTEXT_H
#define __ASM_KVM_GUEST_MMU_CONTEXT_H

#ifdef __KERNEL__

#include <linux/mm.h>

extern void kvm_activate_mm(struct mm_struct *active_mm,
						struct mm_struct *mm);
extern int kvm_get_mm_notifier(struct mm_struct *mm);
extern int kvm_get_mm_notifier_locked(struct mm_struct *mm);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline void
activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	kvm_activate_mm(active_mm, mm);
}
static inline void
deactivate_mm(struct task_struct *dead_task, struct mm_struct *mm)
{
	native_deactivate_mm(dead_task, mm);
	if (!dead_task->clear_child_tid || (atomic_read(&mm->mm_users) <= 1))
		HYPERVISOR_switch_to_guest_init_mm();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KERNEL__ */
#endif	/* __ASM_KVM_GUEST_MMU_CONTEXT_H */
