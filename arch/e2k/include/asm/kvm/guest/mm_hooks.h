#ifndef __ASM_KVM_GUEST_MM_HOOKS_H
#define __ASM_KVM_GUEST_MM_HOOKS_H

#ifdef __KERNEL__

extern int kvm_get_mm_notifier_locked(struct mm_struct *mm);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
static inline int
get_mm_notifier_locked(struct mm_struct *mm)
{
	/* create mm notifier to trace some events over mm */
	return kvm_get_mm_notifier_locked(mm);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __KERNEL__ */
#endif	/* __ASM_KVM_GUEST_MM_HOOKS_H */
