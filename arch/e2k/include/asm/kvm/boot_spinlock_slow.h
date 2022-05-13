#ifndef __ASM_E2K_KVM_BOOT_SPINLOCK_SLOW_H
#define __ASM_E2K_KVM_BOOT_SPINLOCK_SLOW_H
/*
 * This file implements on host the arch-dependent parts of kvm guest
 * boot-time spin_lock()/spin_unlock() slow part
 *
 * Copyright 2020 MCST
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kvm.h>

typedef struct boot_spinlock_unlocked {
	struct list_head	unlocked_list;
	struct kvm_vcpu		*vcpu;
	struct list_head	checked_unlocked;	/* list of tasks */
							/* which alredy */
							/* checked spin */
							/* was unlocked */

	void			*lock;
} boot_spinlock_unlocked_t;

#define BOOT_SPINLOCK_HASH_BITS		6
#define	BOOT_SPINLOCK_HASH_SHIFT	4	/* [9:4] hash bits */
#define BOOT_SPINLOCK_HASH_SIZE		(1 << SPINLOCK_HASH_BITS)
#define boot_spinlock_hashfn(lockp)	\
		hash_long(((unsigned long)(lockp)) >> \
					BOOT_SPINLOCK_HASH_SHIFT, \
				BOOT_SPINLOCK_HASH_BITS)
#define	BOOT_SPINUNLOCKED_LIST_SIZE	32

extern int kvm_boot_spin_lock_slow(struct kvm_vcpu *vcpu, void *lock,
					bool check_unlock);
extern int kvm_boot_spin_locked_slow(struct kvm_vcpu *vcpu, void *lock);
extern int kvm_boot_spin_unlock_slow(struct kvm_vcpu *vcpu, void *lock,
					bool add_to_unlock);

extern int vcpu_boot_spinlock_init(struct kvm_vcpu *vcpu);
extern int kvm_boot_spinlock_init(struct kvm *kvm);
extern void kvm_boot_spinlock_destroy(struct kvm *kvm);

#endif	/* __ASM_E2K_KVM_BOOT_SPINLOCK_SLOW_H */