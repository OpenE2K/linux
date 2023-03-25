#ifndef _ASM_E2K_KVM_SPINLOCK_SLOW_H
#define _ASM_E2K_KVM_SPINLOCK_SLOW_H
/*
 * This file implements on host the arch-dependent parts of kvm guest
 * spin_lock()/spin_unlock() slow part
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kvm.h>

typedef struct spinlock_unlocked {
	struct list_head	unlocked_list;
	struct thread_info	*ti;
	struct gthread_info	*gti;
	struct list_head	checked_unlocked;	/* list of tasks */
							/* which alredy */
							/* checked spin */
							/* was unlocked */

	void			*lock;
} spinlock_unlocked_t;

#define SPINLOCK_HASH_BITS	6
#define	SPINLOCK_HASH_SHIFT	4	/* [9:4] hash bits */
#define SPINLOCK_HASH_SIZE	(1 << SPINLOCK_HASH_BITS)
#define spinlock_hashfn(lockp)	\
		hash_long(((unsigned long)(lockp)) >> SPINLOCK_HASH_SHIFT, \
				SPINLOCK_HASH_BITS)
#define	SPINUNLOCKED_LIST_SIZE	32

extern int kvm_guest_spin_lock_slow(struct kvm *kvm, void *lock,
						bool check_unlock);
extern int kvm_guest_spin_locked_slow(struct kvm *kvm, void *lock);
extern int kvm_guest_spin_unlock_slow(struct kvm *kvm, void *lock,
						bool add_to_unlock);

extern int kvm_guest_spinlock_init(struct kvm *kvm);
extern void kvm_guest_spinlock_destroy(struct kvm *kvm);

#endif	/* _ASM_E2K_KVM_SPINLOCK_SLOW_H */