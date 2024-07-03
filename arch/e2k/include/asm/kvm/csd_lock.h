/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements on host the arch-dependent parts of kvm guest
 * csd_lock/csd_unlock functions to serialize access to per-cpu csd resources
 */

#ifndef _ASM_E2K_KVM_CSD_LOCK_H
#define _ASM_E2K_KVM_CSD_LOCK_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kvm.h>

#ifdef	CONFIG_SMP

#include <asm/kvm/threads.h>
#include <asm/kvm/hypercall.h>

typedef enum unlocked_type {
	undefined_unlocked_type,	/* there is no unlocking */
	woken_unlocked_type,		/* waiting task has been woken up */
	is_running_unlocked_type,	/* task was already running */
	queued_as_unlocked_type,	/* queued to waiting list as */
					/* unlocked entry */
} unlocked_type_t;

typedef struct csd_lock_waiter {
	struct list_head	wait_list;
	struct kvm_vcpu		*vcpu;
	struct task_struct	*task;
	struct kvm_vcpu		*by_vcpu;
	unlocked_type_t		state;
	void			*lock;
} csd_lock_waiter_t;

/* max number of csd lock waiters structures: */
/* on each VCPU 2 structures - current and next */
#define	KVM_MAX_CSD_LOCK_FREE_NUM	(KVM_MAX_VCPUS * 2)

extern int kvm_guest_csd_lock_ctl(struct kvm_vcpu *vcpu,
					csd_ctl_t csd_ctl_no, void *lock);

extern int kvm_guest_csd_lock_init(struct kvm *kvm);
extern void kvm_guest_csd_lock_destroy(struct kvm *kvm);

#else	/* ! CONFIG_SMP */
#define	kvm_guest_csd_lock_ctl(vcpu, csd_ctl_no, lock)	(-ENOSYS)
#define	kvm_guest_csd_lock_init(kvm)			(0)
#define	kvm_guest_csd_lock_destroy(kvm)
#endif	/* CONFIG_SMP */
#endif	/* _ASM_E2K_KVM_CSD_LOCK_H */
