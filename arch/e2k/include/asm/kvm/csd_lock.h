#ifndef _ASM_E2K_KVM_CSD_LOCK_H
#define _ASM_E2K_KVM_CSD_LOCK_H
/*
 * This file implements on host the arch-dependent parts of kvm guest
 * csd_lock/csd_unlock functions to serialize access to per-cpu csd resources
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/sched.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>

#ifdef	CONFIG_SMP

#include <asm/kvm/threads.h>
#include <asm/kvm/hypercall.h>

typedef struct csd_lock_waiter {
	struct list_head	wait_list;
	struct kvm_vcpu		*vcpu;
	struct task_struct	*task;
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