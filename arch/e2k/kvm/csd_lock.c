/*
 * This file implements on host the arch-dependent parts of kvm guest
 * csd_lock/csd_unlock functions to serialize access to per-cpu csd resources
 *
 * Copyright 2016 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>

#include <asm/kvm/csd_lock.h>

#include "process.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_DEADLOCK_MODE
#undef	DebugKVMDL
#define	DEBUG_KVM_DEADLOCK_MODE	0	/* spinlock deadlock debugging */
#define	DebugKVMDL(fmt, args...)					\
({									\
	if (DEBUG_KVM_DEADLOCK_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_UNLOCK_MODE
#undef	DebugKVMUL
#define	DEBUG_KVM_UNLOCK_MODE	0	/* spinlock unlock debugging */
#define	DebugKVMUL(fmt, args...)					\
({									\
	if (DEBUG_KVM_UNLOCK_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	0	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE || kvm_debug)			\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#ifdef	CONFIG_SMP

static inline csd_lock_waiter_t *
find_lock_in_csd_list(struct kvm *kvm, void *lock)
{
	csd_lock_waiter_t *w;

	list_for_each_entry(w, &kvm->arch.csd_lock_wait_head, wait_list) {
		DebugKVM("next csd lock waiter list entry lock %px\n",
			w->lock);
		if (w->lock == lock) {
			if (w->task) {
				DebugKVM("csd lock %px found, task %s (%d) "
					"VCPU #%d\n",
					lock, w->task->comm, w->task->pid,
					w->vcpu->vcpu_id);
			} else {
				DebugKVM("csd lock %px found, unlocked by "
					"VCPU #%d\n",
					lock, w->vcpu->vcpu_id);
			}
			return w;
		}
	}
	return NULL;
}

static void dump_waiter_list(struct kvm *kvm)
{
	csd_lock_waiter_t *w;

	list_for_each_entry(w, &kvm->arch.csd_lock_wait_head, wait_list) {
		pr_alert("next csd lock waiter list entry %px: lock %px",
			w, w->lock);
		if (w->task) {
			pr_cont("is waiting by task %s (%d) VCPU #%d\n",
				w->task->comm, w->task->pid,
				w->vcpu->vcpu_id);
		} else {
			pr_cont("is already unlocked by by VCPU #%d\n",
				w->vcpu->vcpu_id);
		}
		pr_cont("\n");
	}
}

/* Insert lock to waiting list as waiter entry */
/* spinlock should be taken */
static inline csd_lock_waiter_t *
queue_lock_to_waiter_list(struct kvm_vcpu *vcpu, void *lock)
{
	struct kvm *kvm = vcpu->kvm;
	csd_lock_waiter_t *w;

	if (likely(!list_empty(&kvm->arch.csd_lock_free_head))) {
		w = list_first_entry(&kvm->arch.csd_lock_free_head,
					csd_lock_waiter_t, wait_list);
		list_move_tail(&w->wait_list,
				&kvm->arch.csd_lock_wait_head);
		KVM_BUG_ON(vcpu->arch.host_task != current);
		w->task = current;
		w->lock = lock;
		w->vcpu = vcpu;
	} else {
		pr_err("%s(): empty list of free csd lock waiter "
			"structures\n", __func__);
		dump_waiter_list(kvm);
		BUG_ON(true);
		return NULL;
	}
	DebugKVM("add csd lock %px to waiter list %px as waiter entry "
		"on VCPU #%d\n",
		w->lock, w, vcpu->vcpu_id);
	return w;
}

/*
 * Register csd lock waiter structure.
 * Now this function (and CSD ctl) is used to check if the lock already
 * was queued as waiter for unlocking and only to debugging purposes.
 * Should be deleted after debug completion.
 */
static inline int
guest_csd_lock(struct kvm_vcpu *vcpu, void *lock)
{
	struct kvm *kvm = vcpu->kvm;
	csd_lock_waiter_t *w;
	unsigned long flags;

	DebugKVM("%s (%d) started for guest csd lock %px on VCPU #%d\n",
		current->comm, current->pid, lock, vcpu->vcpu_id);

	raw_spin_lock_irqsave(&kvm->arch.csd_spinlock, flags);
	w = find_lock_in_csd_list(kvm, lock);
	if (likely(w == NULL)) {
		DebugKVM("csd lock %px on VCPU #%d is not queued to waiter "
			"list\n",
			lock, vcpu->vcpu_id);
		/* Insert lock to waiting list as waiter entry */
		w = queue_lock_to_waiter_list(vcpu, lock);
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		if (w == NULL)
			goto failed;
		return 0;
	}
	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
	if (likely(w->task)) {
		pr_err("%s(): lock %px on VCPU #%d is now queued to waiter "
			"list by task %s (%d) VCPU #%d\n",
			__func__, lock, vcpu->vcpu_id, w->task->comm,
			w->task->pid, w->vcpu->vcpu_id);
	} else {
		pr_err("%s(): lock %px on VCPU #%d is now queued to waiter "
			"list as unlocked by VCPU #%d\n",
			__func__, lock, vcpu->vcpu_id, w->vcpu->vcpu_id);
	}
	BUG_ON(true);
failed:
	return -EBUSY;
}

/*
 * Unlock csd lock and wake up VCPU task waiting for unlocking
 * Unlocking can outrun waiting VCPU, so if unlocking is first then queue
 * new waiter structure as unlocked.
 * If some VCPU thread already is queued as waiter for csd lock unlocking,
 * then wake up waiting VCPU thread, dequeue and queue to free list
 * the csd lock waiter structure.
 */
static inline int
guest_csd_unlock(struct kvm_vcpu *vcpu, void *lock)
{
	struct kvm *kvm = vcpu->kvm;
	csd_lock_waiter_t *w;
	unsigned long flags;

	DebugKVM("%s (%d) started for guest csd lock %px on VCPU #%d\n",
		current->comm, current->pid, lock, vcpu->vcpu_id);

	raw_spin_lock_irqsave(&kvm->arch.csd_spinlock, flags);
	w = find_lock_in_csd_list(vcpu->kvm, lock);
	if (likely(w != NULL)) {
		/* there is waiter for lock unlocking */
		if (unlikely(w->task)) {
			DebugKVM("guest csd lock %px on VCPU #%d is queued "
				"as waiter task %s (%d) on VCPU #%d\n",
				lock, vcpu->vcpu_id,
				w->task->comm, w->task->pid, w->vcpu->vcpu_id);
			wake_up_process(w->task);
		} else {
			pr_err("%s(): guest csd lock %px on VCPU #%d is queued "
				"as unlocked by VCPU #%d\n",
				__func__, lock, vcpu->vcpu_id,
				w->vcpu->vcpu_id);
			BUG_ON(true);
		}
		w->task = NULL;
		w->vcpu = NULL;
		w->lock = NULL;
		list_move_tail(&w->wait_list, &kvm->arch.csd_lock_free_head);
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		return 0;
	}
	/* csd lock is not found at waiters list, so unlock is comming */
	/* earlier then lock waiting. Insert lock to waiting list as */
	/* unlocked entry */
	if (likely(!list_empty(&kvm->arch.csd_lock_free_head))) {
		w = list_first_entry(&kvm->arch.csd_lock_free_head,
					csd_lock_waiter_t, wait_list);
		list_move_tail(&w->wait_list, &kvm->arch.csd_lock_wait_head);
		w->task = NULL;
		w->lock = lock;
		w->vcpu = vcpu;
		DebugKVMUL("guest csd lock %px on VCPU #%d could not find "
			"at waiters for unlocking list, queue %px as unlocked\n",
			lock, vcpu->vcpu_id, w);
	} else {
		pr_err("%s(): empty list of free csd lock waiter structures\n",
			__func__);
		dump_waiter_list(kvm);
		BUG_ON(true);
	}
	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
	return 0;
}

/*
 * Wait for csd lock unlocking
 * Unlocking can outrun waiting VCPU, so if unlocking is first then queue
 * new waiter structure as unlocked.
 * If some VCPU thread already is queued as waiter for csd lock unlocking,
 * then wake up waiting VCPU thread, dequeue and queue to free list
 * the csd lock waiter structure.
 */
static inline int
guest_csd_lock_wait(struct kvm_vcpu *vcpu, void *lock, bool try)
{
	struct kvm *kvm = vcpu->kvm;
	csd_lock_waiter_t *w;
	struct task_struct *guest_task;
	unsigned long flags;
	bool do_wait = false;

	DebugKVM("%s (%d) started for guest csd lock %px on VCPU #%d\n",
		current->comm, current->pid, lock, vcpu->vcpu_id);

	KVM_BUG_ON(vcpu->arch.host_task != current);
	guest_task = current;
	GTI_BUG_ON(guest_task == NULL);
	raw_spin_lock_irqsave(&kvm->arch.csd_spinlock, flags);
	w = find_lock_in_csd_list(vcpu->kvm, lock);
	if (likely(w == NULL)) {
		int r;
		struct kvm_vcpu *other_vcpu;

		/* csd lock is not found at waiters list as already */
		/* unlocked. */
		if (try) {
			/* waiting does not need, nothing to do */
			raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock,
							flags);
			DebugKVM("none waiters and it is well case\n");
			return 0;
		}
		vcpu->arch.on_csd_lock = true;
		wmb();	/* flag should be seen before read 'on_spinlock' or */
			/* other VCPU waiting state flags */
		if (kvm_test_pending_virqs(vcpu)) {
			/* there are VIRQs to handle, goto to try handle */
			vcpu->arch.on_csd_lock = false;
			raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock,
							flags);
			DebugKVM("there are pending VIRQs, try handle\n");
			return 0;
		}

		kvm_for_each_vcpu(r, other_vcpu, kvm) {
			if (other_vcpu == vcpu)
				continue;
		}

		/* Insert lock to waiting list as waiter entry */
		w = queue_lock_to_waiter_list(vcpu, lock);
		if (w == NULL)
			goto failed;
		do_wait = true;
	} else if (likely(w->task == NULL)) {
		/* there is csd lock already unlocked entry */
		DebugKVM("guest csd lock %px on VCPU #%d is queued "
			"as unlocked by VCPU #%d\n",
			lock, vcpu->vcpu_id, w->vcpu->vcpu_id);
		BUG_ON(!try && vcpu == w->vcpu);
		do_wait = false;
		goto unlocked;
	} else if (w->task == guest_task) {
		/* there is csd lock already waiter entry */
		DebugKVM("guest csd lock %px on VCPU #%d is queued "
			"as waiter by VCPU #%d\n",
			lock, vcpu->vcpu_id, w->vcpu->vcpu_id);
		BUG_ON(!try && vcpu != w->vcpu);
		vcpu->arch.on_csd_lock = true;
		do_wait = true;
	} else {
		pr_err("%s(): guest csd lock %px on VCPU #%d is queued "
			"as waiter task %s (%d) by other VCPU #%d\n",
			__func__, lock, vcpu->vcpu_id,
			w->task->comm, w->task->pid, w->vcpu->vcpu_id);
		BUG_ON(true);
	}
	if (do_wait) {
		set_current_state(TASK_INTERRUPTIBLE);
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		DebugKVM("go to schedule and wait for waking up\n");
		schedule();
		__set_current_state(TASK_RUNNING);
		DebugKVM("guest csd lock %px on VCPU #%d is waked up\n",
			lock, vcpu->vcpu_id);
		if (fatal_signal_pending(current)) {
			vcpu->arch.on_csd_lock = false;
			DebugKVMSH("%s (%d) fatal signal received: spare "
				"VCPU thread\n",
				current->comm, current->pid);
			kvm_spare_host_vcpu_release(vcpu);
			return -ERESTARTSYS;
		}
		raw_spin_lock_irqsave(&kvm->arch.csd_spinlock, flags);
		vcpu->arch.on_csd_lock = false;
		goto unlocked;
	}
unlocked:
	/* lock already unlocked, dequeue and free lock structure */
	/* and return to guest */
	w->task = NULL;
	w->vcpu = NULL;
	w->lock = NULL;
	list_move_tail(&w->wait_list, &kvm->arch.csd_lock_free_head);
	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
	return 0;

failed:
	/* other VCPU on spinlock waiting and */
	/* now cannot handle IPI or VCPU should */
	/* do dumping of guest state */
	vcpu->arch.on_csd_lock = false;
	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
	return -EBUSY;
}

int kvm_guest_csd_lock_ctl(struct kvm_vcpu *vcpu,
				csd_ctl_t csd_ctl_no, void *lock)
{
	switch (csd_ctl_no) {
	case CSD_LOCK_CTL:
		return guest_csd_lock(vcpu, lock);
	case CSD_UNLOCK_CTL:
		return guest_csd_unlock(vcpu, lock);
	case CSD_LOCK_WAIT_CTL:
		return guest_csd_lock_wait(vcpu, lock, false);
	case CSD_LOCK_TRY_WAIT_CTL:
		return guest_csd_lock_wait(vcpu, lock, true);
	default:
		pr_err("%s(): invalid CSD ctl number %d\n",
			__func__, csd_ctl_no);
		return -ENOSYS;
	}
}

int kvm_guest_csd_lock_init(struct kvm *kvm)
{
	csd_lock_waiter_t *w;
	int i;

	kvm->arch.csd_spinlock =
		__RAW_SPIN_LOCK_UNLOCKED(kvm->arch.csd_spinlock);
	INIT_LIST_HEAD(&kvm->arch.csd_lock_wait_head);
	INIT_LIST_HEAD(&kvm->arch.csd_lock_free_head);
	for (i = 0; i < KVM_MAX_CSD_LOCK_FREE_NUM; i++) {
		w = &kvm->arch.csd_lock_free_list[i];
		INIT_LIST_HEAD(&w->wait_list);
		w->task = NULL;
		w->vcpu = NULL;
		w->lock = NULL;
		list_add_tail(&w->wait_list, &kvm->arch.csd_lock_free_head);
	}
	return 0;
}

static inline void destroy_csd_lock_waiter(csd_lock_waiter_t *w)
{
	DebugKVM("current csd lock waiter list entry %px\n", w);
	if (likely(w->task != NULL)) {
		DebugKVM("current csd lock waiter list entry VCPU #%d "
			"task %s (%d) lock %px\n",
			w->vcpu->vcpu_id, w->task->comm, w->task->pid, w->lock);
		wake_up_process(w->task);
		w->task = NULL;
		w->lock = NULL;
		w->vcpu = NULL;
	} else {
		DebugKVM("current csd lock waiter list entry unlocked "
			"by VCPU #%d lock %px\n",
			w->vcpu->vcpu_id, w->lock);
	}
}
void kvm_guest_csd_lock_destroy(struct kvm *kvm)
{
	csd_lock_waiter_t *w;
	csd_lock_waiter_t *tmp;
	unsigned long flags;

	DebugKVM("started\n");

	raw_spin_lock_irqsave(&kvm->arch.csd_spinlock, flags);
	list_for_each_entry_safe(w, tmp,
			&kvm->arch.csd_lock_wait_head, wait_list) {
		destroy_csd_lock_waiter(w);
		list_move_tail(&w->wait_list, &kvm->arch.csd_lock_free_head);
	}
	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
}

#endif	/* CONFIG_SMP */
