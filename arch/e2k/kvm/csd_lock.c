/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements on host the arch-dependent parts of kvm guest
 * csd_lock/csd_unlock functions to serialize access to per-cpu csd resources
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>

#include <asm/kvm/csd_lock.h>

#include "process.h"
#include "cpu.h"

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

#undef	DEBUG_UNLOCK_WAIT_MODE
#undef	DebugWAIT
#define	DEBUG_UNLOCK_WAIT_MODE	0	/* csd unlock waiting debug */
#define	DebugWAIT(fmt, args...)						\
({									\
	if (DEBUG_UNLOCK_WAIT_MODE)					\
		pr_err("%s(): " fmt, __func__, ##args);			\
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

#define CREATE_TRACE_POINTS
#include "trace-csd-lock.h"

static inline csd_lock_waiter_t *
find_lock_in_csd_list(struct kvm *kvm, void *lock)
{
	csd_lock_waiter_t *w, *lock_w = NULL;

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
			if (unlikely(lock_w != NULL)) {
				pr_err("%s(): one more entry of lock %px in the "
					"list of current active waiters\n",
					__func__, lock);
			}
			lock_w = w;
		}
	}
	return lock_w;
}

static void dump_waiter_list(struct kvm *kvm)
{
	csd_lock_waiter_t *w;

	list_for_each_entry(w, &kvm->arch.csd_lock_wait_head, wait_list) {
		pr_alert("csd lock waiter list entry %px: lock %px ",
			w, w->lock);
		if (w->task) {
			pr_cont("is waiting on vcpu #%d",
				w->vcpu->vcpu_id);
			if (w->by_vcpu) {
				pr_cont(" for wake up by vcpu #%d state: %d\n",
					w->by_vcpu->vcpu_id, w->state);
			} else {
				pr_cont("\n");
			}
		} else {
			if (w->by_vcpu) {
				pr_cont("is already unlocked by VCPU #%d "
					"state %d\n",
					w->by_vcpu->vcpu_id, w->state);
			} else {
				pr_cont("is a hang waiter entry, state %d\n",
					w->state);
			}
		}
		pr_cont("\n");
	}
}

/* Insert lock to waiting list as waiter entry */
/* spinlock should be taken */
static inline void queue_waiter_to_list(struct kvm_vcpu *vcpu, void *lock,
				csd_lock_waiter_t *w,  struct task_struct *task)
{
	struct kvm *kvm = vcpu->kvm;

	trace_kvm_queue_waiter_to_lock_wait_list(vcpu, w);
	list_move_tail(&w->wait_list, &kvm->arch.csd_lock_wait_head);
	E2K_KVM_BUG_ON(task && vcpu->arch.host_task != task);
	w->task = task;
	w->lock = lock;
	w->vcpu = vcpu;
	w->by_vcpu = NULL;
	w->state = undefined_unlocked_type;
}

static inline void queue_waiter_to_free_list(struct kvm_vcpu *vcpu,
						csd_lock_waiter_t *w)
{
	struct kvm *kvm = vcpu->kvm;

	trace_kvm_queue_waiter_to_free_list(vcpu, w);
	list_move_tail(&w->wait_list, &kvm->arch.csd_lock_free_head);
	w->task = NULL;
	w->vcpu = NULL;
	w->lock = NULL;
	w->by_vcpu = NULL;
	w->state = undefined_unlocked_type;
}

static inline csd_lock_waiter_t *
queue_lock_to_waiter_list(struct kvm_vcpu *vcpu, void *lock)
{
	struct kvm *kvm = vcpu->kvm;
	csd_lock_waiter_t *w;

	if (likely(!list_empty(&kvm->arch.csd_lock_free_head))) {
		w = list_first_entry(&kvm->arch.csd_lock_free_head,
					csd_lock_waiter_t, wait_list);
		queue_waiter_to_list(vcpu, lock, w, current);
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

/* Insert lock to waiting list as unlocked entry */
static inline csd_lock_waiter_t *
queue_as_unlocked_to_waiter_list(struct kvm_vcpu *vcpu, void *lock)
{
	struct kvm *kvm = vcpu->kvm;
	csd_lock_waiter_t *w;

	if (likely(!list_empty(&kvm->arch.csd_lock_free_head))) {
		w = list_first_entry(&kvm->arch.csd_lock_free_head,
					csd_lock_waiter_t, wait_list);
		list_move_tail(&w->wait_list, &kvm->arch.csd_lock_wait_head);
		w->task = NULL;
		w->lock = lock;
		w->vcpu = NULL;
		w->by_vcpu = vcpu;
		w->state = queued_as_unlocked_type;
		trace_kvm_queue_unlocked_waiter(vcpu, lock, w);
		DebugKVMUL("guest csd lock %px on VCPU #%d could not find "
			"at waiters for unlocking list, queue %px as unlocked\n",
			lock, vcpu->vcpu_id, w);
	} else {
		pr_err("%s(): empty list of free csd lock waiter structures\n",
			__func__);
		dump_waiter_list(kvm);
		BUG_ON(true);
	}
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
		if (w == NULL)
			goto failed;
		trace_kvm_queue_lock_to_waiter_list(vcpu, lock, w);
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		return 0;
	}
	if (likely(w->task == NULL)) {
		struct kvm_vcpu *by_vcpu = w->by_vcpu;

		/*
		 * Lock has been queued as unlocked by other VCPU after
		 * csd lock waiting and before checking the locking flag
		 * by this VCPU.
		 * Move the lock from list as unlocked to list as waiter
		 */
		E2K_KVM_BUG_ON(by_vcpu == NULL);
		E2K_KVM_BUG_ON(vcpu == by_vcpu);
		trace_kvm_queue_waiter_to_list(vcpu, lock, w);
		queue_waiter_to_list(vcpu, lock, w, current);
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		DebugWAIT("csd lock %px on VCPU #%d, other VCPU #%d had time "
			"to queue to waiter list as unlocked\n",
			lock, vcpu->vcpu_id, by_vcpu->vcpu_id);
		return 0;
	}

	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
	pr_err("%s(): lock %px on VCPU #%d is now queued to waiter "
		"list by task %s (%d) VCPU #%d\n",
		__func__, lock, vcpu->vcpu_id, w->task->comm,
		w->task->pid, w->vcpu->vcpu_id);
	E2K_KVM_BUG_ON(true);
failed:
	trace_kvm_csd_lock_ctl_failed(vcpu, lock, CSD_LOCK_CTL, -EBUSY);
	raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
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
		struct task_struct *w_task;
		struct kvm_vcpu *w_vcpu;
		bool woken;

		/* there is waiter for lock unlocking */
		w_task = w->task;
		w_vcpu = w->vcpu;
		w->by_vcpu = vcpu;
		if (unlikely(w_task)) {
			DebugKVM("guest csd lock %px on VCPU #%d is queued "
				"as waiter task %s (%d) on VCPU #%d\n",
				lock, vcpu->vcpu_id,
				w_task->comm, w_task->pid, w->vcpu->vcpu_id);
			woken = wake_up_process(w_task);
			w->state = (woken) ? woken_unlocked_type :
						is_running_unlocked_type;
			trace_kvm_wake_up_waiter(vcpu, lock, w);
		} else {
			/*
			* Lock has been queued as unlocked by other VCPU after
			* csd lock waiting and before checking the locking flag
			* by this VCPU.
			* Free the lock from list of unlocked/waiter items
			*/
			DebugWAIT("free csd lock %px on VCPU #%d, other VCPU #%d "
				"had time to queue to waiter list as unlocked\n",
				lock, vcpu->vcpu_id, w->vcpu->vcpu_id);
			if (likely(w->by_vcpu != NULL)) {
				KVM_WARN_ON(w->by_vcpu == vcpu);
				trace_kvm_free_unlocked_waiter(vcpu, lock, w);
				queue_waiter_to_free_list(vcpu, w);
			} else {
				E2K_KVM_BUG_ON(true);
			}
		}
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		return 0;
	}
	/* csd lock is not found at waiters list, so unlock is comming */
	/* earlier then lock waiting. Insert lock to waiting list as */
	/* unlocked entry */
	w = queue_as_unlocked_to_waiter_list(vcpu, lock);
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
	struct task_struct *host_task;
	unsigned long flags;
	bool do_wait = false;
	bool queued = false;
	int try_num;

	DebugKVM("%s (%d) started for guest csd lock %px on VCPU #%d\n",
		current->comm, current->pid, lock, vcpu->vcpu_id);

	E2K_KVM_BUG_ON(vcpu->arch.host_task != current);
	host_task = current;

	try_num = 0;

again:
	raw_spin_lock_irqsave(&kvm->arch.csd_spinlock, flags);
	w = find_lock_in_csd_list(vcpu->kvm, lock);
	if (likely(w == NULL)) {
		int r;
		struct kvm_vcpu *other_vcpu;

		/* csd lock is not found at waiters list as already */
		/* unlocked. */
		if (try) {
			/* waiting does not need, nothing to do */
			trace_kvm_already_unlocked(vcpu, lock);
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
			trace_kvm_break_lock_waiting(vcpu, lock);
			raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock,
							flags);
			DebugKVM("there are pending VIRQs, try handle\n");
			return -EAGAIN;
		}
		kvm_for_each_vcpu(r, other_vcpu, kvm) {
			if (other_vcpu == vcpu)
				continue;
		}

		/* Insert lock to waiting list as waiter entry */
		w = queue_lock_to_waiter_list(vcpu, lock);
		if (w == NULL)
			goto failed;
		queued = true;
		do_wait = true;
		trace_kvm_queue_lock_to_waiter_list(vcpu, lock, w);
	} else if (likely(w->task == NULL)) {
		/* there is already csd lock unlocked entry */
		DebugKVM("guest csd lock %px on VCPU #%d is queued "
			"as unlocked by VCPU #%d\n",
			lock, vcpu->vcpu_id, w->by_vcpu->vcpu_id);
		E2K_KVM_BUG_ON(w->by_vcpu == NULL);
		E2K_KVM_BUG_ON(w->state != queued_as_unlocked_type);
		if (vcpu == w->by_vcpu) {
			pr_err_once("%s(): csd lock was queued as unlocked on "
				"vcpu #%d by itself, why???\n",
				__func__, vcpu->vcpu_id);
		}
		DebugKVM("guest csd lock %px was queued by VCPU #%d as unlocked "
			"and is waiting for release by VCPU #%d itself\n",
			lock, w->by_vcpu->vcpu_id, vcpu->vcpu_id);
		do_wait = false;
		trace_kvm_free_unlocked_waiter(vcpu, lock, w);
		goto unlocked;
	} else if (w->task == host_task) {
		/* there is csd lock already waiter entry */
		DebugKVM("guest csd lock %px on VCPU #%d is queued "
			"as waiter by VCPU #%d\n",
			lock, vcpu->vcpu_id, w->vcpu->vcpu_id);
		E2K_KVM_BUG_ON(!try && vcpu != w->vcpu);
		if (w->by_vcpu == NULL) {
			/* waiting for unlock is comming earlier then unlocking */
			vcpu->arch.on_csd_lock = true;
			do_wait = true;
		} else {
			/* lock has been already unlocked and waiting task was */
			/* woken up, so free waiter */
			do_wait = false;
			trace_kvm_free_woken_waiter(vcpu, lock, w);
			goto unlocked;
		}
	} else {
		pr_err("%s(): guest csd lock %px on VCPU #%d is queued "
			"as waiter task %s (%d) by other VCPU #%d "
			"by_vcpu #%d, state: %d\n",
			__func__, lock, vcpu->vcpu_id,
			w->task->comm, w->task->pid, w->vcpu->vcpu_id,
			(w->by_vcpu) ? w->by_vcpu->vcpu_id : -1, w->state);
		KVM_WARN_ON(true);
	}
	if (do_wait) {
		trace_kvm_wait_for_wake_up(vcpu, lock, w);
		set_current_state(TASK_INTERRUPTIBLE);
		raw_spin_unlock_irqrestore(&kvm->arch.csd_spinlock, flags);
		if (kvm_test_pending_virqs(vcpu)) {
			/* there are VIRQs to handle, goto to try handle */
			/* and to enable ipi interrupts towards each other */
			vcpu->arch.on_csd_lock = false;
			trace_kvm_break_lock_waiting(vcpu, lock);
			DebugKVM("there are pending VIRQs, try handle\n");
			return -EAGAIN;
		}
		DebugKVM("go to schedule and wait for waking up\n");
		do {
			long out;

			out = schedule_timeout(3);
			__set_current_state(TASK_RUNNING);
			if (out > 0) {
				/* VCPU waked up on some event */
				break;
			} else {
				/* VCPU waked up on timeout */
				vcpu->arch.on_csd_lock = false;
				try_num++;
				if (((try_num) & 0xf) == 0) {
					pr_err("%s(): vcpu #%d waiting is timed "
						"out, try #%d, try again\n",
						__func__, vcpu->vcpu_id, try_num);
				}
				if (unlikely(try_num > 100)) {
					pr_err("%s(): kill user: guest csd lock %px "
						"on VCPU #%d %s queued as waiter "
						"by VCPU #%d\n",
						__func__, lock, vcpu->vcpu_id,
						(queued) ? "is" : "has been",
						(w->vcpu) ? w->vcpu->vcpu_id : -1);
					do_exit(SIGKILL);
				} else {
					/*
					 * Try wait again, probably after unlocking
					 * spinlock and before call scheduler other
					 * vcpu was waked up this waiter and its
					 * is lost here
					 */
					do_wait = false;
					goto again;
				}
			}
		} while (true);
		DebugKVM("guest csd lock %px on VCPU #%d is waked up\n",
			lock, vcpu->vcpu_id);
		if (fatal_signal_pending(current)) {
			vcpu->arch.on_csd_lock = false;
			DebugKVMSH("%s (%d) fatal signal received: spare "
				"VCPU thread\n",
				current->comm, current->pid);
			kvm_spare_host_vcpu_release(vcpu);
			trace_kvm_csd_lock_ctl_failed(vcpu, lock,
					CSD_LOCK_WAIT_CTL, -ERESTARTSYS);
			return -ERESTARTSYS;
		}
		vcpu->arch.on_csd_lock = false;
		trace_kvm_wait_lock_again(vcpu, lock, w);
		goto again;
	}

unlocked:
	/* lock already unlocked, dequeue and free lock structure */
	/* and return to guest */
	queue_waiter_to_free_list(vcpu, w);
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
	trace_kvm_csd_lock_ctl(vcpu, lock, csd_ctl_no);
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
		w->by_vcpu = NULL;
		w->state = undefined_unlocked_type;
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
		w->by_vcpu = NULL;
		w->state = undefined_unlocked_type;
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
