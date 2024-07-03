/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements on host the arch-dependent parts of kvm guest
 * spinlock()/spinunlock() slow part
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hash.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>

#include <asm/kvm/spinlock_slow.h>

#include "irq.h"
#include "process.h"
#include "complete.h"

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

#undef	DEBUG_KVM_UNLOCKED_MODE
#undef	DebugKVMUN
#define	DEBUG_KVM_UNLOCKED_MODE	0	/* spinlock deadlock debugging */
#define	DebugKVMUN(fmt, args...)					\
({									\
	if (DEBUG_KVM_UNLOCKED_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})
#undef	DEBUG_UNLOCKED_MODE
#undef	DebugKVMUL
#define	DEBUG_UNLOCKED_MODE	0	/* spinlock deadlock debugging */
#define	DebugKVMUL(fmt, args...)					\
({									\
	if (DEBUG_UNLOCKED_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static bool debug_loop = false;
#undef	DEBUG_KVM_LOOP_MODE
#undef	DebugLOOP
#define	DEBUG_KVM_LOOP_MODE	0	/* list loop debugging */
#define	DebugLOOP(fmt, args...)					\
({									\
	if (DEBUG_KVM_LOOP_MODE)					\
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

typedef struct spinlock_waiter {
	struct hlist_node	wait_list;
	struct completion	done;
	struct kvm_vcpu		*vcpu;
	void			*lock;
} spinlock_waiter_t;

/*
 * Lock a guest spinlock, slowpath:
 */

/*
 * Probably spinlock was already unlocked, so search
 * the spinlock in list of unlocked spinlocks
 * spinlock hash table and unlocked list should be locked by caller
 * If bool 'find' is true then function only scans list to find specified
 * lock in the list of unlocked spinlocks.
 * If bool 'find' is false, then the function scans list to add new entry with
 * current thread.
 */
static inline boot_spinlock_unlocked_t *
check_boot_spin_unlocked_list(struct kvm_vcpu *vcpu, void *lock, bool find)
{
	struct kvm *kvm = vcpu->kvm;
	boot_spinlock_unlocked_t *u;
	struct kvm_vcpu *vu, *vc;
	int loop = 0;

	list_for_each_entry(u, &kvm->arch.boot_spinunlocked_head,
							unlocked_list) {
		vu = u->vcpu;
		DebugKVM("next spinunlocked list entry VCPU #%d lock %px\n",
			vu->vcpu_id, u->lock);
		if (u->lock == lock) {
			DebugKVM("spinlock %px already was unlocked\n",
				lock);
			if (find) {
				DebugKVM("spinlock found at the unlocked "
					"list entry on VCPU %d\n",
					vu->vcpu_id);
				return u;
			}

			/* FIXME: it seems guest threads lock/unlock spins, */
			/* so their thread agents should be considered here */
			/* 1. In some case on the VCPU (it is one thread of */
			/* host) the guest thread lock spin and guest  */
			/* kernel switch to other thread, which can do */
			/* lock of the same spin. It is deadlock, but host */
			/* does not detect now this case. */
			/* 2. Same as case above, but other guest thread lock */
			/* other spin. It is good case, but host try check */
			/* and update list of unlocked spins on behalf the */
			/* same host thread? it is not good */
			/* Probably guest thread info (gti) should be here */
			/* instead of host thread info (ti) */
			loop = 0;
			list_for_each_entry(vc, &u->checked_unlocked,
							arch.vcpus_to_spin) {
				DebugLOOP("next spinunlocked list entry %px "
					"head %px VCPU #%d lock %px\n",
					u, &u->checked_unlocked, vu->vcpu_id,
					u->lock);
				DebugLOOP("next VCPU #%d current VCPU #%d\n",
					vc->vcpu_id, vcpu->vcpu_id);
				if (vc == vcpu) {
					DebugLOOP("spinlock %px already was "
						"checked by the VCPU #%d\n",
						lock, vu->vcpu_id);
					return NULL;
				}
				loop++;
				if (loop == 50)
					debug_loop = true;
				else if (loop == 100)
					debug_loop = false;
				else if (loop > 100)
					panic("infinity spinlock checked "
						"threads\n");
			}
			GTI_BUG_ON(!list_empty(&vcpu->arch.vcpus_to_spin));
			list_add_tail(&vcpu->arch.vcpus_to_spin,
					&u->checked_unlocked);
			DebugKVM("vcpu #%d is added to the list of "
				"spin %px unlock checked vcpus\n",
				vcpu->vcpu_id, lock);
			return u;
		}
	}
	return NULL;
}
static inline void
clear_boot_spin_unlocked_list(struct kvm_vcpu *vcpu,
					boot_spinlock_unlocked_t *node)
{
	struct kvm_vcpu *v, *tmp;

	DebugKVM("started for node %px lock %px unlocked by VCPU #%d\n",
		node, node->lock, node->vcpu->vcpu_id);
	list_for_each_entry_safe(v, tmp, &node->checked_unlocked,
							arch.vcpus_to_spin) {
		DebugKVM("next VCPU #%d\n", v->vcpu_id);
		/* current thread takes lock, VCPU cannot change */
		list_del_init(&v->arch.vcpus_to_spin);
	}
}
static inline void
free_boot_spin_unlocked_node(struct kvm_vcpu *vcpu, boot_spinlock_unlocked_t *u)
{
	struct kvm *kvm = vcpu->kvm;

	clear_boot_spin_unlocked_list(vcpu, u);
	list_move_tail(&u->unlocked_list, &kvm->arch.boot_spinunlocked_free);

	if (!list_empty(&kvm->arch.boot_spinunlocked_wait)) {
		struct kvm_vcpu *v;

		u = list_first_entry(&kvm->arch.boot_spinunlocked_wait,
				boot_spinlock_unlocked_t, unlocked_list);
		list_del(&u->unlocked_list);
		v = u->vcpu;
		kvm_vcpu_wake_up(v);
		DebugKVM("spinlock on VCPU #%d waiting for unlocked "
			"spinlocks free entry is woken up\n",
			v->vcpu_id);
	}
}

/*
 * Queue the lock to list of waiting for wake up
 * Lock kvm->arch.boot_spinlock_hash_lock should be taken by caller,
 * the function will unlock the spin before calling of scheduler
 * and take the spin again before returen from thr function
 */
static inline int
kvm_queue_boot_spin_lock_to_wait(struct kvm_vcpu *vcpu, void *lock,
					unsigned long flags)
{
	struct kvm *kvm = vcpu->kvm;
	spinlock_waiter_t waiter;
	spinlock_waiter_t *w;
	struct hlist_node *next;
	struct hlist_head *head;
	struct hlist_node *node;
	bool unlocked;

	DebugKVM("started on VCPU #%d for guest lock %px (hash index 0x%02x)\n",
		vcpu->vcpu_id, lock, boot_spinlock_hashfn(lock));

	head = &kvm->arch.boot_spinlock_hash[boot_spinlock_hashfn(lock)];
	waiter.vcpu = vcpu;
	waiter.lock = lock;
	INIT_HLIST_NODE(&waiter.wait_list);
	init_completion(&waiter.done);

	if (hlist_empty(head)) {
		hlist_add_head(&waiter.wait_list, head);
		DebugKVM("spinlock waitqueue is empty, add as first\n");
	} else {
		/* add current thread to the end of the waitqueue */
		/* but before check that this thread and lock is not already */
		/* at waitqueue */
		hlist_for_each_safe(node, next, head) {
			struct kvm_vcpu *v;

			w = hlist_entry(node, spinlock_waiter_t, wait_list);
			v = w->vcpu;
			DebugKVM("next spinlock waitqueue entry VCPU #%d "
				"lock %px\n",
				v->vcpu_id, w->lock);
			while (v == vcpu) {
				if (w->lock == lock) {
					DebugKVMDL("VCPU #%d : same lock %px "
						"detected at waitqueue %px\n",
						v->vcpu_id, w->lock, head);
				} else {
					DebugKVMDL("VCPU #%d : other lock %px "
						"(new lock %px) "
						"detected at waitqueue %px\n",
						v->vcpu_id, w->lock, lock,
						head);
				}
				GTI_BUG_ON(true);
				break;
			}
			if (next == NULL)
				break;
		}
		hlist_add_behind(&waiter.wait_list, node);
		DebugKVM("add to the end\n");
	}
	w = &waiter;

	/*
	 * Wait for the thread will be waked up, but reasons of waking up
	 * can be a few, for example some event occurred and should be passed
	 * to VCPU. In our case reason of waking up must be the spin unlocking.
	 * It need check spinlock waitqueue after waking up to make sure that
	 * the thread is unqueued and
	 *	can try lock the spin again;
	 *	take the spin lock
	 * If spinlock was detected in waitqueue again and pending VIRQs flag
	 * is set, then interrupt the waiting and return to guest to try
	 * handle pending VIRQs (in this case the function return -EINTR)
	 */

	GTI_BUG_ON(vcpu == NULL);
	vcpu->arch.on_spinlock = true;
	wmb();	/* flag should be seen before read 'on_csd_lock' or */
		/* other VCPU waiting state flags */
	do {
		struct kvm_vcpu *other_vcpu;
		struct kvm_vcpu *v;
		int ret;
		int r;

		kvm_for_each_vcpu(r, other_vcpu, kvm) {
			if (other_vcpu == vcpu)
				continue;
			if (other_vcpu->arch.on_csd_lock) {
				if (kvm_guest_vcpu_irqs_disabled(vcpu,
					kvm_get_guest_vcpu_UPSR_value(vcpu),
					kvm_get_guest_vcpu_PSR_value(vcpu))) {
					pr_debug("%s(): VCPU #%d is waiting "
						"for IPI completion VCPU #%d "
						"is waiting for spinlock %px\n",
						__func__, other_vcpu->vcpu_id,
						vcpu->vcpu_id, lock);
				} else if (!kvm_test_pending_virqs(vcpu)) {
					pr_debug("%s(): VCPU #%d there is IPI "
						"but none VIRQs pending flag, "
						"VIRQs count %d\n",
						__func__, vcpu->vcpu_id,
						kvm_get_pending_virqs_num(
									vcpu));
					/* kvm_print_local_APIC(vcpu); */
				}
			}
		}
		if (DO_DUMP_VCPU(vcpu) ||
			kvm_test_pending_virqs(vcpu) &&
				!kvm_guest_vcpu_irqs_disabled(vcpu,
					kvm_get_guest_vcpu_UPSR_value(vcpu),
					kvm_get_guest_vcpu_PSR_value(vcpu))) {
			/* there is signal to do dump guest state or */
			/* there are VIRQs to handle, goto to try handle */
			if (likely(w == &waiter)) {
				/* delete waiter from list */
				hlist_del(&w->wait_list);
			}
			vcpu->arch.on_spinlock = false;
			DebugKVM("VCPU #%d there are pending VIRQs, "
				"counter %d, mask enabled, try to handle\n",
				vcpu->vcpu_id,
				kvm_get_pending_virqs_num(vcpu));
			return -EINTR;
		}
		if (kvm_test_pending_virqs(vcpu) &&
				kvm_guest_vcpu_irqs_disabled(vcpu,
					kvm_get_guest_vcpu_UPSR_value(vcpu),
					kvm_get_guest_vcpu_PSR_value(vcpu))) {
			DebugKVM("VCPU #%d there are pending VIRQs, counter "
				"%d, mask disabled\n",
				vcpu->vcpu_id,
				kvm_get_pending_virqs_num(vcpu));
		}
		raw_spin_unlock_irqrestore(&kvm->arch.boot_spinlock_hash_lock,
						flags);
		DebugKVM("go to wait for completion\n");
		ret = kvm_wait_for_completion_interruptible(&w->done);
		DebugKVM("waiting for completion terminated with %d\n", ret);

		if (kvm->arch.boot_spinlock_hash_disable ||
						ret == -ERESTARTSYS) {
			DebugKVMSH("guest spinlock disabled or fatal signal: "
				"exit from process\n");
			kvm_spare_host_vcpu_release(vcpu);
			do_exit(ret);
		}
		raw_spin_lock_irqsave(&kvm->arch.boot_spinlock_hash_lock,
					flags);
		/* search thread at spinlock waitqueue */
		unlocked = true;
		hlist_for_each_entry(w, head, wait_list) {
			if (w == &waiter) {
				unlocked = false;
				v = w->vcpu;
				break;
			}
		}
		if (!unlocked && ret == 0) {
			pr_err("%s(): VCPU #%d lock %px = 0x%lx detected "
				"at spinlock waitqueue, when waiting was "
				"completed\n",
				__func__, v->vcpu_id, w->lock,
				(IS_HOST_KERNEL_ADDRESS((e2k_addr_t)w->lock)) ?
					(long)w->lock : *(long *)w->lock);
			vcpu->arch.on_spinlock = false;
			return -EINVAL;
		} else if (!unlocked) {
			DebugKVM("VCPU #%d lock %px = 0x%lx detected "
				"at spinlock waitqueue, waiting was "
				"interrupted ret = %d, so continue waiting\n",
				v->vcpu_id, w->lock,
				(IS_HOST_KERNEL_ADDRESS((e2k_addr_t)w->lock)) ?
					(long)w->lock : *(long *)w->lock,
				ret);
		} else if (unlocked) {
			v = waiter.vcpu;
			DebugKVM("VCPU #%d is not detected at spinlock "
				"waitqueue, so complete waiting\n",
				v->vcpu_id);
			break;
		}
	} while (!unlocked);
	vcpu->arch.on_spinlock = false;

	DebugKVM("%s (%d) is woken up, return to guest\n",
		current->comm, current->pid);
	return 0;
}

int kvm_boot_spin_lock_slow(struct kvm_vcpu *vcpu, void *lock,
					bool check_unlock)
{
	struct kvm *kvm = vcpu->kvm;
	boot_spinlock_unlocked_t *u;
	struct kvm_vcpu *v;
	unsigned long flags;
	int ret;

	raw_spin_lock_irqsave(&kvm->arch.boot_spinlock_hash_lock, flags);
	DebugKVMUL("%s (%d) VCPU #%d lock %px started\n",
		current->comm, current->pid, vcpu->vcpu_id, lock);

	/* probably spinlock was already unlocked, so first search our */
	/* spinlock in list of unlocked spinlocks */
	if (check_unlock) {
		if (check_boot_spin_unlocked_list(vcpu, lock, false) != NULL) {
			raw_spin_unlock_irqrestore(
				&kvm->arch.boot_spinlock_hash_lock, flags);
			DebugKVM("spinlock %px already was unlocked, return to "
				"try get locking\n",
				lock);
			return 0;
		}
	} else {
		u = check_boot_spin_unlocked_list(vcpu, lock, true);
		if (u != NULL) {
			v = u->vcpu;
			/* lock is found as already unlocked */
			/* wake up unlocking process to wake up all process */
			/* waiting for the lock */
			DebugKVMUL("%s (%d) lock %px will wake up unlocking "
				"VCPU #%d\n",
				current->comm, current->pid, lock, v->vcpu_id);
			kvm_vcpu_wake_up(v);
		}
	}

	/* spinlock was not unlocked, so add our process to waitqueue */
	ret = kvm_queue_boot_spin_lock_to_wait(vcpu, lock, flags);
	if (ret == -EINTR) {
		DebugKVMDL("%s (%d) VCPU has pending VIRQs, return "
			"to guest to try handle it\n",
			current->comm, current->pid);
	}

	raw_spin_unlock_irqrestore(&kvm->arch.boot_spinlock_hash_lock, flags);

	return ret;
}

/*
 * Guest locked spinlock, slowpath:
 */

int kvm_boot_spin_locked_slow(struct kvm_vcpu *vcpu, void *lock)
{
	struct kvm *kvm = vcpu->kvm;
	boot_spinlock_unlocked_t *u;
	unsigned long flags;
	int ret;

	DebugKVM("%s (%d) started for guest lock %px (hash index 0x%02x)\n",
		current->comm, current->pid, lock, boot_spinlock_hashfn(lock));

	raw_spin_lock_irqsave(&kvm->arch.boot_spinlock_hash_lock, flags);

	/* search spinlock at the list of unlocked spinlocks */
	do {
		u = check_boot_spin_unlocked_list(vcpu, lock, true);
		if (likely(u != NULL))
			break;
		DebugKVMDL("%s (%d) could not find lock at the list of "
			"unlocked spinloks\n",
			current->comm, current->pid);
		/* lock was not yet queued to waitqueue */
		/* so add our process to waitqueue and wait for wake up */
		/* to try find the lock in the list of unlocked spinlocks */
		ret = kvm_queue_boot_spin_lock_to_wait(vcpu, lock, flags);
		if (ret && ret != -EINTR) {
			pr_err("%s(): queue spinlock to waitqueue list failed "
				"with error %d, abort the process %s (%d)\n",
				__func__, ret, current->comm, current->pid);
			raw_spin_unlock_irqrestore(
				&kvm->arch.boot_spinlock_hash_lock, flags);
			do_exit(ret);
		} else if (ret == -EINTR) {
			DebugKVMDL("%s (%d) VCPU has pending VIRQs, return "
				"to guest to try handle it\n",
				current->comm, current->pid);
			raw_spin_unlock_irqrestore(
				&kvm->arch.boot_spinlock_hash_lock, flags);
			return ret;
		}
	} while (u == NULL);

	free_boot_spin_unlocked_node(vcpu, u);

	raw_spin_unlock_irqrestore(&kvm->arch.boot_spinlock_hash_lock, flags);
	DebugKVM("unlocked spinlock %px move to free list\n", lock);
	return 0;
}

/*
 * Add the spinlock to the list of unlocked spinlocks,
 * because of unlocking can outrun locking process, which can in progress
 * and will be waiting for unlocking at any time
 * Spinlock should be taken
 */
static boot_spinlock_unlocked_t *
add_guest_boot_spin_as_unlocked(struct kvm_vcpu *vcpu, void *lock,
				bool add_to_unlock, unsigned long flags)
{
	struct kvm *kvm = vcpu->kvm;
	boot_spinlock_unlocked_t *u = NULL;
	struct kvm_vcpu *v;

	DebugKVM("%s (%d) started for guest lock %px\n",
		current->comm, current->pid, lock);

	do {
		u = check_boot_spin_unlocked_list(vcpu, lock, true);
		if (u != NULL) {
			if (add_to_unlock) {
				pr_err("%s() lock %px detected at unlocked "
					"list WHY ???\n",
					__func__, lock);
				return ERR_PTR(-EINVAL);
			}
			v = u->vcpu;
			DebugKVMUN("guest lock %px already detected at "
				"unlocked list, queued by VCPU #%d\n",
				lock, v->vcpu_id);
			return NULL;
		}

		if (list_empty(&kvm->arch.boot_spinunlocked_free)) {
			boot_spinlock_unlocked_t unlock_waiter;

			pr_warn("kvm_boot_spin_unlock_slow() overflow "
				"of list of unlocked spinlocks\n");
			unlock_waiter.vcpu = vcpu;
			unlock_waiter.lock = lock;
			INIT_LIST_HEAD(&unlock_waiter.unlocked_list);
			list_add_tail(&unlock_waiter.unlocked_list,
					&kvm->arch.boot_spinunlocked_wait);
			set_current_state(TASK_INTERRUPTIBLE);
			raw_spin_unlock_irqrestore(
				&kvm->arch.boot_spinlock_hash_lock, flags);

			DebugKVM("go to schedule and wait for wake up\n");
			schedule();
			__set_current_state(TASK_RUNNING);
			if (kvm->arch.boot_spinlock_hash_disable ||
					fatal_signal_pending(current)) {
				DebugKVMSH("guest spinlock disabled or fatal "
					"signal: exit from process\n");
				kvm_spare_host_vcpu_release(vcpu);
				do_exit(0);
			}
			raw_spin_lock_irqsave(
				&kvm->arch.boot_spinlock_hash_lock, flags);
		} else {
			break;
		}
	} while (u == NULL);

	u = list_first_entry(&kvm->arch.boot_spinunlocked_free,
				boot_spinlock_unlocked_t, unlocked_list);
	list_move_tail(&u->unlocked_list, &kvm->arch.boot_spinunlocked_head);
	u->vcpu = vcpu;
	u->lock = lock;
	INIT_LIST_HEAD(&u->checked_unlocked);
	DebugKVM("add spinlock %s (%d) VCPU #%d lock %px to the list of "
		"unlocked\n",
		current->comm, current->pid, u->vcpu->vcpu_id, u->lock);
	return u;
}

/*
 * Unlock a guest spinlock, slowpath:
 */

int kvm_boot_spin_unlock_slow(struct kvm_vcpu *vcpu, void *lock,
				bool add_to_unlock)
{
	struct kvm *kvm = vcpu->kvm;
	boot_spinlock_unlocked_t *u;
	spinlock_waiter_t *w;
	struct hlist_head *head;
	struct hlist_node *tmp;
	struct kvm_vcpu *v;
	int unlocked = 0;
	unsigned long flags;

	DebugKVMUN("%s (%d) started for guest lock %px (hash index 0x%02x)\n",
		current->comm, current->pid, lock, boot_spinlock_hashfn(lock));

	raw_spin_lock_irqsave(&kvm->arch.boot_spinlock_hash_lock, flags);

	/* at first add our spinlock to the list of unlocked spinlocks, */
	/* because of unlocking can outrun locking process which is */
	/* trying to enable lock */
	if (add_to_unlock) {
		u = add_guest_boot_spin_as_unlocked(vcpu, lock, true, flags);
		if (IS_ERR(u)) {
			raw_spin_unlock_irqrestore(
				&kvm->arch.boot_spinlock_hash_lock, flags);
			return PTR_ERR(u);
		}
	} else {
		u = NULL;
	}

	head = &kvm->arch.boot_spinlock_hash[boot_spinlock_hashfn(lock)];

waking_up:
	if (hlist_empty(head)) {
		DebugKVMUN("spinlock waitqueue is empty\n");
		goto not_found;
	}
	/* find all task waiting for this spinlock and wake up its */
	hlist_for_each_entry_safe(w, tmp, head, wait_list) {
		v = w->vcpu;
		DebugKVMUN("next spinlock waitqueue entry VCPU #%d lock %px\n",
			v->vcpu_id, w->lock);
		if (w->lock != lock)
			continue;
		hlist_del(&w->wait_list);
		if (unlikely(completion_done(&w->done))) {
			pr_err("%s(): VCPU #%d waiting for unlock is already "
				"completed\n",
				__func__, v->vcpu_id);
		}
		complete(&w->done);
		DebugKVMUN("spin unlocked and VCPU #%d is woken up\n",
			v->vcpu_id);
		unlocked++;
	}

not_found:
	if (unlikely(!add_to_unlock && unlocked == 0)) {
		boot_spinlock_unlocked_t *u_new;

		/* could not find any waiting for spin unlocking process, */
		/* so unlocking is first and locking process are in progress */
		/* It need wait for locking process in wait list queue */
		if (u == NULL) {
			u_new = add_guest_boot_spin_as_unlocked(vcpu, lock,
								false, flags);
			if (unlikely(IS_ERR(u_new))) {
				raw_spin_unlock_irqrestore(
					&kvm->arch.boot_spinlock_hash_lock,
					flags);
				return PTR_ERR(u);
			} else if (u_new == NULL) {
				/* there is already unlocking process for */
				/* this lock, it need not second same process */
				goto done;
			}
			u = u_new;
			v = u->vcpu;
			DebugKVMUN("spin lock %px is queued as unlocked "
				"by VCPU #%d\n",
				lock, v->vcpu_id);
		}
		/* the process should wait for any locking process */
		/* which will detect the spin as unlocked and wake up */
		/* this process to restart waking up of all waiting for */
		/* the lock processes */
		set_current_state(TASK_INTERRUPTIBLE);
		DebugKVMUN("%s (%d) lock %px go to schedule and wait for "
			"wake up by locking process\n",
			current->comm, current->pid, lock);
		raw_spin_unlock_irqrestore(
				&kvm->arch.boot_spinlock_hash_lock, flags);

		schedule();
		__set_current_state(TASK_RUNNING);
		if (kvm->arch.boot_spinlock_hash_disable ||
				fatal_signal_pending(current)) {
			goto signaled;
		}
		raw_spin_lock_irqsave(&kvm->arch.boot_spinlock_hash_lock,
					flags);
		DebugKVMUN("%s (%d) lock %px is waked up by locking process\n",
			current->comm, current->pid, lock);
		goto waking_up;
	}
done:
	if (!add_to_unlock && u != NULL) {
		free_boot_spin_unlocked_node(vcpu, u);
		DebugKVMUN("%s (%d) lock %px is deleted from unlocking queue\n",
			current->comm, current->pid, lock);
	}
	raw_spin_unlock_irqrestore(&kvm->arch.boot_spinlock_hash_lock, flags);

	if (unlocked > 0)
		cond_resched();

	DebugKVMUN("%s (%d) completed for guest lock %px, unlocked %d\n",
		current->comm, current->pid, lock, unlocked);
	return 0;

signaled:
	DebugKVMSH("guest spinlock disabled or fatal signal: "
		"exit from process\n");
	kvm_spare_host_vcpu_release(vcpu);
	do_exit(0);
	return 0;
}

int kvm_boot_spinlock_init(struct kvm *kvm)
{
	boot_spinlock_unlocked_t *u;
	int i;

	for (i = 0; i < BOOT_SPINLOCK_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&kvm->arch.boot_spinlock_hash[i]);
	INIT_LIST_HEAD(&kvm->arch.boot_spinunlocked_head);
	INIT_LIST_HEAD(&kvm->arch.boot_spinunlocked_free);
	INIT_LIST_HEAD(&kvm->arch.boot_spinunlocked_wait);
	for (i = 0; i < BOOT_SPINUNLOCKED_LIST_SIZE; i++) {
		u = &kvm->arch.boot_spinunlocked_list[i];
		INIT_LIST_HEAD(&u->unlocked_list);
		list_add_tail(&u->unlocked_list,
				&kvm->arch.boot_spinunlocked_free);
	}
	kvm->arch.boot_spinlock_hash_lock =
		__RAW_SPIN_LOCK_UNLOCKED(kvm->arch.boot_spinlock_hash_lock);
	kvm->arch.boot_spinlock_hash_disable = false;
	return 0;
}


int vcpu_boot_spinlock_init(struct kvm_vcpu *vcpu)
{
	INIT_LIST_HEAD(&vcpu->arch.vcpus_to_spin);
	return 0;
}

static void destroy_boot_spinlock_list(struct hlist_head *head)
{
	spinlock_waiter_t *w;
	struct hlist_node *tmp;
	struct kvm_vcpu *v;

	hlist_for_each_entry_safe(w, tmp, head, wait_list) {
		v = w->vcpu;
		DebugKVM("next spinlock waitqueue entry VCPU #%d lock %px\n",
			v->vcpu_id, w->lock);
		hlist_del(&w->wait_list);
		kvm_vcpu_wake_up(v);
	}
}
void kvm_boot_spinlock_destroy(struct kvm *kvm)
{
	boot_spinlock_unlocked_t *u;
	boot_spinlock_unlocked_t *tmp;
	struct hlist_head *head;
	struct kvm_vcpu *v;
	unsigned long flags;
	int i;

	DebugKVM("started\n");

	raw_spin_lock_irqsave(&kvm->arch.boot_spinlock_hash_lock, flags);
	kvm->arch.boot_spinlock_hash_disable = true;
	for (i = 0; i < BOOT_SPINLOCK_HASH_SIZE; i++) {
		head = &kvm->arch.boot_spinlock_hash[i];
		if (hlist_empty(head)) {
			DebugKVM("hash index 0x%02x: waitqueue is empty\n", i);
			continue;
		}
		DebugKVM("hash index 0x%02x waitqueue is not empty\n", i);
		destroy_boot_spinlock_list(head);
	}
	list_for_each_entry_safe(u, tmp, &kvm->arch.boot_spinunlocked_head,
					unlocked_list) {
		v = u->vcpu;
		DebugKVM("next spin unlocked list entry VCPU #%d lock %px\n",
			v->vcpu_id, u->lock);
		list_del(&u->unlocked_list);
	}
	list_for_each_entry_safe(u, tmp, &kvm->arch.boot_spinunlocked_free,
					unlocked_list) {
		DebugKVM("next spin unlocked free entry %px\n", u);
		list_del(&u->unlocked_list);
	}
	list_for_each_entry_safe(u, tmp, &kvm->arch.boot_spinunlocked_wait,
					unlocked_list) {
		v = u->vcpu;
		DebugKVM("next spin unlocked waiting list entry VCPU #%d "
			"lock %px\n",
			v->vcpu_id, u->lock);
		list_del(&u->unlocked_list);
		kvm_vcpu_wake_up(v);
	}
	raw_spin_unlock_irqrestore(&kvm->arch.boot_spinlock_hash_lock, flags);
}
