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
#include <linux/sched/debug.h>
#include <linux/sched/signal.h>
#include <linux/spinlock.h>
#include <linux/kvm_host.h>

#include <../kernel/sched/sched.h>

#include <asm/kvm/csd_lock.h>

#include "irq.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static inline long __sched
do_wait_for_common(struct completion *x, long timeout, int state)
{
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;

	if (!x->done) {
		DECLARE_SWAITQUEUE(wait);

		__prepare_to_swait(&x->wait, &wait);
		do {
			if (signal_pending_state(state, current)) {
				timeout = -ERESTARTSYS;
				DebugKVM("VCPU #%d interrupted by signal, "
					"VIRQs flag %d counter %d\n",
					vcpu->vcpu_id,
					kvm_test_pending_virqs(vcpu),
					kvm_get_pending_virqs_num(vcpu));
				break;
			}
			__set_current_state(state);
			raw_spin_unlock_irq(&x->wait.lock);
			timeout = schedule_timeout(timeout);
			raw_spin_lock_irq(&x->wait.lock);
			if (timeout && !signal_pending_state(state, current)) {
				timeout = -EINTR;
				DebugKVM("VCPU #%d waked up, "
					"VIRQs flag %d counter %d\n",
					vcpu->vcpu_id,
					kvm_test_pending_virqs(vcpu),
					kvm_get_pending_virqs_num(vcpu));
				break;
			}
		} while (!x->done && timeout);
		__finish_swait(&x->wait, &wait);
		if (!x->done)
			return timeout;
		if (timeout == -EINTR)
			return timeout;
	}
	x->done--;
	return timeout ?: 1;
}

static long __sched
wait_for_common(struct completion *x, long timeout, int state)
{
	might_sleep();

	raw_spin_lock_irq(&x->wait.lock);
	timeout = do_wait_for_common(x, timeout, state);
	raw_spin_unlock_irq(&x->wait.lock);
	return timeout;
}

/**
 * wait_for_completion_interruptible: - waits for completion of a task (w/intr)
 * @x:  holds the state of this particular completion
 *
 * This waits for completion of a specific task to be signaled. It is
 * interruptible.
 */
int __sched kvm_wait_for_completion_interruptible(struct completion *x)
{
	long t = wait_for_common(x, MAX_SCHEDULE_TIMEOUT, TASK_INTERRUPTIBLE);
	if (t == -ERESTARTSYS || t == -EINTR)
		return t;
	return 0;
}
