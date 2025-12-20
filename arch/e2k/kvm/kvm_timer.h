/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_TIMER_H
#define __KVM_E2K_TIMER_H

#include <linux/kthread.h>

typedef enum kvm_timer_type {
	kvm_unknown_timer_type = 0,	/* unknown timer type */
	kvm_sys_timer_type,		/* lt system timer */
	kvm_wd_timer_type,		/* lt watchdog timer */
	kvm_reset_timer_type,		/* lt reset counter */
	kvm_power_timer_type,		/* lt power counter */
	kvm_apic_timer_type,		/* APIC local timer */
	kvm_epic_timer_type,		/* CEPIC local timer */
	kvm_sci_timer_type,		/* SPMC SCI timer */
} kvm_timer_type_t;

typedef enum kvm_timer_work {
	kvm_unknown_timer_work = 0,	/* unknown work */
	kvm_set_reset_irq_timer_work,	/* generate and reset interrupt */
	kvm_set_irq_timer_work,		/* generate interrupt */
	kvm_reset_irq_timer_work,	/* reset interrupt */
	kvm_watchdog_reset_timer_work,	/* reset system on watchdog */
} kvm_timer_work_t;

typedef struct kvm_timer {
	const char *name;		/* timer name */
	kvm_timer_type_t type;		/* timer type (see above) */
	struct hrtimer timer;		/* high resolution timer to emulate */
					/* timers counters */
	u64 start_count;		/* counter value at the (re)start */
					/* moment of high resolution timer */
	s64 period;			/* unit: ns */
	u64 period_start;		/* counter value at the start of */
					/* current timer period */
	s64 running_time;		/* value of VCPU running time at */
					/* moment of last timer setting */
	u64 host_start_ns;		/* hrtimer start time on host */
					/* at nsecs */
	atomic_t pending;		/* accumulated triggered timers */
	bool reinject;
	bool started;			/* timer is runing */
	bool hrtimer_started;		/* hrtimer is started and is active */
	raw_spinlock_t lock;		/* lock to update timer struct */
	kvm_timer_work_t work;		/* work type on timer expires */
	struct kthread_worker *worker;	/* kernel thread to handle timer */
	struct kthread_work expired;
	const struct kvm_timer_ops *t_ops;
	struct kvm *kvm;
	struct kvm_vcpu *vcpu;
} kvm_timer_t;

typedef struct kvm_timer_ops {
	bool (*is_periodic)(struct kvm_timer *ktimer);
	void (*timer_fn)(struct kvm_vcpu *vcpu, void *data);
} kvm_timer_ops_t;

#endif	/* __KVM_E2K_TIMER_H */