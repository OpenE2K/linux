/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM host

#if !defined(_KVM_TRACE_CSD_LOCK_CTL_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_TRACE_CSD_LOCK_CTL_H

#include <linux/types.h>
#include <linux/smp.h>
#include <linux/tracepoint.h>
#include <asm/kvm/csd_lock.h>
#include <asm/kvm/hypercall.h>

#define	TRACE_PRINT_CSD_CTL(ctl_no) \
		(__print_symbolic(ctl_no, \
			{ CSD_LOCK_CTL,			"csd lock" }, \
			{ CSD_UNLOCK_CTL,		"csd unlock" }, \
			{ CSD_LOCK_WAIT_CTL,		"csd wait" }, \
			{ CSD_LOCK_TRY_WAIT_CTL,	"csd try wait" }))

#define	TRACE_PRINT_WAITER_STATE(state) \
		(__print_symbolic(state, \
			{ undefined_unlocked_type,	"there is no unlocking" }, \
			{ woken_unlocked_type,		"waiting task has been " \
							"woken up" }, \
			{ is_running_unlocked_type,	"waiting task was already " \
							"running" }, \
			{ queued_as_unlocked_type,	"as unlocked entry" }))

TRACE_EVENT(
	kvm_csd_lock_ctl,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_ctl_t csd_ctl),

	TP_ARGS(vcpu, lock, csd_ctl),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(csd_ctl_t, ctl)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->ctl = csd_ctl;
	),

	TP_printk("vcpu #%d\n"
		"lock %px %s hypercall\n",
		__entry->vcpu_id, __entry->lock,
		TRACE_PRINT_CSD_CTL(__entry->ctl)
	)
);

TRACE_EVENT(
	kvm_csd_lock_ctl_failed,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_ctl_t csd_ctl, int error),

	TP_ARGS(vcpu, lock, csd_ctl, error),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(csd_ctl_t, ctl)
		__field(int, error)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->ctl = csd_ctl;
		__entry->error = error;
	),

	TP_printk("vcpu #%d\n"
		"lock %px %s hypercall failed %d\n",
		__entry->vcpu_id, __entry->lock,
		TRACE_PRINT_CSD_CTL(__entry->ctl),
		__entry->error
	)
);

TRACE_EVENT(
	kvm_queue_lock_to_waiter_list,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(void *, task)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->task = w->task;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"queued to waiter list %px as waiter entry by vcpu itself task %px\n",
		__entry->vcpu_id, __entry->lock, __entry->w, __entry->task
	)
);

TRACE_EVENT(
	kvm_queue_waiter_to_list,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, by_vcpu_id)
		__field(unlocked_type_t, state)
		__field(void *, w_task)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->by_vcpu_id = (w->by_vcpu) ? w->by_vcpu->vcpu_id : -1;
		__entry->state = w->state;
		__entry->w_task = (void *)w->task;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"has been queued to waiter list %px by vcpu #%d %s "
		"move to wait for task %px wake up\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		__entry->by_vcpu_id,
		TRACE_PRINT_WAITER_STATE(__entry->state),
		__entry->w_task
	)
);

TRACE_EVENT(
	kvm_queue_waiter_to_free_list,

	TP_PROTO(struct kvm_vcpu *vcpu, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, w_vcpu_id)
		__field(void *, w_task)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = w->lock;
		__entry->w = (void *)w;
		__entry->w_vcpu_id = (w->vcpu) ? w->vcpu->vcpu_id : -1;
		__entry->w_task = (void *)w->task;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"waiter %px is queued to free list last vcpu #%d task %px\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		__entry->w_vcpu_id, __entry->w_task
	)
);

TRACE_EVENT(
	kvm_queue_waiter_to_lock_wait_list,

	TP_PROTO(struct kvm_vcpu *vcpu, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, w_vcpu_id)
		__field(void *, w_task)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = w->lock;
		__entry->w = (void *)w;
		__entry->w_vcpu_id = (w->vcpu) ? w->vcpu->vcpu_id : -1;
		__entry->w_task = (void *)w->task;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"waiter %px is queued to wait lock list last vcpu #%d task %px\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		__entry->w_vcpu_id, __entry->w_task
	)
);

TRACE_EVENT(
	kvm_wake_up_waiter,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, w_vcpu_id)
		__field(void *, w_task)
		__field(unlocked_type_t, state)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->w_vcpu_id = (w->vcpu) ? w->vcpu->vcpu_id : -1;
		__entry->w_task = (void *)w->task;
		__entry->state = w->state;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"is queued to waiter list %px by VCPU #%d task %px : %s\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		__entry->w_vcpu_id, __entry->w_task,
		TRACE_PRINT_WAITER_STATE(__entry->state)
	)
);

TRACE_EVENT(
	kvm_wait_for_wake_up,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, w_vcpu_id)
		__field(void *, w_task)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->w_vcpu_id = (w->vcpu) ? w->vcpu->vcpu_id : -1;
		__entry->w_task = (void *)w->task;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"has been queued to waiter list %px by VCPU #%d : "
		"wait for wake up task %px\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		__entry->w_vcpu_id, __entry->w_task
	)
);

TRACE_EVENT(
	kvm_wait_lock_again,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(void *, w_task)
		__field(int, by_vcpu_id)
		__field(unlocked_type_t, state)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->w_task = w->task;
		__entry->by_vcpu_id = (w->by_vcpu) ? w->by_vcpu->vcpu_id : -1;
		__entry->state = w->state;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"wait again : waiter entry %px state: %s, by VCPU #%d, task %px\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		TRACE_PRINT_WAITER_STATE(__entry->state),
		__entry->by_vcpu_id, __entry->w_task
	)
);

TRACE_EVENT(
	kvm_free_woken_waiter,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, by_vcpu_id)
		__field(unlocked_type_t, state)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->by_vcpu_id = (w->by_vcpu) ? w->by_vcpu->vcpu_id : -1;
		__entry->state = w->state;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"waiter %px has been unlocked by VCPU #%d and %s is freeing\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		__entry->by_vcpu_id,
		TRACE_PRINT_WAITER_STATE(__entry->state)
	)
);

TRACE_EVENT(
	kvm_free_unlocked_waiter,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, by_vcpu_id)
		__field(unlocked_type_t, state)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->by_vcpu_id = (w->by_vcpu) ? w->by_vcpu->vcpu_id : -1;
		__entry->state = w->state;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"waiter %px was queued %s by VCPU #%d and is freeing\n",
		__entry->vcpu_id, __entry->lock, __entry->w,
		TRACE_PRINT_WAITER_STATE(__entry->state),
		__entry->by_vcpu_id
	)
);

TRACE_EVENT(
	kvm_queue_unlocked_waiter,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock, csd_lock_waiter_t *w),

	TP_ARGS(vcpu, lock, w),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(void *, w)
		__field(int, by_vcpu_id)
		__field(unlocked_type_t, state)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
		__entry->w = (void *)w;
		__entry->by_vcpu_id = w->by_vcpu->vcpu_id;
		__entry->state = w->state;
	),

	TP_printk("vcpu #%d lock %px\n"
		"queued to waiter list %px by vcpu #%d %s\n",
		__entry->vcpu_id, __entry->lock, __entry->w, __entry->by_vcpu_id,
		TRACE_PRINT_WAITER_STATE(__entry->state)
	)
);

TRACE_EVENT(
	kvm_already_unlocked,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock),

	TP_ARGS(vcpu, lock),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"has been already unlocked\n",
		__entry->vcpu_id, __entry->lock
	)
);

TRACE_EVENT(
	kvm_break_lock_waiting,

	TP_PROTO(struct kvm_vcpu *vcpu, void *lock),

	TP_ARGS(vcpu, lock),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->lock = lock;
	),

	TP_printk("vcpu #%d\n"
		"lock %px\n"
		"there are pending virqs, break waiting to handle\n",
		__entry->vcpu_id, __entry->lock
	)
);

#endif /* _KVM_TRACE_CSD_LOCK_CTL_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../arch/e2k/kvm
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-csd-lock

/* This part must be outside protection */
#include <trace/define_trace.h>
