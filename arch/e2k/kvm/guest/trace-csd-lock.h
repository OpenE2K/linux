/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#undef TRACE_SYSTEM
#define TRACE_SYSTEM guest

#if !defined(_KVM_GUEST_TRACE_CSD_LOCK_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_GUEST_TRACE_CSD_LOCK_H

#include <linux/types.h>
#include <linux/smp.h>
#include <linux/tracepoint.h>
#include <asm/kvm/hypercall.h>

#define	TRACE_PRINT_CSD_LOCK_FLAGS(flags) \
		(__print_flags((flags) & (CSD_FLAG_LOCK | \
					  CSD_TYPE_ASYNC | \
					  CSD_TYPE_SYNC), "|", \
			{ CSD_FLAG_LOCK,	"locked" }, \
			{ CSD_TYPE_ASYNC,	"async" }, \
			{ CSD_TYPE_SYNC,	"synchronous" }))

#define	TRACE_PRINT_CSD_CTL(ctl_no) \
		(__print_symbolic(ctl_no, \
			{ CSD_LOCK_CTL,			"lock" }, \
			{ CSD_UNLOCK_CTL,		"unlock" }, \
			{ CSD_LOCK_WAIT_CTL,		"wait" }, \
			{ CSD_LOCK_TRY_WAIT_CTL,	"try wait" }))

DECLARE_EVENT_CLASS(kvm_csd_lock_class,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl,
		 unsigned long IP_from),

	TP_ARGS(data, csd_ctl, IP_from),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(csd_ctl_t, ctl)
		__field(smp_call_func_t, func)
		__field(unsigned int, flags)
		__field(unsigned long, IP_from)
	),

	TP_fast_assign(
		__entry->vcpu_id = smp_processor_id();
		__entry->lock = (void *)data;
		__entry->ctl = csd_ctl;
		__entry->func = data->func;
		__entry->flags = data->flags;
		__entry->IP_from = IP_from;
	),

	TP_printk("vcpu #%d\n"
		"lock %px flags: %s\n"
		"%s from %psx to run %psx\n",
		__entry->vcpu_id, __entry->lock,
		TRACE_PRINT_CSD_LOCK_FLAGS(__entry->flags),
		TRACE_PRINT_CSD_CTL(__entry->ctl),
		(void *)__entry->IP_from, (void *)__entry->func
	)
);

DEFINE_EVENT(kvm_csd_lock_class, kvm_csd_lock_wait,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl,
		 unsigned long IP_from),

	TP_ARGS(data, csd_ctl, IP_from)
);

DEFINE_EVENT(kvm_csd_lock_class, kvm_csd_lock_try_wait,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl,
		 unsigned long IP_from),

	TP_ARGS(data, csd_ctl, IP_from)
);

DEFINE_EVENT(kvm_csd_lock_class, kvm_csd_lock,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl,
		 unsigned long IP_from),

	TP_ARGS(data, csd_ctl, IP_from)
);

DEFINE_EVENT(kvm_csd_lock_class, kvm_csd_unlock,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl,
		 unsigned long IP_from),

	TP_ARGS(data, csd_ctl, IP_from)
);

TRACE_EVENT(
	kvm_csd_ctl_succeeded,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl),

	TP_ARGS(data, csd_ctl),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(csd_ctl_t, ctl)
		__field(unsigned int, flags)
	),

	TP_fast_assign(
		__entry->vcpu_id = smp_processor_id();
		__entry->lock = (void *)data;
		__entry->ctl = csd_ctl;
		__entry->flags = data->flags;
	),

	TP_printk("vcpu #%d\n"
		"lock %px flags: %s\n"
		"%s succeeded\n",
		__entry->vcpu_id, __entry->lock,
		TRACE_PRINT_CSD_LOCK_FLAGS(__entry->flags),
		TRACE_PRINT_CSD_CTL(__entry->ctl)
	)
);

TRACE_EVENT(
	kvm_csd_ctl_failed,

	TP_PROTO(call_single_data_t *data, csd_ctl_t csd_ctl, int error),

	TP_ARGS(data, csd_ctl, error),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(void *, lock)
		__field(csd_ctl_t, ctl)
		__field(unsigned int, flags)
		__field(int, error)
	),

	TP_fast_assign(
		__entry->vcpu_id = smp_processor_id();
		__entry->lock = (void *)data;
		__entry->ctl = csd_ctl;
		__entry->flags = data->flags;
		__entry->error = error;
	),

	TP_printk("vcpu #%d\n"
		"lock %px flags: %s\n"
		"%s failed %d\n",
		__entry->vcpu_id, __entry->lock,
		TRACE_PRINT_CSD_LOCK_FLAGS(__entry->flags),
		TRACE_PRINT_CSD_CTL(__entry->ctl),
		__entry->error
	)
);

#endif /* _KVM_GUEST_TRACE_CSD_LOCK_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../../arch/e2k/kvm/guest
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-csd-lock

/* This part must be outside protection */
#include <trace/define_trace.h>
