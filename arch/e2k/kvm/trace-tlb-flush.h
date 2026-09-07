/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM host

#if !defined(_KVM_TRACE_TLB_FLUSH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_TRACE_TLB_FLUSH_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(
	host_flush_tlb,

	TP_PROTO(struct kvm_vcpu *vcpu),

	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(int, cpu_id)
		__field(int, vcpu_id)
	),

	TP_fast_assign(
		__entry->cpu_id = smp_processor_id();
		__entry->vcpu_id = vcpu->vcpu_id;
	),

	TP_printk("cpu #%d vcpu #%d tracing enabled",
		__entry->cpu_id, __entry->vcpu_id
	)
);

#endif /* _KVM_TRACE_TLB_FLUSH_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../../arch/e2k/kvm
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-flush

/* This part must be outside protection */
#include <trace/define_trace.h>
