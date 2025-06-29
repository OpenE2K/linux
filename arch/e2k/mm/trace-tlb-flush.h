/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM native

#if !defined(_MM_TRACE_TLB_FLUSH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _MM_TRACE_TLB_FLUSH_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(
	native_flush_tlb,

	TP_PROTO(int cpu_id),

	TP_ARGS(cpu_id),

	TP_STRUCT__entry(
		__field(int, cpu_id)
	),

	TP_fast_assign(
		__entry->cpu_id = cpu_id;
	),

	TP_printk("cpu #%d tracing enabled", __entry->cpu_id)
);

#endif /* _MM_TRACE_TLB_FLUSH_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../arch/e2k/mm
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-flush

/* This part must be outside protection */
#include <trace/define_trace.h>
