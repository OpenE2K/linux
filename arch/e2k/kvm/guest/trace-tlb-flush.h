/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#undef TRACE_SYSTEM
#define TRACE_SYSTEM guest

#if !defined(_KVM_GUEST_TRACE_TLB_FLUSH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_GUEST_TRACE_TLB_FLUSH_H

#include <linux/types.h>
#include <linux/tracepoint.h>

TRACE_EVENT(
	guest_flush_tlb_range,

	TP_PROTO(struct mm_struct *mm, mmu_flush_tlb_op_t opc,
			e2k_addr_t start, e2k_addr_t end),

	TP_ARGS(mm, opc, start, end),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(mmu_flush_tlb_op_t, opc)
		__field(e2k_addr_t, start)
		__field(e2k_addr_t, end)
	),

	TP_fast_assign(
		__entry->vcpu_id = smp_processor_id();
		__entry->gmm_id = (mm != NULL) ? mm->gmmid_nr : -2;
		__entry->opc = opc;
		__entry->start = start;
		__entry->end = end;
	),

	TP_printk("vcpu #%d gmm #%d flush TLB %s from %px to %px",
		__entry->vcpu_id, __entry->gmm_id,
		(__print_symbolic(__entry->opc,
			{ flush_all_tlb_op,		"all" },
			{ flush_mm_page_tlb_op,		"page" },
			{ flush_mm_range_tlb_op,	"mm range" },
			{ flush_mm_tlb_op,		"mm" },
			{ flush_pmd_range_tlb_op,	"pmd range" },
			{ flush_pt_range_tlb_op,	"page tables" },
			{ flush_kernel_range_tlb_op,	"kernel range" })),
		(void *)__entry->start, (void *)__entry->end
	)
);

TRACE_EVENT(
	guest_flush_tlb_failed,

	TP_PROTO(struct mm_struct *mm, mmu_flush_tlb_op_t opc,
			e2k_addr_t start, e2k_addr_t end, int error),

	TP_ARGS(mm, opc, start, end, error),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(mmu_flush_tlb_op_t, opc)
		__field(e2k_addr_t, start)
		__field(e2k_addr_t, end)
		__field(int, error)
	),

	TP_fast_assign(
		__entry->vcpu_id = smp_processor_id();
		__entry->gmm_id = (mm != NULL) ? mm->gmmid_nr : -2;
		__entry->opc = opc;
		__entry->start = start;
		__entry->end = end;
		__entry->error = error;
	),

	TP_printk("vcpu #%d gmm #%d flush TLB %s from %px to %px failed %d",
		__entry->vcpu_id, __entry->gmm_id,
		(__print_symbolic(__entry->opc,
			{ flush_all_tlb_op,		"all" },
			{ flush_mm_page_tlb_op,		"page" },
			{ flush_mm_range_tlb_op,	"mm range" },
			{ flush_mm_tlb_op,		"mm" },
			{ flush_pmd_range_tlb_op,	"pmd range" },
			{ flush_pt_range_tlb_op,	"page tables" },
			{ flush_kernel_range_tlb_op,	"kernel range" })),
		(void *)__entry->start, (void *)__entry->end, __entry->error
	)
);

#endif /* _KVM_GUEST_TRACE_TLB_FLUSH_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../../arch/e2k/kvm/guest
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-flush

/* This part must be outside protection */
#include <trace/define_trace.h>
