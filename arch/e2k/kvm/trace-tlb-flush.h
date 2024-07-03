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

TRACE_EVENT(
	host_flush_tlb_range,

	TP_PROTO(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		 mmu_flush_tlb_op_t opc, e2k_addr_t start, e2k_addr_t end),

	TP_ARGS(vcpu, gmm, opc, start, end),

	TP_STRUCT__entry(
		__field(int, cpu_id)
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(mmu_flush_tlb_op_t, opc)
		__field(e2k_addr_t, start)
		__field(e2k_addr_t, end)
	),

	TP_fast_assign(
		__entry->cpu_id = smp_processor_id();
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = (gmm != NULL) ? gmm->nid.nr : -2;
		__entry->opc = opc;
		__entry->start = start;
		__entry->end = end;
	),

	TP_printk("cpu #%d vcpu #%d gmm #%d flush TLB %s from %px to %px",
		__entry->cpu_id, __entry->vcpu_id, __entry->gmm_id,
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
	host_flush_tlb_failed,

	TP_PROTO(struct kvm_vcpu *vcpu, gmm_struct_t *gmm,
		 mmu_flush_tlb_op_t opc, e2k_addr_t start, e2k_addr_t end,
		 int error),

	TP_ARGS(vcpu, gmm, opc, start, end, error),

	TP_STRUCT__entry(
		__field(int, cpu_id)
		__field(int, vcpu_id)
		__field(int, gmm_id)
		__field(mmu_flush_tlb_op_t, opc)
		__field(e2k_addr_t, start)
		__field(e2k_addr_t, end)
		__field(int, error)
	),

	TP_fast_assign(
		__entry->cpu_id = smp_processor_id();
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = (gmm != NULL) ? gmm->nid.nr : -2;
		__entry->opc = opc;
		__entry->start = start;
		__entry->end = end;
		__entry->error = error;
	),

	TP_printk("cpu #%d vcpu #%d gmm #%d flush TLB %s from %px to %px failed %d",
		__entry->cpu_id, __entry->vcpu_id, __entry->gmm_id,
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

TRACE_EVENT(
	gva_tlb_state,

	TP_PROTO(struct kvm_vcpu *vcpu, gmm_struct_t *gmm, e2k_addr_t address),

	TP_ARGS(vcpu, gmm, address),

	TP_STRUCT__entry(
		__field(	int,			cpu_id		)
		__field(	int,			vcpu_id		)
		__field(	int,			gmm_id		)
		__field(	e2k_addr_t,		address		)
		__field_struct(	tlb_line_state_t,	line		)
		__field_struct(	tlb_line_state_t,	huge_line	)
		__field(	hpa_t,			spt_root	)
		__field(	gpa_t,			guest_root	)
		__field(	unsigned long,		mmu_pid		)
	),

	TP_fast_assign(
		__entry->cpu_id = raw_smp_processor_id();
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gmm_id = (gmm != NULL) ? gmm->nid.nr : -2;
		__entry->spt_root = gmm->root_hpa;
		__entry->guest_root = gmm->u_pptb;
		__entry->address = address;
		get_va_tlb_state(&__entry->line, address, false);
		get_va_tlb_state(&__entry->huge_line, address, true);
		__entry->mmu_pid = gmm->context.cpumsk[__entry->cpu_id];
	),

	TP_printk("cpu #%d vcpu #%d gmm #%d gva 0x%016lx "
		"root: spt 0x%llx guest 0x%llx pid 0x%lx\n"
		"                        TLB set #0 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #1 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #2 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #3 tag 0x%016lx entry 0x%016lx\n"
		"                huge    TLB set #2 tag 0x%016lx entry 0x%016lx\n"
		"                huge    TLB set #3 tag 0x%016lx entry 0x%016lx",
		__entry->cpu_id, __entry->vcpu_id,
		__entry->gmm_id, __entry->address,
		__entry->spt_root, __entry->guest_root, __entry->mmu_pid,
		__entry->line.sets[0].tlb_tag,
		pte_val(__entry->line.sets[0].tlb_entry),
		__entry->line.sets[1].tlb_tag,
		pte_val(__entry->line.sets[1].tlb_entry),
		__entry->line.sets[2].tlb_tag,
		pte_val(__entry->line.sets[2].tlb_entry),
		__entry->line.sets[3].tlb_tag,
		pte_val(__entry->line.sets[3].tlb_entry),
		__entry->huge_line.sets[2].tlb_tag,
		pte_val(__entry->huge_line.sets[2].tlb_entry),
		__entry->huge_line.sets[3].tlb_tag,
		pte_val(__entry->huge_line.sets[3].tlb_entry)
	)
);

#endif /* _KVM_TRACE_TLB_FLUSH_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../arch/e2k/kvm
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-flush

/* This part must be outside protection */
#include <trace/define_trace.h>
