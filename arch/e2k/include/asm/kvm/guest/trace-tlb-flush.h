#if !defined(_KVM_GUEST_TRACE_TLB_FLUSH_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_GUEST_TRACE_TLB_FLUSH_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>

#include <asm/trace-defs.h>
#include <asm/trace_pgtable-v3.h>
#include <asm/trace_pgtable-v6.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/guest/trace-defs.h>
#include <asm/kvm/hypercall.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM guest

TRACE_EVENT(
	guest_flush_tlb_range(mm, opc, start, end),

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

	TP_printk("vcpu #%d gmm #%d flush TLB %s from %x to %px",
		__entry->vcpu_id, __entry->gmm_id,
		(__print_symbolic(__entry->opc,
			{ flush_all_tlb_op,		"all" },
			{ flush_mm_page_tlb_op,		"page" },
			{ flush_mm_range_tlb_op,	"mm range" },
			{ flush_mm_tlb_op,		"mm" },
			{ flush_pmd_range_tlb_op,	"pmd range" },
			{ flush_pt_range_tlb_op,	"page tables" },
			{ flush_kernel_range_tlb_op,	"kernel range" })),
		__entry->start, __entry->end
	)
);

TRACE_EVENT(
	guest_flush_tlb_failed(mm, opc, start, end, error),

	TP_PROTO(struct mm_struct *mm, mmu_flush_tlb_op_t opc,
			e2k_addr_t start, e2k_addr_t end, int eroor),

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

	TP_printk("vcpu #%d gmm #%d flush TLB %s from %x to %px failed %d",
		__entry->vcpu_id, __entry->gmm_id,
		(__print_symbolic(__entry->opc,
			{ flush_all_tlb_op,		"all" },
			{ flush_mm_page_tlb_op,		"page" },
			{ flush_mm_range_tlb_op,	"mm range" },
			{ flush_mm_tlb_op,		"mm" },
			{ flush_pmd_range_tlb_op,	"pmd range" },
			{ flush_pt_range_tlb_op,	"page tables" },
			{ flush_kernel_range_tlb_op,	"kernel range" })),
		__entry->start, __entry->end, __entry->error
	)
);

#endif /* _KVM_GUEST_TRACE_TLB_FLUSH_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../../arch/e2k/kvm/guest
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-flush

/* This part must be outside protection */
#include <trace/define_trace.h>
