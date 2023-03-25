#if !defined(_TRACE_KVM_MMU_NOTIFIER_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_MMU_NOTIFIER_H

#include <linux/tracepoint.h>
#include <linux/trace_events.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM mmu_notifier


TRACE_EVENT(kvm_unmap_hva_range,
	TP_PROTO(struct kvm *kvm, unsigned long start, unsigned long end,
		 unsigned flags),
	TP_ARGS(kvm, start, end, flags),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned, flags)
		__field(long, seq)
		__field(long, count)
	),

	TP_fast_assign(
		__entry->start	= start;
		__entry->end	= end;
		__entry->flags	= flags;
		__entry->seq	= kvm->mmu_notifier_seq;
		__entry->count	= kvm->mmu_notifier_count;
	),

	TP_printk("mmu notifier unmap range: %lx - %lx, flags 0x%x\n"
		  "     notifier seq #%lx, count %ld",
		  __entry->start, __entry->end, __entry->flags,
		  __entry->seq, __entry->count)
);

TRACE_EVENT(kvm_unmap_hva_range_end,
	TP_PROTO(struct kvm *kvm, unsigned long start, unsigned long end,
		 unsigned flags),
	TP_ARGS(kvm, start, end, flags),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
		__field(unsigned, flags)
		__field(long, seq)
		__field(long, count)
	),

	TP_fast_assign(
		__entry->start	= start;
		__entry->end	= end;
		__entry->flags	= flags;
		__entry->seq	= kvm->mmu_notifier_seq;
		__entry->count	= kvm->mmu_notifier_count;
	),

	TP_printk("mmu notifier end of unmap range: %lx - %lx, flags 0x%x\n"
		  "     notifier seq #%lx, count %ld",
		  __entry->start, __entry->end, __entry->flags,
		  __entry->seq, __entry->count)
);

TRACE_EVENT(kvm_set_spte_hva,
	TP_PROTO(struct kvm *kvm, unsigned long hva, pte_t pte),
	TP_ARGS(kvm, hva, pte),

	TP_STRUCT__entry(
		__field(unsigned long, hva)
		__field(pteval_t, pte)
		__field(long, seq)
		__field(long, count)
	),

	TP_fast_assign(
		__entry->hva	= hva;
		__entry->pte	= pte_val(pte);
		__entry->seq	= kvm->mmu_notifier_seq;
		__entry->count	= kvm->mmu_notifier_count;
	),

	TP_printk("mmu notifier set pte hva: %lx, pte: 0x%lx\n"
		  "     notifier seq #%lx, count %ld",
		  __entry->hva, __entry->pte,
		  __entry->seq, __entry->count)
);

TRACE_EVENT(kvm_age_hva,
	TP_PROTO(unsigned long start, unsigned long end),
	TP_ARGS(start, end),

	TP_STRUCT__entry(
		__field(unsigned long, start)
		__field(unsigned long, end)
	),

	TP_fast_assign(
		__entry->start	= start;
		__entry->end	= end;
	),

	TP_printk("mmu notifier age hva: %lx - %lx",
		  __entry->start, __entry->end)
);

TRACE_EVENT(kvm_test_age_hva,
	TP_PROTO(unsigned long hva),
	TP_ARGS(hva),

	TP_STRUCT__entry(
		__field(unsigned long, hva)
	),

	TP_fast_assign(
		__entry->hva	= hva;
	),

	TP_printk("mmu notifier test age hva: %lx", __entry->hva)
);

#endif /* _TRACE_KVM_MMU_NOTIFIER_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE mmu-notifier-trace

/* This part must be outside protection */
#include <trace/define_trace.h>
