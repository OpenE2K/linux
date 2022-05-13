#if !defined(_KVM_GUEST_TRACE_TLB_STATE_H) || defined(TRACE_HEADER_MULTI_READ)
#define _KVM_GUEST_TRACE_TLB_STATE_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>

#include <asm/trace-defs.h>
#include <asm/trace_pgtable-v3.h>
#include <asm/trace_pgtable-v6.h>
#include <asm/pgtable_def.h>

TRACE_EVENT(
	guest_va_tlb_state,

	TP_PROTO(e2k_addr_t address),

	TP_ARGS(address),

	TP_STRUCT__entry(
		__field(	e2k_addr_t,		address		)
		__field(	tlb_tag_t,		set0_tag	)
		__field_struct(	pte_t,			set0_entry	)
		__field(	tlb_tag_t,		set1_tag	)
		__field_struct(	pte_t,			set1_entry	)
		__field(	tlb_tag_t,		set2_tag	)
		__field_struct(	pte_t,			set2_entry	)
		__field(	tlb_tag_t,		set3_tag	)
		__field_struct(	pte_t,			set3_entry	)
		__field(	tlb_tag_t,		setH_tag	)
		__field_struct(	pte_t,			setH_entry	)
		__field(	u64,			dtlb_entry	)
		__field(	unsigned long,		mmu_pptb	)
		__field(	unsigned long,		mmu_pid		)
	),

	TP_fast_assign(
		__entry->address = address;
		__entry->set0_tag = HYPERVISOR_get_tlb_set_tag(address, 0, false);
		pte_val(__entry->set0_entry) =
			HYPERVISOR_get_tlb_set_entry(address, 0, false);
		__entry->set1_tag = HYPERVISOR_get_tlb_set_tag(address, 1, false);
		pte_val(__entry->set1_entry) =
			HYPERVISOR_get_tlb_set_entry(address, 1, false);
		__entry->set2_tag = HYPERVISOR_get_tlb_set_tag(address, 2, false);
		pte_val(__entry->set2_entry) =
			HYPERVISOR_get_tlb_set_entry(address, 2, false);
		__entry->set3_tag = HYPERVISOR_get_tlb_set_tag(address, 3, false);
		pte_val(__entry->set3_entry) =
			HYPERVISOR_get_tlb_set_entry(address, 3, false);
		__entry->setH_tag = HYPERVISOR_get_tlb_set_tag(address, 3, true);
		pte_val(__entry->setH_entry) =
			HYPERVISOR_get_tlb_set_entry(address, 3, true);
		__entry->dtlb_entry = HYPERVISOR_mmu_probe(address,
							KVM_MMU_PROBE_ENTRY);
		__entry->mmu_pptb = HYPERVISOR_get_host_mmu_pptb();
		__entry->mmu_pid = HYPERVISOR_get_host_mmu_pid();
	),

	TP_printk("   0x%016lx : dtlb 0x%016llx U_PPTB 0x%lx PID 0x%lx\n"
		"                        TLB set #0 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #1 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #2 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #3 tag 0x%016lx entry 0x%016lx\n"
		"                        TLB set #H tag 0x%016lx entry 0x%016lx",
		__entry->address, __entry->dtlb_entry,
		__entry->mmu_pptb, __entry->mmu_pid,
		__entry->set0_tag, pte_val(__entry->set0_entry),
		__entry->set1_tag, pte_val(__entry->set1_entry),
		__entry->set2_tag, pte_val(__entry->set2_entry),
		__entry->set3_tag, pte_val(__entry->set3_entry),
		__entry->setH_tag, pte_val(__entry->setH_entry)
	)
);

#endif /* _KVM_GUEST_TRACE_TLB_STATE_H */

#undef	TRACE_INCLUDE_PATH
#define	TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm/guest
#undef	TRACE_INCLUDE_FILE
#define	TRACE_INCLUDE_FILE trace-tlb-state

/* This part must be outside protection */
#include <trace/define_trace.h>
