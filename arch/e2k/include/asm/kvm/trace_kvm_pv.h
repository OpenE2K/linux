#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_pv

#if !defined(_TRACE_KVM_PV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_PV_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_types.h>
#include <asm/kvm/ptrace.h>

#define E2K_TC_TYPE_STORE	(1ULL << 17)
#define E2K_TC_TYPE_S_F		(1ULL << 19)
#define E2K_TC_TYPE_ROOT	(1ULL << 27)
#define E2K_TC_TYPE_SCAL	(1ULL << 28)
#define E2K_TC_TYPE_SRU		(1ULL << 29)
#define E2K_TC_TYPE_SPEC	(1ULL << 30)
#define E2K_TC_TYPE_PM		(1ULL << 31)
#define E2K_TC_TYPE_NUM_ALIGN	(1ULL << 50)
#define E2K_TC_TYPE_EMPT	(1ULL << 51)
#define E2K_TC_TYPE_CLW		(1ULL << 52)

#define E2K_TC_TYPE (E2K_TC_TYPE_STORE | E2K_TC_TYPE_S_F | E2K_TC_TYPE_ROOT | \
		     E2K_TC_TYPE_SCAL | E2K_TC_TYPE_SRU | E2K_TC_TYPE_SPEC | \
		     E2K_TC_TYPE_PM | E2K_TC_TYPE_NUM_ALIGN | \
		     E2K_TC_TYPE_EMPT | E2K_TC_TYPE_CLW)

#define E2K_FAULT_TYPE_GLOBAL_SP	(1ULL << 0)
#define E2K_FAULT_TYPE_EXC_MEM_LOCK__ILLEGAL_SMPH (1ULL << 1)
#define E2K_FAULT_TYPE_EXC_MEM_LOCK__MEM_LOCK	  (1ULL << 2)
#define E2K_FAULT_TYPE_PH_PR_PAGE	(1ULL << 3)
#define E2K_FAULT_TYPE_IO_PAGE		(1ULL << 4)
#define E2K_FAULT_TYPE_ISYS_PAGE	(1ULL << 5)
#define E2K_FAULT_TYPE_PROT_PAGE	(1ULL << 6)
#define E2K_FAULT_TYPE_PRIV_PAGE	(1ULL << 7)
#define E2K_FAULT_TYPE_ILLEGAL_PAGE	(1ULL << 8)
#define E2K_FAULT_TYPE_NWRITE_PAGE	(1ULL << 9)
#define E2K_FAULT_TYPE_PAGE_MISS	(1ULL << 10)
#define E2K_FAULT_TYPE_PH_BOUND		(1ULL << 11)
#define E2K_FAULT_TYPE_INTL_RES_BITS	(1ULL << 12)

TRACE_EVENT(
	intc_trap_cellar,

	TP_PROTO(const trap_cellar_t *tc, int nr),

	TP_ARGS(tc, nr),

	TP_STRUCT__entry(
		__field(	int,	nr		)
		__field(	u64,	address		)
		__field(	u64,	data_val	)
		__field(	u64,	data_ext_val	)
		__field(	u8,	data_tag	)
		__field(	u8,	data_ext_tag	)
		__field(	u64,	condition	)
		__field(	u64,	mask		)
	),

	TP_fast_assign(
		__entry->nr = nr;
		__entry->address = tc->address;
		load_value_and_tagd(&tc->data,
				&__entry->data_val, &__entry->data_tag);
		load_value_and_tagd(&tc->data_ext,
				&__entry->data_ext_val, &__entry->data_ext_tag);
		__entry->condition = AW(tc->condition);
		__entry->mask = AW(tc->mask);
	),

	TP_printk("\n"
		"Entry %d: address 0x%llx   data %hhx 0x%llx   data_ext %hhx 0x%llx\n"
		"Register: address=0x%02hhx, vl=%d, vr=%d\n"
		"Opcode:  fmt=%d, n_prot=%d, fmtc=%d\n"
		"Info1:   chan=%d, mas=0x%02hhx, miss_lvl=%d, rcv=%d, dst_rcv=0x%03x\n"
		"Info2:   %s\n"
		"Ftype:   %s"
		,
		__entry->nr, __entry->address, __entry->data_tag,
		__entry->data_val, __entry->data_ext_tag, __entry->data_ext_val,
		AS((tc_cond_t) __entry->condition).address,
		AS((tc_cond_t) __entry->condition).vl,
		AS((tc_cond_t) __entry->condition).vr,
		AS((tc_cond_t) __entry->condition).fmt,
		AS((tc_cond_t) __entry->condition).npsp,
		AS((tc_cond_t) __entry->condition).fmtc,
		AS((tc_cond_t) __entry->condition).chan,
		AS((tc_cond_t) __entry->condition).mas,
		AS((tc_cond_t) __entry->condition).miss_lvl,
		AS((tc_cond_t) __entry->condition).rcv,
		AS((tc_cond_t) __entry->condition).dst_rcv,
		__print_flags(__entry->condition & E2K_TC_TYPE, "|",
				{ E2K_TC_TYPE_STORE, "store" },
				{ E2K_TC_TYPE_S_F, "s_f" },
				{ E2K_TC_TYPE_ROOT, "root" },
				{ E2K_TC_TYPE_SCAL, "scal" },
				{ E2K_TC_TYPE_SRU, "sru" },
				{ E2K_TC_TYPE_SPEC, "spec" },
				{ E2K_TC_TYPE_PM, "pm" },
				{ E2K_TC_TYPE_NUM_ALIGN, "num_align" },
				{ E2K_TC_TYPE_EMPT, "empt" },
				{ E2K_TC_TYPE_CLW, "clw" }
			),
		__print_flags(AS((tc_cond_t) __entry->condition).fault_type, "|",
				{ E2K_FAULT_TYPE_GLOBAL_SP, "global_sp" },
				{ E2K_FAULT_TYPE_EXC_MEM_LOCK__ILLEGAL_SMPH,
						"exc_mem_lock.illegal_smph" },
				{ E2K_FAULT_TYPE_EXC_MEM_LOCK__MEM_LOCK,
						"exc_mem_lock.mem_lock" },
				{ E2K_FAULT_TYPE_PH_PR_PAGE, "ph_pr_page" },
				{ E2K_FAULT_TYPE_IO_PAGE, "io_page" },
				{ E2K_FAULT_TYPE_ISYS_PAGE, "isys_page" },
				{ E2K_FAULT_TYPE_PROT_PAGE, "prot_page" },
				{ E2K_FAULT_TYPE_PRIV_PAGE, "priv_page" },
				{ E2K_FAULT_TYPE_ILLEGAL_PAGE, "illegal_page" },
				{ E2K_FAULT_TYPE_NWRITE_PAGE, "nwrite_page" },
				{ E2K_FAULT_TYPE_PAGE_MISS, "page_miss" },
				{ E2K_FAULT_TYPE_PH_BOUND, "ph_bound" },
				{ E2K_FAULT_TYPE_INTL_RES_BITS, "intl_res_bits" }
			))
);

#define	kvm_trace_pv_symbol_inject_caller				\
	{ FROM_HOST_INJECT, "From host" },				\
	{ FROM_PV_VCPU_TRAP_INJECT, "From VCPU trap" },			\
	{ FROM_PV_VCPU_SYSCALL_INJECT, "From VCPU syscall" }

TRACE_EVENT(
	pv_injection,

	TP_PROTO(inject_caller_t from, const e2k_stacks_t *stacks, const e2k_mem_crs_t *crs,
		int traps_num, int syscall_num),

	TP_ARGS(from, stacks, crs, traps_num, syscall_num),

	TP_STRUCT__entry(
		__field(	int,	from		)
		/* Stacks */
		__field(	unsigned long,	u_top	)
		__field(	u64,	u_usd_lo	)
		__field(	u64,	u_usd_hi	)
		__field(	unsigned long,	top	)
		__field(	u64,	usd_lo	)
		__field(	u64,	usd_hi	)
		__field(	u64,	psp_lo	)
		__field(	u64,	psp_hi	)
		__field(	u64,	pcsp_lo	)
		__field(	u64,	pcsp_hi	)
		__field(	u64,	pshtp	)
		__field(	unsigned int,	pcshtp	)
		/* CRs */
		__field(	u64,	cr0_lo	)
		__field(	u64,	cr0_hi	)
		__field(	u64,	cr1_lo	)
		__field(	u64,	cr1_hi	)
		/* Recursion level */
		__field(	int,	traps_num	)
		__field(	int,	syscall_num	)
	),

	TP_fast_assign(
		__entry->from = from;
		__entry->u_top = stacks->u_top;
		__entry->u_usd_lo = AW(stacks->u_usd_lo);
		__entry->u_usd_hi = AW(stacks->u_usd_hi);
		__entry->top = stacks->top;
		__entry->usd_lo = AW(stacks->usd_lo);
		__entry->usd_hi = AW(stacks->usd_hi);
		__entry->psp_lo = AW(stacks->psp_lo);
		__entry->psp_hi = AW(stacks->psp_hi);
		__entry->pcsp_lo = AW(stacks->pcsp_lo);
		__entry->pcsp_hi = AW(stacks->pcsp_hi);
		__entry->pshtp = AW(stacks->pshtp);
		__entry->pcshtp = stacks->pcshtp;
		__entry->cr0_lo = AW(crs->cr0_lo);
		__entry->cr0_hi = AW(crs->cr0_hi);
		__entry->cr1_lo = AW(crs->cr1_lo);
		__entry->cr1_hi = AW(crs->cr1_hi);
		__entry->traps_num = traps_num;
		__entry->syscall_num = syscall_num;
	),

	TP_printk("\n"
		"%s. traps_num %d, syscall_num %d. Stacks:\n"
		"u_top 0x%lx, u_usd_lo 0x%llx, u_usd_hi 0x%llx\n"
		"top 0x%lx, usd_lo 0x%llx, usd_hi 0x%llx\n"
		"psp_lo 0x%llx, psp_hi 0x%llx, pcsp_lo 0x%llx, pcsp_hi 0x%llx\n"
		"pshtp 0x%llx, pcshtp 0x%x\n"
		"cr0_lo 0x%llx, cr0_hi 0x%llx, cr1_lo 0x%llx, cr1_hi 0x%llx\n"
		,
		__print_symbolic(__entry->from, kvm_trace_pv_symbol_inject_caller),
		__entry->traps_num, __entry->syscall_num,
		__entry->u_top, __entry->u_usd_lo, __entry->u_usd_hi,
		__entry->top, __entry->usd_lo, __entry->usd_hi,
		__entry->psp_lo, __entry->psp_hi, __entry->pcsp_lo, __entry->pcsp_hi,
		__entry->pshtp, __entry->pcshtp,
		__entry->cr0_lo, __entry->cr0_hi, __entry->cr1_lo, __entry->cr1_hi)

);

#endif /* _TRACE_KVM_PV_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_kvm_pv
#include <trace/define_trace.h>
