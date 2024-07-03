/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_pv

#if !defined(_TRACE_KVM_PV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_PV_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_types.h>
#include <asm/kvm/ptrace.h>
#include <asm/trace-defs.h>

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
		"Register: address=0x%02llx, vl=%lld, vr=%lld\n"
		"Opcode:  fmt=%lld, n_prot=%lld, fmtc=%lld\n"
		"Info1:   chan=%lld, mas=0x%02llx, miss_lvl=%lld, rcv=%lld, dst_rcv=0x%03llx\n"
		"Info2:   %s\n"
		"Ftype:   %s"
		,
		__entry->nr, __entry->address, __entry->data_tag,
		__entry->data_val, __entry->data_ext_tag, __entry->data_ext_val,
		E2K_TC_COND_ADDRESS(__entry->condition),
		E2K_TC_COND_VL(__entry->condition),
		E2K_TC_COND_VR(__entry->condition),
		E2K_TC_COND_FMT(__entry->condition),
		E2K_TC_COND_NPSP(__entry->condition),
		E2K_TC_COND_FMTC(__entry->condition),
		E2K_TC_COND_CHAN(__entry->condition),
		E2K_TC_COND_MAS(__entry->condition),
		E2K_TC_COND_MISS_LVL(__entry->condition),
		E2K_TC_COND_RCV(__entry->condition),
		E2K_TC_COND_DST_RCV(__entry->condition),
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
		__print_flags(E2K_TC_COND_FTYPE(__entry->condition), "|",
				{ E2K_FTYPE_GLOBAL_SP, "global_sp" },
				{ E2K_FTYPE_EXC_MEM_LOCK__ILLEGAL_SMPH,
						"exc_mem_lock.illegal_smph" },
				{ E2K_FTYPE_EXC_MEM_LOCK__MEM_LOCK,
						"exc_mem_lock.mem_lock" },
				{ E2K_FTYPE_PH_PR_PAGE, "ph_pr_page" },
				{ E2K_FTYPE_IO_PAGE, "io_page" },
				{ E2K_FTYPE_ISYS_PAGE, "isys_page" },
				{ E2K_FTYPE_PROT_PAGE, "prot_page" },
				{ E2K_FTYPE_PRIV_PAGE, "priv_page" },
				{ E2K_FTYPE_ILLEGAL_PAGE, "illegal_page" },
				{ E2K_FTYPE_NWRITE_PAGE, "nwrite_page" },
				{ E2K_FTYPE_PAGE_MISS, "page_miss" },
				{ E2K_FTYPE_PH_BOUND, "ph_bound" },
				{ E2K_FTYPE_INTL_RES_BITS, "intl_res_bits" }
			))
);

#define	kvm_trace_pv_symbol_inject_caller				\
	{ FROM_HOST_INJECT, "From host" },				\
	{ FROM_PV_VCPU_TRAP_INJECT, "From vcpu trap" },			\
	{ FROM_PV_VCPU_SYSCALL_INJECT, "From vcpu syscall" },		\
	{ FROM_PV_VCPU_SIGNAL_INJECT, "From vcpu signal inject" },	\
	{ FROM_PV_VCPU_SIGNAL_RETURN, "From vcpu signal return" }

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

TRACE_EVENT(
	pv_vcpu_fake_traps,

	TP_PROTO(struct kvm_vcpu *vcpu, int tirs_num, bool is_fake,
		 e2k_tir_lo_t tir_lo, e2k_tir_hi_t tir_hi, u64 traps_to_guest),

	TP_ARGS(vcpu, tirs_num, is_fake, tir_lo, tir_hi, traps_to_guest),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, tirs_num)
		__field(bool, is_fake)
		__field(u64, tir_lo)
		__field(u64, tir_hi)
		__field(u64, traps_to_guest)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->tirs_num = tirs_num;
		__entry->is_fake = is_fake;
		__entry->tir_lo = tir_lo.TIR_lo_reg;
		__entry->tir_hi = tir_hi.TIR_hi_reg;
		__entry->traps_to_guest = traps_to_guest;
	),

	TP_printk("vcpu #%d to inject %s trap\n"
		"     TIRs num %d, TIR.lo %016llx TIR.hi %016llx\n"
		"     to guest           %016llx\n",
		__entry->vcpu_id, (__entry->is_fake) ? "fake" : "not fake",
		__entry->tirs_num,
		__entry->tir_lo, __entry->tir_hi, __entry->traps_to_guest)

);

DECLARE_EVENT_CLASS(pv_save_resore_l_gregs_class,

	TP_PROTO(struct kvm_vcpu *vcpu, inject_caller_t from, local_gregs_t *l_gregs),

	TP_ARGS(vcpu, from, l_gregs),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(inject_caller_t, from)
		__field(u64, g16)
		__field(u64, g17)
		__field(u64, g18)
		__field(u64, g19)
		__field(u64, g20)
		__field(u64, g21)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->from = from;
		__entry->g16 = l_gregs->g[0].base;
		__entry->g17 = l_gregs->g[1].base;
		__entry->g18 = l_gregs->g[2].base;
		__entry->g19 = l_gregs->g[3].base;
		__entry->g20 = l_gregs->g[4].base;
		__entry->g21 = l_gregs->g[5].base;
	),

	TP_printk("vcpu #%d Injection %s\n"
		"     g16 : %016llx   g17 : %016llx\n"
		"     g18 : %016llx   g19 : %016llx\n"
		"     g20 : %016llx   g21 : %016llx\n",
		__entry->vcpu_id,
		__print_symbolic(__entry->from, kvm_trace_pv_symbol_inject_caller),
		__entry->g16, __entry->g17, __entry->g18, __entry->g19,
		__entry->g20, __entry->g21)

);

DEFINE_EVENT(pv_save_resore_l_gregs_class, pv_save_l_gregs,

	TP_PROTO(struct kvm_vcpu *vcpu, inject_caller_t from, local_gregs_t *l_gregs),

	TP_ARGS(vcpu, from, l_gregs)
);

DEFINE_EVENT(pv_save_resore_l_gregs_class, pv_restore_l_gregs,

	TP_PROTO(struct kvm_vcpu *vcpu, inject_caller_t from, local_gregs_t *l_gregs),

	TP_ARGS(vcpu, from, l_gregs)
);

DECLARE_EVENT_CLASS(vcpu_l_gregs_class,

	TP_PROTO(struct kvm_vcpu *vcpu),

	TP_ARGS(vcpu),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, gti_id)
		__field(vcpu_l_gregs_t *, vcpu_l_gregs)
		__field(bool, valid)
		__field(u64, updated)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->gti_id = pv_vcpu_get_gti(vcpu)->gpid->nid.nr;
		__entry->vcpu_l_gregs = &pv_vcpu_get_gti(vcpu)->l_gregs;
		__entry->valid = __entry->vcpu_l_gregs->valid;
		__entry->updated = __entry->vcpu_l_gregs->updated;
	),

	TP_printk("vcpu #%d vcpu gti #%d local gregs state\n"
		"     valid %d, updated %016llx\n",
		__entry->vcpu_id, __entry->gti_id,
		__entry->valid, __entry->updated)

);

DEFINE_EVENT(vcpu_l_gregs_class, empty_vcpu_l_gregs,

	TP_PROTO(struct kvm_vcpu *vcpu),

	TP_ARGS(vcpu)
);

DEFINE_EVENT(vcpu_l_gregs_class, active_vcpu_l_gregs,

	TP_PROTO(struct kvm_vcpu *vcpu),

	TP_ARGS(vcpu)
);

TRACE_EVENT(update_vcpu_l_gregs,

	TP_PROTO(struct kvm_vcpu *vcpu, int greg_no, u64 old_greg, u64 new_greg),

	TP_ARGS(vcpu, greg_no, old_greg, new_greg),

	TP_STRUCT__entry(
		__field(int, vcpu_id)
		__field(int, greg_no)
		__field(u64, old_greg)
		__field(u64, new_greg)
	),

	TP_fast_assign(
		__entry->vcpu_id = vcpu->vcpu_id;
		__entry->greg_no = greg_no;
		__entry->old_greg = old_greg;
		__entry->new_greg = new_greg;
	),

	TP_printk("vcpu #%d upadate local greg\n"
		"     g%d : from %016llx to %016llx\n",
		__entry->vcpu_id, __entry->greg_no,
		__entry->old_greg, __entry->new_greg)

);

#endif /* _TRACE_KVM_PV_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_kvm_pv
#include <trace/define_trace.h>
