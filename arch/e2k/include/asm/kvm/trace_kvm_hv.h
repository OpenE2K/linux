#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_hv

#if !defined(_TRACE_KVM_HV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_HV_H

#include <linux/tracepoint.h>
#include <asm/kvm_host.h>
#include <asm/mmu_types.h>

#define E2K_TRACE_PRINT_CU_HDR_LO(entry) \
	__print_flags(entry, "|", \
		{ intc_cu_hdr_lo_rr_idr_mask, "rr_idr" }, \
		{ intc_cu_hdr_lo_rr_clkr_mask, "rr_clkr" }, \
		{ intc_cu_hdr_lo_rr_sclkr_mask, "rr_sclkr" }, \
		{ intc_cu_hdr_lo_rr_dbg_mask, "rr_dbg" }, \
		{ intc_cu_hdr_lo_rw_core_mode_mask, "rw_core_mode" }, \
		{ intc_cu_hdr_lo_rw_clkr_mask, "rw_clkr" }, \
		{ intc_cu_hdr_lo_rw_sclkr_mask, "rw_sclkr" }, \
		{ intc_cu_hdr_lo_rw_sclkm3_mask, "rw_sclkm3" }, \
		{ intc_cu_hdr_lo_rw_dbg_mask, "rw_dbg" }, \
		{ intc_cu_hdr_lo_hcem_mask, "hcem" }, \
		{ intc_cu_hdr_lo_virt_mask, "virt" }, \
		{ intc_cu_hdr_lo_stop_mask, "stop" }, \
		{ intc_cu_hdr_lo_hret_last_wish_mask, "hret_last_wish" }, \
		{ intc_cu_hdr_lo_exc_instr_debug_mask, "exc_instr_debug" }, \
		{ intc_cu_hdr_lo_exc_data_debug_mask, "exc_data_debug" }, \
		{ intc_cu_hdr_lo_exc_instr_page_mask, "exc_instr_page" }, \
		{ intc_cu_hdr_lo_exc_data_page_mask, "exc_data_page" }, \
		{ intc_cu_hdr_lo_exc_mova_mask, "exc_mova" }, \
		{ intc_cu_hdr_lo_exc_interrupt_mask, "exc_interrupt" }, \
		{ intc_cu_hdr_lo_exc_nm_interrupt_mask, "exc_nm_interrupt" }, \
		{ intc_cu_hdr_lo_hv_int_mask, "hv_int" }, \
		{ intc_cu_hdr_lo_hv_nm_int_mask, "hv_nm_int" }, \
		{ intc_cu_hdr_lo_g_tmr_mask, "g_tmr" }, \
		{ intc_cu_hdr_lo_rr_mask, "rr" }, \
		{ intc_cu_hdr_lo_rw_mask, "rw" }, \
		{ intc_cu_hdr_lo_exc_mem_error_mask, "exc_mem_error" }, \
		{ intc_cu_hdr_lo_wait_trap_mask, "wait_trap" }, \
		{ intc_cu_hdr_lo_dbg_mask, "dbg" }, \
		{ intc_cu_hdr_lo_tir_fz_mask, "tir_fz" })

#define E2K_TRACE_PRINT_CU_INFO_LO(entry) \
	__print_symbolic(intc_cu_info_lo_get_event_code(entry), \
		{ ICE_FORCED, "FORCED" }, \
		{ ICE_READ_CU, "READ_CU" }, \
		{ ICE_WRITE_CU, "WRITE_CU" }, \
		{ ICE_MASKED_HCALL, "MASKED_HCALL" })

#define E2K_TRACE_PRINT_MU_INFO_HDR(entry) \
	__print_symbolic(intc_mu_info_lo_get_event_code(entry), \
		{ IME_FORCED, "FORCED" }, \
		{ IME_FORCED_GVA, "FORCED_GVA" }, \
		{ IME_SHADOW_DATA, "SHADOW_DATA" }, \
		{ IME_GPA_DATA, "GPA_DATA" }, \
		{ IME_GPA_INSTR, "GPA_INSTR" }, \
		{ IME_GPA_AINSTR, "GPA_AINSTR" }, \
		{ IME_MAS_IOADDR, "MAS_IOADDR" }, \
		{ IME_READ_MU, "READ_MU" }, \
		{ IME_WRITE_MU, "WRITE_MU" }, \
		{ IME_CACHE_FLUSH, "CACHE_FLUSH" }, \
		{ IME_CACHE_LINE_FLUSH, "CACHE_LINE_FLUSH" }, \
		{ IME_ICACHE_FLUSH, "ICACHE_FLUSH" }, \
		{ IME_ICACHE_LINE_FLUSH_USER, "ICACHE_LINE_FLUSH_USER" }, \
		{ IME_ICACHE_LINE_FLUSH_SYSTEM, "ICACHE_LINE_FLUSH_SYSTEM" }, \
		{ IME_TLB_FLUSH, "TLB_FLUSH" }, \
		{ IME_TLB_PAGE_FLUSH_LAST, "TLB_PAGE_FLUSH_LAST" }, \
		{ IME_TLB_PAGE_FLUSH_UPPER, "TLB_PAGE_FLUSH_UPPER" }, \
		{ IME_TLB_ENTRY_PROBE, "TLB_ENTRY_PROBE" })

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
	cu_intc,

	TP_PROTO(const intc_info_cu_t *cu, int num),

	TP_ARGS(cu, num),

	TP_STRUCT__entry(
		__field(	int,	num )
		__field(	u64,	cu_lo )
		__field(	u64,	cu_hi )
	),

	TP_fast_assign(
		__entry->cu_lo = !num ? AW(cu->header.lo) : AW(cu->entry[num - 1].lo);
		__entry->cu_hi = !num ? AW(cu->header.hi) : cu->entry[num - 1].hi;
		__entry->num = num;
	),

	TP_printk("CU %s: %s (lo 0x%llx   hi 0x%llx)",
		(!__entry->num) ? "header" : "entry",
		(!__entry->num) ? E2K_TRACE_PRINT_CU_HDR_LO(__entry->cu_lo) :
				E2K_TRACE_PRINT_CU_INFO_LO(__entry->cu_lo),
		__entry->cu_lo, __entry->cu_hi)
);

TRACE_EVENT(
	mu_intc,

	TP_PROTO(const intc_info_mu_t *mu, int num),

	TP_ARGS(mu, num),

	TP_STRUCT__entry(
		__field(	int,	num		)
		__field(	u64,	header		)
		__field(	u64,	gpa		)
		__field(	u64,	gva		)
		__field(	u64,	data_val	)
		__field(	u64,	data_ext_val	)
		__field(	u8,	data_tag	)
		__field(	u8,	data_ext_tag	)
		__field(	u64,	condition	)
		__field(	u64,	mask		)
	),

	TP_fast_assign(
		__entry->num = num;
		__entry->header = AW(mu[0].hdr);
		__entry->gpa = mu[0].gpa;
		__entry->gva = mu[0].gva;
		load_value_and_tagd(&mu[0].data, &__entry->data_val,
						&__entry->data_tag);
		load_value_and_tagd(&mu[0].data_ext, &__entry->data_ext_val,
						&__entry->data_ext_tag);
		__entry->condition = AW(mu[0].condition);
		__entry->mask = AW(mu[0].mask);
	),

	TP_printk("\n"
		"MU entry %d: header %s   gva 0x%llx   gpa 0x%llx\n"
		"data %hhx 0x%llx   data_ext %hhx 0x%llx\n"
		"condition 0x%llx   mask 0x%llx\n"
		"Register: address=0x%02hhx, vl=%d, vr=%d\n"
		"Opcode:  fmt=%d, n_prot=%d, fmtc=%d\n"
		"Info1:   chan=%d, mas=0x%02hhx, miss_lvl=%d, rcv=%d, dst_rcv=0x%03x\n"
		"Info2:   %s\n"
		"Ftype:   %s",
		__entry->num,
		E2K_TRACE_PRINT_MU_INFO_HDR(__entry->header), __entry->gva, __entry->gpa,
		__entry->data_tag, __entry->data_val, __entry->data_ext_tag, __entry->data_ext_val,
		__entry->condition, __entry->mask,
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

TRACE_EVENT(
	intc_stacks,

	TP_PROTO(const kvm_sw_cpu_context_t *sw_ctxt, const kvm_hw_cpu_context_t *hw_ctxt,
		 const e2k_mem_crs_t *crs),

	TP_ARGS(sw_ctxt, hw_ctxt, crs),

	TP_STRUCT__entry(
		/* Stacks */
		__field(	u64,	sbr	)
		__field(	u64,	usd_lo	)
		__field(	u64,	usd_hi	)
		__field(	u64,	psp_lo	)
		__field(	u64,	psp_hi	)
		__field(	u64,	pcsp_lo	)
		__field(	u64,	pcsp_hi	)
		__field(	u64,	pshtp	)
		__field(	unsigned int,	pcshtp	)
		/* Backup stacks */
		__dynamic_array(u64, frames, hw_ctxt->bu_pcsp_hi.ind / SZ_OF_CR)
		__field(size_t, frames_len)
		__field(	u64,	bu_psp_lo	)
		__field(	u64,	bu_psp_hi	)
		__field(	u64,	bu_pcsp_lo	)
		__field(	u64,	bu_pcsp_hi	)
		/* CRs */
		__field(	u64,	cr0_lo	)
		__field(	u64,	cr0_hi	)
		__field(	u64,	cr1_lo	)
		__field(	u64,	cr1_hi	)
	),

	TP_fast_assign(
		u64 *frames = __get_dynamic_array(frames);
		e2k_mem_crs_t *chain_stack = (e2k_mem_crs_t *) hw_ctxt->bu_pcsp_lo.base;
		size_t len = hw_ctxt->bu_pcsp_hi.ind / SZ_OF_CR;
		unsigned long i;

		__entry->frames_len = len;
		for (i = 0; i < len; i++)
			frames[i] = chain_stack[i].cr0_hi.ip << 3;

		__entry->sbr = AW(sw_ctxt->sbr);
		__entry->usd_lo = AW(sw_ctxt->usd_lo);
		__entry->usd_hi = AW(sw_ctxt->usd_hi);
		__entry->psp_lo = AW(hw_ctxt->sh_psp_lo);
		__entry->psp_hi = AW(hw_ctxt->sh_psp_hi);
		__entry->pcsp_lo = AW(hw_ctxt->sh_pcsp_lo);
		__entry->pcsp_hi = AW(hw_ctxt->sh_pcsp_hi);
		__entry->pshtp = AW(hw_ctxt->sh_pshtp);
		__entry->pcshtp = hw_ctxt->sh_pcshtp;
		__entry->cr0_lo = AW(crs->cr0_lo);
		__entry->cr0_hi = AW(crs->cr0_hi);
		__entry->cr1_lo = AW(crs->cr1_lo);
		__entry->cr1_hi = AW(crs->cr1_hi);
		__entry->bu_psp_lo = AW(hw_ctxt->bu_psp_lo);
		__entry->bu_psp_hi = AW(hw_ctxt->bu_psp_hi);
		__entry->bu_pcsp_lo = AW(hw_ctxt->bu_pcsp_lo);
		__entry->bu_pcsp_hi = AW(hw_ctxt->bu_pcsp_hi);
	),

	TP_printk("\n"
		"sbr 0x%llx, usd_lo 0x%llx, usd_hi 0x%llx\n"
		"sh_psp_lo 0x%llx, sh_psp_hi 0x%llx, sh_pshtp 0x%llx\n"
		"sh_pcsp_lo 0x%llx, sh_pcsp_hi 0x%llx, sh_pcshtp 0x%x\n"
		"cr0_lo 0x%llx, cr0_hi 0x%llx, cr1_lo 0x%llx, cr1_hi 0x%llx\n"
		"bu_psp_lo 0x%llx, bu_psp_hi 0x%llx\n"
		"bu_pcsp_lo 0x%llx, bu_pcsp_hi 0x%llx\n"
		"backup chain stack IPs: %s"
		,
		__entry->sbr, __entry->usd_lo, __entry->usd_hi,
		__entry->psp_lo, __entry->psp_hi, __entry->pshtp,
		__entry->pcsp_lo, __entry->pcsp_hi, __entry->pcshtp,
		__entry->cr0_lo, __entry->cr0_hi, __entry->cr1_lo, __entry->cr1_hi,
		__entry->bu_psp_lo, __entry->bu_psp_hi,
		__entry->bu_pcsp_lo, __entry->bu_pcsp_hi,
		__print_array(__get_dynamic_array(frames),
				__entry->frames_len, sizeof(u64)))

);

TRACE_EVENT(
	irq_delivery,

	TP_PROTO(unsigned int vector, unsigned int dlvm, int vcpu,
		bool dam_active),

	TP_ARGS(vector, dlvm, vcpu, dam_active),

	TP_STRUCT__entry(
		__field(	u32,	vector	)
		__field(	u32,	dlvm	)
		__field(	int,	vcpu	)
		__field(	bool,	dam_active	)
	),

	TP_fast_assign(
		__entry->vector = vector;
		__entry->dlvm = dlvm;
		__entry->vcpu = vcpu;
		__entry->dam_active = dam_active;
	),

	TP_printk("to vcpu %d via %s, vector 0x%x, dlvm %d", __entry->vcpu,
		__entry->dam_active ? "icr" : "pmirr",
		__entry->vector, __entry->dlvm)
);

TRACE_EVENT(
	save_pmirr,

	TP_PROTO(u32 pmirr, u64 val),

	TP_ARGS(pmirr, val),

	TP_STRUCT__entry(
		__field(	u32,	pmirr	)
		__field(	u64,	val	)
	),

	TP_fast_assign(
		__entry->pmirr = pmirr;
		__entry->val = val;
	),

	TP_printk("pmirr#%d val 0x%llx", __entry->pmirr, __entry->val)
);

TRACE_EVENT(
	restore_pmirr,

	TP_PROTO(u32 pmirr, u64 val),

	TP_ARGS(pmirr, val),

	TP_STRUCT__entry(
		__field(	u32,	pmirr	)
		__field(	u64,	val	)
	),

	TP_fast_assign(
		__entry->pmirr = pmirr;
		__entry->val = val;
	),

	TP_printk("pmirr#%d val 0x%llx", __entry->pmirr, __entry->val)
);

TRACE_EVENT(
	save_pnmirr,

	TP_PROTO(u32 val),

	TP_ARGS(val),

	TP_STRUCT__entry(
		__field(	u32,	val	)
	),

	TP_fast_assign(
		__entry->val = val;
	),

	TP_printk("pnmirr val 0x%x", __entry->val)
);

TRACE_EVENT(
	restore_pnmirr,

	TP_PROTO(u32 val),

	TP_ARGS(val),

	TP_STRUCT__entry(
		__field(	u32,	val	)
	),

	TP_fast_assign(
		__entry->val = val;
	),

	TP_printk("pnmirr val 0x%x", __entry->val)
);

TRACE_EVENT(
	save_cir,

	TP_PROTO(u32 cir),

	TP_ARGS(cir),

	TP_STRUCT__entry(
		__field(	u32,	cir	)
	),

	TP_fast_assign(
		__entry->cir = cir;
	),

	TP_printk("cir 0x%x", __entry->cir)
);

TRACE_EVENT(
	restore_cir,

	TP_PROTO(u32 cir),

	TP_ARGS(cir),

	TP_STRUCT__entry(
		__field(	u32,	cir	)
	),

	TP_fast_assign(
		__entry->cir = cir;
	),

	TP_printk("cir 0x%x", __entry->cir)
);

TRACE_EVENT(
	complete_intc_info_io_read,

	TP_PROTO(unsigned long gpa, unsigned long data),

	TP_ARGS(gpa, data),

	TP_STRUCT__entry(
		__field(	unsigned long,	gpa	)
		__field(	unsigned long,	data	)
	),

	TP_fast_assign(
		__entry->gpa = gpa;
		__entry->data = data;
	),

	TP_printk("gpa 0x%lx, data 0x%lx", __entry->gpa, __entry->data)
);

TRACE_EVENT(
	complete_intc_info_io_write,

	TP_PROTO(unsigned long gpa, unsigned long data),

	TP_ARGS(gpa, data),

	TP_STRUCT__entry(
		__field(	unsigned long,	gpa	)
		__field(	unsigned long,	data	)
	),

	TP_fast_assign(
		__entry->gpa = gpa;
		__entry->data = data;
	),

	TP_printk("gpa 0x%lx, data 0x%lx", __entry->gpa, __entry->data)
);

TRACE_EVENT(
	intc_clw,

	TP_PROTO(bool us_cl_d, unsigned long us_cl_b, unsigned long us_cl_up,
		unsigned long us_cl_m0, unsigned long us_cl_m1,
		unsigned long us_cl_m2, unsigned long us_cl_m3),

	TP_ARGS(us_cl_d, us_cl_b, us_cl_up, us_cl_m0, us_cl_m1, us_cl_m2, us_cl_m3),

	TP_STRUCT__entry(
		__field(	bool,		us_cl_d		)
		__field(	unsigned long,	us_cl_b		)
		__field(	unsigned long,	us_cl_up	)
		__field(	unsigned long,	us_cl_m0	)
		__field(	unsigned long,	us_cl_m1	)
		__field(	unsigned long,	us_cl_m2	)
		__field(	unsigned long,	us_cl_m3	)
	),

	TP_fast_assign(
		__entry->us_cl_d = us_cl_d;
		__entry->us_cl_b = us_cl_b;
		__entry->us_cl_up = us_cl_up;
		__entry->us_cl_m0 = us_cl_m0;
		__entry->us_cl_m1 = us_cl_m1;
		__entry->us_cl_m2 = us_cl_m2;
		__entry->us_cl_m3 = us_cl_m3;
	),

	TP_printk("\n"
		"us_cl_d %d, us_cl_b 0x%lx, us_cl_up 0x%lx\n"
		"us_cl_m0 0x%lx us_cl_m1 0x%lx us_cl_m2 0x%lx, us_cl_m3 0x%lx",
		__entry->us_cl_d, __entry->us_cl_b, __entry->us_cl_up,
		__entry->us_cl_m0, __entry->us_cl_m1, __entry->us_cl_m2, __entry->us_cl_m3)
);


#endif /* _TRACE_KVM_HV_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_kvm_hv
#include <trace/define_trace.h>
