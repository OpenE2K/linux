#undef TRACE_SYSTEM
#define TRACE_SYSTEM kvm_hv

#if !defined(_TRACE_KVM_HV_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_KVM_HV_H

#include <linux/tracepoint.h>
#include <asm/kvm_host.h>

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

#define E2K_PRINT_INTC_CU_ENTRY(__entry, i) \
	(__entry->cu_num > i) ? \
		E2K_TRACE_PRINT_CU_INFO_LO(__entry->cu[2 * i]) : "(none)", \
	(__entry->cu_num > i) ? __entry->cu[2 * i] : 0ULL, \
	(__entry->cu_num > i) ? __entry->cu[2 * i + 1] : 0ULL

#define E2K_PRINT_INTC_MU_ENTRY(__entry, mu_num, i) \
	(mu_num > i) ? \
		E2K_TRACE_PRINT_MU_INFO_HDR(__entry->mu[7 * i]) : "(none)", \
	(mu_num > i) ? __entry->mu[7 * i] : 0ULL, \
	(mu_num > i) ? __entry->mu[7 * i + 1] : 0ULL, \
	(mu_num > i) ? __entry->mu[7 * i + 2] : 0ULL, \
	(mu_num > i) ? __entry->mu[7 * i + 3] : 0ULL, \
	(mu_num > i) ? __entry->mu[7 * i + 4] : 0ULL, \
	(mu_num > i) ? __entry->mu[7 * i + 5] : 0ULL, \
	(mu_num > i) ? __entry->mu[7 * i + 6] : 0ULL


TRACE_EVENT(
	intc,

	TP_PROTO(const struct kvm_intc_cpu_context *intc_ctxt,
		u64 guest_ip, u64 cpu),

	TP_ARGS(intc_ctxt, guest_ip, cpu),

	TP_STRUCT__entry(
		__field(	int,	cu_num	)
		__field(	int,	mu_num	)
		__field(	u64,	cu_hdr_lo )
		__array(	u64,	cu,	INTC_INFO_CU_ENTRY_MAX )
		__array(	u64,	mu,	INTC_INFO_MU_MAX )
		__field(	u64,	guest_ip )
		__field(	u64,	cpu )
	),

	TP_fast_assign(
		__entry->cu_num = intc_ctxt->cu_num;
		__entry->mu_num = intc_ctxt->mu_num;

		if (__entry->cu_num >= 0)
			__entry->cu_hdr_lo = AW(intc_ctxt->cu.header.lo);

		if (__entry->cu_num > 0) {
			int i;
			for (i = 0; i < __entry->cu_num; i++) {
				__entry->cu[2 * i] =
					AW(intc_ctxt->cu.entry[i].lo);
				__entry->cu[2 * i + 1] =
					intc_ctxt->cu.entry[i].hi;
			}
		}

		if (__entry->mu_num > 0) {
			int i;
			for (i = 0; i < __entry->mu_num; i++) {
				__entry->mu[7 * i] =
					AW(intc_ctxt->mu[i].hdr);
				__entry->mu[7 * i + 1] =
					intc_ctxt->mu[i].gpa;
				__entry->mu[7 * i + 2] =
					intc_ctxt->mu[i].gva;
				__entry->mu[7 * i + 3] =
					intc_ctxt->mu[i].data;
				__entry->mu[7 * i + 4] =
					AW(intc_ctxt->mu[i].condition);
				__entry->mu[7 * i + 5] =
					intc_ctxt->mu[i].data_ext;
				__entry->mu[7 * i + 6] =
					AW(intc_ctxt->mu[i].mask);
			}
		}

		__entry->guest_ip = guest_ip;
		__entry->cpu = cpu;
	),

	TP_printk("CPU#%llu, guest IP 0x%llx, cu_num %d, mu_num %d\n"
		"CU header: %s (0x%llx)\n"
		"CU entry0: %s (0x%llx 0x%llx)\n"
		"CU entry1: %s (0x%llx 0x%llx)\n"
		"MU entry0: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry1: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry2: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry3: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry4: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry5: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry6: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry7: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry8: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry9: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry10: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		,
		__entry->cpu, __entry->guest_ip,
		__entry->cu_num, __entry->mu_num,
		(__entry->cu_num >= 0) ?
		       E2K_TRACE_PRINT_CU_HDR_LO(__entry->cu_hdr_lo) : "(none)",
		(__entry->cu_num >= 0) ? __entry->cu_hdr_lo : 0,
		E2K_PRINT_INTC_CU_ENTRY(__entry, 0),
		E2K_PRINT_INTC_CU_ENTRY(__entry, 1),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 0),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 1),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 2),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 3),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 4),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 5),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 6),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 7),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 8),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 9),
		E2K_PRINT_INTC_MU_ENTRY(__entry, __entry->mu_num, 10))
);

TRACE_EVENT(
	single_mu_intc,

	TP_PROTO(const intc_info_mu_t *mu, u64 guest_ip, u64 cpu),

	TP_ARGS(mu, guest_ip, cpu),

	TP_STRUCT__entry(
		__array(	u64,	mu,	INTC_INFO_MU_ITEM_SIZE )
		__field(	u64,	guest_ip )
		__field(	u64,	cpu )
	),

	TP_fast_assign(
		__entry->mu[0] = AW(mu[0].hdr);
		__entry->mu[1] = mu[0].gpa;
		__entry->mu[2] = mu[0].gva;
		__entry->mu[3] = mu[0].data;
		__entry->mu[4] = AW(mu[0].condition);
		__entry->mu[5] = mu[0].data_ext;
		__entry->mu[6] = AW(mu[0].mask);
		__entry->guest_ip = guest_ip;
		__entry->cpu = cpu;
	),

	TP_printk("CPU#%llu, guest IP: 0x%llx\n"
		"MU entry0: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
		__entry->cpu, __entry->guest_ip,
		E2K_PRINT_INTC_MU_ENTRY(__entry, 1, 0))
);

TRACE_EVENT(
	double_mu_intc,

	TP_PROTO(const intc_info_mu_t *mu, u64 guest_ip, u64 cpu),

	TP_ARGS(mu, guest_ip, cpu),

	TP_STRUCT__entry(
		__array(	u64,	mu,	2 * INTC_INFO_MU_ITEM_SIZE )
		__field(	u64,	guest_ip )
		__field(	u64,	cpu )
	),

	TP_fast_assign(
		int i;
		for (i = 0; i < 2; i++) {
			__entry->mu[7 * i] =
				AW(mu[i].hdr);
			__entry->mu[7 * i + 1] =
				mu[i].gpa;
			__entry->mu[7 * i + 2] =
				mu[i].gva;
			__entry->mu[7 * i + 3] =
				mu[i].data;
			__entry->mu[7 * i + 4] =
				AW(mu[i].condition);
			__entry->mu[7 * i + 5] =
				mu[i].data_ext;
			__entry->mu[7 * i + 6] =
				AW(mu[i].mask);
		}
		__entry->guest_ip = guest_ip;
		__entry->cpu = cpu;
	),

	TP_printk("CPU#%llu, guest IP: 0x%llx\n"
		"MU entry0: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n"
		"MU entry1: %s (0x%llx), 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx\n",
		__entry->cpu, __entry->guest_ip,
		E2K_PRINT_INTC_MU_ENTRY(__entry, 2, 0),
		E2K_PRINT_INTC_MU_ENTRY(__entry, 2, 1))
);

TRACE_EVENT(
	single_cu_intc,

	TP_PROTO(const intc_info_cu_hdr_t cu_hdr, u64 guest_ip, u64 cpu),

	TP_ARGS(cu_hdr, guest_ip, cpu),

	TP_STRUCT__entry(
		__field(	u64,	cu_hdr_lo )
		__field(	u64,	guest_ip )
		__field(	u64,	cpu )
	),

	TP_fast_assign(
		__entry->cu_hdr_lo = AW(cu_hdr.lo);
		__entry->guest_ip = guest_ip;
		__entry->cpu = cpu;
	),

	TP_printk("CPU#%llu, guest IP: 0x%llx\n"
		"CU header: %s (0x%llx)\n",
		__entry->cpu, __entry->guest_ip,
		E2K_TRACE_PRINT_CU_HDR_LO(__entry->cu_hdr_lo),
		__entry->cu_hdr_lo)

);

TRACE_EVENT(
	intc_exit,

	TP_PROTO(int ret),

	TP_ARGS(ret),

	TP_STRUCT__entry(
		__field(	int,	ret	)
	),

	TP_fast_assign(
		__entry->ret = ret;
	),

	TP_printk("Intercept exit %s(%d)\n",
		(__entry->ret) ? "to QEMU " : "",
		__entry->ret)
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

	TP_printk("to vcpu %d via %s, vector 0x%x, dlvm %d\n", __entry->vcpu,
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

	TP_printk("pmirr#%d val 0x%llx\n", __entry->pmirr, __entry->val)
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

	TP_printk("pmirr#%d val 0x%llx\n", __entry->pmirr, __entry->val)
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

	TP_printk("cir 0x%x\n", __entry->cir)
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

	TP_printk("cir 0x%x\n", __entry->cir)
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

	TP_printk("gpa 0x%lx, data 0x%lx\n", __entry->gpa, __entry->data)
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

	TP_printk("gpa 0x%lx, data 0x%lx\n", __entry->gpa, __entry->data)
);

#endif /* _TRACE_KVM_HV_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm/kvm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace_kvm_hv
#include <trace/define_trace.h>
