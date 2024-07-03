/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


/*
 * CPU hardware virtualized support
 * Interceptions handling
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <asm/cpu_regs.h>
#include <asm/trap_table.h>
#include <asm/traps.h>
#include <asm/mmu_regs_types.h>
#include <asm/system.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/kvm/process.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/guest/tlb_regs_types.h>
#include <asm/kvm/mmu_regs_access.h>
#include <asm/kvm/async_pf.h>
#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/trace_kvm_hv.h>
#include <asm/kvm/gregs.h>

#include "cpu_defs.h"
#include "mmu_defs.h"
#include "cpu.h"
#include "mmu.h"
#include "process.h"
#include "io.h"
#include "intercepts.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_EXC_INSTR_FAULT_MODE
#undef	DebugIPF
#define	DEBUG_EXC_INSTR_FAULT_MODE	0	/* instruction page fault */
						/* exception mode debug */
#define	DebugIPF(fmt, args...)						\
({									\
	if (DEBUG_EXC_INSTR_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_INSTR_FAULT_MODE
#undef	DebugIPINTC
#define	DEBUG_INTC_INSTR_FAULT_MODE	0	/* MMU intercept on instr */
						/* page fault mode debug */
#define	DebugIPINTC(fmt, args...)					\
({									\
	if (DEBUG_INTC_INSTR_FAULT_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_PAGE_FAULT_MODE
#undef	DebugPFINTC
#define	DEBUG_INTC_PAGE_FAULT_MODE	0	/* MMU intercept on data */
						/* page fault mode debug */
#define	DebugPFINTC(fmt, args...)					\
({									\
	if (DEBUG_INTC_PAGE_FAULT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_REEXEC_MODE
#undef	DebugREEXECMU
#define	DEBUG_INTC_REEXEC_MODE	0	/* reexecute MMU intercepts debug */
#define	DebugREEXECMU(fmt, args...)					\
({									\
	if (DEBUG_INTC_REEXEC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_REEXEC_VERBOSE_MODE
#undef	DebugREEXECMUV
#define	DEBUG_INTC_REEXEC_VERBOSE_MODE	0	/* reexecute MMU intercepts */
						/* verbose debug */
#define	DebugREEXECMUV(fmt, args...)					\
({									\
	if (DEBUG_INTC_REEXEC_VERBOSE_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_EXC_INTERRUPT_MODE
#undef	DebugINTR
#define	DEBUG_EXC_INTERRUPT_MODE	0	/* interrupt intercept */
						/* debug */
#define	DebugINTR(fmt, args...)						\
({									\
	if (DEBUG_EXC_INTERRUPT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_INTC_MODE
#undef	DebugINTC
#define	DEBUG_KVM_INTC_MODE	0	/* intercept debug mode */
#define	DebugINTC(fmt, args...)						\
({									\
	if (DEBUG_KVM_INTC_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_CU_ENTRY_MODE
#undef	DebugCUEN
#define	DEBUG_INTC_CU_ENTRY_MODE	0	/* CPU intercept entries */
						/* debug mode */
#define	DebugCUEN(fmt, args...)						\
({									\
	if (DEBUG_INTC_CU_ENTRY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_CU_EXCEPTION_MODE
#undef	DebugINTCEXC
#define	DEBUG_INTC_CU_EXCEPTION_MODE	0	/* CPU exceptions intercept */
						/* debug mode */
#define	DebugINTCEXC(fmt, args...)					\
({									\
	if (DEBUG_INTC_CU_EXCEPTION_MODE)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_TIRs_MODE
#undef	DebugTIRs
#define	DEBUG_INTC_TIRs_MODE	0	/* intercept TIRs debugging */
#define	DebugTIRs(fmt, args...)					\
({									\
	if (DEBUG_INTC_TIRs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_CU_REG_MODE
#undef	DebugCUREG
#define	DEBUG_INTC_CU_REG_MODE	0	/* CPU reguster access intercept */
					/* events debug mode */
#define	DebugCUREG(fmt, args...)					\
({									\
	if (DEBUG_INTC_CU_REG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_MMU_MODE
#undef	DebugINTCMU
#define	DEBUG_INTC_MMU_MODE	0	/* MMU intercept events debug mode */
#define	DebugINTCMU(fmt, args...)					\
({									\
	if (DEBUG_INTC_MMU_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_MMU_SS_REG_MODE
#undef	DebugMMUSSREG
#define	DEBUG_INTC_MMU_SS_REG_MODE	0	/* MMU secondary space */
						/* register access intercept */
						/* events debug mode */
#define	DebugMMUSSREG(fmt, args...)					\
({									\
	if (DEBUG_INTC_MMU_SS_REG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_WAIT_TRAP_MODE
#undef	DebugWTR
#define	DEBUG_INTC_WAIT_TRAP_MODE	0	/* CU wait trap intercept */
#define	DebugWTR(fmt, args...)						\
({									\
	if (DEBUG_INTC_WAIT_TRAP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_RETRY_MODE
#undef	DebugTRY
#define	DEBUG_PF_RETRY_MODE	0	/* retry page fault debug */
#define	DebugTRY(fmt, args...)						\
({									\
	if (DEBUG_PF_RETRY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_FORCED_MODE
#undef	DebugPFFORCED
#define	DEBUG_PF_FORCED_MODE	0	/* forced page fault event debug */
#define	DebugPFFORCED(fmt, args...)					\
({									\
	if (DEBUG_PF_FORCED_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_EXC_RPR_MODE
#undef	DebugEXCRPR
#define	DEBUG_PF_EXC_RPR_MODE	0	/* page fault at recovery mode debug */
#define	DebugEXCRPR(fmt, args...)					\
({									\
	if (DEBUG_PF_EXC_RPR_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_INTC_MMU_PID_MODE
#undef	DebugMMUPID
#define	DEBUG_INTC_MMU_PID_MODE	0	/* MMU PID register access intercept */
					/* events debug mode */
#define	DebugMMUPID(fmt, args...)					\
({									\
	if (DEBUG_INTC_MMU_PID_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	0	/* VIRQs injection debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static void print_intc_ctxt(struct kvm_vcpu *vcpu);
static intc_info_cu_entry_t *find_cu_info_entry(struct kvm_vcpu *vcpu,
						intc_info_cu_t *cu,
						info_cu_event_code_t code,
						cu_reg_no_t reg_no);

static noinline notrace int
do_unsupported_intc(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	pr_err("%s(): unsupported intercept in INTC_INFO_CU\n", __func__);
	return -ENOSYS;
}

/* Interception table. */
exc_intc_handler_t intc_exc_table[INTC_CU_COND_EXC_MAX] = {
	[0 ... INTC_CU_COND_EXC_MAX - 1] =
			(exc_intc_handler_t)(do_unsupported_intc)
};

const cond_exc_info_t cond_exc_info_table[INTC_CU_COND_EXC_MAX] = {
	{
		no		: INTC_CU_EXC_INSTR_DEBUG_NO,
		exc_mask	: exc_instr_debug_mask,
		name		: "exc_instr_debug",
	},
	{
		no		: INTC_CU_EXC_DATA_DEBUG_NO,
		exc_mask	: exc_data_debug_mask,
		name		: "exc_data_debug",
	},
	{
		no		: INTC_CU_EXC_INSTR_PAGE_NO,
		exc_mask	: exc_instr_page_miss_mask |
					exc_instr_page_prot_mask |
					exc_ainstr_page_miss_mask |
					exc_ainstr_page_prot_mask,
		name		: "exc instr/ainstr page miss/prot",
	},
	{
		no		: INTC_CU_EXC_DATA_PAGE_NO,
		exc_mask	: exc_data_page_mask,
		name		: "exc_data_page",
	},
	{
		no		: INTC_CU_EXC_MOVA_NO,
		exc_mask	: exc_mova_ch_0_mask |
					exc_mova_ch_1_mask |
					exc_mova_ch_2_mask |
					exc_mova_ch_3_mask,
		name		: "exc_mova_ch_#0/1/2/3",
	},
	{
		no		: INTC_CU_EXC_INTERRUPT_NO,
		exc_mask	: exc_interrupt_num,
		name		: "exc_interrupt",
	},
	{
		no		: INTC_CU_EXC_NM_INTERRUPT_NO,
		exc_mask	: exc_nm_interrupt_num,
		name		: "exc_nm_interrupt",
	},
	{
		no		: -1,
		exc_mask	: 0,
		name		: "reserved",
	},
};

static int do_forced_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_forced_gva_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_shadow_data_page_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_data_page_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_instr_page_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_ainstr_page_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_read_mmu_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_write_mmu_reg_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
static int do_tlb_line_flush_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);


static noinline notrace int
do_unsupported_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;

	pr_err("%s(): unsupported MMU event intercept code %d %s\n",
		__func__, event, kvm_get_mu_event_name(event));
	return -ENOSYS;
}

static noinline notrace int
do_reserved_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;

	pr_err("%s(): reserved MMU event intercept code %d\n",
		__func__, event);
	return -ENOSYS;
}

const mu_event_desc_t mu_events_desc_table[MU_INTC_EVENTS_MAX] = {
	{
		code	: IME_FORCED,
		handler	: do_forced_data_page_intc_mu,
		name	: "empty: forced",
	},
	{
		code	: IME_FORCED_GVA,
		handler	: do_forced_gva_data_page_intc_mu,
		name	: "empty: page fault GVA->GPA",
	},
	{
		code	: IME_SHADOW_DATA,
		handler	: do_shadow_data_page_intc_mu,
		name	: "data page on shadow PT",
	},
	{
		code	: IME_GPA_DATA,
		handler	: do_data_page_intc_mu,
		name	: "data page fault GPA->PA",
	},
	{
		code	: IME_GPA_INSTR,
		handler	: do_instr_page_intc_mu,
		name	: "instr page fault",
	},
	{
		code	: IME_GPA_AINSTR,
		handler	: do_ainstr_page_intc_mu,
		name	: "async instr page fault",
	},
	{
		code	: IME_RESERVED_6,
		handler	: do_reserved_intc_mu,
		name	: "reserved #6",
	},
	{
		code	: IME_RESERVED_7,
		handler	: do_reserved_intc_mu,
		name	: "reserved #7",
	},
	{
		code	: IME_MAS_IOADDR,
		handler	: do_unsupported_intc_mu,
		name	: "GPA/IO address access",
	},
	{
		code	: IME_READ_MU,
		handler	: do_read_mmu_intc_mu,
		name	: "read MMU register",
	},
	{
		code	: IME_WRITE_MU,
		handler	: do_write_mmu_reg_intc_mu,
		name	: "write MMU register",
	},
	{
		code	: IME_CACHE_FLUSH,
		handler	: do_unsupported_intc_mu,
		name	: "cache flush operation",
	},
	{
		code	: IME_CACHE_LINE_FLUSH,
		handler	: do_unsupported_intc_mu,
		name	: "cache line flush operation",
	},
	{
		code	: IME_ICACHE_FLUSH,
		handler	: do_unsupported_intc_mu,
		name	: "instr cache flush operation",
	},
	{
		code	: IME_ICACHE_LINE_FLUSH_USER,
		handler	: do_unsupported_intc_mu,
		name	: "user instr cache flush operation",
	},
	{
		code	: IME_ICACHE_LINE_FLUSH_SYSTEM,
		handler	: do_unsupported_intc_mu,
		name	: "system instr cache flush operation",
	},
	{
		code	: IME_TLB_FLUSH,
		handler	: do_unsupported_intc_mu,
		name	: "TLB flush operation",
	},
	{
		code	: IME_TLB_PAGE_FLUSH_LAST,
		handler	: do_tlb_line_flush_intc_mu,
		name	: "main TLB page flush operation",
	},
	{
		code	: IME_TLB_PAGE_FLUSH_UPPER,
		handler	: do_tlb_line_flush_intc_mu,
		name	: "upper level TLB page flush operation",
	},
	{
		code	: IME_TLB_ENTRY_PROBE,
		handler	: do_unsupported_intc_mu,
		name	: "TLB entry probe operation",
	},
};

static int do_instr_page_exc(struct kvm_vcpu *vcpu, struct pt_regs *regs,
				bool nonpaging)
{
	int evn_no = 0;	/* should not be used here */
	intc_mu_state_t *mu_state;
	struct trap_pt_regs *trap = regs->trap;
	e2k_tir_lo_t tir_lo;
	e2k_tir_hi_t tir_hi;
	gva_t address;
	unsigned long exc;
	u64 exc_mask;
	u32 error_code;
	bool async_instr = false;
	const char *trap_name;
	int ret;
	pf_res_t pfres;

	E2K_KVM_BUG_ON(nonpaging != !is_paging(vcpu));

	trap->TIR_lo = AW(trap->TIRs[0].TIR_lo);
	trap->TIR_hi = AW(trap->TIRs[0].TIR_hi);
	tir_lo.TIR_lo_reg = trap->TIR_lo;
	tir_hi.TIR_hi_reg = trap->TIR_hi;

	error_code = PFERR_INSTR_FAULT_MASK;
	exc = tir_hi.TIR_hi_exc;

	if (likely(exc & exc_instr_page_miss_mask)) {
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		exc_mask = exc_instr_page_miss_mask;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "instr_page_miss";
	} else if (exc & exc_instr_page_prot_mask) {
		trap->nr_page_fault_exc = exc_instr_page_prot_num;
		exc_mask = exc_instr_page_prot_mask;
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_PROT_MASK;
		trap_name = "instr_page_prot";
	} else if (exc & exc_ainstr_page_miss_mask) {
		trap->nr_page_fault_exc = exc_ainstr_page_miss_num;
		exc_mask = exc_ainstr_page_miss_mask;
		async_instr = true;
		trap_name = "async_instr_page_miss";
	} else if (exc & exc_ainstr_page_prot_mask) {
		trap->nr_page_fault_exc = exc_ainstr_page_prot_num;
		exc_mask = exc_ainstr_page_prot_mask;
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_PROT_MASK;
		async_instr = true;
		trap_name = "async_instr_page_prot";
	} else {
		exc_mask = 0;
		E2K_KVM_BUG_ON(true);
	}

	if (!async_instr) {
		address = tir_lo.TIR_lo_ip;
	} else {
		address = AS(regs->ctpr2).ta_base;
	}

	if (nonpaging)
		address = nonpaging_gva_to_gpa(vcpu, address, ACC_EXEC_MASK,
						NULL, NULL);

	DebugIPF("intercept on %s exception for IP 0x%lx\n",
		trap_name, address);

	vcpu->arch.intc_ctxt.cur_mu = evn_no;
	mu_state = get_intc_mu_state(vcpu);
	mu_state->may_be_retried = false;
	mu_state->ignore_notifier = false;

	ret = kvm_mmu_instr_page_fault(vcpu, address, async_instr, error_code);
	pfres = mu_state->pfres;
	if (ret < 0) {
		/* page fault handler detected error, so pass fault */
		/* to guest handler */
		pr_err("%s(): instr page fault for IP 0x%lx could not be "
			"handled, error %d\n",
			__func__, address, ret);
		kvm_need_pass_vcpu_exception(vcpu, exc_mask);
	} else if (ret == 0) {
		if (pfres == PFRES_NO_ERR) {
			/* page fault successfuly handled and guest can */
			/* continue execution without fault injection */
			kvm_need_delete_vcpu_exception(vcpu, exc_mask);
		} else if (pfres == PFRES_RETRY) {
			/* page fault handling should be retried, but */
			/* it is not allowed (implemented) in this case */
			kvm_need_pass_vcpu_exception(vcpu, exc_mask);
		} else {
			/* page fault failed */
			kvm_need_pass_vcpu_exception(vcpu, exc_mask);
		}
	} else {
		/* The page is not mapped by the guest. */
		/* pass to let the guest handle it */
		kvm_need_pass_vcpu_exception(vcpu, exc_mask);
	}
	return 0;
}

static int do_nonp_instr_page_intc_exc(struct kvm_vcpu *vcpu,
		struct pt_regs *regs)
{
	return do_instr_page_exc(vcpu, regs, true /* nonpaging ? */);
}

static int do_instr_page_intc_exc(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	return do_instr_page_exc(vcpu, regs, false /* nonpaging ? */);
}

static int instr_page_fault_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs, bool async_instr)
{
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
	struct trap_pt_regs *trap = regs->trap;
	gpa_t gpa;
	gva_t address;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	bool nonpaging = !is_paging(vcpu);
	const char *trap_name;
	u32 error_code;

	gpa = intc_info_mu->gpa;
	address = intc_info_mu->gva;
	cond = intc_info_mu->condition;
	AW(ftype) = AS(cond).fault_type;

	DebugIPINTC("intercept on %s instr page, IP gpa 0x%llx gva 0x%lx, "
		"fault type 0x%x\n",
		(async_instr) ? "async" : "sync", gpa, address, AW(ftype));

	if (likely(!nonpaging)) {
		/* paging mode */
		if (is_shadow_paging(vcpu)) {
			/* GP_* PT can be used only to data access */
		} else if (is_phys_paging(vcpu)) {
			address = nonpaging_gva_to_gpa(vcpu, gpa,
						ACC_EXEC_MASK, NULL, NULL);
		} else {
			E2K_KVM_BUG_ON(true);
		}
	} else {
		/* nonpaging mode, all addresses should be physical */
		if (is_phys_paging(vcpu)) {
			address = nonpaging_gva_to_gpa(vcpu, gpa,
						ACC_EXEC_MASK, NULL, NULL);
		} else if (is_shadow_paging(vcpu)) {
			/* GP_* PT is not used, GPA is not set by HW */
			address = nonpaging_gva_to_gpa(vcpu, address,
						ACC_EXEC_MASK, NULL, NULL);
		} else {
			E2K_KVM_BUG_ON(true);
		}
	}

	error_code = PFERR_INSTR_FAULT_MASK;
	if (AS(ftype).page_miss) {
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "instr_page_miss";
	} else if (AS(ftype).prot_page) {
		trap->nr_page_fault_exc = exc_instr_page_prot_num;
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_PROT_MASK;
		trap_name = "instr_page_prot";
	} else if (AS(ftype).illegal_page) {
		E2K_KVM_BUG_ON(is_shadow_paging(vcpu) && !nonpaging);
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "illegal_instr_page";
	} else if (AW(ftype) == 0) {
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "empty_fault_type_instr_page";
	} else {
		pr_err("%s(): bad fault type 0x%x, probably it need pass "
			"fault to guest\n",
			__func__, AW(ftype));
		E2K_KVM_BUG_ON(true);
	}

	DebugIPINTC("intercept on %s fault, IP 0x%lx\n",
		trap_name, address);

	mu_state->may_be_retried = true;
	mu_state->ignore_notifier = false;

	return kvm_mmu_instr_page_fault(vcpu, address, async_instr, error_code);
}

static int do_instr_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	return instr_page_fault_intc_mu(vcpu, intc_info_mu, regs, false);
}

static int do_ainstr_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	return instr_page_fault_intc_mu(vcpu, intc_info_mu, regs, true);
}

static int do_forced_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;
	tc_cond_t cond = intc_info_mu->condition;
	int fmt = TC_COND_FMT_FULL(cond);
	int cur_mu = vcpu->arch.intc_ctxt.cur_mu;
	bool ss_under_rpr;
	bool root = AS(cond).root;	/* secondary space */
	bool ignore_store = false;	/* the store should not be reexecuted */
	intc_info_mu_t *prev_mu;

	DebugPFFORCED("event code %d %s: GVA 0x%lx, GPA 0x%lx, "
		"condition 0x%llx\n",
		event, kvm_get_mu_event_name(event),
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	/* Bug 146747: speculative AAU loads can cause spurious intercepts */
	if (cur_mu == 0) {
		if (tc_cond_is_vector_aau(cond) && AS(cond).spec && !AS(cond).store) {
			if (kvm_debug) {
				pr_info("Forced AAU event is first in INTC_INFO_MU\n");
				print_intc_ctxt(vcpu);
				tracing_off();
			}
		} else {
			pr_err("%s(): forced MU intercept is first in INTC_INFO_MU\n",
				__func__);
			print_intc_ctxt(vcpu);
			kvm_need_create_vcpu_exception(vcpu, exc_software_trap_mask);
		}
	}

	ss_under_rpr = root && kvm_has_vcpu_exc_recovery_point(vcpu);

	if (likely(!ss_under_rpr)) {
		DebugPFFORCED("it is not accsess to secondary space in "
			"generation (RPR) mode, so ignored\n");
		return 0;
	}

	ignore_store = tc_cond_is_store(cond, machine.native_iset_ver);
	if (!ignore_store) {
		DebugPFFORCED("it is load from secondary space in "
			"generation (RPR) mode, so will be reexecuted\n");
		return 0;
	}

	DebugEXCRPR("event code %d %s: %s secondary space at recovery mode: "
		"GVA 0x%lx, GPA 0x%lx, cond 0x%016llx\n",
		event, kvm_get_mu_event_name(event),
		(ignore_store) ? ((AS(cond).store) ? "store to"
					: "load with store semantics to")
				: "load from",
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	if ((fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP)) {
		prev_mu = &vcpu->arch.intc_ctxt.mu[cur_mu - 1];
		if (prev_mu->hdr.event_code == 1) {
			DebugEXCRPR("leaving qword access to secondary space "
			"at recovery mode for guest to handle\n");

			return 0;
		}
	}

	/* mark the INTC_INFO_MU event as deleted to avoid */
	/* hardware reexucution of the store operation */
	kvm_delete_intc_info_mu(vcpu, intc_info_mu);
	DebugEXCRPR("access to secondary space at recovery mode "
		"will not be reexecuted by hardware\n");

	return 0;
}

static int do_forced_gva_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;
	tc_cond_t cond = intc_info_mu->condition;
	bool ss_under_rpr;
	bool root = AS(cond).root;	/* secondary space */
	bool ignore_store = false;	/* the store should not be reexecuted */

	DebugPFFORCED("event code %d %s: GVA 0x%lx, GPA 0x%lx, "
		"condition 0x%llx\n",
		event, kvm_get_mu_event_name(event),
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	ss_under_rpr = root && kvm_has_vcpu_exc_recovery_point(vcpu);

	if (likely(!ss_under_rpr)) {
		DebugPFFORCED("it is not accsess to secondary space in "
			"generation (RPR) mode, so ignored\n");
		return 0;
	}

	ignore_store = tc_cond_is_store(cond, machine.native_iset_ver);
	if (!ignore_store) {
		DebugPFFORCED("it is load from secondary space in "
			"generation (RPR) mode, so will be reexecuted\n");
		return 0;
	}

	DebugEXCRPR("event code %d %s: %s secondary space at recovery mode: "
		"GVA 0x%lx, GPA 0x%lx, cond 0x%016llx\n",
		event, kvm_get_mu_event_name(event),
		(ignore_store) ? ((AS(cond).store) ? "store to"
					: "load with store semantics to")
				: "load from",
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	/*
	 * Pass the fault to guest. Hardware will transfer this entry to
	 * guest's cellar and add exception to TIRs.
	 * Lintel will not re-execute this store.
	 */
	return 0;
}

static int do_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	gpa_t gpa;
	gva_t address;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	bool nonpaging = !is_paging(vcpu);
	int ret;

	gpa = intc_info_mu->gpa;
	address = intc_info_mu->gva;
	cond = intc_info_mu->condition;
	AW(ftype) = AS(cond).fault_type;

	DebugPFINTC("intercept on data page fault, gpa 0x%llx gva 0x%lx, "
		"fault type 0x%x\n",
		gpa, address, AW(ftype));

	if (!is_phys_paging(vcpu)) {
		pr_err("%s(): intercept on GPA->PA translation fault, but "
			"GP_* tables disabled\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}

	address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_ALL, NULL, NULL);

	ret = mmu_pt_hv_page_fault(vcpu, regs, intc_info_mu);
	if (ret != PFRES_NO_ERR && ret != PFRES_TRY_MMIO) {
		pr_info("%s(): could not handle intercept on data "
			"page fault\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	return ret;
}

static int do_shadow_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	gpa_t gpa;
	gva_t address;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	bool nonpaging = !is_paging(vcpu);
	int ret;

	gpa = intc_info_mu->gpa;
	address = intc_info_mu->gva;
	cond = intc_info_mu->condition;
	AW(ftype) = AS(cond).fault_type;

	DebugPFINTC("intercept on data page fault, gpa 0x%llx gva 0x%lx, "
		"fault type 0x%x\n",
		gpa, address, AW(ftype));

	if (!is_shadow_paging(vcpu)) {
		pr_err("%s(): intercept on shadow PT translation fault, but "
			"shadow PT mode is disabled\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	if (nonpaging && is_phys_paging(vcpu)) {
		pr_err("%s(): should be intercept on GPA->PA translation "
			"fault, GP_* tables enabled\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	if (nonpaging)
		address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_ALL,
						NULL, NULL);

	ret = mmu_pt_hv_page_fault(vcpu, regs, intc_info_mu);
	if (ret != PFRES_NO_ERR && ret != PFRES_TRY_MMIO) {
		pr_info("%s(): could not handle intercept on data "
			"page fault\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	return ret;
}

static int do_tlb_line_flush_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	mmu_addr_t mmu_addr;
	flush_addr_t flush_addr;
	gva_t gva;

	mmu_addr = intc_info_mu->gva;
	E2K_KVM_BUG_ON(flush_op_get_type(mmu_addr) != FLUSH_TLB_PAGE_OP);

	flush_addr = intc_info_mu->data;

	/* implemented only for current guest process */
	E2K_KVM_BUG_ON(flush_addr_get_pid(flush_addr) != read_SH_PID_reg());

	gva = FLUSH_VADDR_TO_VA(flush_addr);
	if (!!(flush_addr & FLUSH_ADDR_PHYS)) {
		gva = gfn_to_gpa(gva);
	}

	kvm_mmu_flush_gva(vcpu, gva);

	return 0;
}

static int write_trap_point_mmu_reg(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu)
{
	gpa_t tc_gpa;
	hpa_t tc_hpa;
	int ret;

	tc_gpa = intc_info_mu->data;
	ret = vcpu_write_trap_point_mmu_reg(vcpu, tc_gpa, &tc_hpa);
	if (ret != 0)
		return ret;

	/* set system physical address of guest trap cellar to recover */
	/* intercepted writing to MMU register 'TRAP_POINT' */
	kvm_set_intc_info_mu_modified_data(intc_info_mu, tc_hpa, 0);
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int write_mmu_cr_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_cr_reg(vcpu, (e2k_mmu_cr_t) { .word = intc_info_mu->data });
}

static int write_mmu_u_pptb_reg(struct kvm_vcpu *vcpu,
					intc_info_mu_t *intc_info_mu)
{
	pgprotval_t u_pptb;
	hpa_t u_root;
	bool pt_updated = false;
	int r;

	u_pptb = intc_info_mu->data;
	r = vcpu_write_mmu_u_pptb_reg(vcpu, u_pptb, &pt_updated, &u_root);
	if (r != 0)
		return r;

	if (pt_updated)
		kvm_set_intc_info_mu_modified_data(intc_info_mu, u_root, 0);
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int write_mmu_os_pptb_reg(struct kvm_vcpu *vcpu,
					intc_info_mu_t *intc_info_mu)
{
	pgprotval_t os_pptb;
	hpa_t os_root;
	bool pt_updated = false;
	int r;

	os_pptb = intc_info_mu->data;
	r = vcpu_write_mmu_os_pptb_reg(vcpu, os_pptb, &pt_updated, &os_root);
	if (r != 0)
		return r;

	if (pt_updated)
		kvm_set_intc_info_mu_modified_data(intc_info_mu, os_root, 0);
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int write_mmu_u_vptb_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_u_vptb_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_os_vptb_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_os_vptb_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_os_vab_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_os_vab_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_pid_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_pid_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_ss_ptb_reg(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, int mmu_reg_no)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t mmu_reg, old_mmu_reg;
	const char *reg_name;

	BUG_ON(!is_tdp_paging(vcpu));

	mmu_reg = intc_info_mu->data;
	switch (mmu_reg_no) {
	case _MMU_U2_PPTB_NO:
		old_mmu_reg = mmu->u2_pptb;
		reg_name = "U2_PPTB";
		break;
	case _MMU_MPT_B_NO:
		old_mmu_reg = mmu->mpt_b;
		reg_name = "MPT_B";
		break;
	case _MMU_PDPTE0_NO:
		old_mmu_reg = mmu->pdptes[0];
		reg_name = "PDPTE0";
		break;
	case _MMU_PDPTE1_NO:
		old_mmu_reg = mmu->pdptes[1];
		reg_name = "PDPTE1";
		break;
	case _MMU_PDPTE2_NO:
		old_mmu_reg = mmu->pdptes[2];
		reg_name = "PDPTE2";
		break;
	case _MMU_PDPTE3_NO:
		old_mmu_reg = mmu->pdptes[3];
		reg_name = "PDPTE3";
		break;
	default:
		BUG_ON(true);
	}
	if (old_mmu_reg == mmu_reg) {
		/* the same registers state, so nothing to do */
		DebugMMUSSREG("guest MMU %s: write the same value 0x%llx\n",
			reg_name, mmu_reg);
		return 0;
	}

	/* Only save new MMU register value, probably will be need */
	switch (mmu_reg_no) {
	case _MMU_U2_PPTB_NO:
		mmu->u2_pptb = mmu_reg;
		break;
	case _MMU_MPT_B_NO:
		mmu->mpt_b = mmu_reg;
		break;
	case _MMU_PDPTE0_NO:
		mmu->pdptes[0] = mmu_reg;
		break;
	case _MMU_PDPTE1_NO:
		mmu->pdptes[1] = mmu_reg;
		break;
	case _MMU_PDPTE2_NO:
		mmu->pdptes[2] = mmu_reg;
		break;
	case _MMU_PDPTE3_NO:
		mmu->pdptes[3] = mmu_reg;
		break;
	default:
		BUG_ON(true);
	}
	DebugMMUSSREG("guest MMU %s: write the new value 0x%llx\n",
		reg_name, mmu_reg);

	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int write_mmu_ss_pid_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t pid;

	pid = intc_info_mu->data;
	if (mmu->pid2 != pid) {
		/* only remember secondary space PID */
		mmu->pid2 = pid;
		DebugMMUSSREG("Set MMU guest secondary space new PID: 0x%llx\n",
			pid);
	} else {
		DebugMMUSSREG("MMU guest secondary space is not changed "
			"PID: 0x%llx\n", pid);
		return 0;
	}

	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_trap_point_mmu_reg(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu)
{
	gpa_t tc_gpa;
	int r;

	r = vcpu_read_trap_point_mmu_reg(vcpu, &tc_gpa);
	if (r != 0)
		return r;

	intc_info_mu->data = tc_gpa;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_cr_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	e2k_mmu_cr_t mmu_cr;
	int r;

	r = vcpu_read_mmu_cr_reg(vcpu, &mmu_cr);
	if (r != 0)
		return r;

	intc_info_mu->data = AW(mmu_cr);
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_u_pptb_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	pgprotval_t u_pptb;
	int r;

	r = vcpu_read_mmu_u_pptb_reg(vcpu, &u_pptb);
	if (r != 0)
		return r;

	intc_info_mu->data = u_pptb;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_os_pptb_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	pgprotval_t os_pptb;
	int r;

	r = vcpu_read_mmu_os_pptb_reg(vcpu, &os_pptb);
	if (r != 0)
		return r;

	intc_info_mu->data = os_pptb;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_ss_ptb_reg(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, int mmu_reg_no)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	mmu_reg_t mmu_reg;
	const char *reg_name;

	BUG_ON(!is_tdp_paging(vcpu));

	switch (mmu_reg_no) {
	case _MMU_U2_PPTB_NO:
		mmu_reg = mmu->u2_pptb;
		reg_name = "U2_PPTB";
		break;
	case _MMU_MPT_B_NO:
		mmu_reg = mmu->mpt_b;
		reg_name = "MPT_B";
		break;
	case _MMU_PDPTE0_NO:
		mmu_reg = mmu->pdptes[0];
		reg_name = "PDPTE0";
		break;
	case _MMU_PDPTE1_NO:
		mmu_reg = mmu->pdptes[1];
		reg_name = "PDPTE1";
		break;
	case _MMU_PDPTE2_NO:
		mmu_reg = mmu->pdptes[2];
		reg_name = "PDPTE2";
		break;
	case _MMU_PDPTE3_NO:
		mmu_reg = mmu->pdptes[3];
		reg_name = "PDPTE3";
		break;
	case _MMU_PID2_NO:
		mmu_reg = mmu->pid2;
		reg_name = "PID2";
		break;
	default:
		BUG_ON(true);
	}

	intc_info_mu->data = mmu_reg;
	kvm_set_intc_info_mu_is_updated(vcpu);

	DebugMMUSSREG("guest MMU %s: read the value 0x%llx\n",
		reg_name, mmu_reg);

	return 0;
}

static int read_mmu_u_vptb_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	gva_t u_vptb;
	int r;

	r = vcpu_read_mmu_u_vptb_reg(vcpu, &u_vptb);
	if (r != 0)
		return r;

	intc_info_mu->data = u_vptb;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_os_vptb_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	gva_t os_vptb;
	int r;

	r = vcpu_read_mmu_os_vptb_reg(vcpu, &os_vptb);
	if (r != 0)
		return r;

	intc_info_mu->data = os_vptb;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_os_vab_reg(struct kvm_vcpu *vcpu,
				intc_info_mu_t *intc_info_mu)
{
	gva_t os_vab;
	int r;

	r = vcpu_read_mmu_os_vab_reg(vcpu, &os_vab);
	if (r != 0)
		return r;

	intc_info_mu->data = os_vab;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int do_write_mmu_reg_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	mmu_addr_t mmu_reg_addr;
	int mmu_reg_no;
	int ret;

	E2K_KVM_BUG_ON(intc_info_mu->hdr.event_code != IME_WRITE_MU);

	mmu_reg_addr = intc_info_mu->gva;
	mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_reg_addr);
	switch (mmu_reg_no) {
	case _MMU_TRAP_POINT_NO:
		ret = write_trap_point_mmu_reg(vcpu, intc_info_mu);
		break;
	case _MMU_CR_NO:
		ret = write_mmu_cr_reg(vcpu, intc_info_mu);
		break;
	case _MMU_U_PPTB_NO:
		ret = write_mmu_u_pptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_PPTB_NO:
		ret = write_mmu_os_pptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_U2_PPTB_NO:
	case _MMU_MPT_B_NO:
	case _MMU_PDPTE0_NO:
	case _MMU_PDPTE1_NO:
	case _MMU_PDPTE2_NO:
	case _MMU_PDPTE3_NO:
		ret = write_mmu_ss_ptb_reg(vcpu, intc_info_mu, mmu_reg_no);
		break;
	case _MMU_U_VPTB_NO:
		ret = write_mmu_u_vptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_VPTB_NO:
		ret = write_mmu_os_vptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_VAB_NO:
		ret = write_mmu_os_vab_reg(vcpu, intc_info_mu);
		break;
	case _MMU_PID_NO:
		ret = write_mmu_pid_reg(vcpu, intc_info_mu);
		break;
	case _MMU_PID2_NO:
		ret = write_mmu_ss_pid_reg(vcpu, intc_info_mu);
		break;
	default:
		pr_err("%s(): unimplemented MMU register #%d intercept\n",
			__func__, mmu_reg_no);
		ret = -ENOSYS;
		break;
	}

	return ret;
}

static int read_mmu_reg_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	mmu_addr_t mmu_reg_addr;
	int mmu_reg_no;
	int ret;

	mmu_reg_addr = intc_info_mu->gva;
	mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_reg_addr);
	switch (mmu_reg_no) {
	case _MMU_TRAP_POINT_NO:
		ret = read_trap_point_mmu_reg(vcpu, intc_info_mu);
		break;
	case _MMU_CR_NO:
		ret = read_mmu_cr_reg(vcpu, intc_info_mu);
		break;
	case _MMU_U_PPTB_NO:
		ret = read_mmu_u_pptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_PPTB_NO:
		ret = read_mmu_os_pptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_U2_PPTB_NO:
	case _MMU_MPT_B_NO:
	case _MMU_PDPTE0_NO:
	case _MMU_PDPTE1_NO:
	case _MMU_PDPTE2_NO:
	case _MMU_PDPTE3_NO:
	case _MMU_PID2_NO:
		ret = read_mmu_ss_ptb_reg(vcpu, intc_info_mu, mmu_reg_no);
		break;
	case _MMU_U_VPTB_NO:
		ret = read_mmu_u_vptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_VPTB_NO:
		ret = read_mmu_os_vptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_VAB_NO:
		ret = read_mmu_os_vab_reg(vcpu, intc_info_mu);
		break;
	default:
		pr_err("%s(): unimplemented MMU register #%d intercept\n",
			__func__, mmu_reg_no);
		ret = -ENOSYS;
		break;
	}

	return ret;
}

static int read_dtlb_reg_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	tlb_addr_t tlb_addr;
	mmu_reg_t tlb_entry;

	tlb_addr = intc_info_mu->gva;
	tlb_entry = NATIVE_READ_DTLB_REG(tlb_addr);

	/* FIXME: here should be conversion from native DTLB entry structure */
	/* to guest arch one, but such readings are used only for debug info */
	/* dumping. */
	intc_info_mu->data = tlb_entry;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static void check_virt_ctrl_mu_rr_dbg1(void)
{
	virt_ctrl_mu_t reg = read_VIRT_CTRL_MU_reg();

	if (!reg.rr_dbg1)
		pr_err("%s(): intercepted MLT/DAM read with disabled rr_dbg1\n",
			__func__);
}

static int read_dam_reg_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	e2k_addr_t dam_addr;
	u64 dam_entry;

	dam_addr = intc_info_mu->gva;
	dam_entry = NATIVE_READ_DAM_REG(dam_addr);

	intc_info_mu->data = dam_entry;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mlt_reg_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	e2k_addr_t mlt_addr;
	u64 mlt_entry;

	mlt_addr = intc_info_mu->gva;
	mlt_entry = NATIVE_READ_MLT_REG(mlt_addr);

	intc_info_mu->data = mlt_entry;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int do_read_mmu_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	tc_cond_t cond;
	unsigned int mas;
	int ret;

	E2K_KVM_BUG_ON(intc_info_mu->hdr.event_code != IME_READ_MU);

	cond = intc_info_mu->condition;
	mas = AS(cond).mas;
	if (mas == MAS_MMU_REG) {
		return read_mmu_reg_intc_mu(vcpu, intc_info_mu, regs);
	} else if (mas == MAS_DTLB_REG) {
		return read_dtlb_reg_intc_mu(vcpu, intc_info_mu, regs);
	} else if (mas == MAS_DAM_REG) {
		check_virt_ctrl_mu_rr_dbg1();

		if ((intc_info_mu->gva & REG_DAM_TYPE) == REG_DAM_TYPE) {
			return read_dam_reg_intc_mu(vcpu, intc_info_mu, regs);
		} else if ((intc_info_mu->gva & REG_MLT_TYPE) == REG_MLT_TYPE) {
			return read_mlt_reg_intc_mu(vcpu, intc_info_mu, regs);
		} else {
			pr_err("%s(): not implemented special MMU or AAU "
				"operation type, mas.mod %d, mas.opc %d, "
				"addr 0x%lx\n",
				__func__,
				(mas & MAS_MOD_MASK) >> MAS_MOD_SHIFT,
				(mas & MAS_OPC_MASK) >> MAS_OPC_SHIFT,
				intc_info_mu->gva);
			ret = -EINVAL;
		}
	} else {
		pr_err("%s(): not implemented special MMU or AAU operation "
			"type, mas.mod %d, mac.opc %d\n",
			__func__,
			(mas & MAS_MOD_MASK) >> MAS_MOD_SHIFT,
			(mas & MAS_OPC_MASK) >> MAS_OPC_SHIFT);
		ret = -EINVAL;
	}

	return ret;
}

static int handle_exc_interrupt_intc(struct kvm_vcpu *vcpu,
		struct pt_regs *regs, unsigned long exc_mask)
{
	struct trap_pt_regs *trap = regs->trap;
	unsigned long exc;

	DebugINTR("intercept on interrupt exception\n");

	trap->TIR_lo = trap->TIRs[0].TIR_lo.TIR_lo_reg;
	trap->TIR_hi = trap->TIRs[0].TIR_hi.TIR_hi_reg;
	exc = trap->TIRs[0].TIR_hi.TIR_hi_exc;
	if (unlikely((exc & exc_mask) != exc_mask)) {
		pr_err("%s(): intercept on interrupt exception 0x%016lx, "
			"but TIR[0].exc 0x%016lx has not interrupt\n",
			__func__, exc_mask, exc);
	}
	local_irq_disable();
	if (exc_mask & exc_nm_interrupt_mask)
		do_nm_interrupt(regs);
	if (exc_mask & exc_interrupt_mask)
		native_do_interrupt(regs);
	local_irq_enable();

	return 0;
}

static int do_exc_interrupt_intc(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	return handle_exc_interrupt_intc(vcpu, regs, exc_interrupt_mask);
}

static int do_exc_nm_interrupt_intc(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	return handle_exc_interrupt_intc(vcpu, regs, exc_nm_interrupt_mask);
}

void mmu_init_nonpaging_intc(struct kvm_vcpu *vcpu)
{
	kvm_set_cond_exc_handler(INTC_CU_EXC_INSTR_PAGE_NO,
			(exc_intc_handler_t)(do_nonp_instr_page_intc_exc));
}

void kvm_init_kernel_intc(struct kvm_vcpu *vcpu)
{
	kvm_set_cond_exc_handler(INTC_CU_EXC_INSTR_PAGE_NO,
			(exc_intc_handler_t)(do_instr_page_intc_exc));
	kvm_set_cond_exc_handler(INTC_CU_EXC_INTERRUPT_NO,
			(exc_intc_handler_t)(do_exc_interrupt_intc));
	kvm_set_cond_exc_handler(INTC_CU_EXC_NM_INTERRUPT_NO,
			(exc_intc_handler_t)(do_exc_nm_interrupt_intc));
}

static void print_intc_ctxt(struct kvm_vcpu *vcpu)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	int cu_num = intc_ctxt->cu_num, mu_num = intc_ctxt->mu_num;
	intc_info_mu_t *mu = intc_ctxt->mu;
	int evn_no;

	pr_alert("Dumping intercept context on CPU %d VCPU %d. cu_num %d, mu_num %d\n",
		vcpu->cpu, vcpu->vcpu_id, cu_num, mu_num);
	pr_alert("CU header: lo 0x%llx; hi 0x%llx\n",
		AW(intc_ctxt->cu.header.lo), AW(intc_ctxt->cu.header.hi));
	pr_alert("CU entry0: lo 0x%llx; hi 0x%llx\n",
		AW(intc_ctxt->cu.entry[0].lo), intc_ctxt->cu.entry[0].hi);
	pr_alert("CU entry1: lo 0x%llx; hi 0x%llx\n",
		AW(intc_ctxt->cu.entry[1].lo), intc_ctxt->cu.entry[1].hi);

	for (evn_no = 0; evn_no < mu_num; evn_no++) {
		intc_info_mu_t *mu_event = &mu[evn_no];
		int event = mu_event->hdr.event_code;

		pr_alert("MU entry %d: code %d %s\n", evn_no, event, kvm_get_mu_event_name(event));
		pr_alert("hdr 0x%llx gpa 0x%lx gva 0x%lx data 0x%lx\n",
			mu_event->hdr.word, mu_event->gpa, mu_event->gva, mu_event->data);
		pr_alert("condition 0x%llx data_ext 0x%lx mask 0x%llx\n",
			mu_event->condition.word, mu_event->data_ext, mu_event->mask.word);
	}

	print_all_TIRs(intc_ctxt->TIRs, intc_ctxt->nr_TIRs);
}

static int do_read_cu_idr(struct kvm_vcpu *vcpu, intc_info_cu_t *cu)
{
	kvm_guest_info_t *guest_info = &vcpu->kvm->arch.guest_info;
	intc_info_cu_entry_t *rr_event;
	e2k_idr_t idr;

	rr_event = find_cu_info_entry(vcpu, cu, ICE_READ_CU, IDR_cu_reg_no);
	if (rr_event == NULL) {
		pr_err("%s(): could not find INTC_INFO_CU event with IDR\n", __func__);
		print_intc_ctxt(vcpu);
		E2K_KVM_BUG_ON(true);
		return -EINVAL;
	}

	idr = kvm_vcpu_get_idr(vcpu);

	if (guest_info->is_stranger) {
		rr_event->hi = idr.IDR_reg;
		kvm_set_intc_info_cu_is_updated(vcpu);
	}

	return 0;
}

static int read_reg_intc_cu(struct kvm_vcpu *vcpu,
			intc_info_cu_t *intc_info_cu, pt_regs_t *regs)
{
	u64 rr_events = intc_info_cu->header.lo.evn_c;
	int ret = 0, r;

	if (rr_events & intc_cu_evn_c_rr_idr_mask) {
		r = do_read_cu_idr(vcpu, intc_info_cu);
		if (r != 0)
			ret |= r;
		rr_events &= ~intc_cu_evn_c_rr_idr_mask;
	}

	if (rr_events != 0) {
		pr_err("%s(): some events were not handled: 0x%llx\n",
			__func__, rr_events);
	}

	return ret;
}

static void do_write_cu_sclk_reg(struct kvm_vcpu *vcpu, intc_info_cu_t *cu,
	cu_reg_no_t reg_no)
{
	intc_info_cu_entry_t *rw_event;

	rw_event = find_cu_info_entry(vcpu, cu, ICE_WRITE_CU, reg_no);
	if (rw_event)
		kvm_delete_intc_info_cu(vcpu, rw_event);
}

static int do_write_cu_sclk_regs(struct kvm_vcpu *vcpu, intc_info_cu_t *cu)
{
	do_write_cu_sclk_reg(vcpu, cu, SCLKR_cu_reg_no);
	do_write_cu_sclk_reg(vcpu, cu, SCLKM1_cu_reg_no);
	do_write_cu_sclk_reg(vcpu, cu, SCLKM2_cu_reg_no);

	return 0;
}

static int do_write_cu_sclkm3(struct kvm_vcpu *vcpu, intc_info_cu_t *cu)
{
	struct kvm_arch *ka = &vcpu->kvm->arch;
	unsigned long flags;

	do_write_cu_sclk_reg(vcpu, cu, SCLKM3_cu_reg_no);

	if (cpu_has(CPU_HWBUG_VIRT_SCLKM3_INTC)) {
		raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
		WRITE_SH_SCLKM3_REG_VALUE(ka->sh_sclkm3);
		raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);
	}

	return 0;
}

/* Bug 127993: to ignore guest's CU write, delete it from INTC_INFO_CU */
static int write_reg_intc_cu(struct kvm_vcpu *vcpu,
			intc_info_cu_t *intc_info_cu, pt_regs_t *regs)
{
	u64 rw_events = intc_info_cu->header.lo.evn_c;
	int ret = 0, r;

	/* Ignore guest's writes to sclkr, sclkm1, sclkm2 */
	if (rw_events & intc_cu_evn_c_rw_sclkr_mask) {
		r = do_write_cu_sclk_regs(vcpu, intc_info_cu);
		if (r != 0)
			ret |= r;
		rw_events &= ~intc_cu_evn_c_rw_sclkr_mask;
	}

	/* Ignore guest's writes to sclkm3 */
	if (rw_events & intc_cu_evn_c_rw_sclkm3_mask) {
		r = do_write_cu_sclkm3(vcpu, intc_info_cu);
		if (r != 0)
			ret |= r;
		rw_events &= ~intc_cu_evn_c_rw_sclkm3_mask;
	}

	if (rw_events != 0) {
		pr_err("%s(): some events were not handled: 0x%llx\n",
			__func__, rw_events);
	}

	return ret;
}

static unsigned long long do_hcem_intc(struct kvm_vcpu *vcpu, intc_info_cu_t *cu)
{
	intc_info_cu_entry_t *entry;

	entry = find_cu_info_entry(vcpu, cu, ICE_MASKED_HCALL, -1);
	if (entry == NULL) {
		pr_err("%s(): could not find INTC_INFO_CU event ICE_MASKED_HCALL\n", __func__);
		return 0;
	}

	return entry->hi;
}

static int handle_cu_cond_events(struct kvm_vcpu *vcpu,
			intc_info_cu_t *cu, pt_regs_t *regs)
{
	u64 cond_events = cu->header.lo.evn_c;
	int r, ret = 0;

	if (cond_events & intc_cu_evn_c_rr_mask) {
		r = read_reg_intc_cu(vcpu, cu, regs);
		if (r != 0)
			ret |= r;
		cond_events &= ~intc_cu_hrd_lo_rr_mask;
	}
	if (cond_events & intc_cu_evn_c_rw_mask) {
		r = write_reg_intc_cu(vcpu, cu, regs);
		if (r != 0)
			ret |= r;
		cond_events &= ~intc_cu_hrd_lo_rw_mask;
	}
	if (cond_events & intc_cu_evn_c_hret_last_wish_mask) {
		r = do_hret_last_wish_intc(vcpu, regs);
		if (r < 0) {
			pr_err("%s(): conditional event HRET last wish "
				"intercept handler failed, error %d\n",
				__func__, r);
			E2K_KVM_BUG_ON(true);
		} else if (r != 0) {
			/* it need return to user space to handle */
			/* intercept (exit) reason */
			ret |= 1;
		}
		cond_events &= ~intc_cu_evn_c_hret_last_wish_mask;
	}
	if (cond_events & intc_cu_evn_c_virt_mask) {
		pr_err("%s(): unexpected intercept on virtualization "
			"resources access, ignore\n",
			__func__);
		print_intc_ctxt(vcpu);
		cond_events &= ~intc_cu_evn_c_virt_mask;
	}
	if (cond_events & intc_cu_evn_c_hcem_mask) {
		pr_err("%s(): unexpected hypercall type %llx\n", __func__, do_hcem_intc(vcpu, cu));
		print_intc_ctxt(vcpu);
		E2K_KVM_BUG_ON(true);
		cond_events &= ~intc_cu_evn_c_hcem_mask;
	}
	if (cond_events == 0)
		return ret;

	panic("%s(): is not yet implemented, events: 0x%llx\n",
		__func__, cond_events);
	return ret;
}

static int wait_trap_intc_cu(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	/* Go to scheduler to wait for a wake up event. */
	DebugWTR("VCPU #%d interception on wait trap, block and wait for wake up\n",
			vcpu->vcpu_id);
	vcpu->arch.mp_state = KVM_MP_STATE_HALTED;
	kvm_vcpu_block(vcpu);
	kvm_check_request(KVM_REQ_UNHALT, vcpu);
	vcpu->arch.mp_state = KVM_MP_STATE_RUNNABLE;
	vcpu->arch.unhalted = false;
	DebugWTR("VCPU #%d has been woken up, so run guest again\n", vcpu->vcpu_id);

	return 0;
}

static int handle_cu_uncond_events(struct kvm_vcpu *vcpu,
			intc_info_cu_t *cu, pt_regs_t *regs)
{
	u64 uncond_evn = cu->header.lo.evn_u;

	if ((uncond_evn & intc_cu_evn_u_hv_int_mask) ||
			(uncond_evn & intc_cu_evn_u_hv_nm_int_mask)) {
		/* should be already handled, so ignore here */
		uncond_evn &= ~(intc_cu_evn_u_hv_int_mask |
				intc_cu_evn_u_hv_nm_int_mask);
	}
	if (uncond_evn & intc_cu_evn_u_wait_trap_mask) {
		uncond_evn &= ~intc_cu_evn_u_wait_trap_mask;
		wait_trap_intc_cu(vcpu, regs);
	}
	if (uncond_evn & intc_cu_evn_u_dbg_mask) {
		/* May be sent by:
		 * - simulator, with -bI option
		 * - JTAG, when manually switching to hypervisor mode after
		 *   stop_hard in guest
		 */
		uncond_evn &= ~intc_cu_evn_u_dbg_mask;
		coredump_in_future();
	}
	if (uncond_evn & intc_cu_evn_u_exc_mem_error_mask) {
		uncond_evn &= ~intc_cu_evn_u_exc_mem_error_mask;
		do_mem_error(regs);
	}
	if (uncond_evn & intc_cu_evn_u_g_tmr_mask) {
		/* Ignore G_PREEMPT_TMR */
		uncond_evn &= ~intc_cu_evn_u_g_tmr_mask;
	}
	if (uncond_evn != 0) {
		pr_err("%s(): is not yet implemented, events: 0x%llx\n",
			__func__, uncond_evn);
	}

	return 0;
}

static intc_info_cu_entry_t *find_cu_info_entry(struct kvm_vcpu *vcpu,
						intc_info_cu_t *cu,
						info_cu_event_code_t code,
						cu_reg_no_t reg_no)
{
	u64 entry_handled = vcpu->arch.intc_ctxt.cu_entry_handled;
	unsigned cu_num = vcpu->arch.intc_ctxt.cu_num;
	int no;

	/* all info intries should be already handled */
	for (no = 0; no < cu_num; no++) {
		intc_info_cu_entry_t *cu_entry = &cu->entry[no];
		int event = cu_entry->lo.event_code;
		u64 mask = (1ULL << no);

		if (event != code) {
			continue;
		}
		if (code == ICE_READ_CU || code == ICE_WRITE_CU) {
			if (cu_entry->lo.reg_num != reg_no) {
				continue;
			}
		}
		if (entry_handled & mask) {
			/* entry was already handled */
			pr_err("%s(): event #%d code %d was already handled\n",
				__func__, no, event);
		}
		return cu_entry;
	}
	DebugCUREG("%s(): could not found entry: event code %d\n",
		__func__, code);
	return NULL;
}

static void check_cu_info_entries(struct kvm_vcpu *vcpu,
			intc_info_cu_t *cu, int entries_num)
{
	u64 entry_handled = vcpu->arch.intc_ctxt.cu_entry_handled;
	int no;

	/* all info intries should be already handled */
	for (no = 0; no < entries_num;
			no += (sizeof(intc_info_cu_entry_t) / sizeof(u64))) {
		intc_info_cu_entry_t *cu_entry = &cu->entry[no];
		int event = cu_entry->lo.event_code;
		u64 mask = (1ULL << no);

		if (event == ICE_FORCED) {
			/* Guest event - leave its handling to guest */
			if (entry_handled & mask) {
				DebugCUEN("entry[%d]: has been converted "
					"to empty\n", no);
			} else {
				DebugCUEN("entry[%d]: empty\n", no);
			}
			continue;
		}
		if (event == ICE_READ_CU) {
			/* read from CPU system register */
			DebugCUEN("entry[%d]: read register #%d, channel #%d, "
				"dst 0x%x mask 0x%x\n"
				"          data: 0x%llx\n",
				no, cu_entry->lo.reg_num, cu_entry->lo.ch_code,
				cu_entry->lo.dst, cu_entry->lo.vm_dst,
				cu_entry->hi);
			continue;
		} else if (event == ICE_WRITE_CU) {
			/* write to CPU system register */
			DebugCUEN("entry[%d]: write register #%d, channel #%d\n"
				"          data: 0x%llx\n",
				no, cu_entry->lo.reg_num, cu_entry->lo.ch_code,
				cu_entry->hi);
			continue;
		} else if (event == ICE_MASKED_HCALL) {
			/* hypercall is not alowed */
			DebugCUEN("entry[%d]: masked HCALL\n", no);
			continue;
		} else {
			pr_err("%s(): unknown event code %d at "
				"INTC_INFO_CU[%d]\n",
				__func__, event, INTC_INFO_CU_HDR_MAX + no);
			E2K_KVM_BUG_ON(true);
		}
		if (entry_handled & mask)
			/* entry was handled */
			continue;
		pr_err("%s(): INTC_INFO_CU[%d] entry was not handled, "
			"event code %d\n",
			__func__, INTC_INFO_CU_HDR_MAX + no, event);
		KVM_WARN_ON(true);
	}
}

static int handle_cu_cond_exceptions(struct kvm_vcpu *vcpu,
			intc_info_cu_t *cu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	u64 tir_exc = intc_ctxt->exceptions;
	u64 cond_exc = cu->header.lo.exc_c;
	u64 cond_evn = cu->header.lo.evn_c;
	u64 uncond_evn = cu->header.lo.evn_u;
	u64 exc_to_intc;
	exc_intc_handler_t handler;
	int exc_no;
	u64 cond_exc_mask, tir_exc_mask;
	int r, ret = 0;

	exc_to_intc = vcpu->arch.hw_ctxt.virt_ctrl_cu.VIRT_CTRL_CU_exc_c;

	for (exc_no = 0; exc_no < INTC_CU_COND_EXC_MAX; exc_no++) {
		cond_exc_mask = 1ULL << exc_no;
		tir_exc_mask = kvm_cond_exc_no_to_exc_mask(exc_no);
		if (likely((cond_exc & cond_exc_mask) == 0)) {
			/* intercept of exception did not occur */
			if (tir_exc_mask == 0)
				/* it is reserved bit of exc_c field */
				continue;
			if (likely((tir_exc & tir_exc_mask) == 0))
				/* exception did not occur too */
				continue;
			/* exception occured */
			if (cu->header.lo.tir_fz)
				/* exceptions at frozen TIRs, so guest is not */
				/* yet read TIRs to start handling */
				continue;
			if (likely((exc_to_intc & cond_exc_mask) == 0)) {
				/* exception is not expected and */
				/* intercepted, so it is guest trap, */
				/* pass to guest */
				if (cond_exc == 0 && cond_evn == 0 &&
							uncond_evn == 0) {
					pr_err("%s(): unexpected conditional "
						"exception #%d (0x%llx) %s "
						"occured, but did not "
						"intercepted, expected "
						"mask 0x%llx, so it is trap "
						"of guest and will be passed "
						"to guest\n",
						__func__, exc_no, cond_exc_mask,
						kvm_cond_exc_no_to_exc_name(
									exc_no),
						exc_to_intc);
				}
				kvm_pass_cond_exc_to_vcpu(vcpu, exc_no);
				continue;
			}
			pr_err("%s(): expected conditional exception #%d "
				"(0x%llx) %s occured, but did not intercepted, "
				"expected mask 0x%llx, so will be passed "
				"to guest\n",
				__func__, exc_no, cond_exc_mask,
				kvm_cond_exc_no_to_exc_name(exc_no),
				exc_to_intc);
			kvm_pass_cond_exc_to_vcpu(vcpu, exc_no);
			continue;
		}

		/* intercept on conditional exception occured */
		DebugINTCEXC("INTC CU exception #%d\n", exc_no);
		E2K_KVM_BUG_ON(tir_exc_mask == 0);
		if (unlikely((exc_to_intc & cond_exc_mask) == 0)) {
			pr_err("%s(): unexpected intercept of conditional "
				"exception #%d (0x%llx), "
				"expected mask 0x%llx\n",
				__func__, exc_no, cond_exc_mask, exc_to_intc);
			if (tir_exc_mask & tir_exc) {
				kvm_pass_cond_exc_to_vcpu(vcpu, exc_no);
				pr_err("%s(): unexpected exception %s is "
					"detected in the TIRs, so will be "
					"passed to guest\n",
					__func__,
					kvm_cond_exc_no_to_exc_name(exc_no));
			} else {
				pr_err("%s(): unexpected exception %s is not "
					"detected in the TIRs, so will be "
					"ignored\n",
					__func__,
					kvm_cond_exc_no_to_exc_name(exc_no));
			}
			continue;
		}
		if (unlikely((tir_exc_mask & tir_exc) == 0)) {
			/* but exception did not occur */
			pr_err("%s(): there is intercept of expected "
				"conditional exception #%d (0x%llx) %s, "
				"but exception did not occur, "
				"mask of all TIRs exceptions 0x%llx, "
				"so will be ignored\n",
				__func__, exc_no, cond_exc_mask,
				kvm_cond_exc_no_to_exc_name(exc_no),
				tir_exc);
			continue;
		}
		handler = kvm_get_cond_exc_handler(exc_no);
		r = handler(vcpu, regs);
		if (r < 0) {
			pr_err("%s(): conditional exception #%d %s intercept "
				"handler %pF failed, error %d\n",
				__func__, exc_no,
				kvm_cond_exc_no_to_exc_name(exc_no),
				handler, r);
			E2K_KVM_BUG_ON(true);
		} else if (r != 0) {
			/* it need return to user space to handle */
			/* intercept (exit) reason */
			ret |= 1;
		}
	}
	return ret;
}

/*
 * The function returns new mask of total exceptions (including AAU)
 * at all TIRs
 */
static u64 restore_vcpu_intc_TIRs(struct kvm_vcpu *vcpu,
		u64 TIRs_exc, u64 to_pass, u64 to_delete, u64 to_create)
{
	int TIRs_num, TIR_no, last_valid_TIR_no = -1;
	e2k_tir_lo_t TIR_lo;
	e2k_tir_hi_t TIR_hi;
	u64 TIRs_aa, aa_to_pass, aa_to_delete, aa_to_create;
	u64 new_TIRs_exc = 0;
	u64 new_TIRs_aa = 0;
	bool aa_valid;

	TIRs_num = kvm_get_vcpu_intc_TIRs_num(vcpu);
	E2K_KVM_BUG_ON(TIRs_exc != 0 && TIRs_num < 0);
	TIRs_aa = ((e2k_tir_hi_t)TIRs_exc).TIR_hi_aa;
	aa_to_pass = ((e2k_tir_hi_t)to_pass).TIR_hi_aa;
	aa_to_delete = ((e2k_tir_hi_t)to_delete).TIR_hi_aa;
	aa_to_create = ((e2k_tir_hi_t)to_create).TIR_hi_aa;
	aa_valid = (TIRs_aa || aa_to_pass || aa_to_delete || aa_to_create);

	for (TIR_no = 0; TIR_no <= TIRs_num; TIR_no++) {
		u64 exc, tir_exc, pass, delete, create, new_exc, new_aa;

		TIR_hi = kvm_get_vcpu_intc_TIR_hi(vcpu, TIR_no);
		TIR_lo = kvm_get_vcpu_intc_TIR_lo(vcpu, TIR_no);
		exc = TIR_hi.TIR_hi_exc;
		tir_exc = exc & TIRs_exc;
		pass = exc & to_pass;
		delete = exc & to_delete;
		create = exc & to_create;
		new_exc = pass | create;
		new_exc |= (tir_exc &~delete);
		DebugTIRs("TIR[%d]: source exc 0x%llx. intersections with "
			"TIRs 0x%llx pass 0x%llx delete 0x%llx create 0x%llx "
			" -> new exc 0x%llx\n",
			TIR_no, exc, tir_exc, pass, delete, create, new_exc);
		if (aa_valid) {
			u64 aa, tir_aa, aa_pass, aa_delete, aa_create;

			aa = TIR_hi.TIR_hi_aa;
			tir_aa = aa & TIRs_aa;
			aa_pass = aa & aa_to_pass;
			aa_delete = aa & aa_to_delete;
			aa_create = aa & aa_to_create;
			new_aa = aa_pass | aa_create;
			new_aa |= (tir_aa &~aa_delete);
			DebugTIRs("TIR[%d]: source aa 0x%llx. intersections "
				"with TIRs 0x%llx pass 0x%llx delete 0x%llx "
				"create 0x%llx -> new aa 0x%llx\n",
				TIR_no, aa, tir_aa, aa_pass, aa_delete,
				aa_create, new_aa);
		} else {
			new_aa = 0;
		}
		TIR_hi.TIR_hi_exc = new_exc;
		TIR_hi.TIR_hi_aa = new_aa;
		new_TIRs_exc |= new_exc;
		new_TIRs_aa |= new_aa;
		if (new_exc || new_aa)
			last_valid_TIR_no = TIR_no;
		kvm_set_vcpu_intc_TIR_hi(vcpu, TIR_no, TIR_hi);
		DebugTIRs("TIR[%d].hi: exc 0x%llx alu 0x%x aa 0x%x #%d\n"
			"TIR[%d].lo: IP 0x%llx\n",
			TIR_no, TIR_hi.TIR_hi_exc, TIR_hi.TIR_hi_al,
			TIR_hi.TIR_hi_aa, TIR_hi.TIR_hi_j,
			TIR_no, TIR_lo.TIR_lo_ip);
	}

	if (last_valid_TIR_no < TIRs_num)
		kvm_set_vcpu_intc_TIRs_num(vcpu, last_valid_TIR_no);

	if (kvm_check_is_vcpu_intc_TIRs_empty(vcpu)) {
		DebugTIRs("intercept TIRs are empty to pass to guest\n");
		E2K_KVM_BUG_ON(new_TIRs_exc || new_TIRs_aa);
		return 0;
	} else {
		DebugTIRs("intercept TIRs of %d num total exc mask 0x%llx, "
			"aa 0x%llx will be passed to guest\n",
			kvm_get_vcpu_intc_TIRs_num(vcpu),
			new_TIRs_exc, new_TIRs_aa);
		TIR_hi.TIR_hi_reg = 0;
		TIR_hi.TIR_hi_exc = new_TIRs_exc;
		TIR_hi.TIR_hi_aa = new_TIRs_aa;
		return TIR_hi.TIR_hi_reg;
	}
}


#ifdef CONFIG_KVM_ASYNC_PF

/*
 * Return event code for given event number
 */
intc_info_mu_event_code_t get_event_code(struct kvm_vcpu *vcpu, int ev_no)
{
	intc_info_mu_t *intc_info_mu = &vcpu->arch.intc_ctxt.mu[ev_no];

	return intc_info_mu->hdr.event_code;
}

/*
 * intc_mu_record_asynchronous - return true if the record
 * in intc_info_mu buffer is asynchronous
 * @vcpu: current vcpu descriptor
 * @ev_no: index of record in intc_info_mu buffer
 */
bool intc_mu_record_asynchronous(struct kvm_vcpu *vcpu, int ev_no)
{
	intc_info_mu_t *intc_info_mu = &vcpu->arch.intc_ctxt.mu[ev_no];
	tc_cond_t cond = intc_info_mu->condition;

	return is_record_asynchronous(cond);
}

/*
 * is_in_pm returns:
 * true if guest was intercepted in kernel mode
 * false if guest was intercepted in user mode
 */
static bool is_in_pm(struct pt_regs *regs)
{
	return regs->crs.cr1_lo.CR1_lo_pm;
}

/*
 * Add "dummy" page fault event in guest tcellar
 */
static void add_apf_to_guest_tcellar(struct kvm_vcpu *vcpu)
{
	/* Get pointer to free entries in guest tcellar */
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	int guest_tc_cnt = sw_ctxt->trap_count;
	kernel_trap_cellar_t *guest_tc = ((kernel_trap_cellar_t *)
			vcpu->arch.mmu.tc_kaddr) + guest_tc_cnt/3;
	tc_cond_t condition;
	tc_fault_type_t ftype;

	E2K_KVM_BUG_ON(guest_tc_cnt % 3);

	AW(condition) = 0;
	AW(ftype) = 0;
	AS(condition).store = 0;
	AS(condition).spec = 0;
	AS(condition).fmt = LDST_DWORD_FMT;
	AS(condition).fmtc = 0;
	AS(ftype).page_miss = 1;
	AS(condition).fault_type = AW(ftype);

	guest_tc->condition = condition;

	sw_ctxt->trap_count = guest_tc_cnt + 3;
}

/*
 * Move events which can cause async page fault from intercept buffer
 * to guest tcellar. Leave all other events in intercept buffer.
 */
static void kvm_apf_save_and_clear_intc_mu(struct kvm_vcpu *vcpu)
{
	/* Get pointer to intercept buffer */
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *intc_mu = (intc_info_mu_t *) &vcpu->arch.intc_ctxt.mu;

	/* Get number of entries in guest tcellar */
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	int guest_tc_cnt = sw_ctxt->trap_count;

	E2K_KVM_BUG_ON(guest_tc_cnt % 3);

	/* Get pointer to free entries in guest tcellar */
	kernel_trap_cellar_t *guest_tc = ((kernel_trap_cellar_t *)
			vcpu->arch.mmu.tc_kaddr) + guest_tc_cnt/3;
	kernel_trap_cellar_ext_t *guest_tc_ext =
		((void *) guest_tc) + TC_EXT_OFFSET;

	int e_idx = 0, e_hv_idx = 0, fmt, ev_code;
	intc_info_mu_t hv_intc_mu[INTC_INFO_MU_ITEM_MAX];
	intc_info_mu_t *mu_event;
	tc_opcode_t opcode;


	for (e_idx = 0; e_idx < intc_ctxt->mu_num; e_idx++) {
		ev_code = get_event_code(vcpu, e_idx);

		if ((ev_code <= IME_GPA_DATA) &&
				!intc_mu_record_asynchronous(vcpu, e_idx)) {
			/* Check guest tcellar capacity */
			E2K_KVM_BUG_ON(guest_tc_cnt/3 >= HW_TC_SIZE);

			/* Copy event from intercept buffer to guest tcellar */
			mu_event = &intc_mu[e_idx];
			guest_tc->address = mu_event->gva;
			guest_tc->condition = mu_event->condition;
			AW(opcode) = AS(mu_event->condition).opcode;
			fmt = AS(opcode).fmt;
			if (fmt == LDST_QP_FMT)
				guest_tc_ext->mask = mu_event->mask;

			if (AS(mu_event->condition).store) {
				NATIVE_MOVE_TAGGED_DWORD(&mu_event->data,
						&guest_tc->data);

				if (fmt == LDST_QP_FMT) {
					NATIVE_MOVE_TAGGED_DWORD(
							&mu_event->data_ext,
							&guest_tc_ext->data);
				}
			}
			guest_tc++;
			guest_tc_ext++;
			guest_tc_cnt += 3;
		} else {
			memcpy(&hv_intc_mu[e_hv_idx], &intc_mu[e_idx],
					sizeof(intc_info_mu_t));
			e_hv_idx++;
		}
	}

	/* Set new number of entries in guest tcellar */
	sw_ctxt->trap_count = guest_tc_cnt;

	/* Clear intercept buffer */
	memset(intc_mu, 0, sizeof(intc_info_mu_t) * intc_ctxt->mu_num);

	/* Write remained events back to intercept buffer */
	memcpy(intc_mu, &hv_intc_mu, sizeof(intc_info_mu_t) * e_hv_idx);
	intc_ctxt->mu_num = e_hv_idx;
}

#endif /* CONFIG_KVM_ASYNC_PF */

static u64 inject_new_vcpu_intc_exceptions(struct kvm_vcpu *vcpu,
				u64 to_create, pt_regs_t *regs)
{
	u64 created = 0;

	if (to_create & exc_last_wish_mask) {
		kvm_inject_last_wish(vcpu, regs);
		created |= exc_last_wish_mask;
	}

	if (to_create & exc_software_trap_mask) {
		kvm_inject_software_trap(vcpu, regs);
		created |= exc_software_trap_mask;
	}

	if (to_create & exc_data_page_mask) {
#ifdef CONFIG_KVM_ASYNC_PF
		if (vcpu->arch.apf.enabled &&
				vcpu->arch.apf.host_apf_reason ==
				KVM_APF_PAGE_IN_SWAP) {
			add_apf_to_guest_tcellar(vcpu);
			kvm_apf_save_and_clear_intc_mu(vcpu);
			vcpu->arch.apf.host_apf_reason = KVM_APF_NO;
		}
#endif /* CONFIG_KVM_ASYNC_PF */
		kvm_inject_data_page_exc(vcpu, regs);
		created |= exc_data_page_mask;
	}

	if (to_create & exc_instr_page_miss_mask) {
		kvm_inject_instr_page_exc(vcpu, regs, exc_instr_page_miss_mask,
				vcpu->arch.intc_ctxt.exc_IP_to_create);
		created |= exc_instr_page_miss_mask;
	}

	if (to_create & exc_instr_page_prot_mask) {
		kvm_inject_instr_page_exc(vcpu, regs, exc_instr_page_prot_mask,
				vcpu->arch.intc_ctxt.exc_IP_to_create);
		created |= exc_instr_page_prot_mask;
	}

	if (to_create & exc_ainstr_page_miss_mask) {
		kvm_inject_ainstr_page_exc(vcpu, regs,
				exc_ainstr_page_miss_mask,
				AS(vcpu->arch.intc_ctxt.ctpr2).ta_base);
		created |= exc_ainstr_page_miss_mask;
	}

	if (to_create & exc_ainstr_page_prot_mask) {
		kvm_inject_ainstr_page_exc(vcpu, regs,
				exc_ainstr_page_prot_mask,
				AS(vcpu->arch.intc_ctxt.ctpr2).ta_base);
		created |= exc_ainstr_page_prot_mask;
	}

	/*
	 * Interrupt should be injected last, to the highest non-empty TIR,
	 * but at least to TIR1 (as exc_data_page may register in TIR1 during
	 * GLAUNCH)
	 */
	if (to_create & exc_interrupt_mask) {
		kvm_inject_interrupt(vcpu, regs);
		created |= exc_interrupt_mask;
	}

	if (unlikely(created != to_create)) {
		pr_err("%s() could not inject all exceptions, only 0x%llx "
			"from 0x%llx -> 0x%llx\n",
			__func__, created, to_create, to_create & ~created);
		KVM_WARN_ON(true);
	}
	return created;
}

static void handle_pending_virqs(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	if (likely(!kvm_test_pending_virqs(vcpu))) {
		/* nothing pending VIRQs */
		return;
	}
	if (!kvm_test_inject_direct_guest_virqs(vcpu, NULL,
				vcpu->arch.sw_ctxt.upsr.UPSR_reg,
				regs->crs.cr1_lo.CR1_lo_psr)) {
		/* there are some VIRQs, but cannot be injected right now */
		return;
	}
	if (!(vcpu->arch.intc_ctxt.exceptions & exc_interrupt_mask)) {
		kvm_need_create_vcpu_exception(vcpu, exc_interrupt_mask);
		DebugVIRQs("interrupt is injected on VCPU #%d\n",
			vcpu->vcpu_id);
	}
}

static int handle_cu_exceptions(struct kvm_vcpu *vcpu,
			intc_info_cu_t *cu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	u64 tir_exc, to_delete, to_create, to_pass;
	u64 new_tir_exc;

	handle_pending_virqs(vcpu, regs);

	tir_exc = intc_ctxt->exceptions;
	to_delete = intc_ctxt->exc_to_delete;
	to_create = intc_ctxt->exc_to_create;
	to_pass = intc_ctxt->exc_to_pass;
	if (tir_exc == 0 && to_pass == 0 && to_delete == 0 && to_create == 0) {
		return 0;
	}
	if (unlikely((to_pass & tir_exc) != to_pass)) {
		pr_err("%s(): not all exceptions to pass 0x%llx are present "
			"at TIRs 0x%llx\n",
			__func__, to_pass, tir_exc);
		E2K_KVM_BUG_ON(true);
	}
	if (unlikely((to_delete & tir_exc) != to_delete)) {
		pr_err("%s(): not all exceptions to delete 0x%llx are present "
			"at TIRs 0x%llx\n",
			__func__, to_delete, tir_exc);
		E2K_KVM_BUG_ON(true);
	}
	if (unlikely((to_create & tir_exc) != 0)) {
		pr_err("%s(): not all exceptions to create 0x%llx are not "
			"already present at TIRs 0x%llx -> 0x%llx\n",
			__func__, to_create, tir_exc, to_create & tir_exc);
		E2K_KVM_BUG_ON(true);
	}
	if (unlikely((to_pass & to_delete) != 0)) {
		pr_err("%s(): exceptions to delete 0x%llx and to pass 0x%llx "
			"intersection 0x%llx\n",
			__func__, to_delete, to_pass, to_pass & to_delete);
		E2K_KVM_BUG_ON(true);
	}
	if (unlikely((to_pass & to_create) != 0)) {
		pr_err("%s(): exceptions to create 0x%llx and to pass 0x%llx "
			"intersection 0x%llx\n",
			__func__, to_create, to_pass, to_pass & to_create);
		E2K_KVM_BUG_ON(true);
	}
	if (unlikely((to_delete & to_create) != 0)) {
		pr_err("%s(): exceptions to create 0x%llx and to delete 0x%llx "
			"intersection 0x%llx\n",
			__func__, to_create, to_create, to_create & to_create);
		E2K_KVM_BUG_ON(true);
	}

	new_tir_exc = restore_vcpu_intc_TIRs(vcpu, tir_exc,
				to_pass, to_delete, to_create);
	if (unlikely((new_tir_exc & to_pass) != to_pass)) {
		pr_err("%s(): not all exception to pass 0x%llx "
			"were passed 0x%llx, not passed 0x%llx\n",
			__func__, to_pass, new_tir_exc, new_tir_exc & to_pass);
		E2K_KVM_BUG_ON(true);
	}
	if (unlikely((new_tir_exc & to_delete) != 0)) {
		pr_err("%s(): not all exception to delete 0x%llx "
			"were deleted 0x%llx, not deleted 0x%llx\n",
			__func__, to_delete, new_tir_exc,
			new_tir_exc & to_delete);
		E2K_KVM_BUG_ON(true);
	}
	to_create &= ~new_tir_exc;
	if (to_create != 0) {
		u64 created;

		created = inject_new_vcpu_intc_exceptions(vcpu,
						to_create, regs);
		new_tir_exc |= created;
		intc_ctxt->exceptions |= created;
	}
	DebugTIRs("intercept TIRs of %d num total exc mask 0x%llx, "
		"will be passed to guest\n",
		kvm_get_vcpu_intc_TIRs_num(vcpu), new_tir_exc);

	return 0;
}

static int handle_cu_intercepts(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_cu_t *cu = &intc_ctxt->cu;
	intc_info_cu_hdr_lo_t cu_hdr_lo = cu->header.lo;
	u64 exceptions = intc_ctxt->exceptions;
	int cu_num = intc_ctxt->cu_num;
	int r, ret = 0;

	E2K_KVM_BUG_ON(cu_num < 0);

	/* handle intercepts on conditional events */
	if (cu_hdr_lo.evn_c != 0) {
		r = handle_cu_cond_events(vcpu, cu, regs);
		if (r < 0) {
			ret = r;
			goto out;
		} else if (r == 1) {
			/* it need return to user space to continue handling */
			ret |= 1;
		} else if (r != 0) {
			ret = r;
		}
	}

	/* handle intercepts on unconditional events */
	if (cu_hdr_lo.evn_u != 0) {
		r = handle_cu_uncond_events(vcpu, cu, regs);
		if (r != 0) {
			ret = r;
			goto out;
		}
	}

	/* handle intercepts on conditional exceptions */
	if (cu_hdr_lo.exc_c != 0 || exceptions != 0) {
		r = handle_cu_cond_exceptions(vcpu, cu, regs);
		if (r != 0) {
			ret = r;
			goto out;
		}
	}

	/* check additional info entries to precise events */
	if (cu_num > 0) {
		check_cu_info_entries(vcpu, cu, cu_num);
	}

out:
	/* handle guest CU exceptions to pass to guest */
	r = handle_cu_exceptions(vcpu, cu, regs);
	if (r != 0)
		ret = r;

	return ret;
}

static int soft_reexecute_mu_one_intercept(struct kvm_vcpu *vcpu,
			intc_info_mu_t *mu_event, pt_regs_t *regs)
{
	int event = mu_event->hdr.event_code;
	gpa_t gpa;
	gva_t address;
	tc_cond_t cond;
	tc_fault_type_t ftype;
	bool nonpaging = !is_paging(vcpu);
	int ret;

	gpa = mu_event->gpa;
	address = mu_event->gva;
	cond = mu_event->condition;
	AW(ftype) = AS(cond).fault_type;

	if (unlikely(!nonpaging && !is_shadow_paging(vcpu))) {
		pr_err("%s(): MU %s GVA 0x%lx GPA 0x%llx fault type 0x%x "
			"cannot be software reexecuted\n",
			__func__, kvm_get_mu_event_name(event),
			address, gpa, AW(ftype));
		E2K_KVM_BUG_ON(true);
	}
	DebugREEXECMU("INTC MU event code %d %s GVA 0x%lx GPA 0x%llx "
		"fault type 0x%x\n",
		event, kvm_get_mu_event_name(event), address, gpa, AW(ftype));

	if (nonpaging) {
		/* GPA & GVA should be equal */
		gpa = address;
		mu_event->gpa = gpa;
	}

	ret = mmu_pt_hv_page_fault(vcpu, regs, mu_event);
	if (ret != PFRES_NO_ERR) {
		pr_err("%s(): could not software reexecute %s GVA 0x%lx "
			"GPA 0x%llx fault type 0x%x\n",
			__func__, kvm_get_mu_event_name(event),
			address, gpa, AW(ftype));
		E2K_KVM_BUG_ON(true);
	}
	return 0;
}

static int soft_reexecute_mu_intercepts(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *mu = intc_ctxt->mu;
	int mu_num = intc_ctxt->mu_num;
	unsigned long intc_mu_to_move = intc_ctxt->intc_mu_to_move;
	int evn_no;
	int reexec_num = 0;
	int ret = 0;

	E2K_KVM_BUG_ON(mu_num < 0);

	if (intc_mu_to_move == 0)
		/* nothing to reexecute */
		return 0;

	for (evn_no = 0; evn_no < mu_num; evn_no++) {
		if (intc_mu_to_move & (1UL << evn_no))
			/* intercept should be moved to guest trap cellar */
			/* to handle by guest */
			continue;

		intc_info_mu_t *mu_event = &mu[evn_no];
		int event = mu_event->hdr.event_code;

		DebugREEXECMUV("INTC MU event #%d code %d %s\n",
			evn_no, event, kvm_get_mu_event_name(event));
		switch (event) {
		case IME_FORCED:
		case IME_FORCED_GVA:
			/* should be reexecuted */
			break;
		case IME_SHADOW_DATA:
		case IME_GPA_DATA:
		case IME_GPA_INSTR:
		case IME_GPA_AINSTR:
			/* should be already reexecuted */
			continue;
		default:
			DebugREEXECMU("event #%d %s should not be software "
				"reexecuted\n",
				evn_no, kvm_get_mu_event_name(event));
			continue;
		}
		ret = soft_reexecute_mu_one_intercept(vcpu, mu_event, regs);
		if (ret != 0)
			break;
		reexec_num++;
	}

	DebugREEXECMUV("total number of sofware reexecuted requests %d\n",
		reexec_num);

	return ret;
}

static int handle_mu_one_intercept(struct kvm_vcpu *vcpu,
			intc_info_mu_t *mu_event, pt_regs_t *regs)
{
	int evn_no = vcpu->arch.intc_ctxt.cur_mu;
	int event = mu_event->hdr.event_code;
	mu_intc_handler_t handler;
	int ret;

	DebugINTCMU("INTC MU event code %d %s\n",
		event, kvm_get_mu_event_name(event));

	E2K_KVM_BUG_ON(evn_no < 0 || evn_no >= vcpu->arch.intc_ctxt.mu_num);

	handler = kvm_get_mu_event_handler(event);

	if (handler == NULL) {
		DebugINTCMU("event handler is empty, event is ignored\n");
		return 0;
	}

	ret = handler(vcpu, mu_event, regs);
	if (ret != PFRES_NO_ERR && ret != PFRES_TRY_MMIO) {
		pr_err("%s(): could not handle MMU intercept event %d %s (err %d)\n",
			__func__, event, kvm_get_mu_event_name(event), ret);
		if (event == IME_GPA_INSTR &&
			vcpu->arch.intc_ctxt.mu_num >= 2) {
			pr_err("%s(): ignoring guest trap handler preload\n",
				__func__);
			ret = 0;
		} else {
			print_intc_ctxt(vcpu);
			E2K_KVM_BUG_ON(true);
		}
	}

	return ret;
}

static int try_handle_mu_intercepts(struct kvm_vcpu *vcpu,
					pt_regs_t *regs, bool retry)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_mu_t *mu = intc_ctxt->mu;
	int mu_num = intc_ctxt->mu_num;
	int evn_no;
	int r, ret = 0;

	for (evn_no = 0; evn_no < mu_num; evn_no++) {
		intc_info_mu_t *mu_event = &mu[evn_no];
		int event = mu_event->hdr.event_code;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
		if (unlikely(retry)) {
			intc_mu_state_t *event_state;

			event_state = &intc_ctxt->mu_state[evn_no];
			/* probably some MMU events should be retried */
			if (!event_state->may_be_retried) {
				/* the MMU event is not retried */
				continue;
			}
			if (mmu_notifier_no_retry(vcpu->kvm,
						event_state->notifier_seq)) {
				/* MMU event already uptime */
				continue;
			}
			DebugTRY("retry seq 0x%lx: event #%d code %d : "
				"gpa 0x%lx gva 0x%lx data 0x%lx\n",
				event_state->notifier_seq,
				evn_no, event, mu_event->gpa,
				mu_event->gva, mu_event->data);
		}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
		intc_ctxt->cur_mu = evn_no;
		DebugINTCMU("INTC MU event #%d code %d %s\n",
			evn_no, event, kvm_get_mu_event_name(event));
		DebugINTCMU("hdr 0x%llx gpa 0x%lx gva 0x%lx data 0x%lx\n",
			mu_event->hdr.word, mu_event->gpa, mu_event->gva,
			mu_event->data);
		DebugINTCMU("condition 0x%llx data_ext 0x%lx mask 0x%llx\n",
			mu_event->condition.word, mu_event->data_ext,
			mu_event->mask.word);
		r = handle_mu_one_intercept(vcpu, mu_event, regs);
		if (r != 0)
			ret = r;
	}

	return ret;
}

static int handle_mu_intercepts(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	int mu_num = intc_ctxt->mu_num;
	int ret = 0;
	int try = 0;

	E2K_KVM_BUG_ON(mu_num < 0);

	DebugINTCMU("INTC_INFO_MU total events number %d\n", mu_num);

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER
	do {
		unsigned long mmu_seq;

		mmu_seq = vcpu->kvm->mmu_notifier_seq;
		smp_rmb();
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

		ret = try_handle_mu_intercepts(vcpu, regs, !!(try > 0));

		if (unlikely(ret != 0))
			goto out;

		ret = soft_reexecute_mu_intercepts(vcpu, regs);
		if (unlikely(ret != 0))
			goto out;

#ifdef	KVM_ARCH_WANT_MMU_NOTIFIER

		if (unlikely(mmu_notifier_no_retry(vcpu->kvm, mmu_seq))) {
			/* nothing to retry page faults */
			break;
		}

		mu_num = intc_ctxt->mu_num;
		if (unlikely(mu_num <= 0)) {
			/* INTC_INFO_MU to reexecute and retry is empty */
			break;
		}

		/* host kernel updates some HVA (and probably gfn) mappings */
		/* so probably it need retry some MMU intercepts */
		try++;
		DebugTRY("retry #%d seq 0x%lx:0x%lx to rehandle MU %d "
			"intercept(s)\n",
			try, mmu_seq, vcpu->kvm->mmu_notifier_seq,
			mu_num);

		kvm_mmu_notifier_wait(vcpu->kvm, mmu_seq);
	} while (mu_num > 0);
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */

	return 0;

out:
	return ret;
}

/*
 * Returns 0 to let vcpu_run() continue the guest execution loop without
 * exiting to the userspace. Otherwise, the value will be returned to the
 * userspace.
 * Each intercept handler should return same as the function
 */
noinline /* So that caller's %psr restoring works as intended */
int parse_INTC_registers(struct kvm_vcpu_arch *vcpu)
{
	struct pt_regs regs;
	struct trap_pt_regs trap;
	u64 sbbp[SBBP_ENTRIES_NUM];
	kvm_hw_cpu_context_t *hw_ctxt = &vcpu->hw_ctxt;
	kvm_sw_cpu_context_t *sw_ctxt = &vcpu->sw_ctxt;
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->intc_ctxt;
	intc_info_cu_t *cu = &intc_ctxt->cu;
	int cu_num = intc_ctxt->cu_num, mu_num = intc_ctxt->mu_num;
	e2k_mem_crs_t *frame;
	u64 cu_intc;
	u64 interrupts;
	int ret = 0, ret_mu, ret_cu;
	int r, i;

	/*
	 * We handle interceptions in the following order
	 * (this is similar to parse_TIR_regsiters() since
	 * these two functions do roughly the same thing):
	 * 1) Form pt_regs
	 * 2) Non-maskable interrupts are handled under closed NMIs
	 * 3) Open non-maskable interrupts
	 * 4) Handle maskable interrupts
	 * 5) Open maskable interrupts
	 * 6) Handle MU exceptions
	 * 7) Handle CU exceptions
	 * 8) Remove pt_regs
	 */

	/*
	 * 1) Form pt_regs - they are used by all of our interrupt
	 * handlers. Another way is to replace `hw_ctxt'/`sw_ctxt'
	 * pair in `struct kvm_vcpu_arch' with pt_regs and some new
	 * virtual_pt_regs structure for all the new registers, but
	 * then we will lose the division between hardware-switched
	 * context (hw_ctxt) and software-switched context (sw_ctxt).
	 */

	trap.curr_cnt = -1;
	trap.ignore_user_tc = 0;
	trap.tc_called = 0;
	trap.is_intc = false;
	trap.from_sigreturn = 0;
	trap.tc_count = 0;
	trap.flags = 0;
	CLEAR_CLW_REQUEST_COUNT(&regs);

	memcpy(sbbp, intc_ctxt->sbbp, sizeof(sbbp));
	trap.sbbp = sbbp;

	AW(regs.flags) = 0;
	regs.flags.kvm_hw_intercept = 1;

	regs.trap = &trap;
#ifdef CONFIG_USE_AAU
	regs.aau_context = &sw_ctxt->aau_context;
#endif

	hw_ctxt->sh_psp_lo.PSP_lo_half = READ_SH_PSP_LO_REG_VALUE();
	hw_ctxt->sh_psp_hi.PSP_hi_half = READ_SH_PSP_HI_REG_VALUE();
	hw_ctxt->sh_pcsp_lo.PCSP_lo_half = READ_SH_PCSP_LO_REG_VALUE();
	hw_ctxt->sh_pcsp_hi.PCSP_hi_half = READ_SH_PCSP_HI_REG_VALUE();
	AW(hw_ctxt->sh_pshtp) = READ_SH_PSHTP_REG_VALUE();
	hw_ctxt->sh_pcshtp = READ_SH_PCSHTP_REG_VALUE();

	hw_ctxt->bu_psp_lo.PSP_lo_half = READ_BU_PSP_LO_REG_VALUE();
	hw_ctxt->bu_psp_hi.PSP_hi_half = READ_BU_PSP_HI_REG_VALUE();
	hw_ctxt->bu_pcsp_lo.PCSP_lo_half = READ_BU_PCSP_LO_REG_VALUE();
	hw_ctxt->bu_pcsp_hi.PCSP_hi_half = READ_BU_PCSP_HI_REG_VALUE();
	regs.stacks.psp_lo = hw_ctxt->bu_psp_lo;
	regs.stacks.psp_hi = hw_ctxt->bu_psp_hi;
	regs.stacks.pcsp_lo = hw_ctxt->bu_pcsp_lo;
	regs.stacks.pcsp_hi = hw_ctxt->bu_pcsp_hi;

	trap.nr_TIRs = -1;
	memset(trap.TIRs, 0, sizeof(trap.TIRs[0]));
	if (intc_ctxt->nr_TIRs >= 0) {
		trap.nr_TIRs = intc_ctxt->nr_TIRs;
		memcpy(trap.TIRs, intc_ctxt->TIRs,
			(intc_ctxt->nr_TIRs + 1) * sizeof(trap.TIRs[0]));
	}

	/* This makes sure that user_mode(regs) returns true (thus we
	 * cannot put here real guest SBR since it could be >PAGE_OFFSET). */
	regs.stacks.top = 0;
	AW(regs.stacks.usd_lo) = 0;
	AW(regs.stacks.usd_hi) = 0;

	/* CR registers are used e.g. in perf to get user IP */
	frame = (e2k_mem_crs_t *) (AS(hw_ctxt->bu_pcsp_lo).base +
				   AS(hw_ctxt->bu_pcsp_hi).ind);
	--frame;
	regs.crs = *frame;

	/* Intercepted data page, read guest's trap cellar */
	if (cu->header.lo.exc_data_page)
		NATIVE_SAVE_TRAP_CELLAR(&regs, &trap);

	E2K_KVM_BUG_ON(current_thread_info()->pt_regs == NULL);
	regs.next = current_thread_info()->pt_regs;
	current_thread_info()->pt_regs = &regs;

	trace_kvm_pid(FROM_HV_INTERCEPT, arch_to_vcpu(vcpu)->kvm->arch.vmid.nr,
		arch_to_vcpu(vcpu)->vcpu_id, read_guest_PID_reg(arch_to_vcpu(vcpu)));

	trace_intc_stacks(sw_ctxt, hw_ctxt, frame);

	if (trace_cu_intc_enabled())
		for (i = 0; i < cu_num + 1; i++)
			trace_cu_intc(&intc_ctxt->cu, i);

	if (trace_mu_intc_enabled())
		for (i = 0; i < mu_num; i++)
			trace_mu_intc(&intc_ctxt->mu[i], i);

	if (trace_intc_tir_enabled())
		for (i = 0; i <= trap.nr_TIRs; i++)
			trace_intc_tir(AW(trap.TIRs[i].TIR_lo),
				AW(trap.TIRs[i].TIR_hi));

	trace_intc_ctprs(AW(intc_ctxt->ctpr1), AW(intc_ctxt->ctpr1_hi),
			AW(intc_ctxt->ctpr2), AW(intc_ctxt->ctpr2_hi),
			AW(intc_ctxt->ctpr3), AW(intc_ctxt->ctpr3_hi));

#ifdef CONFIG_USE_AAU
	if (AW(sw_ctxt->aasr))
		trace_intc_aau(&sw_ctxt->aau_context, sw_ctxt->aasr,
				intc_ctxt->lsr, intc_ctxt->lsr1,
				intc_ctxt->ilcr, intc_ctxt->ilcr1);
#endif

#ifdef	CONFIG_CLW_ENABLE
	trace_intc_clw(sw_ctxt->us_cl_d, sw_ctxt->us_cl_b, sw_ctxt->us_cl_up,
		sw_ctxt->us_cl_m0, sw_ctxt->us_cl_m1,
		sw_ctxt->us_cl_m2, sw_ctxt->us_cl_m3);
#endif

	intc_ctxt->exc_to_create = 0;
	intc_ctxt->exc_to_delete = 0;
	intc_ctxt->exc_to_pass = 0;
	intc_ctxt->exc_IP_to_create = 0;
	intc_ctxt->cu_entry_handled = 0;

	interrupts = 0;
	if (cu_num != -1) {
		cu_intc = AW(cu->header.lo);
		interrupts = cu_intc & (intc_cu_hdr_lo_exc_interrupt_mask |
					intc_cu_hdr_lo_exc_nm_interrupt_mask);
		cu_intc &= ~(intc_cu_hdr_lo_exc_interrupt_mask |
				intc_cu_hdr_lo_exc_nm_interrupt_mask);
		AW(cu->header.lo) = cu_intc;
	}

#ifdef CONFIG_KVM_ASYNC_PF
	if (vcpu->apf.enabled)
		vcpu->apf.in_pm = is_in_pm(&regs);
#endif /* CONFIG_KVM_ASYNC_PF */

	/*
	 * 2) Handle NMIs
	 */
	if (unlikely(cu_num != -1 && cu->header.lo.hv_nm_int)) {
		do_nm_interrupt(&regs);
	} else if (interrupts & intc_cu_hdr_lo_exc_nm_interrupt_mask) {
		exc_intc_handler_t handler;

		/* Simulator bug: hypervisor interrupts on guest */
		/* do not cause immediate intercept */
		handler = kvm_get_cond_exc_handler(INTC_CU_EXC_NM_INTERRUPT_NO);
		r = handler(arch_to_vcpu(vcpu), &regs);
		if (r != 0) {
			pr_err("%s(): intercept handler %pF failed, "
				"error %d\n",
				__func__, handler, r);
			E2K_KVM_BUG_ON(true);
		}
		if (intc_ctxt->exceptions & exc_nm_interrupt_mask)
			kvm_need_delete_vcpu_exception(arch_to_vcpu(vcpu),
						exc_nm_interrupt_mask);
	}

	/*
	 * 3) All NMIs have been handled, now we can open them.
	 *
	 * SGE was already disabled by hardware on trap enter.
	 *
	 * We disable NMI in PSR/UPSR here again in case a local_irq_save()
	 * called from an NMI handler enabled it.
	 */
	SET_KERNEL_IRQ_MASK_REG(false	/* enable IRQs */,
				false	/* disable NMI */,
				true	/* set CR1_LO.psr */);
	trace_hardirqs_off();

	/*
	 * 4) Handle external interrupts before enabling interrupts
	 */
	if (cu_num != -1 && cu->header.lo.hv_int) {
		native_do_interrupt(&regs);
	} else if (interrupts & intc_cu_hdr_lo_exc_interrupt_mask) {
		exc_intc_handler_t handler;

		/* Simulator bug: hypervisor interrupts on guest */
		/* do not cause immediate intercept */
		handler = kvm_get_cond_exc_handler(INTC_CU_EXC_INTERRUPT_NO);
		r = handler(arch_to_vcpu(vcpu), &regs);
		if (r != 0) {
			pr_err("%s(): intercept handler %pF failed, "
				"error %d\n",
				__func__, handler, r);
			E2K_KVM_BUG_ON(true);
		}
		if (intc_ctxt->exceptions & exc_interrupt_mask)
			kvm_need_delete_vcpu_exception(arch_to_vcpu(vcpu),
						exc_interrupt_mask);
	}

	/*
	 * 5) Open maskable interrupts
	 *
	 * Nasty hack here: we want to make sure that CEPIC_EPIC_INT interrupt
	 * is always delivered to the current context, otherwise it is very
	 * hard to handle synchronization.  The problem is that a concurrent
	 * interrupts's handler might do a reschedule here:
	 *   kernel_trap_handler() -> preempt_schedule_irq().
	 * So we disable preemption while all interrupts are being handled.
	 */
	preempt_disable();
	local_irq_enable();
	preempt_enable();

	/*
	 * 6) Handle MU exceptions. Currently we handle only those
	 * with GPA and we do _not_ reexecute them: reexecution is
	 * done by hardware for all entries in INTC_INFO_MU registers.
	 */
	if (mu_num > 0) {
		ret_mu = handle_mu_intercepts(arch_to_vcpu(vcpu), &regs);
		if (ret_mu)
			ret = ret_mu;
	}

#ifdef CONFIG_KVM_ASYNC_PF
	if (vcpu->apf.enabled)
		kvm_check_async_pf_completion(arch_to_vcpu(vcpu));
#endif /* CONFIG_KVM_ASYNC_PF */

	/*
	 * 7) Handle CU interceptions
	 */
	if (cu_num != -1)
		ret_cu = handle_cu_intercepts(arch_to_vcpu(vcpu), &regs);
	else
		ret_cu = handle_cu_exceptions(arch_to_vcpu(vcpu), cu, &regs);
	if (ret == 0)
		ret = ret_cu;

	/*
	 * 8) Remove pt_regs - they are not needed anymore
	 */
	current_thread_info()->pt_regs = regs.next;

	return ret;
}
