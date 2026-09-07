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
#include <asm/trap_cellar.h>
#include <asm/trap_table.h>
#include <asm/traps.h>
#include <asm/mmu_regs_access.h>
#include <asm/system.h>
#include <asm/kvm/cpu_hv_regs_types.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_types.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/kvm/process.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/guest/tlb_regs_types.h>
#include <asm/kvm/async_pf.h>
#include <asm/kvm/trace_kvm.h>
#include <asm/kvm/trace_kvm_hv.h>
#include <asm/kvm/gregs.h>

#include "cpu.h"
#include "mmu.h"
#include "process.h"
#include "io.h"
#include "intercepts.h"
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/runstate.h>
#include "paravirt_sw/cpu_defs.h"
#include "paravirt_sw/mmu_defs.h"
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

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
#define	DEBUG_INTC_REEXEC_MODE		0	/* reexecute MMU intercepts debug */
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

#undef	DEBUG_INTC_CU_IDR_MODE
#undef	DebugINTC_IDR
#define	DEBUG_INTC_CU_IDR_MODE	0	/* IDR reguster access intercept */
					/* events debug mode */
#define	DebugINTC_IDR(fmt, args...)					\
({									\
	if (DEBUG_INTC_CU_IDR_MODE)					\
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
#define	DEBUG_PF_RETRY_MODE		0	/* retry page fault debug */
#define	DebugTRY(fmt, args...)						\
({									\
	if (DEBUG_PF_RETRY_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_FORCED_MODE
#undef	DebugPFFORCED
#define	DEBUG_PF_FORCED_MODE		0	/* forced page fault event debug */
#define	DebugPFFORCED(fmt, args...)					\
({									\
	if (DEBUG_PF_FORCED_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PF_EXC_RPR_MODE
#undef	DebugEXCRPR
#define	DEBUG_PF_EXC_RPR_MODE		0	/* page fault at recovery mode debug */
#define	DebugEXCRPR(fmt, args...)					\
({									\
	if (DEBUG_PF_EXC_RPR_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE		0	/* VIRQs injection debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COREDUMP_MODE
#undef	DebugCDUMP
#define	DEBUG_KVM_COREDUMP_MODE	0	/* coredump VCPUs state debugging */
#define	DebugCDUMP(fmt, args...)					\
({									\
	if (DEBUG_KVM_COREDUMP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static void print_intc_ctxt(struct kvm_vcpu *vcpu);

static noinline notrace int
do_unsupported_intc(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	pr_err("%s(): unsupported intercept in INTC_INFO_CU\n", __func__);
	return -ENOSYS;
}

/* Interception table. */
const exc_intc_handler_t intc_exc_table[INTC_CU_COND_EXC_MAX] = {
	[0 ... INTC_CU_COND_EXC_MAX - 1] =
			(exc_intc_handler_t)(do_unsupported_intc)
};

const cond_exc_info_t cond_exc_info_table[INTC_CU_COND_EXC_MAX] = {
	{
		.no		= INTC_CU_EXC_INSTR_DEBUG_NO,
		.exc_mask	= exc_instr_debug_mask,
		.name		= "exc_instr_debug",
	},
	{
		.no		= INTC_CU_EXC_DATA_DEBUG_NO,
		.exc_mask	= exc_data_debug_mask,
		.name		= "exc_data_debug",
	},
	{
		.no		= INTC_CU_EXC_INSTR_PAGE_NO,
		.exc_mask	= exc_instr_page_miss_mask |
					exc_instr_page_prot_mask |
					exc_ainstr_page_miss_mask |
					exc_ainstr_page_prot_mask,
		.name		= "exc instr/ainstr page miss/prot",
	},
	{
		.no		= INTC_CU_EXC_DATA_PAGE_NO,
		.exc_mask	= exc_data_page_mask,
		.name		= "exc_data_page",
	},
	{
		.no		= INTC_CU_EXC_MOVA_NO,
		.exc_mask	= exc_mova_ch_0_mask |
					exc_mova_ch_1_mask |
					exc_mova_ch_2_mask |
					exc_mova_ch_3_mask,
		.name		= "exc_mova_ch_#0/1/2/3",
	},
	{
		.no		= INTC_CU_EXC_INTERRUPT_NO,
		.exc_mask	= exc_interrupt_num,
		.name		= "exc_interrupt",
	},
	{
		.no		= INTC_CU_EXC_NM_INTERRUPT_NO,
		.exc_mask	= exc_nm_interrupt_num,
		.name		= "exc_nm_interrupt",
	},
	{
		.no		= -1,
		.exc_mask	= 0,
		.name		= "reserved",
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
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
static int do_tlb_line_flush_intc_mu(struct kvm_vcpu *vcpu,
			intc_info_mu_t *intc_info_mu, pt_regs_t *regs);
#endif

static noinline notrace int
do_unsupported_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;

	pr_err("%s(): unsupported MMU event intercept code %d %s\n",
		__func__, event, kvm_get_mu_event_name(vcpu, event));
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
		.code	= IME_FORCED,
		.handler	= do_forced_data_page_intc_mu,
		.name	= "empty: forced",
	},
	{
		.code	= IME_FORCED_GVA,
		.handler	= do_forced_gva_data_page_intc_mu,
		.name	= "empty: page fault GVA->GPA",
	},
	{
		.code	= IME_SHADOW_DATA,
		.handler	= do_shadow_data_page_intc_mu,
		.name	= "data page on shadow PT",
	},
	{
		.code	= IME_GPA_DATA,
		.handler	= do_data_page_intc_mu,
		.name	= "data page fault GPA->PA",
	},
	{
		.code	= IME_GPA_INSTR,
		.handler	= do_instr_page_intc_mu,
		.name	= "instr page fault",
	},
	{
		.code	= IME_GPA_AINSTR,
		.handler	= do_ainstr_page_intc_mu,
		.name	= "async instr page fault",
	},
	{
		.code	= IME_RESERVED_6,
		.handler	= do_reserved_intc_mu,
		.name	= "reserved #6",
	},
	{
		.code	= IME_RESERVED_7,
		.handler	= do_reserved_intc_mu,
		.name	= "reserved #7",
	},
	{
		.code	= IME_MAS_IOADDR,
		.handler	= do_unsupported_intc_mu,
		.name	= "GPA/IO address access",
	},
	{
		.code	= IME_READ_MU,
		.handler	= do_read_mmu_intc_mu,
		.name	= "read MMU register",
	},
	{
		.code	= IME_WRITE_MU,
		.handler	= do_write_mmu_reg_intc_mu,
		.name	= "write MMU register",
	},
	{
		.code	= IME_CACHE_FLUSH,
		.handler	= do_unsupported_intc_mu,
		.name	= "cache flush operation",
	},
	{
		.code	= IME_CACHE_LINE_FLUSH,
		.handler	= do_unsupported_intc_mu,
		.name	= "cache line flush operation",
	},
	{
		.code	= IME_ICACHE_FLUSH,
		.handler	= do_unsupported_intc_mu,
		.name	= "instr cache flush operation",
	},
	{
		.code	= IME_ICACHE_LINE_FLUSH_USER,
		.handler	= do_unsupported_intc_mu,
		.name	= "user instr cache flush operation",
	},
	{
		.code	= IME_ICACHE_LINE_FLUSH_SYSTEM,
		.handler	= do_unsupported_intc_mu,
		.name	= "system instr cache flush operation",
	},
	{
		.code	= IME_TLB_FLUSH,
		.handler	= do_unsupported_intc_mu,
		.name	= "TLB flush operation",
	},
	{
		.code	= IME_TLB_PAGE_FLUSH_LAST,
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
		.handler	= do_tlb_line_flush_intc_mu,
#else
		.handler	= do_unsupported_intc_mu,
#endif
		.name	= "main TLB page flush operation",
	},
	{
		.code	= IME_TLB_PAGE_FLUSH_UPPER,
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
		.handler	= do_tlb_line_flush_intc_mu,
#else
		.handler	= do_unsupported_intc_mu,
#endif
		.name	= "upper level TLB page flush operation",
	},
	{
		.code	= IME_TLB_ENTRY_PROBE,
		.handler	= do_unsupported_intc_mu,
		.name	= "TLB entry probe operation",
	},
};

static int instr_page_fault_intc_mu(struct kvm_vcpu *vcpu,
				    intc_info_mu_t *intc_info_mu,
				    pt_regs_t *regs, bool async_instr)
{
	intc_mu_state_t *mu_state = get_intc_mu_state(vcpu);
	struct trap_pt_regs *trap = regs->trap;
	gpa_t gpa;
	gva_t address;
	tc_cond_t cond;
	tc_fault_type_t ftype;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	bool nonpaging = !is_paging(vcpu);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	const char *trap_name;
	u32 error_code;

	gpa = intc_info_mu->gpa;
	address = intc_info_mu->gva;
	cond = intc_info_mu->condition;
	AW(ftype) = cond.fault_type;

	DebugIPINTC("intercept on %s instr page, IP gpa 0x%llx gva 0x%lx, fault type 0x%x\n",
		    (async_instr) ? "async" : "sync", gpa, address, AW(ftype));

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (likely(!nonpaging)) {
		/* paging mode */
		if (is_shadow_paging(vcpu)) {
			/* GP_* PT can be used only to data access */
		} else if (is_phys_paging(vcpu)) {
			address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_EXEC_MASK, NULL, NULL);
		} else {
			E2K_KVM_BUG_ON(true);
		}
	} else {
		/* nonpaging mode, all addresses should be physical */
		if (is_phys_paging(vcpu)) {
			address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_EXEC_MASK, NULL, NULL);
		} else if (is_shadow_paging(vcpu)) {
			/* GP_* PT is not used, GPA is not set by HW */
			address = nonpaging_gva_to_gpa(vcpu, address, ACC_EXEC_MASK, NULL, NULL);
		} else
		{
			E2K_KVM_BUG_ON(true);
		}
	}
#else
	if (WARN_ON_ONCE(!is_phys_paging(vcpu)))
		return -EINVAL;

	address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_EXEC_MASK, NULL, NULL);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	error_code = PFERR_INSTR_FAULT_MASK | PFERR_PT_FAULT_MASK;
	if (ftype.page_miss) {
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "instr_page_miss";
	} else if (ftype.prot_page) {
		trap->nr_page_fault_exc = exc_instr_page_prot_num;
		error_code |= PFERR_NOT_PRESENT_MASK | PFERR_INSTR_PROT_MASK;
		trap_name = "instr_page_prot";
	} else if (ftype.illegal_page) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		E2K_KVM_BUG_ON(is_shadow_paging(vcpu) && !nonpaging);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "illegal_instr_page";
	} else if (AW(ftype) == 0) {
		trap->nr_page_fault_exc = exc_instr_page_miss_num;
		error_code |= PFERR_NOT_PRESENT_MASK;
		trap_name = "empty_fault_type_instr_page";
	} else {
		pr_err("%s(): bad fault type 0x%x, probably it need pass fault to guest\n",
			__func__, AW(ftype));
		return -EINVAL;
	}

	DebugIPINTC("intercept on %s fault, IP 0x%lx\n", trap_name, address);

	mu_state->may_be_retried = true;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	mu_state->ignore_notifier = false;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	return kvm_mmu_instr_page_fault(vcpu, address, async_instr, error_code);
}

static int do_instr_page_intc_mu(struct kvm_vcpu *vcpu,
				 intc_info_mu_t *intc_info_mu,
				 pt_regs_t *regs)
{
	return instr_page_fault_intc_mu(vcpu, intc_info_mu, regs, false);
}

static int do_ainstr_page_intc_mu(struct kvm_vcpu *vcpu,
				  intc_info_mu_t *intc_info_mu,
				  pt_regs_t *regs)
{
	return instr_page_fault_intc_mu(vcpu, intc_info_mu, regs, true);
}

static int do_forced_data_page_intc_mu(struct kvm_vcpu *vcpu,
				       intc_info_mu_t *intc_info_mu,
				       pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;
	tc_cond_t cond = intc_info_mu->condition;
	int fmt = tc_cond_fmt_full(cond);
	int cur_mu = vcpu->arch.intc_ctxt.cur_mu;
	bool ss_under_rpr;
	bool root = cond.root;	/* secondary space */
	bool ignore_store = false;	/* the store should not be reexecuted */
	intc_info_mu_t *prev_mu;

	DebugPFFORCED("event code %d %s: GVA 0x%lx, GPA 0x%lx, condition 0x%llx\n",
		event, kvm_get_mu_event_name(vcpu, event),
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	/* Bug 146747: speculative AAU loads can cause spurious intercepts */
	if (cur_mu == 0) {
		if (tc_cond_is_vector_aau(cond) && cond.spec && !cond.store) {
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
		DebugPFFORCED("No accsess to secondary space in generation (RPR) mode, ignored\n");
		return 0;
	}

	ignore_store = tc_cond_is_store(cond);
	if (!ignore_store) {
		DebugPFFORCED("Load from secondary space in generation (RPR) mode, will be reexecuted\n");
		return 0;
	}

	DebugEXCRPR("event code %d %s: %s secondary space at recovery mode: GVA 0x%lx, GPA 0x%lx, cond 0x%016llx\n",
		event, kvm_get_mu_event_name(vcpu, event),
		ignore_store ? (cond.store ? "store to"
					: "load with store semantics to")
				: "load from",
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	if ((fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP)) {
		prev_mu = &vcpu->arch.intc_ctxt.mu[cur_mu - 1];
		if (prev_mu->hdr.event_code == 1) {
			DebugEXCRPR("leaving qword access to secondary space at recovery mode for guest to handle\n");

			return 0;
		}
	}

	/* mark the INTC_INFO_MU event as deleted to avoid */
	/* hardware reexucution of the store operation */
	kvm_delete_intc_info_mu(vcpu, intc_info_mu);
	DebugEXCRPR("access to secondary space at recovery mode will not be reexecuted by hardware\n");

	return 0;
}

static int do_forced_gva_data_page_intc_mu(struct kvm_vcpu *vcpu,
		intc_info_mu_t *intc_info_mu, pt_regs_t *regs)
{
	int event = intc_info_mu->hdr.event_code;
	tc_cond_t cond = intc_info_mu->condition;
	bool ss_under_rpr;
	bool root = cond.root;		/* secondary space */
	bool ignore_store = false;	/* the store should not be reexecuted */

	DebugPFFORCED("event code %d %s: GVA 0x%lx, GPA 0x%lx, condition 0x%llx\n",
		event, kvm_get_mu_event_name(vcpu, event),
		intc_info_mu->gva, intc_info_mu->gpa, AW(cond));

	ss_under_rpr = root && kvm_has_vcpu_exc_recovery_point(vcpu);

	if (likely(!ss_under_rpr)) {
		DebugPFFORCED("No accsess to secondary space in generation (RPR) mode, ignored\n");
		return 0;
	}

	ignore_store = tc_cond_is_store(cond);
	if (!ignore_store) {
		DebugPFFORCED("Load from secondary space in generation (RPR) mode, will be reexecuted\n");
		return 0;
	}

	DebugEXCRPR("event code %d %s: %s secondary space at recovery mode: GVA 0x%lx, GPA 0x%lx, cond 0x%016llx\n",
		event, kvm_get_mu_event_name(vcpu, event),
		ignore_store ? (cond.store ? "store to"
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

	gpa = intc_info_mu->gpa;
	address = intc_info_mu->gva;
	cond = intc_info_mu->condition;
	AW(ftype) = cond.fault_type;

	DebugPFINTC("intercept on data page fault, gpa 0x%llx gva 0x%lx, fault type 0x%x\n",
		gpa, address, AW(ftype));

	if (!is_phys_paging(vcpu)) {
		pr_err("%s(): intercept on GPA->PA translation fault, but GP_* tables disabled\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}

	address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_ALL, NULL, NULL);

	return mmu_pt_hv_page_fault(vcpu, regs, intc_info_mu);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static int do_shadow_data_page_intc_mu(struct kvm_vcpu *vcpu,
				       intc_info_mu_t *intc_info_mu,
				       pt_regs_t *regs)
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
	AW(ftype) = cond.fault_type;

	DebugPFINTC("intercept on data page fault, gpa 0x%llx gva 0x%lx, fault type 0x%x\n",
		gpa, address, AW(ftype));

	if (!is_shadow_paging(vcpu)) {
		pr_err("%s(): intercept on shadow PT translation fault, but shadow PT mode is disabled\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	if (nonpaging && is_phys_paging(vcpu)) {
		pr_err("%s(): should be intercept on GPA->PA translation fault, GP_* tables enabled\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	if (nonpaging)
		address = nonpaging_gva_to_gpa(vcpu, gpa, ACC_ALL, NULL, NULL);

	ret = mmu_pt_hv_page_fault(vcpu, regs, intc_info_mu);
	if (ret != PFRES_NO_ERR && ret != PFRES_TRY_MMIO) {
		pr_info("%s(): could not handle intercept on data page fault\n",
			__func__);
		E2K_KVM_BUG_ON(true);
	}
	return ret;
}
#else
static int do_shadow_data_page_intc_mu(struct kvm_vcpu *vcpu,
				       intc_info_mu_t *intc_info_mu,
				       pt_regs_t *regs)
{
	return -ENOTSUPP;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
static int do_tlb_line_flush_intc_mu(struct kvm_vcpu *vcpu,
				     intc_info_mu_t *intc_info_mu,
				     pt_regs_t *regs)
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
	if (! !(flush_addr & FLUSH_ADDR_PHYS)) {
		gva = gfn_to_gpa(gva);
	}

	kvm_mmu_flush_gva(vcpu, gva);

	return 0;
}
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */

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
	return vcpu_write_mmu_cr_reg(vcpu, (e2k_mmu_cr_t) {.word = intc_info_mu->data});
}

#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
static int write_mmu_u_pptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int write_mmu_os_pptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int write_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_u_vptb_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_os_vptb_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_os_vab_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_os_vab_reg(vcpu, intc_info_mu->data);
}

static int write_mmu_pid_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	return vcpu_write_mmu_pid_reg(vcpu, intc_info_mu->data);
}
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */

static int write_mmu_hw0_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	e2k_mu_hw0_t old_mu_hw0, new_mu_hw0;

	old_mu_hw0 = mmu->mu_hw0;
	AW(new_mu_hw0) = intc_info_mu->data;
	if (AW(old_mu_hw0) == AW(new_mu_hw0)) {
		/* the same registers state, so nothing to do */
		return 0;
	}

	/* probably here should be analysis of updated modes */
	mmu->mu_hw0 = new_mu_hw0;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
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

static int write_mmu_ss_pid_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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
		DebugMMUSSREG("MMU guest secondary space is not changed PID: 0x%llx\n", pid);
		return 0;
	}

	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */

static int read_trap_point_mmu_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int read_mmu_hw0_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	intc_info_mu->data = AW(mmu->mu_hw0);
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
static int read_mmu_u_pptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int read_mmu_pid_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
{
	mmu_reg_t pid;
	int r;

	r = vcpu_read_mmu_pid_reg(vcpu, &pid);
	if (r != 0)
		return r;

	intc_info_mu->data = (pgprotval_t)pid;
	kvm_set_intc_info_mu_is_updated(vcpu);

	return 0;
}

static int read_mmu_os_pptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int read_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int read_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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

static int read_mmu_os_vab_reg(struct kvm_vcpu *vcpu, intc_info_mu_t *intc_info_mu)
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
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */

static int do_write_mmu_reg_intc_mu(struct kvm_vcpu *vcpu,
				    intc_info_mu_t *intc_info_mu,
				    pt_regs_t *regs)
{
	mmu_addr_t reg_addr = intc_info_mu->gva;
	int mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(reg_addr);
	e2k_mas_t mas;

	E2K_KVM_BUG_ON(intc_info_mu->hdr.event_code != IME_WRITE_MU);

	AW(mas) = intc_info_mu->condition.mas;

	switch (mas.masf1.opc) {
	case MAS_OPC_DTLB_REG:
	case MAS_OPC_L1_REG:
	case MAS_OPC_L2_REG:
	case MAS_OPC_ICACHE_REG:
		/* Ignore */
		return 0;
	case MAS_OPC_MMU_REG:
		switch (mmu_reg_no) {
		case _MMU_TRAP_POINT_NO:
			return write_trap_point_mmu_reg(vcpu, intc_info_mu);
		case _MMU_CR_NO:
			return write_mmu_cr_reg(vcpu, intc_info_mu);
		case _MMU_HW0_NO:
			return write_mmu_hw0_reg(vcpu, intc_info_mu);
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
		case _MMU_U_PPTB_NO:
			return write_mmu_u_pptb_reg(vcpu, intc_info_mu);
		case _MMU_OS_PPTB_NO:
			return write_mmu_os_pptb_reg(vcpu, intc_info_mu);
		case _MMU_U2_PPTB_NO:
		case _MMU_MPT_B_NO:
		case _MMU_PDPTE0_NO:
		case _MMU_PDPTE1_NO:
		case _MMU_PDPTE2_NO:
		case _MMU_PDPTE3_NO:
			return write_mmu_ss_ptb_reg(vcpu, intc_info_mu, mmu_reg_no);
		case _MMU_U_VPTB_NO:
			return write_mmu_u_vptb_reg(vcpu, intc_info_mu);
		case _MMU_OS_VPTB_NO:
			return write_mmu_os_vptb_reg(vcpu, intc_info_mu);
		case _MMU_OS_VAB_NO:
			return write_mmu_os_vab_reg(vcpu, intc_info_mu);
		case _MMU_PID_NO:
			return write_mmu_pid_reg(vcpu, intc_info_mu);
		case _MMU_PID2_NO:
			return write_mmu_ss_pid_reg(vcpu, intc_info_mu);
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */
		default:
			goto unimplemented;
		}
	default:
unimplemented:
		pr_err("%s(): unimplemented MMU register 0x%x (address 0x%lx, opc 0x%x) write intercept\n",
				__func__, mmu_reg_no, reg_addr, mas.masf1.opc);
		return -ENOSYS;
	}
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
	case _MMU_HW0_NO:
		ret = read_mmu_hw0_reg(vcpu, intc_info_mu);
		break;
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
	case _MMU_U_PPTB_NO:
		ret = read_mmu_u_pptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_OS_PPTB_NO:
		ret = read_mmu_os_pptb_reg(vcpu, intc_info_mu);
		break;
	case _MMU_PID_NO:
		ret = read_mmu_pid_reg(vcpu, intc_info_mu);
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
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */
	default:
		pr_err("%s(): unimplemented MMU register 0x%x (address 0x%lx) read intercept\n",
		       __func__, mmu_reg_no, mmu_reg_addr);
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

	if (!kvm_debug) {
		intc_info_mu->data = 0;
		return 0;
	}

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
	mmu_addr_t reg_addr = intc_info_mu->gva;
	e2k_mas_t mas;

	E2K_KVM_BUG_ON(intc_info_mu->hdr.event_code != IME_READ_MU);

	AW(mas) = intc_info_mu->condition.mas;

	switch (mas.masf1.opc) {
	case MAS_OPC_L1_REG:
	case MAS_OPC_L2_REG:
	case MAS_OPC_ICACHE_REG:
		/* Ignore; these are diagnostic registers so returning 0 is OK */
		intc_info_mu->data = 0;
		return 0;
	case MAS_OPC_DAM_REG:
		check_virt_ctrl_mu_rr_dbg1();

		if ((reg_addr & REG_DAM_TYPE) == REG_DAM_TYPE) {
			return read_dam_reg_intc_mu(vcpu, intc_info_mu, regs);
		} else if ((reg_addr & REG_MLT_TYPE) == REG_MLT_TYPE) {
			return read_mlt_reg_intc_mu(vcpu, intc_info_mu, regs);
		} else {
			pr_err("%s(): not implemented special MMU or AAU operation type, opc 0x%x, addr 0x%lx\n",
			       __func__, mas.masf1.opc, reg_addr);
			return -EINVAL;
		}
	case MAS_OPC_DTLB_REG:
		return read_dtlb_reg_intc_mu(vcpu, intc_info_mu, regs);
	case MAS_OPC_MMU_REG:
		return read_mmu_reg_intc_mu(vcpu, intc_info_mu, regs);
	default:
		pr_err("%s(): not implemented special MMU or AAU operation type, opc 0x%x\n",
		       __func__, mas.masf1.opc);
		return -EINVAL;
	}
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
		LO(intc_ctxt->cu.header), HI(intc_ctxt->cu.header));
	pr_alert("CU entry0: lo 0x%llx; hi 0x%llx\n",
		 LO(intc_ctxt->cu.entry[0]), HI(intc_ctxt->cu.entry[0]));
	pr_alert("CU entry1: lo 0x%llx; hi 0x%llx\n",
		 LO(intc_ctxt->cu.entry[1]), HI(intc_ctxt->cu.entry[1]));

	for (evn_no = 0; evn_no < mu_num; evn_no++) {
		intc_info_mu_t *mu_event = &mu[evn_no];
		int event = mu_event->hdr.event_code;

		pr_alert("MU entry %d: code %d %s\n"
			 "hdr 0x%llx gpa 0x%lx gva 0x%lx\n"
			 "condition 0x%llx mask 0x%llx\n",
			 evn_no, event, kvm_get_mu_event_name(vcpu, event),
			 mu_event->hdr.word, mu_event->gpa, mu_event->gva,
			 mu_event->condition.word, mu_event->mask.word);
	}

	print_all_TIRs(intc_ctxt->TIRs, intc_ctxt->nr_TIRs);
}

static void rr_idr_handler(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	e2k_idr_t idr = kvm_vcpu_get_idr(vcpu);
	entry->hi = AW(idr);
	DebugINTC_IDR("IDR replaced with value 0x%llx\n", idr.word);
}

static void intc_wait_trap(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	/* Go to scheduler to wait for a wake up event. */
	DebugWTR("VCPU #%d interception on wait trap, block and wait for wake up\n",
			vcpu->vcpu_id);
	kvm_vcpu_srcu_read_unlock(vcpu);
	kvm_vcpu_block(vcpu);
	kvm_vcpu_srcu_read_lock(vcpu);
	vcpu->arch.unhalted = false;
	DebugWTR("VCPU #%d has been woken up, so run guest again\n", vcpu->vcpu_id);
}

static int handle_cu_rr(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	switch (entry->reg_num) {
	case SCLKR_cu_reg_no:
		kvm_sclkr_read(vcpu, entry);
		return 0;
	case SCLKM1_cu_reg_no:
		kvm_sclkm1_read(vcpu, entry);
		return 0;
	case SCLKM2_cu_reg_no:
		kvm_sclkm2_read(vcpu, entry);
		return 0;
	case IDR_cu_reg_no:
		rr_idr_handler(vcpu, entry);
		return 0;
	case CU_HW0_cu_reg_no:
	case CU_HW1_cu_reg_no:
		/* Allow guest to see real CU_HW0/CU_HW1 value */
		return 0;
	default:
		pr_err("kvm: register 0x%x read is not allowed\n", entry->reg_num);
		return -ENOTSUPP;
	}
}

static int handle_cu_rw(struct kvm_vcpu *vcpu, intc_info_cu_entry_t *entry)
{
	switch (entry->reg_num) {
	case SCLKR_cu_reg_no:
		kvm_sclkr_write(vcpu, entry);
		return 0;
	case SCLKM1_cu_reg_no:
		kvm_sclkm1_write(vcpu, entry);
		return 0;
	case SCLKM2_cu_reg_no:
		kvm_sclkm2_write(vcpu, entry);
		return 0;
	case SCLKM3_cu_reg_no:
		kvm_sclkm3_write(vcpu, entry);
		return 0;
	case CU_HW0_cu_reg_no:
	case CU_HW1_cu_reg_no:
		/* Do not allow guest to change CU_HW{0/1} value, this
		 * register is not intended to be changed dynamically */
		entry->event_code = ICE_FORCED;
		return 0;
	case CU_PMGR0_cu_reg_no:
		if (!cpu_has(CPU_FEAT_ISET_V7))
			goto error;
		entry->event_code = ICE_FORCED;
		return 0;
	default:
error:
		pr_err("kvm: register 0x%x write is not allowed\n", entry->reg_num);
		return -EINVAL;
	}
}

static int handle_cu_cond_exceptions(struct kvm_vcpu *vcpu,
				     intc_info_cu_t *cu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	kvm_hw_cpu_context_t *hw_ctxt = &vcpu->arch.hw_ctxt;
	intc_info_cu_hdr_t *header = &cu->header;
	exc_intc_handler_t handler;
	int exc_no;
	u64 cond_exc_mask, tir_exc_mask;
	int r;
	bool exit_ioctl = false;

	for (exc_no = 0; exc_no < INTC_CU_COND_EXC_MAX; exc_no++) {
		cond_exc_mask = 1ULL << exc_no;
		tir_exc_mask = kvm_cond_exc_no_to_exc_mask(vcpu, exc_no);

		/* Check if there was no interception... */
		if (!(header->exc_c & cond_exc_mask)) {
			if (/* ...while the exception did occur... */
			    (intc_ctxt->exceptions & tir_exc_mask) &&
			    /* ...and it was duly visible in TIRs... */
			    !cu->header.tir_fz &&
			    /* ...but was not intercepted although it was expected to be */
			    (hw_ctxt->virt_ctrl_cu.exc_c & cond_exc_mask)) {
				pr_err("Has interception enabled for exception 0x%llx (%s), but it was not intercepted, virt_ctrl_cu.exc_c=0x%x\n",
					cond_exc_mask, kvm_cond_exc_no_to_exc_name(vcpu, exc_no),
					hw_ctxt->virt_ctrl_cu.exc_c);
				return -ENOTSUPP;
			}

			/* No interception to handle */
			continue;
		}

		/* Check if there was interception...*/
		if ((header->exc_c & cond_exc_mask) &&
		    /* ...which was not expected */
		    !(hw_ctxt->virt_ctrl_cu.exc_c & cond_exc_mask)) {
			pr_err("Unexpected interception of conditional exception 0x%llx (%s), expected mask 0x%x\n",
				cond_exc_mask, kvm_cond_exc_no_to_exc_name(vcpu, exc_no),
				hw_ctxt->virt_ctrl_cu.exc_c);
			return -ENOTSUPP;
		}

		/* Check if there was interception...*/
		if ((header->exc_c & cond_exc_mask) &&
		    /* ...without matching exception */
		    !(tir_exc_mask & intc_ctxt->exceptions)) {
			pr_err("Interception of exception 0x%llx (%s) without exception in TIRs (0x%llx)\n",
				cond_exc_mask, kvm_cond_exc_no_to_exc_name(vcpu, exc_no),
				intc_ctxt->exceptions);
			return -ENOTSUPP;
		}

		handler = kvm_get_cond_exc_handler(vcpu, exc_no);
		r = handler(vcpu, regs);
		if (r < 0) {
			pr_err("%s(): conditional exception #%d %s intercept handler %pF failed, error %d\n",
				__func__, exc_no, kvm_cond_exc_no_to_exc_name(vcpu, exc_no),
				handler, r);
			return r;
		} else if (r != 0) {
			/* Return to user space */
			exit_ioctl = true;
		}
	}
	return exit_ioctl ? 1 : 0;
}

/*
 * The function returns new mask of total exceptions (including AAU)
 * at all TIRs
 */
static u64 restore_vcpu_intc_TIRs(struct kvm_vcpu *vcpu,
				  u64 TIRs_exc, u64 to_pass, u64 to_delete,
				  u64 to_create)
{
	int TIRs_num, TIR_no, last_valid_TIR_no = -1;
	e2k_tir_t TIR;
	u64 TIRs_aa, aa_to_pass, aa_to_delete, aa_to_create;
	u64 new_TIRs_exc = 0;
	u64 new_TIRs_aa = 0;
	bool aa_valid;

	TIRs_num = kvm_get_vcpu_intc_TIRs_num(vcpu);
	E2K_KVM_BUG_ON(TIRs_exc != 0 && TIRs_num < 0);
	TIRs_aa = (e2k_tir_t) { .exc_al_aa_j = TIRs_exc }.aa;
	aa_to_pass = (e2k_tir_t) { .exc_al_aa_j = to_pass }.aa;
	aa_to_delete =  (e2k_tir_t) { .exc_al_aa_j = to_delete }.aa;
	aa_to_create = (e2k_tir_t) { .exc_al_aa_j = to_create }.aa;
	aa_valid = (TIRs_aa || aa_to_pass || aa_to_delete || aa_to_create);

	for (TIR_no = 0; TIR_no <= TIRs_num; TIR_no++) {
		u64 exc, tir_exc, pass, delete, create, new_exc, new_aa;

		TIR = kvm_get_vcpu_intc_TIR(vcpu, TIR_no);
		exc = TIR.exc;
		tir_exc = exc & TIRs_exc;
		pass = exc & to_pass;
		delete = exc & to_delete;
		create = exc & to_create;
		new_exc = pass | create;
		new_exc |= (tir_exc & ~delete);
		DebugTIRs("TIR[%d]: source exc 0x%llx. intersections with TIRs 0x%llx\n"
			" pass 0x%llx delete 0x%llx create 0x%llx  -> new exc 0x%llx\n",
			  TIR_no, exc, tir_exc, pass, delete, create, new_exc);
		if (aa_valid) {
			u64 aa, tir_aa, aa_pass, aa_delete, aa_create;

			aa = TIR.aa;
			tir_aa = aa & TIRs_aa;
			aa_pass = aa & aa_to_pass;
			aa_delete = aa & aa_to_delete;
			aa_create = aa & aa_to_create;
			new_aa = aa_pass | aa_create;
			new_aa |= (tir_aa & ~aa_delete);
			DebugTIRs("TIR[%d]: source aa 0x%llx. intersections with TIRs 0x%llx\n"
				"pass 0x%llx delete 0x%llx create 0x%llx -> new aa 0x%llx\n",
				  TIR_no, aa, tir_aa, aa_pass, aa_delete,
				  aa_create, new_aa);
		} else {
			new_aa = 0;
		}
		TIR.exc = new_exc;
		TIR.aa = new_aa;
		new_TIRs_exc |= new_exc;
		new_TIRs_aa |= new_aa;
		if (new_exc || new_aa)
			last_valid_TIR_no = TIR_no;
		kvm_set_vcpu_intc_TIR(vcpu, TIR_no, TIR);
		DebugTIRs("TIR[%d].hi: exc 0x%llx alu 0x%x aa 0x%x #%d\n"
			  "TIR[%d].lo: IP 0x%llx\n",
			  TIR_no, TIR.exc, TIR.al, TIR.aa, TIR.j, TIR_no,
			  TIR.ip);
	}

	if (last_valid_TIR_no < TIRs_num)
		kvm_set_vcpu_intc_TIRs_num(vcpu, last_valid_TIR_no);

	if (vcpu->arch.intc_ctxt.nr_TIRs < 0) {
		DebugTIRs("intercept TIRs are empty to pass to guest\n");
		WARN_ON_ONCE(new_TIRs_exc || new_TIRs_aa);
		return 0;
	}
	DebugTIRs("intercept TIRs of %d num total exc mask 0x%llx,\n"
		  "aa 0x%llx will be passed to guest\n",
		  kvm_get_vcpu_intc_TIRs_num(vcpu), new_TIRs_exc, new_TIRs_aa);
	TIR.exc_al_aa_j = 0;
	TIR.exc = new_TIRs_exc;
	TIR.aa = new_TIRs_aa;
	return TIR.exc_al_aa_j;
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
	return regs->crs.cr1.pm;
}

/*
 * Add "dummy" page fault event in guest tcellar
 */
static void add_apf_to_guest_tcellar(struct kvm_vcpu *vcpu)
{
	/* Get pointer to free entries in guest tcellar */
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	int guest_tc_cnt = sw_ctxt->trap_count;
	kernel_trap_cellar_t *guest_tc =
			((kernel_trap_cellar_t *)vcpu->arch.mmu.tc_kaddr) + guest_tc_cnt / 3;
	tc_cond_t condition;
	tc_fault_type_t ftype;

	E2K_KVM_BUG_ON(guest_tc_cnt % 3);

	AW(condition) = 0;
	AW(ftype) = 0;
	condition.store = 0;
	condition.spec = 0;
	condition.fmt = LDST_DWORD_FMT;
	condition.fmtc = 0;
	ftype.page_miss = 1;
	condition.fault_type = AW(ftype);

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
	intc_info_mu_t *intc_mu = (intc_info_mu_t *) & vcpu->arch.intc_ctxt.mu;

	/* Get number of entries in guest tcellar */
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	int guest_tc_cnt = sw_ctxt->trap_count;

	E2K_KVM_BUG_ON(guest_tc_cnt % 3);

	/* Get pointer to free entries in guest tcellar */
	kernel_trap_cellar_t *guest_tc =
			((kernel_trap_cellar_t *)vcpu->arch.mmu.tc_kaddr) + guest_tc_cnt / 3;
	kernel_trap_cellar_ext_t *guest_tc_ext =
	    ((void *)guest_tc) + TC_EXT_OFFSET;

	int e_idx = 0, e_hv_idx = 0, fmt, ev_code;
	intc_info_mu_t hv_intc_mu[INTC_INFO_MU_ITEM_MAX];
	intc_info_mu_t *mu_event;
	tc_opcode_t opcode;

	for (e_idx = 0; e_idx < intc_ctxt->mu_num; e_idx++) {
		ev_code = get_event_code(vcpu, e_idx);

		if ((ev_code <= IME_GPA_DATA) &&
		    !intc_mu_record_asynchronous(vcpu, e_idx)) {
			/* Check guest tcellar capacity */
			E2K_KVM_BUG_ON(guest_tc_cnt / 3 >= HW_TC_SIZE);

			/* Copy event from intercept buffer to guest tcellar */
			mu_event = &intc_mu[e_idx];
			guest_tc->address = mu_event->gva;
			guest_tc->condition = mu_event->condition;
			AW(opcode) = mu_event->condition.opcode;
			fmt = opcode.fmt;
			if (fmt == LDST_QP_FMT)
				guest_tc_ext->mask = mu_event->mask;

			if (mu_event->condition.store) {
				NATIVE_MOVE_TAGGED_DWORD(&mu_event->data, &guest_tc->data);

				if (fmt == LDST_QP_FMT) {
					NATIVE_MOVE_TAGGED_DWORD(&mu_event->data_ext,
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
		    vcpu->arch.apf.host_apf_reason == KVM_APF_PAGE_IN_SWAP) {
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
					   vcpu->arch.intc_ctxt.ctpr2.ta_base);
		created |= exc_ainstr_page_miss_mask;
	}

	if (to_create & exc_ainstr_page_prot_mask) {
		kvm_inject_ainstr_page_exc(vcpu, regs,
					   exc_ainstr_page_prot_mask,
					   vcpu->arch.intc_ctxt.ctpr2.ta_base);
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

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static void handle_pending_virqs(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	if (likely(!kvm_test_pending_virqs(vcpu))) {
		/* nothing pending VIRQs */
		return;
	}
	if (!kvm_test_inject_direct_guest_virqs(vcpu, NULL,
						AW(vcpu->arch.sw_ctxt.upsr),
						regs->crs.cr1.psr)) {
		/* there are some VIRQs, but cannot be injected right now */
		return;
	}
	if (!(vcpu->arch.intc_ctxt.exceptions & exc_interrupt_mask)) {
		kvm_need_create_vcpu_exception(vcpu, exc_interrupt_mask);
		DebugVIRQs("interrupt is injected on VCPU #%d\n",
			   vcpu->vcpu_id);
	}
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static void handle_cu_exceptions(struct kvm_vcpu *vcpu,
				intc_info_cu_t *cu, pt_regs_t *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	u64 tir_exc, to_create;
	u64 new_tir_exc;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	handle_pending_virqs(vcpu, regs);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	tir_exc = intc_ctxt->exceptions;
	to_create = intc_ctxt->exc_to_create;
	if (tir_exc == 0 && to_create == 0) {
		return;
	}
	if (unlikely((to_create & tir_exc) != 0)) {
		pr_err("%s(): not all exceptions to create 0x%llx are not\n"
		       "already present at TIRs 0x%llx -> 0x%llx\n",
		       __func__, to_create, tir_exc, to_create & tir_exc);
		E2K_KVM_BUG_ON(true);
	}

	new_tir_exc = restore_vcpu_intc_TIRs(vcpu, tir_exc,
					     0, 0, to_create);
	to_create &= ~new_tir_exc;
	if (to_create != 0) {
		u64 created;

		created = inject_new_vcpu_intc_exceptions(vcpu, to_create, regs);
		new_tir_exc |= created;
		intc_ctxt->exceptions |= created;
	}
	DebugTIRs("intercept TIRs of %d num total exc mask 0x%llx, will be passed to guest\n",
		  kvm_get_vcpu_intc_TIRs_num(vcpu), new_tir_exc);
}

static int handle_cu_intercepts(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_cu_t *cu = &intc_ctxt->cu;
	intc_info_cu_hdr_t header = cu->header;
	int cu_num = intc_ctxt->cu_num;
	int ret = 0;
	bool exit_ioctl = false;

	if (cu_num < 0) {
		WARN_ON_ONCE(cu_num != -1);
		handle_cu_exceptions(vcpu, cu, regs);
		return 0;
	}

	if (header.hret_last_wish) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		ret = intc_hret_last_wish(vcpu, regs);
		if (ret < 0) {
			pr_err("%s [%d]: conditional event HRET last wish intercept handler failed, error %d\n",
				current->comm, current->pid, ret);
			return ret;
		}
		if (ret > 0) {
			/* Return to user space to handle intercept (exit) reason */
			ret = 0;
			exit_ioctl = true;
		}
#else
		pr_err("%s [%d]: unknown reason for HRET last wish intercept\n",
				current->comm, current->pid);
#endif
		header.hret_last_wish = 0;
	}

	if (header.virt) {
		pr_err("%s [%d]: unexpected virtualization resources access\n",
				current->comm, current->pid);
		print_intc_ctxt(vcpu);
		return -EINVAL;
	}

	if (header.hv_int || header.hv_nm_int) {
		/* Should be handled already so ignore here */
		header.hv_int = 0;
		header.hv_nm_int = 0;
	}

	if (header.wait_trap) {
		intc_wait_trap(vcpu, regs);
		header.wait_trap = 0;
	}

	if (header.dbg) {
		/*
		 * Can be sent by:
		 * - simulator, with -bI option
		 * - JTAG, when manually switching to hypervisor mode after
		 *   stop_hard in guest
		 */
		coredump_in_future();
		vcpu->arch.intc_ctxt.coredump = true;
		header.dbg = 0;
	}

	if (header.exc_mem_error) {
		header.exc_mem_error = 0;
		do_mem_error(regs);
		return -EFAULT;
	}

	if (header.g_tmr) {
		/* Ignore G_PREEMPT_TMR */
		header.g_tmr = 0;
	}

	/* Handle intercepted events */
	for (int i = 0; i < cu_num; i++) {
		intc_info_cu_entry_t *entry = &cu->entry[i];

		switch (entry->event_code) {
		case ICE_FORCED:
			/* Nothing to handle */
			ret = 0;
			break;
		case ICE_READ_CU:
			ret = handle_cu_rr(vcpu, entry);
			break;
		case ICE_WRITE_CU:
			ret = handle_cu_rw(vcpu, entry);
			break;
		case ICE_MASKED_HCALL:
		case ICE_GLAUNCH:
		case ICE_HRET:
			/* Inform just in case but do not terminate guest: guest's
			 * user must not be able to terminate guest's kernel. */
			pr_err_ratelimited("%s [%d]: unexpected INTC_INFO_CU entry %llx:%llx\n",
					current->comm, current->pid, entry->lo, entry->hi);
			ret = 0;
			break;
		default:
			pr_err_ratelimited("%s [%d]: unknown event code %d at INTC_INFO_CU[%d]\n",
					current->comm, current->pid, entry->event_code, i);
			ret = -EINVAL;
		}
		if (ret)
			return ret;
	}
	header.rr = 0;
	header.rw = 0;
	header.hcem = 0;
	header.rr_idr = 0;
	header.rr_sclkr = 0;
	header.rw_sclkr = 0;
	header.rw_sclkm3 = 0;

	if (header.evn_u || header.evn_c) {
		pr_err_ratelimited("%s [%d]: CU intercept is not implemented, evn_c=0x%x evn_u=0x%x\n",
				current->comm, current->pid, header.evn_c, header.evn_u);
		return -ENOTSUPP;
	}

	if (cpu_has(CPU_HWBUG_INTC_INFO_CU_0)) {
		int i = 0;

		while (i < cu_num) {
			intc_info_cu_entry_t *entry = &cu->entry[i];

			if (entry->event_code != ICE_FORCED) {
				i += 1;
			} else {
				memmove(entry, &cu->entry[i + 1],
					(cu_num - i - 1) * sizeof(*entry));
				cu_num -= 1;
			}
		}

		intc_ctxt->cu_num = cu_num;
	}

	/* handle intercepts on conditional exceptions */
	if (header.exc_c || intc_ctxt->exceptions) {
		ret = handle_cu_cond_exceptions(vcpu, cu, regs);
	} else {
		ret = 0;
	}

	/* handle guest CU exceptions to pass to guest */
	handle_cu_exceptions(vcpu, cu, regs);

	return ret < 0 ? ret : !!exit_ioctl;
}

static int handle_mu_one_intercept(struct kvm_vcpu *vcpu,
				   intc_info_mu_t *mu_event, pt_regs_t *regs)
{
	int evn_no = vcpu->arch.intc_ctxt.cur_mu;
	int event = mu_event->hdr.event_code;
	mu_intc_handler_t handler;
	int ret;

	DebugINTCMU("INTC MU event code %d %s\n",
		event, kvm_get_mu_event_name(vcpu, event));

	E2K_KVM_BUG_ON(evn_no < 0 || evn_no >= vcpu->arch.intc_ctxt.mu_num);

	handler = kvm_get_mu_event_handler(vcpu, event);

	if (handler == NULL) {
		DebugINTCMU("event handler is empty, event is ignored\n");
		return 0;
	}

	ret = handler(vcpu, mu_event, regs);
	if (ret == 0 || ret == PFRES_TRY_MMIO)
		return ret;

	pr_err("%s(): could not handle MMU intercept event %d %s (err %d)\n",
		__func__, event, kvm_get_mu_event_name(vcpu, event), ret);

	if (event == IME_GPA_INSTR && vcpu->arch.intc_ctxt.mu_num >= 2) {
		pr_err("%s(): ignoring guest trap handler preload\n", __func__);
		return 0;
	}

	vcpu->arch.exit_reason = EXIT_REASON_VM_PANIC;

	return ret;
}

static int try_handle_mu_intercepts(struct kvm_vcpu *vcpu, pt_regs_t *regs, bool retry)
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
			if (mmu_notifier_no_retry(vcpu->kvm, event_state->notifier_seq)) {
				/* MMU event already uptime */
				continue;
			}
			DebugTRY("retry seq 0x%lx: event #%d code %d : gpa 0x%lx gva 0x%lx\n",
				event_state->notifier_seq, evn_no, event,
				mu_event->gpa, mu_event->gva);
		}
#endif	/* KVM_ARCH_WANT_MMU_NOTIFIER */
		intc_ctxt->cur_mu = evn_no;
		DebugINTCMU("INTC MU event #%d code %d %s\n"
			    "hdr 0x%llx gpa 0x%lx gva 0x%lx\n"
			    "condition 0x%llx mask 0x%llx\n",
			    evn_no, event, kvm_get_mu_event_name(vcpu, event),
			    mu_event->hdr.word, mu_event->gpa, mu_event->gva,
			    mu_event->condition.word, mu_event->mask.word);
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

		mmu_seq = vcpu->kvm->mmu_invalidate_seq;
		smp_rmb();
#endif /* KVM_ARCH_WANT_MMU_NOTIFIER */

		ret = try_handle_mu_intercepts(vcpu, regs, !!(try > 0));

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
			try, mmu_seq, vcpu->kvm->mmu_invalidate_seq,
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
noinline	/* So that caller's %psr restoring works as intended */
int parse_INTC_registers(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct pt_regs regs;
	struct trap_pt_regs trap;
	kvm_hw_cpu_context_t *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	kvm_intc_cpu_context_t *intc_ctxt = &vcpu->arch.intc_ctxt;
	intc_info_cu_t *cu = &intc_ctxt->cu;
	int cu_num = intc_ctxt->cu_num, mu_num = intc_ctxt->mu_num;
	e2k_mem_crs_t *frame;
	intc_info_cu_hdr_t cu_hdr;
	int ret = 0, ret_mu, ret_cu, i;

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
	trap.tc_count = 0;
	trap.flags = 0;

	memcpy(&trap.sbbp, intc_ctxt->sbbp, sizeof(trap.sbbp));

	AW(regs.flags) = 0;
	regs.flags.kvm_hw_intercept = 1;

	regs.trap = &trap;
	regs.aau_context = &sw_ctxt->aau_context;

	hw_ctxt->sh_psp = read_SH_PSP_reg();
	hw_ctxt->sh_pcsp = read_SH_PCSP_reg();
	hw_ctxt->sh_pshtp = read_SH_PSHTP_reg();
	hw_ctxt->sh_pcshtp = read_SH_PCSHTP_reg();

	hw_ctxt->bu_psp = read_BU_PSP_reg();
	hw_ctxt->bu_pcsp = read_BU_PCSP_reg();
	regs.stacks.psp = hw_ctxt->bu_psp;
	regs.stacks.pcsp = hw_ctxt->bu_pcsp;

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
	regs.stacks.usd = (e2k_usd_t) {0};

	/* CR registers are used e.g. in perf to get user IP */
	frame = K_PCSP_PTR(hw_ctxt->bu_pcsp);
	--frame;
	regs.crs = *frame;

	/* Intercepted data page, read guest's trap cellar */
	if (cu->header.exc_data_page)
		NATIVE_SAVE_TRAP_CELLAR(&regs, &trap);

	E2K_KVM_BUG_ON(current_thread_info()->pt_regs == NULL);
	regs.next = current_thread_info()->pt_regs;
	current_thread_info()->pt_regs = &regs;

	trace_kvm_pid(FROM_HV_INTERCEPT, kvm->arch.vm_id, vcpu->vcpu_id, read_guest_PID_reg(vcpu));

	trace_intc_stacks(sw_ctxt, hw_ctxt, frame, kvm->arch.guest_info.cpu_iset);

	if (trace_cu_intc_enabled()) {
		for (i = 0; i < cu_num + 1; i++)
			trace_cu_intc(&intc_ctxt->cu, i);
	}

	if (trace_mu_intc_enabled() || trace_mu_intc_tdp_enabled()) {
		for (i = 0; i < mu_num; i++) {
			trace_mu_intc(&intc_ctxt->mu[i], i);

			int type = intc_ctxt->mu[i].hdr.event_code;
			if (type == IME_GPA_DATA || is_tdp_paging(vcpu) &&
					(type == IME_GPA_INSTR || type == IME_GPA_AINSTR))
				trace_mu_intc_tdp(vcpu, intc_ctxt->mu[i].gpa);
		}
	}

	if (trace_intc_tir_enabled()) {
		for (i = 0; i <= trap.nr_TIRs; i++)
			trace_intc_tir(LO(trap.TIRs[i]), HI(trap.TIRs[i]));
	}

	trace_intc_ctprs(&intc_ctxt->ctpr1, &intc_ctxt->ctpr2, &intc_ctxt->ctpr3);

	if (AW(sw_ctxt->aasr)) {
		trace_intc_aau(&sw_ctxt->aau_context, sw_ctxt->aasr,
			       intc_ctxt->lsr, intc_ctxt->lsr1,
			       intc_ctxt->ilcr, intc_ctxt->ilcr1);
	}
#ifdef	CONFIG_CLW_ENABLE
	trace_intc_clw(sw_ctxt->us_cl_d, sw_ctxt->us_cl_b, sw_ctxt->us_cl_up,
		       sw_ctxt->us_cl_m0, sw_ctxt->us_cl_m1,
		       sw_ctxt->us_cl_m2, sw_ctxt->us_cl_m3);
#endif

	intc_ctxt->exc_to_create = 0;
	intc_ctxt->exc_IP_to_create = 0;

	if (cu_num != -1) {
		cu_hdr = cu->header;
		cu->header.exc_interrupt = 0;
		cu->header.exc_nm_interrupt = 0;
	} else {
		cu_hdr.exc_interrupt = 0;
		cu_hdr.exc_nm_interrupt = 0;
	}

#ifdef CONFIG_KVM_ASYNC_PF
	if (vcpu->arch.apf.enabled)
		vcpu->arch.apf.in_pm = is_in_pm(&regs);
#endif /* CONFIG_KVM_ASYNC_PF */

	/*
	 * 2) Handle NMIs
	 */
	if (unlikely(cu_num != -1 && cu->header.hv_nm_int)) {
		do_nm_interrupt(&regs);
	}

	/*
	 * 3) All NMIs have been handled, now we can open them.
	 *
	 * SGE was already disabled by hardware on trap enter.
	 *
	 * We disable NMI in PSR/UPSR here again in case a local_irq_save()
	 * called from an NMI handler enabled it.
	 */
	SET_KERNEL_IRQ_MASK_REG(false /* enable IRQs */ ,
				false /* disable NMI */ ,
				true /* set CR1_LO.psr */ );

	/*
	 * 4) Handle external interrupts before enabling interrupts
	 */
	if (cu_num != -1 && cu->header.hv_int) {
		native_do_interrupt(&regs);
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
		ret_mu = handle_mu_intercepts(vcpu, &regs);
		if (ret_mu)
			ret = ret_mu;
	}
#ifdef CONFIG_KVM_ASYNC_PF
	if (vcpu->arch.apf.enabled)
		kvm_check_async_pf_completion(vcpu);
#endif /* CONFIG_KVM_ASYNC_PF */

	/*
	 * 7) Handle CU interceptions
	 */
	ret_cu = handle_cu_intercepts(vcpu, &regs);
	if (ret == 0)
		ret = ret_cu;

	/*
	 * 8) Remove pt_regs - they are not needed anymore
	 */
	current_thread_info()->pt_regs = regs.next;

	return ret;
}
