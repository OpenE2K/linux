/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Defenition of traps handling routines.
 */

#ifndef _E2K_KVM_TTABLE_H
#define _E2K_KVM_TTABLE_H

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>
#include <asm/ptrace.h>

#include <asm/signal.h>

#ifdef	CONFIG_KVM_HOST_MODE
/* it is native kernel with virtualization support (hypervisor) */

#include <asm/kvm/trace_kvm_pv.h>
#include "cpu.h"
#include "mmutrace-e2k.h"
#include "trace-gmm.h"

#undef	DEBUG_PV_UST_MODE
#undef	DebugUST
#define	DEBUG_PV_UST_MODE	0	/* trap injection debugging */
#define	DebugUST(fmt, args...)						\
({									\
	if (debug_guest_ust)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif /* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#define	CHECK_GUEST_SYSCALL_UPDATES

#ifdef	CHECK_GUEST_VCPU_UPDATES

#define	DebugKVMGT(fmt, args...)					\
		pr_err("%s(): " fmt, __func__, ##args)

static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	{
		e2k_addr_t sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_t usd = kvm_get_guest_vcpu_USD(vcpu);

		if (LO(usd) != LO(regs->stacks.usd) ||
		    HI(usd) != HI(regs->stacks.usd)
		    sbr != regs->stacks.top) {
			DebugKVMGT("FAULT: source USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				vcpu_usd_base(vcpu, regs->stacks.usd),
				vcpu_usd_ind(vcpu, regs->stacks.usd),
				(u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
			DebugKVMGT("NOT updated USD: base 0x%llx ind 0x%llx, size 0x%x\n",
				vcpu_usd_base(vcpu, usd), vcpu_usd_ind(vcpu, usd),
				(u64)sbr - vcpu_usd_base(vcpu, usd));
		}
	}
	{
		e2k_psp_t psp = kvm_get_guest_vcpu_PSP(vcpu);
		e2k_pcsp_t pcsp = kvm_get_guest_vcpu_PCSP(vcpu);

		if (vcpu_psp_base(vcpu, psp) != vcpu_psp_base(vcpu, regs->stacks.psp) ||
		    vcpu_psp_size(vcpu, psp) != vcpu_psp_size(vcpu, regs->stacks.psp)) {
			/* PSP_hi_ind/PCSP_hi_ind can be modified and should */
			/* be restored as saved at regs state */
			DebugKVMGT("FAULT: source  PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_psp_base(vcpu, regs->stacks.psp),
				vcpu_psp_size(vcpu, regs->stacks.psp),
				vcpu_psp_ind(vcpu, regs->stacks.psp));
			DebugKVMGT("NOT updated    PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_psp_base(vcpu, psp), vcpu_psp_size(vcpu, psp),
				vcpu_psp_ind(vcpu, psp));
		}
		if (vcpu_pcsp_base(vcpu, pcsp) != vcpu_pcsp_base(vcpu, regs->stacks.pcsp) ||
		    vcpu_pcsp_size(vcpu, pcsp) != vcpu_pcsp_size(vcpu, regs->stacks.pcsp)) {
			DebugKVMGT("FAULT: source  PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
				vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
				vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
			DebugKVMGT("NOT updated    PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_pcsp_base(vcpu, pcsp), vcpu_pcsp_size(vcpu, pcsp),
				vcpu_pcsp_ind(vcpu, pcsp));
		}
	}
	{
		e2k_cr0_t cr0 = kvm_get_guest_vcpu_CR0(vcpu);
		e2k_cr1_t cr1 = kvm_get_guest_vcpu_CR1(vcpu);

		if (LO(cr0) != LO(regs->crs.cr0) ||
		    HI(cr0) != HI(regs->crs.cr0) ||
		    LO(cr1) != LO(regs->crs.cr1) ||
		    HI(cr1) != HI(regs->crs.cr1)) {
			DebugKVMGT("FAULT: source  CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo.wbs 0x%x CR1 ussz 0x%llx\n",
				   LO(regs->crs.cr0), HI(regs->crs.cr0),
				   regs->crs.cr1._wbs,
				   get_cr1_ussz(regs->crs.cr1));
			DebugKVMGT("NOT updated    CR0.lo 0x%016lx CR0.hi 0x%016lx CR1.lo.wbs 0x%x CR1 ussz 0x%llx\n",
				    LO(cr0), HI(cr0), cr1.wbs,
				    get_cr1_ussz(cr1));
		}
	}
}

#else /* ! CHECK_GUEST_VCPU_UPDATES */
static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
}
#endif /* CHECK_GUEST_VCPU_UPDATES */

static inline void
restore_guest_trap_stack_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	unsigned long regs_status = kvm_get_guest_vcpu_regs_status(vcpu);

	if (!KVM_TEST_UPDATED_CPU_REGS_FLAGS(regs_status)) {
		DebugKVMVGT("competed: nothing updated");
		goto check_updates;
	}

	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, WD_UPDATED_CPU_REGS)) {
		e2k_wd_t wd = kvm_get_guest_vcpu_WD(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (wd.psize != regs->wd.psize) {
			DebugKVMGT("source  WD: size 0x%x\n", regs->wd.psize);
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->wd.psize = wd.psize;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated WD: size 0x%x\n", regs->wd.psize);
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
		unsigned long sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_t usd = kvm_get_guest_vcpu_USD(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (vcpu_usd_ptr(vcpu, usd) != vcpu_usd_ptr(vcpu, regs->stacks.usd) ||
		    vcpu_usd_ind(vcpu, usd) != vcpu_usd_ind(vcpu, regs->stacks.usd) ||
		    sbr != regs->stacks.top) {
			DebugKVMGT("source  USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				   vcpu_usd_base(vcpu, regs->stacks.usd),
				   vcpu_usd_ind(vcpu, regs->stacks.usd),
				   (u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
#endif /* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.usd = usd;
			regs->stacks.top = sbr;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				   vcpu_usd_base(vcpu, regs->stacks.usd),
				   vcpu_usd_ind(vcpu, regs->stacks.usd),
				   (u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
		}
#endif /* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status,
					   HS_REGS_UPDATED_CPU_REGS)) {
		e2k_psp_t psp = kvm_get_guest_vcpu_PSP(vcpu);
		e2k_pcsp_t pcsp = kvm_get_guest_vcpu_PCSP(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (psp != regs->stacks.psp)
			DebugKVMGT("source  PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_psp_base(vcpu, regs->stacks.psp),
				   vcpu_psp_size(vcpu, regs->stacks.psp),
				   vcpu_psp_ind(vcpu, regs->stacks.psp));
#endif /* CHECK_GUEST_VCPU_UPDATES */

		regs->stacks.psp = psp;

#ifdef	CHECK_GUEST_VCPU_UPDATES
		DebugKVMGT("updated PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
			   vcpu_psp_base(vcpu, regs->stacks.psp),
			   vcpu_psp_size(vcpu, regs->stacks.psp),
			   vcpu_psp_ind(vcpu, regs->stacks.psp));
	}
#endif /* CHECK_GUEST_VCPU_UPDATES */

#ifdef	CHECK_GUEST_VCPU_UPDATES
	if (pcsp != regs->stacks.pcsp)
		DebugKVMGT("source  PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
			   vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
			   vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
			   vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
#endif /* CHECK_GUEST_VCPU_UPDATES */

	regs->stacks.pcsp = pcsp;

#ifdef	CHECK_GUEST_VCPU_UPDATES
	DebugKVMGT("updated PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
		   vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
		   vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
		   vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
}
#endif /* CHECK_GUEST_VCPU_UPDATES */
}

if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
	e2k_cr0_t cr0 = kvm_get_guest_vcpu_CR0(vcpu);
	e2k_cr1_t cr1 = kvm_get_guest_vcpu_CR1(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
	if (LO(cr0) != LO(regs->crs.cr0) ||
	    HI(cr0) != HI(regs->crs.cr0) ||
	    LO(cr1) != LO(regs->crs.cr1) || HI(cr1) != HI(regs->crs.cr1)) {
		DebugKVMGT("source  CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.wbs 0x%x ussz of CR1 0x%llx\n",
			   LO(regs->crs.cr0), HI(regs->crs.cr0),
			   regs->crs.cr1.wbs, get_cr1_ussz(regs->crs.cr1));
#endif /* CHECK_GUEST_VCPU_UPDATES */

		regs->crs.cr0 = cr0;
		regs->crs.cr1 = cr1;

#ifdef	CHECK_GUEST_VCPU_UPDATES
		DebugKVMGT("updated CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%llx\n",
			   LO(regs->crs.cr0), HI(regs->crs.cr0),
			   regs->crs.cr1.wbs, get_cr1_ussz(regs->crs.cr1));
	}
#endif /* CHECK_GUEST_VCPU_UPDATES */
}
kvm_reset_guest_updated_vcpu_regs_flags(vcpu, regs_status);

check_updates:
check_guest_stack_regs_updates(vcpu, regs);
}

static inline void
restore_guest_syscall_stack_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	unsigned long regs_status = kvm_get_guest_vcpu_regs_status(vcpu);

	if (unlikely(regs->sys_num == __NR_e2k_longjmp2)) {
		/*
		 * The guest long jump has been updated stack & CRs registers
		 * and has called hypercall to update all registers state
		 * on host at signal stack context.
		 * Update harware CRs registers values, stcak register will
		 * be updated later before return to user
		 */
		NATIVE_RESTORE_USER_CRs(regs);
		kvm_reset_guest_vcpu_regs_status(vcpu);
		return;
	}

	if (unlikely(regs->sys_num == __NR_setcontext))
		NATIVE_RESTORE_USER_CRs(regs);

	regs_status = kvm_get_guest_vcpu_regs_status(vcpu);

	if (!KVM_TEST_UPDATED_CPU_REGS_FLAGS(regs_status)) {
		DebugKVMVGT("competed: there is nothing updated");
		goto check_updates;
	}

	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, WD_UPDATED_CPU_REGS)) {
		e2k_wd_t wd = kvm_get_guest_vcpu_WD(vcpu);

		if (wd.psize != regs->wd.psize) {
			DebugKVMGT("source  WD: size 0x%x\n", regs->wd.psize);

#ifndef	CHECK_GUEST_SYSCALL_UPDATES
			regs->wd.psize = wd.psize;
			DebugKVMGT("updated WD: size 0x%x\n", regs->wd.psize);
#else /* CHECK_GUEST_SYSCALL_UPDATES */
			E2K_LMS_HALT_OK;
			pr_err("%s(): guest updated WD, but it is not yet supported case\n",
				__func__);
			E2K_KVM_BUG_ON(true);
#endif /* !CHECK_GUEST_SYSCALL_UPDATES */

		}
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
		unsigned long sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_t usd = kvm_get_guest_vcpu_USD(vcpu);

		if (LO(usd) != LO(regs->stacks.usd) ||
		    HI(usd) != HI(regs->stacks.usd) ||
		    sbr != regs->stacks.top) {
			DebugKVMGT("source  USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				   vcpu_usd_base(vcpu, regs->stacks.usd),
				   vcpu_usd_ind(vcpu, regs->stacks.usd),
				   (u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));

#ifndef	CHECK_GUEST_SYSCALL_UPDATES
			regs->stacks.usd = usd;
			regs->stacks.top = sbr;
			DebugKVMGT("updated USD: base 0x%llx ind 0x%llx size 0x%llx\n",
				   vcpu_usd_base(vcpu, regs->stacks.usd),
				   vcpu_usd_ind(vcpu, regs->stacks.usd),
				   (u64)regs->stacks.top - vcpu_usd_base(vcpu, regs->stacks.usd));
#else /* CHECK_GUEST_SYSCALL_UPDATES */
			DebugKVMGT("%s(): guest updated stack USD/SBR, but it is not yet supported case\n",
				__func__);
			DebugKVMGT("host  USD: base 0x%llx size 0x%llx top 0x%llx\n",
				vcpu_usd_ptr(vcpu, regs->stacks.usd),
				vcpu_usd_ind(vcpu, regs->stacks.usd),
				(u64)regs->stacks.top);
			DebugKVMGT("guest USD: base 0x%llx size 0x%llx top 0x%llx\n",
				vcpu_usd_ptr(vcpu, usd), vcpu_usd_ind(vcpu, usd), (u64) sbr);
#endif /* !CHECK_GUEST_SYSCALL_UPDATES */
		}
	}

	/* hardware stacks registers should be updated by hypercall as */
	/* for long jump case, so ignore guest register updated state here */
#ifdef	CHECK_GUEST_SYSCALL_UPDATES
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status,
					   HS_REGS_UPDATED_CPU_REGS)) {
		e2k_psp_t psp = kvm_get_guest_vcpu_PSP(vcpu);
		e2k_pcsp_t pcsp = kvm_get_guest_vcpu_PCSP(vcpu);
		e2k_pshtp_t pshtp = regs->stacks.pshtp;
		e2k_pcshtp_t pcshtp = regs->stacks.pcshtp;

		if (vcpu_psp_base(vcpu, psp) != vcpu_psp_base(vcpu, regs->stacks.psp) ||
		    vcpu_psp_ind(vcpu, psp) != vcpu_psp_ind(vcpu, regs->stacks.psp) -
						PSHTP_MEM_INDEX(pshtp) ||
		    vcpu_psp_size(vcpu, psp) != vcpu_psp_size(vcpu, regs->stacks.psp)) {
			DebugKVMGT("source PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_psp_base(vcpu, regs->stacks.psp),
				   vcpu_psp_size(vcpu, regs->stacks.psp),
				   vcpu_psp_ind(vcpu, regs->stacks.psp));
			DebugKVMGT("%s(): guest updated proc stack PSP, but it is not yet supported case\n",
				__func__);
			DebugKVMGT("host  PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_psp_base(vcpu, regs->stacks.psp),
				vcpu_psp_size(vcpu, regs->stacks.psp),
				vcpu_psp_ind(vcpu, regs->stacks.psp) - PSHTP_MEM_INDEX(pshtp));
			DebugKVMGT("guest PSP:  base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_psp_base(vcpu, psp), vcpu_psp_size(vcpu, psp),
				vcpu_psp_ind(vcpu, psp));
		}

		if (vcpu_pcsp_base(vcpu, pcsp) != vcpu_pcsp_base(vcpu, regs->stacks.pcsp) ||
			    vcpu_pcsp_ind(vcpu, pcsp) != vcpu_pcsp_ind(vcpu, regs->stacks.pcsp) -
									     pcshtp.ind ||
			    vcpu_pcsp_size(vcpu, pcsp) != vcpu_pcsp_size(vcpu, regs->stacks.pcsp)) {
			DebugKVMGT("source  PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				   vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
				   vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
				   vcpu_pcsp_ind(vcpu, regs->stacks.pcsp));
			DebugKVMGT("%s(): guest updated chain stack PCSP, but it is not yet supported case\n",
				__func__);
			DebugKVMGT("host  PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_pcsp_base(vcpu, regs->stacks.pcsp),
				vcpu_pcsp_size(vcpu, regs->stacks.pcsp),
				vcpu_pcsp_ind(vcpu, regs->stacks.pcsp) - pcshtp.ind);
			DebugKVMGT("guest PCSP: base 0x%llx size 0x%llx ind 0x%llx\n",
				vcpu_pcsp_base(vcpu, pcsp), vcpu_pcsp_size(vcpu, pcsp),
				vcpu_pcsp_ind(vcpu, pcsp));
		}
	}
#endif /* CHECK_GUEST_SYSCALL_UPDATES */

	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
		e2k_cr0_t cr0 = kvm_get_guest_vcpu_CR0(vcpu);
		e2k_cr1_t cr1 = kvm_get_guest_vcpu_CR1(vcpu);

		if (LO(cr0) != LO(regs->crs.cr0) ||
		    HI(cr0) != HI(regs->crs.cr0) ||
		    LO(cr1) != LO(regs->crs.cr1) ||
		    HI(cr1) != HI(regs->crs.cr1)) {
			DebugKVMGT("source  CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%llx\n",
				   LO(regs->crs.cr0),
				   HI(regs->crs.cr0),
				   regs->crs.cr1.wbs,
				   get_cr1_ussz(regs->crs.cr1));

#ifndef	CHECK_GUEST_SYSCALL_UPDATES
			regs->crs.cr0 = cr0;
			regs->crs.cr1 = cr1;

			DebugKVMGT("updated CR0.lo 0x%016llx CR0.hi 0x%016llx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%llx\n",
				   LO(regs->crs.cr0), HI(regs->crs.cr0),
				   regs->crs.cr1.wbs,
				   get_cr1_ussz(regs->crs.cr1));
#else /* CHECK_GUEST_SYSCALL_UPDATES */
			DebugKVMGT("guest updated CRs (CR0-CR1), but it is not yet supported case\n");
			DebugKVMGT("host  CR0.lo 0x%016llx CR0.hi 0x%016llx\n"
				"      CR1.lo 0x%016llx CR1.hi 0x%016llx\n",
				LO(regs->crs.cr0), HI(regs->crs.cr0),
				LO(regs->crs.cr1), HI(regs->crs.cr1));
			DebugKVMGT("guest CR0.lo 0x%016llx CR0.hi 0x%016llx\n"
				"      CR1.lo 0x%016llx CR1.hi 0x%016llx\n",
				LO(cr0), HI(cr0), LO(cr1), HI(cr1));
#endif /* !CHECK_GUEST_SYSCALL_UPDATES */
		}
	}
	kvm_reset_guest_updated_vcpu_regs_flags(vcpu, regs_status);

check_updates:
	check_guest_stack_regs_updates(vcpu, regs);
}

static inline void
restore_guest_trap_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	restore_guest_trap_stack_regs(vcpu, regs);
}

static inline void
restore_guest_syscall_regs(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	return restore_guest_syscall_stack_regs(vcpu, regs);
}

void __noreturn return_to_injected_syscall_sw_fill(void);

/*
 * We have FILLed user hardware stacks so no
 * function calls are allowed after this point.
 */
static __always_inline __noreturn
void return_to_injected_syscall_switched_stacks(void)
{
	NATIVE_RESTORE_KERNEL_GREGS_IN_SYSCALL(current_thread_info());

	NATIVE_RETURN();

	unreachable();
}

static __always_inline __noreturn
void return_to_injected_syscall(thread_info_t *ti, pt_regs_t *regs)
{
	e2k_pshtp_t pshtp;
	u64 wsz, num_q;
	clear_rf_t clear_fn;

	/*
	 * This can page fault so call with open interrupts
	 */
	wsz = get_wsz();
	pv_vcpu_user_hw_stacks_prepare(ti->vcpu, regs, wsz,
				       FROM_PV_VCPU_SYSCALL, true);

	pshtp = regs->g_stacks.pshtp;

	CHECK_PT_REGS_CHAIN(regs, NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
			    current->stack + KERNEL_C_STACK_SIZE);

	num_q = get_ps_clear_size(wsz, pshtp);

	/* restore guest UPSR and disable all interrupts */
	RETURN_TO_KERNEL_IRQ_MASK_REG(ti->upsr);

	RESTORE_USER_SYSCALL_STACK_REGS(regs);

	clear_fn = get_clear_rf_fn(num_q);

	/* it is guest kernel process return to */
	host_syscall_pv_vcpu_exit_trap(ti, regs);

	/*
	 * If either FILLC or FILLR isn't supported, jump to return_to_injected_syscall_sw_fill.
	 * Otherwise, fall through and call return_to_injected_syscall_switched_stacks directly.
	 */
	user_hw_stacks_restore(&regs->g_stacks, wsz, clear_fn,
			       &return_to_injected_syscall_sw_fill,
			       return_to_injected_syscall_sw_fill_wsz);

	return_to_injected_syscall_switched_stacks();

	unreachable();
}

static __always_inline __noreturn void
guest_syscall_inject(thread_info_t *ti, pt_regs_t *regs)
{
	E2K_KVM_BUG_ON(!kvm_test_and_clear_intc_emul_flag(regs));
	do_return_from_pv_vcpu_intc(ti, regs, FROM_SYSCALL_N_PROT);
	return_to_injected_syscall(ti, regs);
	unreachable();
}

/* --------------------------------------------------------- */

static __always_inline void
pv_vcpu_swicth_to_guest_mmu_ctxt(thread_info_t *ti, struct kvm_vcpu *vcpu)
{
	/* switch host MMU to guest VCPU MMU context */
	trace_host_get_gmm_root_hpa(pv_vcpu_get_gmm(vcpu),
				    native_read_IP_reg_value());
	__guest_enter(ti, &vcpu->arch, DONT_AAU_CONTEXT_SWITCH);

	/* from now the host process is at paravirtualized guest(VCPU) mode */
	set_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);
}

static __always_inline void
switch_to_gst_hw_stacks(struct pt_regs *regs, e2k_stacks_t *stacks,
			struct kvm_vcpu *vcpu)
{
	e2k_sbr_t sbr = (e2k_sbr_t) {.base = stacks->top };

	/* Updte data stack regs TODO: What gst usd ? user or kernel */

	raw_all_irq_disable();

	E2K_FLUSHC;
	/* Update hw stack regs */
	native_write_stacks_cr(stacks->psp, stacks->pcsp, stacks->usd, sbr,
			       regs->crs.cr0, regs->crs.cr1);

	raw_all_irq_enable();

	/*
	 * Initialize guest kernel gregs and make return trick to
	 * pass control to guest handler
	 */
	return_to_injected_syscall_switched_stacks();

	unreachable();
}

static __always_inline void guest_mkctxt_complete(void)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	e2k_stacks_t cur_g_stacks;
	struct signal_stack_context __priv *context;
	struct pv_vcpu_ctxt vcpu_ctxt;
	struct pt_regs regs;
	struct local_gregs l_gregs;
	e2k_aau_t aau_context;
	u64 sbbp[SBBP_ENTRIES_NUM], wsz;
	struct trap_pt_regs saved_trap;
	unsigned long mmu_pid;
	int ret;
	bool return_to_user;

	raw_all_irq_enable();

	mmu_pid = current->mm->context.cpumsk[smp_processor_id()];
	trace_kvm_switch_to_host_mmu_pid(vcpu, current->mm, mmu_pid,
					 trampoline_sw_to_host);

	/*
	 * Copy guest's user context from signal host stack.
	 * This context was filled by kvm_complete_longjmp hypercall,
	 * called from swapcontext.
	 */
	context = get_signal_stack();

	ret = copy_from_priv(&vcpu_ctxt, &context->vcpu_ctxt,
			     sizeof(vcpu_ctxt));
	if (ret) {
		user_exit();
		pr_err("%s(): kill guest: copy from user failed, error %d\n",
		       __func__, ret);
		do_exit(SIGKILL);
	}

	if (copy_context_from_signal_stack(&l_gregs, &regs, &saved_trap,
					   sbbp, &aau_context, NULL)) {
		user_exit();
		pr_err
		    ("%s(): kill guest: copy context from signal stack failed\n",
		     __func__);
		do_exit(SIGKILL);
	}
	atomic_dec(&gti->signal.syscall_num);
	gti->signal.stack.base = current_thread_info()->signal_stack.base;
	gti->signal.stack.size = current_thread_info()->signal_stack.size;
	gti->signal.stack.used = current_thread_info()->signal_stack.used;

	/* Switch guest's interrupts into user mode */
	kvm_emulate_guest_vcpu_psr_done(vcpu, vcpu_ctxt.guest_psr,
					vcpu_ctxt.irq_under_upsr);

	/* Switch to guest's mmu context */
	raw_all_irq_disable();
	pv_vcpu_swicth_to_guest_mmu_ctxt(ti, vcpu);
	raw_all_irq_enable();

	/* Fill context from signal stack to gregs */
	restore_guest_syscall_regs(vcpu, &regs);
	update_pv_vcpu_local_glob_regs(vcpu, &l_gregs);
	restore_local_glob_regs(&l_gregs, false);

	/* Fill guest hw stack user regs */
	COPY_U_HW_STACKS_TO_STACKS(&regs.g_stacks, &cur_g_stacks);
	/* Provide right state of user stacks before return */
	regs.stacks.pshtp.ind = 0;
	regs.stacks.pcshtp.ind = SZ_OF_CR;

	/* Handle all pending events before exiting to guest's usermode */
	wsz = get_wsz();
	return_to_user = true;
	exit_to_usermode_loop(&regs, FROM_SYSCALL_N_PROT, &return_to_user, wsz, true);

	/* Switch to guest hw stacks */
	switch_to_gst_hw_stacks(&regs, &regs.stacks, vcpu);

	unreachable();
}

/* -------------------------------------------------------- */

static __always_inline notrace void return_pv_vcpu_inject(inject_caller_t from)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	struct signal_stack_context __priv *context;
	pv_vcpu_ctxt_t vcpu_ctxt;
	struct pt_regs regs;
	struct trap_pt_regs saved_trap, *trap;
	gthread_info_t *gti;
	bool guest_user, user_stacks;
	u64 sbbp[SBBP_ENTRIES_NUM];
	struct k_sigaction ka;
	e2k_aau_t aau_context;
	struct local_gregs l_gregs;
	e2k_stacks_t cur_g_stacks;
	e2k_pshtp_t u_pshtp;
	e2k_pcshtp_t u_pcshtp;
	e2k_wd_t wd;
	unsigned long mmu_pid;
	int ret;

	gti = pv_vcpu_get_gti(vcpu);
	COPY_U_HW_STACKS_FROM_TI(&cur_g_stacks, ti);
	raw_all_irq_enable();

#ifdef	CONFIG_KERNEL_TIMES_ACCOUNT
	E2K_SAVE_CLOCK_REG(clock);
	{
		register int count;

		GET_DECR_KERNEL_TIMES_COUNT(ti, count);
		scall_times = &(ti->times[count].of.syscall);
		scall_times->do_signal_done = clock;
	}
#endif /* CONFIG_KERNEL_TIMES_ACCOUNT */

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);

	mmu_pid = current->mm->context.cpumsk[smp_processor_id()];
	trace_kvm_switch_to_host_mmu_pid(vcpu, current->mm, mmu_pid,
					 trampoline_sw_to_host);

	context = get_signal_stack();

	ret = copy_from_priv(&vcpu_ctxt, &context->vcpu_ctxt,
			     sizeof(vcpu_ctxt));
	if (ret) {
		user_exit();
		pr_err("%s(): kill guest: copy from user failed, error %d\n",
		       __func__, ret);
		do_exit(SIGKILL);
	}

	E2K_KVM_BUG_ON(kvm_is_guest_migrated_to_other_vcpu(ti, vcpu));

	if (copy_context_from_signal_stack(&l_gregs, &regs, &saved_trap,
					   sbbp, &aau_context, &ka)) {
		user_exit();
		pr_err("%s(): kill guest: copy context from signal stack failed\n",
		     __func__);
		do_exit(SIGKILL);
	}
	if (from == FROM_PV_VCPU_TRAP_INJECT) {
		atomic_dec(&gti->signal.traps_num);
	} else if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		atomic_dec(&gti->signal.syscall_num);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	gti->signal.stack.base = current_thread_info()->signal_stack.base;
	gti->signal.stack.size = current_thread_info()->signal_stack.size;
	gti->signal.stack.used = current_thread_info()->signal_stack.used;

	E2K_KVM_BUG_ON(vcpu_ctxt.inject_from != from);
	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		syscall_handler_trampoline_finish(vcpu, &regs,
						  &vcpu_ctxt, host_ctxt);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		trap_handler_trampoline_finish(vcpu, &vcpu_ctxt, host_ctxt);
	} else {
		E2K_KVM_BUG_ON(true);
	}

	/* Always make any pending restarted system call return -EINTR.
	 * Otherwise we might restart the wrong system call. */
	current->restart_block.fn = do_no_restart_syscall;
	/* Preserve current p[c]shtp as they indicate
	 * how much to FILL when returning */
	u_pshtp = regs.stacks.pshtp;
	u_pcshtp = regs.stacks.pcshtp;
	regs.stacks.pshtp = cur_g_stacks.pshtp;
	regs.stacks.pcshtp = cur_g_stacks.pcshtp;

	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		set_syscall_handler_ret_value(&regs, &vcpu_ctxt);;
		guest_user = true;
		user_stacks = true;
		restore_guest_syscall_regs(vcpu, &regs);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		guest_user = !pv_vcpu_trap_on_guest_kernel(&regs);
		if (guest_user) {
			if (regs.stacks.top >= GUEST_TASK_SIZE) {
				/* guest user, but trap on guest kernel */
				user_stacks = false;
			} else {
				user_stacks = true;
			}
		} else {
			user_stacks = false;
			E2K_KVM_BUG_ON(regs.stacks.top < GUEST_TASK_SIZE);
		}
		if (user_stacks) {
			/* guest trap handler can update some stack & system */
			/* registers state, so update the registers on host */
			restore_guest_trap_regs(vcpu, &regs);
		} else {
			/* clear updating flags for trap on guest kernel */
			kvm_reset_guest_vcpu_regs_status(vcpu);
		}
	} else {
		E2K_KVM_BUG_ON(true);
	}
#if DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
	debug_guest_ust = user_stacks;
#endif
	DebugUST("guest kernel chain stack final state: base 0x%llx ind 0x%llx size 0x%llx PCSHTP 0x%llx\n",
		 vcpu_pcsp_base(vcpu, cur_g_stacks.pcsp),
		 vcpu_pcsp_ind(vcpu, cur_g_stacks.pcsp),
		 vcpu_pcsp_size(vcpu, cur_g_stacks.pcsp),
		 (u64)AW(cur_g_stacks.pcshtp));
	DebugUST("guest kernel proc stack final state: base 0x%llx ind 0x%llx size 0x%llx PSHTP 0x%llx\n",
		 vcpu_psp_base(vcpu, cur_g_stacks.psp),
		 vcpu_psp_ind(vcpu, cur_g_stacks.psp),
		 vcpu_psp_size(vcpu, cur_g_stacks.psp),
		 (u64)AW(cur_g_stacks.pshtp));
	DebugUST("guest user chain stack state: base 0x%llx ind 0x%llx size 0x%llx PCSHTP 0x%llx\n",
		 vcpu_pcsp_base(vcpu, regs.stacks.pcsp),
		 vcpu_pcsp_ind(vcpu, regs.stacks.pcsp),
		 vcpu_pcsp_size(vcpu, regs.stacks.pcsp),
		 (u64)AW(regs.stacks.pcshtp));
	DebugUST("guest user proc stack state: base 0x%llx ind 0x%llx size 0x%llx PSHTP 0x%llx\n",
		 vcpu_psp_base(vcpu, regs.stacks.psp),
		 vcpu_psp_ind(vcpu, regs.stacks.psp),
		 vcpu_psp_size(vcpu, regs.stacks.psp),
		 (u64)AW(regs.stacks.pshtp));
	DebugUST("guest user already filled PSHTP 0x%llx PCSHTP 0x%llx\n",
		 (u64)PSHTP_MEM_INDEX(u_pshtp), (u64)u_pcshtp.ind);

	/*
	 * Restore proper psize as it was when signal was delivered.
	 * Alternative would be to create non-empty frame for
	 * procedure stack in prepare_sighandler_trampoline()
	 * if signal is delivered after a system call.
	 */
	if (regs.wd.psize) {
		raw_all_irq_disable();
		wd = native_read_WD_reg();
		wd.psize = regs.wd.psize;
		native_write_WD_reg(wd);
		raw_all_irq_enable();
	}

	if (from_trap(&regs))
		regs.trap->prev_state = exception_enter();
	else
		user_exit();

	regs.next = NULL;
	/* Make sure 'pt_regs' are ready before enqueuing them */
	barrier();
	ti->pt_regs = &regs;

	trap = regs.trap;
	if (trap && (3 * trap->curr_cnt) < trap->tc_count && trap->tc_count > 0) {
		trap->from_sigreturn = 1;
		do_trap_cellar(&regs, 0);
	}

	clear_restore_sigmask();

	trace_pv_restore_l_gregs(vcpu, from, &l_gregs);

	/* update "local" global registers which were changed */
	/* by page fault handlers */
	update_pv_vcpu_local_glob_regs(vcpu, &l_gregs);

	if (!gti->task_is_binco) {
		/* Kernel has no so called "local" gregs so there is nothing
		 * to restore if this trap happened in the guest kernel. */
		if (regs.is_guest_user)
			restore_local_glob_regs(&l_gregs, false);

		if (!regs.is_guest_user &&
		    kvm_is_guest_migrated_to_other_vcpu(ti, vcpu)) {
			u64 old_task, new_task;

			/*
			 * Return will be on guest handler and
			 * its process has been migrated to other VCPU,
			 * so it need update vcpu state pointer on gregs
			 */
			ONLY_COPY_FROM_KERNEL_CURRENT_GREGS(&ti->k_gregs,
							    old_task);
			RESTORE_GUEST_KERNEL_GREGS_COPY(ti, gti, vcpu);
			ONLY_COPY_FROM_KERNEL_CURRENT_GREGS(&ti->k_gregs,
							    new_task);
			E2K_KVM_BUG_ON(old_task != new_task);
		}
	}

	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		E2K_KVM_BUG_ON(regs.trap || !regs.kernel_entry);
		E2K_KVM_BUG_ON(regs.aau_context);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		E2K_KVM_BUG_ON(!regs.trap || regs.kernel_entry);
		E2K_KVM_BUG_ON(!regs.aau_context);
	} else {
		E2K_KVM_BUG_ON(true);
	}

	if (!user_stacks) {
		E2K_KVM_BUG_ON(from == FROM_PV_VCPU_SYSCALL_INJECT);
		finish_user_trap_handler(&regs, FROM_RETURN_PV_VCPU_TRAP);
	} else {
		COPY_U_HW_STACKS_TO_STACKS(&regs.g_stacks, &cur_g_stacks);
		if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
			bool restart_needed = false;

			switch (regs.sys_rval) {
			case -ERESTART_RESTARTBLOCK:
			case -ERESTARTNOHAND:
				regs.sys_rval = -EINTR;
				break;
			case -ERESTARTSYS:
				if (!(ka.sa.sa_flags & SA_RESTART)) {
					regs.sys_rval = -EINTR;
					break;
				}
				/* fallthrough */
			case -ERESTARTNOINTR:
				restart_needed = true;
				break;
			}

			finish_syscall(&regs, FROM_PV_VCPU_SYSCALL, !restart_needed);
		} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
			finish_user_trap_handler(&regs, FROM_RETURN_PV_VCPU_TRAP);
		} else {
			E2K_KVM_BUG_ON(true);
		}
	}
}

static __always_inline notrace void pv_vcpu_return_from_fork(u64 sys_rval)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	struct pt_regs regs;
	e2k_stacks_t cur_g_stacks;
	gthread_info_t *gti;
	e2k_pshtp_t u_pshtp;
	e2k_pcshtp_t u_pcshtp;
	e2k_wd_t wd;
	unsigned long mmu_pid;

	gti = pv_vcpu_get_gti(vcpu);
	COPY_U_HW_STACKS_FROM_TI(&cur_g_stacks, ti);
	raw_all_irq_enable();

	mmu_pid = current->mm->context.cpumsk[smp_processor_id()];
	trace_kvm_switch_to_host_mmu_pid(vcpu, current->mm, mmu_pid,
					 trampoline_sw_to_host);

	E2K_KVM_BUG_ON(kvm_is_guest_migrated_to_other_vcpu(ti, vcpu));

	if (unlikely(copy_pt_regs_from_signal_stack(&regs))) {
		user_exit();
		pr_err("%s(): kill guest: copy regs from signal stack failed\n",
		       __func__);
		do_exit(SIGKILL);
	}
	atomic_dec(&gti->signal.syscall_num);
	gti->signal.stack.base = current_thread_info()->signal_stack.base;
	gti->signal.stack.size = current_thread_info()->signal_stack.size;
	gti->signal.stack.used = current_thread_info()->signal_stack.used;

	/*
	 * Always make any pending restarted system call return -EINTR.
	 * Otherwise we might restart the wrong system call.
	 */
	current->restart_block.fn = do_no_restart_syscall;

	E2K_KVM_BUG_ON(!is_sys_call_pt_regs(&regs));

	/*
	 * Preserve current p[c]shtp as they indicate
	 * how much to FILL when returning
	 */
	u_pshtp = regs.stacks.pshtp;
	u_pcshtp = regs.stacks.pcshtp;
	regs.stacks.pshtp = cur_g_stacks.pshtp;
	regs.stacks.pcshtp = cur_g_stacks.pcshtp;

	regs.sys_rval = sys_rval;

	if (regs.wd.psize) {
		/* restore proper WD sizes to avoid window bounds exceptions */
		raw_all_irq_disable();
		wd = native_read_WD_reg();
		wd.psize = regs.wd.psize;
		native_write_WD_reg(wd);
		raw_all_irq_enable();
	}

	regs.next = NULL;
	/* Make sure 'pt_regs' are ready before enqueuing them */
	barrier();
	ti->pt_regs = &regs;

	clear_restore_sigmask();

	COPY_U_HW_STACKS_TO_STACKS(&regs.g_stacks, &cur_g_stacks);

	/* emulate restore of guest VCPU PSR state after return from syscall */
	kvm_emulate_guest_vcpu_psr_return(vcpu, &regs.crs);

	finish_syscall(&regs, FROM_PV_VCPU_SYSFORK, true);
}
#else /* !CONFIG_KVM_HOST_MODE */
/* It is native guest kernel whithout virtualization support */
/* Virtualiztion in guest mode cannot be supported */

static __always_inline void
guest_syscall_inject(thread_info_t *ti, pt_regs_t *regs)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}

static __always_inline void host_mkctxt_trampoline_inject(void)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}

static __always_inline void guest_mkctxt_complete(void)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}

static __always_inline notrace void return_pv_vcpu_inject(inject_caller_t from)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}

static __always_inline notrace void pv_vcpu_return_from_fork(u64 sys_rval)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}

static __always_inline __noreturn void
return_to_injected_syscall_switched_stacks(void)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);

	BUG();

	unreachable();
}

#endif /* CONFIG_KVM_HOST_MODE */

#endif /* _E2K_KVM_TTABLE_H */
