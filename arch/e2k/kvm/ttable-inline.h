/*
 *
 * Copyright (C) 2020 MCST
 *
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

#include "cpu.h"

#undef	DEBUG_PV_FORK_MODE
#undef	DebugFORK
#define	DEBUG_PV_FORK_MODE	0	/* syscall fork return debugging */
#define	DebugFORK(fmt, args...)						\
({									\
	if (DEBUG_PV_FORK_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

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
#endif	/* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#define	CHECK_GUEST_SYSCALL_UPDATES

#ifdef	CHECK_GUEST_VCPU_UPDATES

#define	DebugKVMGT(fmt, args...)					\
		pr_err("%s(): " fmt, __func__, ##args)

static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
	{
		e2k_addr_t sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		e2k_usd_lo_t usd_lo = kvm_get_guest_vcpu_USD_lo(vcpu);
		e2k_usd_hi_t usd_hi = kvm_get_guest_vcpu_USD_hi(vcpu);

		if (usd_lo.USD_lo_half != regs->stacks.usd_lo.USD_lo_half ||
			usd_hi.USD_hi_half != regs->stacks.usd_hi.USD_hi_half ||
			sbr != regs->stacks.top) {
			DebugKVMGT("FAULT: source  USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
			DebugKVMGT("NOT updated    USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				usd_lo.USD_lo_base,
				usd_hi.USD_hi_size,
				sbr);
		}
	}
	{
		e2k_psp_lo_t psp_lo = kvm_get_guest_vcpu_PSP_lo(vcpu);
		e2k_psp_hi_t psp_hi = kvm_get_guest_vcpu_PSP_hi(vcpu);
		e2k_pcsp_lo_t pcsp_lo = kvm_get_guest_vcpu_PCSP_lo(vcpu);
		e2k_pcsp_hi_t pcsp_hi = kvm_get_guest_vcpu_PCSP_hi(vcpu);

		if (psp_lo.PSP_lo_half != regs->stacks.psp_lo.PSP_lo_half ||
			psp_hi.PSP_hi_size != regs->stacks.psp_hi.PSP_hi_size) {
			/* PSP_hi_ind/PCSP_hi_ind can be modified and should */
			/* be restored as saved at regs state */
			DebugKVMGT("FAULT: source  PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
			DebugKVMGT("NOT updated    PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				psp_lo.PSP_lo_base,
				psp_hi.PSP_hi_size,
				psp_hi.PSP_hi_ind);
		}
		if (pcsp_lo.PCSP_lo_half != regs->stacks.pcsp_lo.PCSP_lo_half ||
			pcsp_hi.PCSP_hi_size !=
				regs->stacks.pcsp_hi.PCSP_hi_size) {
			DebugKVMGT("FAULT: source  PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
			DebugKVMGT("NOT updated    PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				pcsp_lo.PCSP_lo_base,
				pcsp_hi.PCSP_hi_size,
				pcsp_hi.PCSP_hi_ind);
		}
	}
	{
		unsigned long cr0_lo = kvm_get_guest_vcpu_CR0_lo_value(vcpu);
		unsigned long cr0_hi = kvm_get_guest_vcpu_CR0_hi_value(vcpu);
		e2k_cr1_lo_t cr1_lo = kvm_get_guest_vcpu_CR1_lo(vcpu);
		e2k_cr1_hi_t cr1_hi = kvm_get_guest_vcpu_CR1_hi(vcpu);

		if (cr0_lo != regs->crs.cr0_lo.CR0_lo_half ||
			cr0_hi != regs->crs.cr0_hi.CR0_hi_half ||
			cr1_lo.CR1_lo_half != regs->crs.cr1_lo.CR1_lo_half ||
			cr1_hi.CR1_hi_half != regs->crs.cr1_hi.CR1_hi_half) {
			DebugKVMGT("FAULT: source  CR0.lo 0x%016llx CR0.hi "
				"0x%016llx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
			DebugKVMGT("NOT updated    CR0.lo 0x%016lx CR0.hi "
				"0x%016lx CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				cr0_lo,
				cr0_hi,
				cr1_lo.CR1_lo_wbs,
				cr1_hi.CR1_hi_ussz);
		}
	}
}
#else	/* ! CHECK_GUEST_VCPU_UPDATES */
static inline void
check_guest_stack_regs_updates(struct kvm_vcpu *vcpu, struct pt_regs *regs)
{
}
#endif	/* CHECK_GUEST_VCPU_UPDATES */

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
		if (wd.WD_psize != regs->wd.WD_psize) {
			DebugKVMGT("source  WD: size 0x%x\n",
				regs->wd.WD_psize);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->wd.WD_psize = wd.WD_psize;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated WD: size 0x%x\n",
				regs->wd.WD_psize);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
		unsigned long sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		unsigned long usd_lo = kvm_get_guest_vcpu_USD_lo_value(vcpu);
		unsigned long usd_hi = kvm_get_guest_vcpu_USD_hi_value(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (usd_lo != regs->stacks.usd_lo.USD_lo_half ||
				usd_hi != regs->stacks.usd_hi.USD_hi_half ||
				sbr != regs->stacks.top) {
			DebugKVMGT("source  USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.usd_lo.USD_lo_half = usd_lo;
			regs->stacks.usd_hi.USD_hi_half = usd_hi;
			regs->stacks.top = sbr;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status,
						HS_REGS_UPDATED_CPU_REGS)) {
		unsigned long psp_lo = kvm_get_guest_vcpu_PSP_lo_value(vcpu);
		unsigned long psp_hi = kvm_get_guest_vcpu_PSP_hi_value(vcpu);
		unsigned long pcsp_lo = kvm_get_guest_vcpu_PCSP_lo_value(vcpu);
		unsigned long pcsp_hi = kvm_get_guest_vcpu_PCSP_hi_value(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (psp_lo != regs->stacks.psp_lo.PSP_lo_half ||
				psp_hi != regs->stacks.psp_hi.PSP_hi_half) {
			DebugKVMGT("source  PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.psp_lo.PSP_lo_half = psp_lo;
			regs->stacks.psp_hi.PSP_hi_half = psp_hi;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (pcsp_lo != regs->stacks.pcsp_lo.PCSP_lo_half ||
				pcsp_hi != regs->stacks.pcsp_hi.PCSP_hi_half) {
			DebugKVMGT("source  PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->stacks.pcsp_lo.PCSP_lo_half = pcsp_lo;
			regs->stacks.pcsp_hi.PCSP_hi_half = pcsp_hi;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
		unsigned long cr0_lo = kvm_get_guest_vcpu_CR0_lo_value(vcpu);
		unsigned long cr0_hi = kvm_get_guest_vcpu_CR0_hi_value(vcpu);
		unsigned long cr1_lo = kvm_get_guest_vcpu_CR1_lo_value(vcpu);
		unsigned long cr1_hi = kvm_get_guest_vcpu_CR1_hi_value(vcpu);

#ifdef	CHECK_GUEST_VCPU_UPDATES
		if (cr0_lo != regs->crs.cr0_lo.CR0_lo_half ||
				cr0_hi != regs->crs.cr0_hi.CR0_hi_half ||
				cr1_lo != regs->crs.cr1_lo.CR1_lo_half ||
				cr1_hi != regs->crs.cr1_hi.CR1_hi_half) {
			DebugKVMGT("source  CR0.lo 0x%016llx CR0.hi 0x%016llx "
				"CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
#endif	/* CHECK_GUEST_VCPU_UPDATES */

			regs->crs.cr0_lo.CR0_lo_half = cr0_lo;
			regs->crs.cr0_hi.CR0_hi_half = cr0_hi;
			regs->crs.cr1_lo.CR1_lo_half = cr1_lo;
			regs->crs.cr1_hi.CR1_hi_half = cr1_hi;

#ifdef	CHECK_GUEST_VCPU_UPDATES
			DebugKVMGT("updated CR0.lo 0x%016llx CR0.hi 0x%016llx "
				"CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
		}
#endif	/* CHECK_GUEST_VCPU_UPDATES */
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

		if (wd.WD_psize != regs->wd.WD_psize) {
			DebugKVMGT("source  WD: size 0x%x\n",
				regs->wd.WD_psize);

#ifndef	CHECK_GUEST_SYSCALL_UPDATES
			regs->wd.WD_psize = wd.WD_psize;
			DebugKVMGT("updated WD: size 0x%x\n",
				regs->wd.WD_psize);
#else	/* CHECK_GUEST_SYSCALL_UPDATES */
			E2K_LMS_HALT_OK;
			pr_err("%s(): guest updated WD, but it is not yet "
				"supported case\n",
				__func__);
			KVM_BUG_ON(true);
#endif	/* !CHECK_GUEST_SYSCALL_UPDATES */

		}
	}
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, USD_UPDATED_CPU_REGS)) {
		unsigned long sbr = kvm_get_guest_vcpu_SBR_value(vcpu);
		unsigned long usd_lo = kvm_get_guest_vcpu_USD_lo_value(vcpu);
		unsigned long usd_hi = kvm_get_guest_vcpu_USD_hi_value(vcpu);

		if (usd_lo != regs->stacks.usd_lo.USD_lo_half ||
				usd_hi != regs->stacks.usd_hi.USD_hi_half ||
				sbr != regs->stacks.top) {
			DebugKVMGT("source  USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);

#ifndef	CHECK_GUEST_SYSCALL_UPDATES
			regs->stacks.usd_lo.USD_lo_half = usd_lo;
			regs->stacks.usd_hi.USD_hi_half = usd_hi;
			regs->stacks.top = sbr;
			DebugKVMGT("updated USD: base 0x%llx size 0x%x "
				"top 0x%lx\n",
				regs->stacks.usd_lo.USD_lo_base,
				regs->stacks.usd_hi.USD_hi_size,
				regs->stacks.top);
#else	/* CHECK_GUEST_SYSCALL_UPDATES */
			E2K_LMS_HALT_OK;
			pr_err("%s(): guest updated stack USD/SBR, but it is "
				"not yet supported case\n",
				__func__);
			KVM_BUG_ON(true);
#endif	/* !CHECK_GUEST_SYSCALL_UPDATES */
		}
	}

	/* hardware stacks registers should be updated by hypercall as */
	/* for long jump case, so ignore guest register updated state here */
#ifdef	CHECK_GUEST_SYSCALL_UPDATES
	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status,
						HS_REGS_UPDATED_CPU_REGS)) {
		unsigned long psp_lo = kvm_get_guest_vcpu_PSP_lo_value(vcpu);
		e2k_psp_hi_t psp_hi = kvm_get_guest_vcpu_PSP_hi(vcpu);
		unsigned long pcsp_lo = kvm_get_guest_vcpu_PCSP_lo_value(vcpu);
		e2k_pcsp_hi_t pcsp_hi = kvm_get_guest_vcpu_PCSP_hi(vcpu);
		e2k_pshtp_t pshtp = regs->stacks.pshtp;
		e2k_pcshtp_t pcshtp = regs->stacks.pcshtp;

		if (psp_lo != regs->stacks.psp_lo.PSP_lo_half ||
				psp_hi.PSP_hi_ind !=
					regs->stacks.psp_hi.PSP_hi_ind -
						GET_PSHTP_MEM_INDEX(pshtp) ||
				psp_hi.PSP_hi_size !=
					regs->stacks.psp_hi.PSP_hi_size) {
			DebugKVMGT("source PSP:  base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.psp_lo.PSP_lo_base,
				regs->stacks.psp_hi.PSP_hi_size,
				regs->stacks.psp_hi.PSP_hi_ind);
			E2K_LMS_HALT_OK;
			pr_err("%s(): guest updated proc stack PSP, but it is "
				"not yet supported case\n",
				__func__);
			KVM_BUG_ON(true);
		}

		if (pcsp_lo != regs->stacks.pcsp_lo.PCSP_lo_half ||
				pcsp_hi.PCSP_hi_ind !=
					regs->stacks.pcsp_hi.PCSP_hi_ind -
						PCSHTP_SIGN_EXTEND(pcshtp) ||
				pcsp_hi.PCSP_hi_size !=
					regs->stacks.pcsp_hi.PCSP_hi_size) {
			DebugKVMGT("source  PCSP: base 0x%llx size 0x%x "
				"ind 0x%x\n",
				regs->stacks.pcsp_lo.PCSP_lo_base,
				regs->stacks.pcsp_hi.PCSP_hi_size,
				regs->stacks.pcsp_hi.PCSP_hi_ind);
			E2K_LMS_HALT_OK;
			pr_err("%s(): guest updated chain stack PCSP, but "
				"it is not yet supported case\n",
				__func__);
			KVM_BUG_ON(true);
		}
	}
#endif	/* CHECK_GUEST_SYSCALL_UPDATES */

	if (KVM_TEST_UPDATED_CPU_REGS_FLAG(regs_status, CRS_UPDATED_CPU_REGS)) {
		unsigned long cr0_lo = kvm_get_guest_vcpu_CR0_lo_value(vcpu);
		unsigned long cr0_hi = kvm_get_guest_vcpu_CR0_hi_value(vcpu);
		unsigned long cr1_lo = kvm_get_guest_vcpu_CR1_lo_value(vcpu);
		unsigned long cr1_hi = kvm_get_guest_vcpu_CR1_hi_value(vcpu);

		if (cr0_lo != regs->crs.cr0_lo.CR0_lo_half ||
				cr0_hi != regs->crs.cr0_hi.CR0_hi_half ||
				cr1_lo != regs->crs.cr1_lo.CR1_lo_half ||
				cr1_hi != regs->crs.cr1_hi.CR1_hi_half) {
			DebugKVMGT("source  CR0.lo 0x%016llx CR0.hi 0x%016llx "
				"CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);

#ifndef	CHECK_GUEST_SYSCALL_UPDATES
			regs->crs.cr0_lo.CR0_lo_half = cr0_lo;
			regs->crs.cr0_hi.CR0_hi_half = cr0_hi;
			regs->crs.cr1_lo.CR1_lo_half = cr1_lo;
			regs->crs.cr1_hi.CR1_hi_half = cr1_hi;

			DebugKVMGT("updated CR0.lo 0x%016llx CR0.hi 0x%016llx "
				"CR1.lo.wbs 0x%x CR1.hi.ussz 0x%x\n",
				regs->crs.cr0_lo.CR0_lo_half,
				regs->crs.cr0_hi.CR0_hi_half,
				regs->crs.cr1_lo.CR1_lo_wbs,
				regs->crs.cr1_hi.CR1_hi_ussz);
#else	/* CHECK_GUEST_SYSCALL_UPDATES */
			E2K_LMS_HALT_OK;
			pr_err("%s(): guest updated CRs (CR0-CR1), but it is "
				"not yet supported case\n",
				__func__);
			KVM_BUG_ON(true);
#endif	/* !CHECK_GUEST_SYSCALL_UPDATES */
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

extern void return_to_injected_syscall_sw_fill(void);

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

	/*
	 * This can page fault so call with open interrupts
	 */
	wsz = get_wsz(FROM_PV_VCPU_SYSCALL);
	pv_vcpu_user_hw_stacks_prepare(ti->vcpu, regs, wsz,
					FROM_PV_VCPU_SYSCALL, true);

	pshtp = regs->g_stacks.pshtp;

	CHECK_PT_REGS_CHAIN(regs, NATIVE_NV_READ_USD_LO_REG().USD_lo_base,
			current->stack + KERNEL_C_STACK_SIZE);

	num_q = get_ps_clear_size(wsz, pshtp);

	/* restore guest UPSR and disable all interrupts */
	NATIVE_RETURN_TO_KERNEL_UPSR(ti->upsr);

	RESTORE_USER_SYSCALL_STACK_REGS(regs);

	/* it is guest kernel process return to */
	host_syscall_pv_vcpu_exit_trap(ti, regs);

	/*
	 * If either FILLC or FILLR isn't supported, jump to return_to_injected_syscall_sw_fill.
	 * Otherwise, fall through and call return_to_injected_syscall_switched_stacks directly.
	 */
	user_hw_stacks_restore(regs, &regs->g_stacks, wsz, num_q,
		&return_to_injected_syscall_sw_fill, return_to_injected_syscall_sw_fill_wsz);

	return_to_injected_syscall_switched_stacks();

	unreachable();
}

static __always_inline __noreturn void
guest_syscall_inject(thread_info_t *ti, pt_regs_t *regs)
{
	KVM_BUG_ON(!kvm_test_and_clear_intc_emul_flag(regs));
	do_return_from_pv_vcpu_intc(ti, regs, FROM_SYSCALL_N_PROT);
	return_to_injected_syscall(ti, regs);
	unreachable();
}

/* --------------------------------------------------------- */

static __always_inline void
pv_vcpu_swicth_to_guest_mmu_ctxt(thread_info_t *ti, struct kvm_vcpu *vcpu)
{
	/* switch host MMU to guest VCPU MMU context */
	kvm_switch_to_guest_mmu_pid(vcpu, ti);
	__guest_enter(ti, &vcpu->arch, DONT_AAU_CONTEXT_SWITCH);

	/* from now the host process is at paravirtualized guest(VCPU) mode */
	set_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);
}

static __always_inline void
switch_to_gst_hw_stacks(struct pt_regs *regs, e2k_stacks_t *stacks,
			struct kvm_vcpu *vcpu)
{
	u64 usd_hi, usd_lo, top, cr0_lo, cr0_hi, cr1_lo, cr1_hi;

	/* Updte data stack regs TODO: What gst usd ? user or kernel */
	usd_lo = AS_WORD(stacks->usd_lo);
	usd_hi = AS_WORD(stacks->usd_hi);
	top = stacks->top;

	raw_all_irq_disable();

	E2K_FLUSHC;
	NATIVE_NV_WRITE_USBR_USD_REG_VALUE(top, usd_hi, usd_lo);

	/* Update hw stack regs */
	WRITE_PSP_REG(stacks->psp_hi, stacks->psp_lo);
	WRITE_PCSP_REG(stacks->pcsp_hi, stacks->pcsp_lo);

	/* Update cr0, cr1 */
	cr0_hi = AS_WORD((regs)->crs.cr0_hi);
	cr0_lo = AS_WORD((regs)->crs.cr0_lo);
	cr1_hi = AS_WORD((regs)->crs.cr1_hi);
	cr1_lo = AS_WORD((regs)->crs.cr1_lo);
	NATIVE_NV_NOIRQ_WRITE_CR0_HI_REG_VALUE(cr0_hi);
	NATIVE_NV_NOIRQ_WRITE_CR0_LO_REG_VALUE(cr0_lo);
	NATIVE_NV_NOIRQ_WRITE_CR1_HI_REG_VALUE(cr1_hi);
	NATIVE_NV_NOIRQ_WRITE_CR1_LO_REG_VALUE(cr1_lo);

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
	struct signal_stack_context __user *context;
	struct pv_vcpu_ctxt vcpu_ctxt;
	struct pt_regs regs;
	struct local_gregs l_gregs;
	e2k_aau_t aau_context;
	u64 sbbp[SBBP_ENTRIES_NUM], wsz;
	struct trap_pt_regs saved_trap;
	unsigned long ts_flag;
	int ret;
	bool return_to_user;

	raw_all_irq_enable();

	/*
	 * Copy guest's user context from signal host stack.
	 * This context was filled by kvm_complete_longjmp hypercall,
	 * called from swapcontext.
	 */
	context = get_signal_stack();

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_from_user(&vcpu_ctxt, &context->vcpu_ctxt,
			sizeof(vcpu_ctxt));
	clear_ts_flag(ts_flag);
	if (ret) {
		user_exit();
		do_exit(SIGKILL);
	}

	if (copy_context_from_signal_stack(&l_gregs, &regs, &saved_trap,
				sbbp, &aau_context, NULL)) {
		user_exit();
		do_exit(SIGKILL);
	}

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
	regs.stacks.pshtp = ((e2k_pshtp_t) {.PSHTP_ind = 0});
	regs.stacks.pcshtp = SZ_OF_CR;

	/* Handle all pending events before exiting to guest's usermode */
	wsz = get_wsz(FROM_SYSCALL_N_PROT);
	return_to_user = true;
	exit_to_usermode_loop(&regs, FROM_SYSCALL_N_PROT,
				&return_to_user, wsz, true);

	/* Switch to guest hw stacks */
	switch_to_gst_hw_stacks(&regs, &regs.stacks, vcpu);

	unreachable();
}

/* --------------------------------------------------------- */

static __always_inline int
pv_vcpu_prepare_syscall_trampoline_frame(struct pt_regs *regs,
					struct kvm_vcpu *vcpu)
{
	e2k_mem_crs_t empty_crs, syscall_trampoline_crs;
	e2k_mem_ps_t ps_frames[4];
	int ret;

	/*
	 * Prepare first "empty" frame on chain stack to process
	 * return opearation kvm_guest_mkctxt_trampoline (guest) ->
	 * syscall_handler_trampoline (host).
	 * Prepare reg winodw of standard size (4 * qr) on procedure
	 * stack in accordance to C call convention.
	 */
	memset(&empty_crs, 0, sizeof(empty_crs));
	ret = pv_vcpu_user_hw_stacks_copy_crs(vcpu, &regs->g_stacks,
						regs, &empty_crs);
	memset(&ps_frames, 0, sizeof(ps_frames));
	ret |= pv_vcpu_user_hw_stacks_copy_ps_frames(vcpu, &regs->g_stacks,
							regs, ps_frames, 4);
	if (unlikely(ret))
		return ret;

	ret = pv_vcpu_user_hw_stacks_copy_crs(vcpu, &regs->g_stacks,
						regs, &empty_crs);
	ret |= pv_vcpu_user_hw_stacks_copy_ps_frames(vcpu, &regs->g_stacks,
							regs, ps_frames, 4);
	if (unlikely(ret))
		return ret;

	/*
	 * Prepare return_pv_vcpu_from_mkctxt (host) frame on chain stack
	 * to pass control to this handler when guest returns from
	 * kvm_guest_mkctxt_trampoline.
	 */
	ret = chain_stack_frame_init(&syscall_trampoline_crs,
			return_pv_vcpu_from_mkctxt, KERNEL_C_STACK_SIZE,
			E2K_KERNEL_PSR_DISABLED, 4, 4, false);
	ret |= pv_vcpu_user_hw_stacks_copy_crs(vcpu, &regs->g_stacks,
					regs, &syscall_trampoline_crs);
	if (unlikely(ret))
		return ret;

	return 0;
}

static __always_inline int
pv_vcpu_prepare_gst_mkctxt_trampoline_frame(struct pt_regs *regs,
						struct kvm_vcpu *vcpu)
{
	e2k_mem_crs_t *crs = &regs->crs;
	e2k_mem_ps_t ps_frames[4];
	int ret;

	/*
	 * kvm_guest_mkctxt_trampoline takes no args, create reg winodw
	 * of standard size (4 * qr) on procedure stack and init it by 0
	 */
	memset(ps_frames, 0, sizeof(ps_frames));
	ret = pv_vcpu_user_hw_stacks_copy_ps_frames(vcpu, &regs->g_stacks,
						regs, ps_frames, 4);
	if (unlikely(ret))
		return ret;

	/*
	 * Update crs (top of chain stack) to pass control to guest
	 * handler after return. Do not copy crs on chain stack,
	 * it will be written on cr register before return.
	 */
	memset(crs, 0, sizeof(*crs));

	crs->cr0_lo.CR0_lo_pf = -1ULL;
	crs->cr0_hi.CR0_hi_IP = vcpu->arch.gst_mkctxt_trampoline;
	/* real guest VCPU PSR should be as for user - nonprivileged */
	crs->cr1_lo.CR1_lo_psr = E2K_USER_INITIAL_PSR.PSR_reg;
	crs->cr1_lo.CR1_lo_cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1_lo.CR1_lo_ic = 0;
	crs->cr1_lo.CR1_lo_wpsz = 4;
	crs->cr1_lo.CR1_lo_wbs = 4;
	crs->cr1_hi.CR1_hi_ussz = regs->g_stacks.usd_hi.USD_hi_size >> 4;

	return 0;
}

static __always_inline void
setup_pv_vcpu_mkctxt_trampoline(struct pt_regs *regs,
				struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti;
	struct signal_stack_context __user *context;
	pv_vcpu_ctxt_t __user *vcpu_ctxt;
	int ret;

	/* Initialize regs->g_stacks by regs of guest kernel */
	prepare_pv_vcpu_inject_stacks(vcpu, regs);

	/*
	 * "Allocate" space on host signal stack of this thread to
	 * place there context, which should be restored after
	 * return from makontext handler function. This context
	 * should be placed in allocated space in do_swapcontext->
	 * Hypercall_longjmp.
	 *
	 * FIXME: Need to create own signal stack for each context.
	 * One signal stack for all thread is not allowed in multicontext
	 * mode.
	 */
	ret = reserve_signal_stack();
	if (unlikely(ret))
		do_exit(SIGKILL);
	gti = pv_vcpu_get_gti(vcpu);
	gti->signal.stack.base = current_thread_info()->signal_stack.base;
	gti->signal.stack.size = current_thread_info()->signal_stack.size;
	gti->signal.stack.used = current_thread_info()->signal_stack.used;

	/* Emulate return from guest syscall */
	context = get_signal_stack();
	vcpu_ctxt = &context->vcpu_ctxt;
	ret = __put_user(FROM_PV_VCPU_SYSCALL_INJECT,
				&vcpu_ctxt->inject_from);
	ret |= __put_user(false, &vcpu_ctxt->in_sig_handler);
	if (unlikely(ret)) {
		pop_signal_stack();
		do_exit(SIGKILL);
	}

	/*
	 * Prepare syscall_handler_trampoline frame on guest kernel stack
	 * Guest will return control to syscall_handler_trampoline after
	 * kvm_guest_mkctxt_trampoline switches context on guest's side
	 */
	ret = pv_vcpu_prepare_syscall_trampoline_frame(regs, vcpu);
	if (ret) {
		pop_signal_stack();
		do_exit(SIGKILL);
	}

	/*
	 * Prepare guest's kvm_guest_mkctxt_trampoline frames on stacks
	 * to pass control to it after return
	 */
	ret = pv_vcpu_prepare_gst_mkctxt_trampoline_frame(regs, vcpu);
	if (ret) {
		pop_signal_stack();
		do_exit(SIGKILL);
	}
}

static __always_inline void
guest_mkctxt_trampoline_inject(void)
{
	struct pt_regs regs;
	thread_info_t *ti = current_thread_info();
	struct kvm_vcpu *vcpu = ti->vcpu;
	u64 wsz;
	bool return_to_user;

	raw_all_irq_enable();

	/* Init pt_regs for intc mode */
	memset(&regs, 0, sizeof(struct pt_regs));
	kvm_set_intc_emul_flag(&regs);

	/* Save guest's stack regs state in pt_regs and emulated vcpu regs */
	SAVE_STACK_REGS(&regs, ti, true, false);
	save_pv_vcpu_sys_call_stack_regs(vcpu, &regs);

	/* Prepare all context on guest user stacks */
	setup_pv_vcpu_mkctxt_trampoline(&regs, vcpu);

	/*
	 * Set copy of kernel & host global regs ti initial state:
	 *	kernel gregs is zeroed
	 *	host VCPU state greg is inited by pointer to the VCPU
	 * interface with guest
	 */
	INIT_HOST_GREGS_COPY(ti, vcpu);

	host_return_to_guest_kernel(ti);
	pv_vcpu_swicth_to_guest_mmu_ctxt(ti, vcpu);

	/* restore guest UPSR and disable all interrupts */
	NATIVE_RETURN_TO_KERNEL_UPSR(ti->upsr);

	/*
	 * Handle all pending events before injecting
	 * to guest's mkctxt kernel handler
	 */
	wsz = get_wsz(FROM_SYSCALL_N_PROT);
	return_to_user = false;
	exit_to_usermode_loop(&regs, FROM_SYSCALL_N_PROT,
				&return_to_user, wsz, true);

	/* Switch to guest hw stacks */
	switch_to_gst_hw_stacks(&regs, &regs.g_stacks, vcpu);

	unreachable();
}

/* -------------------------------------------------------- */

static __always_inline notrace void
return_pv_vcpu_inject(inject_caller_t from)
{
	struct thread_info *ti = current_thread_info();
	struct kvm_vcpu *vcpu = current_thread_info()->vcpu;
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	struct signal_stack_context __user *context;
	typeof(context->vcpu_ctxt) vcpu_ctxt;
	struct pt_regs regs;
	struct trap_pt_regs saved_trap, *trap;
	gthread_info_t *gti;
	bool guest_user, user_stacks;
	u64 sbbp[SBBP_ENTRIES_NUM];
	e2k_aau_t aau_context;
	struct local_gregs l_gregs;
	e2k_stacks_t cur_g_stacks;
	e2k_pshtp_t u_pshtp;
	e2k_pcshtp_t u_pcshtp;
	e2k_wd_t wd;
	unsigned long ts_flag;
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
#endif	/* CONFIG_KERNEL_TIMES_ACCOUNT */

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_trap);

	context = get_signal_stack();

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __copy_from_user(&vcpu_ctxt, &context->vcpu_ctxt,
				sizeof(vcpu_ctxt));
	clear_ts_flag(ts_flag);
	if (ret) {
		user_exit();
		do_exit(SIGKILL);
	}

	if (likely(!vcpu_ctxt.in_sig_handler)) {
		KVM_BUG_ON(kvm_is_guest_migrated_to_other_vcpu(ti, vcpu));
	} else {
		/* return from trampoline was from guest user signal handler, */
		/* so the guest global registers contain user values and */
		/* migration checker can not be running here */

		ret = __copy_from_user_with_tags(&regs, &context->regs,
						 sizeof(regs));
		if (ret) {
			user_exit();
			do_exit(SIGKILL);
		}
		insert_pv_vcpu_sigreturn(vcpu, &vcpu_ctxt, &regs);
		/* should not be here */
		KVM_BUG_ON(true);
	}

	if (copy_context_from_signal_stack(&l_gregs, &regs, &saved_trap,
					   sbbp, &aau_context, NULL)) {
		user_exit();
		do_exit(SIGKILL);
	}

	KVM_BUG_ON(vcpu_ctxt.inject_from != from);
	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		syscall_handler_trampoline_finish(vcpu, &regs,
						  &vcpu_ctxt, host_ctxt);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		trap_handler_trampoline_finish(vcpu, &vcpu_ctxt, host_ctxt);
	} else {
		KVM_BUG_ON(true);
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
		regs.sys_rval = vcpu_ctxt.sys_rval;
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
			KVM_BUG_ON(regs.stacks.top < GUEST_TASK_SIZE);
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
		KVM_BUG_ON(true);
	}
#if DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
	debug_guest_ust = user_stacks;
#endif
	DebugUST("guest kernel chain stack final state: base 0x%llx "
		"ind 0x%x size 0x%x PCSHTP 0x%x\n",
		cur_g_stacks.pcsp_lo.PCSP_lo_base,
		cur_g_stacks.pcsp_hi.PCSP_hi_ind,
		cur_g_stacks.pcsp_hi.PCSP_hi_size,
		cur_g_stacks.pcshtp);
	DebugUST("guest kernel proc stack final state: base 0x%llx "
		"ind 0x%x size 0x%x PSHTP 0x%llx\n",
		cur_g_stacks.psp_lo.PSP_lo_base,
		cur_g_stacks.psp_hi.PSP_hi_ind,
		cur_g_stacks.psp_hi.PSP_hi_size,
		GET_PSHTP_MEM_INDEX(cur_g_stacks.pshtp));
	DebugUST("guest user chain stack state: base 0x%llx "
		"ind 0x%x size 0x%x PCSHTP 0x%x\n",
		regs.stacks.pcsp_lo.PCSP_lo_base,
		regs.stacks.pcsp_hi.PCSP_hi_ind,
		regs.stacks.pcsp_hi.PCSP_hi_size,
		regs.stacks.pcshtp);
	DebugUST("guest user proc stack state: base 0x%llx "
		"ind 0x%x size 0x%x PSHTP 0x%llx\n",
		regs.stacks.psp_lo.PSP_lo_base,
		regs.stacks.psp_hi.PSP_hi_ind,
		regs.stacks.psp_hi.PSP_hi_size,
		GET_PSHTP_MEM_INDEX(regs.stacks.pshtp));
	DebugUST("guest user already filled PSHTP 0x%llx PCSHTP 0x%x\n",
		GET_PSHTP_MEM_INDEX(u_pshtp), u_pcshtp);

	/*
	 * Restore proper psize as it was when signal was delivered.
	 * Alternative would be to create non-empty frame for
	 * procedure stack in prepare_sighandler_trampoline()
	 * if signal is delivered after a system call.
	 */
	if (AS(regs.wd).psize) {
		raw_all_irq_disable();
		wd = NATIVE_READ_WD_REG();
		wd.psize = AS(regs.wd).psize;
		NATIVE_WRITE_WD_REG(wd);
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
	if (trap && (3 * trap->curr_cnt) < trap->tc_count &&
			trap->tc_count > 0) {
		trap->from_sigreturn = 1;
		do_trap_cellar(&regs, 0);
	}

	clear_restore_sigmask();

	if (is_actual_pv_vcpu_l_gregs(vcpu)) {
		/* update "local" global registers which were changed */
		/* by page fault handlers */
		update_pv_vcpu_local_glob_regs(vcpu, &l_gregs);
	}
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
			KVM_BUG_ON(old_task != new_task);
		}
	}

	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		KVM_BUG_ON(regs.trap || regs.aau_context ||
				!regs.kernel_entry);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		KVM_BUG_ON(!regs.trap || !regs.aau_context ||
				regs.kernel_entry);
	} else {
		KVM_BUG_ON(true);
	}

	if (!user_stacks) {
		KVM_BUG_ON(from == FROM_PV_VCPU_SYSCALL_INJECT);
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
				if (!(context->sigact.sa.sa_flags & SA_RESTART)) {
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
			finish_user_trap_handler(&regs,
						 FROM_RETURN_PV_VCPU_TRAP);
		} else {
			KVM_BUG_ON(true);
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

	gti = pv_vcpu_get_gti(vcpu);
	COPY_U_HW_STACKS_FROM_TI(&cur_g_stacks, ti);
	raw_all_irq_enable();

	KVM_BUG_ON(kvm_is_guest_migrated_to_other_vcpu(ti, vcpu));

	if (unlikely(copy_pt_regs_from_signal_stack(&regs))) {
		user_exit();
		do_exit(SIGKILL);
	}

	/*
	 * Always make any pending restarted system call return -EINTR.
	 * Otherwise we might restart the wrong system call.
	 */
	current->restart_block.fn = do_no_restart_syscall;

	KVM_BUG_ON(!is_sys_call_pt_regs(&regs));

	/*
	 * Preserve current p[c]shtp as they indicate
	 * how much to FILL when returning
	 */
	u_pshtp = regs.stacks.pshtp;
	u_pcshtp = regs.stacks.pcshtp;
	regs.stacks.pshtp = cur_g_stacks.pshtp;
	regs.stacks.pcshtp = cur_g_stacks.pcshtp;

	regs.sys_rval = sys_rval;

	if (AS(regs.wd).psize) {
		/* restore proper WD sizes to avoid window bounds exceptions */
		raw_all_irq_disable();
		wd = NATIVE_READ_WD_REG();
		wd.psize = AS(regs.wd).psize;
		NATIVE_WRITE_WD_REG(wd);
		raw_all_irq_enable();
	}

	regs.next = NULL;
	/* Make sure 'pt_regs' are ready before enqueuing them */
	barrier();
	ti->pt_regs = &regs;

	clear_restore_sigmask();

	COPY_U_HW_STACKS_TO_STACKS(&regs.g_stacks, &cur_g_stacks);

	/* emulate restore of guest VCPU PSR state after return from syscall */
	kvm_emulate_guest_vcpu_psr_return(vcpu, &regs);

	finish_syscall(&regs, FROM_PV_VCPU_SYSFORK, true);
}
#else	/* !CONFIG_KVM_HOST_MODE */
/* It is native guest kernel whithout virtualization support */
/* Virtualiztion in guest mode cannot be supported */

static __always_inline void
guest_syscall_inject(thread_info_t *ti, pt_regs_t *regs)
{
	pr_err("%s() this kernel is not supported virtualization\n",
		__func__);
}

static __always_inline void
host_mkctxt_trampoline_inject(void)
{
	pr_err("%s() this kernel is not supported virtualization\n",
		__func__);
}

static __always_inline void
guest_mkctxt_complete(void)
{
	pr_err("%s() this kernel is not supported virtualization\n",
		__func__);
}

static __always_inline void
guest_mkctxt_trampoline_inject(void)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}

static __always_inline notrace void
return_pv_vcpu_inject(inject_caller_t from)
{
	pr_err("%s() this kernel is not supported virtualization\n", __func__);
}
static __always_inline notrace void
pv_vcpu_return_from_fork(u64 sys_rval)
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

#endif	/* CONFIG_KVM_HOST_MODE */

#endif	/* _E2K_KVM_TTABLE_H */
