#ifndef _E2K_KVM_SWITCH_H
#define _E2K_KVM_SWITCH_H

#include <linux/kvm_host.h>
#include <asm/machdep.h>
#include <asm/mmu_context.h>
#include <asm/aau_context.h>
#include <asm/alternative.h>
#include <asm/mmu_regs_access.h>
#include <asm/gregs.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>

/*
 * See below the 'flags' argument of xxx_guest_enter()/xxx_guest_exit()
 */
#define	FULL_CONTEXT_SWITCH	0x0001U	/* save/restore full guest/host */
					/* context */
#define	FROM_HYPERCALL_SWITCH	0x0002U	/* save/restore full guest/host */
					/* before/after hypercall */
#define	USD_CONTEXT_SWITCH	0x0004U	/* save/restore local data stack */
#define	DEBUG_REGS_SWITCH	0x0008U	/* save/restore debugging registers */
#define	DONT_CU_REGS_SWITCH	0x0010U	/* do not save/restore CUT and CU */
					/* registers */
#define DONT_MMU_CONTEXT_SWITCH	0x0020U	/* do not switch MMU context */
#define	DONT_SAVE_GREGS_SWITCH	0x0040U	/* do not save global regs */
#define	DONT_AAU_CONTEXT_SWITCH	0x0080U	/* do not switch AAU context */
#define	EXIT_FROM_INTC_SWITCH	0x0100U	/* complete intercept emulation mode */
#define	EXIT_FROM_TRAP_SWITCH	0x0200U	/* complete trap mode */

static inline void
native_trap_guest_enter(struct thread_info *ti, struct pt_regs *regs,
			unsigned flags)
{
	/* nothing guests can be */

	if (flags & EXIT_FROM_INTC_SWITCH)
		return;
	/* IMPORTANT: do NOT access current, current_thread_info() */
	/* and per-cpu variables after this point */
	if (flags & EXIT_FROM_TRAP_SWITCH) {
		NATIVE_RESTORE_KERNEL_GREGS(&ti->k_gregs);
	}
}
static inline void
native_trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
			trap_pt_regs_t *trap, unsigned flags)
{
	/* nothing guests can be */
}
static inline bool
native_guest_trap_pending(struct thread_info *ti)
{
	/* there is not any guest */
	return false;
}

static inline bool
native_trap_from_guest_user(struct thread_info *ti)
{
	/* there is not any guest */
	return false;
}

static inline bool
native_syscall_from_guest_user(struct thread_info *ti)
{
	/* there is not any guest */
	return false;
}

static inline struct e2k_stacks *
native_trap_guest_get_restore_stacks(struct thread_info *ti,
				     struct pt_regs *regs)
{
	return &regs->stacks;
}

static inline struct e2k_stacks *
native_syscall_guest_get_restore_stacks(struct thread_info *ti,
					struct pt_regs *regs)
{
	return &regs->stacks;
}

/*
 * The function should return bool is the system call from guest
 */
static inline bool
native_guest_syscall_enter(struct thread_info *ti, struct pt_regs *regs)
{
	/* nothing guests can be */

	return false;	/* it is not guest system call */
}
static inline void
native_guest_syscall_exit_to(struct thread_info *ti, struct pt_regs *regs,
				unsigned flags)
{
	/* nothing guests can be */
}

#ifdef	CONFIG_VIRTUALIZATION

/*
 * Normally data stack is switched on interceptions as follows:
 * 1) Upon interception guest's USD_hi.size is saved into backup
 * stacks (cr1_lo.ussz field).
 * 2) Then hardware switches PCSP stack (see Phase 5) and does an
 * equivalent of DONE which modifies guest's USD with 'cr1_lo.ussz'
 * from the function that called GLAUNCH.
 * 3) Hypervisor in software saves this modified USD and restores it
 * before GLAUNCH.
 * 4) Hardware in GLAUNCH switches PCSP stack (see Phase 4)
 * 5) Hardware in GLAUNCH does an equivalent of DONE (see Phase 6)
 * which restores proper guest USD.
 *
 * But if hypervisor sets VIRT_CTRL_CU.glnch.g_th then that DONE is
 * skipped and guest's data stack is incorrect. So we manually do
 * here what DONE does. For simplicity do it always although it
 * actually is needed only in 'g_th' case.
 */
static inline void kvm_correct_guest_data_stack_regs(
		struct kvm_sw_cpu_context *sw_ctxt, e2k_cr1_hi_t cr1_hi)
{
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_size_t real_size;

	real_size = cr1_hi.CR1_hi_ussz << 4;
	usd_hi = sw_ctxt->usd_hi;
	usd_lo = sw_ctxt->usd_lo;
	usd_lo.USD_lo_base += (real_size - usd_hi.USD_hi_size);
	usd_hi.USD_hi_size = real_size;
	sw_ctxt->usd_lo = usd_lo;
	sw_ctxt->usd_hi = usd_hi;
}

/*
 * For interceptions just switch actual registers with saved values
 * in 'sw_ctxt'.
 *
 * For hypercalls:
 * 1) Enter hypercall.
 * 2) Save previous values from 'sw_ctxt' to 'sw_ctxt->saved'.
 * 3) Switch actual registers with saved values in @sw_ctxt.
 * 4) Allocate stack with getsp.
 * 5) After hypercall completion switch registers back to guest values.
 * 6) Restore 'sw_ctxt' from 'sw_ctxt->saved'
 * (because 'getsp' above has changed registers we cannot use their values).
 */
static inline void kvm_switch_stack_regs(struct kvm_sw_cpu_context *sw_ctxt,
				bool ctxt_save, bool ctxt_restore)
{
	e2k_usd_lo_t usd_lo;
	e2k_usd_hi_t usd_hi;
	e2k_sbr_t sbr;

	KVM_BUG_ON(ctxt_save && ctxt_restore);

	if (!ctxt_restore) {
		AW(usd_lo) = NATIVE_NV_READ_USD_LO_REG_VALUE();
		AW(usd_hi) = NATIVE_NV_READ_USD_HI_REG_VALUE();
		AW(sbr) = NATIVE_NV_READ_SBR_REG_VALUE();
	}

	NATIVE_NV_WRITE_USBR_USD_REG(sw_ctxt->sbr,
			sw_ctxt->usd_hi, sw_ctxt->usd_lo);

	if (ctxt_save) {
		KVM_BUG_ON(sw_ctxt->saved.valid);
		sw_ctxt->saved.sbr = sw_ctxt->sbr;
		sw_ctxt->saved.usd_lo = sw_ctxt->usd_lo;
		sw_ctxt->saved.usd_hi = sw_ctxt->usd_hi;
		sw_ctxt->saved.valid = true;
	}
	if (!ctxt_restore) {
		sw_ctxt->sbr = sbr;
		sw_ctxt->usd_lo = usd_lo;
		sw_ctxt->usd_hi = usd_hi;
	} else {
		KVM_BUG_ON(!sw_ctxt->saved.valid);
		sw_ctxt->sbr = sw_ctxt->saved.sbr;
		sw_ctxt->usd_lo = sw_ctxt->saved.usd_lo;
		sw_ctxt->usd_hi = sw_ctxt->saved.usd_hi;
		sw_ctxt->saved.valid = false;
	}
}

#define	Compiler_bug_128308_workaround

#ifndef	Compiler_bug_128308_workaround
static inline void kvm_switch_fpu_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	e2k_upsr_t upsr;

	fpcr = NATIVE_NV_READ_FPCR_REG();
	fpsr = NATIVE_NV_READ_FPSR_REG();
	pfpfr = NATIVE_NV_READ_PFPFR_REG();
	upsr = NATIVE_NV_READ_UPSR_REG();

	NATIVE_NV_WRITE_FPCR_REG(sw_ctxt->fpcr);
	NATIVE_NV_WRITE_FPSR_REG(sw_ctxt->fpsr);
	NATIVE_NV_WRITE_PFPFR_REG(sw_ctxt->pfpfr);
	NATIVE_WRITE_UPSR_REG(sw_ctxt->upsr);

	sw_ctxt->fpcr = fpcr;
	sw_ctxt->fpsr = fpsr;
	sw_ctxt->pfpfr = pfpfr;
	sw_ctxt->upsr = upsr;
}
#else	/* Compiler_bug_128308_workaround */
extern noinline void kvm_switch_fpu_regs(struct kvm_sw_cpu_context *sw_ctxt);
#endif	/* !Compiler_bug_128308_workaround */

static inline void kvm_switch_cu_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	e2k_cutd_t cutd;

	AW(cutd) = NATIVE_NV_READ_CUTD_REG_VALUE();

	NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(AW(sw_ctxt->cutd));
	sw_ctxt->cutd = cutd;
}

static inline void kvm_switch_mmu_pt_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	mmu_reg_t u_pptb;
	mmu_reg_t u_vptb;

	u_pptb = NATIVE_READ_MMU_U_PPTB_REG();
	u_vptb = NATIVE_READ_MMU_U_VPTB_REG();

	NATIVE_WRITE_MMU_U_PPTB_REG(sw_ctxt->sh_u_pptb);
	NATIVE_WRITE_MMU_U_VPTB_REG(sw_ctxt->sh_u_vptb);

	sw_ctxt->sh_u_pptb = u_pptb;
	sw_ctxt->sh_u_vptb = u_vptb;
}

static inline void kvm_switch_mmu_tc_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	mmu_reg_t tc_hpa;
	mmu_reg_t trap_count;

	tc_hpa = NATIVE_READ_MMU_TRAP_POINT();
	trap_count = NATIVE_READ_MMU_TRAP_COUNT();

	NATIVE_WRITE_MMU_TRAP_POINT(sw_ctxt->tc_hpa);
	NATIVE_WRITE_MMU_TRAP_COUNT(sw_ctxt->trap_count);

	sw_ctxt->tc_hpa = tc_hpa;
	sw_ctxt->trap_count = trap_count;
}

static inline void kvm_switch_mmu_regs(struct kvm_sw_cpu_context *sw_ctxt,
					bool switch_tc)
{
	kvm_switch_mmu_pt_regs(sw_ctxt);
	if (switch_tc)
		kvm_switch_mmu_tc_regs(sw_ctxt);
}

static inline void kvm_switch_to_guest_mmu_pid(struct kvm_vcpu *vcpu)
{
	mm_context_t *gmm_context;

	gmm_context = pv_vcpu_get_gmm_context(vcpu);
	reload_mmu_pid(gmm_context, smp_processor_id());
}

static inline void kvm_switch_to_host_mmu_pid(struct mm_struct *mm)
{
	reload_context(mm, smp_processor_id());
}

static inline void kvm_switch_debug_regs(struct kvm_sw_cpu_context *sw_ctxt,
					 int is_active)
{
	u64 b_dimar0, b_dimar1, b_ddmar0, b_ddmar1, b_dibar0, b_dibar1,
	    b_dibar2, b_dibar3, b_ddbar0, b_ddbar1, b_ddbar2, b_ddbar3,
	    a_dimar0, a_dimar1, a_ddmar0, a_ddmar1, a_dibar0, a_dibar1,
	    a_dibar2, a_dibar3, a_ddbar0, a_ddbar1, a_ddbar2, a_ddbar3;
	e2k_dimcr_t b_dimcr, a_dimcr;
	e2k_ddmcr_t b_ddmcr, a_ddmcr;
	e2k_dibcr_t b_dibcr, a_dibcr;
	e2k_dibsr_t b_dibsr, a_dibsr;
	e2k_ddbcr_t b_ddbcr, a_ddbcr;
	e2k_ddbsr_t b_ddbsr, a_ddbsr;

	b_dibcr = sw_ctxt->dibcr;
	b_ddbcr = sw_ctxt->ddbcr;
	b_dibsr = sw_ctxt->dibsr;
	b_ddbsr = sw_ctxt->ddbsr;
	b_dimcr = sw_ctxt->dimcr;
	b_ddmcr = sw_ctxt->ddmcr;
	b_dibar0 = sw_ctxt->dibar0;
	b_dibar1 = sw_ctxt->dibar1;
	b_dibar2 = sw_ctxt->dibar2;
	b_dibar3 = sw_ctxt->dibar3;
	b_ddbar0 = sw_ctxt->ddbar0;
	b_ddbar1 = sw_ctxt->ddbar1;
	b_ddbar2 = sw_ctxt->ddbar2;
	b_ddbar3 = sw_ctxt->ddbar3;
	b_dimar0 = sw_ctxt->dimar0;
	b_dimar1 = sw_ctxt->dimar1;
	b_ddmar0 = sw_ctxt->ddmar0;
	b_ddmar1 = sw_ctxt->ddmar1;

	a_dibcr = NATIVE_READ_DIBCR_REG();
	a_ddbcr = NATIVE_READ_DDBCR_REG();
	a_dibsr = NATIVE_READ_DIBSR_REG();
	a_ddbsr = NATIVE_READ_DDBSR_REG();
	a_dimcr = NATIVE_READ_DIMCR_REG();
	a_ddmcr = NATIVE_READ_DDMCR_REG();
	a_dibar0 = NATIVE_READ_DIBAR0_REG_VALUE();
	a_dibar1 = NATIVE_READ_DIBAR1_REG_VALUE();
	a_dibar2 = NATIVE_READ_DIBAR2_REG_VALUE();
	a_dibar3 = NATIVE_READ_DIBAR3_REG_VALUE();
	a_ddbar0 = NATIVE_READ_DDBAR0_REG_VALUE();
	a_ddbar1 = NATIVE_READ_DDBAR1_REG_VALUE();
	a_ddbar2 = NATIVE_READ_DDBAR2_REG_VALUE();
	a_ddbar3 = NATIVE_READ_DDBAR3_REG_VALUE();
	a_ddmar0 = NATIVE_READ_DDMAR0_REG_VALUE();
	a_ddmar1 = NATIVE_READ_DDMAR1_REG_VALUE();
	a_dimar0 = NATIVE_READ_DIMAR0_REG_VALUE();
	a_dimar1 = NATIVE_READ_DIMAR1_REG_VALUE();

	if (is_active) {
		/* These two must be written first to disable monitoring */
		NATIVE_WRITE_DIBCR_REG(b_dibcr);
		NATIVE_WRITE_DDBCR_REG(b_ddbcr);
	}
	NATIVE_WRITE_DIBAR0_REG_VALUE(b_dibar0);
	NATIVE_WRITE_DIBAR1_REG_VALUE(b_dibar1);
	NATIVE_WRITE_DIBAR2_REG_VALUE(b_dibar2);
	NATIVE_WRITE_DIBAR3_REG_VALUE(b_dibar3);
	NATIVE_WRITE_DDBAR0_REG_VALUE(b_ddbar0);
	NATIVE_WRITE_DDBAR1_REG_VALUE(b_ddbar1);
	NATIVE_WRITE_DDBAR2_REG_VALUE(b_ddbar2);
	NATIVE_WRITE_DDBAR3_REG_VALUE(b_ddbar3);
	NATIVE_WRITE_DDMAR0_REG_VALUE(b_ddmar0);
	NATIVE_WRITE_DDMAR1_REG_VALUE(b_ddmar1);
	NATIVE_WRITE_DIMAR0_REG_VALUE(b_dimar0);
	NATIVE_WRITE_DIMAR1_REG_VALUE(b_dimar1);
	NATIVE_WRITE_DIBSR_REG(b_dibsr);
	NATIVE_WRITE_DDBSR_REG(b_ddbsr);
	NATIVE_WRITE_DIMCR_REG(b_dimcr);
	NATIVE_WRITE_DDMCR_REG(b_ddmcr);
	if (!is_active) {
		/* These two must be written last to enable monitoring */
		NATIVE_WRITE_DIBCR_REG(b_dibcr);
		NATIVE_WRITE_DDBCR_REG(b_ddbcr);
	}

	sw_ctxt->dibcr = a_dibcr;
	sw_ctxt->ddbcr = a_ddbcr;
	sw_ctxt->dibsr = a_dibsr;
	sw_ctxt->ddbsr = a_ddbsr;
	sw_ctxt->dimcr = a_dimcr;
	sw_ctxt->ddmcr = a_ddmcr;
	sw_ctxt->dibar0 = a_dibar0;
	sw_ctxt->dibar1 = a_dibar1;
	sw_ctxt->dibar2 = a_dibar2;
	sw_ctxt->dibar3 = a_dibar3;
	sw_ctxt->ddbar0 = a_ddbar0;
	sw_ctxt->ddbar1 = a_ddbar1;
	sw_ctxt->ddbar2 = a_ddbar2;
	sw_ctxt->ddbar3 = a_ddbar3;
	sw_ctxt->ddmar0 = a_ddmar0;
	sw_ctxt->ddmar1 = a_ddmar1;
	sw_ctxt->dimar0 = a_dimar0;
	sw_ctxt->dimar1 = a_dimar1;

}

static inline void
switch_ctxt_trap_enable_mask(struct kvm_sw_cpu_context *sw_ctxt)
{
	unsigned osem;

	osem = NATIVE_READ_OSEM_REG_VALUE();
	NATIVE_WRITE_OSEM_REG_VALUE(sw_ctxt->osem);
	sw_ctxt->osem = osem;
}

static inline void host_guest_enter(struct thread_info *ti,
			struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	switch_ctxt_trap_enable_mask(sw_ctxt);
	/* In full virtualization mode guest sets his own OSEM in thread_init() */
	if (!vcpu->is_hv)
		KVM_BUG_ON((NATIVE_READ_OSEM_REG_VALUE() & HYPERCALLS_TRAPS_MASK) !=
			HYPERCALLS_TRAPS_MASK);

	if (flags & FROM_HYPERCALL_SWITCH) {
		/*
		 * Hypercalls - both hardware and software virtualization
		 */
		KVM_BUG_ON(!sw_ctxt->in_hypercall);
		sw_ctxt->in_hypercall = false;

		/* For hypercalls skip the extended part. */
		HOST_RESTORE_HOST_GREGS(ti);

		/* compilation units context */
		if (!(flags & DONT_CU_REGS_SWITCH)) {
			kvm_switch_cu_regs(sw_ctxt);
		}

		/* restore guest PT context (U_PPTB/U_VPTB) */
		if (!(flags & DONT_MMU_CONTEXT_SWITCH)) {
			kvm_switch_mmu_regs(sw_ctxt, vcpu->is_hv);
		}
	} else if (flags & FULL_CONTEXT_SWITCH) {

		/*
		 * Interceptions - hardware support is enabled
		 */
#ifdef CONFIG_USE_AAU
		if (!(flags & DONT_AAU_CONTEXT_SWITCH))
			machine.calculate_aau_aaldis_aaldas(NULL, ti, &sw_ctxt->aau_context);
#endif

		/* For interceptions restore extended part */
		NATIVE_RESTORE_KERNEL_GREGS(&ti->k_gregs);

		NATIVE_RESTORE_INTEL_REGS(sw_ctxt);

		/* Isolate from QEMU */
		/* TODO if we want to call QEMU from hypercalls,then
		 * we should switch more context in hypercalls - see
		 * the list in sw_ctxt definition */
		kvm_switch_fpu_regs(sw_ctxt);
		kvm_switch_cu_regs(sw_ctxt);
		kvm_switch_mmu_regs(sw_ctxt, vcpu->is_hv);

#ifdef CONFIG_USE_AAU
		if (!(flags & DONT_AAU_CONTEXT_SWITCH)) {
			/*
			 * We cannot rely on %aasr value since interception could have
			 * happened in guest user before "bap" or in guest trap handler
			 * before restoring %aasr, so we must restore all AAU registers.
			 */
			native_clear_apb();
			native_set_aau_context(&sw_ctxt->aau_context);

			/*
			 * It's important to restore AAD after all return operations.
			 */
			NATIVE_RESTORE_AADS(&sw_ctxt->aau_context);
		}
#endif
	} else {
		/*
		 * Return from emulation of interseption to paravirtualized
		 * vcpu
		 */

		/* switch to guest MMU context to continue guest execution */
		kvm_switch_mmu_regs(sw_ctxt, false);
	}

	if (flags & DEBUG_REGS_SWITCH)
		kvm_switch_debug_regs(sw_ctxt, true);

	/* Switch data stack after all function calls */
	if (flags & USD_CONTEXT_SWITCH) {
		if (!(flags & FROM_HYPERCALL_SWITCH) || !vcpu->is_hv) {
			kvm_switch_stack_regs(sw_ctxt, false, false);
		} else {
			/* restore saved source pointers of host stack */
			kvm_switch_stack_regs(sw_ctxt, false, true);
		}
	}
}

static inline void host_guest_enter_light(struct thread_info *ti,
					struct kvm_vcpu_arch *vcpu,
					bool from_sdisp)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	KVM_BUG_ON(!sw_ctxt->in_hypercall);
	sw_ctxt->in_hypercall = false;

	HOST_RESTORE_KERNEL_GREGS_AS_LIGHT(ti);

	kvm_switch_cu_regs(sw_ctxt);

	/* Switch data stack after all function calls */
	if (!from_sdisp) {
		if (!vcpu->is_hv) {
			kvm_switch_stack_regs(sw_ctxt, false, false);
		} else {
			/* restore saved source pointers of host stack */
			kvm_switch_stack_regs(sw_ctxt, false, true);
		}
	}
}

static inline void host_guest_exit(struct thread_info *ti,
			struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	switch_ctxt_trap_enable_mask(sw_ctxt);
	KVM_BUG_ON(NATIVE_READ_OSEM_REG_VALUE() & HYPERCALLS_TRAPS_MASK);

	/* Switch data stack before all function calls */
	if (flags & USD_CONTEXT_SWITCH) {
		if (!(flags & FROM_HYPERCALL_SWITCH) || !vcpu->is_hv) {
			kvm_switch_stack_regs(sw_ctxt, false, false);
		} else {
			/* save source pointers of host stack */
			kvm_switch_stack_regs(sw_ctxt, true, false);
		}
	}

	if (flags & FROM_HYPERCALL_SWITCH) {
		/*
		 * Hypercalls - both hardware and software virtualization
		 */
		KVM_BUG_ON(sw_ctxt->in_hypercall);
		sw_ctxt->in_hypercall = true;

		/* For hypercalls skip the extended part. */
		HOST_SAVE_HOST_GREGS(ti);
		ONLY_SET_KERNEL_GREGS(ti);

		/* compilation units context */
		if (!(flags & DONT_CU_REGS_SWITCH)) {
			kvm_switch_cu_regs(sw_ctxt);
		}
		/* save guest PT context (U_PPTB/U_VPTB) and restore host */
		/* user PT context */
		if (!(flags & DONT_MMU_CONTEXT_SWITCH)) {
			kvm_switch_mmu_regs(sw_ctxt, vcpu->is_hv);
		}
	} else if (flags & FULL_CONTEXT_SWITCH) {

		/*
		 * Interceptions - hardware support is enabled
		 */
#ifdef CONFIG_USE_AAU
		if (!(flags & DONT_AAU_CONTEXT_SWITCH)) {
			e2k_aasr_t aasr;

			/*
			 * We cannot rely on %aasr value since interception could have
			 * happened in guest user before "bap" or in guest trap handler
			 * before restoring %aasr, so we must save all AAU registers.
			 * Several macroses use %aasr to determine, which registers to
			 * save/restore, so pass worst-case %aasr to them in
			 * sw_ctxt->aau_context, and save the actual guest value to
			 * sw_ctxt->aasr
			 */
			aasr = native_read_aasr_reg();
			SWITCH_GUEST_AAU_AASR(&aasr, &sw_ctxt->aau_context, 1);
			/*
			 * This is placed before saving intc cellar since it is done
			 * with 'mmurr' instruction which requires AAU to be stopped.
			 *
			 * Do this before saving %sbbp as it uses 'alc'
			 * and thus zeroes %aaldm.
			 */
			NATIVE_SAVE_AAU_MASK_REGS(&sw_ctxt->aau_context, aasr);

			/* It's important to save AAD before all call operations. */
			NATIVE_SAVE_AADS(&sw_ctxt->aau_context);
			/*
			 * Function calls are allowed from this point on,
			 * mark it with a compiler barrier.
			 */
			barrier();

			/* Since iset v6 %aaldi must be saved too */
			NATIVE_SAVE_AALDIS(sw_ctxt->aau_context.aaldi);

			machine.get_aau_context(&sw_ctxt->aau_context);

			native_clear_apb();
		}
#endif

		/* No atomic/DAM operations are allowed before this point.
		 * Note that we cannot do this before saving AAU. */
		if (cpu_has(CPU_HWBUG_L1I_STOPS_WORKING))
			E2K_DISP_CTPRS();

		/* For interceptions save extended part. */
		machine.save_kernel_gregs(&ti->k_gregs);
		ONLY_SET_KERNEL_GREGS(ti);

		NATIVE_SAVE_INTEL_REGS(sw_ctxt);
#ifdef CONFIG_MLT_STORAGE
		machine.invalidate_MLT();
#endif
		if (machine.flushts)
			machine.flushts();

		/* Isolate from QEMU */
		kvm_switch_fpu_regs(sw_ctxt);
		kvm_switch_cu_regs(sw_ctxt);
		kvm_switch_mmu_regs(sw_ctxt, vcpu->is_hv);
	} else {
		/*
		 * Starting emulation of interseption of paravirtualized vcpu
		 */

		/* switch to hypervisor MMU context to emulate hw intercept */
		kvm_switch_mmu_regs(sw_ctxt, false);
	}

	if (flags & DEBUG_REGS_SWITCH)
		kvm_switch_debug_regs(sw_ctxt, false);
}

static inline void host_guest_exit_light(struct thread_info *ti,
					struct kvm_vcpu_arch *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	KVM_BUG_ON(sw_ctxt->in_hypercall);
	sw_ctxt->in_hypercall = true;

	HOST_SAVE_KERNEL_GREGS_AS_LIGHT(ti);
	ONLY_SET_KERNEL_GREGS(ti);

	kvm_switch_cu_regs(sw_ctxt);
}

/*
 * Some hypercalls return to guest from other exit point then
 * usual hypercall return from. So it need some clearing hypercall track.
 */
static inline bool
host_hypercall_exit(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	if (sw_ctxt->in_hypercall) {
		sw_ctxt->in_hypercall = false;
		return true;
	}
	return false;
}


/*
 * Some hypercalls return from hypercall to host.
 * So it need some restore host context and some clearing hypercall track.
 */
static inline void hypercall_exit_to_host(struct kvm_vcpu *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	switch_ctxt_trap_enable_mask(sw_ctxt);

	KVM_BUG_ON(!sw_ctxt->in_hypercall);

	host_hypercall_exit(vcpu);
}

/*
 * Save/restore VCPU host kernel thread context during switching from
 * one guest threads (current) to other guest thread (next)
 * It need now save only signal context, because of host kernel stacks
 * are the same for all guest threads (processes).
 */
static inline void
pv_vcpu_save_host_context(struct kvm_vcpu *vcpu, gthread_info_t *cur_gti)
{
	cur_gti->signal.stack.base = current_thread_info()->signal_stack.base;
	cur_gti->signal.stack.size = current_thread_info()->signal_stack.size;
	cur_gti->signal.stack.used = current_thread_info()->signal_stack.used;
	cur_gti->signal.traps_num = vcpu->arch.host_ctxt.signal.traps_num;
	cur_gti->signal.in_work = vcpu->arch.host_ctxt.signal.in_work;
	cur_gti->signal.syscall_num = vcpu->arch.host_ctxt.signal.syscall_num;
	cur_gti->signal.in_syscall = vcpu->arch.host_ctxt.signal.in_syscall;
}

static inline void
pv_vcpu_restore_host_context(struct kvm_vcpu *vcpu, gthread_info_t *next_gti)
{
	current_thread_info()->signal_stack.base = next_gti->signal.stack.base;
	current_thread_info()->signal_stack.size = next_gti->signal.stack.size;
	current_thread_info()->signal_stack.used = next_gti->signal.stack.used;
	vcpu->arch.host_ctxt.signal.traps_num = next_gti->signal.traps_num;
	vcpu->arch.host_ctxt.signal.in_work = next_gti->signal.in_work;
	vcpu->arch.host_ctxt.signal.syscall_num = next_gti->signal.syscall_num;
	vcpu->arch.host_ctxt.signal.in_syscall = next_gti->signal.in_syscall;
}

static inline void
pv_vcpu_switch_guest_host_context(struct kvm_vcpu *vcpu,
		gthread_info_t *cur_gti, gthread_info_t *next_gti)
{
	pv_vcpu_save_host_context(vcpu, cur_gti);
	pv_vcpu_restore_host_context(vcpu, next_gti);
}

static inline void pv_vcpu_switch_host_context(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	unsigned long	*stack;
	pt_regs_t	*regs;
	e2k_usd_hi_t	k_usd_hi;
	e2k_usd_lo_t	k_usd_lo;
	e2k_sbr_t	k_sbr;
	e2k_psp_lo_t	k_psp_lo;
	e2k_psp_hi_t	k_psp_hi;
	e2k_pcsp_lo_t	k_pcsp_lo;
	e2k_pcsp_hi_t	k_pcsp_hi;
	unsigned long	base;
	unsigned long	size;
	unsigned long	used;

	/* keep current state of context */
	stack = current->stack;
	regs = current_thread_info()->pt_regs;
	k_usd_lo = current_thread_info()->k_usd_lo;
	k_usd_hi = current_thread_info()->k_usd_hi;
	k_sbr.SBR_reg = (unsigned long)stack + KERNEL_C_STACK_SIZE +
					       KERNEL_C_STACK_OFFSET;
	k_psp_lo = current_thread_info()->k_psp_lo;
	k_psp_hi = current_thread_info()->k_psp_hi;
	k_pcsp_lo = current_thread_info()->k_pcsp_lo;
	k_pcsp_hi = current_thread_info()->k_pcsp_hi;

	/* restore VCPU thread context */
	current->stack = host_ctxt->stack;
	current_thread_info()->pt_regs = host_ctxt->pt_regs;
	current_thread_info()->k_usd_hi = host_ctxt->k_usd_hi;
	current_thread_info()->k_usd_lo = host_ctxt->k_usd_lo;
	current_thread_info()->k_psp_lo = host_ctxt->k_psp_lo;
	current_thread_info()->k_psp_hi = host_ctxt->k_psp_hi;
	current_thread_info()->k_pcsp_lo = host_ctxt->k_pcsp_lo;
	current_thread_info()->k_pcsp_hi = host_ctxt->k_pcsp_hi;

	/* save VCPU thread context */
	host_ctxt->stack = stack;
	host_ctxt->pt_regs = regs;
	host_ctxt->k_usd_lo = k_usd_lo;
	host_ctxt->k_usd_hi = k_usd_hi;
	host_ctxt->k_sbr = k_sbr;
	host_ctxt->k_psp_lo = k_psp_lo;
	host_ctxt->k_psp_hi = k_psp_hi;
	host_ctxt->k_pcsp_lo = k_pcsp_lo;
	host_ctxt->k_pcsp_hi = k_pcsp_hi;

	/* keep current signal stack state */
	base = current_thread_info()->signal_stack.base;
	size = current_thread_info()->signal_stack.size;
	used = current_thread_info()->signal_stack.used;
	/* atomic trap_num is not used for host thread, so keep it in place */

	/* restote VCPU thread signal stack state */
	current_thread_info()->signal_stack.base = host_ctxt->signal.stack.base;
	current_thread_info()->signal_stack.size = host_ctxt->signal.stack.size;
	current_thread_info()->signal_stack.used = host_ctxt->signal.stack.used;

	/* save VCPU thread signal stack state */
	host_ctxt->signal.stack.base = base;
	host_ctxt->signal.stack.size = size;
	host_ctxt->signal.stack.used = used;
	/* atomic trap_num & in_work & syscall_num & in_syscall will not be */
	/* used for host thread, so keep it in place for last guest thread */
}

static inline void pv_vcpu_exit_to_host(struct kvm_vcpu *vcpu)
{
	/* save VCPU guest thread context */
	/* restore VCPU host thread context */
	pv_vcpu_switch_host_context(vcpu);
}

static inline void pv_vcpu_enter_to_guest(struct kvm_vcpu *vcpu)
{
	/* save VCPU host thread context */
	/* restore VCPU guest thread context */
	pv_vcpu_switch_host_context(vcpu);
}

static inline void
host_switch_trap_enable_mask(struct thread_info *ti, struct pt_regs *regs,
				bool guest_enter)
{
	struct kvm_vcpu *vcpu;
	struct kvm_sw_cpu_context *sw_ctxt;

	if (trap_on_guest(regs)) {
		vcpu = ti->vcpu;
		sw_ctxt = &vcpu->arch.sw_ctxt;
		if (guest_enter) {
			/* return from trap, restore hypercall flag */
			sw_ctxt->in_hypercall = regs->in_hypercall;
		} else {	/* guest exit */
			/* enter to trap, save hypercall flag because of */
			/* trap handler can pass traps to guest and run */
			/* guest trap handler with recursive hypercalls */
			regs->in_hypercall = sw_ctxt->in_hypercall;
		}
		if (sw_ctxt->in_hypercall) {
			/* mask should be already switched or */
			/* will be switched by hypercall */
			return;
		}
		switch_ctxt_trap_enable_mask(sw_ctxt);
	}
}

static __always_inline bool
pv_vcpu_trap_on_guest_kernel(pt_regs_t *regs)
{
	if (regs && is_trap_pt_regs(regs) && guest_kernel_mode(regs))
		return true;

	return false;
}

static inline bool
host_guest_trap_pending(struct thread_info *ti)
{
	struct pt_regs *regs = ti->pt_regs;
	struct kvm_vcpu *vcpu;

	if (likely(!regs || !is_trap_pt_regs(regs) ||
					!kvm_test_intc_emul_flag(regs))) {
		/* it is not paravirtualized guest VCPU intercepts */
		/* emulation mode, so nothing to do more */
		return false;
	}
	vcpu = ti->vcpu;
	if (!kvm_check_is_vcpu_intc_TIRs_empty(vcpu)) {
		/* there are some injected traps for guest */
		kvm_clear_vcpu_guest_stacks_pending(vcpu, regs);
		return true;
	}
	if (kvm_is_vcpu_guest_stacks_pending(vcpu, regs)) {
		/* guest user spilled stacks is not empty, */
		/* so it need rocover its */
		return true;
	}
	return false;
}

static inline bool
host_trap_from_guest_user(struct thread_info *ti)
{
	struct pt_regs *regs = ti->pt_regs;

	if (likely(!host_guest_trap_pending(ti) && regs->traps_to_guest == 0))
		return false;
	return !pv_vcpu_trap_on_guest_kernel(ti->pt_regs);
}

static inline bool
host_syscall_from_guest_user(struct thread_info *ti)
{
	struct pt_regs *regs = ti->pt_regs;

	if (likely(!regs || is_trap_pt_regs(regs) ||
					!kvm_test_intc_emul_flag(regs))) {
		/* it is not paravirtualized guest VCPU intercepts */
		/* emulation mode, so nothing system calls from guest */
		return false;
	}
	KVM_BUG_ON(ti->vcpu == NULL);
	KVM_BUG_ON(guest_kernel_mode(regs));
	return true;
}

static inline void
host_trap_guest_exit_intc(struct thread_info *ti, struct pt_regs *regs)
{
	if (!kvm_test_and_clear_intc_emul_flag(regs)) {
		/* it is not paravirtualized guest VCPU intercepts*/
		/* emulation mode, so nothing to do more */
		return;
	}

	/*
	 * Return from trap on paravirtualized guest VCPU which was
	 * interpreted as interception
	 */
	return_from_pv_vcpu_intc(ti, regs);
}

static inline bool
host_return_to_injected_guest_syscall(struct thread_info *ti, pt_regs_t *regs)
{
	struct kvm_vcpu *vcpu;
	int syscall_num, in_syscall;

	vcpu = ti->vcpu;
	syscall_num = atomic_read(&vcpu->arch.host_ctxt.signal.syscall_num);
	in_syscall = atomic_read(&vcpu->arch.host_ctxt.signal.in_syscall);

	if (likely(syscall_num > 0)) {
		if (in_syscall == syscall_num) {
			/* all injected system calls are already handling */
			return false;
		}
		/* it need return to start injected system call */
		return true;
	}
	return false;
}

static inline bool
host_return_to_injected_guest_trap(struct thread_info *ti, pt_regs_t *regs)
{
	struct kvm_vcpu *vcpu;
	gthread_info_t *gti;
	int traps_num, in_work;

	vcpu = ti->vcpu;
	gti = pv_vcpu_get_gti(vcpu);
	traps_num = atomic_read(&vcpu->arch.host_ctxt.signal.traps_num);
	in_work = atomic_read(&vcpu->arch.host_ctxt.signal.in_work);

	if (unlikely(traps_num == 0)) {
		/* there are nothing injected traps */
		return false;
	}
	if (traps_num == in_work) {
		/* there are/(is) some injected to guest traps */
		/* but all the traps are already handling */
		return false;
	}

	/* it need return to start handling of new injected trap */
	if (test_gti_thread_flag(gti, GTIF_KERNEL_THREAD) ||
			pv_vcpu_trap_on_guest_kernel(regs)) {
		/* return to recursive injected trap at guest kernel mode */
		/* so all guest stacks were already switched to */
		return false;
	}

	/* return from host trap to injected trap at user mode */
	/* so it need switch all guest user's stacks to kernel */
	return true;
}

static inline struct e2k_stacks *
host_trap_guest_get_pv_vcpu_restore_stacks(struct thread_info *ti,
							struct pt_regs *regs)
{

	if (host_return_to_injected_guest_trap(ti, regs)) {
		/* it need switch to guest kernel context */
		return &regs->g_stacks;
	} else {
		/* it need switch to guest user context */
		return native_trap_guest_get_restore_stacks(ti, regs);
	}
}

static inline struct e2k_stacks *
host_syscall_guest_get_pv_vcpu_restore_stacks(struct thread_info *ti,
							struct pt_regs *regs)
{

	if (host_return_to_injected_guest_syscall(ti, regs)) {
		/* it need switch to guest kernel context */
		return &regs->g_stacks;
	} else {
		/* it need switch to guest user context */
		return native_syscall_guest_get_restore_stacks(ti, regs);
	}
}

static inline struct e2k_stacks *
host_trap_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	if (test_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE)) {
		/* host return to paravirtualized guest (VCPU) mode */
		return host_trap_guest_get_pv_vcpu_restore_stacks(ti, regs);
	}
	return native_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *
host_syscall_guest_get_restore_stacks(struct thread_info *ti,
						struct pt_regs *regs)
{
	if (test_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE)) {
		/* host return to paravirtualized guest (VCPU) mode */
		return host_syscall_guest_get_pv_vcpu_restore_stacks(ti, regs);
	}
	return native_syscall_guest_get_restore_stacks(ti, regs);
}

static inline void
host_trap_pv_vcpu_exit_trap(struct thread_info *ti, struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu = ti->vcpu;
	int traps_num, in_work;

	traps_num = atomic_read(&vcpu->arch.host_ctxt.signal.traps_num);
	in_work = atomic_read(&vcpu->arch.host_ctxt.signal.in_work);
	if (likely(traps_num <= 0)) {
		/* it is return from host trap to guest (VCPU) mode */
		return;
	} else if (traps_num == in_work) {
		/* there are/(is) some injected to guest traps */
		/* but all the traps are already handling */
		return;
	}

	/* it need return to start handling of new injected trap */
	atomic_inc(&vcpu->arch.host_ctxt.signal.in_work);
}

static inline void
host_trap_guest_exit_trap(struct thread_info *ti, struct pt_regs *regs)
{
	if (test_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE)) {
		/* host return to paravirtualized guest (VCPU) mode */
		host_trap_pv_vcpu_exit_trap(ti, regs);
	}

	host_switch_trap_enable_mask(ti, regs, true);

	/* restore global regs of native kernel */
	native_trap_guest_enter(ti, regs, EXIT_FROM_TRAP_SWITCH);
}

static inline void
host_trap_guest_enter(struct thread_info *ti, struct pt_regs *regs,
			unsigned flags)
{
	if (flags & EXIT_FROM_INTC_SWITCH) {
		host_trap_guest_exit_intc(ti, regs);
	}
	if (flags & EXIT_FROM_TRAP_SWITCH) {
		host_trap_guest_exit_trap(ti, regs);
	}
}

static inline void
host_syscall_pv_vcpu_exit_trap(struct thread_info *ti, struct pt_regs *regs)
{
	struct kvm_vcpu *vcpu = ti->vcpu;
	int syscall_num, in_syscall;

	syscall_num = atomic_read(&vcpu->arch.host_ctxt.signal.syscall_num);
	in_syscall = atomic_read(&vcpu->arch.host_ctxt.signal.in_syscall);
	if (likely(syscall_num == 0)) {
		/* it is return from host syscall to guest (VCPU) mode */
		return;
	} else if (in_syscall == syscall_num) {
		/* there is some injected to guest system call */
		/* and all the call is already handling */
		return;
	}

	/* it need return to start handling of new injected system call */
	atomic_inc(&vcpu->arch.host_ctxt.signal.in_syscall);
}

static inline void
host_syscall_guest_exit_trap(struct thread_info *ti, struct pt_regs *regs)
{
	if (!test_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE))
		return;

	/* host return to paravirtualized guest (VCPU) mode */
	host_syscall_pv_vcpu_exit_trap(ti, regs);

	host_switch_trap_enable_mask(ti, regs, true);
}

static inline void
host_guest_syscall_exit_to(struct thread_info *ti, struct pt_regs *regs,
				unsigned flags)
{
	if (flags & EXIT_FROM_INTC_SWITCH) {
		host_trap_guest_exit_intc(ti, regs);
	}
	if (flags & EXIT_FROM_TRAP_SWITCH) {
		host_syscall_guest_exit_trap(ti, regs);
	}
}

extern void kvm_init_pv_vcpu_intc_handling(struct kvm_vcpu *vcpu, pt_regs_t *regs);
extern int last_light_hcall;

static inline void
host_trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
			trap_pt_regs_t *trap, unsigned flags)
{
	if (!test_and_clear_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE))
		return;

	/*
	 * Trap on paravirtualized guest VCPU is interpreted as intercept
	 */

	kvm_emulate_pv_vcpu_intc(ti, regs, trap);

	/* only after switch to host MMU context at previous function */
	host_switch_trap_enable_mask(ti, regs, false);
}

/*
 * The function should return bool 'is the system call from guest?'
 */
static inline bool
host_guest_syscall_enter(struct thread_info *ti, struct pt_regs *regs)
{
	if (!test_and_clear_ti_thread_flag(ti, TIF_HOST_AT_VCPU_MODE))
		return false;	/* it is not guest system call */

	return pv_vcpu_syscall_intc(ti, regs);
}
#endif	/* CONFIG_VIRTUALIZATION */

#if defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest */
# include <asm/paravirt/switch.h>
#elif   defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravrtualized) */
# include <asm/kvm/guest/switch.h>
#else
/* it is native kernel without any virtualization or */
/* host kernel with virtualization support */
#ifndef	CONFIG_VIRTUALIZATION
/* it is only native kernel without any virtualization */
static inline void __guest_enter(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
}

static inline void __guest_enter_light(struct thread_info *ti,
					struct kvm_vcpu_arch *vcpu,
					bool from_sdisp)
{
}

static inline void __guest_exit(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
}
static inline void __guest_exit_light(struct thread_info *ti,
					struct kvm_vcpu_arch *vcpu)
{
}
static inline void
trap_guest_enter(struct thread_info *ti, struct pt_regs *regs, unsigned flags)
{
	native_trap_guest_enter(ti, regs, flags);
}
static inline void
trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		trap_pt_regs_t *trap, unsigned flags)
{
	native_trap_guest_exit(ti, regs, trap, flags);
}
static inline bool
guest_trap_pending(struct thread_info *ti)
{
	return native_guest_trap_pending(ti);
}

static inline bool
guest_trap_from_user(struct thread_info *ti)
{
	return native_trap_from_guest_user(ti);
}

static inline bool
guest_syscall_from_user(struct thread_info *ti)
{
	return native_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *
trap_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	return native_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *
syscall_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	return native_syscall_guest_get_restore_stacks(ti, regs);
}

/*
 * The function should return bool is the system call from guest
 */
static inline bool
guest_syscall_enter(struct thread_info *ti, struct pt_regs *regs)
{
	return native_guest_syscall_enter(ti, regs);
}
static inline void
guest_syscall_exit_to(struct thread_info *ti, struct pt_regs *regs,
				unsigned flags)
{
	native_guest_syscall_exit_to(ti, regs, flags);
}
#else	/* CONFIG_VIRTUALIZATION */
/* it is only host kernel with virtualization support */
static inline void __guest_enter(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	host_guest_enter(ti, vcpu, flags);
}

static inline void __guest_enter_light(struct thread_info *ti,
					struct kvm_vcpu_arch *vcpu,
					bool from_sdisp)
{
	host_guest_enter_light(ti, vcpu, from_sdisp);
}

static inline void __guest_exit(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	host_guest_exit(ti, vcpu, flags);
}
static inline void __guest_exit_light(struct thread_info *ti,
					struct kvm_vcpu_arch *vcpu)
{
	host_guest_exit_light(ti, vcpu);
}
static inline void
trap_guest_enter(struct thread_info *ti, struct pt_regs *regs, unsigned flags)
{
	host_trap_guest_enter(ti, regs, flags);
}
static inline void
trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		trap_pt_regs_t *trap, unsigned flags)
{
	host_trap_guest_exit(ti, regs, trap, flags);
}
static inline bool
guest_trap_pending(struct thread_info *ti)
{
	return host_guest_trap_pending(ti);
}

static inline bool
guest_trap_from_user(struct thread_info *ti)
{
	return host_trap_from_guest_user(ti);
}

static inline bool
guest_syscall_from_user(struct thread_info *ti)
{
	return host_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *
trap_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	return host_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *
syscall_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	return host_syscall_guest_get_restore_stacks(ti, regs);
}

/*
 * The function should return bool is the system call from guest
 */
static inline bool
guest_syscall_enter(struct thread_info *ti, struct pt_regs *regs)
{
	return host_guest_syscall_enter(ti, regs);
}
static inline void
guest_syscall_exit_to(struct thread_info *ti, struct pt_regs *regs,
				unsigned flags)
{
	host_guest_syscall_exit_to(ti, regs, flags);
}
#endif	/* ! CONFIG_VIRTUALIZATION */
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* ! _E2K_KVM_SWITCH_H */
