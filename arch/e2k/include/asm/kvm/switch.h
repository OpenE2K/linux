/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_KVM_SWITCH_H
#define _E2K_KVM_SWITCH_H

#include <linux/kvm_host.h>
#include <asm/machdep.h>
#include <asm/mmu_context.h>
#include <asm/aau_context.h>
#include <asm/alternative.h>
#include <asm/mmu_regs.h>
#include <asm/gregs.h>
#include <asm/regs_state.h>
#include <asm/processor.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/vcpu-descr-regs.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/pgd.h>
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/gmmu_context.h>
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#define	DEBUG_UPSR_FP_DISABLE

/*
 * See below the 'flags' argument of xxx_guest_enter()/xxx_guest_exit()
 */
#define	FULL_CONTEXT_SWITCH	0x0001U	/* save/restore full guest/host */
					/* context */
#define	FROM_HYPERCALL_SWITCH	0x0002U	/* save/restore full guest/host */
					/* before/after hypercall */
#define	USD_CONTEXT_SWITCH	0x0004U	/* save/restore local data stack */
#define	DEBUG_REGS_SWITCH	0x0008U	/* save/restore debugging registers */
#define DONT_MMU_CONTEXT_SWITCH	0x0020U	/* do not switch MMU context */
#define	DONT_SAVE_KGREGS_SWITCH	0x0040U	/* do not save and set kernel global */
					/* regs */
#define	DONT_AAU_CONTEXT_SWITCH	0x0080U	/* do not switch AAU context */
#define	DONT_TRAP_MASK_SWITCH	0x0100U	/* do not switch OSEM context */
#define	DONT_RESTORE_HOST_GREGS	0x0200U	/* do not restore host kernel gregs */
#define	EXIT_FROM_INTC_SWITCH	0x1000U	/* complete intercept emulation mode */
#define	EXIT_FROM_TRAP_SWITCH	0x2000U	/* complete trap mode */

static __always_inline void
native_trap_guest_enter(struct local_gregs *gregs, struct pt_regs *regs,
			unsigned flags)
{
	/* nothing guests can be */

	if (flags & EXIT_FROM_INTC_SWITCH)
		return;
	/* IMPORTANT: do NOT access current, current_thread_info() */
	/* and per-cpu variables after this point */
	if (flags & EXIT_FROM_TRAP_SWITCH) {
		restore_local_gregs(gregs);
	}
}

static inline void
native_trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		       trap_pt_regs_t *trap, unsigned flags)
{
	/* nothing guests can be */
}

static inline bool native_guest_trap_pending(struct thread_info *ti)
{
	/* there is not any guest */
	return false;
}

static inline bool native_trap_from_guest_user(struct thread_info *ti)
{
	/* there is not any guest */
	return false;
}

static inline bool native_syscall_from_guest_user(struct thread_info *ti)
{
	/* there is not any guest */
	return false;
}

static inline struct e2k_stacks *native_trap_guest_get_restore_stacks(struct thread_info *ti,
								      struct pt_regs *regs)
{
	return &regs->stacks;
}

static inline struct e2k_stacks *native_syscall_guest_get_restore_stacks(struct pt_regs *regs)
{
	return &regs->stacks;
}

/*
 * The function should return bool is the system call from guest
 */
static inline bool native_guest_syscall_enter(struct pt_regs *regs)
{
	/* nothing guests can be */

	return false;	/* it is not guest system call */
}

static inline void
native_pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	/* Nothing to do in native mode */
}

#ifdef	CONFIG_VIRTUALIZATION

#ifdef	CONFIG_CLW_ENABLE
static __always_inline void kvm_switch_clw_regs(struct kvm_sw_cpu_context *sw_ctxt,
						bool guest_enter)
{
	if (guest_enter) {
		u64 us_cl_b = sw_ctxt->us_cl_b, us_cl_up = sw_ctxt->us_cl_up,
		    us_cl_m0 = sw_ctxt->us_cl_m0, us_cl_m1 = sw_ctxt->us_cl_m1,
		    us_cl_m2 = sw_ctxt->us_cl_m2, us_cl_m3 = sw_ctxt->us_cl_m3,
		    us_cl_d = sw_ctxt->us_cl_d;

		if (cpu_has(CPU_HWBUG_CLW_LOW_RESTORE)) {
			RESTORE_US_CL_LOW(sw_ctxt->us_cl_up, native_read_guest_USD_lo());
		}

		native_set_clw_v6(us_cl_b, us_cl_up, us_cl_m0, us_cl_m1, us_cl_m2, us_cl_m3);
		NATIVE_WRITE_MMU_US_CL_D(us_cl_d);
	} else {
		sw_ctxt->us_cl_d = NATIVE_READ_MMU_US_CL_D();

		NATIVE_WRITE_MMU_US_CL_D(1);
		native_get_clw(&sw_ctxt->us_cl_b, &sw_ctxt->us_cl_up, &sw_ctxt->us_cl_m0,
				&sw_ctxt->us_cl_m1, &sw_ctxt->us_cl_m2, &sw_ctxt->us_cl_m3);
	}
}
#else
static __always_inline void kvm_switch_clw_regs(struct kvm_sw_cpu_context *sw_ctxt,
						bool guest_enter)
{
	/* Nothing to do */
}
#endif

static __always_inline void kvm_guest_enter_stack_regs(
		struct kvm_sw_cpu_context *sw_ctxt, bool hypercall)
{
	e2k_usd_t usd;
	e2k_sbr_t sbr;

	usd = native_read_USD_reg();
	/* For glaunch this does nothing (it uses __interrupt).
	 * For exit from hypercall frees up the kvm_generic_hcalls() frame. */
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		usd = incr_usd_ind(usd, read_USFS_reg());
	} else if (hypercall) {
		usd = set_usd_ind(usd, sw_ctxt->usd_size_v6);
	}
	sbr = native_read_SBR_reg();

	/* This clears %usfs, so guest will use exactly this %usd
	 * even if kvm_generic_hcalls() does not use __interrupt
	 * and has nonzero %usfs. */
	native_write_guest_USBR_USD_regs(sw_ctxt->sbr, sw_ctxt->usd);

	sw_ctxt->sbr = sbr;
	sw_ctxt->usd = usd;

	kvm_switch_clw_regs(sw_ctxt, true);
}

static __always_inline void kvm_guest_exit_stack_regs(struct kvm_sw_cpu_context *sw_ctxt,
		const struct kvm_hw_cpu_context *hw_ctxt, bool hypercall)
{
	kvm_switch_clw_regs(sw_ctxt, false);

	/* Do not save %usfs because it zeroed by hardware on guest exit. */
	e2k_usd_t usd = native_read_guest_USD_reg();
	e2k_sbr_t sbr = native_read_SBR_reg();

	native_write_USBR_USD_regs(sw_ctxt->sbr, sw_ctxt->usd);

	if (hypercall && !cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		sw_ctxt->usd_size_v6 = USD_IND(sw_ctxt->usd);
	}
	sw_ctxt->sbr = sbr;
	sw_ctxt->usd = usd;
}

static inline void kvm_switch_fpu_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	e2k_fpcr_t fpcr;
	e2k_fpsr_t fpsr;
	e2k_pfpfr_t pfpfr;
	e2k_upsr_t upsr;

	fpcr = native_read_FPCR_reg();
	fpsr = native_read_FPSR_reg();
	pfpfr = native_read_PFPFR_reg();
	upsr = native_read_UPSR_reg();

	native_write_FPU_regs(sw_ctxt->fpcr, sw_ctxt->fpsr, sw_ctxt->pfpfr);
	native_write_UPSR_reg(sw_ctxt->upsr);

	sw_ctxt->fpcr = fpcr;
	sw_ctxt->fpsr = fpsr;
	sw_ctxt->pfpfr = pfpfr;
	sw_ctxt->upsr = upsr;
}

static inline void kvm_switch_cu_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	e2k_cutd_t cutd;

	cutd = native_read_CUTD_reg();

	native_write_CUTD_reg(sw_ctxt->cutd);
	sw_ctxt->cutd = cutd;
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline void kvm_add_guest_kernel_map(struct kvm_vcpu *vcpu, hpa_t root)
{
	pgprot_t *src_root, *dst_root;
	int start, end, index;

	dst_root = (pgprot_t *)root;
	src_root = (pgprot_t *)kvm_mmu_get_init_gmm_root(vcpu->kvm);
	start = GUEST_KERNEL_PGD_PTRS_START;
	end = GUEST_KERNEL_PGD_PTRS_END;

	for (index = start; index < end; index++) {
		dst_root[index] = src_root[index];
	}
}

static inline void kvm_clear_guest_kernel_map(struct kvm_vcpu *vcpu, hpa_t root)
{
	pgprot_t *dst_root;
	int start, end, index;

	dst_root = (pgprot_t *)root;
	start = GUEST_KERNEL_PGD_PTRS_START;
	end = GUEST_KERNEL_PGD_PTRS_END;

	for (index = start; index < end; index++) {
		dst_root[index] = __pgprot(0);
	}
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline void kvm_switch_hv_mmu_pt_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	mmu_reg_t u_pptb;
	mmu_reg_t u_vptb;

	E2K_KVM_BUG_ON(!MMU_IS_SEPARATE_PT());

	u_pptb = NATIVE_READ_MMU_U_PPTB_REG();
	u_vptb = NATIVE_READ_MMU_U_VPTB_REG();

	NATIVE_WRITE_MMU_U_PPTB_REG(sw_ctxt->sh_u_pptb);
	NATIVE_WRITE_MMU_U_VPTB_REG(sw_ctxt->sh_u_vptb);

	sw_ctxt->sh_u_pptb = u_pptb;
	sw_ctxt->sh_u_vptb = u_vptb;
}

static inline void kvm_switch_hv_mmu_mtrr_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	mmu_reg_t b_mtrr_deftype = sw_ctxt->mtrr_deftype;
	mmu_reg_t b_mtrr_fix_64k_00000 = sw_ctxt->mtrr_fix_64k_00000;
	mmu_reg_t b_mtrr_fix_16k_80000 = sw_ctxt->mtrr_fix_16k_80000;
	mmu_reg_t b_mtrr_fix_16k_a0000 = sw_ctxt->mtrr_fix_16k_a0000;
	mmu_reg_t b_mtrr_fix_4k_c0000 = sw_ctxt->mtrr_fix_4k_c0000;
	mmu_reg_t b_mtrr_fix_4k_c8000 = sw_ctxt->mtrr_fix_4k_c8000;
	mmu_reg_t b_mtrr_fix_4k_d0000 = sw_ctxt->mtrr_fix_4k_d0000;
	mmu_reg_t b_mtrr_fix_4k_d8000 = sw_ctxt->mtrr_fix_4k_d8000;
	mmu_reg_t b_mtrr_fix_4k_e0000 = sw_ctxt->mtrr_fix_4k_e0000;
	mmu_reg_t b_mtrr_fix_4k_e8000 = sw_ctxt->mtrr_fix_4k_e8000;
	mmu_reg_t b_mtrr_fix_4k_f0000 = sw_ctxt->mtrr_fix_4k_f0000;
	mmu_reg_t b_mtrr_fix_4k_f8000 = sw_ctxt->mtrr_fix_4k_f8000;
	mmu_reg_t b_mtrr_physbase0 = sw_ctxt->mtrr_physbase0;
	mmu_reg_t b_mtrr_physbase1 = sw_ctxt->mtrr_physbase1;
	mmu_reg_t b_mtrr_physbase2 = sw_ctxt->mtrr_physbase2;
	mmu_reg_t b_mtrr_physbase3 = sw_ctxt->mtrr_physbase3;
	mmu_reg_t b_mtrr_physbase4 = sw_ctxt->mtrr_physbase4;
	mmu_reg_t b_mtrr_physbase5 = sw_ctxt->mtrr_physbase5;
	mmu_reg_t b_mtrr_physbase6 = sw_ctxt->mtrr_physbase6;
	mmu_reg_t b_mtrr_physbase7 = sw_ctxt->mtrr_physbase7;
	mmu_reg_t b_mtrr_physmask0 = sw_ctxt->mtrr_physmask0;
	mmu_reg_t b_mtrr_physmask1 = sw_ctxt->mtrr_physmask1;
	mmu_reg_t b_mtrr_physmask2 = sw_ctxt->mtrr_physmask2;
	mmu_reg_t b_mtrr_physmask3 = sw_ctxt->mtrr_physmask3;
	mmu_reg_t b_mtrr_physmask4 = sw_ctxt->mtrr_physmask4;
	mmu_reg_t b_mtrr_physmask5 = sw_ctxt->mtrr_physmask5;
	mmu_reg_t b_mtrr_physmask6 = sw_ctxt->mtrr_physmask6;
	mmu_reg_t b_mtrr_physmask7 = sw_ctxt->mtrr_physmask7;

	mmu_reg_t a_mtrr_deftype = NATIVE_READ_MMU_MTRR_DEFTYPE_REG();
	mmu_reg_t a_mtrr_fix_64k_00000 = NATIVE_READ_MMU_MTRR_FIX_64K_00000_REG();
	mmu_reg_t a_mtrr_fix_16k_80000 = NATIVE_READ_MMU_MTRR_FIX_16K_80000_REG();
	mmu_reg_t a_mtrr_fix_16k_a0000 = NATIVE_READ_MMU_MTRR_FIX_16K_A0000_REG();
	mmu_reg_t a_mtrr_fix_4k_c0000 = NATIVE_READ_MMU_MTRR_FIX_4K_C0000_REG();
	mmu_reg_t a_mtrr_fix_4k_c8000 = NATIVE_READ_MMU_MTRR_FIX_4K_C8000_REG();
	mmu_reg_t a_mtrr_fix_4k_d0000 = NATIVE_READ_MMU_MTRR_FIX_4K_D0000_REG();
	mmu_reg_t a_mtrr_fix_4k_d8000 = NATIVE_READ_MMU_MTRR_FIX_4K_D8000_REG();
	mmu_reg_t a_mtrr_fix_4k_e0000 = NATIVE_READ_MMU_MTRR_FIX_4K_E0000_REG();
	mmu_reg_t a_mtrr_fix_4k_e8000 = NATIVE_READ_MMU_MTRR_FIX_4K_E8000_REG();
	mmu_reg_t a_mtrr_fix_4k_f0000 = NATIVE_READ_MMU_MTRR_FIX_4K_F0000_REG();
	mmu_reg_t a_mtrr_fix_4k_f8000 = NATIVE_READ_MMU_MTRR_FIX_4K_F8000_REG();
	mmu_reg_t a_mtrr_physbase0 = NATIVE_READ_MMU_MTRR_PHYSBASE0_REG();
	mmu_reg_t a_mtrr_physbase1 = NATIVE_READ_MMU_MTRR_PHYSBASE1_REG();
	mmu_reg_t a_mtrr_physbase2 = NATIVE_READ_MMU_MTRR_PHYSBASE2_REG();
	mmu_reg_t a_mtrr_physbase3 = NATIVE_READ_MMU_MTRR_PHYSBASE3_REG();
	mmu_reg_t a_mtrr_physbase4 = NATIVE_READ_MMU_MTRR_PHYSBASE4_REG();
	mmu_reg_t a_mtrr_physbase5 = NATIVE_READ_MMU_MTRR_PHYSBASE5_REG();
	mmu_reg_t a_mtrr_physbase6 = NATIVE_READ_MMU_MTRR_PHYSBASE6_REG();
	mmu_reg_t a_mtrr_physbase7 = NATIVE_READ_MMU_MTRR_PHYSBASE7_REG();
	mmu_reg_t a_mtrr_physmask0 = NATIVE_READ_MMU_MTRR_PHYSMASK0_REG();
	mmu_reg_t a_mtrr_physmask1 = NATIVE_READ_MMU_MTRR_PHYSMASK1_REG();
	mmu_reg_t a_mtrr_physmask2 = NATIVE_READ_MMU_MTRR_PHYSMASK2_REG();
	mmu_reg_t a_mtrr_physmask3 = NATIVE_READ_MMU_MTRR_PHYSMASK3_REG();
	mmu_reg_t a_mtrr_physmask4 = NATIVE_READ_MMU_MTRR_PHYSMASK4_REG();
	mmu_reg_t a_mtrr_physmask5 = NATIVE_READ_MMU_MTRR_PHYSMASK5_REG();
	mmu_reg_t a_mtrr_physmask6 = NATIVE_READ_MMU_MTRR_PHYSMASK6_REG();
	mmu_reg_t a_mtrr_physmask7 = NATIVE_READ_MMU_MTRR_PHYSMASK7_REG();

	sw_ctxt->mtrr_deftype = a_mtrr_deftype;
	sw_ctxt->mtrr_fix_64k_00000 = a_mtrr_fix_64k_00000;
	sw_ctxt->mtrr_fix_16k_80000 = a_mtrr_fix_16k_80000;
	sw_ctxt->mtrr_fix_16k_a0000 = a_mtrr_fix_16k_a0000;
	sw_ctxt->mtrr_fix_4k_c0000 = a_mtrr_fix_4k_c0000;
	sw_ctxt->mtrr_fix_4k_c8000 = a_mtrr_fix_4k_c8000;
	sw_ctxt->mtrr_fix_4k_d0000 = a_mtrr_fix_4k_d0000;
	sw_ctxt->mtrr_fix_4k_d8000 = a_mtrr_fix_4k_d8000;
	sw_ctxt->mtrr_fix_4k_e0000 = a_mtrr_fix_4k_e0000;
	sw_ctxt->mtrr_fix_4k_e8000 = a_mtrr_fix_4k_e8000;
	sw_ctxt->mtrr_fix_4k_f0000 = a_mtrr_fix_4k_f0000;
	sw_ctxt->mtrr_fix_4k_f8000 = a_mtrr_fix_4k_f8000;
	sw_ctxt->mtrr_physbase0 = a_mtrr_physbase0;
	sw_ctxt->mtrr_physbase1 = a_mtrr_physbase1;
	sw_ctxt->mtrr_physbase2 = a_mtrr_physbase2;
	sw_ctxt->mtrr_physbase3 = a_mtrr_physbase3;
	sw_ctxt->mtrr_physbase4 = a_mtrr_physbase4;
	sw_ctxt->mtrr_physbase5 = a_mtrr_physbase5;
	sw_ctxt->mtrr_physbase6 = a_mtrr_physbase6;
	sw_ctxt->mtrr_physbase7 = a_mtrr_physbase7;
	sw_ctxt->mtrr_physmask0 = a_mtrr_physmask0;
	sw_ctxt->mtrr_physmask1 = a_mtrr_physmask1;
	sw_ctxt->mtrr_physmask2 = a_mtrr_physmask2;
	sw_ctxt->mtrr_physmask3 = a_mtrr_physmask3;
	sw_ctxt->mtrr_physmask4 = a_mtrr_physmask4;
	sw_ctxt->mtrr_physmask5 = a_mtrr_physmask5;
	sw_ctxt->mtrr_physmask6 = a_mtrr_physmask6;
	sw_ctxt->mtrr_physmask7 = a_mtrr_physmask7;

	NATIVE_SET_28_MMUREGS(mtrr0, mtrr1, mtrr2, mtrr3, mtrr4, mtrr5, mtrr6,
			mtrr7, mtrr8, mtrr9, mtrr10, mtrr11, mtrr12, mtrr13,
			mtrr14, mtrr15, mtrr16, mtrr17, mtrr18, mtrr19, mtrr20,
			mtrr21, mtrr22, mtrr23, mtrr24, mtrr25, mtrr26, mtrr32,
			b_mtrr_physbase0, b_mtrr_physbase1, b_mtrr_physbase2, b_mtrr_physbase3,
			b_mtrr_physbase4, b_mtrr_physbase5, b_mtrr_physbase6, b_mtrr_physbase7,
			b_mtrr_physmask0, b_mtrr_physmask1, b_mtrr_physmask2, b_mtrr_physmask3,
			b_mtrr_physmask4, b_mtrr_physmask5, b_mtrr_physmask6, b_mtrr_physmask7,
			b_mtrr_fix_64k_00000, b_mtrr_fix_16k_80000, b_mtrr_fix_16k_a0000,
			b_mtrr_fix_4k_c0000, b_mtrr_fix_4k_c8000, b_mtrr_fix_4k_d0000,
			b_mtrr_fix_4k_d8000, b_mtrr_fix_4k_e0000, b_mtrr_fix_4k_e8000,
			b_mtrr_fix_4k_f0000, b_mtrr_fix_4k_f8000, b_mtrr_deftype);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline unsigned long
kvm_switch_to_guest_mmu_pid(struct kvm_vcpu *vcpu, thread_info_t *ti)
{
	mm_context_t *gmm_context;
	unsigned long flags;
	u64 context;

	debug_inject_semi_spec_loads(false);

	raw_all_irq_save(flags);
	gmm_context = pv_vcpu_get_gmm_context(vcpu);
#ifdef	CONFIG_SMP
	/* Start flush ipis for the guest mm */
	cpumask_set_cpu(smp_processor_id(), pv_vcpu_get_gmm_cpumask(vcpu));
	/* See comment in switch_mm() */
	smp_mb__after_atomic();
#endif /* CONFIG_SMP */
	if (unlikely(test_ti_status_flag(ti, TS_HOST_SWITCH_MMU_PID))) {
		/* get new MMU context to exclude access to guest kernel */
		/* virtual space from guest user */
		context = get_mmu_pid_irqs_off(gmm_context, MMU_PID_RELOAD_FORCED__NO_UPDATE);
	} else {
		context = get_mmu_pid_irqs_off(gmm_context, MMU_PID_RELOAD_CHECK__NO_UPDATE);
	}
	WRITE_MMU_PID(CTX_HARDWARE(context));
	raw_all_irq_restore(flags);
	return context;
}

static inline void
kvm_switch_pv_mmu_pt_regs_to_guest(struct kvm_sw_cpu_context *sw_ctxt,
				   struct thread_info *ti)
{
	struct kvm_vcpu *vcpu = ti->vcpu;
	mmu_reg_t root;

	/* No need to save host registers in 'sw_regs' - we already know
	 * that host in PV case executes with %pid=0 and kernel %pptb */

	if (likely(test_ti_status_flag(ti, TS_HOST_TO_GUEST_USER))) {
		root = kvm_get_space_type_spt_u_root(vcpu);
		if (unlikely(!is_paging(vcpu))) {
			E2K_KVM_BUG_ON(root != vcpu->kvm->arch.nonp_root_hpa);
		} else {
			E2K_KVM_BUG_ON(root != pv_vcpu_get_gmm(vcpu)->root_hpa);
		}
	} else {
		gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
		gmm_struct_t *gmm;

		if (likely(gti != NULL)) {
			if (unlikely(gti->gmm_in_release)) {
				root = kvm_convert_to_init_gmm(vcpu, gti);
			} else {
				root = kvm_get_space_type_spt_gk_root(vcpu);
			}
		} else {
			E2K_KVM_BUG_ON(is_paging(vcpu));
			root = vcpu->kvm->arch.nonp_root_hpa;
		}
		gmm = pv_vcpu_get_gmm(vcpu);
		if (unlikely(!is_paging(vcpu))) {
			E2K_KVM_BUG_ON(root != vcpu->kvm->arch.nonp_root_hpa);
		} else if (pv_vcpu_is_init_gmm(vcpu, gmm)) {
			E2K_KVM_BUG_ON(VALID_PAGE(gmm->root_hpa) &&
						  root != gmm->root_hpa);
		} else {
			E2K_KVM_BUG_ON(VALID_PAGE(gmm->gk_root_hpa) &&
						  root != gmm->gk_root_hpa);
		}
	}
	NATIVE_SET_MMUREG_ISET(6, u_pptb, root);
	NATIVE_SET_MMUREG_ISET(6, u_vptb, sw_ctxt->sh_u_vptb);

	kvm_switch_to_guest_mmu_pid(vcpu, ti);
}

static inline void kvm_switch_to_host_mmu_pid(struct kvm_vcpu *vcpu,
					      struct mm_struct *mm)
{
	unsigned long flags;

	raw_all_irq_save(flags);
#ifdef	CONFIG_SMP
	/* Stop receiving flush ipis for the guest mm */
	cpumask_clear_cpu(smp_processor_id(), pv_vcpu_get_gmm_cpumask(vcpu));
#endif /* CONFIG_SMP */
	(void)get_mmu_pid_irqs_off(&mm->context, MMU_PID_RELOAD_CHECK);
	raw_all_irq_restore(flags);
}

static inline void
kvm_switch_pv_mmu_pt_regs_to_host(struct kvm_sw_cpu_context *sw_ctxt,
				  struct thread_info *ti)
{
	struct kvm_vcpu *vcpu = ti->vcpu;
	mmu_reg_t u_pptb, u_vptb;

	/* We have switched registers already to host values when entering,
	 * so there is no need to update registers here - instead just
	 * update the values in 'sw_ctxt' */
	u_vptb = NATIVE_GET_MMUREG_ISET(6, u_vptb);
	if (likely(test_ti_status_flag(ti, TS_HOST_TO_GUEST_USER))) {
		u_pptb = kvm_get_space_type_spt_u_root(vcpu);
		if (unlikely(!is_paging(vcpu))) {
			E2K_KVM_BUG_ON(u_pptb != vcpu->kvm->arch.nonp_root_hpa);
		} else {
			E2K_KVM_BUG_ON(u_pptb != pv_vcpu_get_gmm(vcpu)->root_hpa);
		}
	} else {
		gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
		gmm_struct_t *gmm;

		if (likely(gti != NULL)) {
			if (unlikely(gti->gmm_in_release)) {
				u_pptb = kvm_convert_to_init_gmm(vcpu, gti);
			} else {
				u_pptb = kvm_get_space_type_spt_gk_root(vcpu);
			}
		} else {
			E2K_KVM_BUG_ON(is_paging(vcpu));
			u_pptb = vcpu->kvm->arch.nonp_root_hpa;
		}
		gmm = pv_vcpu_get_gmm(vcpu);

		if (unlikely(!is_paging(vcpu))) {
			E2K_KVM_BUG_ON(u_pptb != vcpu->kvm->arch.nonp_root_hpa);
		} else if (pv_vcpu_is_init_gmm(vcpu, gmm)) {
			E2K_KVM_BUG_ON(VALID_PAGE(gmm->root_hpa) &&
						  u_pptb != gmm->root_hpa);
		} else {
			E2K_KVM_BUG_ON(VALID_PAGE(gmm->gk_root_hpa) &&
						  u_pptb != gmm->gk_root_hpa);
		}
	}

	/* return to hypervisor MMU roots & context to emulate hw intercept */
	kvm_switch_to_host_mmu_pid(vcpu, thread_info_task(ti)->mm);

	sw_ctxt->sh_u_pptb = u_pptb;
	sw_ctxt->sh_u_vptb = u_vptb;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline void kvm_switch_mmu_tc_regs(struct kvm_sw_cpu_context *sw_ctxt)
{
	mmu_reg_t tc_hpa;
	mmu_reg_t trap_count;

	tc_hpa = NATIVE_READ_MMU_TRAP_POINT();
	trap_count = NATIVE_READ_MMU_TRAP_COUNT();

	NATIVE_WRITE_MMU_TRAP_POINT(sw_ctxt->tc_hpa);
	NATIVE_SET_MMUREG_ISET(6, trap_count, sw_ctxt->trap_count);

	sw_ctxt->tc_hpa = tc_hpa;
	sw_ctxt->trap_count = trap_count;
}

static inline void kvm_switch_hv_mmu_regs(struct kvm_sw_cpu_context *sw_ctxt,
					  bool switch_tc)
{
	kvm_switch_hv_mmu_pt_regs(sw_ctxt);
	if (switch_tc) {
		kvm_switch_mmu_tc_regs(sw_ctxt);
	}
	kvm_switch_hv_mmu_mtrr_regs(sw_ctxt);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline void
kvm_switch_pv_mmu_regs_to_guest(struct kvm_sw_cpu_context *sw_ctxt,
				struct thread_info *ti, bool switch_tc)
{
	kvm_switch_pv_mmu_pt_regs_to_guest(sw_ctxt, ti);
	if (switch_tc) {
		kvm_switch_mmu_tc_regs(sw_ctxt);
	}
}

static inline void
kvm_switch_pv_mmu_regs_to_host(struct kvm_sw_cpu_context *sw_ctxt,
			       struct thread_info *ti, bool switch_tc)
{
	kvm_switch_pv_mmu_pt_regs_to_host(sw_ctxt, ti);
	if (switch_tc) {
		kvm_switch_mmu_tc_regs(sw_ctxt);
	}
}

static inline unsigned long kvm_get_guest_mmu_pid(struct kvm_vcpu *vcpu)
{
	mm_context_t *gmm_context;

	gmm_context = pv_vcpu_get_gmm_context(vcpu);
	return gmm_context->cpumsk[smp_processor_id()];
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static __always_inline void kvm_switch_gregs(struct kvm_sw_cpu_context *sw_ctxt, bool guest_enter)
{
	if (guest_enter) {
		switch_local_gregs(&sw_ctxt->host_l_gregs, &sw_ctxt->vcpu_l_gregs);
	} else {
		switch_local_gregs(&sw_ctxt->vcpu_l_gregs, &sw_ctxt->host_l_gregs);
	}
}

static __always_inline void switch_ctxt_trap_enable_mask(struct kvm_sw_cpu_context *sw_ctxt)
{
	u32 b_osem = sw_ctxt->osem;
	u32 a_osem = native_read_OSEM_reg_value();

	native_write_OSEM_reg_value(b_osem);
	sw_ctxt->osem = a_osem;
}

static inline void kvm_switch_prefetchers(struct kvm_sw_cpu_context *sw_ctxt)
{
	if (!cpu_has(CPU_HWBUG_GENERATIONS_L2_PREF))
		return;

	l2_prefetcher_switch(&sw_ctxt->l2_prefetcher_enabled);
}

extern void kvm_switch_debug_regs(struct kvm_sw_cpu_context *sw_ctxt, bool guest_enter);

static __always_inline void host_guest_enter(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	kvm_switch_prefetchers(sw_ctxt);

	if (likely(!(flags & DONT_TRAP_MASK_SWITCH))) {
		switch_ctxt_trap_enable_mask(sw_ctxt);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		/* In full virtualization mode guest sets his own OSEM */
		/* in thread_init() */
		if (!vcpu->is_hv) {
			E2K_KVM_BUG_ON((native_read_OSEM_reg_value() &
					HYPERCALLS_TRAPS_MASK) !=
						HYPERCALLS_TRAPS_MASK);
		}
	} else {
		/* In full virtualization mode guest sets his own OSEM */
		/* in thread_init() */
		if (!vcpu->is_hv) {
			E2K_KVM_BUG_ON((native_read_OSEM_reg_value() &
					HYPERCALLS_TRAPS_MASK) != 0);
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

	/* This makes a call so switch it before AAU */
	if (flags & DEBUG_REGS_SWITCH)
		kvm_switch_debug_regs(sw_ctxt, true);

	if ((flags & (FROM_HYPERCALL_SWITCH | FULL_CONTEXT_SWITCH))) {
		NATIVE_RESTORE_BINCO_REGS(sw_ctxt);

		/* Compilation units context */
		kvm_switch_cu_regs(sw_ctxt);

		/* restore guest PT context (U_PPTB/U_VPTB) */
		if (!(flags & DONT_MMU_CONTEXT_SWITCH)) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			if (likely(!vcpu->is_hv))
				kvm_switch_pv_mmu_regs_to_guest(sw_ctxt, ti, vcpu->is_hv);
			else
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
				kvm_switch_hv_mmu_regs(sw_ctxt, true);
		}
	}

	kvm_switch_fpu_regs(sw_ctxt);

	if (flags & FROM_HYPERCALL_SWITCH) {
		/*
		 * Hypercalls - both hardware and software virtualization
		 */
		E2K_KVM_BUG_ON(!sw_ctxt->in_hypercall);
		sw_ctxt->in_hypercall = false;
	} else if (flags & FULL_CONTEXT_SWITCH) {
		/*
		 * Interceptions - hardware support is enabled
		 */

		/* Isolate from QEMU
		 *
		 * Since we do not support calling QEMU from hypercalls,
		 * we should switch more context in interceptions - see
		 * the list in sw_ctxt definition */
		if (!(flags & DONT_AAU_CONTEXT_SWITCH)) {
			machine.calculate_aau_aaldis_aaldas(NULL, ti->aalda, &sw_ctxt->aau_context);

			/*
			 * We cannot rely on %aasr value since interception could have
			 * happened in guest user before "bap" or in guest trap handler
			 * before restoring %aasr, so we must restore all AAU registers.
			 */
			NATIVE_CLEAR_APB();
			native_set_aau_context(&sw_ctxt->aau_context, ti->aalda, E2K_FULL_AASR);

			/*
			 * It's important to restore AAD after all return operations.
			 */
			NATIVE_RESTORE_AADS(&sw_ctxt->aau_context);
		}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else {
		/*
		 * Return from emulation of interseption to virtualized
		 * vcpu
		 */

		/* switch to guest MMU context to continue guest execution */
		if (likely(!vcpu->is_hv)) {
			kvm_switch_pv_mmu_regs_to_guest(sw_ctxt, ti, false);
		} else {
			E2K_KVM_BUG_ON(true);
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

	/* Switch data stack after all function calls */
	if (flags & USD_CONTEXT_SWITCH) {
		kvm_guest_enter_stack_regs(sw_ctxt, flags & FROM_HYPERCALL_SWITCH);
	}

	/* Cannot use current and cpu_has() after this */
	if ((flags & (FROM_HYPERCALL_SWITCH | FULL_CONTEXT_SWITCH)) &&
			!(flags & DONT_SAVE_KGREGS_SWITCH)) {
		kvm_switch_gregs(sw_ctxt, true);
	}
}

static __always_inline void host_guest_enter_light(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, bool from_sdisp)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	E2K_KVM_BUG_ON(!sw_ctxt->in_hypercall);
	sw_ctxt->in_hypercall = false;

	HOST_RESTORE_KERNEL_GREGS_AS_LIGHT(ti);

	kvm_switch_cu_regs(sw_ctxt);

	/* Switch data stack after all function calls */
	if (!from_sdisp) {
		kvm_guest_enter_stack_regs(sw_ctxt, true);
	}
}

static __always_inline void host_guest_exit(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	/* Can use current and cpu_has() after this */
	if ((flags & (FROM_HYPERCALL_SWITCH | FULL_CONTEXT_SWITCH)) &&
			!(flags & DONT_SAVE_KGREGS_SWITCH)) {
		kvm_switch_gregs(sw_ctxt, false);
	}

	/* Switch data stack before all function calls */
	if (flags & USD_CONTEXT_SWITCH) {
		kvm_guest_exit_stack_regs(sw_ctxt, &vcpu->hw_ctxt,
					  flags & FROM_HYPERCALL_SWITCH);
	}

	if (likely(!(flags & DONT_TRAP_MASK_SWITCH))) {
		switch_ctxt_trap_enable_mask(sw_ctxt);
	}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	E2K_KVM_BUG_ON(native_read_OSEM_reg_value() & HYPERCALLS_TRAPS_MASK);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	if (flags & FROM_HYPERCALL_SWITCH) {
		/*
		 * Hypercalls - both hardware and software virtualization
		 */
		E2K_KVM_BUG_ON(sw_ctxt->in_hypercall);
		sw_ctxt->in_hypercall = true;
	} else if (flags & FULL_CONTEXT_SWITCH) {
		/*
		 * Interceptions - hardware support is enabled
		 */
		if (!(flags & DONT_AAU_CONTEXT_SWITCH)) {
			/*
			 * We cannot rely on %aasr value since interception could have
			 * happened in guest user before "bap" or in guest trap handler
			 * before restoring %aasr, so we must save all AAU registers.
			 * Several macroses use %aasr to determine, which registers to
			 * save/restore, so pass worst-case %aasr to them directly
			 * while saving the actual guest value to sw_ctxt->aasr
			 */
			sw_ctxt->aasr = aasr_parse(native_read_aasr_reg());

			/*
			 * This is placed before saving intc cellar since it is done
			 * with 'mmurr' instruction which requires AAU to be stopped.
			 *
			 * Do this before saving %sbbp as it uses 'alc'
			 * and thus zeroes %aaldm.
			 */
			NATIVE_SAVE_AAU_MASK_REGS(&sw_ctxt->aau_context, E2K_FULL_AASR);

			/* It's important to save AAD before all call operations. */
			NATIVE_SAVE_AADS(&sw_ctxt->aau_context);
			/*
			 * Function calls are allowed from this point on,
			 * mark it with a compiler barrier.
			 */
			barrier();

			/* Since iset v6 %aaldi must be saved too */
			save_aaldi(sw_ctxt->aau_context.aaldi);

			/* No atomic/DAM/call operations are allowed before this point.
			 * Note that we cannot do this before saving AAU. */
			if (cpu_has(CPU_HWBUG_L1I_RBRANCH_CALLS))
				E2K_DISP_CTPRS();

			machine.get_aau_context(&sw_ctxt->aau_context, E2K_FULL_AASR);

			NATIVE_CLEAR_APB();
		} else {
			/* No atomic/DAM/call operations are allowed before this point.
			 * Note that we cannot do this before saving AAU. */
			if (cpu_has(CPU_HWBUG_L1I_RBRANCH_CALLS))
				E2K_DISP_CTPRS();
		}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else {
		/*
		 * Starting emulation of interseption of virtualized vcpu
		 */

		/* switch to hypervisor MMU context to emulate hw intercept */
		if (likely(!vcpu->is_hv)) {
			kvm_switch_pv_mmu_regs_to_host(sw_ctxt, ti, false);
		} else {
			E2K_KVM_BUG_ON(true);
		}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	}

	kvm_switch_fpu_regs(sw_ctxt);

	if ((flags & (FROM_HYPERCALL_SWITCH | FULL_CONTEXT_SWITCH))) {
		NATIVE_SAVE_BINCO_REGS(sw_ctxt);
		invalidate_MLT();

		/* Compilation units context */
		kvm_switch_cu_regs(sw_ctxt);

		/* Save guest PT context (U_PPTB/U_VPTB) and
		 * restore host user PT context */
		if (likely(!(flags & DONT_MMU_CONTEXT_SWITCH))) {
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
			if (likely(!vcpu->is_hv))
				kvm_switch_pv_mmu_regs_to_host(sw_ctxt, ti, false);
			else
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
				kvm_switch_hv_mmu_regs(sw_ctxt, true);
		}
	}

	/* This makes a call so switch it after AAU */
	if (flags & DEBUG_REGS_SWITCH)
		kvm_switch_debug_regs(sw_ctxt, false);

	kvm_switch_prefetchers(sw_ctxt);
}

static __always_inline void host_guest_exit_light(struct thread_info *ti,
		struct kvm_vcpu_arch *vcpu)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->sw_ctxt;

	E2K_KVM_BUG_ON(sw_ctxt->in_hypercall);
	sw_ctxt->in_hypercall = true;

	HOST_SAVE_KERNEL_GREGS_AS_LIGHT(ti);
	ONLY_SET_KERNEL_GREGS(ti);

	kvm_guest_exit_stack_regs(sw_ctxt, &vcpu->hw_ctxt, true);

	kvm_switch_cu_regs(sw_ctxt);
}

/*
 * Some hypercalls return to guest from other exit point then
 * usual hypercall return from. So it need some clearing hypercall track.
 */
static inline bool host_hypercall_exit(struct kvm_vcpu *vcpu)
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

	E2K_KVM_BUG_ON(!sw_ctxt->in_hypercall);

	host_hypercall_exit(vcpu);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
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
	cur_gti->usr_pfault_jump = current->thread.usr_pfault_jump;
	cur_gti->recovery_pfault_jump = vcpu->arch.mmu.recovery_pfault_jump;
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
	current->thread.usr_pfault_jump = next_gti->usr_pfault_jump;
	vcpu->arch.mmu.recovery_pfault_jump = next_gti->recovery_pfault_jump;
}

static inline void
pv_vcpu_switch_guest_host_context(struct kvm_vcpu *vcpu, gthread_info_t *cur_gti,
				  gthread_info_t *next_gti)
{
	pv_vcpu_save_host_context(vcpu, cur_gti);
	pv_vcpu_restore_host_context(vcpu, next_gti);
}

static inline void pv_vcpu_switch_host_context(struct kvm_vcpu *vcpu)
{
	kvm_host_context_t *host_ctxt = &vcpu->arch.host_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	unsigned long	*stack;
	pt_regs_t	*regs;
	e2k_usd_t	k_usd;
	e2k_sbr_t	k_sbr;
	e2k_psp_t	k_psp;
	e2k_pcsp_t	k_pcsp;
	e2k_upsr_t	upsr;
	void		__user *base;
	unsigned long	size;
	unsigned long	used;
	unsigned	osem;

	/* keep current state of context */
	stack = current->stack;
	regs = current_thread_info()->pt_regs;
	upsr = current_thread_info()->upsr;
	k_usd = current_thread_info()->k_usd;
	k_sbr.base = (unsigned long)stack + KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET;
	k_psp = current_thread_info()->k_psp;
	k_pcsp = current_thread_info()->k_pcsp;

	/* restore VCPU thread context */
	current->stack = host_ctxt->stack;
	current_thread_info()->pt_regs = host_ctxt->pt_regs;
	current_thread_info()->upsr = host_ctxt->upsr;
	current_thread_info()->k_usd = host_ctxt->k_usd;
	current_thread_info()->k_psp = host_ctxt->k_psp;
	current_thread_info()->k_pcsp = host_ctxt->k_pcsp;

	/* save VCPU thread context */
	host_ctxt->stack = stack;
	host_ctxt->pt_regs = regs;
	host_ctxt->upsr = upsr;
	host_ctxt->k_usd = k_usd;
	host_ctxt->k_sbr = k_sbr;
	host_ctxt->k_psp = k_psp;
	host_ctxt->k_pcsp = k_pcsp;

	/* remember host/guest OSEM registers state & restore guest/host state */
	osem = host_ctxt->osem;
	host_ctxt->osem = sw_ctxt->osem;
	sw_ctxt->osem = osem;

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
#ifdef	DEBUG_UPSR_FP_DISABLE
	if (unlikely(!current_thread_info()->upsr.fe)) {
		pr_err("%s(): switch to host QEMU process with disabled\n"
		       "FloatPoint mask, UPSR 0x%x\n",
		       __func__, AW(current_thread_info()->upsr));
		/* correct UPSR to enable float pointing */
		current_thread_info()->upsr.fe = 1;
	}
	if (unlikely(!vcpu->arch.host_ctxt.upsr.fe)) {
		pr_err("%s(): switch from host VCPU process where disabled\n"
		       "FloatPoint mask, UPSR 0x%x\n",
		       __func__, AW(vcpu->arch.host_ctxt.upsr));
	}
#endif /* DEBUG_UPSR_FP_DISABLE */
}

static inline void pv_vcpu_enter_to_guest(struct kvm_vcpu *vcpu)
{
	/* save VCPU host thread context */
	/* restore VCPU guest thread context */
	pv_vcpu_switch_host_context(vcpu);
#ifdef	DEBUG_UPSR_FP_DISABLE
	if (unlikely(!current_thread_info()->upsr.fe)) {
		pr_err("%s(): switch to host VCPU process with disabled\n"
		       "FloatPoint mask, UPSR 0x%x\n",
		       __func__, AW(current_thread_info()->upsr));
		/* do not correct UPSR, maybe it should be */
	}
#endif /* DEBUG_UPSR_FP_DISABLE */
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

static __always_inline bool pv_vcpu_trap_on_guest_kernel(pt_regs_t *regs)
{
	if (regs && is_trap_pt_regs(regs) && guest_kernel_mode(regs))
		return true;

	return false;
}

static inline bool host_guest_trap_pending(struct thread_info *ti)
{
	struct pt_regs *regs = ti->pt_regs;
	struct kvm_vcpu *vcpu;

	if (likely(!regs || !is_trap_pt_regs(regs) || !kvm_test_intc_emul_flag(regs))) {
		/* it is not virtualized guest VCPU intercepts */
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

static inline bool host_trap_from_guest_user(struct thread_info *ti)
{
	struct pt_regs *regs = ti->pt_regs;

	if (likely(!host_guest_trap_pending(ti) && regs->traps_to_guest == 0))
		return false;
	return !pv_vcpu_trap_on_guest_kernel(ti->pt_regs);
}

static inline bool host_syscall_from_guest_user(struct thread_info *ti)
{
	struct pt_regs *regs = ti->pt_regs;

	if (likely(!regs || is_trap_pt_regs(regs) || !kvm_test_intc_emul_flag(regs))) {
		/* it is not virtualized guest VCPU intercepts */
		/* emulation mode, so nothing system calls from guest */
		return false;
	}
	BUG_ON(ti->vcpu == NULL);
	E2K_KVM_BUG_ON(guest_kernel_mode(regs));
	return true;
}

static inline void
host_trap_guest_exit_intc(struct thread_info *ti, struct pt_regs *regs,
			  restore_caller_t from)
{
	if (likely(!kvm_test_intc_emul_flag(regs))) {
		/* it is not virtualized guest VCPU intercepts */
		/* emulation mode, so nothing to do more */
		return;
	}
	kvm_clear_intc_emul_flag(regs);

	/*
	 * Return from trap on virtualized guest VCPU which was
	 * interpreted as interception
	 */
	return_from_pv_vcpu_intc(ti, regs, from);
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
	if (pv_vcpu_trap_on_guest_kernel(regs)) {
		/* return to recursive injected trap at guest kernel mode */
		/* so all guest stacks were already switched to */
		return false;
	}
	if (test_gti_thread_flag(gti, GTIF_KERNEL_THREAD)) {
		/* the guest user thread can be in the completion stage */
		/* and switched to kernel init mm as kernel thread */
		return !pv_vcpu_trap_on_guest_kernel(regs);
	}

	/* return from host trap to injected trap at user mode */
	/* so it need switch all guest user's stacks to kernel */
	return true;
}

static inline struct e2k_stacks *
host_trap_guest_get_pv_vcpu_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
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
host_syscall_guest_get_pv_vcpu_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{

	if (host_return_to_injected_guest_syscall(ti, regs)) {
		/* it need switch to guest kernel context */
		return &regs->g_stacks;
	} else {
		/* it need switch to guest user context */
		return native_syscall_guest_get_restore_stacks(regs);
	}
}

static inline struct e2k_stacks *
host_trap_guest_get_restore_stacks(struct thread_info *ti, struct pt_regs *regs)
{
	if (test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)) {
		/* host return to virtualized guest (VCPU) mode */
		return host_trap_guest_get_pv_vcpu_restore_stacks(ti, regs);
	}
	return native_trap_guest_get_restore_stacks(ti, regs);
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
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

static inline void
host_trap_guest_exit_trap(struct thread_info *ti, struct pt_regs *regs)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)) {
		/* host return to virtualized guest (VCPU) mode */
		host_trap_pv_vcpu_exit_trap(ti, regs);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* restore global regs of native kernel */
	native_trap_guest_enter(&current->thread.u_gregs, regs, EXIT_FROM_TRAP_SWITCH);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline void
host_trap_guest_enter(struct thread_info *ti, struct pt_regs *regs,
		      unsigned flags, restore_caller_t from)
{
	if (flags & EXIT_FROM_INTC_SWITCH) {
		host_trap_guest_exit_intc(ti, regs, from);
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

extern void host_syscall_guest_exit_trap(struct thread_info *, struct pt_regs *);

extern void kvm_init_pv_vcpu_intc_handling(struct kvm_vcpu *vcpu, pt_regs_t *regs);

static inline void
host_trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		     trap_pt_regs_t *trap, unsigned flags)
{
	if (likely(!test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)))
		return;

	clear_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);

	/*
	 * Trap on virtualized guest VCPU is interpreted as intercept
	 */
	kvm_emulate_pv_vcpu_intc(ti, regs, trap);
}

static inline void __guest_exit(struct thread_info *ti,
				struct kvm_vcpu_arch *vcpu, unsigned flags);
/*
 * The function should return bool 'is the system call from guest?'
 */
static inline bool host_guest_syscall_enter(struct pt_regs *regs,
					    bool ts_host_at_vcpu_mode)
{
	struct kvm_vcpu *vcpu;

	if (likely(!ts_host_at_vcpu_mode))
		return false;	/* it is not guest system call */

	clear_ts_flag(TS_HOST_AT_VCPU_MODE);

	vcpu = current_thread_info()->vcpu;
	__guest_exit(current_thread_info(), &vcpu->arch, DONT_MMU_CONTEXT_SWITCH);
	kvm_set_intc_emul_flag(regs);

	vcpu->mode = OUTSIDE_GUEST_MODE;
	smp_wmb();	/* See the comment in kvm_vcpu_exiting_guest_mode() */

	return true;
}

extern void host_pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#endif /* CONFIG_VIRTUALIZATION */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
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

static __always_inline void trap_guest_enter(struct thread_info *ti, struct pt_regs *regs,
				    unsigned flags, restore_caller_t from)
{
	native_trap_guest_enter(&current->thread.u_gregs, regs, flags);
}

static inline void trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
				   trap_pt_regs_t *trap, unsigned flags)
{
	native_trap_guest_exit(ti, regs, trap, flags);
}

static inline bool guest_trap_pending(struct thread_info *ti)
{
	return native_guest_trap_pending(ti);
}

static inline bool guest_trap_from_user(struct thread_info *ti)
{
	return native_trap_from_guest_user(ti);
}

static inline bool guest_syscall_from_user(struct thread_info *ti)
{
	return native_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *trap_guest_get_restore_stacks(struct thread_info *ti,
							       struct pt_regs *regs)
{
	return native_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *syscall_guest_get_restore_stacks(bool ts_host_at_vcpu_mode,
								  struct pt_regs *regs)
{
	return native_syscall_guest_get_restore_stacks(regs);
}

#define ts_host_at_vcpu_mode() false

/*
 * The function should return bool is the system call from guest
 */
static inline bool guest_syscall_enter(struct pt_regs *regs,
				       bool ts_host_at_vcpu_mode)
{
	return native_guest_syscall_enter(regs);
}

static inline void pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	native_pv_vcpu_syscall_intc(ti, regs);
}

static inline void guest_exit_intc(struct pt_regs *regs, bool intc_emul_flag,
				   restore_caller_t from) { }

static inline void guest_syscall_exit_trap(struct pt_regs *regs,
					   bool ts_host_at_vcpu_mode) { }

#else /* CONFIG_VIRTUALIZATION */
/* it is only host kernel with virtualization support */
static __always_inline void __guest_enter(struct thread_info *ti,
				 struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	host_guest_enter(ti, vcpu, flags);
}

static __always_inline void __guest_enter_light(struct thread_info *ti,
				       struct kvm_vcpu_arch *vcpu,
				       bool from_sdisp)
{
	host_guest_enter_light(ti, vcpu, from_sdisp);
}

static __always_inline void __guest_exit(struct thread_info *ti,
				struct kvm_vcpu_arch *vcpu, unsigned flags)
{
	host_guest_exit(ti, vcpu, flags);
}

static __always_inline void __guest_exit_light(struct thread_info *ti,
				      struct kvm_vcpu_arch *vcpu)
{
	host_guest_exit_light(ti, vcpu);
}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
static inline void
trap_guest_enter(struct thread_info *ti, struct pt_regs *regs, unsigned flags,
		 restore_caller_t from)
{
	host_trap_guest_enter(ti, regs, flags, from);
}

static inline void
trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
		trap_pt_regs_t *trap, unsigned flags)
{
	host_trap_guest_exit(ti, regs, trap, flags);
}

static inline bool guest_trap_pending(struct thread_info *ti)
{
	return host_guest_trap_pending(ti);
}

static inline bool guest_trap_from_user(struct thread_info *ti)
{
	return host_trap_from_guest_user(ti);
}

static inline bool guest_syscall_from_user(struct thread_info *ti)
{
	return host_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *trap_guest_get_restore_stacks(struct thread_info *ti,
							       struct pt_regs *regs)
{
	return host_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *syscall_guest_get_restore_stacks(bool ts_host_at_vcpu_mode,
								  struct pt_regs *regs)
{
	if (unlikely(ts_host_at_vcpu_mode)) {
		/* host return to virtualized guest (VCPU) mode */
		return host_syscall_guest_get_pv_vcpu_restore_stacks(
				current_thread_info(), regs);
	}
	return native_syscall_guest_get_restore_stacks(regs);
}
#else
static __always_inline void trap_guest_enter(struct thread_info *ti, struct pt_regs *regs,
				    unsigned flags, restore_caller_t from)
{
	native_trap_guest_enter(&current->thread.u_gregs, regs, flags);
}

static inline void trap_guest_exit(struct thread_info *ti, struct pt_regs *regs,
				   trap_pt_regs_t *trap, unsigned flags)
{
	native_trap_guest_exit(ti, regs, trap, flags);
}

static inline bool guest_trap_from_user(struct thread_info *ti)
{
	return native_trap_from_guest_user(ti);
}

static inline bool guest_syscall_from_user(struct thread_info *ti)
{
	return native_syscall_from_guest_user(ti);
}

static inline struct e2k_stacks *trap_guest_get_restore_stacks(struct thread_info *ti,
							       struct pt_regs *regs)
{
	return native_trap_guest_get_restore_stacks(ti, regs);
}

static inline struct e2k_stacks *syscall_guest_get_restore_stacks(bool ts_host_at_vcpu_mode,
								  struct pt_regs *regs)
{
	return native_syscall_guest_get_restore_stacks(regs);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#define ts_host_at_vcpu_mode() unlikely(!!test_ts_flag(TS_HOST_AT_VCPU_MODE))

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
/*
 * The function should return bool is the system call from guest
 */
static inline bool guest_syscall_enter(struct pt_regs *regs,
				       bool ts_host_at_vcpu_mode)
{
	return host_guest_syscall_enter(regs, ts_host_at_vcpu_mode);
}

static inline void pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	host_pv_vcpu_syscall_intc(ti, regs);
}

static inline void guest_exit_intc(struct pt_regs *regs, bool intc_emul_flag,
				   restore_caller_t from)
{
	if (unlikely(intc_emul_flag)) {
		kvm_clear_intc_emul_flag(regs);

		/*
		 * Return from trap on virtualized guest VCPU which was
		 * interpreted as interception
		 */
		return_from_pv_vcpu_intc(current_thread_info(), regs, from);
	}
}

static inline void guest_syscall_exit_trap(struct pt_regs *regs,
					   bool ts_host_at_vcpu_mode)
{
	if (unlikely(ts_host_at_vcpu_mode))
		host_syscall_guest_exit_trap(current_thread_info(), regs);
}
#else
static inline void guest_exit_intc(struct pt_regs *regs, bool intc_emul_flag,
				   restore_caller_t from) { }
static inline void guest_syscall_exit_trap(struct pt_regs *regs,
					   bool ts_host_at_vcpu_mode) { }
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#endif /* !CONFIG_VIRTUALIZATION */
#endif /* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_SWITCH_H */
