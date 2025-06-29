/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


/*
 * CPU virtualization
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
#include <asm/kvm/process.h>
#include <asm/kvm/runstate.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/trace_kvm_pv.h>
#include <asm/kvm/gregs.h>
#include "cpu.h"
#include "process.h"
#include "mmu.h"
#include "gaccess.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_GREGS_MODE
#undef	DebugGREGS
#define	DEBUG_KVM_GREGS_MODE	0	/* global registers debugging */
#define	DebugGREGS(fmt, args...)					\
({									\
	if (DEBUG_KVM_GREGS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHADOW_CONTEXT_MODE
#undef	DebugSHC
#define	DEBUG_SHADOW_CONTEXT_MODE 0	/* shadow context debugging */
#define	DebugSHC(fmt, args...)					\
({									\
	if (DEBUG_SHADOW_CONTEXT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HWS_UPDATE_MODE
#undef	DebugKVMHSU
#define	DEBUG_KVM_HWS_UPDATE_MODE	0	/* hardware stacks frames */
						/* update debugging */
#define	DebugKVMHSU(fmt, args...)					\
({									\
	if (DEBUG_KVM_HWS_UPDATE_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_HWS_PATCH_MODE
#undef	DebugKVMHSP
#define	DEBUG_KVM_HWS_PATCH_MODE	0	/* hardware stacks frames */
						/* patching debug */
#define	DebugKVMHSP(fmt, args...)					\
({									\
	if (DEBUG_KVM_HWS_PATCH_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_VCPU_TRAP_MODE
#undef	DebugTRAP
#define	DEBUG_PV_VCPU_TRAP_MODE	0	/* trap injection debugging */
#define	DebugTRAP(fmt, args...)						\
({									\
	if (DEBUG_PV_VCPU_TRAP_MODE)					\
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

#undef	DEBUG_INTC_CU_REG_MODE
#undef	DebugCUREG
#define	DEBUG_INTC_CU_REG_MODE	0	/* CPU reguster access intercept */
					/* events debug mode */
#define	DebugCUREG(fmt, args...)					\
({									\
	if (DEBUG_INTC_CU_REG_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_PV_SYSCALL_MODE
#define	DEBUG_PV_SYSCALL_MODE	0	/* syscall injection debugging */

#if	DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE
extern bool debug_guest_ust;
#else
#define	debug_guest_ust	false
#endif /* DEBUG_PV_UST_MODE || DEBUG_PV_SYSCALL_MODE */

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE	0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

bool debug_guest_user_stacks = false;

__visible int __nodedata slt_disable;

static int kvm_save_updated_guest_local_glob_regs(struct kvm_vcpu *vcpu,
						  inject_caller_t from);

void kvm_set_pv_vcpu_kernel_image(struct kvm_vcpu *vcpu)
{
	e2k_cud_t oscud;
	e2k_gd_t osgd;
	e2k_cute_t *cute_p;
	u64 base;
	e2k_cutd_t cutd;

	if (vcpu->arch.vcpu_state == NULL)
		return;

	oscud = vcpu_new_cud(vcpu, (u64)vcpu->arch.guest_phys_base,
			vcpu->arch.guest_size, 0, cud_m64);
	kvm_set_guest_vcpu_OSCUD(vcpu, oscud);
	DebugKVM("set OSCUD to guest kernel image: base 0x%llx, size 0x%llx\n",
		 vcpu_cud_base(vcpu, oscud), vcpu_cud_size(vcpu, oscud));
	kvm_set_guest_vcpu_CUD(vcpu, oscud);
	DebugKVM("set CUD to init state: base 0x%llx, size 0x%llx\n",
		 vcpu_cud_base(vcpu, oscud), vcpu_cud_size(vcpu, oscud));

	osgd = vcpu_new_gd(vcpu, (u64) vcpu->arch.guest_phys_base, vcpu->arch.guest_size);
	kvm_set_guest_vcpu_OSGD(vcpu, osgd);
	DebugKVM("set OSGD to guest kernel image: base 0x%llx, size 0x%llx\n",
		 vcpu_gd_base(vcpu, osgd), vcpu_gd_size(vcpu, osgd));
	kvm_set_guest_vcpu_GD(vcpu, osgd);
	DebugKVM("set GD to init state: base 0x%llx, size 0x%llx\n",
		 vcpu_gd_base(vcpu, osgd), vcpu_gd_size(vcpu, osgd));

	cute_p = (e2k_cute_t *) kvm_vcpu_hva_to_gpa(vcpu, (unsigned long)vcpu->arch.guest_cut);
	base = (e2k_addr_t) cute_p;
	cutd.base = base;
	kvm_set_guest_vcpu_OSCUTD(vcpu, cutd);
	kvm_set_guest_vcpu_CUTD(vcpu, cutd);
	DebugKVM("set OSCUTD & CUTD to init state: base 0x%llx\n", cutd.base);
}

void kvm_reset_cpu_state(struct kvm_vcpu *vcpu)
{
	{
		u64 osr0;

		osr0 = 0;
		kvm_set_guest_vcpu_OSR0(vcpu, osr0);
		DebugKVM("set OSR0 to init state: base 0x%llx\n", osr0);
	}
	{
		e2k_core_mode_t core_mode;

		AW(core_mode) = 0;
		kvm_set_guest_vcpu_CORE_MODE(vcpu, core_mode);
		DebugKVM("set CORE_MODE to init state: 0x%x\n", AW(core_mode));
	}

	/* TIRs num from -1: 0 it means 1 TIR */
	kvm_set_guest_vcpu_TIRs_num(vcpu, -1);

	/* Set virtual CPUs registers status to initial value */
	kvm_reset_guest_vcpu_regs_status(vcpu);
}

e2k_idr_t kvm_vcpu_get_idr(const struct kvm_vcpu *vcpu)
{
	kvm_guest_info_t *guest_info = &vcpu->kvm->arch.guest_info;
	e2k_idr_t idr = read_IDR_reg();

	if (guest_info->is_stranger ||
			cpu_has(CPU_FEAT_V7_CPU_REGS) && !vcpu_descr_v7(vcpu)) {
		/* update IDR in accordance with guest machine CPUs type */
		idr.mdl = guest_info->cpu_mdl;
		idr.rev = guest_info->cpu_rev;
		idr.core = vcpu->vcpu_id;
		idr.pn = 0;	/* FIXME: is not implemented NUMA node id */
		if (unlikely(guest_info->cpu_iset < E2K_ISET_V3)) {
			/* set IDR.hw_virt to mark guest mode because of */
			/* CPUs of iset V2 have not CORE_MODE register */
			idr.hw_virt = vcpu->kvm->arch.is_hv;
		}

		DebugCUREG("guest IDR was changed: 0x%llx\n", AW(idr));
	}

	return idr;
}

void kvm_reset_cpu_state_idr(struct kvm_vcpu *vcpu)
{
	e2k_idr_t idr = kvm_vcpu_get_idr(vcpu);

	kvm_set_guest_vcpu_IDR(vcpu, idr);
	DebugKVM("set IDR to init state: 0x%llx\n", AW(idr));
}

static void vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu,
						  const struct kvm_hw_cpu_context *hw_ctxt)
{
	/*
	 * CPU shadow context
	 */
	kvm_set_guest_vcpu_OSCUD(vcpu, hw_ctxt->sh_oscud);
	kvm_set_guest_vcpu_OSGD(vcpu, hw_ctxt->sh_osgd);
	kvm_set_guest_vcpu_OSCUTD(vcpu, hw_ctxt->sh_oscutd);
	kvm_set_guest_vcpu_OSCUIR(vcpu, hw_ctxt->sh_oscuir);
	DebugSHC("initialized VCPU #%d shadow context\n"
		 "SH_OSCUD:  base 0x%llx size 0x%llx\n"
		 "SH_OSGD:   base 0x%llx size 0x%llx\n"
		 "CUTD:      base 0x%llx\n"
		 "SH_OSCUTD: base 0x%llx\n"
		 "SH_OSCUIR: index 0x%x\n",
		 vcpu->vcpu_id,
		 vcpu_cud_base(vcpu, hw_ctxt->sh_oscud),
		 vcpu_cud_size(vcpu, hw_ctxt->sh_oscud),
		 vcpu_gd_base(vcpu, hw_ctxt->sh_osgd),
		 vcpu_gd_size(vcpu, hw_ctxt->sh_osgd),
		 vcpu->arch.sw_ctxt.cutd.base,
		 hw_ctxt->sh_oscutd.base, hw_ctxt->sh_oscuir.index);
}

void write_hw_ctxt_to_pv_vcpu_registers(struct kvm_vcpu *vcpu,
					const struct kvm_hw_cpu_context *hw_ctxt,
					const struct kvm_sw_cpu_context *sw_ctxt)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	/*
	 * Stack registers
	 */
	kvm_set_guest_vcpu_PSP(vcpu, hw_ctxt->sh_psp);
	kvm_set_guest_vcpu_PCSP(vcpu, hw_ctxt->sh_pcsp);

	DebugSHC("initialized VCPU #%d shadow registers:\n"
		 "SH_PSP:   base 0x%llx size 0x%llx index 0x%llx\n"
		 "SH_PCSP:  base 0x%llx size 0x%llx index 0x%llx\n",
		 vcpu->vcpu_id,
		 vcpu_psp_base(vcpu, hw_ctxt->sh_psp), vcpu_psp_size(vcpu, hw_ctxt->sh_psp),
		 vcpu_psp_ind(vcpu, hw_ctxt->sh_psp),
		 vcpu_pcsp_base(vcpu, hw_ctxt->sh_pcsp), vcpu_pcsp_size(vcpu, hw_ctxt->sh_pcsp),
		 vcpu_pcsp_ind(vcpu, hw_ctxt->sh_pcsp));

	kvm_set_guest_vcpu_WD(vcpu, hw_ctxt->sh_wd);

	/*
	 * MMU shadow context
	 */
	kvm_write_pv_vcpu_MMU_CR_reg(vcpu, hw_ctxt->sh_mmu_cr);
	kvm_write_pv_vcpu_mmu_PID_reg(vcpu, hw_ctxt->sh_pid);
	DebugSHC("initialized VCPU #%d MMU shadow context:\n"
		 "SH_MMU_CR:  value 0x%llx\n"
		 "SH_PID:     value 0x%llx\n"
		 "GP_PPTB:    value 0x%llx\n"
		 "sh_U_PPTB:  value 0x%lx\n"
		 "sh_U_VPTB:  value 0x%lx\n"
		 "U_PPTB:     value 0x%lx\n"
		 "U_VPTB:     value 0x%lx\n"
		 "GID:        value 0x%llx\n",
		 vcpu->vcpu_id,
		 AW(hw_ctxt->sh_mmu_cr), hw_ctxt->sh_pid,
		 mmu->get_vcpu_gp_pptb(vcpu),
		 mmu->get_vcpu_context_u_pptb(vcpu),
		 mmu->get_vcpu_context_u_vptb(vcpu),
		 mmu->get_vcpu_u_pptb(vcpu),
		 mmu->get_vcpu_u_vptb(vcpu), hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	vcpu_write_os_cu_hw_ctxt_to_registers(vcpu, hw_ctxt);

	kvm_set_guest_vcpu_OSR0(vcpu, hw_ctxt->sh_osr0);
	DebugSHC("SH_OSR0: value 0x%llx\n", hw_ctxt->sh_osr0);
	kvm_set_guest_vcpu_CORE_MODE(vcpu, hw_ctxt->sh_core_mode);
	DebugSHC("SH_CORE_MODE: value 0x%x, gmi %s, hci %s\n",
		 AW(hw_ctxt->sh_core_mode),
		 (hw_ctxt->sh_core_mode.gmi) ? "true" : "false",
		 (hw_ctxt->sh_core_mode.hci) ? "true" : "false");
}

void kvm_dump_shadow_u_pptb(struct kvm_vcpu *vcpu, const char *title)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	DebugSHC("%s   sh_U_PPTB:  value 0x%lx\n"
		 "   sh_U_VPTB:  value 0x%lx\n"
		 "   U_PPTB:     value 0x%lx\n"
		 "   U_VPTB:     value 0x%lx\n"
		 "   SH_PID:     value 0x%llx\n",
		 title,
		 mmu->get_vcpu_context_u_pptb(vcpu),
		 mmu->get_vcpu_context_u_vptb(vcpu),
		 mmu->get_vcpu_u_pptb(vcpu),
		 mmu->get_vcpu_u_vptb(vcpu), read_guest_PID_reg(vcpu));
}

void prepare_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu,
				    e2k_mem_ps_t *ps_frames,
				    e2k_mem_crs_t *pcs_frames, u64 *args,
				    int args_num, char *entry_point,
				    e2k_psr_t psr, e2k_size_t usd_size,
				    e2k_size_t *ps_ind, e2k_size_t *pcs_ind,
				    int cui, bool kernel)
{
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	unsigned long ussz, entry_IP;
	int arg;
	int wbs;

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	entry_IP = (unsigned long)entry_point;

	wbs = (sizeof(*args) * 2 * args_num + (EXT_4_NR_SZ - 1)) / EXT_4_NR_SZ;

	/* pcs[0] frame can be empty, because of it should not be returns */
	/* to here and it is used only to fill into current CR registers */
	/* while function on the next frame pcs[1] is running */
	pcs_frames[0].cr0.pf = -1;
	set_cr0_ip(pcs_frames[0].cr0, 0);
	pcs_frames[0].cr1 = (e2k_cr1_t) {
	0};

	/* guest is user of host for pv, GLAUNCH set PSR for hv */
	/* set mode to run guest */
	psr.pm = vcpu->arch.is_hv;

	/* Prepare pcs[1] frame, it is frame of VCPU start function */
	/* Important only only IP (as start of function) */
	cr0.pf = -1;
	set_cr0_ip(cr0, entry_IP);
	cr1 = (e2k_cr1_t) {
	0};
	cr1.psr = AW(psr);
	cr1.wbs = wbs;
	cr1.wpsz = wbs;
	cr1.cui = cui;
	if (!cpu_has(CPU_FEAT_ISET_V6))
		cr1.ic = kernel;

	ussz = (vcpu_descr_v7(vcpu)) ? 0 : usd_size;
	cr1 = vcpu_set_cr1_ussz(vcpu, cr1, ussz);
	pcs_frames[1].cr0 = cr0;
	pcs_frames[1].cr1 = cr1;

	DebugKVMSTUP("VCPU start PCS[1]: IP %pF wbs 0x%x\n",
		     (void *)get_cr0_ip(pcs_frames[1].cr0),
		     pcs_frames[1].cr1.wbs * EXT_4_NR_SZ);
	DebugKVMSTUP("   PCS[%d] CR0 lo: 0x%016llx  hi: 0x%016llx\n",
		     1, LO(pcs_frames[1].cr0), HI(pcs_frames[1].cr0));
	DebugKVMSTUP("   PCS[%d] CR1 lo: 0x%016llx  hi: 0x%016llx\n",
		     1, LO(pcs_frames[1].cr1), HI(pcs_frames[1].cr1));
	DebugKVMSTUP("   PCS[%d] CR0 lo: 0x%016llx  hi: 0x%016llx\n",
		     0, LO(pcs_frames[0].cr0), HI(pcs_frames[0].cr0));
	DebugKVMSTUP("   PCS[%d] CR1 lo: 0x%016llx  hi: 0x%016llx\n",
		     0, LO(pcs_frames[0].cr1), HI(pcs_frames[0].cr1));

	/* prepare procedure stack frame ps[0] for pcs[1] should contain */
	/* VCPU start function arguments */
#pragma loop count (2)
	for (arg = 0; arg < args_num; arg++) {
		int frame = (arg * sizeof(*args)) / (EXT_4_NR_SZ / 2);
		bool lo = (arg & 0x1) == 0x0;
		unsigned long long arg_value;

		arg_value = args[arg];

		if (machine.native_iset_ver < E2K_ISET_V5) {
			if (lo)
				ps_frames[frame].v3.word_lo = arg_value;
			else
				ps_frames[frame].v3.word_hi = arg_value;
			/* Skip frame[2] and frame[3] - they hold */
			/* extended data not used by kernel */
		} else {
			if (lo)
				ps_frames[frame].v5.word_lo = arg_value;
			else
				ps_frames[frame].v5.word_hi = arg_value;
			/* Skip frame[1] and frame[3] - they hold */
			/* extended data not used by kernel */
		}
		DebugKVMSTUP("   PS[%d].%s is 0x%016llx\n",
			     frame, (lo) ? "lo" : "hi", arg_value);
	}

	/* set stacks pointers indexes */
	*ps_ind = wbs * EXT_4_NR_SZ;
	*pcs_ind = 2 * SZ_OF_CR;
	DebugKVMSTUP("stacks PS.ind 0x%lx PCS.ind 0x%lx\n", *ps_ind, *pcs_ind);
}

void kvm_init_pv_vcpu_intc_handling(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;

	/* MMU intercepts were handled, clear state for new intercepts */
	kvm_clear_intc_mu_state(vcpu);

	/* clear hypervisor intercept event counters */
	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	intc_ctxt->cur_mu = -1;

	/* clear guest interception TIRs & trap cellar */
	if (likely(!vcpu->arch.trap_wish)) {
		kvm_clear_vcpu_intc_TIRs_num(vcpu);
		regs->traps_to_guest = 0;
	} else {
		/* some trap(s)was (were) injected as wish to handle them */
		regs->traps_to_guest = 0;
	}

	/* replace stacks->top value with real register SBR state */
	regs->stacks.top = regs->g_stacks.top;

	pv_vcpu_check_trap_in_fast_syscall(vcpu, regs);
}

noinline __interrupt void
startup_pv_vcpu(struct kvm_vcpu *vcpu, guest_hw_stack_t *stack_regs,
		unsigned flags)
{
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	e2k_sbr_t sbr;
	e2k_usd_t usd;
	e2k_cutd_t cutd;

	cr0 = stack_regs->crs.cr0;
	cr1 = stack_regs->crs.cr1;
	psp = stack_regs->stacks.psp;
	pcsp = stack_regs->stacks.pcsp;
	sbr.base = stack_regs->stacks.top;
	usd = stack_regs->stacks.usd;
	cutd = stack_regs->cutd;

	/* return interrupts control to PSR and disable all IRQs */
	/* disable all IRQs in UPSR to switch mmu context */
	RETURN_TO_KERNEL_IRQ_MASK_REG(E2K_KERNEL_UPSR_DISABLED_ALL);

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	if (unlikely(!(flags & FROM_HYPERCALL_SWITCH))) {
		E2K_KVM_BUG_ON(true);	/* now only from hypercall */
		/* save host VCPU data stack pointer registers */
		sw_ctxt->host_sbr = native_read_SBR_reg();
		sw_ctxt->host_usd = native_read_USD_reg();
	}

	/* set flags of return type to guest kernel or guest user: */
	/* now it is to kernel */
	host_return_to_guest_kernel(current_thread_info());

	__guest_enter(current_thread_info(), &vcpu->arch, flags);

	if (flags & FROM_HYPERCALL_SWITCH) {
		int users;

		/* free MMU hypercall stacks */
		users = kvm_pv_put_hcall_guest_stacks(vcpu, false);
		E2K_KVM_BUG_ON(users != 0);
	}
	E2K_KVM_BUG_ON(host_hypercall_exit(vcpu));

	/* set guest UPSR to initial state */
	native_write_UPSR_reg(sw_ctxt->upsr);

	/*
	 * Optimization to do not flush chain stack.
	 *
	 * Old stacks are not needed anymore, do not flush procedure
	 * registers and chain registers - only strip sizes
	 */
	native_strip_PSHTP_window();
	native_strip_PCSHTP_window();

	/*
	 * There might be a FILL operation still going right now.
	 * Wait for it's completion before going further - otherwise
	 * the next FILL on the new PSP/PCSP registers will race
	 * with the previous one.
	 *
	 * The first and the second FILL operations will use different
	 * addresses because we will change PSP/PCSP registers, and
	 * thus loads/stores from these two FILLs can race with each
	 * other leading to bad register file (containing values from
	 * both stacks)..
	 */
	E2K_WAIT(_ma_c);

	native_write_CUTD_reg(cutd);

	native_write_stacks_cr(psp, pcsp, usd, sbr, cr0, cr1);
}

/* See at arch/include/asm/switch.h  the 'flags' argument values */
noinline __interrupt unsigned long
launch_pv_vcpu(struct kvm_vcpu *vcpu, unsigned switch_flags)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;
	thread_info_t *ti = current_thread_info();
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	long ret_value;

	/*
	 * It is important if there was before switching from hypercall
	 * to vcpu-host mode and now return to vcpu-guest mode,
	 * so it is return value of hypercall
	 */
	ret_value = sw_ctxt->ret_value;
	sw_ctxt->ret_value = 0;	/* this value should not be used by vcpu-host */

	cr0 = sw_ctxt->crs.cr0;
	cr1 = sw_ctxt->crs.cr1;
	psp = hw_ctxt->sh_psp;
	pcsp = hw_ctxt->sh_pcsp;
	pcsp = hw_ctxt->sh_pcsp;

	/* Switch IRQ control to PSR and disable MI/NMIs */
	/* disable all IRQs in UPSR to switch mmu context */
	RETURN_TO_KERNEL_IRQ_MASK_REG(E2K_KERNEL_UPSR_DISABLED_ALL);

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	/* save host VCPU data stack pointer registers */
	sw_ctxt->host_sbr = native_read_SBR_reg();
	sw_ctxt->host_usd = native_read_USD_reg();

	/* set flags of return type to guest kernel or guest user: */
	/* now it is to kernel */
	host_return_to_guest_kernel(ti);

	__guest_enter(ti, &vcpu->arch, switch_flags);

	/* from now the host process is at paravirtualized guest (VCPU) mode */
	set_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);

	if (switch_flags & FROM_HYPERCALL_SWITCH) {
		int users;

		/* free MMU hypercall stacks */
		users = kvm_pv_put_hcall_guest_stacks(vcpu, false);
		E2K_KVM_BUG_ON(users != 0);
	}
	E2K_KVM_BUG_ON(host_hypercall_exit(vcpu));

	NATIVE_FLUSHCPU;	/* spill all host hardware stacks */

	sw_ctxt->crs.cr0 = native_read_CR0_reg();
	sw_ctxt->crs.cr1 = native_read_CR1_reg();

	E2K_WAIT_MA;		/* wait for spill completion */

	hw_ctxt->sh_psp = native_read_PSP_reg();
	hw_ctxt->sh_pcsp = native_read_PCSP_reg();

	/*
	 * There might be a FILL operation still going right now.
	 * Wait for it's completion before going further - otherwise
	 * the next FILL on the new PSP/PCSP registers will race
	 * with the previous one.
	 *
	 * The first and the second FILL operations will use different
	 * addresses because we will change PSP/PCSP registers, and
	 * thus loads/stores from these two FILLs can race with each
	 * other leading to bad register file (containing values from
	 * both stacks)..
	 */
	E2K_WAIT(_ma_c);

	native_write_hw_stacks_cr(psp, pcsp, cr0, cr1);

	return ret_value;
}

notrace noinline __interrupt void
pv_vcpu_switch_to_host_from_intc(thread_info_t *ti)
{
	struct kvm_vcpu *vcpu = ti->vcpu;

	BUG_ON(vcpu == NULL);
	vcpu->arch.from_pv_intc = true;
	(void) switch_to_host_pv_vcpu_mode(ti, vcpu, false /* from vcpu-guest */,
			FULL_CONTEXT_SWITCH | DONT_AAU_CONTEXT_SWITCH |
				DONT_SAVE_KGREGS_SWITCH | DONT_MMU_CONTEXT_SWITCH |
				DONT_TRAP_MASK_SWITCH,
			0 /* return value should not be used */);
}

notrace noinline __interrupt void
pv_vcpu_return_to_intc_mode(thread_info_t *ti, struct kvm_vcpu *vcpu)
{
	BUG_ON(vcpu == NULL);
	vcpu->arch.from_pv_intc = false;
	(void)return_to_intc_pv_vcpu_mode(ti, vcpu,
					  FULL_CONTEXT_SWITCH |
					  DONT_AAU_CONTEXT_SWITCH |
					  DONT_SAVE_KGREGS_SWITCH |
					  DONT_MMU_CONTEXT_SWITCH |
					  DONT_TRAP_MASK_SWITCH);
}

void kvm_emulate_pv_vcpu_intc(thread_info_t *ti, pt_regs_t *regs,
			      trap_pt_regs_t *trap)
{
	do_emulate_pv_vcpu_intc(ti, regs, trap);
}

void return_from_pv_vcpu_intc(struct thread_info *ti, pt_regs_t *regs,
			      restore_caller_t from)
{
	do_return_from_pv_vcpu_intc(ti, regs, from);
}

static notrace __always_inline void inject_handler_trampoline(void)
{
	e2k_sbr_t sbr;
	e2k_usd_t usd;

	if (TASK_IS_PROTECTED(current))
		DISABLE_US_CLW();

	/*
	 * Switch to kernel stacks.
	 */
	GET_SIG_RESTORE_STACK(current_thread_info(), sbr, usd);
	native_write_USBR_USD_regs(sbr, usd);

	/*
	 * Switch to %upsr for interrupts control
	 */
	current_thread_info()->upsr = read_UPSR_reg();
	SET_KERNEL_IRQ_WITH_DISABLED_NMI();
}

noinline notrace  __interrupt __section(".entry.text")
void trap_handler_trampoline_continue(void)
{
	inject_handler_trampoline();

	/* return to hypervisor context */
	return_from_pv_vcpu_inject(current_thread_info()->vcpu);

	E2K_JUMP(return_pv_vcpu_trap);
}

noinline notrace  __interrupt __section(".entry.text")
void syscall_handler_trampoline_continue(u64 sys_rval)
{
	struct kvm_vcpu *vcpu;

	inject_handler_trampoline();

	vcpu = current_thread_info()->vcpu;
	/* return to hypervisor context */
	return_from_pv_vcpu_inject(vcpu);

	syscall_handler_trampoline_start(vcpu, sys_rval);

	E2K_JUMP(return_pv_vcpu_syscall);
}

noinline notrace  __interrupt __section(".entry.text")
void return_pv_vcpu_from_mkctxt_continue(void)
{
	struct kvm_vcpu *vcpu;

	inject_handler_trampoline();

	vcpu = current_thread_info()->vcpu;
	/* return to hypervisor context */
	return_from_pv_vcpu_inject(vcpu);

	E2K_JUMP(pv_vcpu_mkctxt_complete);
}

noinline notrace  __interrupt __section(".entry.text")
void syscall_fork_trampoline_continue(u64 sys_rval)
{
	struct kvm_vcpu *vcpu;

	inject_handler_trampoline();

	vcpu = current_thread_info()->vcpu;
	/* return to hypervisor context */
	return_from_pv_vcpu_inject(vcpu);

	syscall_fork_handler_trampoline_start(vcpu);

	E2K_JUMP_WITH_ARG(return_pv_vcpu_syscall_fork, sys_rval);
}

static void fill_pv_vcpu_handler_trampoline(struct kvm_vcpu *vcpu,
				e2k_mem_crs_t *crs, inject_caller_t from)
{
	unsigned long ussz;

	memset(crs, 0, sizeof(*crs));

	crs->cr0.pf = -1ULL;
	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		set_cr0_ip(crs->cr0, syscall_handler_trampoline);
	} else if (from == FROM_PV_VCPU_SYS_SIGRETURN_INJECT) {
		set_cr0_ip(crs->cr0, sys_sigreturn_handler_trampoline);
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		set_cr0_ip(crs->cr0, trap_handler_trampoline);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	crs->cr1.psr = E2K_KERNEL_PSR_DISABLED_ALL.all;
	crs->cr1.cui = KERNEL_CODES_INDEX;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1.ic = 1;
	if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		crs->cr1.wpsz = 1;
		crs->cr1.wbs = 0;
	} else if (from == FROM_PV_VCPU_SYS_SIGRETURN_INJECT) {
		crs->cr1.wpsz = 0;
		crs->cr1.wbs = 0;
	} else if (from == FROM_PV_VCPU_TRAP_INJECT) {
		crs->cr1.wpsz = 0;
		crs->cr1.wbs = 0;
	} else {
		E2K_KVM_BUG_ON(true);
	}
	ussz = (vcpu_descr_v7(vcpu)) ? 0 : pv_vcpu_get_gti(vcpu)->us_size;
	crs->cr1 = vcpu_set_cr1_ussz(vcpu, crs->cr1, ussz);
}

static int prepare_pv_vcpu_inject_handler_trampoline(struct kvm_vcpu *vcpu,
				pt_regs_t *regs, e2k_stacks_t *stacks,
				inject_caller_t from, bool guest_user)
{
	e2k_mem_crs_t *k_crs, crs;
	e2k_pcsp_t k_pcsp;
	unsigned long flags;
	int ret;

	/*
	 * Prepare 'sighandler_trampoline' frame
	 */
	fill_pv_vcpu_handler_trampoline(vcpu, &crs, from);

	if (likely(stacks->pcshtp.ind > 0 || !guest_user)) {
		/*
		 * Copy the new frame into host chain stack because of top guest
		 * frame was spilled to guest's kernel stack and can be replaced
		 * at host's kernel stack by the trampoline frame
		 *
		 * See user_hw_stacks_copy_full() for an explanation why this frame
		 * is located at (AS(ti->k_pcsp_lo).base).
		 */
		k_pcsp = current_thread_info()->k_pcsp;
		k_crs = (e2k_mem_crs_t *)PCSP_BASE(k_pcsp);

		raw_all_irq_save(flags);
		E2K_FLUSHC;
		/* User frame from *k_crs has been copied to userspace */
		/* already in user_hw_stacks_copy_full() */
		*k_crs = crs;
		raw_all_irq_restore(flags);

		stacks->pcsp = vcpu_incr_pcsp_ind(vcpu, stacks->pcsp, SZ_OF_CR);
		ret = 0;
	} else {
		/*
		 * k_crs frame of the kernel chain stack has not free and
		 * trampoline frame can be located only at the top of
		 * guest chain stack
		 */
		ret = pv_vcpu_user_hw_stacks_copy_crs(vcpu, stacks, regs, &crs);
	}

	DebugUST("set trampoline CRS at bottom of host stack from %px,\n"
		 "increase guest kernel chain index 0x%llx, error %d\n",
		 k_crs, vcpu_pcsp_ind(vcpu, stacks->pcsp), ret);

	return ret;
}

static int prepare_pv_vcpu_trap_handler_frame(struct kvm_vcpu *vcpu,
					      pt_regs_t *regs,
					      e2k_stacks_t *g_stacks)
{
	e2k_mem_ps_t ps_frames[4];
	void __user *u_pframe;
	int wbs, ret;

	/*
	 * Create clean procedure stack to avoid procedure stack overflow
	 * fake trap at the moment of launch the guest trap handler
	 */
	memset(ps_frames, 0, sizeof(ps_frames));

	u_pframe = (void __user *)vcpu_psp_ptr(vcpu, g_stacks->psp);

	ret = copy_e2k_stack_to_user(u_pframe, &ps_frames, sizeof(ps_frames), regs);
	if (unlikely(ret)) {
		pr_err("%s() : copy clean stack frame to user failed\n",
		       __func__);
		return -EFAULT;
	}

	g_stacks->psp = vcpu_incr_psp_ind(vcpu, g_stacks->psp, sizeof(ps_frames));
	DebugUST("set trap handler proc frame at bottom of guest kernel stack from %px\n",
		u_pframe);
	wbs = (sizeof(ps_frames) + (EXT_4_NR_SZ - 1)) / EXT_4_NR_SZ;
	return wbs;
}

static int prepare_pv_vcpu_inject_handler_frame(struct kvm_vcpu *vcpu,
						pt_regs_t *regs,
						e2k_stacks_t *stacks,
						e2k_mem_crs_t *crs)
{
	thread_info_t *ti = current_thread_info();
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	unsigned long ussz, flags;
	e2k_mem_crs_t *k_crs;
	long g_pcshtp;
	int wbs, cui;

	wbs = prepare_pv_vcpu_trap_handler_frame(vcpu, regs, stacks);
	if (unlikely(wbs < 0))
		return wbs;

	/*
	 * Update chain stack
	 */
	memset(crs, 0, sizeof(*crs));

	cui = 0;

	/* FIXME: Here it need set guest OSCUD as CUD and remember curren CUD */
	/* which can be guest user CUD
	   NATIVE_NV_NOIRQ_WRITE_CUTD_REG(vcpu->arch.hw_ctxt.oscutd);
	 */

	crs->cr0.pf = -1ULL;
	set_cr0_ip(crs->cr0, kvm_get_pv_vcpu_ttable_base(vcpu));
	/* real guest VCPU PSR should be as for user - nonprivileged */
	crs->cr1.psr = E2K_USER_INITIAL_PSR.all;
	crs->cr1.cui = cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1.ic = 0;
	crs->cr1.wbs = 0;
	crs->cr1.wpsz = 0;
	ussz = (vcpu_descr_v7(vcpu)) ? 0 : vcpu_usd_ind(vcpu, stacks->usd);
	crs->cr1 = vcpu_set_cr1_ussz(vcpu, crs->cr1, ussz);

	/*
	 * handle_sys_call() does not restore %cr registers from pt_regs
	 * for performance reasons, so update chain stack in memory too.
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base + SZ_OF_CR).
	 */
	k_crs = (e2k_mem_crs_t *)PCSP_BASE(ti->k_pcsp);

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	if (unlikely(stacks->pcshtp.ind == 0)) {
		/*
		 * The host kernel chain stack has only one guest frame:
		 * the guest's frame of user system call point
		 */
		*k_crs = *crs;
	} else {
		/* there are two frames of guest's user at bottom of host */
		++k_crs;
		*k_crs = *crs;
	}
	raw_all_irq_restore(flags);
	DebugUST("set trap handler chain frame at bottom of host stack\n"
		 "from %px and CRS at %px to return to handler instead of trap point\n",
		k_crs, crs);

	/* See comment in user_hw_stacks_copy_full() */
	/* but guest user chain stack can be empty */
	g_pcshtp = stacks->pcshtp.ind;
	E2K_KVM_BUG_ON(g_pcshtp != SZ_OF_CR && g_pcshtp != 0
		       && !regs->need_inject);

	return 0;
}

static int prepare_pv_vcpu_syscall_handler_frame(struct kvm_vcpu *vcpu,
						 pt_regs_t *regs)
{
	e2k_stacks_t *g_stacks = &regs->g_stacks;
	e2k_mem_crs_t *crs = &regs->crs;
	e2k_mem_ps_t ps_frames[4];
	e2k_mem_crs_t *k_crs;
	unsigned long ussz, flags, ts_flag;
	void __user *u_pframe;
	int arg, cui, wbs, ret;

	/*
	 * Update procedure stack
	 */
	memset(ps_frames, 0, sizeof(ps_frames));

	for (arg = 0; arg <= 6; arg++) {
		int frame = (arg * sizeof(*regs->dargs)) / (EXT_4_NR_SZ / 2);
		bool lo = (arg & 0x1) == 0x0;
		unsigned long long arg_value;

		if (arg == 0) {
			arg_value = regs->sys_num;
		} else {
			arg_value = regs->dargs[arg];
		}

		if (machine.native_iset_ver < E2K_ISET_V5) {
			if (lo)
				ps_frames[frame].v3.word_lo = arg_value;
			else
				ps_frames[frame].v3.word_hi = arg_value;
			/* Skip frame[2] and frame[3] - they hold */
			/* extended data not used by kernel */
		} else {
			if (lo)
				ps_frames[frame].v5.word_lo = arg_value;
			else
				ps_frames[frame].v5.word_hi = arg_value;
			/* Skip frame[1] and frame[3] - they hold */
			/* extended data not used by kernel */
		}
		DebugUST("   PS[%d].%s is 0x%016llx\n",
			 frame, (lo) ? "lo" : "hi", arg_value);
	}

	u_pframe = (void __user *)vcpu_psp_ptr(vcpu, g_stacks->psp);

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = copy_e2k_stack_to_user(u_pframe, &ps_frames, sizeof(ps_frames), regs);
	clear_ts_flag(ts_flag);
	if (ret)
		return -EFAULT;

	g_stacks->psp = vcpu_incr_psp_ind(vcpu, g_stacks->psp, sizeof(ps_frames));
	DebugUST("set system call handler proc frame at bottom of guest kernel stack from %px\n",
		u_pframe);

	/*
	 * Update chain stack
	 */
	memset(crs, 0, sizeof(*crs));

	cui = 0;
	wbs = (sizeof(*regs->dargs) * 2 * 8 + (EXT_4_NR_SZ - 1)) / EXT_4_NR_SZ;

	/* FIXME: Here it need set guest OSCUD as CUD and remember curren CUD */
	/* which can be guest user CUD
	   NATIVE_NV_NOIRQ_WRITE_CUTD_REG(vcpu->arch.hw_ctxt.oscutd);
	 */

	crs->cr0.pf = -1ULL;
	set_cr0_ip(crs->cr0, (kvm_get_pv_vcpu_ttable_base(vcpu) +
			      regs->kernel_entry *
			      E2K_SYSCALL_TRAP_ENTRY_SIZE));
	/* real guest VCPU PSR should be as for user - nonprivileged */
	crs->cr1.psr = E2K_USER_INITIAL_PSR.all;
	crs->cr1.cui = cui;
	if (machine.native_iset_ver < E2K_ISET_V6)
		crs->cr1.ic = 0;
	crs->cr1.wpsz = 4;
	crs->cr1.wbs = wbs;
	ussz = (vcpu_descr_v7(vcpu)) ? 0 : vcpu_usd_ind(vcpu, g_stacks->usd);
	crs->cr1 = vcpu_set_cr1_ussz(vcpu, crs->cr1, ussz);

	/*
	 * handle_sys_call() does not restore %cr registers from pt_regs
	 * for performance reasons, so update chain stack in memory too.
	 *
	 * See user_hw_stacks_copy_full() for an explanation why this frame
	 * is located at (AS(ti->k_pcsp_lo).base + SZ_OF_CR).
	 */
	E2K_KVM_BUG_ON(g_stacks->pcshtp.ind > SZ_OF_CR);
	k_crs = (e2k_mem_crs_t *)PCSP_BASE(current_thread_info()->k_pcsp);

	raw_all_irq_save(flags);
	E2K_FLUSHC;
	if (unlikely(g_stacks->pcshtp.ind == 0)) {
		/*
		 * The host kernel chain stack has only one guest frame:
		 * the guest's frame of user system call point
		 */
		*k_crs = *crs;
	} else {
		/* there are two frames of guest's user at bottom of host */
		++k_crs;
		*k_crs = *crs;
	}
	raw_all_irq_restore(flags);

	DebugUST("set trap handler chain frame at bottom of host stack\n"
		 "from %px and CRS at %px to return to handler instead of trap point\n",
		k_crs, crs);

	return 0;
}

/**
 * setup_pv_vcpu_trap_stack - save priviliged part of interrupted
 * (emulated interception mode) user context to a special privileged area
 * now in user space of host VCPU process (qemu)
 */
static int setup_pv_vcpu_trap_stack(struct kvm_vcpu *vcpu, struct pt_regs *regs,
				    inject_caller_t from)
{
	gthread_info_t *gti;
	struct signal_stack_context __user *context;
	pv_vcpu_ctxt_t __user *vcpu_ctxt;
	kvm_host_context_t *host_ctxt;
	int trap_no = 0, scall_no = 0;
	e2k_psr_t guest_psr;
	bool irq_under_upsr;
	unsigned long ts_flag;
	int ret;

	host_ctxt = &vcpu->arch.host_ctxt;
	if (from == FROM_PV_VCPU_TRAP_INJECT) {
		trap_no = atomic_inc_return(&host_ctxt->signal.traps_num);
		E2K_KVM_BUG_ON(trap_no <= atomic_read(&host_ctxt->signal.in_work));
	} else if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		scall_no = atomic_inc_return(&host_ctxt->signal.syscall_num);
		E2K_KVM_BUG_ON(scall_no <= atomic_read(&host_ctxt->signal.in_syscall));
	} else {
		E2K_KVM_BUG_ON(true);
	}

	trace_pv_injection(from, &regs->stacks, &regs->crs,
			   atomic_read(&host_ctxt->signal.traps_num),
			   atomic_read(&host_ctxt->signal.syscall_num));

	ret = kvm_save_updated_guest_local_glob_regs(vcpu, from);
	if (unlikely(ret)) {
		pr_err("%s(): can't save updated local gregs at the context of current signal stack, error %d\n",
		       __func__, ret);
		return ret;
	}

	ret = setup_signal_stack(regs, false);
	if (unlikely(ret)) {
		pr_err("%s(): could not create signal stack to save context, error %d\n",
			__func__, ret);
		return ret;
	}
	gti = pv_vcpu_get_gti(vcpu);
	if (from == FROM_PV_VCPU_TRAP_INJECT) {
		atomic_set(&gti->signal.traps_num, trap_no);
	} else if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		atomic_set(&gti->signal.syscall_num, scall_no);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	gti->signal.stack.base = current_thread_info()->signal_stack.base;
	gti->signal.stack.size = current_thread_info()->signal_stack.size;
	gti->signal.stack.used = current_thread_info()->signal_stack.used;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);

	context = get_signal_stack();
	vcpu_ctxt = &context->vcpu_ctxt;
	ret = 0;
	if (from == FROM_PV_VCPU_TRAP_INJECT) {
		ret |= __put_user(FROM_PV_VCPU_TRAP_INJECT, &vcpu_ctxt->inject_from);
		ret |= __put_user(trap_no, &vcpu_ctxt->trap_no);
	} else if (from == FROM_PV_VCPU_SYSCALL_INJECT) {
		ret |= __put_user(FROM_PV_VCPU_SYSCALL_INJECT, &vcpu_ctxt->inject_from);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	ret |= __put_user(false, &vcpu_ctxt->from_sigreturn);
	ret |= __put_user(0, &vcpu_ctxt->skip_frames);
	ret |= __put_user(0, &vcpu_ctxt->skip_traps);
	ret |= __put_user(0, &vcpu_ctxt->skip_syscalls);

	/* emulate guest VCPU PSR state after trap */
	guest_psr = kvm_emulate_guest_vcpu_psr_trap(vcpu, &irq_under_upsr);
	ret |= __put_user(AW(guest_psr), &AW(vcpu_ctxt->guest_psr));
	ret |= __put_user(irq_under_upsr, &(vcpu_ctxt->irq_under_upsr));

	clear_ts_flag(ts_flag);

	if (unlikely(from == FROM_PV_VCPU_SYSCALL_INJECT && guest_psr.pm)) {
		pr_err("%s(): privileged PSR 0x%x at syscall #%d\n",
		       __func__, AW(guest_psr), scall_no);
		KVM_WARN_ON(true);
		ret = -EINVAL;
	}
	if (trace_pv_save_l_gregs_enabled()) {
		local_gregs_t l_gregs;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = raw_copy_from_user_with_tags(&l_gregs, &context->l_gregs,
						 sizeof(l_gregs));
		clear_ts_flag(ts_flag);
		if (ret) {
			pr_err("%s(): copy local gregs from user with tags failed, error %d\n",
				__func__, ret);
		}
		trace_pv_save_l_gregs(vcpu, from, &l_gregs);
	}
	return ret;
}

static int setup_pv_vcpu_trap(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	bool guest_user;
	int ret;

	BUG_ON(!user_mode(regs));

	guest_user = !pv_vcpu_trap_on_guest_kernel(regs);
	regs->is_guest_user = guest_user;
#if DEBUG_PV_UST_MODE
	debug_guest_ust = guest_user;
#endif
	if (guest_user && !regs->g_stacks_valid) {
		prepare_pv_vcpu_inject_stacks(vcpu, regs);
	}

	DebugTRAP("recursive trap injection, already %d trap(s), in work %d in %s mode\n",
		  atomic_read(&vcpu->arch.host_ctxt.signal.traps_num),
		  atomic_read(&vcpu->arch.host_ctxt.signal.in_work),
		  (guest_user) ? "user" : "kernel");

	if (guest_user && gti->task_is_binco)
		regs->rpr = native_read_RPR_reg();

	/*
	 * After having called setup_signal_stack() we must unroll signal
	 * stack by calling pop_signal_stack() in case an error happens.
	 */
	ret = setup_pv_vcpu_trap_stack(vcpu, regs, FROM_PV_VCPU_TRAP_INJECT);
	if (ret)
		return ret;

	/*
	 * Copy guest's part of kernel hardware stacks into user
	 */
	if (guest_user) {
		ret = pv_vcpu_user_hw_stacks_copy_full(vcpu, regs);
	} else {
		ret = do_user_hw_stacks_copy_full(&regs->stacks, regs, &regs->crs);
		if (!ret)
			regs->stacks.pcsp = vcpu_incr_pcsp_ind(vcpu, regs->stacks.pcsp,
							       SZ_OF_CR);
	}
	if (ret)
		goto free_signal_stack;

	/*
	 * We want user to return to inject_handler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	if (guest_user) {
		ret = prepare_pv_vcpu_inject_handler_trampoline(vcpu, regs,
								&regs->g_stacks,
								FROM_PV_VCPU_TRAP_INJECT,
								true);
	} else {
		ret = prepare_pv_vcpu_inject_handler_trampoline(vcpu, regs,
								&regs->stacks,
								FROM_PV_VCPU_TRAP_INJECT,
								false);
	}
	if (ret)
		goto free_signal_stack;

	/*
	 * guest's trap handler frame should be the last in stacks
	 */
	if (guest_user) {
		ret = prepare_pv_vcpu_inject_handler_frame(vcpu, regs,
							   &regs->g_stacks,
							   &regs->crs);
	} else {
		ret = prepare_pv_vcpu_inject_handler_frame(vcpu, regs,
							   &regs->stacks,
							   &regs->crs);
	}
	if (ret)
		goto free_signal_stack;

	if (guest_user) {
		/*
		 * Set copy of kernel & host global regs ti initial state:
		 *      kernel gregs is zeroed
		 *      host VCPU state greg is inited by pointer to the VCPU
		 * interface with guest
		 */
		INIT_HOST_GREGS_COPY(current_thread_info(), vcpu);
	} else {
		/* keep the current kernel & host global registers state */
		kvm_check_vcpu_state_greg();
	}

	return 0;

free_signal_stack:
	pop_signal_stack();

	return ret;
}

/*
 * Returns true if all traps are fake and cleared or they were not at all
 */
static bool clear_pv_vcpu_fake_traps(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	e2k_tir_t tir;
	bool is_fake = false;

	if (kvm_check_is_vcpu_intc_TIRs_empty(vcpu)) {
		/* nothing traps */
		is_fake = false;
		tir = (e2k_tir_t) {
		0};
	} else {
		tir = kvm_get_vcpu_intc_TIR(vcpu, 0);
		if ((tir.exc_proc_stack_bounds) &&
		    (tir.ip == kvm_get_pv_vcpu_ttable_base(vcpu))) {
			/* it is fake procedure stack bounds trap */
			/* on guest's trap handler start instruction */
			is_fake = true;
		}
	}
	trace_pv_vcpu_fake_traps(vcpu, kvm_get_vcpu_intc_TIRs_num(vcpu),
				 is_fake, tir.lo, tir.hi, regs->traps_to_guest);

	if (!is_fake) {
		/* there is (are) not fake traps */
		return false;
	}

	/* all traps is (are) fake and can be cleared */
	kvm_clear_vcpu_intc_TIRs_num(vcpu);
	regs->traps_to_guest = 0;
	kvm_clear_vcpu_guest_stacks_pending(vcpu, regs);
	return true;
}

static void print_injected_TIRs(struct kvm_vcpu *vcpu)
{
	int TIRs_num = kvm_get_guest_vcpu_TIRs_num(vcpu);

	pr_err("TIRs already injected to guest:\n");
	print_all_TIRs(vcpu->arch.kmap_vcpu_state->cpu.regs.CPU_TIRs, TIRs_num);
	pr_err("TIRs to now inject to guest:\n");
	print_all_TIRs(vcpu->arch.intc_ctxt.TIRs, vcpu->arch.intc_ctxt.nr_TIRs);
}

void insert_pv_vcpu_traps(thread_info_t *ti, pt_regs_t *regs)
{
	static bool __section(".data.once") __warned;
	struct kvm_vcpu *vcpu;
	int failed;
	int TIRs_num;
	bool is_fake = false;

	vcpu = ti->vcpu;
	BUG_ON(vcpu == NULL);

	E2K_KVM_BUG_ON(!kvm_test_intc_emul_flag(regs));
	E2K_KVM_BUG_ON(vcpu->arch.sw_ctxt.in_hypercall);

	TIRs_num = kvm_get_guest_vcpu_TIRs_num(vcpu);
	if (atomic_read(&vcpu->arch.host_ctxt.signal.traps_num) -
	    atomic_read(&vcpu->arch.host_ctxt.signal.in_work) > 1) {
		pr_err
		    ("%s() recursive trap injection, already %d trap(s), in work %d\n",
		     __func__,
		     atomic_read(&vcpu->arch.host_ctxt.signal.traps_num),
		     atomic_read(&vcpu->arch.host_ctxt.signal.in_work));
		if (TIRs_num >= 0) {
			if (!__warned) {
				__warned = true;
				WARN(1, "%s(): guest trap handler did not have time\n"
				     "to read %d TIRs of previous injection\n",
				     __func__, TIRs_num);
				print_injected_TIRs(vcpu);
			}
			pr_err("%s(): kill guest: too many recursive guest traps injection\n",
				__func__);
			goto out_to_kill;
		}
	}

	is_fake = clear_pv_vcpu_fake_traps(vcpu, regs);
	if (TIRs_num >= 0) {
		if (!__warned) {
			__warned = true;
			if (is_fake) {
				/* all new traps are fake, ignore its */
				WARN(1,
				     "%s(): a new trap(s) before previous trap's\n"
				     "TIRs has been read by guest\n"
				     "The trap(s) is considered as fake and ignored for injection\n",
				     __func__);
				print_injected_TIRs(vcpu);
				print_all_TIRs(regs->trap->TIRs,
					       regs->trap->nr_TIRs);
				return;
			} else {
				tracing_off();
				WARN(1, "%s(): a new trap(s) before previous trap's TIRs has been read by guest\n",
					__func__);
			}
		}
		if (unlikely(!is_fake)) {
			pr_err
			    ("%s(): kill guest: new not fake trap, previous TIRs not yet read\n",
				__func__);
			print_injected_TIRs(vcpu);
			print_all_TIRs(regs->trap->TIRs, regs->trap->nr_TIRs);
			goto out_to_kill;
		} else {
			/*
			 * Ignore new trap and retry continue previous trap handler
			 */
			return;
		}
	} else if ((unlikely(is_fake))) {
		if (!__warned) {
			__warned = true;
			WARN(1, "%s(): fake trap, but there is not previous TIRs\n", __func__);
			print_all_TIRs(regs->trap->TIRs, regs->trap->nr_TIRs);
		}
		return;
	}

	kvm_clear_vcpu_guest_stacks_pending(vcpu, regs);

	kvm_set_pv_vcpu_SBBP_TIRs(vcpu, regs);
	kvm_set_pv_vcpu_trap_cellar(vcpu);
	kvm_set_pv_vcpu_trap_context(vcpu, regs);

	kvm_clear_guest_traps_wish(vcpu);

	failed = setup_pv_vcpu_trap(vcpu, regs);
	if (failed) {
		pr_err("%s(): setup vcpu trap failed, error %d\n",
		       __func__, failed);
		goto out_to_kill;
	}

	return;

out_to_kill:
	force_sig(SIGKILL);
}

static int setup_pv_vcpu_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	gthread_info_t *gti = pv_vcpu_get_gti(vcpu);
	inject_caller_t from;
	int ret;

	DebugTRAP("start on VCPU #%d, system call entry #%d/%d, regs at %px\n",
		  vcpu->vcpu_id, regs->kernel_entry, regs->sys_num, regs);

	BUG_ON(!user_mode(regs));
	regs->is_guest_user = true;

#if DEBUG_PV_SYSCALL_MODE
	debug_guest_ust = true;
#endif

	E2K_KVM_BUG_ON(!is_sys_call_pt_regs(regs));

	if (!regs->g_stacks_valid) {
		prepare_pv_vcpu_inject_stacks(vcpu, regs);
	}

	/*
	 * After having called setup_signal_stack() we must unroll signal
	 * stack by calling pop_signal_stack() in case an error happens.
	 */
	ret = setup_pv_vcpu_trap_stack(vcpu, regs, FROM_PV_VCPU_SYSCALL_INJECT);
	if (ret)
		return ret;

	/*
	 * Copy guest's part of kernel hardware stacks into user
	 */
	ret = pv_vcpu_user_hw_stacks_copy_full(vcpu, regs);
	if (ret)
		goto free_signal_stack;

	/*
	 * We want user to return to inject_handler_trampoline so
	 * create fake kernel frame in user's chain stack
	 */
	from = (regs->sys_num == __NR_sigreturn) ?
			FROM_PV_VCPU_SYS_SIGRETURN_INJECT :
					FROM_PV_VCPU_SYSCALL_INJECT;
	ret = prepare_pv_vcpu_inject_handler_trampoline(vcpu, regs,
					&regs->g_stacks, from, true);
	if (ret)
		goto free_signal_stack;

	/*
	 * guest's trap handler frame should be the last in stacks
	 */
	ret = prepare_pv_vcpu_syscall_handler_frame(vcpu, regs);
	if (ret)
		goto free_signal_stack;

	/*
	 * Set copy of kernel & host global regs ti initial state:
	 *      kernel gregs is zeroed
	 *      host VCPU state greg is inited by pointer to the VCPU
	 * interface with guest
	 */
	INIT_HOST_GREGS_COPY(current_thread_info(), vcpu);

	return 0;

free_signal_stack:
	pop_signal_stack();

	return ret;
}

static void insert_pv_vcpu_syscall(struct kvm_vcpu *vcpu, pt_regs_t *regs)
{
	int failed;

	save_pv_vcpu_sys_call_stack_regs(vcpu, regs);

	failed = setup_pv_vcpu_syscall(vcpu, regs);

	if (!failed) {
#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
		if (regs->trap && regs->trap->rp) {
			pr_err("%s(): binary compliler support is not yet impleneted for trap in generations mode\n",
			       __func__);
			E2K_KVM_BUG_ON(true);
		}
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */
	} else {
		pr_err("%s(): kill guest: setup syscall failed, error %d\n",
		       __func__, failed);
		do_exit(SIGKILL);
	}

}

void host_pv_vcpu_syscall_intc(thread_info_t *ti, pt_regs_t *regs)
{
	struct kvm_vcpu *vcpu = ti->vcpu;
	unsigned long mmu_pid;

	/* replace stacks->top value with real register SBR state */
	regs->stacks.top = regs->g_stacks.top;

	pv_vcpu_check_trap_in_fast_syscall(vcpu, regs);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);

	mmu_pid = current->mm->context.cpumsk[smp_processor_id()];
	trace_kvm_switch_to_host_mmu_pid(vcpu, current->mm, mmu_pid,
					 syscall_sw_to_host);

	insert_pv_vcpu_syscall(vcpu, regs);
}

static inline unsigned long
kvm_get_host_guest_glob_regs(struct kvm_vcpu *vcpu,
			     unsigned long **g_gregs,
			     unsigned long not_get_gregs_mask,
			     bool dirty_bgr,
			     unsigned int *bgr)
{
	e2k_global_regs_t gregs;
	unsigned long ret = 0;

	preempt_disable();	/* to save on one CPU */
	machine.save_gregs_on_mask(&gregs, dirty_bgr, not_get_gregs_mask);
	preempt_enable();

	if (copy_to_user_with_tags(g_gregs, gregs.g, sizeof(gregs.g))) {
		pr_err("%s(): could not copy global registers to user\n",
		       __func__);
		ret = -EFAULT;
	}
	if (bgr != NULL) {
		if (put_user(AW(gregs.bgr), bgr)) {
			pr_err("%s(): could not copy BGR register to user\n",
			       __func__);
			ret = -EFAULT;
		}
	}

	copy_k_gregs_to_gregs(&gregs, &current_thread_info()->k_gregs);

	if (ret == 0) {
		DebugGREGS("get %ld global registers of guest\n",
			   sizeof(gregs.g) / sizeof(*gregs.g));
	}
	return ret;
}

unsigned long
kvm_get_guest_glob_regs(struct kvm_vcpu *vcpu,
			unsigned long *g_gregs[2],
			unsigned long not_get_gregs_mask,
			bool dirty_bgr,
			unsigned int *bgr)
{
	hva_t hva, bgr_hva;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) g_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	if (bgr != NULL) {
		bgr_hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) bgr, true, &exception);
		if (kvm_is_error_hva(bgr_hva)) {
			DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
				bgr);
			kvm_vcpu_inject_page_fault(vcpu, (void *)bgr, &exception);
			return -EAGAIN;
		}
	} else {
		bgr_hva = 0;
	}
	return kvm_get_host_guest_glob_regs(vcpu, (void __user *)hva,
			not_get_gregs_mask, dirty_bgr, (void __user *)bgr_hva);
}

static inline int
copy_gregs_to_guest_gregs(__user unsigned long *g_gregs[2], struct e2k_greg *gregs, int gregs_size)
{
	if (copy_to_user_with_tags(g_gregs, gregs, gregs_size)) {
		DebugKVM("could not copy global registers used by kernel to user\n");
		return -EFAULT;
	}
	return 0;
}

static inline int
copy_k_gregs_to_guest_gregs(__user unsigned long *g_gregs[2], e2k_global_regs_t *k_gregs)
{
	kernel_gregs_t *kerne_gregs;

	return copy_gregs_to_guest_gregs(&g_gregs[KERNEL_GREGS_PAIRS_START],
					 &k_gregs->g[KERNEL_GREGS_PAIRS_START],
					 sizeof(kerne_gregs->g));
}

static inline int
copy_kernel_gregs_to_guest_gregs(__user unsigned long *g_gregs[2],
				 kernel_gregs_t *k_gregs)
{
	return copy_gregs_to_guest_gregs(&g_gregs[KERNEL_GREGS_PAIRS_START],
					 k_gregs->g, sizeof(k_gregs->g));
}

static inline int
copy_local_gregs_to_guest_l_gregs(__user unsigned long *g_l_gregs[2],
				  local_gregs_t *k_l_gregs)
{
	if (copy_to_user_with_tags(g_l_gregs, k_l_gregs, sizeof(*k_l_gregs))) {
		DebugKVM("could not copy local global registers to user\n");
		return -EFAULT;
	}
	return 0;
}

static inline void
copy_guest_k_gregs_to_guest_gregs(e2k_global_regs_t *g_gregs,
				  kernel_gregs_t *k_gregs)
{
	kernel_gregs_t *kernel_gregs;

	tagged_memcpy_8(&g_gregs->g[KERNEL_GREGS_PAIRS_START],
			&k_gregs->g[CURRENT_GREGS_PAIRS_INDEX_LO],
			sizeof(kernel_gregs->g));
}

static int copy_k_gregs_from_sig_context(kernel_gregs_t *k_gregs,
					 struct signal_stack_context __user *context)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = raw_copy_from_user_with_tags(k_gregs, &context->l_gregs, sizeof(*k_gregs));
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static int copy_k_gregs_to_sig_context(struct signal_stack_context __user *context,
					kernel_gregs_t *k_gregs)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = raw_copy_to_user_with_tags(&context->l_gregs, k_gregs, sizeof(*k_gregs));
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static int copy_local_gregs_from_sig_context(local_gregs_t *l_gregs,
				      struct signal_stack_context __user *context)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = raw_copy_from_user_with_tags(l_gregs, &context->l_gregs, sizeof(*l_gregs));
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static int copy_local_gregs_to_sig_context(struct signal_stack_context __user *context,
					   local_gregs_t *l_gregs)
{
	unsigned long ts_flag;
	int ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = raw_copy_to_user_with_tags(&context->l_gregs, l_gregs,
				       sizeof(*l_gregs));
	clear_ts_flag(ts_flag);

	return (ret) ? -EFAULT : 0;
}

static int kvm_get_updated_guest_local_glob_regs(struct kvm_vcpu *vcpu,
						 struct signal_stack_context __user *context,
						 local_gregs_t *k_l_gregs)
{
	kernel_gregs_t *k_gregs;
	int ret;

	/* only "kernel" user local global registers can be at context */
	k_gregs = (kernel_gregs_t *) k_l_gregs;
	ret = copy_k_gregs_from_sig_context(k_gregs, context);
	if (ret)
		return ret;

	/* other locals should be on real hardware registers */
	preempt_disable();	/* to save on one CPU */
	machine.save_local_gregs(k_l_gregs, true);
	preempt_enable();

	/* update all guest local gregs which may be as targets of page faults */
	update_pv_vcpu_local_glob_regs(vcpu, k_l_gregs);

	return ret;
}

static int kvm_save_updated_guest_local_glob_regs(struct kvm_vcpu *vcpu,
						  inject_caller_t from)
{
	struct signal_stack_context __user *context;
	local_gregs_t k_l_gregs;
	kernel_gregs_t *k_gregs;
	int ret;

	context = get_signal_stack();
	if (likely(!is_actual_pv_vcpu_l_gregs(vcpu)))
		/* nothing to update and save at context local gregs */
		return 0;

	E2K_KVM_BUG_ON(context == NULL);

	ret = kvm_get_updated_guest_local_glob_regs(vcpu, context, &k_l_gregs);
	if (ret != 0)
		return ret;

	/* save updated "kernel" user local global registers */
	/* at current context */
	k_gregs = (kernel_gregs_t *) & k_l_gregs;
	ret = copy_k_gregs_to_sig_context(context, k_gregs);

	/* restore other locals on real hardware registers */
	preempt_disable();	/* to save on one CPU */
	machine.restore_local_gregs(&k_l_gregs, true);
	preempt_enable();

	E2K_KVM_BUG_ON(is_actual_pv_vcpu_l_gregs(vcpu));

	trace_pv_save_l_gregs(vcpu, from, &k_l_gregs);

	return ret;
}

unsigned long
kvm_get_guest_local_glob_regs(struct kvm_vcpu *vcpu,
			      unsigned long *u_l_gregs[2],
			      bool is_signal)
{
	thread_info_t *ti = current_thread_info();
	struct signal_stack_context __user *context = NULL;
	local_gregs_t k_l_gregs;
	unsigned long **l_gregs = u_l_gregs;
	hva_t hva;
	kvm_arch_exception_t exception;
	int ret;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) l_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			l_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)l_gregs, &exception);
		return -EAGAIN;
	}

	l_gregs = (void *)hva;

	context = get_signal_stack();
	ret = kvm_get_updated_guest_local_glob_regs(vcpu, context, &k_l_gregs);
	if (ret != 0)
		return ret;

	if (likely(context != NULL)) {
		/* all user local global registers should be saved at context */
		ret = copy_local_gregs_to_sig_context(context, &k_l_gregs);
		if (ret)
			return ret;
	} else {
		/* only "kernel" user local global registers can be at context */
		/* other locals should be on real hardware registers */
		E2K_KVM_BUG_ON(is_signal);
		copy_k_gregs_to_l_gregs(&k_l_gregs, &ti->k_gregs);

		preempt_disable();	/* to save on one CPU */
		k_l_gregs.bgr = native_read_BGR_reg();
		machine.save_local_gregs(&k_l_gregs, true);
		preempt_enable();
	}

	E2K_KVM_BUG_ON(is_actual_pv_vcpu_l_gregs(vcpu));

	trace_pv_save_l_gregs(vcpu, FROM_PV_VCPU_SIGNAL_INJECT, &k_l_gregs);

	return copy_local_gregs_to_guest_l_gregs(l_gregs, &k_l_gregs);
}

int kvm_get_all_guest_glob_regs(struct kvm_vcpu *vcpu,
				unsigned long *g_gregs[2])
{
	thread_info_t *ti = current_thread_info();
	unsigned long **gregs = g_gregs;
	hva_t hva;
	int ret;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	gregs = (void *)hva;
	ret = kvm_get_host_guest_glob_regs(vcpu, gregs, GUEST_GREGS_MASK, true,	/* dirty BGR */
					   NULL);
	if (ret)
		return ret;
	ret = copy_kernel_gregs_to_guest_gregs(gregs, &ti->k_gregs);
	return ret;
}

unsigned long
kvm_set_guest_glob_regs(struct kvm_vcpu *vcpu,
			unsigned long *g_gregs[2],
			unsigned long not_set_gregs_mask, bool dirty_bgr,
			unsigned int *bgr)
{
	e2k_global_regs_t gregs;
	hva_t hva, bgr_hva;
	unsigned long ret = 0;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) g_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	if (copy_from_user(gregs.g, (void __user *)hva, sizeof(gregs.g))) {
		DebugKVM("could not copy global registers base from user\n");
		ret = -EFAULT;
	}

	bgr_hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) bgr, true, &exception);
	if (kvm_is_error_hva(bgr_hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			bgr);
		kvm_vcpu_inject_page_fault(vcpu, (void *)bgr, &exception);
		return -EAGAIN;
	}

	if (get_user(AW(gregs.bgr), (u32 __user *)bgr_hva)) {
		DebugKVM("could not copy BGR registers from user\n");
		ret = -EFAULT;
	}
	get_k_gregs_from_gregs(&current_thread_info()->k_gregs, &gregs);

	preempt_disable();	/* to restore on one CPU */
	if (ret == 0) {
		if (!dirty_bgr) {
			gregs.bgr = native_read_BGR_reg();
		}
		machine.restore_gregs_on_mask(&gregs, dirty_bgr, not_set_gregs_mask);
		DebugKVM("set %ld global registers of guest\n",
			 sizeof(gregs.g) / sizeof(*gregs.g));
	}
	preempt_enable();

	return ret;
}

static inline void
copy_k_gregs_from_guest_gregs(kernel_gregs_t *k_gregs, e2k_global_regs_t *g_gregs)
{
	kernel_gregs_t *kernel_gregs;

	tagged_memcpy_8(&k_gregs->g[CURRENT_GREGS_PAIRS_INDEX_LO],
			&g_gregs->g[KERNEL_GREGS_PAIRS_START],
			sizeof(kernel_gregs->g));
}

static inline void
copy_local_gregs_from_guest_gregs(e2k_global_regs_t *l_gregs,
				  e2k_global_regs_t *g_gregs)
{
	local_gregs_t *local_gregs;

	tagged_memcpy_8(&l_gregs->g[LOCAL_GREGS_START],
			&g_gregs->g[LOCAL_GREGS_START], sizeof(local_gregs->g));
}

static inline int
copy_guest_local_gregs_to_l_gregs(local_gregs_t *k_l_gregs,
				  __user unsigned long *u_l_gregs[2])
{
	if (copy_from_user_with_tags(k_l_gregs, u_l_gregs, sizeof(*k_l_gregs))) {
		DebugKVM("could not copy local global registers from user\n");
		return -EFAULT;
	}
	return 0;
}

int kvm_copy_guest_all_glob_regs(struct kvm_vcpu *vcpu,
				 e2k_global_regs_t *h_gregs,
				 unsigned long *g_gregs)
{
	hva_t hva;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) g_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		pr_err("%s(): failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			__func__, g_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)g_gregs, &exception);
		return -EAGAIN;
	}

	g_gregs = (void *)hva;
	if (copy_from_user_with_tags(h_gregs->g, g_gregs, sizeof(h_gregs->g))) {
		pr_err("%s(); could not copy global registers from user\n",
		       __func__);
		return -EFAULT;
	}

	return 0;
}

unsigned long
kvm_set_guest_local_glob_regs(struct kvm_vcpu *vcpu,
			      unsigned long *u_l_gregs[2],
			      bool is_signal)
{
	thread_info_t *ti = current_thread_info();
	struct signal_stack_context __user *context = NULL;
	local_gregs_t k_l_gregs;
	unsigned long **l_gregs = u_l_gregs;
	hva_t hva;
	int ret;
	kvm_arch_exception_t exception;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) l_gregs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n",
			l_gregs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)l_gregs, &exception);
		return -EAGAIN;
	}

	l_gregs = (void *)hva;
	ret = copy_guest_local_gregs_to_l_gregs(&k_l_gregs, l_gregs);
	if (ret != 0)
		return ret;

	context = get_signal_stack();
	if (likely(context != NULL && !is_signal)) {
		local_gregs_t gregs;
		int r;

		copy_local_gregs_from_sig_context(&gregs, context);
		for (r = 0; r < sizeof(gregs.g) / sizeof(gregs.g[0].xreg); r++) {
			if (k_l_gregs.g[r].base != gregs.g[r].base) {
				pr_err("   dg%d updated from %016llx to %016llx\n",
					r, k_l_gregs.g[r].base, gregs.g[r].base);
				gregs.g[r].base = k_l_gregs.g[r].base;
			}
		}
	} else if (context != NULL && is_signal) {
		ret = copy_local_gregs_to_sig_context(context, &k_l_gregs);
		if (ret)
			return ret;
	}

	if (likely(context != NULL && !is_signal)) {
		kernel_gregs_t *k_gregs = (kernel_gregs_t *)&k_l_gregs;

		/* only "kernel" user local global registers can be at context */
		/* but registers state saved at context should not be updated */
		ret = copy_k_gregs_to_sig_context(context, k_gregs);
		if (ret)
			return ret;
	} else if (context == NULL) {
		E2K_KVM_BUG_ON(is_signal);
		get_k_gregs_from_l_regs(&ti->k_gregs, &k_l_gregs);
	}

	preempt_disable();	/* to restore on one CPU */
	k_l_gregs.bgr = native_read_BGR_reg();
	machine.restore_local_gregs(&k_l_gregs, is_signal);
	preempt_enable();

	trace_pv_restore_l_gregs(vcpu, FROM_PV_VCPU_SIGNAL_RETURN, &k_l_gregs);

	return 0;
}

void kvm_guest_vcpu_relax(void)
{
	yield();		/* to activate other VCPU waiting for real CPU */
}

int kvm_update_hw_stacks_frames(struct kvm_vcpu *vcpu,
				e2k_mem_crs_t *u_pcs_frame,
				int pcs_frame_ind,
				kernel_mem_ps_t *u_ps_frame,
				int ps_frame_ind, int ps_frame_size)
{
	kernel_mem_ps_t ps_frame[KVM_MAX_PS_FRAME_NUM_TO_UPDATE];
	e2k_mem_crs_t pcs_frame;
	e2k_mem_crs_t __user *u_pcs;
	e2k_cr0_t cr0;
	e2k_cr1_t cr1;
	e2k_mem_ps_t __user *u_ps;
	unsigned long flags;
	bool priv_guest;
	e2k_stacks_t *guest_stacks;
	hva_t hva;
	int ps_ind, pcs_ind;
	int frame;
	int ret;
	kvm_arch_exception_t exception;

	if ((pcs_frame_ind & E2K_ALIGN_PSTACK_TOP_MASK) != 0) {
		DebugKVM("chain stack frame ind 0x%x is not aligned\n",
			 pcs_frame_ind);
		return -EINVAL;
	}
	if (ps_frame_size > KVM_MAX_PS_FRAME_SIZE_TO_UPDATE ||
	    ((ps_frame_size & E2K_ALIGN_PSTACK_TOP_MASK) != 0)) {
		DebugKVM("procedure stack frame size 0x%x is too big or not aligned\n",
			ps_frame_size);
		return -EINVAL;
	}
	if ((ps_frame_ind & E2K_ALIGN_PSTACK_TOP_MASK) != 0) {
		DebugKVM("procedure stack frame ind 0x%x is not aligned\n",
			 ps_frame_ind);
		return -EINVAL;
	}
	/* hypercalls are running on own hardware stacks */
	guest_stacks = &vcpu->arch.guest_stacks.stacks;
	ps_ind = vcpu_psp_ind(vcpu, guest_stacks->psp);
	pcs_ind = vcpu_pcsp_ind(vcpu, guest_stacks->pcsp);
	if (pcs_frame_ind >= pcs_ind) {
		DebugKVM("chain stack frame ind 0x%x is out of current stack boundaries 0x%x\n",
			pcs_frame_ind, pcs_ind);
		return -EINVAL;
	}
	if (ps_frame_ind + ps_frame_size > ps_ind) {
		DebugKVM("procedure stack frame ind 0x%x and size 0x%x is out of current stack boundaries 0x%x\n",
			 ps_frame_ind, ps_frame_size, ps_ind);
		return -EINVAL;
	}
	ret = kvm_vcpu_copy_from_guest(vcpu, &pcs_frame, u_pcs_frame, sizeof(pcs_frame));
	if (unlikely(ret < 0)) {
		DebugKVM("copy chain stack frames from user failed, maybe retried\n");
		return ret;
	}
	ret = kvm_vcpu_copy_from_guest(vcpu, &ps_frame, u_ps_frame,
				       ps_frame_size);
	if (unlikely(ret < 0)) {
		DebugKVM("copy procedure stack frames from user failed, maybe retried\n");
		return ret;
	}

	/* hardware virtualized guest runs by GLAUNCH at privileged mode */
	priv_guest = vcpu->arch.is_hv;

	raw_all_irq_save(flags);

	/* hypercalls are running on own hardware stacks */

	hva = kvm_vcpu_gva_to_hva(vcpu, vcpu_psp_base(vcpu, guest_stacks->psp),
				  true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %llx GVA, inject page fault to guest\n",
			vcpu_psp_base(vcpu, guest_stacks->psp));
		kvm_vcpu_inject_page_fault(vcpu, (void *)vcpu_psp_base(vcpu, guest_stacks->psp),
					   &exception);
		ret = -EAGAIN;
		goto out_error;
	}
	u_ps = (e2k_mem_ps_t __user *) hva;

	hva = kvm_vcpu_gva_to_hva(vcpu, vcpu_pcsp_base(vcpu, guest_stacks->pcsp),
				  true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %llx GVA, inject page fault to guest\n",
			vcpu_pcsp_base(vcpu, guest_stacks->pcsp));
		kvm_vcpu_inject_page_fault(vcpu, (void *)vcpu_pcsp_base(vcpu, guest_stacks->pcsp),
					   &exception);
		ret = -EAGAIN;
		goto out_error;
	}
	u_pcs = (e2k_mem_crs_t __user *) hva;

	u_ps = &u_ps[ps_frame_ind / sizeof(*u_ps)];
	u_pcs = &u_pcs[pcs_frame_ind / sizeof(*u_pcs)];
	DebugKVMHSU("procedure stack frame to update: index 0x%x base %px\n"
		    "chain stack frame to update: index 0x%x base %px\n",
		    ps_frame_ind, u_ps, pcs_frame_ind, u_pcs);

	if (get_user(LO(cr1), &LO(u_pcs->cr1)) ||
	    get_user(HI(cr1), &HI(u_pcs->cr1))) {
		DebugKVM("failed to read PCS frame CR1 at HVA %px\n", u_pcs);
		ret = -EFAULT;
		goto out_error;
	}

	if (get_user(HI(cr0), &HI(u_pcs->cr0))) {
		DebugKVM("failed to read PCS frame at HVA %px\n", u_pcs);
		ret = -EFAULT;
		goto out_error;
	}

	if (cr1.pm && !priv_guest) {
		DebugKVM("try to update host kernel frame\n");
		ret = -EINVAL;
		goto out_error;
	}
	if (ps_frame_size > cr1.wbs * EXT_4_NR_SZ) {
		DebugKVM("try to update too big procedure frame\n");
		ret = -EINVAL;
		goto out_error;
	}

	/* FIXME: it need use kvm_vcpu_copy_/to_guest/from_guest() */
	/* functions to update guest hw stacks frames */

	/* now can update only IP field of chain stack registers */
	DebugKVMHSU("will update only CR0_hi IP from %llx to %llx\n",
		    get_cr0_ip(cr0), get_cr0_ip(pcs_frame.cr0));
	if (put_user(HI(pcs_frame.cr0), &HI(u_pcs->cr0))) {
		DebugKVM("failed to write PCS frame at HVA %px\n", u_pcs);
		ret = -EFAULT;
		goto out_error;
	}

	/* FIXME: tags are not copied */
	for (frame = 0; frame < ps_frame_size / EXT_4_NR_SZ; frame++) {
		if (machine.native_iset_ver < E2K_ISET_V5) {
			ret = put_user(ps_frame[frame].word_lo, &u_ps[frame].v3.word_lo);
			ret = ret ? : put_user(ps_frame[frame].word_hi, &u_ps[frame].v3.word_hi);
			/* Skip frame[2] and frame[3] - they hold */
			/* extended data not used by kernel */
		} else {
			ret = put_user(ps_frame[frame].word_lo, &u_ps[frame].v5.word_lo);
			ret = ret ? : put_user(ps_frame[frame].word_hi, &u_ps[frame].v5.word_hi);
			/* Skip frame[1] and frame[3] - they hold */
			/* extended data not used by kernel */
		}
		if (ret) {
			DebugKVM("failed to write PS frame at HVA %px\n", &u_ps[frame]);
			goto out_error;
		}
	}

	raw_all_irq_restore(flags);

	return 0;

out_error:
	raw_all_irq_restore(flags);
	return ret;
}

static int kvm_patch_guest_data_stack(struct kvm_vcpu *vcpu, kvm_data_stack_info_t *u_ds_patch)
{
	thread_info_t *ti = current_thread_info();
	gthread_info_t *gti = ti->gthread_info;
	kvm_data_stack_info_t ds_patch;
	int do_patch = 0;
	int ret = 0;

	ret = kvm_vcpu_copy_from_guest(vcpu, &ds_patch, u_ds_patch, sizeof(ds_patch));
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy dat stack pointers patch from user failed, maybe retried\n",
			__func__);
		return ret;
	}
	if (gti == NULL) {
		pr_err("%s(): process %s (%d) is not guest thread\n",
		       __func__, current->comm, current->pid);
		return -EINVAL;
	}
	DebugKVMHSP("host guest kernel data stack bottom 0x%lx top 0x%lx size 0x%lx\n",
		    gti->data_stack.bottom, gti->data_stack.top,
		    gti->data_stack.size);
	DebugKVMHSP("native user data stack bottom 0x%lx top 0x%lx size 0x%lx\n",
		    ti->u_stack.bottom, ti->u_stack.top, ti->u_stack.size);
	DebugKVMHSP("current guest kernel data stack top 0x%llx base 0x%llx size 0x%llx\n",
		    (u64) gti->stack_regs.stacks.u_top,
		    vcpu_usd_ptr(vcpu, gti->stack_regs.stacks.u_usd),
		    vcpu_usd_ind(vcpu, gti->stack_regs.stacks.u_usd));
	DebugKVMHSP("patched data stack: top 0x%lx base 0x%lx size 0x%lx\n",
		    ds_patch.top, ds_patch.usd_base, ds_patch.usd_size);
	if (ds_patch.protected) {
		pr_err("%s(): patching of protected data stacks is not yet implemented\n",
			__func__);
		return -EINVAL;
	}
	if (ds_patch.top < gti->data_stack.bottom || ds_patch.top > gti->data_stack.top) {
		DebugKVMHSP("top to patch is out of data stack bounderies\n");
		return -EINVAL;
	}
	if (ds_patch.usd_base < gti->data_stack.bottom || ds_patch.usd_base > gti->data_stack.top) {
		DebugKVMHSP("base to patch is out of data stack bounderies\n");
		return -EINVAL;
	}
	if (ds_patch.usd_base >= ds_patch.top) {
		DebugKVMHSP("base to patch is above of top to patch\n");
		return -EINVAL;
	}
	if (ds_patch.usd_base - ds_patch.usd_size < gti->data_stack.bottom) {
		DebugKVMHSP("base - size to patch is below of stack bottom\n");
		return -EINVAL;
	}
	if (ds_patch.top != gti->stack_regs.stacks.u_top) {
		DebugKVMHSP("will patch top (SBR) of guest kernel data stack from 0x%lx to 0x%lx\n",
			    gti->stack_regs.stacks.u_top, ds_patch.top);
		gti->stack_regs.stacks.u_top = ds_patch.top;
		do_patch = 1;
	}
	if (ds_patch.usd_base != vcpu_usd_ptr(vcpu, gti->stack_regs.stacks.u_usd)) {
		DebugKVMHSP("will patch base of guest kernel data stack from 0x%llx to 0x%lx\n",
			    vcpu_usd_ptr(vcpu, gti->stack_regs.stacks.u_usd),
			    ds_patch.usd_base);
		do_patch = 1;
	}
	if (ds_patch.usd_size != vcpu_usd_ind(vcpu, gti->stack_regs.stacks.u_usd)) {
		DebugKVMHSP("will patch size of guest kernel data stack from 0x%llx to 0x%lx\n",
			    vcpu_usd_ptr(vcpu, gti->stack_regs.stacks.u_usd),
			    ds_patch.usd_size);
		do_patch = 1;
	}
	if (do_patch) {
		gti->stack_regs.stacks.u_usd =
			vcpu_new_usd(vcpu,
				ds_patch.usd_base -  ds_patch.usd_size,
				ds_patch.top - ds_patch.usd_base + ds_patch.usd_size,
				ds_patch.usd_size);
	}
	return ret;
}

static int kvm_patch_guest_chain_stack(struct kvm_vcpu *vcpu,
				__user kvm_pcs_patch_info_t u_pcs_patch[],
				int pcs_frames)
{
	kvm_pcs_patch_info_t pcs_patch[KVM_MAX_PCS_FRAME_NUM_TO_PATCH];
	kvm_pcs_patch_info_t *patch;
	e2k_mem_crs_t *pcs, *frame;
	e2k_stacks_t *guest_stacks;
	e2k_addr_t pcs_base;
	hva_t hva;
	e2k_size_t pcs_ind, pcs_size, pcshtop;
	bool priv_guest;
	unsigned long flags;
	int fr_no;
	int ret = 0;
	kvm_arch_exception_t exception;

	if (pcs_frames > KVM_MAX_PCS_FRAME_NUM_TO_PATCH || pcs_frames < 0) {
		pr_err("%s(): PCS frames number %d is too big, can only %d\n",
		       __func__, pcs_frames, KVM_MAX_PCS_FRAME_NUM_TO_PATCH);
		return -EINVAL;
	}
	ret = kvm_vcpu_copy_from_guest(vcpu, pcs_patch, u_pcs_patch,
				       sizeof(pcs_patch[0]) * pcs_frames);
	if (unlikely(ret < 0)) {
		pr_err("%s(): copy chain stack frames patch from user failed, maybe retried\n",
			__func__);
		return ret;
	}

	/* hardware virtualized guest runs by GLAUNCH at privileged mode */
	priv_guest = vcpu->arch.is_hv;

	raw_all_irq_save(flags);

	/* FIXME: disable stack boundaries traps to exclude resident window */
	/* change, because now is implemented patch only frames into */
	/* the resident window */
	//TODO is this needed now ??? native_reset_sge();

	guest_stacks = &vcpu->arch.guest_stacks.stacks;
	pcs_base = vcpu_pcsp_base(vcpu, guest_stacks->pcsp);
	pcs_ind = vcpu_pcsp_ind(vcpu, guest_stacks->pcsp);
	pcs_size = vcpu_pcsp_size(vcpu, guest_stacks->pcsp);
	pcshtop = 0;

	pcs = (e2k_mem_crs_t *) pcs_base;

	hva = kvm_vcpu_gva_to_hva(vcpu, (gva_t) pcs, true, &exception);
	if (kvm_is_error_hva(hva)) {
		DebugKVM("failed to find GPA for dst %lx GVA, inject page fault to guest\n", pcs);
		kvm_vcpu_inject_page_fault(vcpu, (void *)pcs, &exception);
		ret = -EAGAIN;
		goto out_error;
	}

	pcs = (e2k_mem_crs_t *) hva;
	for (fr_no = 0; fr_no < pcs_frames; fr_no++) {
		patch = &pcs_patch[fr_no];
		DebugKVMHSP("PCS patch #%d will patch frame at ind 0x%x\n",
			    fr_no, patch->ind);
		if (patch->ind < 0 || patch->ind >= pcs_ind + pcshtop) {
			DebugKVMHSP("PCS frame ind 0x%x to patch is out of chain stack boundaries\n",
				patch->ind);
			ret = -EINVAL;
			goto out_error;
		}
		/* FIXME: patching of not resident part of chain stack */
		/* is not implemented */
		WARN_ONCE(1, "stacks are not resident anymore");
		if (patch->ind >= pcs_ind) {
			pr_err("%s(): patching of chain stack frame ind 0x%x up of current final frame ind 0x%lx\n",
			       __func__, patch->ind, pcs_ind);
			ret = -EINVAL;
			goto out_error;
		}
		frame = &pcs[patch->ind / sizeof(*pcs)];
		if (frame->cr1.pm && !priv_guest) {
			pr_err("%s(): try to patch host kernel frame\n",
			       __func__);
			ret = -EINVAL;
			goto out_error;
		}
		if (patch->update_flags == 0) {
			DebugKVMHSP("PCS frame ind 0x%x update flags empty\n",
				    patch->ind);
			continue;
		}
		if (patch->update_flags & KVM_PCS_IP_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch IP from 0x%llx to 0x%lx at PCS frame ind 0x%x\n",
				    get_cr0_ip(frame->cr0), patch->IP, patch->ind);
			set_cr0_ip(frame->cr0, patch->IP);
		}
		/* `ussz` field has full size since iset v7 so nothing to update there */
		if (!cpu_has(CPU_FEAT_V7_CPU_REGS) &&
		    (patch->update_flags & KVM_PCS_USSZ_UPDATE_FLAG)) {
			unsigned long ussz;

			DebugKVMHSP("wiil patch USD size from 0x%llx to 0x%llx at PCS frame ind 0x%llx\n",
				    get_cr1_ussz(frame->cr1),
				    (u64) patch->usd_size, (u64) patch->ind);
			ussz = (vcpu_descr_v7(vcpu)) ? 0 : patch->usd_size;
			frame->cr1 = vcpu_set_cr1_ussz(vcpu, frame->cr1, ussz);
		}
		if (patch->update_flags & KVM_PCS_WBS_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch wbs from 0x%x to 0x%x at PCS frame ind 0x%x\n",
				    frame->cr1.wbs, patch->wbs, patch->ind);
			frame->cr1.wbs = patch->wbs;
		}
		if (patch->update_flags & KVM_PCS_WPSZ_UPDATE_FLAG) {
			DebugKVMHSP("wiil patch wpsz from 0x%x to 0x%x at PCS frame ind 0x%x\n",
				    frame->cr1.wpsz, patch->wpsz, patch->ind);
			frame->cr1.wpsz = patch->wpsz;
		}
	}
	ret = 0;

out_error:

	/* FIXME: enabl stack boundaries traps to include resident window */
	/* change, because now is implemented patch only frames into */
	/* the resident window */
	//TODO needed?? native_set_sge();

	raw_all_irq_restore(flags);

	return ret;
}

int kvm_patch_guest_data_and_chain_stacks(struct kvm_vcpu *vcpu,
					  kvm_data_stack_info_t *u_ds_patch,
					  kvm_pcs_patch_info_t
					  u_pcs_patch[], int pcs_frames)
{
	int ret = 0;

	if (u_ds_patch != NULL)
		ret = kvm_patch_guest_data_stack(vcpu, u_ds_patch);
	if (ret != 0)
		return ret;
	if (u_pcs_patch != NULL && pcs_frames != 0)
		ret = kvm_patch_guest_chain_stack(vcpu, u_pcs_patch, pcs_frames);
	return ret;
}

void kvm_switch_debug_regs(struct kvm_sw_cpu_context *sw_ctxt, int is_active)
{
	u64 b_dimar0, b_dimar1, b_dimar2, b_dimar3, b_ddmar0, b_ddmar1, b_ddmar2 = 0,
	    b_ddmar3 = 0, b_dibar0, b_dibar1, b_dibar2, b_dibar3, b_ddbar0, b_ddbar1,
	    b_ddbar2 = 0, b_ddbar3 = 0, a_dimar0, a_dimar1, a_dimar2, a_dimar3, a_ddmar0,
	    a_ddmar1, a_ddmar2 = 0, a_ddmar3 = 0, a_dibar0, a_dibar1, a_dibar2, a_dibar3,
	    a_ddbar0, a_ddbar1, a_ddbar2, a_ddbar3;
	e2k_dimcr_t b_dimcr, b_dimcr1, a_dimcr, a_dimcr1;
	e2k_ddmcr_t b_ddmcr, b_ddmcr1, a_ddmcr, a_ddmcr1;
	e2k_dibcr_t b_dibcr, a_dibcr;
	e2k_dibsr_t b_dibsr, a_dibsr;
	e2k_ddbcr_t b_ddbcr, a_ddbcr;
	e2k_ddbsr_t b_ddbsr, a_ddbsr;
	e2k_dimtp_t b_dimtp, a_dimtp;

	b_dibcr = sw_ctxt->dibcr;
	b_ddbcr = sw_ctxt->ddbcr;
	b_dibsr = sw_ctxt->dibsr;
	b_ddbsr = sw_ctxt->ddbsr;
	b_dimcr = sw_ctxt->dimcr;
	b_ddmcr = sw_ctxt->ddmcr;
	b_dibar0 = sw_ctxt->dibar[0];
	b_dibar1 = sw_ctxt->dibar[1];
	b_dibar2 = sw_ctxt->dibar[2];
	b_dibar3 = sw_ctxt->dibar[3];
	b_ddbar0 = sw_ctxt->ddbar[0];
	b_ddbar1 = sw_ctxt->ddbar[1];
	b_ddbar2 = sw_ctxt->ddbar[2];
	b_ddbar3 = sw_ctxt->ddbar[3];
	b_dimar0 = sw_ctxt->dimar[0];
	b_dimar1 = sw_ctxt->dimar[1];
	b_ddmar0 = sw_ctxt->ddmar[0];
	b_ddmar1 = sw_ctxt->ddmar[1];
	b_dimtp = sw_ctxt->dimtp;

	if (cpu_has(CPU_FEAT_ISET_V7)) {
		b_ddmcr1 = sw_ctxt->ddmcr1;
		b_ddmar2 = sw_ctxt->ddmar[2];
		b_ddmar3 = sw_ctxt->ddmar[3];

		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			b_dimcr1 = sw_ctxt->dimcr1;
			b_dimar2 = sw_ctxt->dimar[2];
			b_dimar3 = sw_ctxt->dimar[3];
		}

		a_ddmcr1 = NATIVE_READ_DDMCR1_REG();
		a_ddmar2 = NATIVE_READ_DDMAR2_REG_VALUE();
		a_ddmar3 = NATIVE_READ_DDMAR3_REG_VALUE();

		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			a_dimcr1 = native_read_DIMCR1_reg();
			a_dimar2 = native_read_DIMAR2_reg_value();
			a_dimar3 = native_read_DIMAR3_reg_value();
		}
	}

	a_dibcr = native_read_DIBCR_reg();
	a_ddbcr = NATIVE_READ_DDBCR_REG();
	a_dibsr = native_read_DIBSR_reg();
	a_ddbsr = NATIVE_READ_DDBSR_REG();
	a_dimcr = native_read_DIMCR_reg();
	a_ddmcr = NATIVE_READ_DDMCR_REG();
	a_dibar0 = native_read_DIBAR0_reg_value();
	a_dibar1 = native_read_DIBAR1_reg_value();
	a_dibar2 = native_read_DIBAR2_reg_value();
	a_dibar3 = native_read_DIBAR3_reg_value();
	a_ddbar0 = NATIVE_READ_DDBAR0_REG_VALUE();
	a_ddbar1 = NATIVE_READ_DDBAR1_REG_VALUE();
	a_ddbar2 = NATIVE_READ_DDBAR2_REG_VALUE();
	a_ddbar3 = NATIVE_READ_DDBAR3_REG_VALUE();
	a_ddmar0 = NATIVE_READ_DDMAR0_REG_VALUE();
	a_ddmar1 = NATIVE_READ_DDMAR1_REG_VALUE();
	a_dimar0 = native_read_DIMAR0_reg_value();
	a_dimar1 = native_read_DIMAR1_reg_value();
	a_dimtp = native_read_DIMTP_reg();

	if (is_active) {
		/* These two must be written first to disable monitoring */
		native_write_DIBCR_reg(b_dibcr);
		NATIVE_WRITE_DDBCR_REG(b_ddbcr);
	}
	native_write_DIBAR0_reg_value(b_dibar0);
	native_write_DIBAR1_reg_value(b_dibar1);
	native_write_DIBAR2_reg_value(b_dibar2);
	native_write_DIBAR3_reg_value(b_dibar3);
	NATIVE_WRITE_DDBAR0_REG_VALUE(b_ddbar0);
	NATIVE_WRITE_DDBAR1_REG_VALUE(b_ddbar1);
	NATIVE_WRITE_DDBAR2_REG_VALUE(b_ddbar2);
	NATIVE_WRITE_DDBAR3_REG_VALUE(b_ddbar3);
	NATIVE_WRITE_DDMAR0_REG_VALUE(b_ddmar0);
	NATIVE_WRITE_DDMAR1_REG_VALUE(b_ddmar1);
	native_write_DIMAR0_reg_value(b_dimar0);
	native_write_DIMAR1_reg_value(b_dimar1);
	native_write_DIBSR_reg(b_dibsr);
	NATIVE_WRITE_DDBSR_REG(b_ddbsr);
	native_write_DIMCR_reg(b_dimcr);
	NATIVE_WRITE_DDMCR_REG(b_ddmcr);
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		NATIVE_WRITE_DDMAR2_REG_VALUE(b_ddmar2);
		NATIVE_WRITE_DDMAR3_REG_VALUE(b_ddmar3);
		NATIVE_WRITE_DDMCR1_REG(b_ddmcr1);
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			native_write_DIMAR2_reg_value(b_dimar2);
			native_write_DIMAR3_reg_value(b_dimar3);
			native_write_DIMCR1_reg(b_dimcr1);
		}
	}
	native_write_DIMTP_reg(b_dimtp);
	if (!is_active) {
		/* These two must be written last to enable monitoring */
		native_write_DIBCR_reg(b_dibcr);
		NATIVE_WRITE_DDBCR_REG(b_ddbcr);
	}

	sw_ctxt->dibcr = a_dibcr;
	sw_ctxt->ddbcr = a_ddbcr;
	sw_ctxt->dibsr = a_dibsr;
	sw_ctxt->ddbsr = a_ddbsr;
	sw_ctxt->dimcr = a_dimcr;
	sw_ctxt->ddmcr = a_ddmcr;
	sw_ctxt->dibar[0] = a_dibar0;
	sw_ctxt->dibar[1] = a_dibar1;
	sw_ctxt->dibar[2] = a_dibar2;
	sw_ctxt->dibar[3] = a_dibar3;
	sw_ctxt->ddbar[0] = a_ddbar0;
	sw_ctxt->ddbar[1] = a_ddbar1;
	sw_ctxt->ddbar[2] = a_ddbar2;
	sw_ctxt->ddbar[3] = a_ddbar3;
	sw_ctxt->ddmar[0] = a_ddmar0;
	sw_ctxt->ddmar[1] = a_ddmar1;
	sw_ctxt->dimar[0] = a_dimar0;
	sw_ctxt->dimar[1] = a_dimar1;
	sw_ctxt->dimtp = a_dimtp;
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		sw_ctxt->ddmcr1 = a_ddmcr1;
		sw_ctxt->ddmar[2] = a_ddmar2;
		sw_ctxt->ddmar[3] = a_ddmar3;
		if (!cpu_has(CPU_HWBUG_DIMCR1)) {
			sw_ctxt->dimcr1 = a_dimcr1;
			sw_ctxt->dimar[2] = a_dimar2;
			sw_ctxt->dimar[3] = a_dimar3;
		}
	}
}
