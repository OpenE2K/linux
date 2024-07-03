/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


/*
 * CPU hardware virtualized support
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 */

#include <linux/kvm_host.h>
#include <linux/kvm.h>
#include <linux/uaccess.h>
#include <linux/entry-kvm.h>
#include <asm/cpu_regs.h>
#include <asm/epic.h>
#include <asm/trace.h>
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
#include <asm/kvm/gregs.h>
#include "cpu_defs.h"
#include "cpu.h"
#include "mmu_defs.h"
#include "mmu.h"
#include "process.h"
#include "intercepts.h"
#include "io.h"
#include "pic.h"
#include "trace-tlb-flush.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE || kvm_debug)				\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE	0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
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

#undef	DEBUG_INTC_WAIT_TRAP_MODE
#undef	DebugWTR
#define	DEBUG_INTC_WAIT_TRAP_MODE	0	/* CU wait trap intercept */
#define	DebugWTR(fmt, args...)						\
({									\
	if (DEBUG_INTC_WAIT_TRAP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IT_MODE
#undef	DebugKVMIT
#define	DEBUG_KVM_IT_MODE	0	/* CEPIC idle timer */
#define	DebugKVMIT(fmt, args...)					\
({									\
	if (DEBUG_KVM_IT_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})
#undef	VM_BUG_ON
#define VM_BUG_ON(cond) BUG_ON(cond)


void prepare_bu_stacks_to_startup_vcpu(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup;
	vcpu_boot_stack_t *boot_stacks;
	e2k_mem_crs_t *pcs_frames;
	e2k_mem_ps_t *ps_frames;
	e2k_size_t ps_ind, pcs_ind;
	bool priv_guest = vcpu->arch.is_hv;
	e2k_psr_t psr;

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	prepare_vcpu_startup_args(vcpu);
	hypv_backup = &vcpu->arch.hypv_backup;
	boot_stacks = &vcpu->arch.boot_stacks;

	ps_frames = (e2k_mem_ps_t *)GET_BACKUP_PS_BASE(hypv_backup);
	VM_BUG_ON(ps_frames == NULL);
	pcs_frames = (e2k_mem_crs_t *)GET_BACKUP_PCS_BASE(hypv_backup);
	VM_BUG_ON(pcs_frames == NULL);

	if (priv_guest)
		psr = E2K_KERNEL_PSR_DISABLED_ALL;
	else
		psr = E2K_USER_INITIAL_PSR;
	prepare_stacks_to_startup_vcpu(vcpu, ps_frames, pcs_frames,
			vcpu->arch.args, vcpu->arch.args_num,
			vcpu->arch.entry_point, psr,
			GET_VCPU_BOOT_CS_SIZE(boot_stacks),
			&ps_ind, &pcs_ind, 0, 1);

	/* correct stacks pointers indexes */
	hypv_backup->psp_hi.PSP_hi_ind = ps_ind;
	hypv_backup->pcsp_hi.PCSP_hi_ind = pcs_ind;
	DebugKVMSTUP("backup PS.ind 0x%x PCS.ind 0x%x\n",
		hypv_backup->psp_hi.PSP_hi_ind,
		hypv_backup->pcsp_hi.PCSP_hi_ind);
}

void init_hv_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	e2k_tir_hi_t TIR_hi;
	e2k_tir_lo_t TIR_lo;

	/* Initialize empty TIRs before first GLAUNCH to avoid showing host's
	 * IP to guest */
	TIR_lo.TIR_lo_reg = GET_CLEAR_TIR_LO(1);
	TIR_hi.TIR_hi_reg = GET_CLEAR_TIR_HI(1);
	kvm_clear_vcpu_intc_TIRs_num(vcpu);
	kvm_update_vcpu_intc_TIR(vcpu, 1, TIR_hi, TIR_lo);

	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;

	/* Clean INTC_INFO_CU/MU before first GLAUNCH */
	kvm_set_intc_info_mu_is_updated(vcpu);
	kvm_set_intc_info_cu_is_updated(vcpu);
}

void kvm_reset_mmu_intc_mode(struct kvm_vcpu *vcpu)
{
	e2k_mmu_cr_t sh_mmu_cr;
	mmu_reg_t sh_pid;

	sh_mmu_cr = vcpu->arch.mmu.init_sh_mmu_cr;
	sh_pid = vcpu->arch.mmu.init_sh_pid;
	E2K_KVM_BUG_ON(sh_pid != 0);
	E2K_KVM_BUG_ON(AW(sh_mmu_cr) != AW(MMU_CR_KERNEL_OFF));
	vcpu_write_SH_MMU_CR_reg(vcpu, sh_mmu_cr);
}

void kvm_setup_mmu_intc_mode(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	virt_ctrl_mu_t mu;
	mmu_reg_t sh_pid;
	e2k_mmu_cr_t sh_mmu_cr, g_w_imask_mmu_cr;

	/* MMU interception control registers state */
	mu.VIRT_CTRL_MU_reg = 0;
	AW(g_w_imask_mmu_cr) = 0;

	if (kvm_is_tdp_enable(kvm)) {
		mu.sh_pt_en = 0;
	} else if (kvm_is_shadow_pt_enable(kvm)) {
		mu.sh_pt_en = 1;
	} else {
		E2K_KVM_BUG_ON(true);
	}

	if (kvm_is_phys_pt_enable(kvm))
		mu.gp_pt_en = 1;

	/* Guest should not be able to write special MMU/AAU */
	mu.rw_dbg1 = 1;

	if (vcpu->arch.is_hv) {
		if (kvm_is_tdp_enable(kvm)) {
			/* intercept only MMU_CR updates to track */
			/* paging enable/disable */
			mu.rw_mmu_cr = 0;
			g_w_imask_mmu_cr.tlb_en = 1;
		} else if (kvm_is_shadow_pt_enable(kvm)) {
			/* intercept all read/write MMU CR */
			/* and Page Table Base */
			mu.rr_mmu_cr = 1;
			mu.rr_pptb = 1;
			mu.rr_vptb = 1;
			mu.rw_mmu_cr = 1;
			mu.rw_pptb = 1;
			mu.rw_vptb = 1;
			mu.fl_tlbpg = 1;
			mu.fl_tlb2pg = 1;
			g_w_imask_mmu_cr.tlb_en = 1;
		} else {
			E2K_KVM_BUG_ON(true);
		}
	}
	vcpu->arch.mmu.virt_ctrl_mu = mu;
	vcpu->arch.mmu.g_w_imask_mmu_cr = g_w_imask_mmu_cr;


	/* MMU shadow registers initial state */
	if (vcpu->arch.is_hv || vcpu->arch.is_pv) {
		sh_mmu_cr = MMU_CR_KERNEL_OFF;
		sh_pid = 0;	/* guest kernel should have PID == 0 */
	} else {
		E2K_KVM_BUG_ON(true);
	}
	vcpu->arch.mmu.init_sh_mmu_cr = sh_mmu_cr;
	vcpu->arch.mmu.init_sh_pid = sh_pid;
}

void init_backup_hw_ctxt(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup;
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

	if (!vcpu->arch.is_hv) {
		/* there is not support of hardware virtualizsation */
		return;
	}

	/*
	 * Stack registers
	 */
	hypv_backup = &vcpu->arch.hypv_backup;
	hw_ctxt->bu_psp_lo = hypv_backup->psp_lo;
	hw_ctxt->bu_psp_hi = hypv_backup->psp_hi;
	hw_ctxt->bu_pcsp_lo = hypv_backup->pcsp_lo;
	hw_ctxt->bu_pcsp_hi = hypv_backup->pcsp_hi;

	/* set backup stacks to empty state will be done by hardware after */
	/* GLAUNCH, so update software pointers at hypv_backup structure */
	/* for following GLAUNCHes and paravirtualization HCALL emulation */
	hypv_backup->psp_hi.PSP_hi_ind = 0;
	hypv_backup->pcsp_hi.PCSP_hi_ind = 0;
}

void kvm_hv_update_guest_stacks_registers(struct kvm_vcpu *vcpu,
					guest_hw_stack_t *stack_regs)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_sw_cpu_context *sw_ctxt = &vcpu->arch.sw_ctxt;

	/*
	 * Guest Stack state is now on back UP registers
	 */
	hw_ctxt->sh_psp_lo = stack_regs->stacks.psp_lo;
	hw_ctxt->sh_psp_hi = stack_regs->stacks.psp_hi;
	hw_ctxt->sh_pcsp_lo = stack_regs->stacks.pcsp_lo;
	hw_ctxt->sh_pcsp_hi = stack_regs->stacks.pcsp_hi;

	WRITE_BU_PSP_LO_REG_VALUE(AW(hw_ctxt->sh_psp_lo));
	WRITE_BU_PSP_HI_REG_VALUE(AW(hw_ctxt->sh_psp_hi));
	WRITE_BU_PCSP_LO_REG_VALUE(AW(hw_ctxt->sh_pcsp_lo));
	WRITE_BU_PCSP_HI_REG_VALUE(AW(hw_ctxt->sh_pcsp_hi));

	sw_ctxt->crs.cr0_lo = stack_regs->crs.cr0_lo;
	sw_ctxt->crs.cr0_hi = stack_regs->crs.cr0_hi;
	sw_ctxt->crs.cr1_lo = stack_regs->crs.cr1_lo;
	sw_ctxt->crs.cr1_hi = stack_regs->crs.cr1_hi;

	DebugSHC("update guest stacks registers:\n"
		"BU_PSP:  base 0x%llx size 0x%x index 0x%x\n"
		"BU_PCSP: base 0x%llx size 0x%x index 0x%x\n",
		stack_regs->stacks.psp_lo.PSP_lo_base,
		stack_regs->stacks.psp_hi.PSP_hi_size,
		stack_regs->stacks.psp_hi.PSP_hi_ind,
		stack_regs->stacks.pcsp_lo.PCSP_lo_base,
		stack_regs->stacks.pcsp_hi.PCSP_hi_size,
		stack_regs->stacks.pcsp_hi.PCSP_hi_ind);
}

static void kvm_dump_mmu_tdp_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	DebugSHC("Set MMU guest TDP PT context:\n");

	if (DEBUG_SHADOW_CONTEXT_MODE && (flags & GP_ROOT_PT_FLAG)) {
		pr_info("   GP_PPTB: value 0x%llx\n",
			mmu->get_vcpu_context_gp_pptb(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE &&
			((flags & U_ROOT_PT_FLAG) ||
				((flags & OS_ROOT_PT_FLAG) &&
					!is_sep_virt_spaces(vcpu)))) {
		pr_info("   U_PPTB:  value 0x%lx\n"
			"   U_VPTB:  value 0x%lx\n",
			mmu->get_vcpu_context_u_pptb(vcpu),
			mmu->get_vcpu_context_u_vptb(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE &&
			((flags & OS_ROOT_PT_FLAG) &&
					is_sep_virt_spaces(vcpu))) {
		pr_info("   OS_PPTB: value 0x%lx\n"
			"   OS_VPTB: value 0x%lx\n"
			"   OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		pr_info("   SH_PID:  value 0x%llx\n",
			read_guest_PID_reg(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && (flags & SEP_VIRT_ROOT_PT_FLAG)) {
		e2k_core_mode_t core_mode = read_guest_CORE_MODE_reg(vcpu);

		pr_info("   SH_CORE_MODE:  0x%x sep_virt_space: %s\n",
			core_mode.CORE_MODE_reg,
			(core_mode.CORE_MODE_sep_virt_space) ?
				"true" : "false");
	}
}

static void setup_mmu_tdp_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	/* setup MMU page tables hardware and software context */
	kvm_set_vcpu_the_pt_context(vcpu, flags);

	/* setup user PID on hardware shadow register */
	write_SH_PID_reg(vcpu->arch.mmu.pid);

	if ((flags & SEP_VIRT_ROOT_PT_FLAG) && vcpu->arch.is_pv) {
		e2k_core_mode_t core_mode = read_SH_CORE_MODE_reg();

		/* enable/disable guest separate Page Tables support */
		core_mode.CORE_MODE_sep_virt_space = is_sep_virt_spaces(vcpu);
		write_SH_CORE_MODE_reg(core_mode);
		vcpu->arch.hw_ctxt.sh_core_mode = core_mode;
	}

	kvm_dump_mmu_tdp_context(vcpu, flags);
}

void kvm_setup_mmu_tdp_u_pt_context(struct kvm_vcpu *vcpu)
{
	unsigned flags;

	if (vcpu->arch.mmu.u_context_on) {
		flags = U_ROOT_PT_FLAG;
	} else {
		flags = U_ROOT_PT_FLAG | OS_ROOT_PT_FLAG |
						SEP_VIRT_ROOT_PT_FLAG;
	}
	/* setup MMU page tables hardware and software context */
	setup_mmu_tdp_context(vcpu, flags);
}

void kvm_setup_mmu_tdp_context(struct kvm_vcpu *vcpu)
{
	/* setup MMU page tables hardware and software context */
	setup_mmu_tdp_context(vcpu,
		GP_ROOT_PT_FLAG | OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG |
			SEP_VIRT_ROOT_PT_FLAG);
}

void kvm_hv_setup_mmu_spt_context(struct kvm_vcpu *vcpu)
{
	e2k_core_mode_t core_mode = read_SH_CORE_MODE_reg();

	/* enable/disable guest separate Page Tables support */
	core_mode.CORE_MODE_sep_virt_space = is_sep_virt_spaces(vcpu);
	write_SH_CORE_MODE_reg(core_mode);
	vcpu->arch.hw_ctxt.sh_core_mode = core_mode;
}

void kvm_set_mmu_guest_pt(struct kvm_vcpu *vcpu)
{
	e2k_mmu_cr_t mmu_cr;

	if (is_tdp_paging(vcpu)) {
		kvm_setup_mmu_tdp_context(vcpu);
	} else if (is_shadow_paging(vcpu)) {
		kvm_setup_mmu_spt_context(vcpu);
	} else {
		E2K_KVM_BUG_ON(true);
	}

	/* enable TLB in paging mode */
	mmu_cr = MMU_CR_KERNEL;
	write_guest_MMU_CR_reg(vcpu, mmu_cr);
	DebugSHC("Enable guest MMU paging:\n"
		"   SH_MMU_CR: value 0x%llx\n",
		AW(mmu_cr));
}

void kvm_set_mmu_guest_u_pt(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	e2k_core_mode_t core_mode;

	if (likely(mmu->u_context_on))
		return kvm_switch_mmu_guest_u_pt(vcpu);

	/* setup OS and user PT hardware and software context */
	kvm_set_vcpu_pt_context(vcpu);

	/* setup user PID on hardware shadow register */
	write_guest_PID_reg(vcpu, mmu->pid);

	kvm_dump_shadow_u_pptb(vcpu, "Set MMU guest shadow OS/U_PT context:\n");
	if (DEBUG_SHADOW_CONTEXT_MODE && is_sep_virt_spaces(vcpu)) {
		pr_info("   SH_OS_PPTB: value 0x%lx\n"
			"   SH_OS_VPTB: value 0x%lx\n"
			"   OS_PPTB:    value 0x%lx\n"
			"   OS_VPTB:    value 0x%lx\n"
			"   SH_OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_os_pptb(vcpu),
			mmu->get_vcpu_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && is_phys_paging(vcpu)) {
		pr_info("   GP_PPTB:    value 0x%llx\n",
			mmu->get_vcpu_context_gp_pptb(vcpu));
	}

	/* enable separate Page Tables support */
	core_mode = read_guest_CORE_MODE_reg(vcpu);
	core_mode.CORE_MODE_sep_virt_space = is_sep_virt_spaces(vcpu);
	write_guest_CORE_MODE_reg(vcpu, core_mode);
	DebugSHC("Set separate PT support on guest MMU:\n"
		"   SH_CORE_MODE: 0x%x gmi %s hci %s sep_virt_space %s\n",
		core_mode.CORE_MODE_reg,
		(core_mode.CORE_MODE_gmi) ? "true" : "false",
		(core_mode.CORE_MODE_hci) ? "true" : "false",
		(core_mode.CORE_MODE_sep_virt_space) ? "true" : "false");
}

void hv_vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt)
{
	/*
	 * CPU shadow context
	 */
	if (vcpu->arch.is_hv) {
		WRITE_SH_OSCUD_LO_REG(hw_ctxt->sh_oscud_lo);
		WRITE_SH_OSCUD_HI_REG(hw_ctxt->sh_oscud_hi);
		WRITE_SH_OSGD_LO_REG(hw_ctxt->sh_osgd_lo);
		WRITE_SH_OSGD_HI_REG(hw_ctxt->sh_osgd_hi);
		WRITE_SH_OSCUTD_REG(hw_ctxt->sh_oscutd);
		WRITE_SH_OSCUIR_REG(hw_ctxt->sh_oscuir);
	}
	DebugSHC("initialized CPU shadow context\n"
		"SH_OSCUD:  base 0x%llx size 0x%x\n"
		"SH_OSGD:   base 0x%llx size 0x%x\n"
		"CUTD:      base 0x%llx\n"
		"SH_OSCUTD: base 0x%llx\n"
		"SH_OSCUIR: index 0x%x\n"
		"Trap table entry at %px\n",
		hw_ctxt->sh_oscud_lo.OSCUD_lo_base,
		hw_ctxt->sh_oscud_hi.OSCUD_hi_size,
		hw_ctxt->sh_osgd_lo.OSGD_lo_base,
		hw_ctxt->sh_osgd_hi.OSGD_hi_size,
		vcpu->arch.sw_ctxt.cutd.CUTD_base,
		hw_ctxt->sh_oscutd.CUTD_base,
		hw_ctxt->sh_oscuir.CUIR_index,
		vcpu->arch.trap_entry);
}

void write_hw_ctxt_to_hv_vcpu_registers(struct kvm_vcpu *vcpu,
				const struct kvm_hw_cpu_context *hw_ctxt,
				const struct kvm_sw_cpu_context *sw_ctxt)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	epic_page_t *cepic = hw_ctxt->cepic;
	unsigned int i;

	/*
	 * Stack registers
	 */
	WRITE_SH_PSP_LO_REG_VALUE(AW(hw_ctxt->sh_psp_lo));
	WRITE_SH_PSP_HI_REG_VALUE(AW(hw_ctxt->sh_psp_hi));
	WRITE_SH_PCSP_LO_REG_VALUE(AW(hw_ctxt->sh_pcsp_lo));
	WRITE_SH_PCSP_HI_REG_VALUE(AW(hw_ctxt->sh_pcsp_hi));
	WRITE_BU_PSP_LO_REG_VALUE(AW(hw_ctxt->bu_psp_lo));
	WRITE_BU_PSP_HI_REG_VALUE(AW(hw_ctxt->bu_psp_hi));
	WRITE_BU_PCSP_LO_REG_VALUE(AW(hw_ctxt->bu_pcsp_lo));
	WRITE_BU_PCSP_HI_REG_VALUE(AW(hw_ctxt->bu_pcsp_hi));
	/* Filling of backup stacks is made on main PSHTP/PCSHTP and
	 * BU_PSP/BU_PCSP pointers. Switch from main PSHTP/PCSHTP to
	 * shadow SH_PSHTP/SH_PCSHTP is done after filling, so set
	 * shadow SH_PSHTP/SH_PCSHTP to sizes of backup stacks */
	WRITE_SH_PSHTP_REG_VALUE(hw_ctxt->bu_psp_hi.PSP_hi_ind);
	WRITE_SH_PCSHTP_REG_SVALUE(hw_ctxt->bu_pcsp_hi.PCSP_hi_ind);

	DebugSHC("initialized hardware shadow registers:\n"
		"SH_PSP:   base 0x%llx size 0x%x index 0x%x\n"
		"SH_PCSP:  base 0x%llx size 0x%x index 0x%x\n"
		"BU_PSP:   base 0x%llx size 0x%x index 0x%x\n"
		"BU_PCSP:  base 0x%llx size 0x%x index 0x%x\n"
		"SH_PSHTP: value 0x%x\n"
		"SH_PSHTP: value 0x%x\n",
		hw_ctxt->sh_psp_lo.PSP_lo_base, hw_ctxt->sh_psp_hi.PSP_hi_size,
		hw_ctxt->sh_psp_hi.PSP_hi_ind, hw_ctxt->sh_pcsp_lo.PCSP_lo_base,
		hw_ctxt->sh_pcsp_hi.PCSP_hi_size,
		hw_ctxt->sh_pcsp_hi.PCSP_hi_ind, hw_ctxt->bu_psp_lo.PSP_lo_base,
		hw_ctxt->bu_psp_hi.PSP_hi_size, hw_ctxt->bu_psp_hi.PSP_hi_ind,
		hw_ctxt->bu_pcsp_lo.PCSP_lo_base,
		hw_ctxt->bu_pcsp_hi.PCSP_hi_size,
		hw_ctxt->bu_pcsp_hi.PCSP_hi_ind, hw_ctxt->bu_psp_hi.PSP_hi_ind,
		hw_ctxt->bu_pcsp_hi.PCSP_hi_ind);

	WRITE_SH_WD_REG_VALUE(hw_ctxt->sh_wd.WD_reg);

	/*
	 * MMU shadow context 
	 */
	write_SH_MMU_CR_reg(hw_ctxt->sh_mmu_cr);
	write_SH_PID_reg(hw_ctxt->sh_pid);
	write_GID_reg(hw_ctxt->gid);
	DebugSHC("initialized MMU shadow context:\n"
		"SH_MMU_CR:  value 0x%llx\n"
		"SH_PID:     value 0x%llx\n"
		"GP_PPTB:    value 0x%llx\n"
		"sh_U_PPTB:  value 0x%lx\n"
		"sh_U_VPTB:  value 0x%lx\n"
		"SH_OS_PPTB: value 0x%lx\n"
		"SH_OS_VPTB: value 0x%lx\n"
		"SH_OS_VAB:  value 0x%lx\n"
		"GID:        value 0x%llx\n",
		AW(hw_ctxt->sh_mmu_cr), hw_ctxt->sh_pid,
		mmu->get_vcpu_context_gp_pptb(vcpu),
		mmu->get_vcpu_context_u_pptb(vcpu),
		mmu->get_vcpu_context_u_vptb(vcpu),
		mmu->get_vcpu_context_os_pptb(vcpu),
		mmu->get_vcpu_context_os_vptb(vcpu),
		mmu->get_vcpu_context_os_vab(vcpu),
		hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	hv_vcpu_write_os_cu_hw_ctxt_to_registers(vcpu, hw_ctxt);

	WRITE_SH_OSR0_REG_VALUE(hw_ctxt->sh_osr0);
	DebugSHC("SH_OSR0: value 0x%llx\n", hw_ctxt->sh_osr0);
	write_SH_CORE_MODE_reg(hw_ctxt->sh_core_mode);
	DebugSHC("SH_CORE_MODE: value 0x%x, gmi %s, hci %s\n",
		hw_ctxt->sh_core_mode.CORE_MODE_reg,
		(hw_ctxt->sh_core_mode.CORE_MODE_gmi) ? "true" : "false",
		(hw_ctxt->sh_core_mode.CORE_MODE_hci) ? "true" : "false");

	/*
	 * VIRT_CTRL_* registers
	 */
	WRITE_VIRT_CTRL_CU_REG(hw_ctxt->virt_ctrl_cu);
	write_VIRT_CTRL_MU_reg(hw_ctxt->virt_ctrl_mu);
	write_G_W_IMASK_MMU_CR_reg(hw_ctxt->g_w_imask_mmu_cr);
	DebugSHC("initialized VIRT_CTRL registers\n"
		"VIRT_CTRL_CU: 0x%llx\n"
		"VIRT_CTRL_MU: 0x%llx, sh_pt_en : %s, gp_pt_en : %s\n"
		"G_W_IMASK_MMU_CR: 0x%llx, tlb_en : %s\n",
		AW(hw_ctxt->virt_ctrl_cu), AW(hw_ctxt->virt_ctrl_mu),
		(hw_ctxt->virt_ctrl_mu.sh_pt_en) ? "true" : "false",
		(hw_ctxt->virt_ctrl_mu.gp_pt_en) ? "true" : "false",
		AW(hw_ctxt->g_w_imask_mmu_cr),
		(hw_ctxt->g_w_imask_mmu_cr.tlb_en) ? "true" : "false");

	epic_write_guest_w(CEPIC_CTRL, cepic->ctrl);
	epic_write_guest_w(CEPIC_ID, cepic->id);
	epic_write_guest_w(CEPIC_CPR, cepic->cpr);
	epic_write_guest_w(CEPIC_ESR, cepic->esr);
	epic_write_guest_w(CEPIC_ESR2, cepic->esr2.raw);
	epic_write_guest_w(CEPIC_CIR, cepic->cir.raw);
	epic_write_guest_w(CEPIC_ESR_NEW, cepic->esr_new.counter);
	epic_write_guest_d(CEPIC_ICR, cepic->icr.raw);
	epic_write_guest_w(CEPIC_TIMER_LVTT, cepic->timer_lvtt.raw);
	epic_write_guest_w(CEPIC_TIMER_INIT, cepic->timer_init);
	epic_write_guest_w(CEPIC_TIMER_CUR, cepic->timer_cur);
	epic_write_guest_w(CEPIC_TIMER_DIV, cepic->timer_div);
	epic_write_guest_w(CEPIC_NM_TIMER_LVTT, cepic->nm_timer_lvtt);
	epic_write_guest_w(CEPIC_NM_TIMER_INIT, cepic->nm_timer_init);
	epic_write_guest_w(CEPIC_NM_TIMER_CUR, cepic->nm_timer_cur);
	epic_write_guest_w(CEPIC_NM_TIMER_DIV, cepic->nm_timer_div);
	epic_write_guest_w(CEPIC_SVR, cepic->svr);
	epic_write_guest_w(CEPIC_PNMIRR_MASK, cepic->pnmirr_mask);
	for (i = 0; i < CEPIC_PMIRR_NR_DREGS; i++)
		epic_write_guest_d(CEPIC_PMIRR + i * 8,
			cepic->pmirr[i].counter);
	epic_write_guest_w(CEPIC_PNMIRR, cepic->pnmirr.counter);
}

static inline bool g_th_exceptions(const intc_info_cu_hdr_t *cu_hdr,
		const struct kvm_intc_cpu_context *intc_ctxt)
{
	u64 exceptions = intc_ctxt->exceptions;

	/* Entering trap handler will freeze TIRs, so no need for g_th flag */
	if (cu_hdr->lo.tir_fz)
		return false;

	/* #132939 - hardware always tries to translate guest trap handler upon
	 * interception, so we do not set 'g_th' bit if only exc_instr_page_prot
	 * or exc_instr_page_miss happened (as those are precise traps, they
	 * will be regenerated by hardware anyway). */
	exceptions &= ~(exc_instr_page_prot_mask | exc_instr_page_miss_mask);

	if (exceptions)
		return true;

	return intc_ctxt->cu_num >= 0 && cu_hdr->lo.exc_c;
}

static inline bool calculate_g_th(const intc_info_cu_hdr_t *cu_hdr,
		struct kvm_intc_cpu_context *intc_ctxt)
{
	bool g_th = g_th_exceptions(cu_hdr, intc_ctxt);
	bool coredump = intc_ctxt->coredump;

	if (!WARN_ON(g_th && coredump))
		intc_ctxt->coredump = false;

	return g_th || coredump;
}

/*
 * There are TIR_NUM(19) tir regs. Bits 64 - 56 is current tir nr
 * After each NATIVE_READ_TIR_LO_REG() we will read next tir.
 * For more info see instruction set doc.
 * Read tir hi/lo regs order is significant
 */
static void restore_SBBP_TIRs(u64 sbbp[], e2k_tir_t TIRs[], int TIRs_num,
		bool tir_fz, bool g_th)
{
	virt_ctrl_cu_t virt_ctrl_cu;
	int i;

	virt_ctrl_cu = READ_VIRT_CTRL_CU_REG();

	/* Allow writing of TIRs and SBBP */
	virt_ctrl_cu.tir_rst = 1;
	WRITE_VIRT_CTRL_CU_REG(virt_ctrl_cu);

	for (i = SBBP_ENTRIES_NUM - 1; i >= 0; i--)
		NATIVE_WRITE_SBBP_REG_VALUE(sbbp[i]);

#pragma loop count (2)
	for (i = TIRs_num; i >= 0; i--) {
		NATIVE_WRITE_TIR_HI_REG_VALUE(AW(TIRs[i].TIR_hi));
		NATIVE_WRITE_TIR_LO_REG_VALUE(AW(TIRs[i].TIR_lo));
	}

	/* Keep guest TIRs frozen after GLAUNCH */
	virt_ctrl_cu.VIRT_CTRL_CU_glnch_tir_fz = tir_fz;

	/* Enter guest trap handler after GLAUNCH */
	virt_ctrl_cu.VIRT_CTRL_CU_glnch_g_th = g_th;

	/* Forbid writing of TIRs and SBBP */
	virt_ctrl_cu.tir_rst = 0;
	WRITE_VIRT_CTRL_CU_REG(virt_ctrl_cu);
}

static int kvm_e2k_check_request(struct kvm_vcpu *vcpu, struct kvm_intc_cpu_context *intc_ctxt)
{
	int r;

	if (kvm_check_request(KVM_REQ_MMU_RELOAD, vcpu))
		kvm_mmu_unload(vcpu, GP_ROOT_PT_FLAG);

	/* Allocate a new GP_PPTB root (it may have been invalidated on memslot deletion) */
	r = kvm_mmu_reload(vcpu, NULL, GP_ROOT_PT_FLAG);
	if (unlikely(r))
		return r;

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu) || cpu_has(CPU_HWBUG_VIRT_TLU_IB)) {
		trace_host_flush_tlb(vcpu);
		kvm_vcpu_flush_tlb(vcpu);
	}

	/* Following requests are only for SPT mode */
	kvm_clear_request(KVM_REQ_ADDR_FLUSH, vcpu);
	if (kvm_check_request(KVM_REQ_MMU_SYNC, vcpu)) {
		kvm_mmu_sync_roots(vcpu, OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
	}
	intc_ctxt->coredump |= kvm_check_request(KVM_REQ_TO_COREDUMP, vcpu);

	return 0;
}

static void kvm_set_g_tmr(void)
{
	if (kvm_g_tmr) {
		g_preempt_tmr_t tmr;

		AW(tmr) = 0;
		tmr.tmr = kvm_g_tmr;
		tmr.v = 1;
		WRITE_G_PREEMPT_TMR_REG(tmr);
	}

}

bool kvm_vcpu_exit_request(struct kvm_vcpu *vcpu)
{
	return vcpu->mode == EXITING_GUEST_MODE || kvm_request_pending(vcpu) ||
		xfer_to_guest_mode_work_pending();
}

int vcpu_enter_guest(struct kvm_vcpu *vcpu)
{
	gthread_info_t *gti = current_thread_info()->gthread_info;
	e2k_upsr_t guest_upsr;
	intc_info_cu_t *cu = &vcpu->arch.intc_ctxt.cu;
	intc_info_mu_t *mu = vcpu->arch.intc_ctxt.mu;
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	u64 exceptions;
	bool g_th;
	int r;

	r = kvm_e2k_check_request(vcpu, intc_ctxt);
	if (unlikely(r))
		return r;

	preempt_disable();
	raw_all_irq_disable();

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	srcu_read_unlock(&vcpu->kvm->srcu, vcpu->srcu_idx);
	smp_mb__after_srcu_read_unlock();

	if (kvm_vcpu_exit_request(vcpu)) {
		smp_store_mb(vcpu->mode, OUTSIDE_GUEST_MODE);
		raw_all_irq_enable();
		preempt_enable();
		vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);
		return 0;
	}

	/* Check if guest should enter trap handler after glaunch. */
	g_th = calculate_g_th(&cu->header, intc_ctxt);

	kvm_set_g_tmr();

	restore_SBBP_TIRs(intc_ctxt->sbbp, intc_ctxt->TIRs, intc_ctxt->nr_TIRs,
			cu->header.lo.tir_fz, g_th);
	kvm_clear_vcpu_intc_TIRs_num(vcpu);

	/* if intc info structures were updated, then restore registers */
	if (kvm_get_intc_info_mu_is_updated(vcpu)) {
		modify_intc_info_mu_data(intc_ctxt->mu, intc_ctxt->mu_num);
		restore_intc_info_mu(intc_ctxt->mu, intc_ctxt->mu_num);
	}
	if (kvm_get_intc_info_cu_is_updated(vcpu))
		restore_intc_info_cu(&intc_ctxt->cu, intc_ctxt->cu_num);

	/* MMU intercepts were handled, clear state for new intercepts */
	kvm_clear_intc_mu_state(vcpu);

	/* clear hypervisor intercept event counters */
	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	intc_ctxt->cur_mu = -1;
	kvm_reset_intc_info_mu_is_updated(vcpu);
	kvm_reset_intc_info_cu_is_updated(vcpu);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);

	/* Switch IRQ control to PSR and disable MI/NMIs */
	NATIVE_WRITE_PSR_IRQ_BARRIER(AW(E2K_KERNEL_PSR_DISABLED_ALL));

	/* the function should set initial UPSR state */
	if (gti != NULL) {
		KVM_RESTORE_GUEST_KERNEL_UPSR(current_thread_info());
	}

	launch_hv_vcpu(&vcpu->arch);

	/* Guest can switch to other thread, so update guest thread info */
	gti = current_thread_info()->gthread_info;

	save_intc_info_cu(cu, &vcpu->arch.intc_ctxt.cu_num);
	save_intc_info_mu(mu, &vcpu->arch.intc_ctxt.mu_num);

	/* See the comment in kvm_vcpu_exiting_guest_mode() */
	smp_store_mb(vcpu->mode, OUTSIDE_GUEST_MODE);

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	SAVE_SBBP(intc_ctxt->sbbp);

	/*
	 * Save guest TIRs should be at any case, including empty state
	 */
	exceptions = 0;
	exceptions = SAVE_TIRS(intc_ctxt->TIRs, intc_ctxt->nr_TIRs,
		true); /* from_intc */
	/* un-freeze the TIR's LIFO */
	UNFREEZE_TIRs();
	intc_ctxt->exceptions = exceptions;

	/* save current state of guest kernel UPSR */
	NATIVE_DO_SAVE_UPSR_REG(guest_upsr);
	if (gti != NULL) {
		DO_SAVE_GUEST_KERNEL_UPSR(gti, guest_upsr);
	}

	preempt_enable();

	vcpu->srcu_idx = srcu_read_lock(&vcpu->kvm->srcu);

	/* This will enable interrupts */
	return parse_INTC_registers(&vcpu->arch);
}

static void kvm_epic_write_gstid(int gst_id)
{
	union cepic_gstid reg_gstid;

	reg_gstid.raw = 0;
	reg_gstid.bits.gstid = gst_id;
	epic_write_w(CEPIC_GSTID, reg_gstid.raw);
}

static void kvm_epic_write_gstbase(unsigned long epic_gstbase)
{
	epic_write_d(CEPIC_GSTBASE_LO, epic_gstbase >> PAGE_SHIFT);
}

/*
 * Currently DAT only has 64 rows, so hardware will transform full CEPIC ID
 * back to short to get index
 */
static void kvm_epic_write_dat(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned int vcpu_id = kvm_vcpu_to_full_cepic_id(vcpu);
	unsigned int cpu = cpu_to_full_cepic_id(vcpu->cpu);
	unsigned int gst_id = kvm->arch.vmid.nr;
	unsigned long flags;
	union cepic_dat reg;

	reg.raw = 0;
	reg.bits.gst_id = gst_id;
	reg.bits.gst_dst = vcpu_id;
	reg.bits.index = cpu;
	reg.bits.dat_cop = CEPIC_DAT_WRITE;

	raw_spin_lock_irqsave(&vcpu->arch.epic_dat_lock, flags);
	epic_write_d(CEPIC_DAT, reg.raw);

	/* Wait for status bit */
	do {
		cpu_relax();
		reg.raw = (unsigned long) epic_read_w(CEPIC_DAT);
	} while (reg.bits.stat);
	vcpu->arch.epic_dat_active = true;
	raw_spin_unlock_irqrestore(&vcpu->arch.epic_dat_lock, flags);
}

void kvm_epic_invalidate_dat(struct kvm_vcpu_arch *vcpu)
{
	union cepic_dat reg;
	unsigned long flags;

	reg.raw = 0;
	reg.bits.index = cpu_to_full_cepic_id(arch_to_vcpu(vcpu)->cpu);
	reg.bits.dat_cop = CEPIC_DAT_INVALIDATE;

	raw_spin_lock_irqsave(&vcpu->epic_dat_lock, flags);
	epic_write_w(CEPIC_DAT, (unsigned int)reg.raw);

	/* Wait for status bit */
	do {
		cpu_relax();
		reg.raw = (unsigned long) epic_read_w(CEPIC_DAT);
	} while (reg.bits.stat);

	vcpu->epic_dat_active = false;
	raw_spin_unlock_irqrestore(&vcpu->epic_dat_lock, flags);
}

void kvm_epic_timer_start(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	WARN_ON_ONCE(!reg.bits.timer_stop);
	reg.bits.timer_stop = 0;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void kvm_epic_timer_stop(bool skip_check)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	WARN_ON_ONCE(!skip_check && reg.bits.timer_stop);
	reg.bits.timer_stop = 1;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void kvm_epic_enable_int(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	reg.bits.mi_gst_blk = 0;
	reg.bits.nmi_gst_blk = 0;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

/*
 * PNMIRR "startup_entry" field cannot be restored using "OR"
 * write to PNMIRR as that will create a mix of restored and
 * previous values.  So we restore it by sending startup IPI
 * to ourselves.
 *
 * No need to acquire epic_dat_lock, as we are in the process
 * of restoring the target vcpu (this is the last step).
 */
static void kvm_epic_restore_pnmirr_startup_entry(struct kvm_vcpu *vcpu)
{
	epic_page_t *cepic = vcpu->arch.hw_ctxt.cepic;
	union cepic_pnmirr reg;

	reg.raw = atomic_read(&cepic->pnmirr);
	if (reg.bits.startup)
		kvm_hw_epic_deliver_to_icr(vcpu, reg.bits.startup_entry,
				CEPIC_ICR_DLVM_STARTUP);
}

void kvm_hv_epic_load(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned int gst_id = kvm->arch.vmid.nr;
	unsigned long epic_gstbase =
		(unsigned long) __pa(page_address(kvm->arch.epic_pages));

	kvm_epic_write_gstid(gst_id);
	kvm_epic_write_gstbase(epic_gstbase);
	kvm_epic_write_dat(vcpu);
	kvm_epic_restore_pnmirr_startup_entry(vcpu);
}


enum hrtimer_restart kvm_epic_idle_timer_fn(struct hrtimer *hrtimer)
{
	struct kvm_vcpu *vcpu = container_of(hrtimer, struct kvm_vcpu, arch.cepic_idle);

	DebugKVMIT("started on VCPU #%d\n", vcpu->vcpu_id);
	vcpu->arch.unhalted = true;
	kvm_vcpu_wake_up(vcpu);

	return HRTIMER_NORESTART;
}

void kvm_init_cepic_idle_timer(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu != NULL);
	DebugKVMIT("started on VCPU #%d\n", vcpu->vcpu_id);

	hrtimer_init(&vcpu->arch.cepic_idle, CLOCK_MONOTONIC,
		     HRTIMER_MODE_ABS);
	vcpu->arch.cepic_idle.function = kvm_epic_idle_timer_fn;
}

/* Useful for debugging problems with wakeup */
static bool periodic_wakeup = false;
module_param_named(e2k_periodic_wakeup, periodic_wakeup, bool, 0600);

void kvm_epic_start_idle_timer(struct kvm_vcpu *vcpu)
{
	struct hrtimer *hrtimer = &vcpu->arch.cepic_idle;
	struct kvm *kvm = vcpu->kvm;
	u64 cepic_timer_cur = (u64) vcpu->arch.hw_ctxt.cepic->timer_cur;
	u64 vcpu_idle_timeout_ns = jiffies_to_nsecs(VCPU_IDLE_TIMEOUT);
	u64 delta_ns;

	if (unlikely(cepic_timer_cur == 0 && !periodic_wakeup &&
			!kvm_arch_has_assigned_device(kvm)))
		return;

	delta_ns = (cepic_timer_cur)
			? ((u64) cepic_timer_cur * NSEC_PER_SEC / kvm->arch.cepic_freq)
			: vcpu_idle_timeout_ns;

	/* Make sure to wake up periodically to check for interrupts
	 * from external devices.  Also do it if debugging option
	 * [periodic_wakeup] is enabled. */
	if (delta_ns > vcpu_idle_timeout_ns && (periodic_wakeup ||
						kvm_arch_has_assigned_device(kvm)))
		delta_ns = vcpu_idle_timeout_ns;

	ktime_t current_time = hrtimer->base->get_time();
	vcpu->arch.cepic_idle_start_time = current_time;
	hrtimer_start(&vcpu->arch.cepic_idle,
			ktime_add_ns(current_time, delta_ns), HRTIMER_MODE_ABS);
}

static u32 calculate_cepic_timer_cur(struct kvm_vcpu *vcpu, u32 cepic_timer_cur)
{
	struct hrtimer *hrtimer = &vcpu->arch.cepic_idle;
	u64 cepic_freq = vcpu->kvm->arch.cepic_freq;
	u64 cepic_timer_ns = (u64) cepic_timer_cur * NSEC_PER_SEC / cepic_freq;
	u64 passed_time_ns = ktime_to_ns(ktime_sub(hrtimer->base->get_time(),
					vcpu->arch.cepic_idle_start_time));
	if (cepic_timer_ns > passed_time_ns)
		cepic_timer_ns -= passed_time_ns;
	else
		cepic_timer_ns = 0;

	u64 new_timer_cur = max(cepic_timer_ns * cepic_freq / NSEC_PER_SEC, 1ull);
	if (WARN_ON_ONCE(new_timer_cur > (u64) UINT_MAX))
		new_timer_cur = UINT_MAX;
	return new_timer_cur;
}

void kvm_epic_stop_idle_timer(struct kvm_vcpu *vcpu)
{
	struct hrtimer *hrtimer = &vcpu->arch.cepic_idle;
	epic_page_t *cepic = vcpu->arch.hw_ctxt.cepic;
	u32 cepic_timer_cur = (u64) cepic->timer_cur;

	/* Stop the software timer if it is still running */
	hrtimer_cancel(hrtimer);

	/* Adjust CEPIC timer if it is running, otherwise the guest might hang
	 * for a long time.  For example, if guest waits in idle then most of
	 * the time it does not actually execute and thus the timer advances
	 * at a _much_ slower rate; it is hypervisor's duty to forward CEPIC
	 * timer in this case. */
	if (cepic_timer_cur) {
		cepic->timer_cur = calculate_cepic_timer_cur(vcpu, cepic_timer_cur);
		DebugKVMIT("Recalculating cepic timer %d from %x to %x\n",
				vcpu->vcpu_id, cepic_timer_cur, cepic->timer_cur);
	} else {
		DebugKVMIT("Not recalculating cepic timer %d\n", vcpu->vcpu_id);
	}
}

int kvm_prepare_hv_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	prepare_bu_stacks_to_startup_vcpu(vcpu);
	return 0;
}
