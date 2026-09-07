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
#include <asm/kvm/switch.h>
#include <asm/kvm/gregs.h>
#include "cpu.h"
#include "mmu.h"
#include "process.h"
#include "intercepts.h"
#include "io.h"
#include "pic.h"
#include "trace-tlb-flush.h"
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include <asm/kvm/paravirt_sw/runstate.h>
#include "paravirt_sw/cpu_defs.h"
#include "paravirt_sw/mmu_defs.h"
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#undef	DEBUG_KVM_STARTUP_MODE
#undef	DebugKVMSTUP
#define	DEBUG_KVM_STARTUP_MODE		0	/* VCPU startup debugging */
#define	DebugKVMSTUP(fmt, args...)					\
({									\
	if (DEBUG_KVM_STARTUP_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SHADOW_CONTEXT_MODE
#undef	DebugSHC
#define	DEBUG_SHADOW_CONTEXT_MODE	0	/* shadow context debugging */
#define	DebugSHC(fmt, args...)					\
({									\
	if (DEBUG_SHADOW_CONTEXT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IT_MODE
#undef	DebugKVMIT
#define	DEBUG_KVM_IT_MODE		0	/* CEPIC idle timer */
#define	DebugKVMIT(fmt, args...)					\
({									\
	if (DEBUG_KVM_IT_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_COREDUMP_MODE
#undef	DebugCDUMP
#define	DEBUG_KVM_COREDUMP_MODE		0	/* coredump VCPUs state */
#define	DebugCDUMP(fmt, args...)					\
({									\
	if (DEBUG_KVM_COREDUMP_MODE)					\
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

	DebugKVMSTUP("started on VCPU #%d\n", vcpu->vcpu_id);

	prepare_vcpu_startup_args(vcpu);
	hypv_backup = &vcpu->arch.hypv_backup;
	boot_stacks = &vcpu->arch.boot_stacks;

	ps_frames = hypv_backup->ps.base;
	VM_BUG_ON(ps_frames == NULL);
	pcs_frames = hypv_backup->pcs.base;
	VM_BUG_ON(pcs_frames == NULL);

	prepare_stacks_to_startup_vcpu(vcpu, ps_frames, pcs_frames,
			vcpu->arch.args, vcpu->arch.args_num, vcpu->arch.entry_point,
			E2K_RESET_PSR, boot_stacks->data.size,
			&ps_ind, &pcs_ind, KERNEL_CODES_INDEX, 1);

	/* correct stacks pointers indexes */
	hypv_backup->psp = set_psp_ind(hypv_backup->psp, ps_ind);
	hypv_backup->pcsp = set_pcsp_ind(hypv_backup->pcsp, pcs_ind);
	DebugKVMSTUP("backup PS.ind 0x%llx PCS.ind 0x%llx\n",
		     PSP_IND(hypv_backup->psp), PCSP_IND(hypv_backup->pcsp));
}

void init_hv_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	e2k_tir_t TIR;

	/* Initialize empty TIRs before first GLAUNCH to avoid showing host's
	 * IP to guest */
	TIR = (e2k_tir_t) {
	0};
	TIR.j = 1;
	kvm_clear_vcpu_intc_TIRs_num(vcpu);
	kvm_update_vcpu_intc_TIR(vcpu, 1, TIR);

	/* Clean INTC_INFO_MU before first GLAUNCH */
	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	kvm_set_intc_info_mu_is_updated(vcpu);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* set flag of first GLAUNCH VM */
	intc_ctxt->start_gm = true;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
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
	virt_ctrl_mu_t mu;
	mmu_reg_t sh_pid;
	e2k_mmu_cr_t sh_mmu_cr, g_w_imask_mmu_cr;
	e2k_mu_hw0_t mu_hw0;

	/* MMU interception control registers state */
	mu.VIRT_CTRL_MU_reg = 0;
	AW(g_w_imask_mmu_cr) = 0;

#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
	if (kvm_is_tdp_enable(vcpu->kvm)) {
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */
		mu.sh_pt_en = 0;
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
	} else {
		mu.sh_pt_en = 1;
	}
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_is_phys_pt_enable(vcpu->kvm))
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		mu.gp_pt_en = 1;

	/* Guest should not be able to access special registers */
	mu.rw_dbg1 = 1;
	if (!kvm_debug)
		mu.rr_dbg1 = 1;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
		if (kvm_is_tdp_enable(vcpu->kvm)) {
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */
			/* intercept only MMU_CR updates to track */
			/* paging enable/disable */
			mu.rw_mmu_cr = 0;
			g_w_imask_mmu_cr.tlb_en = 1;
#ifdef CONFIG_KVM_HW_SHADOW_PT_ENABLE
		} else {
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
		}
#endif /* CONFIG_KVM_HW_SHADOW_PT_ENABLE */
	}
	vcpu->arch.mmu.virt_ctrl_mu = mu;
	vcpu->arch.mmu.g_w_imask_mmu_cr = g_w_imask_mmu_cr;

	/* MMU shadow registers initial state */
	sh_mmu_cr = MMU_CR_KERNEL_OFF;
	sh_pid = 0;	/* guest kernel should have PID == 0 */
	vcpu->arch.mmu.init_sh_mmu_cr = sh_mmu_cr;
	vcpu->arch.mmu.init_sh_pid = sh_pid;

	/* initial state of guest mu_hw0 set as on host */
	mu_hw0 = native_read_MU_HW0_reg();
	vcpu->arch.mmu.mu_hw0 = mu_hw0;
}

void init_backup_hw_ctxt(struct kvm_vcpu *vcpu)
{
	bu_hw_stack_t *hypv_backup;
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (!vcpu->arch.is_hv) {
		/* there is not support of hardware virtualizsation */
		return;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/*
	 * Stack registers
	 */
	hypv_backup = &vcpu->arch.hypv_backup;
	hw_ctxt->bu_psp = hypv_backup->psp;
	hw_ctxt->bu_pcsp = hypv_backup->pcsp;

	/* set backup stacks to empty state will be done by hardware after */
	/* GLAUNCH, so update software pointers at hypv_backup structure */
	/* for following GLAUNCHes and paravirtualization HCALL emulation */
	hypv_backup->psp = set_psp_ind(hypv_backup->psp, 0);
	hypv_backup->pcsp = set_pcsp_ind(hypv_backup->pcsp, 0);
}

void kvm_hv_update_guest_stacks_registers(struct kvm_vcpu *vcpu,
					  guest_hw_stack_t *stack_regs)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

	/*
	 * Guest Stack state is now on back UP registers
	 */
	hw_ctxt->sh_psp = stack_regs->stacks.psp;
	hw_ctxt->sh_pcsp = stack_regs->stacks.pcsp;

	write_BU_PSP_reg(hw_ctxt->sh_psp);
	write_BU_PCSP_reg(hw_ctxt->sh_pcsp);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	vcpu->arch.sw_ctxt.crs.cr0 = stack_regs->crs.cr0;
	vcpu->arch.sw_ctxt.crs.cr1 = stack_regs->crs.cr1;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	DebugSHC("vcpu #%d update guest stacks registers (now on BU_*):\n"
		 "BU_PSP:  base 0x%llx size 0x%llx index 0x%llx\n"
		 "BU_PCSP: base 0x%llx size 0x%llx index 0x%llx\n",
		 vcpu->vcpu_id,
		 vcpu_psp_base(vcpu, stack_regs->stacks.psp),
		 vcpu_psp_size(vcpu, stack_regs->stacks.psp),
		 vcpu_psp_ind(vcpu, stack_regs->stacks.psp),
		 vcpu_pcsp_base(vcpu, stack_regs->stacks.pcsp),
		 vcpu_pcsp_size(vcpu, stack_regs->stacks.pcsp),
		 vcpu_pcsp_ind(vcpu, stack_regs->stacks.pcsp));
}

static void kvm_dump_mmu_tdp_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	DebugSHC("vcpu #%d: Set MMU guest TDP PT context:\n", vcpu->vcpu_id);

	if (DEBUG_SHADOW_CONTEXT_MODE && (flags & GP_ROOT_PT_FLAG)) {
		pr_info("   GP_PPTB: value 0x%llx\n",
			mmu->get_vcpu_context_gp_pptb(vcpu));
	}
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (DEBUG_SHADOW_CONTEXT_MODE &&
	    ((flags & U_ROOT_PT_FLAG) ||
	     ((flags & OS_ROOT_PT_FLAG) && !is_sep_virt_spaces(vcpu)))) {
		pr_info("   U_PPTB:  value 0x%lx\n"
			"   U_VPTB:  value 0x%lx\n",
			mmu->get_vcpu_context_u_pptb(vcpu),
			mmu->get_vcpu_context_u_vptb(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE &&
	    ((flags & OS_ROOT_PT_FLAG) && is_sep_virt_spaces(vcpu))) {
		pr_info("   OS_PPTB: value 0x%lx\n"
			"   OS_VPTB: value 0x%lx\n"
			"   OS_VAB:  value 0x%lx\n",
			mmu->get_vcpu_context_os_pptb(vcpu),
			mmu->get_vcpu_context_os_vptb(vcpu),
			mmu->get_vcpu_context_os_vab(vcpu));
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	if (DEBUG_SHADOW_CONTEXT_MODE) {
		pr_info("   SH_PID:  value 0x%llx\n", read_guest_PID_reg(vcpu));
	}
	if (DEBUG_SHADOW_CONTEXT_MODE && (flags & SEP_VIRT_ROOT_PT_FLAG)) {
		e2k_core_mode_t core_mode = read_guest_CORE_MODE_reg(vcpu);

		pr_info("   SH_CORE_MODE:  0x%x sep_virt_space: %s\n",
			AW(core_mode),
			(core_mode.sep_virt_space) ?
			"true" : "false");
	}
}

static void setup_mmu_tdp_context(struct kvm_vcpu *vcpu, unsigned flags)
{
	E2K_KVM_BUG_ON(!is_tdp_paging(vcpu));

	/* setup MMU page tables hardware and software context */
	kvm_set_vcpu_the_pt_context(vcpu, flags);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* setup user PID on hardware shadow register */
	write_SH_PID_reg(vcpu->arch.mmu.pid);

	if ((flags & SEP_VIRT_ROOT_PT_FLAG) && vcpu->arch.is_pv) {
		e2k_core_mode_t core_mode = read_SH_CORE_MODE_reg();

		/* enable/disable guest separate Page Tables support */
		core_mode.sep_virt_space = is_sep_virt_spaces(vcpu);
		vcpu->arch.hw_ctxt.sh_core_mode = core_mode;
		write_guest_CORE_MODE_reg(vcpu, core_mode);
	}
#else
	write_SH_PID_reg(0);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	kvm_dump_mmu_tdp_context(vcpu, flags);
}

void kvm_setup_mmu_tdp_context(struct kvm_vcpu *vcpu)
{
	/* setup MMU page tables hardware and software context */
	setup_mmu_tdp_context(vcpu,
			      GP_ROOT_PT_FLAG | OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG
			      | SEP_VIRT_ROOT_PT_FLAG);
}

void kvm_hv_setup_mmu_spt_context(struct kvm_vcpu *vcpu)
{
	e2k_core_mode_t core_mode = read_SH_CORE_MODE_reg();

	/* enable/disable guest separate Page Tables support */
	core_mode.sep_virt_space = is_sep_virt_spaces(vcpu);
	vcpu->arch.hw_ctxt.sh_core_mode = core_mode;
	write_guest_CORE_MODE_reg(vcpu, core_mode);
}

void hv_vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu, const struct kvm_hw_cpu_context
					      *hw_ctxt)
{
	/*
	 * CPU shadow context
	 */
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (vcpu->arch.is_hv)
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	{
		write_SH_OSCUD_reg(hw_ctxt->sh_oscud);
		write_SH_OSGD_reg(hw_ctxt->sh_osgd);
		write_SH_OSCUTD_reg(hw_ctxt->sh_oscutd);
		write_SH_OSCUIR_reg(hw_ctxt->sh_oscuir);
	}
	DebugSHC("initialized vcpu #%d shadow context\n"
		 "SH_OSCUD:  base 0x%llx size 0x%llx\n"
		 "SH_OSGD:   base 0x%llx size 0x%llx\n"
		 "RSH_OSCUD: base 0x%llx size 0x%llx\n"
		 "RSH_OSGD:  base 0x%llx size 0x%llx\n"
		 "CUTD:      base 0x%llx\n"
		 "SH_OSCUTD: base 0x%llx\n"
		 "SH_OSCUIR: index 0x%llx\n",
		 vcpu->vcpu_id,
		 vcpu_cud_base(vcpu, hw_ctxt->sh_oscud),
		 vcpu_cud_size(vcpu, hw_ctxt->sh_oscud),
		 vcpu_gd_base(vcpu, hw_ctxt->sh_osgd),
		 vcpu_gd_size(vcpu, hw_ctxt->sh_osgd),
		 vcpu_cud_base(vcpu, read_SH_OSCUD_reg()),
		 vcpu_cud_size(vcpu, read_SH_OSCUD_reg()),
		 vcpu_gd_base(vcpu, read_SH_OSGD_reg()),
		 vcpu_gd_size(vcpu, read_SH_OSGD_reg()),
		 vcpu->arch.sw_ctxt.cutd.base,
		 hw_ctxt->sh_oscutd.base,
		 (u64) hw_ctxt->sh_oscuir.index);
}

void write_hw_ctxt_to_hv_vcpu_registers(struct kvm_vcpu *vcpu, const struct kvm_hw_cpu_context
					*hw_ctxt, const struct kvm_sw_cpu_context
					*sw_ctxt)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;
	epic_page_t *cepic = hw_ctxt->cepic;
	unsigned int i;

	/* set shadow register-pointers format before init them */
	write_guest_CORE_MODE_reg(vcpu, hw_ctxt->sh_core_mode);
	if (likely(!cpu_has(CPU_FEAT_ISET_V7))) {
		DebugSHC("SH_CORE_MODE: value 0x%x:\n"
			"     sep_virt_space %s, pt_v6 %s, gmi %s, hci %s\n",
			AW(hw_ctxt->sh_core_mode),
			(hw_ctxt->sh_core_mode.sep_virt_space) ? "true" : "false",
			(hw_ctxt->sh_core_mode.pt_v6) ? "true" : "false",
			(hw_ctxt->sh_core_mode.gmi) ? "true" : "false",
			(hw_ctxt->sh_core_mode.hci) ? "true" : "false");
	} else {
		DebugSHC("SH_CORE_MODE: value 0x%x:\n"
			"     sep_virt_space %s, pt_v6 %s, gmi %s, hci %s, getsp_v7 %s descr_v7 %s macp_enbl %s\n",
			AW(hw_ctxt->sh_core_mode),
			(hw_ctxt->sh_core_mode.sep_virt_space) ? "true" : "false",
			(hw_ctxt->sh_core_mode.pt_v6) ? "true" : "false",
			(hw_ctxt->sh_core_mode.gmi) ? "true" : "false",
			(hw_ctxt->sh_core_mode.hci) ? "true" : "false",
			(hw_ctxt->sh_core_mode.getsp_v7) ? "true" : "false",
			(hw_ctxt->sh_core_mode.descr_v7) ? "true" : "false",
			(hw_ctxt->sh_core_mode.macp_enbl) ? "true" : "false");
	}
	__E2K_WAIT_ALL;

	/*
	 * Stack registers
	 */
	write_SH_PSP_reg(hw_ctxt->sh_psp);
	write_SH_PCSP_reg(hw_ctxt->sh_pcsp);
	write_BU_PSP_reg(hw_ctxt->bu_psp);
	write_BU_PCSP_reg(hw_ctxt->bu_pcsp);
	/* Filling of backup stacks is made on main PSHTP/PCSHTP and
	 * BU_PSP/BU_PCSP pointers. Switch from main PSHTP/PCSHTP to
	 * shadow SH_PSHTP/SH_PCSHTP is done after filling, so set
	 * shadow SH_PSHTP/SH_PCSHTP to sizes of backup stacks */
	write_SH_PSHTP_reg((e2k_pshtp_t) {.ind = PSP_IND(hw_ctxt->bu_psp)});
	write_SH_PCSHTP_reg((e2k_pcshtp_t) {.ind = PCSP_IND(hw_ctxt->bu_pcsp)});

	DebugSHC("initialized hardware shadow registers:\n"
		 "SH_PSP:   base 0x%llx size 0x%llx index 0x%llx\n"
		 "SH_PCSP:  base 0x%llx size 0x%llx index 0x%llx\n"
		 "BU_PSP:   base 0x%llx size 0x%llx index 0x%llx\n"
		 "BU_PCSP:  base 0x%llx size 0x%llx index 0x%llx\n",
		 vcpu_psp_base(vcpu, hw_ctxt->sh_psp),
		 vcpu_psp_size(vcpu, hw_ctxt->sh_psp), vcpu_psp_ind(vcpu, hw_ctxt->sh_psp),
		 vcpu_pcsp_base(vcpu, hw_ctxt->sh_pcsp),
		 vcpu_pcsp_size(vcpu, hw_ctxt->sh_pcsp), vcpu_pcsp_ind(vcpu, hw_ctxt->sh_pcsp),
		 PSP_BASE(hw_ctxt->bu_psp),
		 PSP_SIZE(hw_ctxt->bu_psp), PSP_IND(hw_ctxt->bu_psp),
		 PCSP_BASE(hw_ctxt->bu_pcsp),
		 PCSP_SIZE(hw_ctxt->bu_pcsp), PCSP_IND(hw_ctxt->bu_pcsp));

	write_SH_WD_reg(hw_ctxt->sh_wd);

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
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		 "sh_U_PPTB:  value 0x%lx\n"
		 "sh_U_VPTB:  value 0x%lx\n"
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		 "SH_OS_PPTB: value 0x%lx\n"
		 "SH_OS_VPTB: value 0x%lx\n"
		 "SH_OS_VAB:  value 0x%lx\n"
		 "GID:        value 0x%llx\n",
		 AW(hw_ctxt->sh_mmu_cr), hw_ctxt->sh_pid, mmu->get_vcpu_context_gp_pptb(vcpu),
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
		 mmu->get_vcpu_context_u_pptb(vcpu), mmu->get_vcpu_context_u_vptb(vcpu),
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
		 read_SH_OS_PPTB_reg(), read_SH_OS_VPTB_reg(), read_SH_OS_VAB_reg(),
		 hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	hv_vcpu_write_os_cu_hw_ctxt_to_registers(vcpu, hw_ctxt);

	write_SH_OSR0_reg_value(hw_ctxt->sh_osr0);
	DebugSHC("SH_OSR0: value 0x%llx\n", hw_ctxt->sh_osr0);
#ifdef CONFIG_CPU_HAS_OSR1
	write_SH_OSR1_reg_value(hw_ctxt->sh_osr1);
	DebugSHC("SH_OSR1: value 0x%llx\n", hw_ctxt->sh_osr1);
#endif

	if (likely(cpu_has(CPU_FEAT_ISET_V7))) {
		write_SH_T_off_reg(hw_ctxt->sh_t_off);
		DebugSHC("initialized T_OFF register by %lld\n",
			hw_ctxt->sh_t_off);
	} else if (cpu_has(CPU_FEAT_ISET_V6)) {
		write_SH_SCLKM3_reg_value(hw_ctxt->sh_sclkm3);
	}

	/*
	 * VIRT_CTRL_* registers
	 */
	write_VIRT_CTRL_CU_reg(hw_ctxt->virt_ctrl_cu);
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
	if (cu_hdr->tir_fz)
		return false;

	/* #132939 - hardware always tries to translate guest trap handler upon
	 * interception, so we do not set 'g_th' bit if only exc_instr_page_prot
	 * or exc_instr_page_miss happened (as those are precise traps, they
	 * will be regenerated by hardware anyway). */
	exceptions &= ~(exc_instr_page_prot_mask | exc_instr_page_miss_mask);

	if (exceptions)
		return true;

	return intc_ctxt->cu_num >= 0 && cu_hdr->exc_c;
}

static inline bool calculate_g_th(const intc_info_cu_hdr_t *cu_hdr,
		struct kvm_intc_cpu_context *intc_ctxt, bool *dump)
{
	bool g_th = g_th_exceptions(cu_hdr, intc_ctxt);
	bool coredump = intc_ctxt->coredump;

	*dump = coredump;
	if (coredump) {
		DebugCDUMP("CPU #%d detected coredump flag, exceptions %d\n",
			   smp_processor_id(), g_th);
	}
	WARN_ON(g_th && coredump);
	if (coredump && !g_th) {
		intc_ctxt->coredump = false;
		DebugCDUMP("CPU #%d reset coredump flag, exceptions 0x%llx\n",
			   smp_processor_id(), intc_ctxt->exceptions);
	}

	return g_th || coredump;
}

static void restore_sbbp(const u64 *sbbp)
{
	BUILD_BUG_ON(SBBP_ENTRIES_NUM != 32);
	asm volatile (
		"{rwd %[sbbp31], %%sbbp} {rwd %[sbbp30], %%sbbp}"
		"{rwd %[sbbp29], %%sbbp} {rwd %[sbbp28], %%sbbp}"
		"{rwd %[sbbp27], %%sbbp} {rwd %[sbbp26], %%sbbp}"
		"{rwd %[sbbp25], %%sbbp} {rwd %[sbbp24], %%sbbp}"
		"{rwd %[sbbp23], %%sbbp} {rwd %[sbbp22], %%sbbp}"
		"{rwd %[sbbp21], %%sbbp} {rwd %[sbbp20], %%sbbp}"
		"{rwd %[sbbp19], %%sbbp} {rwd %[sbbp18], %%sbbp}"
		"{rwd %[sbbp17], %%sbbp} {rwd %[sbbp16], %%sbbp}"
		"{rwd %[sbbp15], %%sbbp} {rwd %[sbbp14], %%sbbp}"
		"{rwd %[sbbp13], %%sbbp} {rwd %[sbbp12], %%sbbp}"
		"{rwd %[sbbp11], %%sbbp} {rwd %[sbbp10], %%sbbp}"
		"{rwd %[sbbp9], %%sbbp}  {rwd %[sbbp8], %%sbbp}"
		"{rwd %[sbbp7], %%sbbp}  {rwd %[sbbp6], %%sbbp}"
		"{rwd %[sbbp5], %%sbbp}  {rwd %[sbbp4], %%sbbp}"
		"{rwd %[sbbp3], %%sbbp}  {rwd %[sbbp2], %%sbbp}"
		"{rwd %[sbbp1], %%sbbp}  {rwd %[sbbp0], %%sbbp}"
		:
		: [sbbp31] "r" (sbbp[31]), [sbbp30] "r" (sbbp[30]),
		  [sbbp29] "r" (sbbp[29]), [sbbp28] "r" (sbbp[28]),
		  [sbbp27] "r" (sbbp[27]), [sbbp26] "r" (sbbp[26]),
		  [sbbp25] "r" (sbbp[25]), [sbbp24] "r" (sbbp[24]),
		  [sbbp23] "r" (sbbp[23]), [sbbp22] "r" (sbbp[22]),
		  [sbbp21] "r" (sbbp[21]), [sbbp20] "r" (sbbp[20]),
		  [sbbp19] "r" (sbbp[19]), [sbbp18] "r" (sbbp[18]),
		  [sbbp17] "r" (sbbp[17]), [sbbp16] "r" (sbbp[16]),
		  [sbbp15] "r" (sbbp[15]), [sbbp14] "r" (sbbp[14]),
		  [sbbp13] "r" (sbbp[13]), [sbbp12] "r" (sbbp[12]),
		  [sbbp11] "r" (sbbp[11]), [sbbp10] "r" (sbbp[10]),
		  [sbbp9] "r" (sbbp[9]), [sbbp8] "r" (sbbp[8]),
		  [sbbp7] "r" (sbbp[7]), [sbbp6] "r" (sbbp[6]),
		  [sbbp5] "r" (sbbp[5]), [sbbp4] "r" (sbbp[4]),
		  [sbbp3] "r" (sbbp[3]), [sbbp2] "r" (sbbp[2]),
		  [sbbp1] "r" (sbbp[1]), [sbbp0] "r" (sbbp[0]));
}


/*
 * There are TIR_NUM(19) tir regs. Bits 64 - 56 is current tir nr
 * After each NATIVE_READ_TIR_LO_REG() we will read next tir.
 * For more info see instruction set doc.
 * Read tir hi/lo regs order is significant
 */
static int restore_SBBP_TIRs_usincr(u64 sbbp[], e2k_tir_t TIRs[], int TIRs_num,
		e2k_usincr_t usincr, bool tir_fz, bool g_th, bool coredump)
{
	virt_ctrl_cu_t virt_ctrl_cu;
	int i;

	virt_ctrl_cu = read_VIRT_CTRL_CU_reg();

	/* Allow writing of TIRs, SBBP and %usincr */
	virt_ctrl_cu.tir_rst = 1;
	write_VIRT_CTRL_CU_reg(virt_ctrl_cu);

	if (unlikely(kvm_debug)) {
		/* Mark interception in guest's SBBP with magic number */
		memmove(&sbbp[1], sbbp, (SBBP_ENTRIES_NUM - 1) * sizeof(sbbp[0]));
		sbbp[0] = 0xbeef8888;
	}
	restore_sbbp(sbbp);

	/* Write %usincr even when guest is in v6 mode to avoid
	 * host information leak */
	if (cpu_has(CPU_FEAT_ISET_V7))
		native_write_USINCR_reg(usincr);

	if (unlikely(coredump)) {
		e2k_tir_t tir;
		int tir_no;

		/* empty TIRs is signal to do coredump */
		tir.ip = 0;
		tir.exc_al_aa_j = GET_CLEAR_TIR_HI(0);
		tir_no = 0;
		TIRs[tir_no] = tir;
		TIRs_num = tir_no;
	}
#pragma loop count (2)
	for (i = TIRs_num; i >= 0; i--) {
		native_write_TIR_reg(TIRs[i]);
	}
	/* Keep guest TIRs frozen after GLAUNCH */
	virt_ctrl_cu.tir_fz = tir_fz;

	/* Enter guest trap handler after GLAUNCH */
	virt_ctrl_cu.g_th = g_th;

	/* Forbid writing of TIRs and SBBP */
	virt_ctrl_cu.tir_rst = 0;
	write_VIRT_CTRL_CU_reg(virt_ctrl_cu);
	return TIRs_num;
}

static int kvm_e2k_check_request(struct kvm_vcpu *vcpu, struct kvm_intc_cpu_context *intc_ctxt)
{
	int r;

	/* Allocate a new GP_PPTB root (it may have been invalidated on memslot deletion) */
	if (kvm_check_request(KVM_REQ_MMU_RELOAD, vcpu)) {
		r = kvm_mmu_reload(vcpu,
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
				NULL,
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
				GP_ROOT_PT_FLAG);
		if (unlikely(r))
			return r;
	}

	if (kvm_check_request(KVM_REQ_TLB_FLUSH, vcpu) || cpu_has(CPU_HWBUG_VIRT_TLU_IB)) {
		trace_host_flush_tlb(vcpu);
		kvm_vcpu_flush_tlb(vcpu);
	}

	/* Following requests are only for SPT mode */
	kvm_clear_request(KVM_REQ_ADDR_FLUSH, vcpu);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (kvm_check_request(KVM_REQ_MMU_SYNC, vcpu)) {
		kvm_mmu_sync_roots(vcpu, OS_ROOT_PT_FLAG | U_ROOT_PT_FLAG);
	}
	intc_ctxt->coredump |= kvm_check_request(KVM_REQ_TO_COREDUMP, vcpu);
	if (intc_ctxt->coredump) {
		DebugCDUMP("CPU #%d set coredamp flag on vcpu #%d\n",
			   smp_processor_id(), vcpu->vcpu_id);
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	return 0;
}

static void kvm_set_g_tmr(void)
{
	if (kvm_g_tmr) {
		g_preempt_tmr_t tmr;

		AW(tmr) = 0;
		tmr.tmr = kvm_g_tmr;
		tmr.v = 1;
		write_G_PREEMPT_TMR_reg(tmr);
	}

}

static bool kvm_vcpu_exit_request(struct kvm_vcpu *vcpu)
{
	return vcpu->mode == EXITING_GUEST_MODE || kvm_request_pending(vcpu) ||
		xfer_to_guest_mode_work_pending();
}

/**
 * vcpu_enter_guest - handle single VCPU guest entry
 *
 * Checks whether VCPU can be run and then executes it.  Will
 * return here only on intercepts which are then be handled by
 * parse_INTC_registers().  Hypercalls are handled on separate
 * stacks (%bu_psp/%bu_pcsp) by kvm_generic_hcalls() instead.
 * The %usd data stack is shared between vcpu_enter_guest()
 * and hypercalls.
 *
 * Returns 0 on success and non-zero code on error or when
 * intercept must be handled by QEMU.
 */
int vcpu_enter_guest(struct kvm_vcpu *vcpu) __must_hold(vcpu)
{
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	gthread_info_t *gti = current_thread_info()->gthread_info;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	intc_info_cu_t *cu = &vcpu->arch.intc_ctxt.cu;
	intc_info_mu_t *mu = vcpu->arch.intc_ctxt.mu;
	struct kvm_intc_cpu_context *intc_ctxt = &vcpu->arch.intc_ctxt;
	u64 exceptions;
	bool g_th, dump;
	int r;

	r = kvm_e2k_check_request(vcpu, intc_ctxt);
	if (unlikely(r))
		return r;

	/* Do not allow values forbidden by hardware. */
	if (read_SH_PCSHTP_reg().ind < -32) {
		pr_emerg("kvm: SH_PCSHTP value %d is too small, halting guest\n",
			read_SH_PCSHTP_reg().ind);
		vcpu->arch.exit_reason = EXIT_REASON_VM_PANIC;
		return -EINVAL;
	}

	all_irq_disable();
	if (unlikely(kvm_rebooting)) {
		all_irq_enable();
		vcpu->arch.exit_shutdown_terminate = KVM_EXIT_E2K_SHUTDOWN;
		return 0;
	}

	/*
	 * Ensure we set mode to IN_GUEST_MODE after we disable
	 * interrupts and before the final VCPU requests check.
	 * See the comment in kvm_vcpu_exiting_guest_mode() and
	 * Documentation/virt/kvm/vcpu-requests.rst
	 */
	smp_store_mb(vcpu->mode, IN_GUEST_MODE);

	kvm_vcpu_srcu_read_unlock(vcpu);
	smp_mb__after_srcu_read_unlock();

	if (kvm_vcpu_exit_request(vcpu)) {
		smp_store_mb(vcpu->mode, OUTSIDE_GUEST_MODE);
		all_irq_enable();
		kvm_vcpu_srcu_read_lock(vcpu);
		return 0;
	}

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_running);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	/* Return to user will enable interrupts */
	trace_hardirqs_on();

	/* Check if guest should enter trap handler after glaunch. */
	g_th = calculate_g_th(&cu->header, intc_ctxt, &dump);
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	if (unlikely(intc_ctxt->start_gm)) {
		DebugKVMSTUP("start guest vm, g_th is %d\n"
			"     SH_OSCUD base 0x%llx size 0x%llx, SH_OSCUIR 0x%x\n",
			g_th,
			vcpu_cud_base(vcpu, vcpu->arch.hw_ctxt.sh_oscud),
			vcpu_cud_size(vcpu, vcpu->arch.hw_ctxt.sh_oscud),
			vcpu->arch.hw_ctxt.sh_oscuir.index);
		intc_ctxt->start_gm = false;
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	kvm_set_g_tmr();

	intc_ctxt->nr_TIRs = restore_SBBP_TIRs_usincr(intc_ctxt->sbbp, intc_ctxt->TIRs,
			intc_ctxt->nr_TIRs, intc_ctxt->usincr, cu->header.tir_fz, g_th, dump);
	if (dump) {
		DebugCDUMP("vcpu #%d with coredump flag, TIRs num is %d\n",
			   vcpu->vcpu_id, intc_ctxt->nr_TIRs);
		if (DEBUG_KVM_COREDUMP_MODE)
			print_all_TIRs(intc_ctxt->TIRs, intc_ctxt->nr_TIRs);
	}
	kvm_clear_vcpu_intc_TIRs_num(vcpu);

	/* if intc info structures were updated, then restore registers */
	if (kvm_get_intc_info_mu_is_updated(vcpu)) {
		modify_intc_info_mu_data(intc_ctxt->mu, intc_ctxt->mu_num);
		restore_intc_info_mu(intc_ctxt->mu, intc_ctxt->mu_num);
	}
	restore_intc_info_cu(&intc_ctxt->cu, intc_ctxt->cu_num);

	/* MMU intercepts were handled, clear state for new intercepts */
	kvm_clear_intc_mu_state(vcpu);

	/* clear hypervisor intercept event counters */
	intc_ctxt->cu_num = -1;
	intc_ctxt->mu_num = -1;
	intc_ctxt->cur_mu = -1;
	kvm_reset_intc_info_mu_is_updated(vcpu);

	/* Switch IRQ control to PSR and disable MI/NMIs */
	native_write_irq_barrier_PSR_reg(E2K_KERNEL_PSR_DISABLED_ALL);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* the function should set initial UPSR state */
	if (gti != NULL) {
		KVM_RESTORE_GUEST_KERNEL_UPSR(current_thread_info());
	}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	launch_hv_vcpu(&vcpu->arch);

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* Guest can switch to other thread, so update guest thread info */
	gti = current_thread_info()->gthread_info;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	save_intc_info_cu(cu, &vcpu->arch.intc_ctxt.cu_num);
	save_intc_info_mu(mu, &vcpu->arch.intc_ctxt.mu_num);

	/* See the comment in kvm_vcpu_exiting_guest_mode() */
	smp_store_mb(vcpu->mode, OUTSIDE_GUEST_MODE);

	/*
	 * %sbbp LIFO stack is unfreezed by writing %TIR register,
	 * so it must be read before TIRs.
	 */
	save_sbbp(intc_ctxt->sbbp);

	/*
	 * Save guest TIRs should be at any case, including empty state
	 */
	exceptions = 0;
	exceptions = save_tirs(intc_ctxt->TIRs, &intc_ctxt->nr_TIRs, &intc_ctxt->usincr, true);
	/* un-freeze the TIR's LIFO */
	native_unfreeze_TIRS();
	intc_ctxt->exceptions = exceptions;
	if (intc_ctxt->nr_TIRs < 0 && dump) {
		/* simulator bug: empty TIR0 was lost, restore here */
		e2k_tir_t tir;
		int tir_no;

		/* empty TIRs is signal to do coredump */
		tir.ip = 0;
		tir.exc_al_aa_j = GET_CLEAR_TIR_HI(0);
		tir_no = 0;
		intc_ctxt->TIRs[tir_no] = tir;
		intc_ctxt->nr_TIRs = tir_no;
		DebugCDUMP("vcpu #%d restored empty TIR0, TIRs num is %d\n",
			   vcpu->vcpu_id, intc_ctxt->nr_TIRs);
		if (DEBUG_KVM_COREDUMP_MODE)
			print_all_TIRs(intc_ctxt->TIRs, intc_ctxt->nr_TIRs);
	}

	trace_hardirqs_off();
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	/* save current state of guest kernel UPSR */
	if (gti != NULL) {
		e2k_upsr_t guest_upsr;

		guest_upsr = native_read_UPSR_reg();
		DO_SAVE_GUEST_KERNEL_UPSR(gti, guest_upsr);
	}

	kvm_do_update_guest_vcpu_current_runstate(vcpu, RUNSTATE_in_intercept);
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

	kvm_vcpu_srcu_read_lock(vcpu);

	/* This will enable interrupts */
	return parse_INTC_registers(vcpu);
}

static void kvm_epic_write_gstid(int gst_id)
{
	union cepic_gstid reg_gstid;

	reg_gstid.raw = 0;
	reg_gstid.gstid = gst_id;
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
	unsigned int gst_id = kvm->arch.vm_id;
	unsigned long flags;
	union cepic_dat reg;

	reg.raw = 0;
	reg.gst_id = gst_id;
	reg.gst_dst = vcpu_id;
	reg.index = cpu;
	reg.dat_cop = CEPIC_DAT_WRITE;

	raw_spin_lock_irqsave(&vcpu->arch.epic_dat_lock, flags);
	epic_write_d(CEPIC_DAT, reg.raw);

	/* Wait for status bit */
	do {
		cpu_relax();
		reg.raw = (unsigned long)epic_read_w(CEPIC_DAT);
	} while (reg.stat);
	vcpu->arch.epic_dat_active = true;
	raw_spin_unlock_irqrestore(&vcpu->arch.epic_dat_lock, flags);
}

void kvm_epic_invalidate_dat(struct kvm_vcpu_arch *vcpu)
{
	union cepic_dat reg;
	unsigned long flags;

	reg.raw = 0;
	reg.index = cpu_to_full_cepic_id(arch_to_vcpu(vcpu)->cpu);
	reg.dat_cop = CEPIC_DAT_INVALIDATE;

	raw_spin_lock_irqsave(&vcpu->epic_dat_lock, flags);
	epic_write_w(CEPIC_DAT, (unsigned int)reg.raw);

	/* Wait for status bit */
	do {
		cpu_relax();
		reg.raw = (unsigned long)epic_read_w(CEPIC_DAT);
	} while (reg.stat);

	vcpu->epic_dat_active = false;
	raw_spin_unlock_irqrestore(&vcpu->epic_dat_lock, flags);
}

static bool kvm_is_epic_timer_reg_stopped(union cepic_ctrl2 reg)
{
	return !!reg.timer_stop;
}

bool kvm_is_epic_timer_stopped(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	return kvm_is_epic_timer_reg_stopped(reg);
}

void kvm_epic_timer_start(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	WARN_ON_ONCE(!kvm_is_epic_timer_reg_stopped(reg));
	reg.timer_stop = 0;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void kvm_epic_timer_stop(bool skip_check)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	WARN_ON_ONCE(!skip_check && kvm_is_epic_timer_reg_stopped(reg));
	reg.timer_stop = 1;
	epic_write_w(CEPIC_CTRL2, reg.raw);
}

void kvm_epic_enable_int(void)
{
	union cepic_ctrl2 reg;

	reg.raw = epic_read_w(CEPIC_CTRL2);
	reg.mi_gst_blk = 0;
	reg.nmi_gst_blk = 0;
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
	if (reg.startup)
		kvm_hw_epic_deliver_to_icr(vcpu, reg.startup_entry,
					   CEPIC_ICR_DLVM_STARTUP);
}

void kvm_hv_epic_load(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	unsigned int gst_id = kvm->arch.vm_id;
	unsigned long epic_gstbase =
	    (unsigned long)__pa(page_address(kvm->arch.epic_pages));

	kvm_epic_write_gstid(gst_id);
	kvm_epic_write_gstbase(epic_gstbase);
	kvm_epic_write_dat(vcpu);
	kvm_epic_restore_pnmirr_startup_entry(vcpu);
}

static enum hrtimer_restart kvm_epic_idle_timer_fn(struct hrtimer *hrtimer)
{
	struct kvm_vcpu *vcpu =
	    container_of(hrtimer, struct kvm_vcpu, arch.cepic_idle);

	DebugKVMIT("started on VCPU #%d\n", vcpu->vcpu_id);
	vcpu->arch.unhalted = true;
	kvm_vcpu_wake_up(vcpu);

	return HRTIMER_NORESTART;
}

void kvm_init_cepic_idle_timer(struct kvm_vcpu *vcpu)
{
	ASSERT(vcpu != NULL);
	DebugKVMIT("started on VCPU #%d\n", vcpu->vcpu_id);

	hrtimer_init(&vcpu->arch.cepic_idle, CLOCK_MONOTONIC, HRTIMER_MODE_ABS);
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

	u64 new_timer_cur =
	    max(cepic_timer_ns * cepic_freq / NSEC_PER_SEC, 1ull);
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
		cepic->timer_cur =
		    calculate_cepic_timer_cur(vcpu, cepic_timer_cur);
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
