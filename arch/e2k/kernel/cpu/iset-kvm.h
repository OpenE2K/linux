/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#ifndef __E2K_CPU_ISET_KVM_H
#define __E2K_CPU_ISET_KVM_H

#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#ifdef CONFIG_SCLKR_CLOCKSOURCE
#include <asm/sclkr.h>
#endif

#include "iset-v6.h"
#include "iset-v7.h"

#if	defined(CONFIG_KVM_HW_VIRTUALIZATION) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is hardware virtualized host */

extern void mem_wait_vcpumask_set(int vcpu_id, struct cpumask *vcpu_mask);
extern void mem_wait_vcpumask_reset(int vcpu_id, struct cpumask *vcpu_mask);

static inline void mem_wait_vcpu_startup(int vcpu_id, struct cpumask *vcpu_mask)
{
	mem_wait_vcpumask_set(vcpu_id, vcpu_mask);
}

static inline void mem_wait_vcpu_wake_up(int vcpu_id, struct cpumask *vcpu_mask)
{
	mem_wait_vcpumask_reset(vcpu_id, vcpu_mask);
}

extern void save_epic_context(struct kvm_vcpu_arch *vcpu);
extern void restore_epic_context(const struct kvm_vcpu_arch *vcpu);

static inline void
kvm_save_host_context(struct kvm_vcpu *vcpu, e2k_iset_ver_t iset)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	unsigned long flags;
	struct kvm_arch *ka = &vcpu->kvm->arch;
	e2k_mmu_cr_t mmu_cr, old_mmu_cr;

	/*
	 * First of all the CORE_MODE register is saved to correctly understand
	 * the format and all fields of the registers-pointers (shadow PSP, PCSP...)
	 */
	hw_ctxt->sh_core_mode = read_SH_CORE_MODE_reg();
	E2K_WAIT_ALL_EX;

	/*
	 * Hardware Stack registers
	 */
	hw_ctxt->sh_psp = read_SH_PSP_reg();
	hw_ctxt->sh_pcsp = read_SH_PCSP_reg();
	hw_ctxt->bu_psp = read_BU_PSP_reg();
	hw_ctxt->bu_pcsp = read_BU_PCSP_reg();
	hw_ctxt->sh_pshtp = read_SH_PSHTP_reg();
	hw_ctxt->sh_pcshtp = read_SH_PCSHTP_reg();
	hw_ctxt->sh_wd = read_SH_WD_reg();

	/*
	 * MMU shadow context
	 */
	AW(hw_ctxt->sh_mmu_cr) = READ_SH_MMU_CR_REG_VALUE();
	hw_ctxt->sh_pid = READ_SH_PID_REG_VALUE();
	hw_ctxt->sh_os_pptb = READ_SH_OS_PPTB_REG_VALUE();
	hw_ctxt->gp_pptb = READ_GP_PPTB_REG_VALUE();
	hw_ctxt->sh_os_vptb = READ_SH_OS_VPTB_REG_VALUE();
	hw_ctxt->sh_os_vab = READ_SH_OS_VAB_REG_VALUE();
	hw_ctxt->gid = READ_GID_REG_VALUE();

	/*
	 * CPU shadow context
	 */
	hw_ctxt->sh_oscud = read_SH_OSCUD_reg();
	hw_ctxt->sh_osgd = read_SH_OSGD_reg();
	hw_ctxt->sh_oscutd = read_SH_OSCUTD_reg();
	hw_ctxt->sh_oscuir = read_SH_OSCUIR_reg();

	hw_ctxt->sh_osr0 = read_SH_OSR0_reg_value();

	/*
	 * CPU/MMU iset specific shadow context
	 */
	if (iset == E2K_ISET_V7) {
		save_sh_context_v7((struct kvm_vcpu *)vcpu);
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	} else if (iset == E2K_ISET_V6) {
		save_sh_context_v6(&vcpu->arch);
#endif
	} else {
		BUG();
	}

	if (iset == E2K_ISET_V7) {
		save_hst_context_v7(ka);
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	} else if (iset == E2K_ISET_V6) {
		save_hst_context_v6(ka);
#endif
	} else {
		BUG();
	}

	/*
	 * VIRT_CTRL_* registers
	 */
	hw_ctxt->virt_ctrl_cu = read_VIRT_CTRL_CU_reg();
	hw_ctxt->virt_ctrl_mu = READ_VIRT_CTRL_MU_REG();
	AW(hw_ctxt->g_w_imask_mmu_cr) = READ_G_W_IMASK_MMU_CR_REG_VALUE();

	/*
	 * INTC_INFO_* registers have to be saved immediately upon
	 * interception to handle it, so they are not saved here,
	 * but the hardware pointers should be cleared and VCPU marked as
	 * updated to recover ones if need.
	 */
	read_INTC_PTR_CU_reg_value();
	kvm_set_intc_info_cu_is_updated(vcpu);
	READ_INTC_PTR_MU();
	kvm_set_intc_info_mu_is_updated(vcpu);

	/*
	 * CEPIC context
	 * See comment before kvm_arch_vcpu_blocking() for details
	 * to save/restore cepic context
	 */
	if (cpu_has(CPU_FEAT_EPIC)) {
		if (!vcpu->arch.blocked) {
			save_epic_context(&vcpu->arch);
		} else {
			/* epic context should be already saved by kvm_vcpu_block() */
			BUG_ON(!kvm_is_epic_timer_stopped());
		}
	}

	/*
	 * Binco context
	 *
	 * Note that reading higher 32 bits of %u2_pptb depends
	 * on %mmu_cr.{slma,spae} bits, so we want to save %u2_pptb
	 * using guest's values of those bits; also cr0_pg=1 enables
	 * secondary space support and upt=0 avoids undefined
	 * behavior.
	 */
	raw_all_irq_save(flags);

	AW(old_mmu_cr) = NATIVE_GET_MMUREG(mmu_cr);
	mmu_cr = old_mmu_cr;
	mmu_cr.slma = hw_ctxt->sh_mmu_cr.slma;
	mmu_cr.spae = hw_ctxt->sh_mmu_cr.spae;
	mmu_cr.cr0_pg = 1;
	mmu_cr.upt = 0;
	NATIVE_SET_MMUREG(mmu_cr, AW(mmu_cr));
	hw_ctxt->u2_pptb = NATIVE_GET_MMUREG(u2_pptb);
	NATIVE_SET_MMUREG(mmu_cr, AW(old_mmu_cr));

	raw_all_irq_restore(flags);

	hw_ctxt->pid2 = NATIVE_GET_MMUREG(pid2);
	hw_ctxt->mpt_b = NATIVE_GET_MMUREG(mpt_b);
	hw_ctxt->pci_l_b = NATIVE_GET_MMUREG(pci_l_b);
	hw_ctxt->ph_h_b = NATIVE_GET_MMUREG(ph_h_b);
	hw_ctxt->ph_hi_l_b = NATIVE_GET_MMUREG(ph_hi_l_b);
	hw_ctxt->ph_hi_h_b = NATIVE_GET_MMUREG(ph_hi_h_b);
	hw_ctxt->pat = NATIVE_GET_MMUREG(pat);
	hw_ctxt->pdpte0 = NATIVE_GET_MMUREG(pdpte0);
	hw_ctxt->pdpte1 = NATIVE_GET_MMUREG(pdpte1);
	hw_ctxt->pdpte2 = NATIVE_GET_MMUREG(pdpte2);
	hw_ctxt->pdpte3 = NATIVE_GET_MMUREG(pdpte3);
}

static inline void
kvm_restore_host_context(const struct kvm_vcpu *vcpu, e2k_iset_ver_t iset)
{
	const struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;
	struct kvm_arch *ka = &vcpu->kvm->arch;
	unsigned long flags;
	e2k_mmu_cr_t mmu_cr, old_mmu_cr;

	/*
	 * First of all the CORE_MODE register is restored to correctly setup
	 * format and all fields of the registers-pointers (shadow PSP, PCSP...)
	 */
	write_SH_CORE_MODE_reg(hw_ctxt->sh_core_mode);
	E2K_WAIT_ALL_EX;

	/*
	 * Stack registers
	 */
	write_SH_PSP_reg(hw_ctxt->sh_psp);
	write_SH_PCSP_reg(hw_ctxt->sh_pcsp);
	write_BU_PSP_reg(hw_ctxt->bu_psp);
	write_BU_PCSP_reg(hw_ctxt->bu_pcsp);
	write_SH_PSHTP_reg(hw_ctxt->sh_pshtp);
	write_SH_PCSHTP_reg(hw_ctxt->sh_pcshtp);
	write_SH_WD_reg(hw_ctxt->sh_wd);

	/*
	 * MMU shadow context
	 */
	WRITE_SH_MMU_CR_REG_VALUE(AW(hw_ctxt->sh_mmu_cr));
	WRITE_SH_PID_REG_VALUE(hw_ctxt->sh_pid);
	WRITE_SH_OS_PPTB_REG_VALUE(hw_ctxt->sh_os_pptb);
	WRITE_GP_PPTB_REG_VALUE(hw_ctxt->gp_pptb);
	WRITE_SH_OS_VPTB_REG_VALUE(hw_ctxt->sh_os_vptb);
	WRITE_SH_OS_VAB_REG_VALUE(hw_ctxt->sh_os_vab);
	WRITE_GID_REG_VALUE(hw_ctxt->gid);

	/*
	 * CPU shadow context
	 */
	write_SH_OSCUD_reg(hw_ctxt->sh_oscud);
	write_SH_OSGD_reg(hw_ctxt->sh_osgd);
	write_SH_OSCUTD_reg(hw_ctxt->sh_oscutd);
	write_SH_OSCUIR_reg(hw_ctxt->sh_oscuir);

	write_SH_OSR0_reg_value(hw_ctxt->sh_osr0);

	/*
	 * CPU/MMU iset specific shadow context
	 */
	if (iset == E2K_ISET_V7) {
		restore_sh_context_v7((struct kvm_vcpu *)vcpu);
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	} else if (iset == E2K_ISET_V6) {
		restore_sh_context_v6(&vcpu->arch);
#endif
	} else {
		BUG();
	}

	if (iset == E2K_ISET_V7) {
		restore_hst_context_v7(ka);
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	} else if (iset == E2K_ISET_V6) {
		restore_hst_context_v6(ka);
#endif
	} else {
		BUG();
	}

	/*
	 * VIRT_CTRL_* registers
	 */
	write_VIRT_CTRL_CU_reg(hw_ctxt->virt_ctrl_cu);
	WRITE_VIRT_CTRL_MU_REG(hw_ctxt->virt_ctrl_mu);
	WRITE_G_W_IMASK_MMU_CR_REG_VALUE(AW(hw_ctxt->g_w_imask_mmu_cr));

	/*
	 * INTC_INFO_* registers were saved immediately upon
	 * interception to handle it, and will be restored
	 * by interceptions handler if it need.
	 */

	/*
	 * CEPIC context
	 */
	if (cpu_has(CPU_FEAT_EPIC)) {
		if (!vcpu->arch.blocked) {
			restore_epic_context(&vcpu->arch);
		} else {
			/* epic context will be restored by kvm_vcpu_block() */
			BUG_ON(!kvm_is_epic_timer_stopped());
		}
	}

	/*
	 * Binco context
	 *
	 * Note that writing higher 32 bits of %u2_pptb depends
	 * on %mmu_cr.{slma,spae} bits, so we want to save %u2_pptb
	 * using guest's values of those bits; also cr0_pg=1 enables
	 * secondary space support.
	 */
	raw_all_irq_save(flags);

	AW(old_mmu_cr) = NATIVE_GET_MMUREG(mmu_cr);
	mmu_cr = old_mmu_cr;
	mmu_cr.slma = hw_ctxt->sh_mmu_cr.slma;
	mmu_cr.spae = hw_ctxt->sh_mmu_cr.spae;
	mmu_cr.cr0_pg = 1;
	NATIVE_SET_MMUREG(mmu_cr, AW(mmu_cr));
	NATIVE_SET_MMUREG(u2_pptb, hw_ctxt->u2_pptb);
	NATIVE_SET_MMUREG(mmu_cr, AW(old_mmu_cr));

	raw_all_irq_restore(flags);

	NATIVE_SET_MMUREG(pid2, hw_ctxt->pid2);
	NATIVE_SET_MMUREG(mpt_b, hw_ctxt->mpt_b);
	NATIVE_SET_MMUREG(pci_l_b, hw_ctxt->pci_l_b);
	NATIVE_SET_MMUREG(ph_h_b, hw_ctxt->ph_h_b);
	NATIVE_SET_MMUREG(ph_hi_l_b, hw_ctxt->ph_hi_l_b);
	NATIVE_SET_MMUREG(ph_hi_h_b, hw_ctxt->ph_hi_h_b);
	NATIVE_SET_MMUREG(pat, hw_ctxt->pat);
	NATIVE_SET_MMUREG(pdpte0, hw_ctxt->pdpte0);
	NATIVE_SET_MMUREG(pdpte1, hw_ctxt->pdpte1);
	NATIVE_SET_MMUREG(pdpte2, hw_ctxt->pdpte2);
	NATIVE_SET_MMUREG(pdpte3, hw_ctxt->pdpte3);
}
#else
static inline void kvm_save_host_context(struct kvm_vcpu *vcpu, e2k_iset_ver_t iset) {}
static inline void kvm_restore_host_context(const struct kvm_vcpu *vcpu, e2k_iset_ver_t iset) {}

#endif /* CONFIG_KVM_HW_VIRTUALIZATION && !CONFIG_KVM_GUEST_KERNEL */

#endif /* __E2K_CPU_ISET_KVM_H */

