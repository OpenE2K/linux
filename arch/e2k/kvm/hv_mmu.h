/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_HV_MMU_H
#define __KVM_E2K_HV_MMU_H

#include <linux/types.h>
#include <linux/kvm_host.h>
#include "pv_mmu.h"

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
extern void kvm_setup_mmu_intc_mode(struct kvm_vcpu *vcpu);
extern void kvm_reset_mmu_intc_mode(struct kvm_vcpu *vcpu);
extern int kvm_hv_setup_tdp_paging(struct kvm_vcpu *vcpu);
#else
static inline void kvm_setup_mmu_intc_mode(struct kvm_vcpu *vcpu) { }
static inline void kvm_reset_mmu_intc_mode(struct kvm_vcpu *vcpu) { }
static inline int kvm_hv_setup_tdp_paging(struct kvm_vcpu *vcpu)
{
	return -EINVAL;
}
#endif /* CONFIG_KVM_HW_VIRTUALIZATION */

extern void kvm_setup_mmu_spt_context(struct kvm_vcpu *vcpu);
extern int vcpu_write_trap_point_mmu_reg(struct kvm_vcpu *vcpu,
					 gpa_t tc_gpa, hpa_t *tc_hpap);
extern int vcpu_write_mmu_pid_reg(struct kvm_vcpu *vcpu, mmu_reg_t pid);
extern int vcpu_write_mmu_cr_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t mmu_cr);
extern int vcpu_write_mmu_u_pptb_reg(struct kvm_vcpu *vcpu, pgprotval_t u_pptb,
					bool *pt_updated, hpa_t *u_root);
extern int vcpu_write_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, gva_t u_vptb);
extern int vcpu_write_mmu_os_pptb_reg(struct kvm_vcpu *vcpu,
			pgprotval_t os_pptb, bool *pt_updated, hpa_t *os_root);
extern int vcpu_write_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, gva_t os_vptb);
extern int vcpu_write_mmu_os_vab_reg(struct kvm_vcpu *vcpu, gva_t os_vab);
extern int vcpu_read_trap_point_mmu_reg(struct kvm_vcpu *vcpu, gpa_t *tc_gpa);
extern int vcpu_read_mmu_cr_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t *mmu_cr);
extern int vcpu_read_mmu_u_pptb_reg(struct kvm_vcpu *vcpu,
			pgprotval_t *u_pptb_p);
extern int vcpu_read_mmu_os_pptb_reg(struct kvm_vcpu *vcpu,
			pgprotval_t *os_pptb_p);
extern int vcpu_read_mmu_u_vptb_reg(struct kvm_vcpu *vcpu, gva_t *u_vptb_p);
extern int vcpu_read_mmu_os_vptb_reg(struct kvm_vcpu *vcpu, gva_t *os_vptb_p);
extern int vcpu_read_mmu_os_vab_reg(struct kvm_vcpu *vcpu, gva_t *os_vab_p);

extern bool kvm_mmu_is_hv_paging(struct kvm_vcpu *vcpu);

static inline e2k_mmu_cr_t read_guest_MMU_CR_reg(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.is_hv)) {
		return read_SH_MMU_CR_reg();
	} else if (vcpu->arch.is_pv) {
		return read_pv_MMU_CR_reg(vcpu);
	} else {
		E2K_KVM_BUG_ON(true);
		WARN_ON_ONCE(1);
		return MMU_CR_KERNEL;
	}
}

static inline void
write_guest_MMU_CR_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t value)
{
	if (likely(vcpu->arch.is_hv)) {
		write_SH_MMU_CR_reg(value);
	} else if (vcpu->arch.is_pv) {
		write_pv_MMU_CR_reg(vcpu, value);
	} else {
		E2K_KVM_BUG_ON(true);
	}
}

static inline mmu_reg_t read_guest_PID_reg(struct kvm_vcpu *vcpu)
{
	if (likely(vcpu->arch.is_hv)) {
		return read_SH_PID_reg();
	} else if (vcpu->arch.is_pv) {
		return read_pv_PID_reg(vcpu);
	} else {
		E2K_KVM_BUG_ON(true);
	}
	return (mmu_reg_t) -1;
}

static inline void
write_guest_PID_reg(struct kvm_vcpu *vcpu, mmu_reg_t value)
{
	if (likely(vcpu->arch.is_hv)) {
		write_SH_PID_reg(value);
	} else if (vcpu->arch.is_pv) {
		write_pv_PID_reg(vcpu, value);
	} else {
		E2K_KVM_BUG_ON(true);
	}
}

#endif	/* __KVM_E2K_HV_MMU_H */
