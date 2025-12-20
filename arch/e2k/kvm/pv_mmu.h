/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_PV_MMU_H
#define __KVM_E2K_PV_MMU_H

#include <linux/types.h>
#include <linux/kvm_host.h>

/*
 * Paravirtualized guest has not hardware shadow register.
 *
 * Any write to shadow MMU register shuld be duplicated by setting
 * appropriate field at the structures 'hw_ctxt' or 'sw_ctxt'.
 * So write to nonexistent register can be omitted.
 *
 * Any read from nonexistent register can be changed by read
 * from appropriate field at the structures
 */

static inline e2k_mmu_cr_t read_pv_MMU_CR_reg(struct kvm_vcpu *vcpu)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

	return hw_ctxt->sh_mmu_cr;
}

static inline void
write_pv_MMU_CR_reg(struct kvm_vcpu *vcpu, e2k_mmu_cr_t value)
{
}

static inline mmu_reg_t read_pv_PID_reg(struct kvm_vcpu *vcpu)
{
	struct kvm_mmu *mmu = &vcpu->arch.mmu;

	return mmu->pid;
}

static inline void
write_pv_PID_reg(struct kvm_vcpu *vcpu, mmu_reg_t value)
{
}

#endif	/* __KVM_E2K_PV_MMU_H */
