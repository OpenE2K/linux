/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#ifndef __E2K_CPU_ISET_V7_H
#define __E2K_CPU_ISET_V7_H

#include <asm/kvm/cpu_hv_regs_access.h>

static __always_inline void
save_sh_context_v7(struct kvm_vcpu *vcpu)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

	/* CPU shadow context */
	hw_ctxt->sh_t_off = read_SH_T_off_reg();

	/* MMU shadow context */
	AW(hw_ctxt->sh_os_madmr) = READ_SH_OS_MADMR_REG_VALUE();
}

static __always_inline void
restore_sh_context_v7(struct kvm_vcpu *vcpu)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->arch.hw_ctxt;

	/* CPU shadow context */
	write_SH_T_off_reg(hw_ctxt->sh_t_off);

	/* MMU shadow context */
	WRITE_SH_OS_MADMR_REG_VALUE(AW(hw_ctxt->sh_os_madmr));
}

static __always_inline void
restore_hst_context_v7(struct kvm_arch *ka)
{
	/*
	 * Guest last idle time is not deducted from the guest's time.
	 * That is, saved T_OFF of the guest is not changed by the host.
	 */
	write_SH_T_off_reg(ka->hst_t_off);
	/* Guest time run resumed (including still sleeping vcpu-s) */
}

#endif /* __E2K_CPU_ISET_V7_H */
