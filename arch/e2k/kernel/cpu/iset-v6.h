/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#ifndef __E2K_CPU_ISET_V6_H
#define __E2K_CPU_ISET_V6_H

#ifdef CONFIG_SCLKR_CLOCKSOURCE
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/sclkr.h>

static __always_inline void
save_sh_context_v6(struct kvm_vcpu_arch *vcpu)
{
	struct kvm_hw_cpu_context *hw_ctxt = &vcpu->hw_ctxt;

	/* CPU shadow context */
	hw_ctxt->sh_sclkm3 = read_SH_SCLKM3_reg_value();
}

static __always_inline void
restore_sh_context_v6(const struct kvm_vcpu_arch *vcpu)
{
	const struct kvm_hw_cpu_context *hw_ctxt = &vcpu->hw_ctxt;

	/* CPU shadow context */
	write_SH_SCLKM3_reg_value(hw_ctxt->sh_sclkm3);
}

static __always_inline void
restore_hst_context_v6(struct kvm_arch *ka)
{
	/*
	 * Guest last idle time is not deducted from the guest's time.
	 * That is, saved SCLKM3 of the guest is not changed by the host.
	 */
	write_SH_SCLKM3_reg_value(ka->hst_t_off);
	/* Guest time run resumed (including still sleeping vcpu-s) */
}
#endif
#endif /* __E2K_CPU_ISET_V6_H */
