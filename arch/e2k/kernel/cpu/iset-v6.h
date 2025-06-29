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
save_hst_context_v6(struct kvm_arch *ka)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
	/* The last still runnig vcpu saves it's leaving cpu time */
	if (!redpill)
		if (ka->num_sclkr_run-- == 1) {
			ka->hst_t_leave = read_sclkr(NULL);
			/* Guest time run paused */
		}
	raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);
}

static __always_inline void
restore_hst_context_v6(struct kvm_arch *ka)
{
	unsigned long flags;
	long long sclkr_tm;

	raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
	/* If kernel param redpill==0
	 * the first activated vcpu calculates t_off if guest time was frozen:
	 * T_leave = T_resume;
	 * T_leave is sh_t_leavea;         sclkm3 is hst_t_off.
	 * T_resume = read_sclkr(considering sh_sclkm3_new) =
	 *         read_sclkr(considering sclkm3_old) - hst_t_off_old +
	 *                                                      hst_t_off_new
	 * hst_t_off_new = hst_t_leave - (read_sclkr() - ka->hst_t_off)
	 *							hst_t_off_new
	 * If redpill==1 then guest last idle time
	 * is not deducted from the guest's time
	 * that is, saved SCLKM3 and vcpus_idl_tm of the guest
	 * is not changed by the host
	 */
	if (!redpill)
		if (ka->num_sclkr_run++ == 0) {
			sclkr_tm = read_sclkr(NULL);
			ka->hst_t_off = ka->hst_t_leave -
				(sclkr_tm - ka->hst_t_off);
			ka->vcpus_idl_tm += sclkr_tm - ka->hst_t_leave;
		}
	write_SH_SCLKM3_reg_value(ka->hst_t_off);
	/* Guest time run resumed (including still sleeping vcpu-s) */
	raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);
}
#endif
#endif /* __E2K_CPU_ISET_V6_H */
