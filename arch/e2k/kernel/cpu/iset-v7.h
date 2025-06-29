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
save_hst_context_v7(struct kvm_arch *ka)
{
	unsigned long flags;
	raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
	/* The last still runnig vcpu saves T_ABS_leave
	 * Guest time run paused/frozen at T_ABS_leave */
	if (redpill)
		if (ka->num_sclkr_run-- == 1) {
			ka->hst_t_leave = read_T_ABS();
		}
	raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);
}

static __always_inline void
restore_hst_context_v7(struct kvm_arch *ka)
{
	unsigned long flags;
	long long t_abs;

	raw_spin_lock_irqsave(&ka->sh_sclkr_lock, flags);
	/* If kernel param redpill==0
	 * the first activated vcpu calculates T_off if guest time was frozen
	 * T_ABS_leave = T_ABS_resume;
	 * T_ABS_leave = (T_ABS(considering old T_OFF) - hst_t_off_old) +
	 *							hst_t_off_new
	 * If redpill==1 then guest last idle time
	 * is not deducted from the guest's time
	 * that is, saved T_OFF  and vcpus_idl_tm of the guest
	 * is not changed by the host
	 */
	if (!redpill)
		if (ka->num_sclkr_run++ == 0) {
			t_abs = read_T_ABS();
			ka->hst_t_off = ka->hst_t_leave -
						(t_abs - ka->hst_t_off);
			ka->vcpus_idl_tm += t_abs - ka->hst_t_leave;
		}
	write_SH_T_off_reg(ka->hst_t_off);
	/* Guest time run resumed (including still sleeping vcpu-s) */
	raw_spin_unlock_irqrestore(&ka->sh_sclkr_lock, flags);
}

#endif /* __E2K_CPU_ISET_V7_H */
