/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/thread_info.h>
#include <asm/kvm/regs_state.h>
#include <asm/kvm/switch.h>

notrace void host_syscall_guest_exit_trap(struct thread_info *ti,
						struct pt_regs *regs)
{
	if (likely(!test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)))
		return;

	/* CUTD register restore is important on host for guest syscall */
	HOST_RESTORE_USER_CUT_REGS(ti, regs, true);

	/* host return to paravirtualized guest (VCPU) mode */
	host_syscall_pv_vcpu_exit_trap(ti, regs);

	host_switch_trap_enable_mask(ti, regs, true);
}
