/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/clocksource.h>

#include <asm/fast_syscalls.h>


/*
 * Guest trap table cannot be placed into host kernel table because of
 * host table is located in privileged area.
 * FIXME: to improve locality, fast syscalls tables should be located
 * in the .text section nearly to the OS entry code.
 */

int notrace kvm_fast_sys_set_return(u64 ip, int flags)
{
	if (IS_HV_GM()) {
		return native_do_fast_sys_set_return(ip, flags);
	} else {
		thread_info_t *gti = READ_CURRENT_REG();

		return HYPERVISOR_set_return_user_ip((u64) gti, ip, flags);
	}
}

