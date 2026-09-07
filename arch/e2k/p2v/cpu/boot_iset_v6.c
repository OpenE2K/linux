/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_api.h>
#include <asm/mmu_regs.h>
#include <asm/kvm/hypercall.h>

#ifdef CONFIG_KVM_GUEST_HW_HCALL
unsigned long light_hw_hypercall(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6)
{
	unsigned long ret;

	ret = E2K_HCALL(LINUX_HCALL_LIGHT_TRAPNUM, nr, 6,
			arg1, arg2, arg3, arg4, arg5, arg6);
	return ret;
}

u64 generic_hw_hypercall(u64 nr, u64 arg1, u64 arg2, u64 arg3,
			 u64 arg4, u64 arg5, u64 arg6, u64 arg7)
{
	unsigned long ret;
	e2k_upsr_t upsr_before, upsr_after;

	upsr_before = native_read_UPSR_reg();
	ret = E2K_HCALL(LINUX_HCALL_GENERIC_TRAPNUM, nr, 7,
			arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	upsr_after = native_read_UPSR_reg();
	WARN_ON_ONCE(upsr_before.word != upsr_after.word);
	return ret;
}
#endif
