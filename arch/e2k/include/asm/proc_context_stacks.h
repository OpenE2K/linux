/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef PROC_CTXT_STACKS
#define PROC_CTXT_STACKS

#include <linux/types.h>

#include <asm/mmu.h>

extern int native_mkctxt_prepare_hw_user_stacks(void __user *user_func,
		void *args, u64 args_size, size_t d_stack_sz, int format,
		void __user *tramp_ps_frames, void __user *ps_frames,
		e2k_mem_crs_t __user *cs_frames, const void __user *uc_link);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/proc_context_stacks.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without or with virtualization support */

static inline int mkctxt_prepare_hw_user_stacks(void (*user_func)(void),
		void *args, u64 args_size, size_t d_stack_sz, int format,
		void __user *tramp_ps_frames, void __user *ps_frames,
		e2k_mem_crs_t __user *cs_frames, const void __user *uc_link)
{
	return native_mkctxt_prepare_hw_user_stacks(user_func, args, args_size,
			d_stack_sz, format, tramp_ps_frames, ps_frames,
			cs_frames, uc_link);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* PROC_CTXT_STACKS */
