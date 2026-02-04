/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef PROC_CTXT_STACKS
#define PROC_CTXT_STACKS

#include <linux/types.h>

#include <asm/mmu.h>

extern int native_mkctxt_prepare_hw_user_stacks(void __user *user_func,
		void __user *args, u64 args_size, size_t dstack_free_size,
		size_t dstack_frame_size, int format,
		void __priv *tramp_ps_frames, void __priv *ps_frames,
		e2k_mem_crs_t __priv *cs_frames, const void __user *uc_link);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/proc_context_stacks.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without or with virtualization support */

static inline int mkctxt_prepare_hw_user_stacks(void (__user *user_func)(void),
		void __user *args, u64 args_size, size_t dstack_free_size,
		size_t dstack_frame_size, int format,
		void __priv *tramp_ps_frames, void __priv *ps_frames,
		e2k_mem_crs_t __priv *cs_frames, const void __user *uc_link)
{
	return native_mkctxt_prepare_hw_user_stacks(user_func, args, args_size,
			dstack_free_size, dstack_frame_size, format,
			tramp_ps_frames, ps_frames, cs_frames, uc_link);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* PROC_CTXT_STACKS */
