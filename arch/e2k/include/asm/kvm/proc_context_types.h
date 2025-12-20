/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef KVM_PROC_CTXT_TYPES
#define KVM_PROC_CTXT_TYPES

#include <linux/types.h>

#include <asm/cpu_regs_types.h>

typedef struct kvm_proc_ctxt_hw_stacks {
	void (*user_func)(void);
	void *args;
	u64 args_size;
	size_t d_stack_sz;
	int format;
	e2k_mem_ps_t *trampoline_ps_frames;
	e2k_mem_ps_t *ps_frames;
	e2k_mem_crs_t *cs_frames;
	const void __user *uc_link;
} kvm_proc_ctxt_hw_stacks_t;

#endif /* KVM_PROC_CTXT_TYPES */
