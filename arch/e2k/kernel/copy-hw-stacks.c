/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/types.h>

#include <asm/ptrace.h>
#include <asm/copy-hw-stacks.h>

#define CREATE_TRACE_POINTS
#include <asm/kvm/trace-hw-stacks.h>

/**
 * user_hw_stacks_copy_full - copy part of user stacks that was SPILLed
 *	into kernel back to user stacks.
 * @stacks: saved user stack registers
 * @regs: pt_regs pointer
 * @crs: last frame to copy
 *
 * If @crs is not NULL then the frame pointed to by it will also be copied
 * to userspace.  Note that 'stacks->pcsp_hi.ind' is _not_ updated after
 * copying since it would leave stack in inconsistent state (with two
 * copies of the same @crs frame), this is left to the caller.
 *
 * Inlining this reduces the amount of memory to copy in
 * collapse_kernel_hw_stacks().
 */
int user_hw_stacks_copy_full(struct e2k_stacks *stacks,
			     pt_regs_t *regs, e2k_mem_crs_t *crs)
{
	return do_user_hw_stacks_copy_full(stacks, regs, crs);
}

