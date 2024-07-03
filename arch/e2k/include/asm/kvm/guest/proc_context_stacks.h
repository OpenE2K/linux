/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef KVM_GUEST_PROC_CTXT_STACKS
#define KVM_GUEST_PROC_CTXT_STACKS

#include <linux/mm_types.h>

#include <asm/machdep.h>
#include <asm/trap_table.h>
#include <asm/kvm/proc_context_types.h>
#include <asm/copy-hw-stacks.h>

static inline int
kvm_mkctxt_prepare_hw_user_stacks(void __user *user_func, void *args,
		u64 args_size, size_t d_stack_sz, int format,
		void __user *tramp_ps_frames, void __user *ps_frames,
		e2k_mem_crs_t __user *cs_frames, const void __user *uc_link)
{
	unsigned long tramp_ps_frames_k, ps_frames_k, cs_frames_k;
	struct page *pg_tramp_ps_frames, *pg_ps_frames, *pg_cs_frames;
	int ret = 0;

	/* Get kernel address for procedure stack */
	pg_tramp_ps_frames = get_user_addr_to_kernel_page((unsigned long) tramp_ps_frames);
	if (IS_ERR_OR_NULL(pg_tramp_ps_frames)) {
		ret = (IS_ERR(pg_tramp_ps_frames)) ? PTR_ERR(pg_tramp_ps_frames) : -EINVAL;
		if (ret)
			return ret;
	} else {
		tramp_ps_frames_k = ((unsigned long)page_address(pg_tramp_ps_frames)) +
				(((unsigned long) tramp_ps_frames) & ~PAGE_MASK);
	}

	pg_ps_frames = get_user_addr_to_kernel_page((unsigned long)ps_frames);
	if (IS_ERR_OR_NULL(pg_ps_frames)) {
		ret = (IS_ERR(pg_ps_frames)) ? PTR_ERR(pg_ps_frames) : -EINVAL;
		if (ret)
			goto out_pg_tramp_ps;
	} else {
		ps_frames_k = ((unsigned long)page_address(pg_ps_frames)) +
				(((unsigned long)ps_frames) & ~PAGE_MASK);
	}

	/* Get kernel address for chain stack */
	pg_cs_frames = get_user_addr_to_kernel_page((unsigned long)cs_frames);
	if (IS_ERR_OR_NULL(pg_cs_frames)) {
		ret = (IS_ERR(pg_cs_frames)) ? PTR_ERR(pg_cs_frames) : -EINVAL;
		if (ret)
			goto out_pg_ps;
	} else {
		cs_frames_k = ((unsigned long)page_address(pg_cs_frames)) +
			(((unsigned long)cs_frames) & ~PAGE_MASK);
	}

	kvm_proc_ctxt_hw_stacks_t hw_stacks = {
		.user_func = user_func,
		.args = args,
		.args_size = args_size,
		.d_stack_sz = d_stack_sz,
		.format = format,
		.trampoline_ps_frames = (void *) tramp_ps_frames_k,
		.ps_frames = (void *) ps_frames_k,
		.cs_frames = (e2k_mem_crs_t *) cs_frames_k,
		.uc_link = uc_link,
	};

	ret = HYPERVISOR_prepare_mkctxt_hw_user_stacks(&hw_stacks);

	put_user_addr_to_kernel_page(pg_cs_frames);
out_pg_ps:
	put_user_addr_to_kernel_page(pg_ps_frames);
out_pg_tramp_ps:
	put_user_addr_to_kernel_page(pg_tramp_ps_frames);

	return ret;
}

static inline int mkctxt_prepare_hw_user_stacks(void __user *user_func,
		void *args, u64 args_size, size_t d_stack_sz, int format,
		void __user *tramp_ps_frames, void __user *ps_frames,
		e2k_mem_crs_t __user *cs_frames, const void __user *uc_link)
{
	if (IS_HV_GM()) {
		return native_mkctxt_prepare_hw_user_stacks(user_func, args, args_size,
				d_stack_sz, format, tramp_ps_frames, ps_frames,
				cs_frames, uc_link);
	} else {
		return kvm_mkctxt_prepare_hw_user_stacks(user_func, args, args_size,
				d_stack_sz, format, tramp_ps_frames, ps_frames,
				cs_frames, uc_link);
	}
}

#endif /* KVM_GUEST_PROC_CTXT_STACKS */
