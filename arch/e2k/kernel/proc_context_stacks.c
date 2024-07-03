/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/uaccess.h>

#include <asm/proc_context_stacks.h>
#include <asm/mmu_types.h>
#include <asm/thread_info.h>
#include <asm/e2k_ptypes.h>
#include <asm/debug_print.h>
#include <asm/cpu_regs_types.h>
#include <asm/mmu_fault.h>
#include <asm/hw_stacks.h>
#include <asm/process.h>
#include <asm/protected_syscalls.h>
#include <asm/ucontext.h>

#define	DEBUG_CTX_STACK_MODE	0	/* hw stacks for contexts */
#define	DebugCTX_STACK(...)	DebugPrint(DEBUG_CTX_STACK_MODE, ##__VA_ARGS__)


int native_mkctxt_prepare_hw_user_stacks(void __user *user_func,
		void *args, u64 args_size, size_t d_stack_sz, int format,
		void __user *tramp_ps_frames, void __user *ps_frames,
		e2k_mem_crs_t __user *cs_frames, const void __user *uc_link)
{
	e2k_mem_crs_t crs_trampoline, crs_user;
	unsigned long ts_flag;
	void *trampoline;
	bool protected = (format == CTX_128_BIT);
	int ret, i;

	/*
	 * Put uc_link pointer into trampoline frame
	 */
	if (format == CTX_32_BIT) {
		u32 link;

		if (get_user(link, (u32 __user *) uc_link))
			return -EFAULT;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user(link, (u32 __user *) tramp_ps_frames);
		clear_ts_flag(ts_flag);
	} else if (format == CTX_64_BIT) {
		u64 link;

		if (get_user(link, (u64 __user *) uc_link))
			return -EFAULT;

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user(link, (u64 __user *) tramp_ps_frames);
		clear_ts_flag(ts_flag);
	} else {
		e2k_ptr_t link;
		u32 tag;

		if (get_user_tagged_16(link.lo, link.hi, tag, uc_link))
			return -EFAULT;

		if (tag == ETAGNPQ && !link.lo && !link.hi) {
			/* Null pointer */
		} else if (tag == ETAGAPQ && e2k_ptr_size(link.lo, link.hi,
				offsetofend(struct ucontext_prot, uc_extra.pfpfr))) {
			/* Good descriptor */
		} else {
			return -EINVAL;
		}

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user_tagged_16_offset(link.lo, link.hi, tag,
				tramp_ps_frames, machine.qnr1_offset);
		clear_ts_flag(ts_flag);
	}
	if (ret)
		return -EFAULT;

	for (i = 0; i < args_size / 16; i++) {
		u64 val_lo, val_hi;
		u8 tag_lo, tag_hi, tag;

		if (IS_ALIGNED((unsigned long) args, 16)) {
			load_qvalue_and_tagq((unsigned long) (args + 16 * i),
					&val_lo, &val_hi, &tag_lo, &tag_hi);
		} else {
			/* Can happen in 32 and 64 bit modes */
			load_value_and_tagd(args + 16 * i, &val_lo, &tag_lo);
			load_value_and_tagd(args + 16 * i + 8, &val_hi, &tag_hi);
		}
		tag = (tag_hi << 4) | tag_lo;
		DebugCTX_STACK("register arguments: 0x%llx 0x%llx\n",
				val_lo, val_hi);


		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user_tagged_16_offset(val_lo, val_hi, tag,
				ps_frames + EXT_4_NR_SZ * i, machine.qnr1_offset);
		clear_ts_flag(ts_flag);
		if (ret)
			return -EFAULT;
	}

	if (2 * i < args_size / 8) {
		u64 val;
		u8 tag;

		load_value_and_tagd(args + 16 * i, &val, &tag);

		ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
		ret = __put_user_tagged_8(val, tag,
				(u64 __user *) (ps_frames + EXT_4_NR_SZ * i));
		clear_ts_flag(ts_flag);
		if (ret)
			return -EFAULT;
		DebugCTX_STACK("register arguments: 0x%llx\n", val);
	}

	if (format == CTX_128_BIT) {
		trampoline = (void *) makecontext_trampoline_128;
	} else if (format == CTX_64_BIT) {
		trampoline = (void *) makecontext_trampoline_64;
	} else if (format == CTX_32_BIT) {
		trampoline = (void *) makecontext_trampoline_32;
	} else {
		return -EINVAL;
	}
	ret = chain_stack_frame_init(&crs_trampoline, trampoline,
			d_stack_sz, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	ret = ret ?: chain_stack_frame_init(&crs_user, (void __force *) user_func,
			d_stack_sz, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	if (ret)
		return ret;

	ts_flag = set_ts_flag(TS_KERNEL_SYSCALL);
	ret = __clear_user(&cs_frames[1], SZ_OF_CR);
	ret = ret ?: __copy_to_user(&cs_frames[2], &crs_trampoline, SZ_OF_CR);
	ret = ret ?: __copy_to_user(&cs_frames[3], &crs_user, SZ_OF_CR);
	clear_ts_flag(ts_flag);
	if (ret)
		return -EFAULT;

	return 0;
}
