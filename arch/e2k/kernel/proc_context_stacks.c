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
		void __user *args, u64 args_size, size_t dstack_free_size,
		size_t dstack_frame_size, int format,
		void __priv *tramp_ps_frames, void __priv *ps_frames,
		e2k_mem_crs_t __priv *cs_frames, const void __user *uc_link)
{
	e2k_mem_crs_t crs_trampoline, crs_user;
	unsigned long trampoline;
	bool protected = (format == CTX_128_BIT);
	int ret, i;

	/*
	 * Put uc_link pointer into trampoline frame
	 */
	if (format == CTX_32_BIT) {
		u32 link;

		if (get_user(link, (u32 __user *) uc_link))
			return -EFAULT;

		ret = put_priv(link, (u32 __priv *) tramp_ps_frames);
	} else if (format == CTX_64_BIT) {
		u64 link;

		if (get_user(link, (u64 __user *) uc_link))
			return -EFAULT;

		ret = put_priv(link, (u64 __priv *) tramp_ps_frames);
	} else {
		e2k_ap_t link;
		u32 tag;

		if (get_user_tagged_16(link.qword, tag, uc_link))
			return -EFAULT;

		if (tag == ETAGNPQ && !link.lo && !link.hi) {
			/* Null pointer */
		} else if (IS_AP(link, tag) &&
				AP_OBJ_SIZE(link) >= offsetofend(struct ucontext_prot,
								   uc_extra.pfpfr)) {
			/* Good descriptor */
		} else {
			return -EINVAL;
		}

		ret = put_priv_tagged_16_offset(link.qword, tag,
				tramp_ps_frames, machine.qnr1_offset);
	}
	if (ret)
		return -EFAULT;

	for (i = 0; i < args_size / 16; i++) {
		e2k_qreg_t data;
		u32 tag;

		if (IS_ALIGNED((unsigned long) args, 16)) {
			if (get_user_tagged_16(data, tag, args + 16 * i))
				return -EFAULT;
		} else {
			/* Can happen in 32 and 64 bit modes */
			u32 tag_lo, tag_hi;
			if (get_user_tagged_8(data.lo, tag_lo, (u64 __user *) (args + 16 * i)) ||
			    get_user_tagged_8(data.hi, tag_hi, (u64 __user *) (args + 16 * i + 8)))
				return -EFAULT;
			tag = (tag_hi << 4) | tag_lo;
		}
		DebugCTX_STACK("register arguments: 0x%llx 0x%llx\n", data.lo, data.hi);

		ret = put_priv_tagged_16_offset(data, tag,
				ps_frames + EXT_4_NR_SZ * i, machine.qnr1_offset);
		if (ret)
			return -EFAULT;
	}

	if (2 * i < args_size / 8) {
		u64 val;
		u32 tag;

		if (get_user_tagged_8(val, tag, (u64 __user *) (args + 16 * i)))
			return -EFAULT;

		if (put_priv_tagged_8(val, tag,
				(u64 __priv *) (ps_frames + EXT_4_NR_SZ * i)))
			return -EFAULT;
		DebugCTX_STACK("register arguments: 0x%llx\n", val);
	}

	if (format == CTX_128_BIT) {
		trampoline = makecontext_trampoline_128(current->mm);
	} else if (format == CTX_64_BIT) {
		trampoline = makecontext_trampoline_64(current->mm);
	} else if (format == CTX_32_BIT) {
		trampoline = makecontext_trampoline_32(current->mm);
	} else {
		return -EINVAL;
	}
	ret = chain_stack_frame_init(&crs_trampoline, trampoline,
			dstack_free_size, dstack_frame_size, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	ret = ret ?: chain_stack_frame_init(&crs_user, (unsigned long) user_func,
			dstack_free_size, dstack_frame_size, E2K_USER_INITIAL_PSR,
			C_ABI_PSIZE(protected), C_ABI_PSIZE(protected), true);
	if (ret)
		return ret;

	if (clear_priv(&cs_frames[1], SZ_OF_CR) ||
	    copy_to_priv(&cs_frames[2], &crs_trampoline, SZ_OF_CR) ||
	    copy_to_priv(&cs_frames[3], &crs_user, SZ_OF_CR)) {
		return -EFAULT;
	}

	return 0;
}
