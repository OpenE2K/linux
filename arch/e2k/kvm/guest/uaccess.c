/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/mm.h>
#include <linux/uaccess.h>

#include <asm/kvm/guest/uaccess.h>

UACCESS_FN_DEFINE3(kvm_get_user_val_and_tagw_fn,
		const void __user *, ptr, u32 *, val, u8 *, tag)
{
	u64 tmp;
	HYPERVISOR_recovery_faulted_load((unsigned long) ptr, &tmp, tag,
			TAGGED_MEM_LOAD_REC_OPC_W, 0);
	*val = (u32) tmp;
	return 0;
}

int kvm_get_user_val_and_tagw(const void __user *ptr, u32 *val, u8 *tag)
{
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ptr, 4),
			"unaligned get_user_val_and_tagw() parameter"))
		return -EFAULT;

	return __UACCESS_FN_CALL(kvm_get_user_val_and_tagw_fn, ptr, val, tag);
}

UACCESS_FN_DEFINE3(kvm_get_user_val_and_tagd_fn,
		const void __user *, ptr, u64 *, val, u8 *, tag)
{
	HYPERVISOR_recovery_faulted_load((unsigned long) ptr, val, tag,
			TAGGED_MEM_LOAD_REC_OPC, 0);
	return 0;
}

int kvm_get_user_val_and_tagd(const void __user *ptr, u64 *val, u8 *tag)
{
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ptr, 8),
			"unaligned get_user_val_and_tagd() parameter"))
		return -EFAULT;

	return __UACCESS_FN_CALL(kvm_get_user_val_and_tagd_fn, ptr, val, tag);
}

UACCESS_FN_DEFINE6(kvm_get_user_val_and_tagq_fn, const void __user *, ptr,
		u64 *, val_lo, u64 *, val_hi, u8 *, tag_lo, u8 *, tag_hi,
		unsigned long, offset)
{
	HYPERVISOR_recovery_faulted_load((unsigned long) ptr, val_lo, tag_lo,
			TAGGED_MEM_LOAD_REC_OPC, 0);
	HYPERVISOR_recovery_faulted_load((unsigned long) ptr + offset,
			val_hi, tag_hi, TAGGED_MEM_LOAD_REC_OPC, 0);
	return 0;
}

int kvm_get_user_val_and_tagq(const void __user *ptr, u64 *val_lo, u64 *val_hi,
		u8 *tag_lo, u8 *tag_hi, unsigned long offset)
{
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ptr, 16),
			"unaligned get_user_val_and_tagq() parameter"))
		return -EFAULT;

	return __UACCESS_FN_CALL(kvm_get_user_val_and_tagq_fn,
			ptr, val_lo, val_hi, tag_lo, tag_hi, offset);
}

UACCESS_FN_DEFINE3(kvm_put_user_val_and_tagd_fn,
		void __user *, ptr, u64, val, u32, tag)
{
	recovery_faulted_tagged_store((unsigned long) ptr, val, tag,
			TAGGED_MEM_STORE_REC_OPC, 0, 0, 0, 1, 0, 0);
	return 0;
}

int kvm_put_user_val_and_tagd(void __user *ptr, u64 val, u32 tag)
{
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ptr, 8),
			"unaligned put_user_val_and_tagd() parameter"))
		return -EFAULT;

	return __UACCESS_FN_CALL(kvm_put_user_val_and_tagd_fn, ptr, val, tag);
}

UACCESS_FN_DEFINE6(kvm_put_user_val_and_tagq_fn, void __user *, ptr,
		u64, val_lo, u64, val_hi, u32, tag_lo, u32, tag_hi,
		unsigned long, offset)
{
	recovery_faulted_tagged_store((unsigned long) ptr, val_lo, tag_lo,
			TAGGED_MEM_STORE_REC_OPC, val_hi, tag_hi,
			TAGGED_MEM_STORE_REC_OPC | offset, 0, 0, 1);
	return 0;
}

int kvm_put_user_val_and_tagq(void __user *ptr, u64 val_lo, u64 val_hi, u32 tag,
		unsigned long offset)
{
	if (WARN_ONCE(!IS_ALIGNED((unsigned long) ptr, 16),
			"unaligned put_user_val_and_tagq() parameter"))
		return -EFAULT;

	return __UACCESS_FN_CALL(kvm_put_user_val_and_tagq_fn, ptr,
			val_lo, val_hi, tag & 0xf, (tag >> 4) & 0xf, offset);
}
