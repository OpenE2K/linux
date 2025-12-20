/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include <asm/p2v/boot_v2p.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/export.h>

#include <asm/pv_info.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/string.h>
#include <asm/p2v/boot_console.h>
#include <asm/p2v/boot_head.h>

#ifdef	DEBUG_GUEST_STRINGS
/*
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 */
unsigned long
boot_kvm_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		ldst_rec_op_t strd_opcode, ldst_rec_op_t ldrd_opcode, int prefetch)
{
	long ret;

	if (likely(BOOT_IS_HV_GM()))
		ret = boot_native_fast_tagged_memory_copy(dst, src, len,
				AW(strd_opcode), AW(ldrd_opcode), prefetch);
	else
		ret = kvm_do_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
	if (ret) {
		do_boot_printk("%s(): could not copy memory from %px to %px, "
			"size 0x%lx, error %ld\n",
			__func__, src, dst, len, ret);
	}
	return ret;
}
EXPORT_SYMBOL(boot_kvm_fast_tagged_memory_copy);

unsigned long
boot_kvm_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	long ret = 0;

	if (likely(BOOT_IS_HV_GM()))
		boot_native_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	else
		ret = kvm_do_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	if (ret != len) {
		do_boot_printk("%s() could not set memory from %px "
			"by 0x%x_0x%x, size 0x%lx, error %ld\n",
			__func__, addr, val, tag, len, ret);
	}
	return ret;
}
EXPORT_SYMBOL(boot_kvm_fast_tagged_memory_set);

#endif	/* DEBUG_GUEST_STRINGS */
