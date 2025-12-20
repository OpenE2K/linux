/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/uaccess.h>
#include <asm/kvm/pv-emul.h>

/*
 * Inside light hypercalls we have to be careful about
 * switching %u_pptb/%pid, so need a specialized function.
 * Another reason is that this function does not check 'to'
 * alignment - so it does not guarantee copying of tags.
 */
static unsigned long copy_aligned_user_tagged_memory_light_hcall(
		void __user *to, const void __user *from, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode, bool prefetch)
{
	void *volatile dst = to;
	const void *volatile src = from;
	volatile unsigned long n = len;

	if (unlikely(((long)dst & 0x7) || (n & 0x7))) {
		pr_err("%s() dst %px or length %lx is not double-word "
			"aligned\n",
			__func__, dst, n);
		return -EINVAL;
	}

	do {
		struct uaccess_regs regs;
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);
		size_t copied;

		/* See comment before native_uaccess_save() */
		native_uaccess_save(&regs);
		SET_USR_PFAULT("$recovery_memcpy_fault", true);
		copied = fast_tagged_memory_copy_in_user(dst, src, length,
				NULL, prefetch);
		RESTORE_USR_PFAULT(true);
		native_uaccess_restore(&regs);

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			break;
	} while (unlikely(n > 0));

	return n;
}

/*
 * Inside light hypercalls we have to be careful about
 * switching %u_pptb/%pid, so need a specialized function.
 */
static unsigned long set_aligned_user_tagged_memory_light_hcall(
		void __user *addr, unsigned long dw, unsigned long tag,
		size_t len, u64 strd_opcode)
{
	struct uaccess_regs regs;
	size_t cleared = 0;

	if (unlikely(((long)addr & 0x7) || (len & 0x7))) {
		pr_err("%s(): dst %px or length %lx is not double-word "
			"aligned\n",
			__func__, addr, len);
		return -EINVAL;
	}

	/* See comment before native_uaccess_save() */
	native_uaccess_save(&regs);
	SET_USR_PFAULT("$recovery_memset_fault", true);
	cleared = fast_tagged_memory_set_user(addr, dw, tag, len, NULL, strd_opcode);
	RESTORE_USR_PFAULT(true);
	native_uaccess_restore(&regs);

	return len - cleared;
}

long kvm_fast_guest_kernel_tagged_memory_copy_light_hcall(struct kvm_vcpu *vcpu,
		void *dst, const void *src, size_t len, unsigned long strd_opcode,
		unsigned long ldrd_opcode, int prefetch)
{
	long ret;

	if (unlikely(!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)dst) ||
			!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)src))) {
		/* only guest kernel memory areas can be copied */
		ret = -EINVAL;
		goto failed;
	}

	kvm_vcpu_set_dont_inject(vcpu);
	ret = copy_aligned_user_tagged_memory_light_hcall(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
	kvm_vcpu_reset_dont_inject(vcpu);
	if (likely(ret == 0))
		return ret;

failed:
	return ret;
}

long kvm_fast_guest_kernel_tagged_memory_set_light_hcall(struct kvm_vcpu *vcpu,
		void *addr, u64 val, u64 tag, size_t len, u64 strd_opcode)
{
	long ret;

	if (unlikely(!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)addr))) {
		/* only guest kernel memory areas can be set */
		ret = -EINVAL;
		goto failed;
	}

	kvm_vcpu_set_dont_inject(vcpu);
	ret = set_aligned_user_tagged_memory_light_hcall(addr, val, tag,
							 len, strd_opcode);
	kvm_vcpu_reset_dont_inject(vcpu);
	if (likely(ret == 0))
		return ret;

failed:
	return ret;
}
