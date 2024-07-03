/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>

#include <asm/pv_info.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/priv-hypercall.h>
#include <asm/kvm/guest/string.h>
#include <asm-generic/bug.h>


#ifdef BOOT
/* This file is included in kernel's builtin boot directly,
 * undefine EXPORT_SYMBOL to avoid linking errors. */
# undef EXPORT_SYMBOL
# define EXPORT_SYMBOL(sym)
# define DEBUG_DISABLE_BOOT 1
#else
# define DEBUG_DISABLE_BOOT 0
#endif

#undef	DEBUG_KVM_RETRY_MODE
#undef	DebugRETRY
#define	DEBUG_KVM_RETRY_MODE		0	/* memory copy retries debug */
#define	DebugRETRY(fmt, args...)					\
({									\
	if (DEBUG_KVM_RETRY_MODE && !DEBUG_DISABLE_BOOT)		\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_FAULT_MODE
#undef	DebugFAULT
#define	DEBUG_KVM_FAULT_MODE		0	/* memory copy page fault debug */
#define	DebugFAULT(fmt, args...)					\
({									\
	if (DEBUG_KVM_FAULT_MODE && !DEBUG_DISABLE_BOOT)		\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_EXTRACT_TAGS
#undef	DebugEXTRACT
#define	DEBUG_KVM_EXTRACT_TAGS		1	/* extract tags debug */
#define	DebugEXTRACT(fmt, args...)					\
({									\
	if (DEBUG_KVM_EXTRACT_TAGS && !DEBUG_DISABLE_BOOT)		\
		pr_err("%s(): " fmt, __func__, ##args);			\
})

#ifdef	DEBUG_GUEST_STRINGS
/*
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 *
 * Returns number of successfully copied bytes.
 */
unsigned long
kvm_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		ldst_rec_op_t strd_opcode, ldst_rec_op_t ldrd_opcode, int prefetch)
{
	long ret;

retry:
	if (likely(IS_HV_GM())) {
		return native_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
	} else {
		ret = kvm_do_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
	}

	if (unlikely(ret < 0)) {
		if (unlikely(ret != -EAGAIN)) {
			if (!DEBUG_DISABLE_BOOT)
				pr_err("%s(): copy memory from %px to %px, size 0x%lx failed, error %ld\n",
					__func__, src, dst, len, ret);
			return ret;
		}
		goto retry;
	}

	BUG_ON(ret != len);

	return ret;
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_copy);

unsigned long
kvm_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	long ret;

retry:
	if (likely(IS_HV_GM())) {
		return native_fast_tagged_memory_set(addr, val, tag, len,
						    strd_opcode);
	} else {
		ret = kvm_do_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	}

	if (unlikely(ret < 0)) {
		if (unlikely(ret != -EAGAIN)) {
			if (!DEBUG_DISABLE_BOOT)
				pr_err("%s(): set memory at %px by %llx, size 0x%lx failed, error %ld\n",
					__func__, addr, val, len, ret);
			return ret;
		}
		DebugRETRY("could not set memory %px, size 0x%lx, "
				"error %ldi, retry\n",
				addr, len, ret);
		goto retry;
	}

	BUG_ON(ret != len);

	return ret;
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_set);

#ifdef	CONFIG_PRIV_HYPERCALLS
static unsigned long kvm_priv_kernel_tagged_memory_copy(void *dst, const void *src,
			size_t len, unsigned long strd_opcode,
			unsigned long ldrd_opcode,
			bool prefetch)
{
	unsigned long copied;

	copied = HYPERVISOR_priv_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
	if (unlikely((long)copied < 0))
		return copied;

	return len - copied;
}

/*
 * All arguments must be aligned
 */
static unsigned long kvm_priv_kernel_tagged_memory_set(void *addr,
			unsigned long dw, unsigned long tag, size_t len,
			u64 strd_opcode)
{
	unsigned long cleared;

	cleared = HYPERVISOR_priv_tagged_memory_set(addr, dw, tag, len, strd_opcode);
	if (unlikely((long)cleared < 0))
		return cleared;

	return len - cleared;
}

static unsigned long kvm_priv_tagged_memory_copy_user(void *dst, const void *src,
			size_t len, size_t *copiedp,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			bool prefetch)
{
	unsigned long copied;

	copied = HYPERVISOR_priv_tagged_memory_copy_user(dst, src, len, copiedp,
					strd_opcode, ldrd_opcode, prefetch);
	return copied;
}
static unsigned long kvm_priv_tagged_memory_set_user(void *addr,
			unsigned long dw, unsigned long tag,
			size_t len, size_t *clearedp,
			u64 strd_opcode)
{
	unsigned long cleared;

	cleared = HYPERVISOR_priv_tagged_memory_set_user(addr, dw, tag,
							 len, clearedp,
							 strd_opcode);
	return cleared;
}

#else	/* !CONFIG_PRIV_HYPERCALLS */
static int kvm_priv_kernel_tagged_memory_copy(void *dst, const void *src,
			size_t len, unsigned long strd_opcode,
			unsigned long ldrd_opcode, bool prefetch)
{
	return -ENOSYS;
}
static unsigned long kvm_priv_kernel_tagged_memory_set(void *addr,
			unsigned long dw, unsigned long tag, size_t len,
			u64 strd_opcode)
{
	return -ENOSYS;
}
static unsigned long kvm_priv_tagged_memory_copy_user(void *dst, const void *src,
			size_t len, size_t *copiedp,
			unsigned long strd_opcode, unsigned long ldrd_opcode,
			bool prefetch)
{
	return -ENOSYS;
}
static unsigned long kvm_priv_tagged_memory_set_user(void *addr,
			unsigned long dw, unsigned long tag,
			size_t len, size_t *clearedp,
			u64 strd_opcode)
{
	return -ENOSYS;
}
#endif	/* CONFIG_PRIV_HYPERCALLS */

unsigned long kvm_fast_kernel_tagged_memory_copy(void *dst, const void *src,
			size_t len, ldst_rec_op_t strd_opcode,
			ldst_rec_op_t ldrd_opcode, int prefetch)
{
	unsigned long copied;

	if (unlikely(!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)dst) ||
			!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)src))) {
		/* only guest kernel memory areas can be copied */
		/* here by light hypercall */
		goto slow_copy;
	}

	copied = kvm_priv_kernel_tagged_memory_copy(dst, src, len,
					AW(strd_opcode), AW(ldrd_opcode), prefetch);
	if (likely(copied == 0))
		return copied;

	if (copied == -ENOSYS) {
		copied = HYPERVISOR_fast_tagged_memory_copy(dst, src, len,
					AW(strd_opcode), AW(ldrd_opcode), prefetch);
		if (unlikely(copied < 0)) {
			goto slow_copy;
		} else {
			return len - copied;
		}
	}

slow_copy:
	return kvm_do_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
EXPORT_SYMBOL(kvm_fast_kernel_tagged_memory_copy);

unsigned long kvm_fast_kernel_tagged_memory_set(void *addr, u64 val, u64 tag,
						size_t len, u64 strd_opcode)
{
	unsigned long cleared;

	if (unlikely(!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)addr))) {
		/* only guest kernel memory areas can be set */
		/* here by light hypercall */
		goto slow_set;
	}

	cleared = kvm_priv_kernel_tagged_memory_set(addr, val, tag, len,
						strd_opcode);
	if (likely(cleared == 0))
		return cleared;

	if (cleared == -ENOSYS) {
		cleared = HYPERVISOR_fast_tagged_memory_set(addr, val, tag, len,
							    strd_opcode);
		if (unlikely(cleared < 0)) {
			goto slow_set;
		} else {
			return len - cleared;
		}
	}

slow_set:
	return kvm_do_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}
EXPORT_SYMBOL(kvm_fast_kernel_tagged_memory_set);

/*
 * Extract tags from 32 bytes of data
 * FIXME: need improve function to extract tags from any size of data
 */
unsigned long
kvm_extract_tags_32(u16 *dst, const void *src)
{
	long ret;

	if (IS_HOST_KERNEL_ADDRESS((e2k_addr_t)src) ||
		IS_HOST_KERNEL_ADDRESS((e2k_addr_t)dst)) {
		DebugEXTRACT("could not extract tags from host kernel memory "
			"address %px to %px\n",
			src, dst);
	}
	if (!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)src) ||
		!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)dst)) {
		DebugEXTRACT("could not extract tags from user memory "
			"address %px to %px\n",
			src, dst);
	}
	if (likely(IS_HV_GM()))
		ret = native_extract_tags_32(dst, src);
	else
		ret = kvm_do_extract_tags_32(dst, src);
	if (ret) {
		DebugEXTRACT("could not extract tags from %px to %px, "
			"error %ld\n",
			src, dst, ret);
	}
	return ret;
}
EXPORT_SYMBOL(kvm_extract_tags_32);

#endif	/* DEBUG_GUEST_STRINGS */

unsigned long
kvm_fast_tagged_memory_copy_user(void __user *dst, const void __user *src,
		size_t len, size_t *copiedp, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch)
{
	long ret;
	static unsigned long memcpy_fault_IP = 0UL;
	bool no_fault = false;
	unsigned long copied;

	if (likely(memcpy_fault_IP != 0)) {
		unsigned long to_save_replaced_IP = 0;

		if (likely(IS_HV_GM())) {
			return native_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
		}

		/* return IP is inverted to tell the host that the return */
		/* should be on the host privileged action handler */
		SAVE_REPLACE_USR_PFAULT(0 - memcpy_fault_IP, to_save_replaced_IP);

		copied = kvm_priv_tagged_memory_copy_user(dst, src, len, copiedp,
					AW(strd_opcode), AW(ldrd_opcode), prefetch);

		if (likely((long)copied >= 0)) {
			RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);
			if (copiedp != NULL)
				*copiedp = copied;
			ret = copied;
			no_fault = true;
			goto out;
		} else if (copied == -ENOSYS) {
			/* copying as privileged action is disable */
			/* restore not inverted IP */
			REPLACE_USR_PFAULT(memcpy_fault_IP);
		} else if ((long)copied < 0) {
			ret = copied;
			goto failed;
		}

retry:
		ret = HYPERVISOR_fast_tagged_memory_copy_user(dst, src, len, copiedp,
				AW(strd_opcode), AW(ldrd_opcode), prefetch);

failed:
		if (unlikely(ret < 0)) {
			if (likely(ret == -EAGAIN)) {
				DebugRETRY("could not copy memory from %px to %px, "
					"size 0x%lx, copied 0x%lx, error %ld, "
					"retry\n",
					src, dst, len, (copiedp) ? *copiedp : 0, ret);
				goto retry;
			}
		} else {
			no_fault = true;
		}
		RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);
	} else {
		/* calculate IP to goto in case of page fault on user address */
		ret = 0;
		no_fault = true;
	}

out:
	E2K_CMD_SEPARATOR;
	memcpy_fault_IP = NATIVE_READ_IP_REG_VALUE();
	if (unlikely(!no_fault)) {
		DebugFAULT("copy memory from %px to %px, size 0x%lx, "
			"only %px == 0x%lx bytes copied\n",
			src, dst, len, copiedp, (copiedp) ? *copiedp : 0);
	}
	if (copiedp == NULL) {
		return ret;
	} else if (*copiedp <= 0) {
		return 0;
	} else {
		return *copiedp;
	}
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_copy_user);

unsigned long
kvm_fast_tagged_memory_set_user(void __user *addr, u64 val, u64 tag,
		size_t len, size_t *clearedp, u64 strd_opcode)
{
	long ret;
	static unsigned long memset_fault_IP = 0UL;
	unsigned long cleared;

	if (likely(memset_fault_IP != 0)) {
		unsigned long to_save_replaced_IP = 0;

		if (likely(IS_HV_GM())) {
			return native_fast_tagged_memory_set(addr,
					val, tag, len, strd_opcode);
		}

		/* return IP is inverted to tell the host that the return */
		/* should be on the host privileged action handler */
		SAVE_REPLACE_USR_PFAULT(0 - memset_fault_IP, to_save_replaced_IP);

		cleared = kvm_priv_tagged_memory_set_user(addr, val, tag,
							  len, clearedp,
							  strd_opcode);
		if (likely((long)cleared >= 0)) {
			RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);
			if (clearedp != NULL)
				*clearedp = cleared;
			ret = cleared;
			goto out;
		} else if (cleared == -ENOSYS) {
			/* copying as privileged action is disable */
			/* restore not inverted IP */
			REPLACE_USR_PFAULT(memset_fault_IP);
		} else if ((long)cleared < 0) {
			ret = cleared;
			goto failed;
		}

retry:
		ret = HYPERVISOR_fast_tagged_memory_set_user(addr,
				val, tag, len, clearedp, strd_opcode);

failed:
		if (unlikely(ret < 0)) {
			if (likely(ret == -EAGAIN)) {
				DebugRETRY("could set memory %px, size 0x%lx, "
					"cleared 0x%lx, error %ld, retry\n",
					addr, len, (clearedp) ? *clearedp : 0, ret);
				goto retry;
			}
		}
		RESTORE_REPLACED_USR_PFAULT(to_save_replaced_IP);
	} else {
		/* calculate IP to goto in case of page fault on user address */
		ret = 0;
	}

out:
	E2K_CMD_SEPARATOR;
	memset_fault_IP = NATIVE_READ_IP_REG_VALUE();
	if (clearedp == NULL) {
		return ret;
	} else if (*clearedp <= 0) {
		return 0;
	} else {
		return *clearedp;
	}
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_set_user);
