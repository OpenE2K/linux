
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>

#include <asm/pv_info.h>
#include <asm/kvm/hypercall.h>
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
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
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
		BUG_ON(ret != -EAGAIN);
		DebugRETRY("could not copy memory from %px to %px, "
			"size 0x%lx, error %ldi, retry\n",
			src, dst, len, ret);
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
		BUG_ON(ret != -EAGAIN);
		DebugRETRY("could set memory %px, size 0x%lx, "
				"error %ldi, retry\n",
				addr, len, ret);
		goto retry;
	}

	BUG_ON(ret != len);

	return ret;
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_set);

unsigned long kvm_fast_kernel_tagged_memory_copy(void *dst, const void *src,
			size_t len, unsigned long strd_opcode,
			unsigned long ldrd_opcode, int prefetch)
{
	long ret;

	if (unlikely(!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)dst) ||
			!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)src))) {
		/* only guest kernel memory areas can be copied */
		/* here by light hypercall */
		goto slow_copy;
	}

	ret = HYPERVISOR_fast_kernel_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
	if (likely(ret == 0))
		return ret;

slow_copy:
	return kvm_do_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
EXPORT_SYMBOL(kvm_fast_kernel_tagged_memory_copy);

unsigned long kvm_fast_kernel_tagged_memory_set(void *addr, u64 val, u64 tag,
						size_t len, u64 strd_opcode)
{
	long ret;
	if (unlikely(!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)addr))) {
		/* only guest kernel memory areas can be set */
		/* here by light hypercall */
		goto slow_set;
	}

	ret = HYPERVISOR_fast_kernel_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	if (likely(ret == 0))
		return ret;

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
		size_t len, size_t *copied,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	long ret;
	static unsigned long memcpy_fault_IP = 0UL;
	bool no_fault = false;

	if (likely(memcpy_fault_IP != 0)) {

		REPLACE_USR_PFAULT(memcpy_fault_IP);

retry:
		if (likely(IS_HV_GM())) {
			return native_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
		} else {
			ret = HYPERVISOR_fast_tagged_memory_copy_user(dst, src,
					len, copied,
					strd_opcode, ldrd_opcode, prefetch);
		}

		if (unlikely(ret < 0)) {
			if (likely(ret == -EAGAIN)) {
				DebugRETRY("could not copy memory from %px to %px, "
					"size 0x%lx, copied 0x%lx, error %ld, "
					"retry\n",
					src, dst, len, (copied) ? *copied : 0, ret);
				goto retry;
			}
		} else {
			no_fault = true;
		}
	} else {
		/* calculate IP to goto in case of page fault on user address */
		ret = 0;
		no_fault = true;
	}

	E2K_CMD_SEPARATOR;
	memcpy_fault_IP = NATIVE_READ_IP_REG_VALUE();
	if (unlikely(!no_fault)) {
		DebugFAULT("copy memory from %px to %px, size 0x%lx, "
			"only %px == 0x%lx bytes copied\n",
			src, dst, len, copied, (copied) ? *copied : 0);
	}
	if (copied == NULL) {
		return ret;
	} else if (*copied <= 0) {
		return 0;
	} else {
		return *copied;
	}
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_copy_user);

unsigned long
kvm_fast_tagged_memory_set_user(void __user *addr, u64 val, u64 tag,
		size_t len, size_t *cleared, u64 strd_opcode)
{
	long ret;
	static unsigned long memset_fault_IP = 0UL;

	if (likely(memset_fault_IP != 0)) {

		REPLACE_USR_PFAULT(memset_fault_IP);

retry:
		if (likely(IS_HV_GM())) {
			return native_fast_tagged_memory_set(addr,
					val, tag, len, strd_opcode);
		} else {
			ret = HYPERVISOR_fast_tagged_memory_set_user(addr,
					val, tag, len, cleared, strd_opcode);
		}

		if (unlikely(ret < 0)) {
			if (likely(ret == -EAGAIN)) {
				DebugRETRY("could set memory %px, size 0x%lx, "
					"cleared 0x%lx, error %ld, retry\n",
					addr, len, (cleared) ? *cleared : 0, ret);
				goto retry;
			}
		}
	} else {
		/* calculate IP to goto in case of page fault on user address */
		ret = 0;
	}

	E2K_CMD_SEPARATOR;
	memset_fault_IP = NATIVE_READ_IP_REG_VALUE();
	if (cleared == NULL) {
		return ret;
	} else if (*cleared <= 0) {
		return 0;
	} else {
		return *cleared;
	}
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_set_user);
