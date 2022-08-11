
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
		printk(KERN_ERR "%s(): could not copy memory from %px to %px, "
			"size 0x%lx, error %ldi, retry\n", __func__, src, dst,
			len, ret);
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
		printk(KERN_ERR "%s(): could set memory %px, size 0x%lx, "
				"error %ldi, retry\n", __func__,
				addr, len, ret);
		goto retry;
	}

	BUG_ON(ret != len);

	return ret;
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_set);

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
