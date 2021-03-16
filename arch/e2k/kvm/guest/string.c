
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/export.h>
#include <linux/mm.h>
#include <linux/errno.h>

#include <asm/pv_info.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/string.h>

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
	if (likely(ret == len))
		return ret;

	if (unlikely(ret < 0)) {
		pr_err("%s(): could not copy memory from %px to %px, "
			"size 0x%lx, error %ld\n",
			__func__, src, dst, len, ret);
		return ret;
	}

	if ((u64)dst >= GUEST_TASK_SIZE) {
		/* guest kernel address should be always allocated */
		pr_warn("%s() could not copy memory to guest kernel addr %px from 0x%px size 0x%lx\n",
			__func__, dst, src, len);
	}

	/*
	 * 1) If it is copy to user then dst can be only mapped (valid) but
	 * not allocated real pages, so force alloccation
	 * 2) copied only part or nothing of data and page fault has been
	 * occured on dst
	 */
	BUG_ON(ret > 0 && ((unsigned long)(dst) & PAGE_MASK) ==
				((unsigned long)(dst + ret) & PAGE_MASK));
	ret = fixup_user_fault(current, current->mm, (unsigned long)(dst + ret),
				FAULT_FLAG_WRITE, NULL);
	if (likely(ret == 0)) {
		goto retry;
	} else {
		pr_err("%s(): could not fixup guest user addr %px fault, "
			"error %ld\n",
			__func__, dst, ret);
		ret = 0;
	}
	return ret;
}
EXPORT_SYMBOL(kvm_fast_tagged_memory_copy);

unsigned long
kvm_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	long ret = 0;

retry:
	if (likely(IS_HV_GM())) {
		ret = native_fast_tagged_memory_set(addr, val, tag, len,
						    strd_opcode);
	} else {
		ret = kvm_do_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	}
	if (likely(ret == len))
		return ret;

	if (ret < 0) {
		pr_err("%s() could not set memory from %px "
			"by 0x%01llx_0x%016llx, size 0x%lx, error %ld\n",
			__func__, addr, tag, val, len, ret);
		return ret;
	}

	if ((u64)addr >= GUEST_TASK_SIZE) {
		/* guest kernel address should be always allocated */
		pr_warn("%s() could not set memory from guest kernel addr %px "
			"by 0x%01llx_0x%016llx, size 0x%lx\n",
			__func__, addr, tag, val, len);
	}

	/*
	 * 1) If it is copy to user then dst can be only mapped (valid) but
	 * not allocated real pages, so force alloccation
	 * 2) copied only part or nothing of data and page fault has been
	 * occured on dst
	 */
	BUG_ON(ret > 0 && ((unsigned long)(addr) & PAGE_MASK) ==
				((unsigned long)(addr + ret) & PAGE_MASK));
	ret = fixup_user_fault(current, current->mm,
				(unsigned long)(addr + ret),
				FAULT_FLAG_WRITE, NULL);
	if (likely(ret == 0)) {
		goto retry;
	} else {
		pr_err("%s(): could not fixup guest user addr %px fault, "
			"error %ld\n",
			__func__, addr, ret);
	}
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
		pr_err("%s(): could not extract tags from host kernel memory "
			"address %px to %px\n",
			__func__, src, dst);
	}
	if (!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)src) ||
		!IS_GUEST_KERNEL_ADDRESS((e2k_addr_t)dst)) {
		pr_err("%s(): could not extract tags from user memory "
			"address %px to %px\n",
			__func__, src, dst);
	}
	if (likely(IS_HV_GM()))
		ret = native_extract_tags_32(dst, src);
	else
		ret = kvm_do_extract_tags_32(dst, src);
	if (ret) {
		pr_err("%s(): could not extract tags from %px to %px, "
			"error %ld\n",
			__func__, src, dst, ret);
	}
	return ret;
}
EXPORT_SYMBOL(kvm_extract_tags_32);

#endif	/* DEBUG_GUEST_STRINGS */
