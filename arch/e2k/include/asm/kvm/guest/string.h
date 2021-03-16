#ifndef _E2K_KVM_GUEST_STRING_H_
#define _E2K_KVM_GUEST_STRING_H_

#include <linux/types.h>

#include <asm/pv_info.h>
#include <asm/kvm/hypercall.h>

#ifndef __ASSEMBLY__

/*
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 */
static inline unsigned long
kvm_do_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	long ret;

	if (IS_HOST_KERNEL_ADDRESS((e2k_addr_t)src) ||
			IS_HOST_KERNEL_ADDRESS((e2k_addr_t)dst)) {
		ret = HYPERVISOR_fast_tagged_guest_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
	} else {
		ret = HYPERVISOR_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
	}
	return ret;
}
static inline unsigned long
kvm_do_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	long ret;

	if (IS_HOST_KERNEL_ADDRESS((e2k_addr_t)addr)) {
		ret = HYPERVISOR_fast_tagged_guest_memory_set(addr, val, tag,
							len, strd_opcode);
	} else {
		ret = HYPERVISOR_fast_tagged_memory_set(addr, val, tag, len,
								strd_opcode);
	}
	return ret;
}

/*
 * Extract tags from 32 bytes of data
 * FIXME: need improve function to extract tags from any size of data
 */
static inline unsigned long
kvm_do_extract_tags_32(u16 *dst, const void *src)
{
	return HYPERVISOR_extract_tags_32(dst, src);
}

#define	DEBUG_GUEST_STRINGS

#ifndef	DEBUG_GUEST_STRINGS
static inline unsigned long
kvm_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	if (likely(IS_HV_GM()))
		return native_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
	else
		return kvm_do_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
kvm_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	if (likely(IS_HV_GM()))
		return native_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	else
		return kvm_do_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
}

static inline unsigned long
kvm_extract_tags_32(u16 *dst, const void *src)
{
	if (likely(IS_HV_GM()))
		return native_extract_tags_32(dst, src);
	else
		return kvm_do_extract_tags_32(dst, src);
}
#else	/* DEBUG_GUEST_STRINGS */
extern unsigned long kvm_fast_tagged_memory_copy(void *dst, const void *src,
				size_t len,
				unsigned long strd_opcode,
				unsigned long ldrd_opcode,
				int prefetch);
extern unsigned long kvm_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
				size_t len, u64 strd_opcode);
extern unsigned long boot_kvm_fast_tagged_memory_copy(void *dst,
				const void *src, size_t len,
				unsigned long strd_opcode,
				unsigned long ldrd_opcode,
				int prefetch);
extern unsigned long boot_kvm_fast_tagged_memory_set(void *addr, u64 val,
				u64 tag, size_t len, u64 strd_opcode);

extern unsigned long kvm_extract_tags_32(u16 *dst, const void *src);
#endif	/* ! DEBUG_GUEST_STRINGS */

static inline int
kvm_fast_tagged_memory_copy_to_user(void __user *dst, const void *src,
		size_t len, const struct pt_regs *regs,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	/* guest kernel does not support any nested guests */
	return kvm_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline int
kvm_fast_tagged_memory_copy_from_user(void *dst, const void __user *src,
		size_t len, const struct pt_regs *regs,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	/* guest kernel does not support any nested guests */
	return kvm_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline void kvm_tagged_memcpy_8(void *dst, const void *src, size_t n)
{
	E2K_PREFETCH_L2(src);

	__tagged_memcpy_8(dst, src, n);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
/**
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 */

#define tagged_memcpy_8(dst, src, n)					\
({									\
	if (likely(IS_HV_GM()))						\
		native_tagged_memcpy_8(dst, src, n,			\
				__alignof(*(dst)), __alignof(*(src)));	\
	else								\
		kvm_tagged_memcpy_8(dst, src, n);			\
})

static inline unsigned long
fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return kvm_fast_tagged_memory_copy(dst, src, len, strd_opcode,
						ldrd_opcode, prefetch);
}
static inline unsigned long
boot_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return boot_kvm_fast_tagged_memory_copy(dst, src, len, strd_opcode,
						ldrd_opcode, prefetch);
}
static inline unsigned long
fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return kvm_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}
static inline void
boot_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	boot_kvm_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}

static inline unsigned long
extract_tags_32(u16 *dst, const void *src)
{
	return kvm_extract_tags_32(dst, src);
}

static inline int
fast_tagged_memory_copy_to_user(void __user *dst, const void *src,
		size_t len, const struct pt_regs *regs,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return kvm_fast_tagged_memory_copy_to_user(dst, src, len, regs,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline int
fast_tagged_memory_copy_from_user(void *dst, const void __user *src,
		size_t len, const struct pt_regs *regs,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return kvm_fast_tagged_memory_copy_from_user(dst, src, len, regs,
				strd_opcode, ldrd_opcode, prefetch);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASSEMBLY__ */
#endif /* _E2K_KVM_GUEST_STRING_H_ */
