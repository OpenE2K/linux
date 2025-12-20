/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_KVM_GUEST_STRING_H_
#define _E2K_KVM_GUEST_STRING_H_

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/bug.h>

#include <asm/pv_info.h>
#include <asm/kvm/hypercall.h>

#ifndef __ASSEMBLY__

#define SAVE_REPLACE_USR_PFAULT(new_pfault_IP, to_save_prev_IP) \
({ \
	(to_save_prev_IP) = current->thread.usr_pfault_jump; \
	current->thread.usr_pfault_jump = (new_pfault_IP); \
})

#define REPLACE_USR_PFAULT(new_pfault_IP) \
({ \
	current->thread.usr_pfault_jump = (new_pfault_IP); \
})

#define RESTORE_REPLACED_USR_PFAULT(saved_prev_IP) \
({ \
	current->thread.usr_pfault_jump = (saved_prev_IP); \
})

extern unsigned long kvm_fast_kernel_tagged_memory_copy(void *dst, const void *src,
				size_t len, ldst_rec_op_t strd_opcode,
				ldst_rec_op_t ldrd_opcode, int prefetch);
extern unsigned long kvm_fast_kernel_tagged_memory_set(void *addr, u64 val, u64 tag,
				size_t len, u64 strd_opcode);

/*
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 */
static inline unsigned long
kvm_do_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		ldst_rec_op_t strd_opcode, ldst_rec_op_t ldrd_opcode, int prefetch)
{
	long ret;

	do {
		ret = HYPERVISOR_fast_tagged_memory_copy(dst, src, len,
				AW(strd_opcode), AW(ldrd_opcode), prefetch);
	} while (ret == -EAGAIN);

	return ret;
}
static inline unsigned long
kvm_do_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	long ret;

	do {
		ret = HYPERVISOR_fast_tagged_memory_set(addr, val, tag, len,
							strd_opcode);
	} while (ret == -EAGAIN);

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
		ldst_rec_op_t strd_opcode, ldst_rec_op_t ldrd_opcode,
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
		size_t len, ldst_rec_op_t strd_opcode, ldst_rec_op_t ldrd_opcode,
		int prefetch);
extern unsigned long kvm_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode);
extern unsigned long boot_kvm_fast_tagged_memory_copy(void *dst,
		const void *src, size_t len, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch);
extern unsigned long boot_kvm_fast_tagged_memory_set(void *addr, u64 val,
		u64 tag, size_t len, u64 strd_opcode);

extern unsigned long kvm_extract_tags_32(u16 *dst, const void *src);
#endif	/* ! DEBUG_GUEST_STRINGS */

extern unsigned long kvm_fast_tagged_memory_copy_user(void *dst, const void *src,
		size_t len, size_t *copied, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch);
extern unsigned long kvm_fast_tagged_memory_set_user(void *addr, u64 val, u64 tag,
		size_t len, size_t *cleared, u64 strd_opcode);

static inline size_t kvm_fast_tagged_memory_copy_to_user(void __user *dst,
		const void *src, size_t len, size_t *copied,
		const struct pt_regs *regs, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch)
{
	/* guest kernel does not support any nested guests */
	return kvm_fast_tagged_memory_copy_user(dst, src, len, copied,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline size_t kvm_fast_tagged_memory_copy_from_user(void *dst,
		const void __user *src, size_t len, size_t *copied,
		const struct pt_regs *regs, ldst_rec_op_t strd_opcode,
		ldst_rec_op_t ldrd_opcode, int prefetch)
{
	/* guest kernel does not support any nested guests */
	return kvm_fast_tagged_memory_copy_user(dst, src, len, copied,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline void kvm_tagged_memcpy_8(void *dst, const void *src, size_t n)
{
	E2K_PREFETCH_L1_SPEC(src);

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

static inline void fast_tagged_memory_copy(void *dst, const void *src,
		size_t len, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t)
		{ .fmt = LDST_QWORD_FMT, .mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	kvm_fast_kernel_tagged_memory_copy(dst, src, len, strd_opcode,
						  ldrd_opcode, prefetch);
}
static inline void fast_tagged_memcpy_io(void *dst, const void *src, size_t len, int prefetch)
{
	fast_tagged_memory_copy(dst, src, len, prefetch);
}
static __always_inline unsigned long
fast_tagged_memory_copy_to_user(void __user *dst, const void *src, size_t len,
		size_t *copied, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT, .prot = 1 };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	return kvm_fast_tagged_memory_copy_user((void __force *) dst, src, len,
			copied, strd_opcode, ldrd_opcode, prefetch);
}
static __always_inline unsigned long
fast_tagged_memory_copy_from_user(void *dst, const void __user *src, size_t len,
		size_t *copied, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE, .prot = 1 };
	return kvm_fast_tagged_memory_copy_user(dst, (void __force *) src, len,
			copied, strd_opcode, ldrd_opcode, prefetch);
}
static __always_inline unsigned long
fast_tagged_memory_copy_in_user(void __user *dst, const void __user *src, size_t len,
		size_t *copied, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT, .prot = 1 };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE, .prot = 1 };
	return kvm_fast_tagged_memory_copy_user((void __force *)  dst, (void __force *) src,
			len, copied, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
boot_fast_tagged_memory_copy(void *dst, const void *src, size_t len, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t)
		{ .fmt = LDST_QWORD_FMT, .mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	return boot_kvm_fast_tagged_memory_copy(dst, src, len, strd_opcode,
						ldrd_opcode, prefetch);
}
static inline unsigned long
fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return kvm_fast_kernel_tagged_memory_set(addr, val, tag, len, strd_opcode);
}
static inline void fast_tagged_memset_io(void *addr, u64 val, u64 tag, size_t len)
{
	ldst_rec_op_t st_op = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	(void) kvm_fast_kernel_tagged_memory_set(addr, val, tag, len, AW(st_op));
}
static inline unsigned long
fast_tagged_memory_set_user(void *addr, u64 val, u64 tag,
		size_t len, size_t *cleared, u64 strd_opcode)
{
	return kvm_fast_tagged_memory_set_user(addr, val, tag, len, cleared,
						strd_opcode);
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

static inline size_t fast_tagged_memory_copy_to_user_gva(void __user *dst,
		const void *src, size_t len,
		const struct pt_regs *regs, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT, .prot = 1 };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };

	return kvm_fast_tagged_memory_copy_to_user(dst, src, len, NULL, regs,
				strd_opcode, ldrd_opcode, prefetch);
}

static inline size_t
fast_tagged_memory_copy_from_user_gva(void *dst, const void __user *src,
		size_t len, const struct pt_regs *regs, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE, .prot = 1 };

	return kvm_fast_tagged_memory_copy_from_user(dst, src, len, NULL, regs,
				strd_opcode, ldrd_opcode, prefetch);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASSEMBLY__ */
#endif /* _E2K_KVM_GUEST_STRING_H_ */
