/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_STRING_H_
#define _E2K_STRING_H_

#include <linux/swab.h>
#include <linux/align.h>

#include <asm/page_size.h>
#include <asm/bug.h>
#include <asm/cpu_features.h>
#include <asm/e2k_api.h>
#include <asm/mmu_types.h>

#define __HAVE_ARCH_STRNLEN
extern size_t strnlen(const char *s, size_t count) __pure;

#define __HAVE_ARCH_STRLEN
extern size_t strlen(const char *s) __pure;

#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dst, const void *src, size_t count);
extern void *__memmove(void *dst, const void *src, size_t count);

#if (defined(CONFIG_KASAN) && !defined(__SANITIZE_ADDRESS__))
/*
 * For files that not instrumented (e.g. mm/slub.c) we
 * should use not instrumented version of mem* functions.
 */

#undef memmove
#define memmove(dst, src, len) __memmove(dst, src, len)

#ifndef __NO_FORTIFY
#define __NO_FORTIFY /* FORTIFY_SOURCE uses __builtin_memcpy, etc. */
#endif

#endif

#define __HAVE_ARCH_MEMCHR
extern void *memchr(const void *s, int c, size_t n) __pure;

#define __HAVE_ARCH_MEMCMP
extern int memcmp(const void *cs, const void *ct, size_t count);
extern int __memcmp(const void *cs, const void *ct, size_t count) __pure;
#define memcmp(dst, src, n) _memcmp((dst), (src), (n))
static inline int _memcmp(const void *s1, const void *s2, size_t n)
{
	if (__builtin_constant_p(n) && n < 0x20) {
		/* Inline small memcmp's */
		if (n & 0x10) {
			u64 v1 = *(u64 *) s1;
			u64 v2 = *(u64 *) s2;
			u64 v21 = *(u64 *) (s1 + 8);
			u64 v22 = *(u64 *) (s2 + 8);
			if (v1 != v2)
				return (__swab64(v1) > __swab64(v2)) ? 1 : -1;
			if (v21 != v22)
				return (__swab64(v21) > __swab64(v22)) ? 1 : -1;

			s1 += 0x10;
			s2 += 0x10;
		}
		if (n & 0x8) {
			u64 v1 = *(u64 *) s1;
			u64 v2 = *(u64 *) s2;
			if (v1 != v2)
				return (__swab64(v1) > __swab64(v2)) ? 1 : -1;

			s1 += 0x8;
			s2 += 0x8;
		}
		if (n & 0x4) {
			u64 v1 = *(u32 *) s1;
			u64 v2 = *(u32 *) s2;
			if (v1 != v2)
				return (__swab32(v1) > __swab32(v2)) ? 1 : -1;

			s1 += 0x4;
			s2 += 0x4;
		}
		if (n & 0x2) {
			u64 v1 = *(u16 *) s1;
			u64 v2 = *(u16 *) s2;
			if (!(n & 0x1) || v1 != v2)
				return (u32) __swab16(v1) - (u32) __swab16(v2);

			s1 += 0x1;
			s2 += 0x1;
		}
		if (n & 0x1) {
			u64 v1 = *(u8 *) s1;
			u64 v2 = *(u8 *) s2;
			return v1 - v2;
		}
		return 0;
	}

	E2K_PREFETCH_L1_SPEC(s1);
	E2K_PREFETCH_L1_SPEC(s1);
	return __memcmp(s1, s2, n);
}

#define __HAVE_ARCH_MEMSET
#ifdef __HAVE_ARCH_MEMSET
extern void *memset(void *, int, size_t);
extern void *__memset(void *, int, size_t);
#if defined E2K_P2V && !defined CONFIG_BOOT_E2K
extern void *boot_memset(void *s_va, int c, size_t count);
# define memset boot_memset
#elif !defined CONFIG_KASAN || !defined(__SANITIZE_ADDRESS__)
# define memset(dst, c, n) _memset(dst, c, n, __alignof(*(dst)))
#endif
static inline u64 memset_pattern_u64(int c)
{
	if (__builtin_constant_p(c)) {
		u64 cc = (u8) c;
		cc |= cc << 8;
		cc |= cc << 16;
		cc |= cc << 32;
		return cc;
	} else {
		return __builtin_e2k_pshufb(c, c, 0);
	}
}

static inline void *_memset(void *dst, int c, size_t n,
		const unsigned long dst_align)
{
	if (__builtin_constant_p(n) && dst_align >= 8 && n < 136) {
		/* Inline small aligned memset's */
		u64 cc = memset_pattern_u64(c);
		u64 *l_dst = dst;

		if (n >= 8)
			l_dst[0] = cc;
		if (n >= 16)
			l_dst[1] = cc;
		if (n >= 24)
			l_dst[2] = cc;
		if (n >= 32)
			l_dst[3] = cc;
		if (n >= 40)
			l_dst[4] = cc;
		if (n >= 48)
			l_dst[5] = cc;
		if (n >= 56)
			l_dst[6] = cc;
		if (n >= 64)
			l_dst[7] = cc;
		if (n >= 72)
			l_dst[8] = cc;
		if (n >= 80)
			l_dst[9] = cc;
		if (n >= 88)
			l_dst[10] = cc;
		if (n >= 96)
			l_dst[11] = cc;
		if (n >= 104)
			l_dst[12] = cc;
		if (n >= 112)
			l_dst[13] = cc;
		if (n >= 120)
			l_dst[14] = cc;
		if (n >= 128)
			l_dst[15] = cc;

		/* Set the tail */
		if (n & 4)
			*(u32 *) (dst + (n & ~0x7UL)) = cc;
		if (n & 2)
			*(u16 *) (dst + (n & ~0x3UL)) = cc;
		if (n & 1)
			*(u8 *) (dst + (n & ~0x1UL)) = cc;
	} else if (__builtin_constant_p(n) && n <= 24) {
		int i;
		/* Inline small memset's */
		char *c_dst = dst;
		for (i = 0; i < n; i++)
			c_dst[i] = c;
	} else {
		__memset(dst, c, n);
	}

	return dst;
}
#endif /* __HAVE_ARCH_MEMSET */

#define __HAVE_ARCH_MEMCPY
#ifdef __HAVE_ARCH_MEMCPY
extern void *memcpy(void *__restrict dst, const void *__restrict src, size_t n);
#define memcpy_nocache memcpy_nocache
extern void memcpy_nocache(void *dst, const void *src, size_t n);
extern void *__memcpy(void *dst, const void *src, size_t n);
#if defined E2K_P2V && !defined CONFIG_BOOT_E2K
extern void *boot_memcpy(void *dest_va, const void *src_va, size_t count);
# define memcpy boot_memcpy
#elif !defined CONFIG_KASAN || !defined(__SANITIZE_ADDRESS__)
# define memcpy(dst, src, n) _memcpy(dst, src, n, __alignof(*(dst)))
#endif
static inline void *_memcpy(void *__restrict dst,
		const void *__restrict src, 
		size_t n, const unsigned long dst_align)
{
	bool unaligned_fast = (CONFIG_CPU_ISET_MIN >= 6);

	/*
	 * As measurements show, an unaligned dst causes a 4x slowdown,
	 * but unaligned src causes only a 2x slowdown (also note that
	 * since v6 unaligned accesses do not cause any slowdown at all).
	 *
	 * We can manually assure dst's alignment, but what about src?
	 *
	 * Consider the following situations:
	 *  1) src is 8 bytes aligned. Just do the copy.
	 *  2) src is 4 bytes aligned. Copying with unaligned loads will cause
	 * a 100% slowdown, the same as copying with 4-bytes words. So we can
	 * treat this case the same way as the previous one.
	 *  3) src is 2-bytes aligned or unaligned. Copying with 2-bytes
	 *  (1-byte for unaligned) will cause a 4x slowdown (8x slowdown for
	 *  unaligned), so copying with unaligned doublewords is preferred
	 *  as it causes only 2x slowdown.
	 *
	 * To sum it up: the best way to copy is to assure dst's 8-bytes
	 * alignment and do the copy with 8-bytes words.
	 */

	if (__builtin_constant_p(n) && (n <= 32 ||
			n < 136 && (dst_align >= 8 || unaligned_fast))) {
		/* Inline small memcpy's with constant size */
		const u64 *__restrict l_src = src;
		u64 *__restrict l_dst = dst;

		if (n >= 8)
			l_dst[0] = l_src[0];
		if (n >= 16)
			l_dst[1] = l_src[1];
		if (n >= 24)
			l_dst[2] = l_src[2];
		if (n >= 32)
			l_dst[3] = l_src[3];
		if (n >= 40)
			l_dst[4] = l_src[4];
		if (n >= 48)
			l_dst[5] = l_src[5];
		if (n >= 56)
			l_dst[6] = l_src[6];
		if (n >= 64)
			l_dst[7] = l_src[7];
		if (n >= 72)
			l_dst[8] = l_src[8];
		if (n >= 80)
			l_dst[9] = l_src[9];
		if (n >= 88)
			l_dst[10] = l_src[10];
		if (n >= 96)
			l_dst[11] = l_src[11];
		if (n >= 104)
			l_dst[12] = l_src[12];
		if (n >= 112)
			l_dst[13] = l_src[13];
		if (n >= 120)
			l_dst[14] = l_src[14];
		if (n >= 128)
			l_dst[15] = l_src[15];

		/* Copy the tail */
		if (n & 4)
			*(u32 *) (dst + (n & ~0x7UL)) =
					*(u32 *) (src + (n & ~0x7UL));
		if (n & 2)
			*(u16 *) (dst + (n & ~0x3UL)) =
					*(u16 *) (src + (n & ~0x3UL));
		if (n & 1)
			*(u8 *) (dst + (n & ~0x1UL)) =
					*(u8 *) (src + (n & ~0x1UL));
	} else {
		E2K_PREFETCH_L2_SPEC(src);
		__memcpy(dst, src, n);
	}

	return dst;
}
#endif /* __HAVE_ARCH_MEMCPY */

extern unsigned long __recovery_memset_8(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode);
/* Since iset v5 we can use this with 16-bytes aligned addr and len */
extern unsigned long __recovery_memset_16(void *addr, u64 val, u64 tag,
		size_t len, u64 strqp_opcode);
#define recovery_memset_8(addr, val, tag, len, strd_opcode) \
({ \
	u64 ___strd_opcode = (strd_opcode); \
	unsigned long __ret; \
	__ret = __recovery_memset_8((addr), (val), (tag), (len), \
				    ___strd_opcode); \
	if (HAS_HWBUG_WC_DAM && \
			(((___strd_opcode >> LDST_REC_OPC_MAS_SHIFT) & \
			 MAS_BYPASS_ALL_CACHES) == MAS_BYPASS_ALL_CACHES)) \
		__E2K_WAIT(_st_c); \
	__ret; \
})

extern void __tagged_memcpy_8(void *dst, const void *src, size_t len);

/*
 * recovery_memcpy_8() - optimized memory copy using strd/ldrd instructions
 *
 * Maximum allowed size is 8 Kb (it can copy bigger blocks, but performance
 * will hurt because of bad prefetching policy).
 *
 * All parameters must be 8-bytes aligned (but if tags are not copied
 * then dst and src can be unaligned).
 *
 * For the best performance it is recommended to copy memory with 8192
 * bytes blocks.
 *
 * 'strd_opcode' can be used to specify cache policy: usually L1 cache
 * is disabled to avoid its pollution (disabling L2 cache slows copying
 * of blocks larger than the size of the memory buffers).
 *
 * When copying from/to physical/IO memory, disable prefetch through the
 * last argument.
 *
 * On success returns len. On error returns the number of bytes actually
 * copied, which can be a little less than the actual copied size.
 * (For error returns to work the page fault handler should be set up
 * with SET_USR_PFAULT("recovery_memcpy_fault")).
 */
extern unsigned long __recovery_memcpy_8(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);
/* Since iset v5 we can use this with 16-bytes aligned src, dst and len */
extern unsigned long __recovery_memcpy_16(void *dst, const void *src, size_t len,
		unsigned long strqp_opcode, unsigned long ldrqp_opcode,
		int prefetch);
#ifdef E2K_P2V
# define HAS_HWBUG_WC_DAM (IS_ENABLED(CONFIG_CPU_E2S) || \
		IS_ENABLED(CONFIG_CPU_E8C) || IS_ENABLED(CONFIG_CPU_E8C2))
#else
# define HAS_HWBUG_WC_DAM cpu_has(CPU_HWBUG_WC_DAM)
#endif
#define recovery_memcpy_8(dst, src, len, strd_opcode, ldrd_opcode, prefetch) \
({ \
	unsigned long __ret; \
	u64 ___strd_opcode = (strd_opcode); \
	__ret = __recovery_memcpy_8((dst), (src), (len), ___strd_opcode, \
			    (ldrd_opcode), (prefetch)); \
	if (HAS_HWBUG_WC_DAM && \
			(((___strd_opcode >> LDST_REC_OPC_MAS_SHIFT) & \
			 MAS_BYPASS_ALL_CACHES) == MAS_BYPASS_ALL_CACHES)) \
		__E2K_WAIT(_st_c); \
	__ret; \
})

/**
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 */
static __can_be_priv_hypercall __always_inline unsigned long
native_fast_tagged_memory_copy(
		void *dst, const void __force *src, size_t len,
		ldst_rec_op_t st_op, ldst_rec_op_t ld_op, int prefetch)
{
	unsigned long ret;

	if (CONFIG_CPU_ISET_MIN >= 5 && !st_op.fmt_h && !ld_op.fmt_h &&
	    st_op.fmt == LDST_QWORD_FMT && ld_op.fmt == LDST_QWORD_FMT &&
	    !((u64) dst & 0xf) && !((u64) src & 0xf) && !(len & 0xf)) {
		ret = __recovery_memcpy_16(dst, src, len,
					   AW(st_op), AW(ld_op), prefetch);
	} else {
		ret = __recovery_memcpy_8(dst, src, len,
					  AW(st_op), AW(ld_op), prefetch);
	}

	if (HAS_HWBUG_WC_DAM && (st_op.mas & MAS_BYPASS_ALL_CACHES) ==
				MAS_BYPASS_ALL_CACHES)
		__E2K_WAIT(_st_c);

	return ret;
}

static __can_be_priv_hypercall __always_inline unsigned long
native_fast_tagged_memory_set(
		void *addr, u64 val, u64 tag, size_t len, u64 strd_opcode)
{
	unsigned long ret;
	ldst_rec_op_t st_op;

	AW(st_op) = strd_opcode;

	if (CONFIG_CPU_ISET_MIN >= 5 && !((u64) addr & 0xf) && !(len & 0xf) &&
	    !st_op.fmt_h && st_op.fmt == LDST_QWORD_FMT) {
		ret = __recovery_memset_16(addr, val, tag, len, strd_opcode);
	} else {
		ret = __recovery_memset_8(addr, val, tag, len, strd_opcode);
	}

	if (HAS_HWBUG_WC_DAM &&
			((strd_opcode >> LDST_REC_OPC_MAS_SHIFT) &
			 MAS_BYPASS_ALL_CACHES) == MAS_BYPASS_ALL_CACHES)
		__E2K_WAIT(_st_c);

	return ret;
}

#define boot_native_fast_tagged_memory_copy(...) recovery_memcpy_8(__VA_ARGS__)

#define boot_native_fast_tagged_memory_set(...) recovery_memset_8(__VA_ARGS__)

static inline unsigned long
native_extract_tags_32(u16 *dst, const void *src)
{
	NATIVE_EXTRACT_TAGS_32(dst, src);
	return 0;
}

static inline void native_tagged_memcpy_8(void *__restrict dst,
		const void *__restrict src, size_t n,
		const unsigned long dst_align,
		const unsigned long src_align)
{
	if (__builtin_constant_p(n) && src_align >= 8 && dst_align >= 8 &&
			(n == 64 || n == 56 || n == 48 || n == 40 ||
			 n == 32 || n == 24 || n == 16 || n == 8)) {
		/* Inline small aligned memcpy's */
		if (n == 64)
			E2K_TAGGED_MEMMOVE_64(dst, src);
		else if (n == 56)
			E2K_TAGGED_MEMMOVE_56(dst, src);
		else if (n == 48)
			E2K_TAGGED_MEMMOVE_48(dst, src);
		else if (n == 40)
			E2K_TAGGED_MEMMOVE_40(dst, src);
		else if (n == 32)
			E2K_TAGGED_MEMMOVE_32(dst, src);
		else if (n == 24)
			E2K_TAGGED_MEMMOVE_24(dst, src);
		else if (n == 16)
			E2K_TAGGED_MEMMOVE_16(dst, src);
		else
			E2K_TAGGED_MEMMOVE_8(dst, src);
	} else {
		E2K_PREFETCH_L2_SPEC(src);

		__tagged_memcpy_8(dst, src, n);
	}
}

/**
 * tagged_memcpy_8() - copy memory along with tags
 *
 * All parameters must be 8-bytes aligned.
 */
#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/string.h>
#else /* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */
#define tagged_memcpy_8(dst, src, n)					\
({									\
	native_tagged_memcpy_8(dst, src, n,				\
			__alignof(*(dst)), __alignof(*(src)));		\
})
#endif /* CONFIG_KVM_GUEST_KERNEL */

extern void boot_fast_memcpy(void *, const void *, size_t);
extern notrace void boot_fast_memset(void *s_va, long c, size_t count);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/string.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */
/**
 * optimized copy memory along with tags
 * using privileged LD/ST recovery operations
 */
static inline void
fast_tagged_memory_copy(void *dst, const void *src, size_t len, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	size_t copied;

	copied = native_fast_tagged_memory_copy(dst, src, len,
					strd_opcode, ldrd_opcode, prefetch);
	BUG_ON(copied != len);
}

static inline void colored_page_copy(void *dst, const void *src)
{
	ldst_rec_op_t ld_op = (ldst_rec_op_t) { .fmt_h = LDST_MCOLOR_FMT_H,
						.mas = MAS_BYPASS_L1_CACHE };

	WARN_ON_ONCE(!IS_ALIGNED((u64)dst, PAGE_SIZE) || !IS_ALIGNED((u64)src, PAGE_SIZE));

	if (cpu_has(CPU_FEAT_E48C_MAKET)) {
		ldst_rec_op_t st_op = (ldst_rec_op_t) { .fmt_h = LDST_MCOLOR_FMT_H };
		size_t copied =  __recovery_memcpy_16(dst, src, PAGE_SIZE, AW(st_op), AW(ld_op), 1);
		BUG_ON(copied != PAGE_SIZE);
	} else {
		u64 i = 0;

		for (; i < PAGE_SIZE / 8; i++) {
			ldst_rec_op_t st_op = (ldst_rec_op_t) {
				.fmt = LDST_QWORD_FMT,
				.mask = 0xff,
				.dcp = 1
			};
			register u64 val asm("r16");
			u64 color, *src_i, *dst_i;
			u8 color_shift;

			src_i = (u64 *)src + i;
			dst_i = (u64 *)dst + i;

			val = __user_ldrd_d_opc(src_i,
					(ldst_rec_op_t) { .word = TAGGED_MEM_LOAD_REC_OPC });
			color = __user_ldrd_d_opc(src_i, ld_op);

			color_shift = ((u64)dst_i & 0x10) ? 61 : 60;
			dst_i = (u64 *)((u64)dst_i | (color << color_shift));

			__user_strd_d_opc(val, dst_i, st_op);
		}
	}
}

/* Avoid 16 bytes loads when talking to devices (this might non-prefetchable area) */
static inline void fast_tagged_memcpy_io(void *dst, const void *src, size_t len, int prefetch)
{
	ldst_rec_op_t st_op = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ld_op = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	size_t copied;

	copied = __recovery_memcpy_8(dst, src, len,
					    AW(st_op), AW(ld_op), prefetch);
	BUG_ON(copied != len);
}

static __always_inline __must_check size_t
fast_tagged_memory_copy_to_user(void __user *dst, const void *src, size_t len,
		size_t *copied, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT, .prot = 1 };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	return native_fast_tagged_memory_copy((void __force *) dst, src, len,
			strd_opcode, ldrd_opcode, prefetch);
}
static __always_inline __must_check size_t
fast_tagged_memory_copy_from_user(void *dst, const void __user *src, size_t len,
		size_t *copied, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE, .prot = 1 };
	return native_fast_tagged_memory_copy(dst, (void __force *) src, len,
			strd_opcode, ldrd_opcode, prefetch);
}
static __always_inline __must_check size_t
fast_tagged_memory_copy_in_user(void __user *dst, const void __user *src, size_t len,
		size_t *copied, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT, .prot = 1 };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE, .prot = 1 };
	return native_fast_tagged_memory_copy((void __force *)  dst, (void __force *) src,
			len, strd_opcode, ldrd_opcode, prefetch);
}
static inline unsigned long
fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return native_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}

static inline void fast_tagged_memset_io(void *addr, u64 val, u64 tag, size_t len)
{
	ldst_rec_op_t st_op = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	(void) __recovery_memset_8(addr, val, tag, len, AW(st_op));
}

static __always_inline __must_check unsigned long
fast_tagged_memory_set_user(void __user *addr, u64 val, u64 tag,
		size_t len, size_t *cleared, u64 strd_opcode)
{
	return native_fast_tagged_memory_set((void __force *) addr, val,
			tag, len, strd_opcode);
}

static inline unsigned long
boot_fast_tagged_memory_copy(void *dst, const void *src, size_t len, int prefetch)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT };
	ldst_rec_op_t ldrd_opcode = (ldst_rec_op_t)
		{ .fmt = LDST_QWORD_FMT, .mas = MAS_FILL_OPERATION | MAS_BYPASS_L1_CACHE };
	return boot_native_fast_tagged_memory_copy(dst, src, len, AW(strd_opcode),
						   AW(ldrd_opcode), prefetch);
}
static inline void
boot_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	boot_native_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}
static inline unsigned long
extract_tags_32(u16 *dst, const void *src)
{
	return native_extract_tags_32(dst, src);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */


#define __HAVE_ARCH_MEMSET64
#ifdef __HAVE_ARCH_MEMSET64
static inline void *memset64(uint64_t *dst, uint64_t v, size_t count)
{
	if (__builtin_constant_p(count) && count <= 16) {
		/* Inline small memset's */
		if (count >= 1)
			dst[0] = v;
		if (count >= 2)
			dst[1] = v;
		if (count >= 3)
			dst[2] = v;
		if (count >= 4)
			dst[3] = v;
		if (count >= 5)
			dst[4] = v;
		if (count >= 6)
			dst[5] = v;
		if (count >= 7)
			dst[6] = v;
		if (count >= 8)
			dst[7] = v;
		if (count >= 9)
			dst[8] = v;
		if (count >= 10)
			dst[9] = v;
		if (count >= 11)
			dst[10] = v;
		if (count >= 12)
			dst[11] = v;
		if (count >= 13)
			dst[12] = v;
		if (count >= 14)
			dst[13] = v;
		if (count >= 15)
			dst[14] = v;
		if (count >= 16)
			dst[15] = v;
	} else {
		fast_tagged_memory_set(dst, v, 0, count << 3,
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT
				| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT);
	}

	return dst;
}
#endif

#endif /* _E2K_STRING_H_ */
