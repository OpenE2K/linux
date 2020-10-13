#ifndef _E2K_STRING_H_
#define _E2K_STRING_H_

#define __HAVE_ARCH_STRNLEN
extern size_t strnlen(const char *s, size_t count);

#define __HAVE_ARCH_STRLEN
extern size_t strlen(const char *s);

#define __HAVE_ARCH_MEMMOVE
extern void *memmove(void *dst, const void *src, size_t count);

#define __HAVE_ARCH_MEMCMP
extern int memcmp(const void *cs, const void *ct, size_t count);

#define __HAVE_ARCH_MEMSET
#ifdef __HAVE_ARCH_MEMSET
extern void __memset(void *, long, size_t);
#define memset(dst, c, n) _memset(dst, c, n, __alignof(*(dst)))
static inline void *_memset(void *dst, int c, size_t n,
		const unsigned long dst_align)
{
	if (__builtin_constant_p(n) && dst_align >= 8 && n < 136) {
		/* Inline small aligned memset's */
		u64 *l_dst = dst;
		long cc;

		cc = c & 0xff;
		cc = cc | (cc << 8);
		cc = cc | (cc << 16);
		cc = cc | (cc << 32);

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
	} else {
		if (__builtin_constant_p(n) && n <= 24) {
			int i;
			/* Inline small memset's */
			char *c_dst = dst;
			for (i = 0; i < n; i++)
				c_dst[i] = c;
		} else {
			long cc;

			cc = c & 0xff;
			cc = cc | (cc << 8);
			cc = cc | (cc << 16);
			cc = cc | (cc << 32);

			__memset(dst, cc, n);
		}
	}

	return dst;
}
#endif /* __HAVE_ARCH_MEMSET */

#define __HAVE_ARCH_MEMCPY
#ifdef __HAVE_ARCH_MEMCPY
extern void __memcpy(void *dst, const void *src, size_t n);
#define memcpy(dst, src, n) _memcpy(dst, src, n, __alignof(*(dst)))
static inline void *_memcpy(void *__restrict dst,
		const void *__restrict src, 
		size_t n, const unsigned long dst_align)
{
	/*
	 * As measurements show, an unaligned dst causes a 20x slowdown,
	 * but unaligned src causes only a 2x slowdown.
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

	if (__builtin_constant_p(n) && dst_align >= 8 && n < 136) {
		/* Inline small aligned memcpy's */
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
		__builtin_prefetch(src);
		__memcpy(dst, src, n);
	}

	return dst;
}
#endif /* __HAVE_ARCH_MEMCPY */

extern void recovery_memset_8(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode);
extern void _tagged_memcpy_8(void *dst, const void *src, size_t len);

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
 * of blocks larger than the size of the memory buffers - 1024 bytes on E3M).
 *
 * When copying from/to physical/IO memory, disable prefetch through the
 * last argument.
 *
 * On success returns len. On error returns the number of bytes actually
 * copied, which can be a little less than the actual copied size.
 * (For error returns to work the page fault handler should be set up
 * with BEGIN_USR_PFAULT("recovery_memcpy_fault")).
 */
extern unsigned long recovery_memcpy_8(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch);

extern int printk(const char * fmt, ...)
		__attribute__ ((format (printf, 1, 2)));

/**
 * tagged_memcpy_8() - copy memory along with tags
 *
 * All parameters must be 8-bytes aligned.
 */
static inline void tagged_memcpy_8(void *dst, const void *src, size_t n)
{
	if (unlikely(((unsigned long) dst & 0x7) || ((unsigned long) src & 0x7)
			|| ((unsigned long) n & 0x7))) {
		static bool once;

		if (unlikely(!once)) {
			once = true;
			printk("Bad parameters in tagged_memcpy_8: "
					"%lx %lx %lx\n", dst, src, n);
		}
	}

	_tagged_memcpy_8(dst, src, n);
}

#endif /* _E2K_STRING_H_ */
