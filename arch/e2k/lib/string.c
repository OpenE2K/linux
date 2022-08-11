/*
 * string routines
 *
 * This file contains memcpy/memset routines that are better done
 * in an architecture-specific manner due to speed..
 */


#include <linux/string.h>
#include <linux/export.h>
#include <asm/cacheflush.h>
#include <asm/word-at-a-time.h>


#ifdef BOOT
/* This file is included in kernel's builtin boot directly,
 * undefine EXPORT_SYMBOL to avoid linking errors. */
# undef EXPORT_SYMBOL
# define EXPORT_SYMBOL(sym)
#endif


#ifdef __HAVE_ARCH_MEMSET

EXPORT_SYMBOL(__recovery_memset_8);
EXPORT_SYMBOL(__recovery_memset_16);

void __memset(void *s, long c, size_t count)
{
	unsigned long head, head1, head3, head7, tail8, tail12, tail14;
	void *tail;

	if (unlikely(count < 16)) {
		u64 n8, n12, n14;

		n8 = count & 8;
		n12 = count & 12;
		n14 = count & 14;

		if (count & 8)
			*(u64 *) s = c;
		if (count & 4)
			*(u32 *) (s + n8) = c;
		if (count & 2)
			*(u16 *) (s + n12) = c;
		if (count & 1)
			*(u8 *) (s + n14) = c;

		return;
	}

	/* Set the head */
	head = 16 - ((unsigned long) s & 0xfUL);

	head1 = (unsigned long) s & 1;	/* s & 1 == head & 1 */
	head3 = head & 3;
	head7 = head & 7;

	if (head1)
		*(u8 *) s = c;
	if (head & 2)
		*(u16 *) (s + head1) = c;
	if (head & 4)
		*(u32 *) (s + head3) = c;
	if (head & 8)
		*(u64 *) (s + head7) = c;

	s = PTR_ALIGN(s, 16);
	count -= head & 0xf;

	/* Set the tail */
	tail = s + (count & ~0xfUL);

	tail8 = count & 8;
	tail12 = count & 12;
	tail14 = count & 14;

	if (count & 8)
		*(u64 *) tail = c;
	if (count & 4)
		*(u32 *) (tail + tail8) = c;
	if (count & 2)
		*(u16 *) (tail + tail12) = c;
	if (count & 1)
		*(u8 *) (tail + tail14) = c;

	if (count & ~0xfUL) {
		fast_tagged_memory_set(s, c, 0, count & ~0xfUL,
			LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT
			| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT);
	}
}
EXPORT_SYMBOL(__memset);

/* Same as __memset but makes sure that stores from the same long
 * instruction land in the same page (to ensure ordering). */
void __memset_io(void *s, long c, size_t count)
{
	unsigned long align = (unsigned long) s & 0xf, head, head1, head2,
			head3, head4, head7, head8, tail1, tail2, tail4, tail6;

	if (unlikely(count < 16)) {
		char *dst = (char *) s;

		/* Ugly, but otherwise lcc won't do it this way */
		if (count > 0)
			WRITE_ONCE(dst[0], c);
		if (count > 1)
			WRITE_ONCE(dst[1], c);
		if (count > 2)
			WRITE_ONCE(dst[2], c);
		if (count > 3)
			WRITE_ONCE(dst[3], c);
		if (count > 4)
			WRITE_ONCE(dst[4], c);
		if (count > 5)
			WRITE_ONCE(dst[5], c);
		if (count > 6)
			WRITE_ONCE(dst[6], c);
		if (count > 7)
			WRITE_ONCE(dst[7], c);
		if (count > 8)
			WRITE_ONCE(dst[8], c);
		if (count > 9)
			WRITE_ONCE(dst[9], c);
		if (count > 10)
			WRITE_ONCE(dst[10], c);
		if (count > 11)
			WRITE_ONCE(dst[11], c);
		if (count > 12)
			WRITE_ONCE(dst[12], c);
		if (count > 13)
			WRITE_ONCE(dst[13], c);
		if (count > 14)
			WRITE_ONCE(dst[14], c);

		return;
	}

	/* Set the head */
	head = 16 - align;

	head1 = (unsigned long) s & 1;	/* s & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;
	head7 = head & 7;
	head8 = head & 8;

	if (head1)
		WRITE_ONCE(*(u8 *) s, c);
	if (head2)
		WRITE_ONCE(*(u16 *) (s + head1), c);
	if (head4)
		WRITE_ONCE(*(u32 *) (s + head3), c);
	if (head8)
		WRITE_ONCE(*(u64 *) (s + head7), c);

	s = PTR_ALIGN(s, 16);
	count -= head & 0xf;

	fast_tagged_memory_set(s, c, 0, count & ~0x7UL,
			LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT
			| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT);

	/* Set the tail */
	s += count & ~0x7UL;

	tail1 = count & 1;
	tail2 = count & 2;
	tail4 = count & 4;
	tail6 = count & 6;

	if (tail4)
		WRITE_ONCE(*(u32 *) s, c);
	if (tail2)
		WRITE_ONCE(*(u16 *) (s + tail4), c);
	if (tail1)
		WRITE_ONCE(*(u8 *) (s + tail6), c);
}
EXPORT_SYMBOL(__memset_io);


#undef memset
void *memset(void *dst, int c, size_t n)
{
	long cc = __builtin_e2k_pshufb(c, c, 0);

	__memset(dst, cc, n);

	return dst;
}
EXPORT_SYMBOL(memset);
#endif /* __HAVE_ARCH_MEMSET */


#ifdef __HAVE_ARCH_MEMCPY
static __always_inline void aligned_memcpy(char *__restrict dst,
		const char *__restrict src, size_t n)
{
	int i;

	if (IS_ALIGNED((unsigned long) src, 4) &&
	    IS_ALIGNED((unsigned long) dst, 4)) {
		u32 *dst32 = (u32 *) dst;
		u32 *src32 = (u32 *) src;

		for (i = 0; i < n / 4; i++)
			dst32[i] = src32[i];

		dst += n & ~0x3UL;
		src += n & ~0x3UL;
		for (i = 0; i < (n & 0x3); i++)
			dst[i] = src[i];
	} else if (IS_ALIGNED((unsigned long) src, 2) &&
		   IS_ALIGNED((unsigned long) dst, 2)) {
		u16 *dst16 = (u16 *) dst;
		u16 *src16 = (u16 *) src;

		for (i = 0; i < n / 2; i++)
			dst16[i] = src16[i];

		if (n & 1)
			dst[n - 1] = src[n - 1];
	} else {
		for (i = 0; i < n; i++)
			dst[i] = src[i];
	}
}


#if !defined(CONFIG_BOOT_E2K)
# define HAS_HWBUG_UNALIGNED_LOADS unlikely(cpu_has(CPU_HWBUG_UNALIGNED_LOADS))
#else
# define HAS_HWBUG_UNALIGNED_LOADS IS_ENABLED(CONFIG_CPU_ES2)
#endif

static __always_inline void smallest_memcpy(char *__restrict dst,
		const char *__restrict src, size_t n)
{
	u64 n8, n12, n14;

	n8 = n & 8;
	n12 = n & 12;
	n14 = n & 14;

	if (n & 8)
		*(u64 *) dst = *(u64 *) src;
	if (n & 4)
		*(u32 *) (dst + n8) = *(u32 *) (src + n8);
	if (n & 2)
		*(u16 *) (dst + n12) = *(u16 *) (src + n12);
	if (n & 1)
		*(u8 *) (dst + n14) = *(u8 *) (src + n14);
}

void *__memcpy(void *dst, const void *src, size_t n)
{
	int hwbug = HAS_HWBUG_UNALIGNED_LOADS;
	void *const orig_dst = dst;
	unsigned long head, tail, head1, head3, head7,
			tail8, tail12, tail14;
	u64 head_val8, tail_val8;
	u32 head_val4, tail_val4;
	u16 head_val2, tail_val2;
	u8 head_val1, tail_val1;
	size_t length, orig_n = n;

	if (hwbug) {
		/*
		 * bug 103351 comment 46 - try to avoid unaligned accesses
		 */
		if (!IS_ALIGNED((unsigned long) src, 8) ||
		    !IS_ALIGNED((unsigned long) dst, 8)) {
			/* can't use the optimized loop below */
			aligned_memcpy(dst, src, n);

			return orig_dst;
		}

		prefetch_nospec_range(src, n);

		__E2K_WAIT(_ld_c);
	}

	if (unlikely(n < 16)) {
		smallest_memcpy(dst, src, n);

		return orig_dst;
	}

	/* Copy the head */

	head = 16 - ((unsigned long) dst & 0xfUL);

	n -= head & 0xf;
	length = (orig_n >= 2 * 8192) ? 8192 : (n & ~0xfUL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head3 = head & 3;
	head7 = head & 7;

	tail = n;
	tail8 = tail & 8;
	tail12 = tail & 12;
	tail14 = tail & 14;

	if (head & 1)
		head_val1 = *(u8 *) src;
	if (head & 2)
		head_val2 = *(u16 *) (src + head1);
	if (head & 4)
		head_val4 = *(u32 *) (src + head3);
	if (head & 8)
		head_val8 = *(u64 *) (src + head7);

	src += head & 0xf;
	dst = PTR_ALIGN(dst, 16);

	/* Do the copy. Bypass L1 cache - usually after memcpy memory
	 * is not accessed immediately since user knows its contents */
	do {
		n -= length;

		/* Copy with tags. This is useful for access_process_vm. */
		if (likely(length)) {
			fast_tagged_memory_copy(dst, src, length,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				!hwbug);
		}

		src += length;
		dst += length;

		length = (n >= 2 * 8192) ? 8192 : (n & ~0xfUL);
	} while (unlikely(n >= 16));

	/* Copy the tail */

	if (tail & 8)
		tail_val8 = *(u64 *) src;
	if (tail & 4)
		tail_val4 = *(u32 *) (src + tail8);
	if (tail & 2)
		tail_val2 = *(u16 *) (src + tail12);
	if (tail & 1)
		tail_val1 = *(u8 *) (src + tail14);

	if (head & 1)
		*(u8 *) orig_dst = head_val1;
	if (head & 2)
		*(u16 *) (orig_dst + head1) = head_val2;
	if (head & 4)
		*(u32 *) (orig_dst + head3) = head_val4;
	if (head & 8)
		*(u64 *) (orig_dst + head7) = head_val8;

	if (tail & 8)
		*(u64 *) dst = tail_val8;
	if (tail & 4)
		*(u32 *) (dst + tail8) = tail_val4;
	if (tail & 2)
		*(u16 *) (dst + tail12) = tail_val2;
	if (tail & 1)
		*(u8 *) (dst + tail14) = tail_val1;

	return orig_dst;
}
EXPORT_SYMBOL(__memcpy);

#undef memcpy
void *memcpy(void *dst, const void *src, size_t n)
{
	return __memcpy(dst, src, n);
}
EXPORT_SYMBOL(memcpy);

/* Kernel's decompressor and built-in boot do not use the code below,
 * so keep things simple with this #ifndef */
# ifndef BOOT
static void __memcpy_from_io_slow(void *__restrict dst,
				 const volatile void *__restrict src, size_t n)
{
	unsigned long head, tail, head1, head2, head3, head4, head7, head8,
			head15, head16, tail1, tail2, tail4, tail6;
	u64 head_val8, head_val16_lo, head_val16_hi;
	u32 head_val4, tail_val4;
	u16 head_val2, tail_val2;
	u8 head_val1, tail_val1;

	if (unlikely(n < 32)) {
		int i;

		for (i = 0; i < n; i++) {
			WRITE_ONCE(((u8 *) dst)[i],
					READ_ONCE(((u8 *) src)[i]));
			__E2K_WAIT(_st_c);
		}

		return;
	}

	/* Copy the head */

	head = 32 - ((unsigned long) src & 0x1fUL);

	head1 = (unsigned long) src & 1;	/* src & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;
	head7 = head & 7;
	head8 = head & 8;
	head15 = head & 15;
	head16 = head & 16;

	if (head1) {
		head_val1 = READ_ONCE(*(u8 *) src);
		__E2K_WAIT(_ld_c);
	}
	if (head2) {
		head_val2 = READ_ONCE(*(u16 *) (src + head1));
		__E2K_WAIT(_ld_c);
	}
	if (head4) {
		head_val4 = READ_ONCE(*(u32 *) (src + head3));
		__E2K_WAIT(_ld_c);
	}
	if (head8) {
		head_val8 = READ_ONCE(*(u64 *) (src + head7));
		__E2K_WAIT(_ld_c);
	}
	if (head16) {
		head_val16_lo = READ_ONCE(*(u64 *) (src + head15));
		__E2K_WAIT(_ld_c);
		head_val16_hi = READ_ONCE(*(u64 *) (src + head15 + 8));
		__E2K_WAIT(_ld_c);
	}

	if (head1) {
		WRITE_ONCE(*(u8 *) dst, head_val1);
		__E2K_WAIT(_st_c);
	}
	if (head2) {
		WRITE_ONCE(*(u16 *) (dst + head1), head_val2);
		__E2K_WAIT(_st_c);
	}
	if (head4) {
		WRITE_ONCE(*(u32 *) (dst + head3), head_val4);
		__E2K_WAIT(_st_c);
	}
	if (head8) {
		WRITE_ONCE(*(u64 *) (dst + head7), head_val8);
		__E2K_WAIT(_st_c);
	}
	if (head16) {
		WRITE_ONCE(*(u64 *) (dst + head15), head_val16_lo);
		__E2K_WAIT(_st_c);
		WRITE_ONCE(*(u64 *) (dst + head15 + 8), head_val16_hi);
		__E2K_WAIT(_st_c);
	}

	dst += head & 0x1f;
	src = PTR_ALIGN(src, 32);
	n -= head & 0x1f;

	while (n >= 8) {
		WRITE_ONCE(*(u64 *) dst, READ_ONCE(*(u64 *) src));
		__E2K_WAIT(_st_c);
		n -= 8;
		src += 8;
		dst += 8;
	}

	/* Copy the tail */
	tail = n;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail6 = tail & 6;

	if (tail4) {
		tail_val4 = READ_ONCE(*(u32 *) src);
		__E2K_WAIT(_ld_c);
	}
	if (tail2) {
		tail_val2 = READ_ONCE(*(u16 *) (src + tail4));
		__E2K_WAIT(_ld_c);
	}
	if (tail1) {
		tail_val1 = READ_ONCE(*(u8 *) (src + tail6));
		__E2K_WAIT(_ld_c);
	}

	if (tail4) {
		WRITE_ONCE(*(u32 *) dst, tail_val4);
		__E2K_WAIT(_st_c);
	}
	if (tail2) {
		WRITE_ONCE(*(u16 *) (dst + tail4), tail_val2);
		__E2K_WAIT(_st_c);
	}
	if (tail1) {
		WRITE_ONCE(*(u8 *) (dst + tail6), tail_val1);
		__E2K_WAIT(_st_c);
	}
}

/*
 * __memcpy_fromio() - the same as __memcpy() but with ordered loads
 * and disabled prefetch. Also makes sure that loads from the same
 * long instruction land in the same page (to ensure ordering).
 */
void __memcpy_fromio(void *__restrict dst, const volatile void __iomem *__restrict src, size_t n)
{
	const void *const orig_dst = dst;
	unsigned long head, tail, head1, head2, head3, head4, head7, head8,
			head15, head16, tail1, tail2, tail4, tail6;
	u64 head_val8, head_val16_lo, head_val16_hi;
	u32 head_val4, tail_val4;
	u16 head_val2, tail_val2;
	u8 head_val1, tail_val1;

	if (unlikely(cpu_has(CPU_HWBUG_PIO_READS))) {
		__memcpy_from_io_slow(dst, src, n);
		return;
	}

	if (unlikely(n < 32)) {
		int i;

		for (i = 0; i < n; i++)
			((u8 *) dst)[i] = READ_ONCE(((u8 *) src)[i]);

		return;
	}

	/* Copy the head */

	head = 32 - ((unsigned long) src & 0x1fUL);

	head1 = (unsigned long) src & 1;	/* src & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;
	head7 = head & 7;
	head8 = head & 8;
	head15 = head & 15;
	head16 = head & 16;

	if (head1)
		head_val1 = READ_ONCE(*(u8 *) src);
	if (head2)
		head_val2 = READ_ONCE(*(u16 *) (src + head1));
	if (head4)
		head_val4 = READ_ONCE(*(u32 *) (src + head3));
	if (head8)
		head_val8 = READ_ONCE(*(u64 *) (src + head7));
	if (head16) {
		head_val16_lo = READ_ONCE(*(u64 *) (src + head15));
		head_val16_hi = READ_ONCE(*(u64 *) (src + head15 + 8));
	}

	dst += head & 0x1f;
	src = PTR_ALIGN(src, 32);
	n -= head & 0x1f;

	/* Do the copy. Bypass L1 cache - usually after memcpy memory
	 * is not accessed immediately since user knows its contents */
	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);

		n -= length;

		fast_tagged_memory_copy(dst, (__force const void *__restrict) src, length,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				0);

		src += length;
		dst += length;
	} while (unlikely(n >= 8));

	/* Copy the tail */
	tail = n;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail6 = tail & 6;

	if (tail4)
		tail_val4 = READ_ONCE(*(u32 *) src);
	if (tail2)
		tail_val2 = READ_ONCE(*(u16 *) (src + tail4));
	if (tail1)
		tail_val1 = READ_ONCE(*(u8 *) (src + tail6));

	if (head1)
		*(u8 *) orig_dst = head_val1;
	if (head2)
		*(u16 *) (orig_dst + head1) = head_val2;
	if (head4)
		*(u32 *) (orig_dst + head3) = head_val4;
	if (head8)
		*(u64 *) (orig_dst + head7) = head_val8;
	if (head16) {
		*(u64 *) (orig_dst + head15) = head_val16_lo;
		*(u64 *) (orig_dst + head15 + 8) = head_val16_hi;
	}

	if (tail4)
		*(u32 *) dst = tail_val4;
	if (tail2)
		*(u16 *) (dst + tail4) = tail_val2;
	if (tail1)
		*(u8 *) (dst + tail6) = tail_val1;
}
EXPORT_SYMBOL(__memcpy_fromio);

static __always_inline void smallest_memcpy_toio(volatile char *__restrict dst,
		const char *__restrict src, size_t n)
{
	char c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14;

	/* Ugly, but otherwise lcc won't do it this way */

	if (n > 0)
		c0 = src[0];
	if (n > 1)
		c1 = src[1];
	if (n > 2)
		c2 = src[2];
	if (n > 3)
		c3 = src[3];
	if (n > 4)
		c4 = src[4];
	if (n > 5)
		c5 = src[5];
	if (n > 6)
		c6 = src[6];
	if (n > 7)
		c7 = src[7];
	if (n > 8)
		c8 = src[8];
	if (n > 9)
		c9 = src[9];
	if (n > 10)
		c10 = src[10];
	if (n > 11)
		c11 = src[11];
	if (n > 12)
		c12 = src[12];
	if (n > 13)
		c13 = src[13];
	if (n > 14)
		c14 = src[14];

	if (n > 0)
		WRITE_ONCE(dst[0], c0);
	if (n > 1)
		WRITE_ONCE(dst[1], c1);
	if (n > 2)
		WRITE_ONCE(dst[2], c2);
	if (n > 3)
		WRITE_ONCE(dst[3], c3);
	if (n > 4)
		WRITE_ONCE(dst[4], c4);
	if (n > 5)
		WRITE_ONCE(dst[5], c5);
	if (n > 6)
		WRITE_ONCE(dst[6], c6);
	if (n > 7)
		WRITE_ONCE(dst[7], c7);
	if (n > 8)
		WRITE_ONCE(dst[8], c8);
	if (n > 9)
		WRITE_ONCE(dst[9], c9);
	if (n > 10)
		WRITE_ONCE(dst[10], c10);
	if (n > 11)
		WRITE_ONCE(dst[11], c11);
	if (n > 12)
		WRITE_ONCE(dst[12], c12);
	if (n > 13)
		WRITE_ONCE(dst[13], c13);
	if (n > 14)
		WRITE_ONCE(dst[14], c14);
}

/*
 * __memcpy_toio() - the same as __memcpy() but with ordered stores
 * and makes sure that stores from the same long instruction land in
 * the same page (to ensure ordering).
 */
void __memcpy_toio(volatile void __iomem *__restrict dst, const void *__restrict src, size_t n)
{
	int hwbug = HAS_HWBUG_UNALIGNED_LOADS;
	unsigned long head, tail, head1, head2, head3, head4, head7, head8,
			tail1, tail2, tail4, tail6;
	u64 tmp8;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;

	if (unlikely(n < 16)) {
		smallest_memcpy_toio(dst, src, n);

		return;
	}

	if (hwbug) {
		prefetch_nospec_range(src, n);
		__E2K_WAIT(_ld_c);
	}

	/* Copy the head */

	head = 16 - ((unsigned long) dst & 0xfUL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;
	head7 = head & 7;
	head8 = head & 8;

	if (head1)
		tmp1 = *(u8 *) src;
	if (head2)
		tmp2 = *(u16 *) (src + head1);
	if (head4)
		tmp4 = *(u32 *) (src + head3);
	if (head8)
		tmp8 = *(u64 *) (src + head7);

	if (head1)
		WRITE_ONCE(*(u8 *) dst, tmp1);
	if (head2)
		WRITE_ONCE(*(u16 *) (dst + head1), tmp2);
	if (head4)
		WRITE_ONCE(*(u32 *) (dst + head3), tmp4);
	if (head8)
		WRITE_ONCE(*(u64 *) (dst + head7), tmp8);

	src += head & 0xf;
	dst = PTR_ALIGN(dst, 16);
	n -= head & 0xf;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);

		n -= length;

		fast_tagged_memory_copy((__force void *__restrict) dst, src, length,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				!hwbug);

		src += length;
		dst += length;
	} while (unlikely(n >= 8));

	/* Copy the tail */
	tail = n;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail6 = tail & 6;

	if (tail4)
		tmp4 = *(u32 *) src;
	if (tail2)
		tmp2 = *(u16 *) (src + tail4);
	if (tail1)
		tmp1 = *(u8 *) (src + tail6);

	if (tail4)
		WRITE_ONCE(*(u32 *) dst, tmp4);
	if (tail2)
		WRITE_ONCE(*(u16 *) (dst + tail4), tmp2);
	if (tail1)
		WRITE_ONCE(*(u8 *) (dst + tail6), tmp1);
}
EXPORT_SYMBOL(__memcpy_toio);


/**
 * tagged_memcpy_8() - copy memory along with tags
 *
 * All parameters must be 8-bytes aligned.
 */
void __tagged_memcpy_8(void *dst, const void *src, size_t n)
{
	int hwbug = HAS_HWBUG_UNALIGNED_LOADS;

	WARN_ONCE(((unsigned long) dst & 0x7) || ((unsigned long) src & 0x7) ||
			((unsigned long) n & 0x7),
		"BUG: bad parameters in tagged_memcpy_8: %lx %lx %lx\n",
		dst, src, n);

	if (hwbug) {
		prefetch_nospec_range(src, n);
		__E2K_WAIT(_ld_c);
	}

	/* Both src and dst are 8-bytes aligned. */
	for (;;) {
		/* Copy with 8192 bytes blocks */
		if (n >= 2 * 8192) {
			fast_tagged_memory_copy(dst, src, 8192,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				!hwbug);
			n -= 8192;
			src += 8192;
			dst += 8192;
		} else {
			fast_tagged_memory_copy(dst, src, n & ~0x7,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				!hwbug);
			break;
		}
	};
}
EXPORT_SYMBOL(__tagged_memcpy_8);
# endif /* BOOT */
#endif /* __HAVE_ARCH_MEMCPY */

#ifdef __HAVE_ARCH_MEMMOVE
void *memmove(void *dst, const void *src, size_t count)
{
	char *tmp;
	const char *s;

	prefetch(src);

	if (dst + count <= src || dst >= src + count)
		return __memcpy(dst, src, count);

	if (dst <= src) {
		tmp = dst;
		s = src;
		while (count--)
			*tmp++ = *s++;
	} else {
		tmp = dst;
		tmp += count;
		s = src;
		s += count;
		while (count--)
			*--tmp = *--s;
	}
	return dst;
}
EXPORT_SYMBOL(memmove);
#endif

#ifdef __HAVE_ARCH_MEMCMP
int __memcmp(const void *p1, const void *p2, size_t n)
{
	u64 v1, v2;
	unsigned long head, head1, head2, head3, head4,
			tail, tail1, tail2, tail4, tail6;

	if (unlikely(n < 8)) {
		const u8 *cp1 = p1, *cp2 = p2;
		int i, diff;

		for (i = 0; i < n; i++) {
			diff = cp1[i] - cp2[i];
			if (diff)
				return diff;
		}

		return 0;
	}

	/* Compare the head */
	head = 8 - ((unsigned long) p1 & 0x7UL);

	head1 = (unsigned long) p1 & 1;	/* dst & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1) {
		v1 = *(u8 *) p1;
		v2 = *(u8 *) p2;
		if (v1 != v2)
			return v1 - v2;
	}
	if (head2) {
		v1 = *(u16 *) (p1 + head1);
		v2 = *(u16 *) (p2 + head1);
		if (v1 != v2)
			return (u32) __swab16(v1) - (u32) __swab16(v2);
	}
	if (head4) {
		v1 = *(u32 *) (p1 + head3);
		v2 = *(u32 *) (p2 + head3);
		if (v1 != v2)
			return ((u32) __builtin_bswap32(v1) >
				(u32) __builtin_bswap32(v2)) ? 1 : -1;
	}

	p2 += head & 0x7;
	p1 = PTR_ALIGN(p1, 8);
	n -= head & 0x7;

	/* At least p1 is aligned at 8-bytes boundary.
	 * Do the check with 8-bytes loads. */

	for (; n >= 8; p1 += 8, p2 += 8, n -= 8) {
		v1 = *(u64 *) p1;
		v2 = *(u64 *) p2;
		if (v1 != v2)
			break;
	}

	if (v1 != v2)
		return (__builtin_bswap64(v1) > __builtin_bswap64(v2)) ? 1 : -1;

	tail = n;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail6 = tail & 6;

	if (tail4) {
		v1 = *(u32 *) p1;
		v2 = *(u32 *) p2;
		if (v1 != v2)
			return ((u32) __builtin_bswap32(v1) >
				(u32) __builtin_bswap32(v2)) ? 1 : -1;
	}
	if (tail2) {
		v1 = *(u16 *) (p1 + tail4);
		v2 = *(u16 *) (p2 + tail4);
		if (v1 != v2)
			return (u32) __swab16(v1) - (u32) __swab16(v2);
	}
	if (tail1) {
		v1 = *(u8 *) (p1 + tail6);
		v2 = *(u8 *) (p2 + tail6);
		if (v1 != v2)
			return v1 - v2;
	}

	return 0;
}
EXPORT_SYMBOL(__memcmp);

#undef memcmp
int memcmp(const void *p1, const void *p2, size_t n)
{
	return __memcmp(p1, p2, n);
}
EXPORT_SYMBOL(memcmp);
#endif

#ifdef __HAVE_ARCH_STRNLEN
size_t strnlen(const char *src, size_t count)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	long align, res = 0;
	unsigned long c, max = count;

	if (unlikely(!count))
		return 0;

	align = (sizeof(long) - 1) & (unsigned long) src;
	src -= align;
	/* Check for overflows */
	max = ((long) max >= 0) ? (max + align) : -1ul;

	c = *(unsigned long *) src;
	c |= aligned_byte_mask(align);

	for (;;) {
		unsigned long data;
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			res += find_zero(data) - align;
			if (res > count)
				res = count;
			return res;
		}
		res += sizeof(unsigned long);
		if (unlikely(max <= sizeof(unsigned long)))
			break;
		max -= sizeof(unsigned long);
		c = *(unsigned long *) (src + res);
	}
	res -= align;

	return count;
}
EXPORT_SYMBOL(strnlen);
#endif


#ifdef __HAVE_ARCH_STRLEN
/**
 * strlen - Find the length of a string
 * @s: The string to be sized
 */
size_t strlen(const char *src)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	long align, res = 0;
	unsigned long c;

	align = (sizeof(long) - 1) & (unsigned long) src;
	src -= align;

	c = *(unsigned long *) src;
	c |= aligned_byte_mask(align);

	for (;;) {
		unsigned long data;
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			return res + find_zero(data) - align;
		}
		res += sizeof(unsigned long);
		c = *(unsigned long *) (src + res);
	}
}
EXPORT_SYMBOL(strlen);
#endif
