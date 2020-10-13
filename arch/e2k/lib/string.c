/*
 * string routines
 *
 * This file contains memcpy/memset routines that are better done
 * in an architecture-specific manner due to speed..
 */


#include <linux/string.h>
#include <linux/module.h>
#include <asm/cacheflush.h>
#include <asm/word-at-a-time.h>


#ifdef BOOT
/* This file is included in kernel's builtin boot directly,
 * undefine EXPORT_SYMBOL to avoid linking errors. */
# undef EXPORT_SYMBOL
# define EXPORT_SYMBOL(sym)
#endif


#ifdef __HAVE_ARCH_MEMSET
extern void recovery_memset_8(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode);
EXPORT_SYMBOL(recovery_memset_8);

void __memset(void *s, long c, size_t count)
{
	unsigned long align = (unsigned long) s & 0x7, head,
			head1, head2, head3, head4, tail1, tail2, tail4, tail6;

	if (unlikely(count < 8)) {
		char *dst = (char *) s;

		/* Ugly, but otherwise lcc won't do it this way */
		if (count > 0)
			ACCESS_ONCE(dst[0]) = c;
		if (count > 1)
			ACCESS_ONCE(dst[1]) = c;
		if (count > 2)
			ACCESS_ONCE(dst[2]) = c;
		if (count > 3)
			ACCESS_ONCE(dst[3]) = c;
		if (count > 4)
			ACCESS_ONCE(dst[4]) = c;
		if (count > 5)
			ACCESS_ONCE(dst[5]) = c;
		if (count > 6)
			ACCESS_ONCE(dst[6]) = c;

		return;
	}

	/* Set the head */
	head = 8 - align;

	head1 = (unsigned long) s & 1;	/* s & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1)
		ACCESS_ONCE(*(u8 *) s) = c;
	if (head2)
		ACCESS_ONCE(*(u16 *) (s + head1)) = c;
	if (head4)
		ACCESS_ONCE(*(u32 *) (s + head3)) = c;

	s = PTR_ALIGN(s, 8);
	count -= head & 0x7;

	/* Bypass L1 cache - usually after memset memory is not accessed
	 * immediately since user knows its contents */
	recovery_memset_8(s, c, 0, count & ~0x7UL,
			LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT
			| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT);

	/* Set the tail */
	s += count & ~0x7UL;

	tail1 = count & 1;
	tail2 = count & 2;
	tail4 = count & 4;
	tail6 = count & 6;

	if (tail4)
		ACCESS_ONCE(*(u32 *) s) = c;
	if (tail2)
		ACCESS_ONCE(*(u16 *) (s + tail4)) = c;
	if (tail1)
		ACCESS_ONCE(*(u8 *) (s + tail6)) = c;
}
EXPORT_SYMBOL(__memset);

#undef memset
void *memset(void *dst, int c, size_t n)
{
	long cc;

	cc = c & 0xff;
	cc = cc | (cc << 8);
	cc = cc | (cc << 16);
	cc = cc | (cc << 32);

	__memset(dst, cc, n);

	return dst;
}
EXPORT_SYMBOL(memset);
#endif /* __HAVE_ARCH_MEMSET */


#ifdef __HAVE_ARCH_MEMCPY
static __always_inline void smallest_memcpy(char *__restrict dst,
		const char *__restrict src, size_t n)
{
	char c0, c1, c2, c3, c4, c5, c6;

	/* Ugly, but otherwise lcc won't do it this way */

	if (n > 0)
		c0 = ACCESS_ONCE(src[0]);
	if (n > 1)
		c1 = ACCESS_ONCE(src[1]);
	if (n > 2)
		c2 = ACCESS_ONCE(src[2]);
	if (n > 3)
		c3 = ACCESS_ONCE(src[3]);
	if (n > 4)
		c4 = ACCESS_ONCE(src[4]);
	if (n > 5)
		c5 = ACCESS_ONCE(src[5]);
	if (n > 6)
		c6 = ACCESS_ONCE(src[6]);

	if (n > 0)
		ACCESS_ONCE(dst[0]) = c0;
	if (n > 1)
		ACCESS_ONCE(dst[1]) = c1;
	if (n > 2)
		ACCESS_ONCE(dst[2]) = c2;
	if (n > 3)
		ACCESS_ONCE(dst[3]) = c3;
	if (n > 4)
		ACCESS_ONCE(dst[4]) = c4;
	if (n > 5)
		ACCESS_ONCE(dst[5]) = c5;
	if (n > 6)
		ACCESS_ONCE(dst[6]) = c6;
}

void __memcpy(void *__restrict dst, const void *__restrict src, size_t n)
{
	void *const orig_dst = dst;
	unsigned long head, tail, head1, head2, head3, head4,
			tail1, tail2, tail4, tail6;
	u32 head_val4, tail_val4;
	u16 head_val2, tail_val2;
	u8 head_val1, tail_val1;

	if (unlikely(n < 8)) {
		smallest_memcpy(dst, src, n);

		return;
	}

	/* Copy the head */

	head = 8 - ((unsigned long) dst & 0x7UL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1)
		head_val1 = ACCESS_ONCE(*(u8 *) src);
	if (head2)
		head_val2 = ACCESS_ONCE(*(u16 *) (src + head1));
	if (head4)
		head_val4 = ACCESS_ONCE(*(u32 *) (src + head3));

	src += head & 0x7;
	dst = PTR_ALIGN(dst, 8);
	n -= head & 0x7;

	/* Do the copy. Bypass L1 cache - usually after memcpy memory
	 * is not accessed immediately since user knows its contents */
	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);

		n -= length;

		/* Copy with tags. This is useful for access_process_vm. */
		recovery_memcpy_8(dst, src, length,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				1);

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
		tail_val4 = ACCESS_ONCE(*(u32 *) src);
	if (tail2)
		tail_val2 = ACCESS_ONCE(*(u16 *) (src + tail4));
	if (tail1)
		tail_val1 = ACCESS_ONCE(*(u8 *) (src + tail6));

	if (head1)
		ACCESS_ONCE(*(u8 *) orig_dst) = head_val1;
	if (head2)
		ACCESS_ONCE(*(u16 *) (orig_dst + head1)) = head_val2;
	if (head4)
		ACCESS_ONCE(*(u32 *) (orig_dst + head3)) = head_val4;

	if (tail4)
		ACCESS_ONCE(*(u32 *) dst) = tail_val4;
	if (tail2)
		ACCESS_ONCE(*(u16 *) (dst + tail4)) = tail_val2;
	if (tail1)
		ACCESS_ONCE(*(u8 *) (dst + tail6)) = tail_val1;
}
EXPORT_SYMBOL(__memcpy);

#undef memcpy
void *memcpy(void *dst, const void *src, size_t n)
{
	__memcpy(dst, src, n);

	return dst;
}
EXPORT_SYMBOL(memcpy);

/*
 * __memcpy_fromio() - the same as __memcpy() but with ordered loads
 * and disabled prefetch.
 */
void __memcpy_fromio(void *__restrict dst, const void *__restrict src, size_t n)
{
	void *const orig_dst = dst;
	unsigned long head, tail, head1, head2, head3, head4,
			tail1, tail2, tail4, tail6;
	u32 head_val4, tail_val4;
	u16 head_val2, tail_val2;
	u8 head_val1, tail_val1;

	if (unlikely(n < 8)) {
		smallest_memcpy(dst, src, n);

		return;
	}

	/* Copy the head */

	head = 8 - ((unsigned long) dst & 0x7UL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1)
		head_val1 = ACCESS_ONCE(*(u8 *) src);
	if (head2)
		head_val2 = ACCESS_ONCE(*(u16 *) (src + head1));
	if (head4)
		head_val4 = ACCESS_ONCE(*(u32 *) (src + head3));

	src += head & 0x7;
	dst = PTR_ALIGN(dst, 8);
	n -= head & 0x7;

	/* Do the copy. Bypass L1 cache - usually after memcpy memory
	 * is not accessed immediately since user knows its contents */
	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);

		n -= length;

		recovery_memcpy_8(dst, src, length,
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT |
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT,
				MAS_FILL_OPERATION << LDST_REC_OPC_MAS_SHIFT |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT |
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT,
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
		tail_val4 = ACCESS_ONCE(*(u32 *) src);
	if (tail2)
		tail_val2 = ACCESS_ONCE(*(u16 *) (src + tail4));
	if (tail1)
		tail_val1 = ACCESS_ONCE(*(u8 *) (src + tail6));

	if (head1)
		ACCESS_ONCE(*(u8 *) orig_dst) = head_val1;
	if (head2)
		ACCESS_ONCE(*(u16 *) (orig_dst + head1)) = head_val2;
	if (head4)
		ACCESS_ONCE(*(u32 *) (orig_dst + head3)) = head_val4;

	if (tail4)
		ACCESS_ONCE(*(u32 *) dst) = tail_val4;
	if (tail2)
		ACCESS_ONCE(*(u16 *) (dst + tail4)) = tail_val2;
	if (tail1)
		ACCESS_ONCE(*(u8 *) (dst + tail6)) = tail_val1;
}
EXPORT_SYMBOL(__memcpy_fromio);

/*
 * __memcpy_toio() - the same as __memcpy() but with ordered stores
 */
void __memcpy_toio(void *__restrict dst, const void *__restrict src, size_t n)
{
	unsigned long head, tail, head1, head2, head3, head4,
			tail1, tail2, tail4, tail6;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;

	if (unlikely(n < 8)) {
		smallest_memcpy(dst, src, n);

		return;
	}

	/* Copy the head */

	head = 8 - ((unsigned long) dst & 0x7UL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1)
		tmp1 = ACCESS_ONCE(*(u8 *) src);
	if (head2)
		tmp2 = ACCESS_ONCE(*(u16 *) (src + head1));
	if (head4)
		tmp4 = ACCESS_ONCE(*(u32 *) (src + head3));

	if (head1)
		ACCESS_ONCE(*(u8 *) dst) = tmp1;
	if (head2)
		ACCESS_ONCE(*(u16 *) (dst + head1)) = tmp2;
	if (head4)
		ACCESS_ONCE(*(u32 *) (dst + head3)) = tmp4;

	src += head & 0x7;
	dst = PTR_ALIGN(dst, 8);
	n -= head & 0x7;

	/* Do the copy. Bypass L1 cache - usually after memcpy memory
	 * is not accessed immediately since user knows its contents */
	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);

		n -= length;

		recovery_memcpy_8(dst, src, length,
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT |
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT,
				MAS_FILL_OPERATION << LDST_REC_OPC_MAS_SHIFT |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT |
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT,
				1);

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
		tmp4 = ACCESS_ONCE(*(u32 *) src);
	if (tail2)
		tmp2 = ACCESS_ONCE(*(u16 *) (src + tail4));
	if (tail1)
		tmp1 = ACCESS_ONCE(*(u8 *) (src + tail6));

	if (tail4)
		ACCESS_ONCE(*(u32 *) dst) = tmp4;
	if (tail2)
		ACCESS_ONCE(*(u16 *) (dst + tail4)) = tmp2;
	if (tail1)
		ACCESS_ONCE(*(u8 *) (dst + tail6)) = tmp1;
}
EXPORT_SYMBOL(__memcpy_toio);


/* Kernel's built-in boot does not use the code below, so keep things simple
 * with this #ifndef */
# ifndef BOOT

/**
 * tagged_memcpy_8() - copy memory along with tags
 *
 * All parameters must be 8-bytes aligned.
 */
void _tagged_memcpy_8(void *dst, const void *src, size_t n)
{
	void *const orig_dst = dst;
	const size_t orig_size = n;
	const unsigned long ldrd_opcode = TAGGED_MEM_LOAD_REC_OPC
			| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT;
	const unsigned long strd_opcode = TAGGED_MEM_STORE_REC_OPC
			| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT;

	/* Both src and dst are 8-bytes aligned. */
	for (;;) {
		/* Copy with 8192 bytes blocks */
		if (n >= 2 * 8192) {
			recovery_memcpy_8(dst, src, 8192, strd_opcode,
					ldrd_opcode, 1);
			n -= 8192;
			src += 8192;
			dst += 8192;
		} else {
			recovery_memcpy_8(dst, src, n & ~0x7, strd_opcode,
					ldrd_opcode, 1);
			break;
		}
	};

	if (cpu_has(CPU_HWBUG_QUADRO_STRD))
		flush_DCACHE_range(orig_dst, orig_size);

}
EXPORT_SYMBOL(_tagged_memcpy_8);
# endif /* BOOT */
#endif /* __HAVE_ARCH_MEMCPY */

#ifdef __HAVE_ARCH_MEMMOVE
#define OVERLAP_LIMIT 10
void *memmove(void *dst, const void *src, size_t count)
{
	int i;
	unsigned long delta;

	prefetchw(src);

	if (dst <= src || dst >= src + count) {
		__memcpy(dst, src, count);

		return dst;
	}

	delta = (unsigned long) dst - (unsigned long) src;

	if (delta >= OVERLAP_LIMIT) {
		do {
			count -= delta;

			__memcpy(dst + count, src + count, delta);
		} while (count >= delta);

		if (count)
			__memcpy(dst, src, count);

		return dst;
	}

	for (i = count - 1; i >= 0; i--)
		((char *) dst)[i] = ((char *) src)[i];

	return dst;
}
EXPORT_SYMBOL(memmove);
#endif

#ifdef __HAVE_ARCH_MEMCMP
int memcmp(const void *p1, const void *p2, size_t n)
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
			return ((u16) __builtin_bswap16(v1) >
				(u16) __builtin_bswap16(v2)) ? 1 : -1;
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
			return ((u16) __builtin_bswap16(v1) >
				(u16) __builtin_bswap16(v2)) ? 1 : -1;
	}
	if (tail1) {
		v1 = *(u8 *) (p1 + tail6);
		v2 = *(u8 *) (p2 + tail6);
		if (v1 != v2)
			return v1 - v2;
	}

	return 0;
}
EXPORT_SYMBOL(memcmp);
#endif


/* Set bits in the first 'n' bytes when loaded from memory */
#define aligned_byte_mask(n) ((1ul << 8*(n))-1)

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
