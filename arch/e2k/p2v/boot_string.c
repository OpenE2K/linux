/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * boot-time initialization string library routines
 * based on general lib/string.c
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <asm/p2v/boot_v2p.h>
#include <asm/mmu_types.h>
#include <asm/processor.h>
#include "boot_string.h"

/**
 * strcpy - Copy a %NUL terminated string
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 */
char *boot_strcpy(char *dest_va, const char *src_va)
{
	char *dest = boot_vp_to_pp(dest_va);
	const char *src = boot_vp_to_pp(src_va);
	char *tmp = dest;

	while ((*dest++ = *src++) != '\0')
		/* nothing */;
	return tmp;
}

/**
 * strncpy - Copy a length-limited, %NUL-terminated string
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @count: The maximum number of bytes to copy
 *
 * The result is not %NUL-terminated if the source exceeds
 * @count bytes.
 *
 * In the case where the length of @src is less than  that  of
 * count, the remainder of @dest will be padded with %NUL.
 *
 */
char *boot_strncpy(char *dest_va, const char *src_va, size_t count)
{
	char *dest = boot_vp_to_pp(dest_va);
	const char *src = boot_vp_to_pp(src_va);
	char *tmp = dest;

	while (count) {
		if ((*tmp = *src) != 0)
			src++;
		tmp++;
		count--;
	}
	return dest;
}

/**
 * strlcpy - Copy a %NUL terminated string into a sized buffer
 * @dest: Where to copy the string to
 * @src: Where to copy the string from
 * @size: size of destination buffer
 *
 * Compatible with *BSD: the result is always a valid
 * NUL-terminated string that fits in the buffer (unless,
 * of course, the buffer size is zero). It does not pad
 * out the result like strncpy() does.
 */
size_t boot_strlcpy(char *dest_va, const char *src_va, size_t size)
{
	char *dest = boot_vp_to_pp(dest_va);
	const char *src = boot_vp_to_pp(src_va);
	size_t ret = boot_strlen(src);

	if (size) {
		size_t len = (ret >= size) ? size - 1 : ret;
		boot_memcpy(dest, src, len);
		dest[len] = '\0';
	}
	return ret;
}
int boot_strcmp(const char *cs_va, const char *ct_va)
{
	const char *cs = boot_vp_to_pp(cs_va);
	const char *ct = boot_vp_to_pp(ct_va);
	unsigned char c1, c2;

	while (1) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
	}
	return 0;
}
/**
 * strncmp - Compare two length-limited strings
 * @cs: One string
 * @ct: Another string
 * @count: The maximum number of bytes to compare
 */
int boot_strncmp(const char *cs_va, const char *ct_va, size_t count)
{
	const char *cs = boot_vp_to_pp(cs_va);
	const char *ct = boot_vp_to_pp(ct_va);
	unsigned char c1, c2;

	while (count) {
		c1 = *cs++;
		c2 = *ct++;
		if (c1 != c2)
			return c1 < c2 ? -1 : 1;
		if (!c1)
			break;
		count--;
	}
	return 0;
}
/**
 * strlen - Find the length of a string
 * @s: The string to be sized
 */
size_t boot_strlen(const char *s_va)
{
	const char *s = boot_vp_to_pp(s_va);
	const char *sc;

	for (sc = s; *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}
/**
 * strnlen - Find the length of a length-limited string
 * @s: The string to be sized
 * @count: The maximum number of bytes to search
 */
size_t boot_strnlen(const char *s_va, size_t count)
{
	const char *s = boot_vp_to_pp(s_va);
	const char *sc;

	for (sc = s; count-- && *sc != '\0'; ++sc)
		/* nothing */;
	return sc - s;
}

/**
 * p2v_strstr - Find the first substring in a %NUL terminated string
 * @s1: The string to be searched
 * @s2: The string to search for
 */
char *boot_strstr(const char *s1_va, const char *s2_va)
{
	const char *s1 = boot_vp_to_pp(s1_va);
	const char *s2 = boot_vp_to_pp(s2_va);
	size_t l1, l2;

	l2 = boot_strlen(s2);
	if (!l2)
		return (char *)s1;
	l1 = boot_strlen(s1);
	while (l1 >= l2) {
		l1--;
		if (!boot_memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}
/**
 * memset - Fill a region of memory with the given value
 * @s: Pointer to the start of the area.
 * @c: The byte to fill the area with
 * @count: The size of the area.
 *
 * Do not use memset() to access IO space, use memset_io() instead.
 */
void *boot_memset(void *s_va, int c, size_t count)
{
	void *s = boot_vp_to_pp(s_va);
	char *xs = s;

	while (count--)
		*xs++ = c;
	return s;
}
/**
 * memcpy - Copy one area of memory to another
 * @dest: Where to copy to
 * @src: Where to copy from
 * @count: The size of the area.
 *
 * You should not use this function to access IO space, use memcpy_toio()
 * or memcpy_fromio() instead.
 */
void *boot_memcpy(void *dest_va, const void *src_va, size_t count)
{
	void *dest = boot_vp_to_pp(dest_va);
	const void *src = boot_vp_to_pp(src_va);
	char *tmp = dest;
	const char *s = src;

	while (count--)
		*tmp++ = *s++;
	return dest;
}
/*
 * The following function is same as arch/e2k/lib/string.c function __memset()
 * but can operate with physical addresses
 */

notrace void boot_fast_memset(void *s_va, long c, size_t count)
{
	void *s = boot_vp_to_pp(s_va);
	unsigned long align = (unsigned long) s & 0x7, head, tail,
			head1, head2, head3, head4, tail1, tail2, tail4, tail6;

	if (unlikely(count < 8))
		goto set_tail;

	/* Set the head */
	head = 8 - align;

	head1 = (unsigned long) s & 1;	/* s & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1)
		WRITE_ONCE(*(u8 *) s, c);
	if (head2)
		WRITE_ONCE(*(u16 *) (s + head1), c);
	if (head4)
		WRITE_ONCE(*(u32 *) (s + head3), c);

	s = PTR_ALIGN(s, 8);
	count -= head & 0x7;

	/* Bypass L1 cache - usually after memset memory is not accessed
	 * immediately since user knows its contents.
	 *
	 * Do NOT use WC memory access here - otherwise
	 * cpu_has() -> boot_cpu_has() in recovery_memset_8()
	 * might access uninitilized data when clearing kernel BSS. */
	boot_fast_tagged_memory_set(s, c, 0, count & ~0x7UL,
			LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT
			| MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT);

	/* Set the tail */
	s += count & ~0x7UL;
set_tail:
	tail = count;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail6 = tail & 6;

	if (tail4)
		WRITE_ONCE(*(u32 *) s, c);
	if (tail2)
		WRITE_ONCE(*(u16 *) (s + tail4), c);
	if (tail1)
		WRITE_ONCE(*(u8 *) (s + tail6), c);
}

/* Same as __memcpy, but assume "hwbug == true" */
notrace void
boot_fast_memcpy(void *dst_va, const void *src_va, size_t n)
{
	void *dst = boot_vp_to_pp(dst_va);
	void *src = boot_vp_to_pp(((void *)src_va));
	void *const orig_dst = dst;
	unsigned long head, tail, head1, head2, head3, head4,
			tail1, tail2, tail4, tail6;
	u32 head_val4, tail_val4;
	u16 head_val2, tail_val2;
	u8 head_val1, tail_val1;

	if (unlikely(n < 8)) {
		boot_memcpy(dst_va, src_va, n);
		return;
	}

	prefetchr_nospec_range(src, n);
	__E2K_WAIT(_ld_c);

	/* Copy the head */

	head = 8 - ((unsigned long) dst & 0x7UL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;

	if (head1)
		head_val1 = READ_ONCE(*(u8 *) src);
	if (head2)
		head_val2 = READ_ONCE(*(u16 *) (src + head1));
	if (head4)
		head_val4 = READ_ONCE(*(u32 *) (src + head3));

	src += head & 0x7;
	dst = PTR_ALIGN(dst, 8);
	n -= head & 0x7;

	/* Do the copy. Bypass L1 cache - usually after memcpy memory
	 * is not accessed immediately since user knows its contents */
	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);

		n -= length;

		boot_fast_tagged_memory_copy(dst, src, length, 0);

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
		WRITE_ONCE(*(u8 *) orig_dst, head_val1);
	if (head2)
		WRITE_ONCE(*(u16 *) (orig_dst + head1), head_val2);
	if (head4)
		WRITE_ONCE(*(u32 *) (orig_dst + head3), head_val4);

	if (tail4)
		WRITE_ONCE(*(u32 *) dst, tail_val4);
	if (tail2)
		WRITE_ONCE(*(u16 *) (dst + tail4), tail_val2);
	if (tail1)
		WRITE_ONCE(*(u8 *) (dst + tail6), tail_val1);
}

int boot_memcmp(const void *p1_va, const void *p2_va, size_t n)
{
	void *p1 = boot_vp_to_pp((void *)p1_va);
	void *p2 = boot_vp_to_pp(((void *)p2_va));
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
