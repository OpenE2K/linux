/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/types.h>
#include <linux/mm.h>

#include <linux/uaccess.h>
#include <asm/word-at-a-time.h>
#include <asm/mmu_fault.h>


#ifdef CONFIG_DEBUG_VM
EXPORT_SYMBOL(__uaccess_start);
EXPORT_SYMBOL(__uaccess_end);
#endif

UACCESS_FN_DEFINE3(fill_user_fn, void __user *, to, unsigned long, n, u64, b)
{
	unsigned long i, align, head, tail, head1, head2, head3, head4, head7,
			head8, tail1, tail2, tail4, tail8, tail12, tail14, n_aligned;
	void __user *to_aligned = PTR_ALIGN((void __user *) to, 16);
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_BYPASS_L1_CACHE, .prot = 1 };
	size_t cleared;

	align = (unsigned long) to & 0xf;
	head = 16 - align;

	if (unlikely(n < 16)) {
		for (i = 0; i < n; i++)
			USER_ST(b, &((u8 __user *) to)[i]);

		return 0;
	}

	/* set the head */
	n -= head & 0xf;

	head1 = (unsigned long) to & 1;	/* to & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;
	head7 = head & 7;
	head8 = head & 8;

	if (head1)
		USER_ST(b, (u8 __user *) to);
	if (head2)
		USER_ST(b, (u16 __user *) (to + head1));
	if (head4)
		USER_ST(b, (u32 __user *) (to + head3));
	if (head8)
		USER_ST(b, (u64 __user *) (to + head7));


	n_aligned = round_down(n, 16);
	SET_USR_PFAULT("$recovery_memset_fault", true);
	cleared = fast_tagged_memory_set_user(to_aligned, b, ETAGNVQ,
			n_aligned, &cleared, AW(strd_opcode));
	RESTORE_USR_PFAULT(true);
	if (unlikely(cleared != n_aligned))
		return n - cleared;

	/* set the tail */
	to_aligned += n_aligned;
	tail = n;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail8 = tail & 8;
	tail12 = tail & 12;
	tail14 = tail & 14;

	if (tail8)
		USER_ST(b, (u64 __user *) to_aligned);
	if (tail4)
		USER_ST(b, (u32 __user *) (to_aligned + tail8));
	if (tail2)
		USER_ST(b, (u16 __user *) (to_aligned + tail12));
	if (tail1)
		USER_ST(b, (u8 __user *) (to_aligned + tail14));

	return 0;
}

/* Fallback function - fills as much as possible */
UACCESS_FN_DEFINE3(fill_user_fn_fallback, void __user *, to, unsigned long *, n, u64, b)
{
	unsigned long i, orig_n = *n;

	for (i = 0; i < orig_n; i++) {
		USER_ST(b, &((u8 __user *) to)[i]);
		E2K_CMD_SEPARATOR;
		WRITE_ONCE(*n, *n - 1);
	}

	return 0;
}

/**
 * fill_user: - Fill a block of memory in user space with given bytes.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 * @b:    Byte to fill memory with.
 *
 * Fill a block of memory in user space.
 *
 * Returns number of bytes that could not be filled.
 * On success, this will be zero.
 */
unsigned long __fill_user(void __user *to, unsigned long n, u8 c)
{
	u64 b = __builtin_e2k_pshufb(c, c, 0);

	if (unlikely(__UACCESS_FN_CALL(fill_user_fn, to, n, b))) {
		__UACCESS_FN_CALL(fill_user_fn_fallback, to, &n, b);
		return n;
	}

	return 0;
}
EXPORT_SYMBOL(__fill_user);


UACCESS_FN_DEFINE3(strncpy_from_user_fn, char *__restrict, dst,
		const char __user *__restrict, src, long, count)
{
	long i;

	for (i = 0; i < count; i++) {
		char c;
		USER_LD(c, &src[i]);
		if (unlikely((dst[i] = c) == 0))
			break;
	}

	return i;
}

/**
 * strncpy_from_user: - Copy a NUL terminated string from userspace.
 * @dst:   Destination address, in kernel space.  This buffer must be at
 *         least @count bytes long.
 * @src:   Source address, in user space.
 * @count: Maximum number of bytes to copy, including the trailing NUL.
 * 
 * Copies a NUL-terminated string from userspace to kernel space.
 *
 * On success, returns the length of the string (not including the trailing
 * NUL).
 *
 * If access to userspace fails, returns -EFAULT (some data may have been
 * copied).
 *
 * If @count is smaller than the length of the string, copies @count bytes
 * and returns @count.
 */

long strncpy_from_user(char *__restrict dst,
		const char __user *src, long count)
{
	unsigned long max, max_addr = user_addr_max();
	unsigned long src_addr = (unsigned long) src;

	if (unlikely(count <= 0))
		return 0;
	if (unlikely(src_addr >= max_addr))
		return -EFAULT;

	max = max_addr - src_addr;
	if (count > max)
		count = max;

	return __UACCESS_FN_CALL(strncpy_from_user_fn, dst, src, count);
}
EXPORT_SYMBOL(strncpy_from_user);


/*
 * Do a strnlen, return length of string *with* final '\0'.
 * 'count' is the user-supplied count, while 'max' is the
 * address space maximum.
 *
 * Return 0 for exceptions (which includes hitting the address
 * space maximum), or 'count+1' if hitting the user-supplied
 * maximum count.
 */
UACCESS_FN_DEFINE3(strnlen_user_fn, const char __user *, src,
		unsigned long, count, unsigned long, max)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	long align, res = 0;
	unsigned long c;

	/*
	 * Do everything aligned. But that means that we
	 * need to also expand the maximum..
	 */
	align = (sizeof(long) - 1) & (unsigned long)src;
	src -= align;
	/* Cannot overflow - max is already limited by PAGE_OFFSET */
	max += align;

	USER_LD(c, (unsigned long __user *) src);
	c |= aligned_byte_mask(align);

#pragma vector aligned
	for (;;) {
		unsigned long data;
		if (has_zero(c, &data, &constants)) {
			data = prep_zero_mask(c, data, &constants);
			data = create_zero_mask(data);
			res += find_zero(data) + 1 - align;
			if (res > count)
				res = count + 1;
			return res;
		}
		res += sizeof(unsigned long);
		if (unlikely(max <= sizeof(unsigned long)))
			break;
		max -= sizeof(unsigned long);
		USER_LD(c, (unsigned long __user *) (src + res));
	}
	res -= align;

	/*
	 * Uhhuh. We hit 'max'. But was that the user-specified maximum
	 * too? If so, return the marker for "too long".
	 */
	if (likely(res >= count))
		return count+1;

	/*
	 * Nope: we hit the address space limit, and we still had more
	 * characters the caller would have wanted. That's 0.
	 */
	return 0;
}

/**
 * strnlen_user: - Get the size of a user string INCLUDING final NUL.
 * @str: The string to measure.
 * @count: Maximum count (including NUL character)
 *
 * Context: User context only.  This function may sleep.
 *
 * Get the size of a NUL-terminated string in user space.
 *
 * Returns the size of the string INCLUDING the terminating NUL.
 * If the string is too long, returns 'count+1'.
 * On exception (or invalid count), returns 0.
 */
long strnlen_user(const char __user *str, long count)
{
	unsigned long max, max_addr = user_addr_max(),
			   src_addr = (unsigned long __user) str;
	long res;

	/* We cannot accept count = -1 since then (count + 1) would overflow. */
	if (unlikely(count < 0 || src_addr >= max_addr))
		return 0;

	max = max_addr - src_addr;
	/*
	 * Truncate 'max' to the user-specified limit, so that
	 * we only have one limit we need to check in the loop
	 */
	if (max > count)
		max = count;
	res = __UACCESS_FN_CALL(strnlen_user_fn, str, count, max);
	return (res == -EFAULT) ? 0 : res;
}
EXPORT_SYMBOL(strnlen_user);

UACCESS_GLOBEXP_FN_DEFINE4(copy_from_user_fn, void *, to, const void __user *, from,
		unsigned long, size, unsigned long *, left)
{
	unsigned long n = size;
	unsigned long head, tail, head1, head3, head7, tail8, tail12, tail14;
	void *dst = to, *orig_dst = to;
	const void __user *src = from;
	u64 tmp8;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;

	if (unlikely(n < 16))
		goto copy_tail;

	/* Copy the head */

	head = 16 - ((unsigned long) dst & 0xfUL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head3 = head & 3;
	head7 = head & 7;

	if (head & 1)
		USER_LD(tmp1, (u8 __user *) src);
	if (head & 2)
		USER_LD(tmp2, (u16 __user *) (src + head1));
	if (head & 4)
		USER_LD(tmp4, (u32 __user *) (src + head3));
	if (head & 8)
		USER_LD(tmp8, (u64 __user *) (src + head7));

	src += head & 0xf;
	dst = PTR_ALIGN(dst, 16);
	n -= head & 0xf;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0xfUL);
		size_t copied = 0;

		if (likely(length)) {
			SET_USR_PFAULT("$recovery_memcpy_fault", true);
			copied = fast_tagged_memory_copy_from_user(dst, src,
					length, &copied, true);
			RESTORE_USR_PFAULT(true);
			WRITE_ONCE(*left, n - copied);
		}

		n -= copied;

		src += copied;
		dst += copied;

		/* The first pagefault could have happened on prefetch,
		 * so we might end up doing a 1-byte-at-a-time copy of
		 * the whole area. But this is an extremely unlikely
		 * case, so we do not care. */
		if (unlikely(copied != length)) {
			/* 'dst' cannot fault, so we can delay stores
			 * without worrying about possible page faults. */
			if (head & 1)
				*(u8 *) orig_dst = tmp1;
			if (head & 2)
				*(u16 *) (orig_dst + head1) = tmp2;
			if (head & 4)
				*(u32 *) (orig_dst + head3) = tmp4;
			if (head & 8)
				*(u64 *) (orig_dst + head7) = tmp8;

			return -EFAULT;
		}
	} while (unlikely(n >= 16));

	/* 'dst' cannot fault, so we can delay stores
	 * without worrying about possible page faults. */
	if (head & 1)
		*(u8 *) orig_dst = tmp1;
	if (head & 2)
		*(u16 *) (orig_dst + head1) = tmp2;
	if (head & 4)
		*(u32 *) (orig_dst + head3) = tmp4;
	if (head & 8)
		*(u64 *) (orig_dst + head7) = tmp8;

copy_tail:
	/* Copy the tail */
	tail = n;

	BUG_ON((u64) tail >= 16);

	tail8 = tail & 8;
	tail12 = tail & 12;
	tail14 = tail & 14;

	if (tail & 8)
		USER_LD(tmp8, (u64 __user *) src);
	if (tail & 4)
		USER_LD(tmp4, (u32 __user *) (src + tail8));
	if (tail & 2)
		USER_LD(tmp2, (u16 __user *) (src + tail12));
	if (tail & 1)
		USER_LD(tmp1, (u8 __user *) (src + tail14));

	if (tail & 8)
		*(u64 *) dst = tmp8;
	if (tail & 4)
		*(u32 *) (dst + tail8) = tmp4;
	if (tail & 2)
		*(u16 *) (dst + tail12) = tmp2;
	if (tail & 1)
		*(u8 *) (dst + tail14) = tmp1;

	return 0;
}

UACCESS_GLOBEXP_FN_DEFINE4(copy_to_user_fn, void __user *, to, const void *, from,
		unsigned long, size, unsigned long *, left)
{
	unsigned long n = size;
	unsigned long head, tail, head1, head3, head7, tail8, tail12, tail14;
	void __user *dst = to;
	const void *src = from;
	u64 tmp8;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;

	if (unlikely(n < 16))
		goto copy_tail;

	/* Copy the head */

	head = 16 - ((unsigned long) dst & 0xfUL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head3 = head & 3;
	head7 = head & 7;

	if (head & 1)
		tmp1 = *(u8 *) src;
	if (head & 2)
		tmp2 = *(u16 *) (src + head1);
	if (head & 4)
		tmp4 = *(u32 *) (src + head3);
	if (head & 8)
		tmp8 = *(u64 *) (src + head7);

	if (head & 1)
		USER_ST(tmp1, (u8 __user *) dst);
	if (head & 2)
		USER_ST(tmp2, (u16 __user *) (dst + head1));
	if (head & 4)
		USER_ST(tmp4, (u32 __user *) (dst + head3));
	if (head & 8)
		USER_ST(tmp8, (u64 __user *) (dst + head7));

	src += head & 0xf;
	dst = PTR_ALIGN(dst, 16);
	n -= head & 0xf;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0xfUL);
		size_t copied = 0;

		if (likely(length)) {
			SET_USR_PFAULT("$recovery_memcpy_fault", true);
			copied = fast_tagged_memory_copy_to_user(dst, src,
					length, &copied, true);
			RESTORE_USR_PFAULT(true);
			WRITE_ONCE(*left, n - copied);
		}

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			return -EFAULT;
	} while (unlikely(n >= 16));

copy_tail:
	/* Copy the tail */
	tail = n;

	BUG_ON((u64) tail >= 16);

	tail8 = tail & 8;
	tail12 = tail & 12;
	tail14 = tail & 14;

	if (tail & 8)
		tmp8 = *(u64 *) src;
	if (tail & 4)
		tmp4 = *(u32 *) (src + tail8);
	if (tail & 2)
		tmp2 = *(u16 *) (src + tail12);
	if (tail & 1)
		tmp1 = *(u8 *) (src + tail14);

	if (tail & 8)
		USER_ST(tmp8, (u64 __user *) dst);
	if (tail & 4)
		USER_ST(tmp4, (u32 __user *) (dst + tail8));
	if (tail & 2)
		USER_ST(tmp2, (u16 __user *) (dst + tail12));
	if (tail & 1)
		USER_ST(tmp1, (u8 __user *) (dst + tail14));

	return 0;
}

UACCESS_GLOBEXP_FN_DEFINE4(copy_in_user_fn, void __user *, to, const void __user *, from,
		unsigned long, size, unsigned long *, left)
{
	unsigned long n = size;
	unsigned long head, tail, head1, head3, head7, tail8, tail12, tail14;
	void __user *dst = to;
	const void __user *src = from;
	u64 tmp8;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;

	if (unlikely(n < 16))
		goto copy_tail;

	/* Copy the head */

	head = 16 - ((unsigned long) dst & 0xfUL);

	head1 = (unsigned long) dst & 1;	/* dst & 1 == head & 1 */
	head3 = head & 3;
	head7 = head & 7;

	if (head & 1)
		USER_LD(tmp1, (u8 __user *) src);
	if (head & 2)
		USER_LD(tmp2, (u16 __user *) (src + head1));
	if (head & 4)
		USER_LD(tmp4, (u32 __user *) (src + head3));
	if (head & 8)
		USER_LD(tmp8, (u64 __user *) (src + head7));

	if (head & 1)
		USER_ST(tmp1, (u8 __user *) dst);
	if (head & 2)
		USER_ST(tmp2, (u16 __user *) (dst + head1));
	if (head & 4)
		USER_ST(tmp4, (u32 __user *) (dst + head3));
	if (head & 8)
		USER_ST(tmp8, (u64 __user *) (dst + head7));

	/* Make sure "n" is changed *after* the actual
	 * user accesses have been issued */
	E2K_CMD_SEPARATOR;

	src += head & 0xf;
	dst = PTR_ALIGN(dst, 16);
	n -= head & 0xf;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0xfUL);
		size_t copied = 0;

		if (likely(length)) {
			SET_USR_PFAULT("$recovery_memcpy_fault", true);
			copied = fast_tagged_memory_copy_in_user(dst, src,
					length, &copied, true);
			RESTORE_USR_PFAULT(true);
			WRITE_ONCE(*left, n - copied);
		}

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			return -EFAULT;
	} while (unlikely(n >= 16));

copy_tail:
	/* Copy the tail */
	tail = n;

	BUG_ON((u64) tail >= 16);

	tail8 = tail & 8;
	tail12 = tail & 12;
	tail14 = tail & 14;

	if (tail & 8)
		USER_LD(tmp8, (u64 __user *) src);
	if (tail & 4)
		USER_LD(tmp4, (u32 __user *) (src + tail8));
	if (tail & 2)
		USER_LD(tmp2, (u16 __user *) (src + tail12));
	if (tail & 1)
		USER_LD(tmp1, (u8 __user *) (src + tail14));

	if (tail & 8)
		USER_ST(tmp8, (u64 __user *) dst);
	if (tail & 4)
		USER_ST(tmp4, (u32 __user *) (dst + tail8));
	if (tail & 2)
		USER_ST(tmp2, (u16 __user *) (dst + tail12));
	if (tail & 1)
		USER_ST(tmp1, (u8 __user *) (dst + tail14));

	return 0;
}

/*
 * All arguments must be aligned
 */
unsigned long __copy_in_user_with_tags(void __user *to, const void __user *from,
		unsigned long n)
{
	void __user *dst = to;
	const void __user *src = from;

	if (unlikely(!IS_ALIGNED((unsigned long) to, 8) ||
			!IS_ALIGNED((unsigned long) from, 8) ||
			!IS_ALIGNED(n, 8)))
		return n;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : n;
		size_t copied;

		SET_USR_PFAULT("$recovery_memcpy_fault", false);
		copied = fast_tagged_memory_copy_in_user(dst, src, length,
				&copied, true);
		RESTORE_USR_PFAULT(false);

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			break;
	} while (unlikely(n >= 8));

	return n;
}

/*
 * All arguments must be aligned
 */
unsigned long __copy_from_user_with_tags(void *to, const void __user *from,
		unsigned long n)
{
	void *dst = to;
	const void __user *src = from;

	if (unlikely(!IS_ALIGNED((unsigned long) to, 8) ||
			!IS_ALIGNED((unsigned long) from, 8) ||
			!IS_ALIGNED(n, 8)))
		return n;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : n;
		size_t copied;

		SET_USR_PFAULT("$recovery_memcpy_fault", false);
		copied = fast_tagged_memory_copy_from_user(dst, src, length,
				&copied, true);
		RESTORE_USR_PFAULT(false);

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			break;
	} while (unlikely(n >= 8));

	return n;
}

/*
 * All arguments must be aligned
 * NB> This is "copy-to-user" action.
 */
unsigned long __copy_to_user_with_tags(void __user *to, const void *from,
		unsigned long n)
{
	void __user *dst = to;
	const void *src = from;

	if (unlikely(!IS_ALIGNED((unsigned long) to, 8) ||
			!IS_ALIGNED((unsigned long) from, 8) ||
			!IS_ALIGNED(n, 8)))
		return n;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : n;
		size_t copied;

		SET_USR_PFAULT("$recovery_memcpy_fault", false);
		copied = fast_tagged_memory_copy_to_user(dst, src, length,
				&copied, true);
		RESTORE_USR_PFAULT(false);

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			break;
	} while (unlikely(n >= 8));

	return n;
}

/*
 * All arguments must be aligned
 */
unsigned long __fill_user_with_tags(void __user *to, unsigned long n,
		unsigned long tag, unsigned long dw)
{
	ldst_rec_op_t strd_opcode = (ldst_rec_op_t) { .fmt = LDST_QWORD_FMT,
			.mas = MAS_BYPASS_L1_CACHE, .prot = 1 };
	size_t cleared;

	if (unlikely(!IS_ALIGNED((unsigned long) to, 8) || !IS_ALIGNED(n, 8)))
		return n;

	SET_USR_PFAULT("$recovery_memset_fault", false);
	cleared = fast_tagged_memory_set_user(to, dw, tag, n, &cleared, AW(strd_opcode));
	RESTORE_USR_PFAULT(false);

	return n - cleared;
}
