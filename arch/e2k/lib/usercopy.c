/* linux/arch/e2k/lib/usercopy.c, v 1.7 15/08/2001.
 *
 * Copyright (C) 2001 MCST
 */

#include <linux/types.h>
#include <linux/mm.h>

#include <asm/uaccess.h>
#include <asm/word-at-a-time.h>


/**
 * clear_user: - Zero a block of memory in user space.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 *
 * Zero a block of memory in user space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned long
__clear_user(void __user *to, const unsigned long n)
{
	unsigned long align = (unsigned long) to & 0xf, head, tail,
			head1, head2, head3, head4, head7, head8,
			tail1, tail2, tail4, tail8, tail12, tail14;
	void *to_aligned = PTR_ALIGN(to, 16);
	unsigned long i;
	unsigned long count = n;
	
	DebugUA("__clear_user %p : 0x%lx\n", to, n);

	head = 16 - align;

	/* save addr to return from trap if 'to' is bad */
	BEGIN_USR_PFAULT("__clear_user_trapret", "0f");

	if (unlikely(n < 16)) {
		int i;

		for (i = 0; i < n; i++)
			((u8 *) to)[i] = 0;

		goto out;
	}

	/* set the head */
	count -= head & 0xf;

	head1 = (unsigned long) to & 1;	/* to & 1 == head & 1 */
	head2 = head & 2;
	head3 = head & 3;
	head4 = head & 4;
	head7 = head & 7;
	head8 = head & 8;

	if (head1)
		*(u8 *) to = 0;
	if (head2)
		*(u16 *) (to + head1) = 0;
	if (head4)
		*(u32 *) (to + head3) = 0;
	if (head8)
		*(u64 *) (to + head7) = 0;

	for (i = 0; i < (count >> 3) - 1; i += 2) {
		((u64 *) to_aligned)[i] = 0;
		((u64 *) to_aligned)[i + 1] = 0;
	}

	/* set the tail */
	to_aligned += count & ~0xfUL;
	tail = count;

	tail1 = tail & 1;
	tail2 = tail & 2;
	tail4 = tail & 4;
	tail8 = tail & 8;
	tail12 = tail & 12;
	tail14 = tail & 14;

	if (tail8)
		*(u64 *) to_aligned = 0;
	if (tail4)
		*(u32 *) (to_aligned + tail8) = 0;
	if (tail2)
		*(u16 *) (to_aligned + tail12) = 0;
	if (tail1)
		*(u8 *) (to_aligned + tail14) = 0;

out:
	LBL_USR_PFAULT("__clear_user_trapret", "0:");
	if (END_USR_PFAULT) {
		/*
		 * There was a trap that could not be handled.
		 * Clearing all the area again with 1-byte stores
		 * is certainly slow, but this is an extremely
		 * unlikely case we do not care about.
		 */
		int i;

		BEGIN_USR_PFAULT("lbl_clear_user_fallback", "1f");
		for (i = 0; i < n; i++) {
			ACCESS_ONCE(((u8 *) to)[i]) = 0;
			E2K_CMD_SEPARATOR;
		}
		LBL_USR_PFAULT("lbl_clear_user_fallback", "1:");
		if (END_USR_PFAULT)
			return n - i;

		BUG_ON(n != i);
	}

	return 0;
}
EXPORT_SYMBOL(__clear_user);

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

long __strncpy_from_user(char *__restrict dst,
		const char *__restrict src, long count)
{
	long i;

	BEGIN_USR_PFAULT("__strncpy_from_user_trapret", "2f");
	DebugUA("to = %#lX,  from = %#lX,  "
		"count = %ld\n",  (u64) dst, (u64) src, count);
	for (i = 0; likely(i < count); i++)
		if (unlikely((dst[i] = src[i]) == 0))
			break;
	LBL_USR_PFAULT("__strncpy_from_user_trapret", "2:");
	if (END_USR_PFAULT) {
		/* It was trap */ 
		i = -EFAULT;
        }   
	return i;
}
EXPORT_SYMBOL(__strncpy_from_user);

/* Set bits in the first 'n' bytes when loaded from memory */
#define aligned_byte_mask(n) ((1ul << 8*(n))-1)

/*
 * Do a strnlen, return length of string *with* final '\0'.
 * 'count' is the user-supplied count, while 'max' is the
 * address space maximum.
 *
 * Return 0 for exceptions (which includes hitting the address
 * space maximum), or 'count+1' if hitting the user-supplied
 * maximum count.
 */
static __always_inline long do_strnlen_user(const char __user *src,
		unsigned long count, unsigned long max)
{
	const struct word_at_a_time constants = WORD_AT_A_TIME_CONSTANTS;
	long align, res = 0;
	unsigned long c;

	/*
	 * Truncate 'max' to the user-specified limit, so that
	 * we only have one limit we need to check in the loop
	 */
	if (max > count)
		max = count;

	/*
	 * Do everything aligned. But that means that we
	 * need to also expand the maximum..
	 */
	align = (sizeof(long) - 1) & (unsigned long)src;
	src -= align;
	/* Cannot overflow - max is already limited by PAGE_OFFSET */
	max += align;

	c = *(unsigned long __user *) src;
	c |= aligned_byte_mask(align);

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
		c = *(unsigned long __user *) (src + res);
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
	unsigned long max_addr = user_addr_max(), src_addr;
	long res;

	/* We cannot accept count = -1 since than (count + 1) wuold overflow. */
	if (unlikely(count < 0))
		return 0;

	BEGIN_USR_PFAULT("lbl_strnlen", "3f");

	src_addr = (unsigned long) str;
	if (likely(src_addr < max_addr)) {
		unsigned long max = max_addr - src_addr;
		res = do_strnlen_user(str, count, max);
	} else {
		res = 0;
	}

	LBL_USR_PFAULT("lbl_strnlen", "3:");
	if (END_USR_PFAULT)
		return 0;

	return res;
}
EXPORT_SYMBOL(strnlen_user);


noinline unsigned long generic_copy_from_user(void *to,
		const void __user *from, unsigned long size)
{
	void *dst = to;
	const void *src = from;
	unsigned long head, tail, head1, head2, head3, head4,
			tail1, tail2, tail4, tail6;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;
	unsigned long n = size;

	BEGIN_USR_PFAULT("lbl_generic_copy_from_user", "4f");

	if (unlikely(n < 8))
		goto copy_tail;

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

	/* Make sure "n" is changed *after* the actual
	 * user accesses have been issued */
	E2K_CMD_SEPARATOR;

	src += head & 0x7;
	dst = PTR_ALIGN(dst, 8);
	n -= head & 0x7;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);
		size_t copied;

		BEGIN_USR_PFAULT("recovery_memcpy_fault",
				 "$.recovery_memcpy_fault");
		copied = recovery_memcpy_8(dst, src, length,
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				1);
		END_USR_PFAULT;

		n -= copied;

		src += copied;
		dst += copied;

		/* The first pagefault could have happened on prefetch,
		 * so we might end up doing a 1-byte-at-a-time copy of
		 * the whole area. But this is an extremely unlikely
		 * case, so we do not care. */
		if (unlikely(copied != length)) {
			/* 'dst' cannot fault, so we can delay stores without
			 * worrying about possible page faults. */
			if (head1)
				ACCESS_ONCE(*(u8 *) to) = tmp1;
			if (head2)
				ACCESS_ONCE(*(u16 *) (to + head1)) = tmp2;
			if (head4)
				ACCESS_ONCE(*(u32 *) (to + head3)) = tmp4;

			goto fallback;
		}
	} while (unlikely(n >= 8));

	/* 'dst' cannot fault, so we can delay stores without
	 * worrying about possible page faults. */
	if (head1)
		ACCESS_ONCE(*(u8 *) to) = tmp1;
	if (head2)
		ACCESS_ONCE(*(u16 *) (to + head1)) = tmp2;
	if (head4)
		ACCESS_ONCE(*(u32 *) (to + head3)) = tmp4;

copy_tail:
	/* Copy the tail */
	tail = n;

	BUG_ON((u64) tail >= 8);

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

	LBL_USR_PFAULT("lbl_generic_copy_from_user", "4:");
fallback:
	END_USR_PFAULT;

	if (n) {
		char *from_c, *to_c;
		int i;

		from_c = (char *) from;
		to_c = (char *) to;
		BUG_ON(from + size - n != src || to + size - n != dst);

		BEGIN_USR_PFAULT("lbl_generic_copy_from_user_fallback", "5f");
		for (i = size - n; i < size; i++) {
			ACCESS_ONCE(to_c[i]) = ACCESS_ONCE(from_c[i]);
			E2K_CMD_SEPARATOR;
			--n;
		}
		LBL_USR_PFAULT("lbl_generic_copy_from_user_fallback", "5:");
		if (END_USR_PFAULT)
			return n;

		BUG_ON(n);
	}

	return 0;
}
EXPORT_SYMBOL(generic_copy_from_user);

noinline unsigned long generic_copy_in_user(void __user *to,
		const void __user *from, unsigned long size)
{
	void *dst = to;
	const void *src = from;
	unsigned long head, tail, head1, head2, head3, head4,
			tail1, tail2, tail4, tail6;
	u32 tmp4;
	u16 tmp2;
	u8 tmp1;
	unsigned long n = size;

	BEGIN_USR_PFAULT("lbl_generic_copy_in_user", "6f");

	if (unlikely(n < 8))
		goto copy_tail;

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
		ACCESS_ONCE(*(u8 *) to) = tmp1;
	if (head2)
		ACCESS_ONCE(*(u16 *) (to + head1)) = tmp2;
	if (head4)
		ACCESS_ONCE(*(u32 *) (to + head3)) = tmp4;

	/* Make sure "n" is changed *after* the actual
	 * user accesses have been issued */
	E2K_CMD_SEPARATOR;

	src += head & 0x7;
	dst = PTR_ALIGN(dst, 8);
	n -= head & 0x7;

	do {
		size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);
		size_t copied;

		BEGIN_USR_PFAULT("recovery_memcpy_fault",
				 "$.recovery_memcpy_fault");
		copied = recovery_memcpy_8(dst, src, length,
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				1);
		END_USR_PFAULT;

		n -= copied;

		src += copied;
		dst += copied;

		if (unlikely(copied != length))
			goto fallback;
	} while (unlikely(n >= 8));

copy_tail:
	/* Copy the tail */
	tail = n;

	BUG_ON((u64) tail >= 8);

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

	LBL_USR_PFAULT("lbl_generic_copy_in_user", "6:");
fallback:
	END_USR_PFAULT;

	if (n) {
		char *from_c, *to_c;
		int i;

		from_c = (char *) from;
		to_c = (char *) to;
		BUG_ON(from + size - n != src || to + size - n != dst);

		BEGIN_USR_PFAULT("lbl_generic_copy_in_user_fallback", "7f");
		for (i = size - n; i < size; i++) {
			ACCESS_ONCE(to_c[i]) = ACCESS_ONCE(from_c[i]);
			E2K_CMD_SEPARATOR;
			--n;
		}
		LBL_USR_PFAULT("lbl_generic_copy_in_user_fallback", "7:");
		if (END_USR_PFAULT)
			return n;

		BUG_ON(n);
	}

	return 0;
}
EXPORT_SYMBOL(generic_copy_in_user);


/*
 * all address  must be aligned
 */
unsigned long __copy_user_with_tags(void *to, const void *from, unsigned long n)
{
	const unsigned long orig_n = n;

	DebugUA	("copy_user_with_tags  n = 0x%lx to = %p, from = %p\n",
			n, to, from);
	if (unlikely(((long) to & 0x7) || ((long) from & 0x7) || (n & 0x7))) {
		DebugUA	(" copy_user_with_tags to=%p prom=%p n=%ld\n",
				to, from, n);
		return n;
	}

	/** save addr to return from trap if 'from'' is not well */
	BEGIN_USR_PFAULT("lbl_copy_user_with_tags", "8f");

	while (n) {
		E2K_MOVE_TAGGED_DWORD(from, to);
		from += 8;
		to += 8;
		n -= 8;
	}

	LBL_USR_PFAULT("lbl_copy_user_with_tags", "8:");
	if (END_USR_PFAULT) {
		n = orig_n;
        }        
	DebugUA	("copy_user_with_tags n = 0x%lx to = %p, frpm = %p\n",
			n, to, from);
	return n;
}
