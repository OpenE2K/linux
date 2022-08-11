/* linux/arch/e2k/lib/usercopy.c, v 1.7 15/08/2001.
 *
 * Copyright (C) 2001 MCST
 */

#include <linux/types.h>
#include <linux/mm.h>

#include <linux/uaccess.h>
#include <asm/word-at-a-time.h>
#include <asm/mmu_fault.h>


/**
 * fill_user: - Fill a block of memory in user space with given bytes.
 * @to:   Destination address, in user space.
 * @n:    Number of bytes to zero.
 * @b:    Byte to fill memory with.
 *
 * Zero a block of memory in user space.
 *
 * Returns number of bytes that could not be cleared.
 * On success, this will be zero.
 */
unsigned long
__fill_user(void __user *_to, const unsigned long _n, const u8 _b)
{
	u64 b = __builtin_e2k_pshufb(_b, _b, 0);
	volatile long n = _n;
	void *volatile to = _to;
	unsigned long align = (unsigned long) _to & 0xf, head, tail,
			head1, head2, head3, head4, head7, head8,
			tail1, tail2, tail4, tail8, tail12, tail14;
	void *to_aligned = PTR_ALIGN((void *)to, 16);
	long i, count = _n;

	DebugUA("__clear_user %px : 0x%lx\n", to, n);

	head = 16 - align;

	/* save addr to return from trap if 'to' is bad */
	TRY_USR_PFAULT {
		if (unlikely(n < 16)) {
			int i;

			for (i = 0; i < n; i++)
				((u8 *) to)[i] = b;

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
			*(u8 *) to = b;
		if (head2)
			*(u16 *) (to + head1) = b;
		if (head4)
			*(u32 *) (to + head3) = b;
		if (head8)
			*(u64 *) (to + head7) = b;

		for (i = 0; i < (count >> 3) - 1; i += 2) {
			((u64 *) to_aligned)[i] = b;
			((u64 *) to_aligned)[i + 1] = b;
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
			*(u64 *) to_aligned = b;
		if (tail4)
			*(u32 *) (to_aligned + tail8) = b;
		if (tail2)
			*(u16 *) (to_aligned + tail12) = b;
		if (tail1)
			*(u8 *) (to_aligned + tail14) = b;

out:
		;
	} CATCH_USR_PFAULT {
		/*
		 * There was a trap that could not be handled.
		 * Clearing all the area again with 1-byte stores
		 * is certainly slow, but this is an extremely
		 * unlikely case we do not care about.
		 */
		volatile int i;

		TRY_USR_PFAULT {
			for (i = 0; i < n; i++) {
				WRITE_ONCE(((u8 *) to)[i], b);
				E2K_CMD_SEPARATOR;
			}
		} CATCH_USR_PFAULT {
			return n - i;
		} END_USR_PFAULT

		BUG_ON(n != i);
	} END_USR_PFAULT

	return 0;
}
EXPORT_SYMBOL(__fill_user);

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

	TRY_USR_PFAULT {
		DebugUA("to = %#llX, from = %#llX, count = %ld\n",
			(u64) dst, (u64) src, count);
		for (i = 0; likely(i < count); i++)
			if (unlikely((dst[i] = src[i]) == 0))
				break;
	} CATCH_USR_PFAULT {
		/* It was trap */ 
		return -EFAULT;
	} END_USR_PFAULT

	return i;
}
EXPORT_SYMBOL(__strncpy_from_user);

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

	TRY_USR_PFAULT {
		src_addr = (unsigned long) str;
		if (likely(src_addr < max_addr)) {
			unsigned long max = max_addr - src_addr;
			res = do_strnlen_user(str, count, max);
		} else {
			res = 0;
		}
	} CATCH_USR_PFAULT {
		return 0;
	} END_USR_PFAULT

	return res;
}
EXPORT_SYMBOL(strnlen_user);

noinline unsigned long raw_copy_from_user(void *_to,
		const void __user *_from, unsigned long _size)
{
	int hwbug = cpu_has(CPU_HWBUG_UNALIGNED_LOADS);
	const void __user *volatile from = _from;
	void __user *volatile to = _to;
	volatile unsigned long size = _size;
	volatile unsigned long n = _size;

	TRY_USR_PFAULT {
		unsigned long head, tail, head1, head3, head7,
				tail8, tail12, tail14;
		void *dst = to, *orig_dst = to;
		const void *src = from;
		u64 tmp8;
		u32 tmp4;
		u16 tmp2;
		u8 tmp1;

		if (hwbug) {
			prefetch_nospec_range((void *) src, size);
			E2K_WAIT(_ld_c);
		}

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
				SET_USR_PFAULT("$.recovery_memcpy_fault");
				copied = fast_tagged_memory_copy((void *)dst,
					(void *)src, length,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
					MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
					MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
					!hwbug);
				RESTORE_USR_PFAULT;
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

				goto fallback;
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
			tmp8 = *(u64 *) src;
		if (tail & 4)
			tmp4 = *(u32 *) (src + tail8);
		if (tail & 2)
			tmp2 = *(u16 *) (src + tail12);
		if (tail & 1)
			tmp1 = *(u8 *) (src + tail14);

		if (tail & 8)
			*(u64 *) dst = tmp8;
		if (tail & 4)
			*(u32 *) (dst + tail8) = tmp4;
		if (tail & 2)
			*(u16 *) (dst + tail12) = tmp2;
		if (tail & 1)
			*(u8 *) (dst + tail14) = tmp1;

		/* Make sure "n" is changed *after* the actual
		 * user accesses have been issued */
		E2K_CMD_SEPARATOR;
		n = 0;
fallback:;
	} CATCH_USR_PFAULT {
	} END_USR_PFAULT

	if (n) {
		const char *from_c = from;
		char *to_c = to;
		int i;

		TRY_USR_PFAULT {
			for (i = size - n; i < size; i++) {
				WRITE_ONCE(to_c[i], READ_ONCE(from_c[i]));
				E2K_CMD_SEPARATOR;
				--n;
			}
		} CATCH_USR_PFAULT {
			return n;
		} END_USR_PFAULT

		BUG_ON(n);
	}

	return 0;
}
EXPORT_SYMBOL(raw_copy_from_user);

noinline unsigned long raw_copy_in_user(void __user *_to,
		const void __user *_from, unsigned long _size)
{
	int hwbug = cpu_has(CPU_HWBUG_UNALIGNED_LOADS);
	const void __user *volatile from = _from;
	void __user *volatile to = _to;
	volatile unsigned long size = _size;
	volatile unsigned long n = _size;

	TRY_USR_PFAULT {
		unsigned long head, tail, head1, head3, head7,
				tail8, tail12, tail14;
		void *dst = to;
		const void *src = from;
		u64 tmp8;
		u32 tmp4;
		u16 tmp2;
		u8 tmp1;

		if (hwbug) {
			prefetch_nospec_range((void *) src, size);
			E2K_WAIT(_ld_c);
		}

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
			*(u8 *) dst = tmp1;
		if (head & 2)
			*(u16 *) (dst + head1) = tmp2;
		if (head & 4)
			*(u32 *) (dst + head3) = tmp4;
		if (head & 8)
			*(u64 *) (dst + head7) = tmp8;

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
				SET_USR_PFAULT("$.recovery_memcpy_fault");
				copied = fast_tagged_memory_copy((void *)dst,
					(void *)src, length,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
					MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
					LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT |
					MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
					!hwbug);
				RESTORE_USR_PFAULT;
			}

			n -= copied;

			src += copied;
			dst += copied;

			if (unlikely(copied != length))
				goto fallback;
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
			*(u64 *) dst = tmp8;
		if (tail & 4)
			*(u32 *) (dst + tail8) = tmp4;
		if (tail & 2)
			*(u16 *) (dst + tail12) = tmp2;
		if (tail & 1)
			*(u8 *) (dst + tail14) = tmp1;

		/* Make sure "n" is changed *after* the actual
		 * user accesses have been issued */
		E2K_CMD_SEPARATOR;
		n = 0;
fallback:;
	} CATCH_USR_PFAULT {
	} END_USR_PFAULT

	if (n) {
		const char *from_c = from;
		char *to_c = to;
		int i;

		TRY_USR_PFAULT {
			for (i = size - n; i < size; i++) {
				WRITE_ONCE(to_c[i], READ_ONCE(from_c[i]));
				E2K_CMD_SEPARATOR;
				--n;
			}
		} CATCH_USR_PFAULT {
			return n;
		} END_USR_PFAULT

		BUG_ON(n);
	}

	return 0;
}
EXPORT_SYMBOL(raw_copy_in_user);


/*
 * All arguments must be aligned
 */
unsigned long __copy_user_with_tags(void *to, const void *from,
				    unsigned long _n)
{
	int hwbug = cpu_has(CPU_HWBUG_UNALIGNED_LOADS);
	void *volatile dst = to;
	const void *volatile src = from;
	volatile unsigned long n = _n;

	if (unlikely(((long) to & 0x7) || ((long) from & 0x7) || (_n & 0x7))) {
		DebugUA(" copy_user_with_tags to=%px from=%px n=%ld\n",
				to, from, n);
		return _n;
	}

	TRY_USR_PFAULT {
		if (hwbug) {
			prefetch_nospec_range((void *) from, n);
			E2K_WAIT(_ld_c);
		}

		do {
			size_t length = (n >= 2 * 8192) ? 8192 : (n & ~0x7UL);
			size_t copied;

			SET_USR_PFAULT("$.recovery_memcpy_fault");
			copied = fast_tagged_memory_copy(dst, src, length,
				TAGGED_MEM_STORE_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				TAGGED_MEM_LOAD_REC_OPC |
				MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT,
				!hwbug);
			RESTORE_USR_PFAULT;

			n -= copied;

			src += copied;
			dst += copied;

			if (unlikely(copied != length))
				break;
		} while (unlikely(n >= 8));
	} CATCH_USR_PFAULT {
	} END_USR_PFAULT

	return n;
}

/*
 * All arguments must be aligned
 */
unsigned long __fill_user_with_tags(void *to, unsigned long n,
		unsigned long tag, unsigned long dw)
{
	unsigned long cleared;

	if (unlikely(((long) to & 0x7) || (n & 0x7))) {
		DebugUA(" clear_user_with_tags to=%px n=%ld\n", to, n);
		return n;
	}

	SET_USR_PFAULT("$.recovery_memset_fault");
	cleared = fast_tagged_memory_set(to, dw, tag, n,
			TAGGED_MEM_STORE_REC_OPC |
			MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT);
	RESTORE_USR_PFAULT;

	return n - cleared;
}
