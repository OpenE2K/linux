#ifndef _ASM_WORD_AT_A_TIME_H
#define _ASM_WORD_AT_A_TIME_H

#include <linux/kernel.h>

/* Unused */
struct word_at_a_time { };
#define WORD_AT_A_TIME_CONSTANTS { }

/* This will give us 0xff for a zero char and 0x00 elsewhere */
static inline unsigned long has_zero(unsigned long a, unsigned long *bits,
				     const struct word_at_a_time *c)
{
	*bits = __builtin_e2k_pcmpeqb(a, 0);
	return *bits;
}

static inline unsigned long prep_zero_mask(unsigned long a, unsigned long bits,
					   const struct word_at_a_time *c)
{
	return bits;
}

/* This will give us 0xff until the first zero char (excluding it) */
static inline unsigned long create_zero_mask(unsigned long bits)
{
	return (bits - 1) & ~bits;
}

/* The mask we created is directly usable as a bytemask */
#define zero_bytemask(mask) (mask)

static inline unsigned long find_zero(unsigned long mask)
{
	return __builtin_e2k_popcntd(mask) >> 3;
}

/*
 * Load an unaligned word from kernel space.
 *
 * In the (very unlikely) case of the word being a page-crosser
 * and the next page not being mapped, take the exception and
 * return zeroes in the non-existing part.
 */
static inline unsigned long load_unaligned_zeropad(const void *addr)
{
	return LOAD_UNALIGNED_ZEROPAD(addr);
}

#endif /* _ASM_WORD_AT_A_TIME_H */
