/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_BITOPS_H_
#define _E2K_BITOPS_H_

#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <linux/compiler.h>
#include <asm/barrier.h>

/* This is better than generic definition */
static inline int fls(unsigned int x)
{
	return 8 * sizeof(int) - __builtin_e2k_lzcnts(x);
}

static inline unsigned int __arch_hweight32(unsigned int w)
{
	return __builtin_e2k_popcnts(w);
}

static inline unsigned int __arch_hweight16(unsigned int w)
{
	return __builtin_e2k_popcnts(w & 0xffff);
}

static inline unsigned int __arch_hweight8(unsigned int w)
{
	return __builtin_e2k_popcnts(w & 0xff);
}

static inline unsigned long __arch_hweight64(unsigned long w)
{
	return __builtin_e2k_popcntd(w);
}

/**
 * fls64 - find last set bit in a 64-bit word
 * @x: the word to search
 *
 * This is defined in a similar way as the libc and compiler builtin
 * ffsll, but returns the position of the most significant set bit.
 *
 * fls64(value) returns 0 if value is 0 or the position of the last
 * set bit if value is nonzero. The last (most significant) bit is
 * at position 64.
 */
static __always_inline int fls64(__u64 x)
{
	return 64 - __builtin_e2k_lzcntd(x);
}

#include <asm-generic/bitops/builtin-__ffs.h>
#include <asm-generic/bitops/builtin-__fls.h>
#include <asm-generic/bitops/builtin-ffs.h>
#include <asm-generic/bitops/ffz.h>
#include <asm-generic/bitops/non-atomic.h>

#if defined E2K_P2V && !defined CONFIG_BOOT_E2K
extern unsigned long boot_find_next_bit(const unsigned long *addr,
		unsigned long size, unsigned long offset);
extern unsigned long boot_find_next_zero_bit(const unsigned long *addr,
		unsigned long size, unsigned long offset);
# define find_next_bit boot_find_next_bit
# define find_next_zero_bit boot_find_next_zero_bit
#endif

#include <asm-generic/bitops/atomic.h>
#include <asm-generic/bitops/const_hweight.h>
#include <asm-generic/bitops/ext2-atomic-setbit.h>
#include <asm-generic/bitops/le.h>
#include <asm-generic/bitops/lock.h>
#include <asm-generic/bitops/sched.h>

#endif /* _E2K_BITOPS_H_ */
