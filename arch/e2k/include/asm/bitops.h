#ifndef _E2K_BITOPS_H_
#define _E2K_BITOPS_H_

#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <linux/compiler.h>
#include <asm/barrier.h>
#include <asm/e2k_api.h>

/* This is better than generic definition */
static inline int fls(unsigned int x)
{
	return 8 * sizeof(int) - E2K_LZCNTS(x);
}

static inline unsigned int __arch_hweight32(unsigned int w)
{
	return E2K_POPCNTS(w);
}

static inline unsigned int __arch_hweight16(unsigned int w)
{
	return E2K_POPCNTS(w & 0xffff);
}

static inline unsigned int __arch_hweight8(unsigned int w)
{
	return E2K_POPCNTS(w & 0xff);
}

static inline unsigned long __arch_hweight64(unsigned long w)
{
	return E2K_POPCNTD(w);
}

#include <asm-generic/bitops/builtin-__ffs.h>
#include <asm-generic/bitops/builtin-__fls.h>
#include <asm-generic/bitops/builtin-ffs.h>
#include <asm-generic/bitops/fls64.h>
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
#include <asm-generic/bitops/find.h>

#include <asm-generic/bitops/atomic.h>
#include <asm-generic/bitops/const_hweight.h>
#include <asm-generic/bitops/ext2-atomic-setbit.h>
#include <asm-generic/bitops/le.h>
#include <asm-generic/bitops/lock.h>
#include <asm-generic/bitops/sched.h>

#endif /* _E2K_BITOPS_H_ */
