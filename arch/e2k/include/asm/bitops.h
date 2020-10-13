#ifndef _E2K_BITOPS_H_
#define _E2K_BITOPS_H_

#ifndef _LINUX_BITOPS_H
#error only <linux/bitops.h> can be included directly
#endif

#include <linux/compiler.h>
#include <asm/e2k_api.h>
#include <asm/bitsperlong.h>
#include <asm/machdep.h>

#define BIT_64(n)	(U64_C(1) << (n))

/*
 * Atomic operations imply a full memory barrier since e2s.
 */
#define smp_mb__before_clear_bit()	do { } while (0)

#if !defined CONFIG_E2K_MACHINE || \
		defined CONFIG_E2K_E3M || \
		defined CONFIG_E2K_E3M_IOHUB || \
		defined CONFIG_E2K_E3S || \
		defined CONFIG_E2K_ES2_DSP || \
		defined CONFIG_E2K_ES2_RU
# define smp_mb__after_clear_bit()	smp_mb()
# define smp_mb__after_set_bit()	smp_mb()
#else
# define smp_mb__after_clear_bit()	do { } while (0)
# define smp_mb__after_set_bit()	do { } while (0)
#endif

#ifdef CONFIG_E2K_HAS_OPT_BITOPS

static inline int ffz(unsigned long x)
{
	unsigned long r;

	r = E2K_BITREVD(x);
	r = ~r;

	return E2K_LZCNTD(r);
}

static inline int ffs(int x)
{
	int r;

	if (!x)
		return 0;

	r = E2K_BITREVS(x);

	return E2K_LZCNTS(r) + 1;

}

static inline unsigned long __ffs(unsigned long x)
{
	unsigned long r;

	r = E2K_BITREVD(x);

	return E2K_LZCNTD(r);
}

static inline int fls(unsigned int x)
{
	return 8 * sizeof(int) - E2K_LZCNTS(x);
}

static inline unsigned long __fls(unsigned long word)
{
	return BITS_PER_LONG - E2K_LZCNTD(word) - 1;
}

static inline int fls64(unsigned long x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}

static inline unsigned int hweight32(unsigned int w)
{
	return E2K_POPCNTS(w);
}

static inline unsigned int hweight16(unsigned int w)
{
	return E2K_POPCNTS(w & 0xffff);
}

static inline unsigned int hweight8(unsigned int w)
{
	return E2K_POPCNTS(w & 0xff);
}

static inline unsigned long hweight64(unsigned long w)
{
	return E2K_POPCNTD(w);
}

#define __arch_hweight32 hweight32
#define __arch_hweight16 hweight16
#define __arch_hweight8  hweight8
#define __arch_hweight64 hweight64

#else /* !CONFIG_E2K_HAS_OPT_BITOPS */

#include <asm-generic/bitops/ffz.h>
#include <asm-generic/bitops/ffs.h>
#include <asm-generic/bitops/__ffs.h>
#include <asm-generic/bitops/fls.h>
#include <asm-generic/bitops/__fls.h>
#include <asm-generic/bitops/fls64.h>

#define ARCH_HAS_FAST_MULTIPLIER 1
#include <asm-generic/bitops/hweight.h>

#endif /* CONFIG_E2K_HAS_OPT_BITOPS */


#include <asm-generic/bitops/non-atomic.h>

#include <asm-generic/bitops/find.h>

#define bitops_get_mask(nr)	(1UL << (nr & 63));
	
static inline void set_bit(long nr, volatile void * addr)
{
	volatile unsigned long *m = ((volatile unsigned long *) addr)
			+ (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic64_set_mask(mask, m);
}

static inline void clear_bit(long nr, volatile void * addr)
{
	volatile unsigned long *m = ((volatile unsigned long *) addr)
			+ (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic64_clear_mask(mask, m);
}

static inline void change_bit(long nr, volatile void * addr)
{
	volatile unsigned long *m = ((volatile unsigned long *) addr)
			+ (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic64_change_mask(mask, m);
}

static inline int test_and_set_bit(long nr, volatile void * addr)
{
	long retval;
	volatile unsigned long *m = ((volatile unsigned long *) addr)
			+ (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic64_get_old_set_mask(mask, m);
	return (retval & mask) != 0;
}

static inline int test_and_clear_bit(long nr, volatile void * addr)
{
	long retval;
	volatile unsigned long *m = ((volatile unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic64_get_old_clear_mask(mask, m);
	return (retval & mask) != 0;
}

static inline int test_and_change_bit(long nr, volatile void * addr)
{
	long retval;
	volatile unsigned long *m = ((volatile unsigned long *) addr)
			+ (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic64_get_old_change_mask(mask, m);
	return (retval & mask) != 0;
}

#ifdef __KERNEL__

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
static inline void __clear_bit_32(long nr, volatile void * addr)
{
	volatile unsigned long *m = ((volatile unsigned long *)addr)+(nr >> 6);
	unsigned int mask = (unsigned int) bitops_get_mask(nr);
	(void)__api_atomic_clear_mask_32(mask, m);
}

static inline int __test_and_clear_bit_32(long nr, volatile void * addr)
{
	int retval;
	volatile unsigned long *m = ((volatile unsigned long *)addr)+(nr >> 6);
	unsigned int mask = (unsigned int) bitops_get_mask(nr);

	retval = __api_atomic_get_old_clear_mask_32(mask, m);
	return (retval & mask) != 0;
}

#define clear_bit_32		__clear_bit_32
#define test_and_clear_bit_32	__test_and_clear_bit_32	
#endif /* CONFIG_SECONDARY_SPACE_SUPPORT */


#include <asm-generic/bitops/const_hweight.h>

#include <asm-generic/bitops/le.h>

#include <asm-generic/bitops/ext2-atomic-setbit.h>

#include <asm-generic/bitops/sched.h>

#include <asm-generic/bitops/lock.h>

#endif /* __KERNEL__ */


#endif /* _E2K_BITOPS_H_ */
