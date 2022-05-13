#ifndef _E2K_P2V_BOOT_BITOPS_H_
#define _E2K_P2V_BOOT_BITOPS_H_

#include <linux/init.h>

#include <asm/types.h>
#include <asm/head.h>
#include <asm/atomic.h>

#define bitops_get_mask(nr)	(1UL << (nr & 63));

static inline void boot_set_bit(int nr, volatile void * addr)
{
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic_op(mask, m, d, "ord", RELAXED_MB);
}

static inline void boot_clear_bit(int nr, volatile void * addr)
{
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic_op(mask, m, d, "andnd", RELAXED_MB);
}

static inline void boot_change_bit(int nr, volatile void * addr)
{
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic_op(mask, m, d, "xord", RELAXED_MB);
}

static inline int boot_test_and_set_bit(int nr, volatile void * addr)
{
	long retval;
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic_fetch_op(mask, m, d, "ord", STRONG_MB);

	return (retval & mask) != 0;
}

static inline int boot_test_and_clear_bit(int nr, volatile void * addr)
{
	long retval;
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic_fetch_op(mask, m, d, "andnd", STRONG_MB);

	return (retval & mask) != 0;
}

static inline int boot_test_and_change_bit(int nr, volatile void * addr)
{
	long retval;
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic_fetch_op(mask, m, d, "xord", STRONG_MB);

	return (retval & mask) != 0;
}

static inline int boot_test_bit(int nr, const volatile void *addr)
{
	return (1UL & (((unsigned long *)addr)[nr >> 6] >> (nr & 63))) != 0UL;
}

#endif /* _E2K_P2V_BOOT_BITOPS_H_ */
