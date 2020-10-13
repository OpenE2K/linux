#ifndef _E2K_BOOT_BITOPS_H_
#define _E2K_BOOT_BITOPS_H_

#include <linux/init.h>

#include <asm/types.h>
#include <asm/boot_head.h>
#include <asm/head.h>
#include <asm/atomic.h>

#define bitops_get_mask(nr)	(1UL << (nr & 63));

static inline void boot_set_bit(int nr, volatile void * addr)
{
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic64_set_mask(mask, m);
}

static inline void boot_clear_bit(int nr, volatile void * addr)
{
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic64_clear_mask(mask, m);
}

static inline void boot_change_bit(int nr, volatile void * addr)
{
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);
	__api_atomic64_change_mask(mask, m);
}

static inline int boot_test_and_set_bit(int nr, volatile void * addr)
{
	long retval;
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic64_get_old_set_mask(mask, m);
	return (retval & mask) != 0;
}

static inline int boot_test_and_clear_bit(int nr, volatile void * addr)
{
	long retval;
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic64_get_old_clear_mask(mask, m);
	return (retval & mask) != 0;
}

static inline int boot_test_and_change_bit(int nr, volatile void * addr)
{
	long retval;
	unsigned long *m = ((unsigned long *)addr) + (nr >> 6);
	unsigned long mask = bitops_get_mask(nr);

	retval = __api_atomic64_get_old_change_mask(mask, m);
	return (retval & mask) != 0;
}

static inline int boot_test_bit(int nr, const volatile void *addr)
{
	return (1UL & (((unsigned long *)addr)[nr >> 6] >> (nr & 63))) != 0UL;
}

#endif /* _E2K_BOOT_BITOPS_H_ */
