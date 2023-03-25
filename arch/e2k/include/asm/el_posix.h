#ifndef _ASM_EL_POSIX_ATOMIC_H
#define _ASM_EL_POSIX_ATOMIC_H

#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
#ifdef __KERNEL__
#include <linux/uaccess.h>
#include <asm/atomic.h>

#define ARCH_HAS_GET_CYCLES

#define ARCH_HAS_ATOMIC_CMPXCHG

#define el_atomic_cmpxchg_acq(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg_acq(&x, uaddr, oldval, newval)
static int __el_atomic_cmpxchg_acq(int *x, int *uaddr, int oldval, int newval)
{
	int ret;

	uaccess_enable();
	ret = __api_user_cmpxchg_word(oldval, newval, uaddr, ACQUIRE_MB, *x);
	uaccess_disable();

	return ret;
}

#define el_atomic_cmpxchg_rel(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg_rel(&x, uaddr, oldval, newval)
static int __el_atomic_cmpxchg_rel(int *x, int *uaddr, int oldval, int newval)
{
	int ret;

	uaccess_enable();
	ret = __api_user_cmpxchg_word(oldval, newval, uaddr, RELEASE_MB, *x);
	uaccess_disable();

	return ret;
}

#define el_atomic_xchg_acq(x, uaddr, value) \
		__el_atomic_xchg_acq(&x, uaddr, value)
static int __el_atomic_xchg_acq(int *x, int *uaddr, const int value)
{
	int ret;

	uaccess_enable();
	ret = __api_user_xchg(value, addr, w, ACQUIRE_MB, *x);
	uaccess_disable();

	return ret;
}

#endif
#endif
#endif
