#ifndef _ASM_EL_POSIX_ATOMIC_H
#define _ASM_EL_POSIX_ATOMIC_H

#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
#ifdef __KERNEL__
#include <linux/uaccess.h>
#include <asm/atomic.h>

#define ARCH_HAS_GET_CYCLES

#define ARCH_HAS_ATOMIC_CMPXCHG

static int __el_atomic_cmpxchg(int *x, int *uaddr, int oldval, int newval)
{
	int rval;

	TRY_USR_PFAULT {
		*x = cmpxchg(uaddr, oldval, newval);
		rval = 0;
	} CATCH_USR_PFAULT {
		DebugUAF("%s (%d) - %s : "
			"el_atomic_cmpxchg data fault %px(%ld)\n",
			__FILE__, __LINE__, __FUNCTION__,
			(uaddr), (sizeof(*uaddr)));
		rval = -EFAULT;
	} END_USR_PFAULT

	return rval;
}

#define el_atomic_cmpxchg_acq(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg(&x, uaddr, oldval, newval)
#define el_atomic_cmpxchg_rel(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg(&x, uaddr, oldval, newval)

#define el_atomic_xchg_acq(x, uaddr, value) \
		__el_atomic_xchg_acq(&x, uaddr, value)

static int __el_atomic_xchg_acq(int *x, int *uaddr, const int value)
{
	int rval;

	TRY_USR_PFAULT {
		*x = xchg(uaddr, value);
		rval = 0;
	} CATCH_USR_PFAULT {
		DebugUAF("%s (%d) - %s : "
			"el_atomic_xchg data fault %px(%ld)\n",
			__FILE__, __LINE__, __FUNCTION__,
			(uaddr), (sizeof(*uaddr)));
		rval = -EFAULT;
	} END_USR_PFAULT

	return rval;
}

#endif
#endif
#endif
