#ifndef _ASM_EL_POSIX_ATOMIC_H
#define _ASM_EL_POSIX_ATOMIC_H

#ifdef __KERNEL__
#include <asm/uaccess.h>
#include <asm/atomic.h>

#define ARCH_HAS_GET_CYCLES

#define ARCH_HAS_ATOMIC_CMPXCHG

static noinline int __el_atomic_cmpxchg(int *x, int *uaddr, int oldval,
		int newval)
{
	int rval, tmp;

	BEGIN_USR_PFAULT("lbl_el_atomic_cmpxchg", "9f");
	tmp = cmpxchg(uaddr, oldval, newval);
	LBL_USR_PFAULT("lbl_el_atomic_cmpxchg", "9:");
	if (END_USR_PFAULT) {
		DebugUAF("%s (%d) - %s : "
			"el_atomic_cmpxchg data fault %p(%ld)\n",
			__FILE__, __LINE__, __FUNCTION__,
			(uaddr), (sizeof(*uaddr)));
		rval = -EFAULT;
	} else {
		*x = tmp;
		rval = 0;
	}
	return rval;
}

#define el_atomic_cmpxchg_acq(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg(&x, uaddr, oldval, newval)
#define el_atomic_cmpxchg_rel(x, uaddr, oldval, newval) \
		__el_atomic_cmpxchg(&x, uaddr, oldval, newval)

#define el_atomic_xchg_acq(x, uaddr, value) \
		__el_atomic_xchg_acq(&x, uaddr, value)

static noinline int __el_atomic_xchg_acq(int *x, int *uaddr, const int value)
{
	int rval, tmp;

	BEGIN_USR_PFAULT("lbl_el_atomic_xchg", "8f");
	tmp = xchg(uaddr, value);
	LBL_USR_PFAULT("lbl_el_atomic_xchg", "8:");
	if (END_USR_PFAULT) {
		DebugUAF("%s (%d) - %s : "
			"el_atomic_xchg data fault %p(%ld)\n",
			__FILE__, __LINE__, __FUNCTION__,
			(uaddr), (sizeof(*uaddr)));
		rval = -EFAULT;
	} else {
		*x = tmp;
		rval = 0;
	}
	return rval;
}

#endif
#endif
