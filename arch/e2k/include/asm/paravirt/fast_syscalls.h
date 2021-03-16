#ifndef _ASM_E2K_PARAVIRT_FAST_SYSCALLS_H
#define _ASM_E2K_PARAVIRT_FAST_SYSCALLS_H

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline int
pv_do_fast_clock_gettime(const clockid_t which_clock, struct timespec *tp)
{
	return pv_cpu_ops.do_fast_clock_gettime(which_clock, tp);
}

static inline int
pv_fast_sys_clock_gettime(const clockid_t which_clock,
				struct timespec __user *tp)
{
	return pv_cpu_ops.fast_sys_clock_gettime(which_clock, tp);
}

static inline int
pv_do_fast_gettimeofday(struct timeval *tv)
{
	return pv_cpu_ops.do_fast_gettimeofday(tv);
}

static inline int
pv_fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return pv_cpu_ops.fast_sys_siggetmask(oset, sigsetsize);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is native guest kernel (not paravirtualized based on pv_ops) */
static inline int
do_fast_clock_gettime(const clockid_t which_clock, struct timespec *tp)
{
	return pv_do_fast_clock_gettime(which_clock, tp);
}

static inline int
fast_sys_clock_gettime(const clockid_t which_clock, struct timespec __user *tp)
{
	return pv_fast_sys_clock_gettime(which_clock, tp);
}

static inline int
do_fast_gettimeofday(struct timeval *tv)
{
	return pv_do_fast_gettimeofday(tv);
}
static inline int
fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return pv_fast_sys_siggetmask(oset, sigsetsize);
}
#endif	/* ! CONFIG_PARAVIRT_GUEST */

#endif /* _ASM_E2K_PARAVIRT_FAST_SYSCALLS_H */

