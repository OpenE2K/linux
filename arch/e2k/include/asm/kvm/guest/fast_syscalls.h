#ifndef _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H
#define _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H

#include <linux/time.h>
#include <asm/sections.h>
#include <asm/signal.h>

int kvm_do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp);
int kvm_fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp);
int kvm_do_fast_gettimeofday(struct timeval *tv);
int kvm_fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel (not paravirtualized based on pv_ops) */
static inline int
do_fast_clock_gettime(const clockid_t which_clock, struct timespec *tp)
{
	return kvm_do_fast_clock_gettime(which_clock, tp);
}

static inline int
fast_sys_clock_gettime(const clockid_t which_clock, struct timespec __user *tp)
{
	return kvm_fast_sys_clock_gettime(which_clock, tp);
}

static inline int
do_fast_gettimeofday(struct timeval *tv)
{
	return kvm_do_fast_gettimeofday(tv);
}
static inline int
fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return kvm_fast_sys_siggetmask(oset, sigsetsize);
}
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H */

