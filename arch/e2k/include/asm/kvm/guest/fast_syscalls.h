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
int kvm_do_fast_sys_set_return(u64 ip, int flags);

#ifdef	CONFIG_KVM_GUEST_KERNEL

#define __NR_fast_gettimeofday	0
#define __NR_fast_clock_gettime	1
#define __NR_fast_getcpu	2
#define __NR_fast_siggetmask	3
#define __NR_fast_getcontext	4
#define __NR_fast_set_return	5

#define	goto_ttable_entry1_args3(sys_num, arg1, arg2, ret)	\
		E2K_SCALL_ARG7(1, ret, sys_num, arg1, arg2, 0, 0, 0, 0)
#define	goto_ttable_entry1_args4(sys_num, arg1, arg2, arg3, ret)	\
		E2K_SCALL_ARG7(1, ret, sys_num, arg1, arg2, arg3, 0, 0, 0)

#define	goto_ttable_entry3_args3(sys_num, arg1, arg2, ret)	\
		E2K_SCALL_ARG7(3, ret, sys_num, arg1, arg2, 0, 0, 0, 0)
#define	goto_ttable_entry3_args4(sys_num, arg1, arg2, arg3, ret)	\
		E2K_SCALL_ARG7(3, ret, sys_num, arg1, arg2, arg3, 0, 0, 0)

/* it is native guest kernel (not paravirtualized based on pv_ops) */
static inline int
do_fast_clock_gettime(const clockid_t which_clock, struct timespec *tp)
{
	return kvm_do_fast_clock_gettime(which_clock, tp);
}
static inline int
do_fast_gettimeofday(struct timeval *tv)
{
	return kvm_do_fast_gettimeofday(tv);
}
static inline int
do_fast_sys_set_return(u64 ip, int flags)
{
	return kvm_do_fast_sys_set_return(ip, flags);
}
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H */
