#include <linux/clocksource.h>

#include <asm/fast_syscalls.h>


/*
 * Guest trap table cannot be placed into host kernel table because of
 * host table is located in privileged area.
 * FIXME: to improve locality, fast syscalls tables should be located
 * in the .text section nearly to the OS entry code.
 */

int kvm_do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp)
{
	return DO_FAST_CLOCK_GETTIME(which_clock, tp);
}

int kvm_fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp)
{
	return FAST_SYS_CLOCK_GETTIME(which_clock, tp);
}

int kvm_do_fast_gettimeofday(struct timeval *tv)
{
	return DO_FAST_GETTIMEOFDAY(tv);
}

int kvm_fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return FAST_SYS_SIGGETMASK(oset, sigsetsize);
}

const fast_system_call_func kvm_fast_sys_calls_table[NR_fast_syscalls] = {
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	FAST_SYSTEM_CALL_TBL_ENTRY(kvm_fast_sys_clock_gettime),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	FAST_SYSTEM_CALL_TBL_ENTRY(kvm_fast_sys_siggetmask),

	/*
	 * the follow fast system call is not yet implemented
	 * FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	 */
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),

	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};

#ifdef CONFIG_COMPAT
const fast_system_call_func kvm_fast_sys_calls_table_32[NR_fast_syscalls] = {
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),

	/*
	 * the follow fast system call is not yet implemented
	 * COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	 */
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),

	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};
#endif

#ifdef CONFIG_PROTECTED_MODE
const fast_system_call_func kvm_fast_sys_calls_table_128[NR_fast_syscalls] = {
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),

	/*
	 * the follow fast system call is not yet implemented
	 * PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	 */
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),

	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};
#endif

