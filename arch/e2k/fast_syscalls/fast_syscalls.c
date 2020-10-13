#include <linux/clocksource.h>
#include <linux/timekeeper_internal.h>

#include <asm/fast_syscalls.h>

struct fast_syscalls_data fsys_data;

void update_vsyscall(struct timekeeper *tk)
{
	/* update_vsyscall() is called with xtime_lock held for writing,
	 * so all synchronization with readers is done by the caller */
	fsys_data.tk = tk;
	fsys_data.mult = tk->mult;
	fsys_data.shift = tk->shift;
	fsys_data.clock = tk->clock;
	fsys_data.wall_time_coarse = __current_kernel_time();
}

void update_vsyscall_tz(void)
{

}


typedef void (*fast_system_call_func)(u64 arg1, u64 arg2);

notrace __interrupt
int fast_sys_ni_syscall()
{
	return -ENOSYS;
}

#define FAST_SYSTEM_CALL_TBL_ENTRY(sysname)  (fast_system_call_func) sysname
#define COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(fast_system_call_func) compat_##sysname
#define PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(fast_system_call_func) protected_##sysname


/*
 * To improve locality, fast syscalls tables are located
 * in the .text section next to the OS entry code.
 */

__section(.ttable_entry6_table)
const fast_system_call_func fast_sys_calls_table[NR_fast_syscalls] = {
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};

#ifdef CONFIG_COMPAT
__section(.ttable_entry5_table)
const fast_system_call_func fast_sys_calls_table_32[NR_fast_syscalls] = {
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};
#endif

#ifdef CONFIG_PROTECTED_MODE
__section(.ttable_entry7_table)
const fast_system_call_func fast_sys_calls_table_128[NR_fast_syscalls] = {
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),
	PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};
#endif

