/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/clocksource.h>
#include <linux/timekeeper_internal.h>

#include <asm/fast_syscalls.h>

struct fast_syscalls_data fsys_data __cacheline_aligned;

void update_vsyscall(struct timekeeper *tk)
{
	struct timespec64 ts;

	ts.tv_sec = tk->xtime_sec;
	ts.tv_nsec = (long)(tk->tkr_mono.xtime_nsec >> tk->tkr_mono.shift);

	fastsys_write_begin(&fsys_data);

	fsys_data.mult = tk->tkr_mono.mult;
	fsys_data.shift = tk->tkr_mono.shift;
	fsys_data.clock = tk->tkr_mono.clock;
	fsys_data.cycle_last = tk->tkr_mono.cycle_last;
	fsys_data.sec = tk->xtime_sec;
	fsys_data.nsec = tk->tkr_mono.xtime_nsec;
	fsys_data.w2m_sec = tk->wall_to_monotonic.tv_sec;
	fsys_data.w2m_nsec = tk->wall_to_monotonic.tv_nsec;
	fsys_data.wall_time_coarse.tv_sec = ts.tv_sec;
	fsys_data.wall_time_coarse.tv_nsec = ts.tv_nsec;

	fastsys_write_end(&fsys_data);
}

void update_vsyscall_tz(void)
{
}

notrace __section(".entry.text")
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

__section(".ttable_entry6_table")
const fast_system_call_func fast_sys_calls_table[NR_fast_syscalls] = {
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_set_return),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
};

__section(".ttable_entry5_table")
const fast_system_call_func fast_sys_calls_table_32[NR_fast_syscalls] = {
#ifdef CONFIG_COMPAT
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_gettimeofday),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_clock_gettime),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcpu),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_siggetmask),
	COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_getcontext),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_set_return),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall),
#else
	FAST_SYSTEM_CALL_TBL_ENTRY(fast_sys_ni_syscall)
#endif
};

#ifdef CONFIG_PROTECTED_MODE
__section(".ttable_entry7_table")
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
