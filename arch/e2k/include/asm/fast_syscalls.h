#ifndef _ASM_E2K_FAST_SYSCALLS_H
#define _ASM_E2K_FAST_SYSCALLS_H

#include <linux/time.h>
#include <asm/sections.h>
#include <asm/signal.h>


struct fast_syscalls_data {
	struct timekeeper *tk;
	u32 mult;
	u32 shift;
	struct clocksource *clock;
	struct timespec wall_time_coarse;
};

extern struct fast_syscalls_data fsys_data;

int do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp);
int do_fast_gettimeofday(struct timeval *tv);
int fast_sys_gettimeofday(struct timeval __user *tv,
		struct timezone __user *tz);
int fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp);
struct getcpu_cache;
int fast_sys_getcpu(unsigned __user *cpup, unsigned __user *nodep,
		struct getcpu_cache __user *unused);
int fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize);
struct ucontext;
int fast_sys_getcontext(struct ucontext __user *ucp, size_t sigsetsize);

struct compat_timespec;
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct compat_timespec __user *tp);
struct compat_timeval;
int compat_fast_sys_gettimeofday(struct compat_timeval __user *tv,
		struct timezone __user *tz);
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize);
struct ucontext_32;
int compat_fast_sys_getcontext(struct ucontext_32 __user *ucp,
		size_t sigsetsize);

int protected_fast_sys_clock_gettime(u32 tags, const clockid_t which_clock,
		long arg2, long arg3);
int protected_fast_sys_gettimeofday(u32 tags, long arg1, long arg2, long arg3,
		long arg4, long arg5);
int protected_fast_sys_getcpu(u32 tags, long arg1, long arg2, long arg3,
		long arg4, long arg5);
int protected_fast_sys_siggetmask(u32 tags, long arg1, long arg2, long arg3,
		size_t sigsetsize);
int protected_fast_sys_getcontext(u32 tags, long arg1, long arg2, long arg3,
		size_t sigsetsize);
#endif /* _ASM_E2K_FAST_SYSCALLS_H */

