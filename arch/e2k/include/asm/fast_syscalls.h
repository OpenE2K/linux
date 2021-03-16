#ifndef _ASM_E2K_FAST_SYSCALLS_H
#define _ASM_E2K_FAST_SYSCALLS_H

#include <linux/time.h>
#include <linux/time.h>
#include <linux/timekeeper_internal.h>
#include <asm/sections.h>
#include <asm/signal.h>
#include <asm/sclkr.h>
#include <asm/clkr.h>
#include <asm/trap_table.h>

struct fast_syscalls_data {
	struct timekeeper *tk;
	u32 mult;
	u32 shift;
	struct clocksource *clock;
	struct timespec wall_time_coarse;
};

extern struct fast_syscalls_data fsys_data;

extern seqcount_t timekeeper_seq;

typedef void (*fast_system_call_func)(u64 arg1, u64 arg2);

extern const fast_system_call_func fast_sys_calls_table[NR_fast_syscalls];
extern const fast_system_call_func fast_sys_calls_table_32[NR_fast_syscalls];

int fast_sys_ni_syscall(void);

#define FAST_SYSTEM_CALL_TBL_ENTRY(sysname)	\
		(fast_system_call_func) sysname
#define COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(fast_system_call_func) compat_##sysname
#define PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(fast_system_call_func) protected_##sysname

int native_do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp);
int native_fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp);
int native_do_fast_gettimeofday(struct timeval *tv);
int native_fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is pure guest kernel (not paravirtualized basec on pv_ops) */
#include <asm/kvm/guest/fast_syscalls.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/fast_syscalls.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* it is native host kernel withounr virtualization */
/* or host kernel with virtualization support */
static inline int
do_fast_clock_gettime(const clockid_t which_clock, struct timespec *tp)
{
	return native_do_fast_clock_gettime(which_clock, tp);
}

static inline int
fast_sys_clock_gettime(const clockid_t which_clock, struct timespec __user *tp)
{
	return native_fast_sys_clock_gettime(which_clock, tp);
}

static inline int
do_fast_gettimeofday(struct timeval *tv)
{
	return native_do_fast_gettimeofday(tv);
}
static inline int
fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return native_fast_sys_siggetmask(oset, sigsetsize);
}
#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

/*
 * These have to be macros since there is no way to return two
 * values (seconds and nanoseconds) to an __interrupt function
 * without assembler magic.
 */

enum {
	FAST_SYS_OK,
	FAST_SYS_ERROR
};

#define fast_get_time(secs, nsecs, monotonic)				\
({									\
	struct clocksource *__clock;					\
	struct timekeeper *__tk;					\
	u64 __cycles = 0, __cycle_last = 0, __mask = 0;			\
	u32 __mult, __shift;						\
	unsigned __seq;							\
	int __ret = FAST_SYS_ERROR;					\
	long wall2mon_sec, wall2mon_nsec;				\
									\
	do {								\
		__seq = raw_read_seqcount_begin(&timekeeper_seq);	\
									\
		__tk = fsys_data.tk;					\
		__clock = fsys_data.clock;				\
		__mult = fsys_data.mult;				\
		__shift = fsys_data.shift;				\
									\
		secs = __tk->xtime_sec;			\
		nsecs = __tk->tkr_mono.xtime_nsec;			\
									\
		if (monotonic) {					\
			wall2mon_sec = __tk->wall_to_monotonic.tv_sec;	\
			wall2mon_nsec = __tk->wall_to_monotonic.tv_nsec;\
		}							\
									\
		if (likely(__clock == &clocksource_sclkr)) {		\
			__cycle_last = __tk->tkr_mono.cycle_last;	\
			__mask = __clock->mask;				\
			__cycles = fast_syscall_read_sclkr();		\
			if (__cycles)					\
				__ret = FAST_SYS_OK;			\
		} else if (likely(__clock == &clocksource_clkr)) {	\
			__cycle_last = __tk->tkr_mono.cycle_last;	\
			__mask = __clock->mask;				\
			__cycles = fast_syscall_read_clkr();		\
			__ret = FAST_SYS_OK;				\
		}							\
	} while (unlikely(read_seqcount_retry(&timekeeper_seq, __seq))); \
									\
	if (__ret == FAST_SYS_OK) {					\
		nsecs = (((__cycles - __cycle_last) & __mask)		\
			* __mult + nsecs) >> __shift;			\
									\
		if (monotonic) {					\
			secs += wall2mon_sec;				\
			nsecs += wall2mon_nsec;				\
		}							\
									\
		while (nsecs >= NSEC_PER_SEC) {				\
			++secs;						\
			nsecs -= NSEC_PER_SEC;				\
		}							\
	}								\
									\
	__ret;								\
})

#define fast_get_time_coarse(secs, nsecs, monotonic)			\
({									\
	struct timekeeper *__tk;					\
	unsigned __seq;							\
									\
	do {								\
		__seq = raw_read_seqcount_begin(&timekeeper_seq);	\
									\
		secs = fsys_data.wall_time_coarse.tv_sec;		\
		nsecs = fsys_data.wall_time_coarse.tv_nsec;		\
									\
		if (monotonic) {					\
			__tk = fsys_data.tk;				\
			secs += __tk->wall_to_monotonic.tv_sec;		\
			nsecs += __tk->wall_to_monotonic.tv_nsec;	\
		}							\
	} while (unlikely(read_seqcount_retry(&timekeeper_seq, __seq))); \
									\
	while (nsecs >= NSEC_PER_SEC) {					\
		++secs;							\
		nsecs -= NSEC_PER_SEC;					\
	}								\
									\
	FAST_SYS_OK;							\
})

static inline int
DO_FAST_CLOCK_GETTIME(const clockid_t which_clock, struct timespec *tp)
{
	u64 secs = 0, nsecs = 0;
	int ret;

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
		ret = fast_get_time(secs, nsecs,
				which_clock == CLOCK_MONOTONIC);
		break;
	case CLOCK_REALTIME_COARSE:
	case CLOCK_MONOTONIC_COARSE:
		ret = fast_get_time_coarse(secs, nsecs,
				which_clock == CLOCK_MONOTONIC_COARSE);
		break;
	default:
		ret = FAST_SYS_ERROR;
		break;
	}

	if (likely(!ret)) {
		tp->tv_sec = secs;
		tp->tv_nsec = nsecs;
	}

	return ret;
}

/* trap table entry is called as function (it is closer to hardware start) */
typedef long (*ttable_entry_args3)(int sys_num, u64 arg1, u64 arg2);
#define	ttable_entry3_args3(sys_num, arg1, arg2)	\
		((ttable_entry_args3)(get_ttable_entry3))(sys_num, arg1, arg2)

/* trap table entry started by direct branch (it is closer to fast system */
/* call wirthout switch and use user local data stack */
#define	goto_ttable_entry_args3(entry_label, sys_num, arg1, arg2)	\
		E2K_GOTO_ARG3(entry_label, sys_num, arg1, arg2)
#define	goto_ttable_entry3_args3(sys_num, arg1, arg2)	\
		goto_ttable_entry_args3(ttable_entry3, sys_num, arg1, arg2)

#define	ttable_entry_clock_gettime(which, time)		\
/* ibranch */	goto_ttable_entry3_args3(__NR_clock_gettime, which, time)
/* call		ttable_entry3_args3(__NR_clock_gettime, which, time) */
#define	ttable_entry_gettimeofday(tv, tz)		\
/* ibranch */	goto_ttable_entry3_args3(__NR_gettimeofday, tv, tz)
/*		ttable_entry3_args3(__NR_gettimeofday, tv, tz) */

static inline int
FAST_SYS_CLOCK_GETTIME(const clockid_t which_clock, struct timespec __user *tp)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	int r;

	prefetchw(&fsys_data);

	tp = (typeof(tp)) ((u64) tp & E2K_VA_MASK);
	if (unlikely((u64) tp + sizeof(struct timespec) > ti->addr_limit.seg))
		return -EFAULT;

	r = do_fast_clock_gettime(which_clock, tp);
	if (unlikely(r))
/* ibranch */	ttable_entry_clock_gettime((u64) which_clock, (u64) tp);
/* call		r = ttable_entry_clock_gettime((u64) which_clock, (u64) tp); */
	return r;
}

static inline int
DO_FAST_GETTIMEOFDAY(struct timeval *tv)
{
	u64 secs = 0, nsecs = 0;
	int ret;

	ret = fast_get_time(secs, nsecs, false);
	if (likely(!ret)) {
		tv->tv_sec = secs;
		tv->tv_usec = nsecs / 1000;
	}

	return ret;
}

static inline int
FAST_SYS_SIGGETMASK(u64 __user *oset, size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);
	u64 set;

	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	oset = (typeof(oset)) ((u64) oset & E2K_VA_MASK);
	if (unlikely((u64) oset + sizeof(sigset_t) > ti->addr_limit.seg))
		return -EFAULT;

	*oset = set;

	return 0;
}

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
int fast_sys_set_return(u64 ip, int flags);

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
int compat_fast_sys_set_return(u32 ip, int flags);

int protected_fast_sys_clock_gettime(u32 tags, clockid_t which_clock,
		u64 arg3, u64 arg4, u64 arg5);
int protected_fast_sys_gettimeofday(u32 tags,
		u64 arg2, u64 arg3, u64 arg4, u64 arg5);
int protected_fast_sys_getcpu(u32 tags, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
int protected_fast_sys_siggetmask(u32 tags, u64 arg2, u64 arg3, size_t sigsetsize);
int protected_fast_sys_getcontext(u32 tags, u64 arg2, u64 arg3, size_t sigsetsize);
#endif /* _ASM_E2K_FAST_SYSCALLS_H */

