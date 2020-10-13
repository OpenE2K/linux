#include <linux/clocksource.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/timekeeper_internal.h>

#include <asm/fast_syscalls.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>

#include <asm-l/clkr.h>


enum {
	FAST_SYS_OK,
	FAST_SYS_ERROR
};

extern seqcount_t timekeeper_seq;

/*
 * These have to be macros since there is no way to return two
 * values (seconds and nanoseconds) to an __interrupt function
 * without assembler magic.
 */

#define fast_get_time(secs, nsecs, monotonic)				\
({									\
	struct clocksource *__clock;					\
	struct timekeeper *__tk;					\
	cycle_t __cycles = 0, __cycle_last = 0, __mask = 0;		\
	u32 __mult, __shift;						\
	unsigned __seq;							\
	int __ret = FAST_SYS_ERROR;					\
									\
	do {								\
		__seq = read_seqcount_begin(&timekeeper_seq);		\
									\
		__tk = fsys_data.tk;					\
		__clock = fsys_data.clock;				\
		__mult = fsys_data.mult;				\
		__shift = fsys_data.shift;				\
									\
		secs = __tk->xtime_sec;					\
		nsecs = __tk->xtime_nsec;				\
									\
		if (monotonic) {					\
			secs += __tk->wall_to_monotonic.tv_sec;		\
			nsecs += __tk->wall_to_monotonic.tv_nsec;	\
		}							\
									\
		if (likely(__clock == &clocksource_clkr)) {		\
			__cycle_last = __clock->cycle_last;		\
			__mask = __clock->mask;				\
			__cycles = fast_syscall_read_clkr();		\
			__ret = FAST_SYS_OK;				\
		}							\
	} while (unlikely(read_seqcount_retry(&timekeeper_seq, __seq))); \
									\
	nsecs = (((__cycles - __cycle_last) & __mask) * __mult + nsecs)	\
			>> __shift; \
									\
	while (nsecs >= NSEC_PER_SEC) {					\
		++secs;							\
		nsecs -= NSEC_PER_SEC;					\
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
		__seq = read_seqcount_begin(&timekeeper_seq);		\
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
	FAST_SYS_OK;							\
})


extern long ttable_entry3(int sys_num, u64 arg1, u64 arg2);

noinline notrace __interrupt __section(.ttable_entry7_C)
int do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp)
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


notrace __interrupt __section(.ttable_entry6_C)
int fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	int ret;

	prefetchw(&fsys_data);

	tp = (typeof(tp)) ((u64) tp & E2K_VA_MASK);
	if (unlikely((u64) tp + sizeof(struct timespec) > ti->addr_limit.seg))
		return -EFAULT;

	ret = do_fast_clock_gettime(which_clock, tp);
	if (unlikely(ret))
		ret = ttable_entry3(__NR_clock_gettime,
				(u64) which_clock, (u64) tp);

	return ret;
}


noinline notrace __interrupt __section(.ttable_entry5_C)
int do_fast_gettimeofday(struct timeval *tv)
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

notrace __interrupt __section(.ttable_entry6_C)
int fast_sys_gettimeofday(struct timeval __user *tv,
		struct timezone __user *tz)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	int ret;

	prefetchw(&fsys_data);

	tv = (typeof(tv)) ((u64) tv & E2K_VA_MASK);
	tz = (typeof(tz)) ((u64) tz & E2K_VA_MASK);
	if (unlikely((u64) tv + sizeof(struct timeval) > ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone)
					> ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(tv);
		if (unlikely(ret))
			return ttable_entry3(__NR_gettimeofday,
					     (u64) tv, (u64) tz);
	} else {
		ret = 0;
	}

	if (tz) {
		tz->tz_minuteswest = sys_tz.tz_minuteswest;
		tz->tz_dsttime = sys_tz.tz_dsttime;
	}

	return ret;
}

