/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/clocksource.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/timekeeper_internal.h>

#include <asm/fast_syscalls.h>
#include <asm/sclkr.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#define	ttable_entry_clock_gettime(which, time)	\
/* ibranch */	goto_ttable_entry3_args3(__NR_clock_gettime, which, time)
#define	ttable_entry_gettimeofday(tv, tz)		\
/* ibranch */	goto_ttable_entry3_args3(__NR_gettimeofday, tv, tz)

notrace __interrupt __section(".entry.text")
int fast_sys_clock_gettime(const clockid_t which_clock, struct timespec64 __user *tp)
{
	time64_t kts64_tv_sec;
	long kts64_tv_nsec;
	enum fast_gettime_return fast_ret;
	int ret;

	prefetch_nospec(&fsys_data);

	tp = (typeof(tp)) ((unsigned long) tp & E2K_VA_MASK);
	if (unlikely((unsigned long) tp + sizeof(*tp) > user_addr_max()))
		return -EFAULT;

	fast_ret = __fast_get_time(which_clock, &kts64_tv_sec, &kts64_tv_nsec);
	if (unlikely(fast_ret))
		return ttable_entry_clock_gettime(which_clock, (unsigned long) tp);

	/* Can use `|=` because put_user_switched_pt can return only -EFAULT error */
	ret = put_user_switched_pt(kts64_tv_sec, &tp->tv_sec);
	return ret | put_user_switched_pt(kts64_tv_nsec, &tp->tv_nsec);
}

notrace __interrupt __section(".entry.text")
int fast_sys_gettimeofday(struct __kernel_old_timeval __user *__restrict tv,
			  struct timezone __user *__restrict tz)
{
	prefetch_nospec(&fsys_data);

	tv = (typeof(tv)) ((unsigned long) tv & E2K_VA_MASK);
	tz = (typeof(tz)) ((unsigned long) tz & E2K_VA_MASK);
	if (unlikely((unsigned long) tv + sizeof(*tv) > user_addr_max() ||
		     (unsigned long) tz + sizeof(*tz) > user_addr_max()))
		return -EFAULT;

	if (likely(tv)) {
		enum fast_gettime_return fast_ret = fast_gettimeofday_user(tv);
		if (unlikely(fast_ret))
			return ttable_entry_gettimeofday((unsigned long) tv, (unsigned long) tz);
	}

	int ret = 0;
	if (tz) {
		/* Can use `|=` because put_user_switched_pt can return only -EFAULT error */
		ret = put_user_switched_pt(sys_tz.tz_minuteswest, &tz->tz_minuteswest);
		ret |= put_user_switched_pt(sys_tz.tz_dsttime, &tz->tz_dsttime);
	}

	return 0;
}
