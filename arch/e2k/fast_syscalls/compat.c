/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/compat.h>
#include <linux/time.h>

#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <linux/uaccess.h>
#include <asm/ucontext.h>

#define	ttable_entry1_args3(sys_num, arg1, arg2)	\
		((ttable_entry_args3)(ttable_entry1))(sys_num, arg1, arg2)
#define	ttable_entry1_args4(sys_num, arg1, arg2, arg3)	\
		((ttable_entry_args4)(ttable_entry1))(sys_num, arg1, arg2, arg3)
 
notrace __interrupt __section(".entry.text")
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct old_timespec32 __user *__restrict tp)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	time64_t kts_tv_sec;
	long kts_tv_nsec;
	enum fast_gettime_return fast_ret;
	int ret;

	prefetch_nospec(&fsys_data);

	if (unlikely((u64) tp + sizeof(*tp) > ti->addr_limit.seg))
		return -EFAULT;

	fast_ret = __fast_get_time(which_clock, &kts_tv_sec, &kts_tv_nsec);
	if (unlikely(fast_ret))
		return ttable_entry1_clock_gettime((u64) which_clock, (u64) tp);

	ret = __put_user_switched_pt(kts_tv_sec, &tp->tv_sec);
	return unlikely(ret) ? ret : __put_user_switched_pt(kts_tv_nsec, &tp->tv_nsec);
}


notrace __interrupt __section(".entry.text")
int compat_fast_sys_gettimeofday(struct old_timeval32 __user *__restrict tv,
				 struct timezone __user *__restrict tz)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	time64_t ktv_tv_sec;
	long ktv_tv_nsec;
	int ret = 0;

	prefetch_nospec(&fsys_data);

	if (unlikely((u64) tv + sizeof(*tv) > ti->addr_limit.seg ||
		     (u64) tz + sizeof(*tz) > ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		enum fast_gettime_return fast_ret =
				fast_get_time_precise(&ktv_tv_sec, &ktv_tv_nsec, false);
		if (unlikely(fast_ret))
			return ttable_entry1_gettimeofday((u64) tv, (u64) tz);
	}

	if (tv) {
		ret = __put_user_switched_pt(ktv_tv_sec, &tv->tv_sec);
		ret = unlikely(ret) ? ret : __put_user_switched_pt(ktv_tv_nsec / 1000,
								  &tv->tv_usec);
	}
	if (tz) {
		ret = unlikely(ret) ? ret : __put_user_switched_pt(sys_tz.tz_minuteswest,
							      &tz->tz_minuteswest);
		ret = unlikely(ret) ? ret : __put_user_switched_pt(sys_tz.tz_dsttime,
							      &tz->tz_dsttime);
	}

	return ret;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(".entry.text")
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	union {
		u32 word[2];
		u64 whole;
	} set;

	set.whole = thread_info_task(ti)->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	if (unlikely((u64) oset + sizeof(sigset_t) > ti->addr_limit.seg))
		return -EFAULT;

	int ret = __put_user_switched_pt(set.word[0], &oset[0]);
	return unlikely(ret) ? ret : __put_user_switched_pt(set.word[1], &oset[1]);
}
