#include <linux/clocksource.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/timekeeper_internal.h>

#include <asm/fast_syscalls.h>
#include <asm/sclkr.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

#include <asm-l/clkr.h>

noinline notrace __interrupt
int native_do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp)
{
	return DO_FAST_CLOCK_GETTIME(which_clock, tp);
}

notrace __interrupt __section(.ttable_entry6_C)
int native_fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp)
{
	return FAST_SYS_CLOCK_GETTIME(which_clock, tp);
}

notrace __interrupt __section(".entry.text")
int native_do_fast_gettimeofday(struct timeval *tv)
{
	return DO_FAST_GETTIMEOFDAY(tv);
}

notrace __interrupt __section(".entry.text")
int fast_sys_gettimeofday(struct timeval __user *__restrict tv,
		struct timezone __user *__restrict tz)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	int ret;

	prefetch_nospec(&fsys_data);

#ifdef	CONFIG_KVM_HOST_MODE
	if (unlikely(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)))
		ttable_entry_gettimeofday((u64) tv, (u64) tz);
#endif

	tv = (typeof(tv)) ((u64) tv & E2K_VA_MASK);
	tz = (typeof(tz)) ((u64) tz & E2K_VA_MASK);
	if (unlikely((u64) tv + sizeof(struct timeval) > ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone)
					> ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(tv);
		if (unlikely(ret))
			ttable_entry_gettimeofday((u64) tv, (u64) tz);
	} else {
		ret = 0;
	}

	if (tz) {
		tz->tz_minuteswest = sys_tz.tz_minuteswest;
		tz->tz_dsttime = sys_tz.tz_dsttime;
	}

	return ret;
}

