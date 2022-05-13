#include <linux/clocksource.h>
#include <linux/seqlock.h>
#include <linux/time.h>
#include <linux/timekeeper_internal.h>

#include <asm/fast_syscalls.h>
#include <asm/sclkr.h>
#include <linux/uaccess.h>
#include <asm/unistd.h>

noinline notrace __interrupt
int native_do_fast_clock_gettime(const clockid_t which_clock,
		struct timespec *tp)
{
	return DO_FAST_CLOCK_GETTIME(which_clock, tp);
}

notrace __interrupt __section(.entry_handlers)
int fast_sys_clock_gettime(const clockid_t which_clock,
		struct timespec __user *tp)
{
	return _fast_sys_clock_gettime(which_clock, tp);
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
	return _fast_sys_gettimeofday(tv, tz);
}
