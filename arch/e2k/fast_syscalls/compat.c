#include <linux/compat.h>
#include <linux/time.h>

#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <asm/uaccess.h>
#include <asm/ucontext.h>


extern long ttable_entry1(int sys_num, u64 arg1, u64 arg2);

notrace __section(.ttable_entry5_C)
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct compat_timespec __user *tp)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	struct timespec kts;
	int ret;

	prefetchw(&fsys_data);

	if (unlikely((u64) tp + sizeof(struct compat_timespec) >
			ti->addr_limit.seg))
		return -EFAULT;

	ret = do_fast_clock_gettime(which_clock, &kts);
	if (likely(!ret)) {
		tp->tv_sec = kts.tv_sec;
		tp->tv_nsec = kts.tv_nsec;
	} else {
		ret = ttable_entry1(__NR_clock_gettime,
				(u64) which_clock, (u64) tp);
	}

	return ret;
}


notrace __section(.entry_handlers)
int compat_fast_sys_gettimeofday(struct compat_timeval __user *tv,
		struct timezone __user *tz)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	struct timeval ktv;
	int ret;

	prefetchw(&fsys_data);

	if (unlikely((u64) tv + sizeof(struct compat_timeval) >
					ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone) >
					ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(&ktv);
		if (unlikely(ret))
			return ttable_entry1(__NR_gettimeofday,
					     (u64) tv, (u64) tz);
	} else {
		ret = 0;
	}

	if (tv) {
		tv->tv_sec = ktv.tv_sec;
		tv->tv_usec = ktv.tv_usec;
	}
	if (tz) {
		tz->tz_minuteswest = sys_tz.tz_minuteswest;
		tz->tz_dsttime = sys_tz.tz_dsttime;
	}

	return ret;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(.ttable_entry5_C)
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	struct task_struct *task = ti->task;
	int ret = 0;
	union {
		u32 word[2];
		u64 whole;
	} set;

	set.whole = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	if (unlikely((u64) oset + sizeof(sigset_t) > ti->addr_limit.seg))
		return -EFAULT;

	oset[0] = set.word[0];
	oset[1] = set.word[1];

	return ret;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(.entry_handlers)
int compat_fast_sys_getcontext(struct ucontext_32 __user *ucp,
		size_t sigsetsize)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	struct task_struct *task = ti->task;
	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	union {
		u32 word[2];
		u64 whole;
	} set;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set.whole = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	if (unlikely((u64) ucp + sizeof(struct ucontext_32) >
					ti->addr_limit.seg
			|| (u64) ucp >= ti->addr_limit.seg))
		return -EFAULT;

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	((u32 *) &ucp->uc_sigmask)[0] = set.word[0];
	((u32 *) &ucp->uc_sigmask)[1] = set.word[1];
	ucp->uc_mcontext.sbr = context_ti_key(ti);
	ucp->uc_mcontext.pcsp_lo = pcsp_lo;
	ucp->uc_mcontext.pcsp_hi = pcsp_hi;
	ucp->uc_extra.fpcr = fpcr;
	ucp->uc_extra.fpsr = fpsr;
	ucp->uc_extra.pfpfr = pfpfr;

	return 0;
}

