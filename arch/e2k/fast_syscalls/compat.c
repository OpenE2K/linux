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

/* trap table entry started by direct branch (it is closer to fast system */
/* call wirthout switch and use user local data stack) */
#define	goto_ttable_entry1_args3(sys_num, arg1, arg2)	\
		goto_ttable_entry_args3(ttable_entry1, sys_num, arg1, arg2)
#define	goto_ttable_entry1_args4(sys_num, arg1, arg2, arg3)	\
		goto_ttable_entry_args4(ttable_entry1, sys_num, arg1, arg2, arg3)

#define	ttable_entry1_clock_gettime(which, time)		\
		goto_ttable_entry1_args3(__NR_clock_gettime, which, time)
#define	ttable_entry1_gettimeofday(tv, tz)		\
		goto_ttable_entry1_args3(__NR_gettimeofday, tv, tz)
#define	ttable_entry1_sigprocmask(how, nset, oset)		\
		goto_ttable_entry1_args4(__NR_sigprocmask, how, nset, oset)

notrace __section(".entry.text")
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct compat_timespec __user *__restrict tp)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct timespec kts;
	int ret;

	prefetch_nospec(&fsys_data);

#ifdef	CONFIG_KVM_HOST_MODE
	if (unlikely(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)))
		ttable_entry1_clock_gettime((u64) which_clock, (u64) tp);
#endif

	if (unlikely((u64) tp + sizeof(struct compat_timespec) >
			ti->addr_limit.seg))
		return -EFAULT;

	ret = do_fast_clock_gettime(which_clock, &kts);
	if (likely(!ret)) {
		tp->tv_sec = kts.tv_sec;
		tp->tv_nsec = kts.tv_nsec;
	} else {
		ttable_entry1_clock_gettime((u64) which_clock, (u64) tp);
	}

	return ret;
}

notrace __section(".entry.text")
int compat_fast_sys_gettimeofday(struct compat_timeval __user *__restrict tv,
		struct timezone __user *__restrict tz)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct timeval ktv;
	int ret;

	prefetch_nospec(&fsys_data);

#ifdef	CONFIG_KVM_HOST_MODE
	if (unlikely(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE)))
		ttable_entry1_gettimeofday((u64) tv, (u64) tz);
#endif

	if (unlikely((u64) tv + sizeof(struct compat_timeval) >
					ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone) >
					ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(&ktv);
		if (unlikely(ret))
			ttable_entry1_gettimeofday((u64) tv, (u64) tz);
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
notrace __interrupt __section(".entry.text")
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);
	int ret = 0;
#ifdef	CONFIG_KVM_HOST_MODE
	bool guest = test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE);
#endif
	union {
		u32 word[2];
		u64 whole;
	} set;

	set.whole = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

#ifdef	CONFIG_KVM_HOST_MODE
	if (unlikely(guest))
		ttable_entry1_sigprocmask((u64) 0, (u64) NULL, (u64) oset);
#endif

	if (unlikely((u64) oset + sizeof(sigset_t) > ti->addr_limit.seg))
		return -EFAULT;

	oset[0] = set.word[0];
	oset[1] = set.word[1];

	return ret;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(".entry.text")
int compat_fast_sys_getcontext(struct ucontext_32 __user *ucp,
		size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);
	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	union {
		u32 word[2];
		u64 whole;
	} set;
	u64 key;

#ifdef	CONFIG_KVM_HOST_MODE
	/* TODO getcontext does not have a slow counterpart, not implemented for paravirt guest */
	KVM_BUG_ON(test_ti_status_flag(ti, TS_HOST_AT_VCPU_MODE));
#endif

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set.whole = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	if (unlikely((u64) ucp + sizeof(struct ucontext_32) >
					ti->addr_limit.seg
			|| (u64) ucp >= ti->addr_limit.seg))
		return -EFAULT;

	key = context_ti_key_fast_syscall(ti);

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	((u32 *) &ucp->uc_sigmask)[0] = set.word[0];
	((u32 *) &ucp->uc_sigmask)[1] = set.word[1];
	ucp->uc_mcontext.sbr = key;
	ucp->uc_mcontext.pcsp_lo = pcsp_lo;
	ucp->uc_mcontext.pcsp_hi = pcsp_hi;
	ucp->uc_extra.fpcr = fpcr;
	ucp->uc_extra.fpsr = fpsr;
	ucp->uc_extra.pfpfr = pfpfr;

	return 0;
}

