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
#include <asm/gregs.h>
#include <asm/hw_stacks.h>
#include <asm/ucontext.h>

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

/* trap table entry started by direct branch (it is closer to fast system */
/* call wirthout switch and use user local data stack) */

#define	ttable_entry1_clock_gettime(which, time, ret)		\
		goto_ttable_entry1_args3(__NR_clock_gettime, which, time, ret)
#define	ttable_entry1_gettimeofday(tv, tz, ret)		\
		goto_ttable_entry1_args3(__NR_gettimeofday, tv, tz, ret)
#define	ttable_entry1_sigprocmask(how, nset, oset, ret)		\
		goto_ttable_entry1_args4(__NR_sigprocmask, how, \
					nset, oset, ret)

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
int native_do_fast_sys_set_return(u64 ip, int flags);
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
do_fast_gettimeofday(struct timeval *tv)
{
	return native_do_fast_gettimeofday(tv);
}

static inline int
do_fast_sys_set_return(u64 ip, int flags)
{
	return native_do_fast_sys_set_return(ip, flags);
}

#ifdef CONFIG_KVM_HOST_MODE
extern long ret_from_fast_sys_call(void);

static inline long kvm_return_from_fast_syscall(thread_info_t *ti, long arg1)
{
	/* Restore vcpu state reg old value (guest user) */
	HOST_VCPU_STATE_REG_RESTORE(ti);

	/* TODO: Cleanup guest kernel's pgds in shadow page table */

	/* Get current parameters of top chain stack frame */
	e2k_cr0_lo_t cr0_lo = READ_CR0_LO_REG();
	e2k_cr0_hi_t cr0_hi = READ_CR0_HI_REG();
	e2k_cr1_lo_t cr1_lo = READ_CR1_LO_REG();
	e2k_cr1_hi_t cr1_hi = READ_CR1_HI_REG();

	/*
	 * Correct ip in current chain stack frame to return to guest user
	 * through special trap function ret_from_fast_syscall_trampoline
	 */
	AS(cr0_lo).pf = -1ULL;
	AS(cr0_hi).ip = ((u64)ret_from_fast_sys_call) >> 3;
	AS(cr1_lo).psr = AW(E2K_KERNEL_PSR_DISABLED);
	AS(cr1_lo).cui = KERNEL_CODES_INDEX;

	WRITE_CR0_LO_REG(cr0_lo);
	WRITE_CR0_HI_REG(cr0_hi);
	WRITE_CR1_LO_REG(cr1_lo);
	WRITE_CR1_HI_REG(cr1_hi);

	return arg1;
}

static inline long kvm_set_return_user_ip(thread_info_t *gti, u64 ip, int flags)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_mem_crs_t *frame, *base;
	u64 prev_ip;

	E2K_FLUSHC;

	if (unlikely(flags))
		return -EINVAL;

	if (unlikely(ip >= USER_DS.seg))
		return -EFAULT;

	pcsp_hi = READ_PCSP_HI_REG(); /* We don't use %pcsp_hi.size */
	pcsp_lo = READ_PCSP_LO_REG();

	base = (e2k_mem_crs_t *) GET_PCS_BASE(&gti->u_hw_stack);
	frame = (e2k_mem_crs_t *) (AS(pcsp_lo).base + AS(pcsp_hi).ind);

	do {
		--frame;

		cr0_hi = frame->cr0_hi;
		prev_ip = AS(cr0_hi).ip << 3;
	} while (unlikely(prev_ip >= GUEST_TASK_SIZE && frame > base));

	/* No user frames above? */
	if (unlikely(prev_ip >= GUEST_TASK_SIZE))
		return -EPERM;

	/* Modify stack */
	AS(cr0_hi).ip = ip >> 3;
	frame->cr0_hi = cr0_hi;
	return 0;
}
#endif /* CONFIG_KVM_HOST_MODE */

/* trap table entry started by direct branch (it is closer to fast system */
/* call wirthout switch and use user local data stack */
#define	goto_ttable_entry1_args3(sys_num, arg1, arg2, ret)	\
	E2K_GOTO_ARG7(native_ttable_entry1, sys_num, arg1, arg2, 0, 0, 0, 0)
#define	goto_ttable_entry1_args4(sys_num, arg1, arg2, arg3, ret)	\
	E2K_GOTO_ARG7(native_ttable_entry1, sys_num, arg1, arg2, arg3, 0, 0, 0)

#define	goto_ttable_entry3_args3(sys_num, arg1, arg2, ret)	\
	E2K_GOTO_ARG7(native_ttable_entry3, sys_num, arg1, arg2, 0, 0, 0, 0)
#define	goto_ttable_entry3_args4(sys_num, arg1, arg2, arg3, ret)	\
	E2K_GOTO_ARG7(native_ttable_entry3, sys_num, arg1, arg2, arg3, 0, 0, 0)

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
typedef long (*ttable_entry_args4)(int sys_num, u64 arg1, u64 arg2, u64 arg3);
#define	ttable_entry3_args3(sys_num, arg1, arg2)	\
		((ttable_entry_args3)(get_ttable_entry3))(sys_num, arg1, arg2)
#define	ttable_entry3_args4(sys_num, arg1, arg2)	\
		((ttable_entry_args4)(get_ttable_entry3))(sys_num, arg1, arg2, arg3)

#define	ttable_entry_clock_gettime(which, time, ret)	\
/* ibranch */	goto_ttable_entry3_args3(__NR_clock_gettime, which, time, ret)
/* call		ttable_entry3_args3(__NR_clock_gettime, which, time) */
#define	ttable_entry_gettimeofday(tv, tz, ret)		\
/* ibranch */	goto_ttable_entry3_args3(__NR_gettimeofday, tv, tz, ret)
/*		ttable_entry3_args3(__NR_gettimeofday, tv, tz) */
#define	ttable_entry_sigprocmask(how, nset, oset, ret)		\
/* ibranch */	goto_ttable_entry3_args4(__NR_sigprocmask, how, \
					nset, oset, ret)
/*		ttable_entry3_args4(__NR_sigprocmask, how, nset, oset) */
#define	ttable_entry_getcpu(cpup, nodep, unused, ret)		\
/* ibranch */	goto_ttable_entry3_args4(__NR_getcpu, cpup, nodep, unused, ret)
/*		ttable_entry3_args4(__NR_getcpu, cpup, nodep, unused) */

static inline int
FAST_SYS_CLOCK_GETTIME(const clockid_t which_clock, struct timespec __user *tp)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	int r;

	prefetch_nospec(&fsys_data);

	tp = (typeof(tp)) ((u64) tp & E2K_VA_MASK);
	if (unlikely((u64) tp + sizeof(struct timespec) > ti->addr_limit.seg))
		return -EFAULT;

	r = do_fast_clock_gettime(which_clock, tp);
	if (unlikely(r))
		ttable_entry_clock_gettime(which_clock, tp, r);

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
int fast_sys_getcontext(struct ucontext __user *ucp, size_t sigsetsize);

struct compat_timespec;
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct compat_timespec __user *tp);
struct compat_timeval;
int compat_fast_sys_gettimeofday(struct compat_timeval __user *tv,
		struct timezone __user *tz);
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize);
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

/* Inlined handlers for fast syscalls */

notrace __interrupt __section(.entry_handlers)
static inline int _fast_sys_gettimeofday(struct timeval __user *__restrict tv,
					struct timezone __user *__restrict tz)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	int ret;

	prefetch_nospec(&fsys_data);

	tv = (typeof(tv)) ((u64) tv & E2K_VA_MASK);
	tz = (typeof(tz)) ((u64) tz & E2K_VA_MASK);
	if (unlikely((u64) tv + sizeof(struct timeval) > ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone)
					> ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(tv);
		if (unlikely(ret))
			ttable_entry_gettimeofday((u64) tv, (u64) tz, ret);
	} else {
		ret = 0;
	}

	if (tz) {
		tz->tz_minuteswest = sys_tz.tz_minuteswest;
		tz->tz_dsttime = sys_tz.tz_dsttime;
	}

	return ret;
}

notrace __interrupt __section(.entry_handlers)
static inline int _fast_sys_clock_gettime(const clockid_t which_clock,
					struct timespec __user *tp)
{
	return FAST_SYS_CLOCK_GETTIME(which_clock, tp);
}

notrace __interrupt __section(.entry_handlers)
static inline int _fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize)
{
	return FAST_SYS_SIGGETMASK(oset, sigsetsize);
}

notrace __interrupt __section(.entry_handlers)
static inline int _fast_sys_getcontext(struct ucontext __user *ucp,
					size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);

	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	u64 set, key;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	ucp = (typeof(ucp)) ((u64) ucp & E2K_VA_MASK);
	if (unlikely((u64) ucp + sizeof(struct ucontext) > ti->addr_limit.seg))
		return -EFAULT;

	key = context_ti_key_fast_syscall(ti);

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	*((u64 *) &ucp->uc_sigmask) = set;
	ucp->uc_mcontext.sbr = key;
	ucp->uc_mcontext.pcsp_lo = pcsp_lo;
	ucp->uc_mcontext.pcsp_hi = pcsp_hi;
	ucp->uc_extra.fpcr = fpcr;
	ucp->uc_extra.fpsr = fpsr;
	ucp->uc_extra.pfpfr = pfpfr;

	return 0;
}

notrace __section(.entry_handlers)
static inline int fast_sys_set_return(u64 ip, int flags)
{
	return do_fast_sys_set_return(ip, flags);
}


/* Inlined handlers for compat fast syscalls */

notrace __section(".entry.text")
static inline int _compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct compat_timespec __user *__restrict tp)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct timespec kts;
	int ret;

	prefetch_nospec(&fsys_data);

	if (unlikely((u64) tp + sizeof(struct compat_timespec) >
			ti->addr_limit.seg))
		return -EFAULT;

	ret = do_fast_clock_gettime(which_clock, &kts);
	if (likely(!ret)) {
		tp->tv_sec = kts.tv_sec;
		tp->tv_nsec = kts.tv_nsec;
	} else {
		ttable_entry1_clock_gettime((u64) which_clock, (u64) tp, ret);
	}

	return ret;
}

notrace __section(".entry.text")
static inline int _compat_fast_sys_gettimeofday(
			struct compat_timeval __user *__restrict tv,
			struct timezone __user *__restrict tz)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct timeval ktv;
	int ret;

	prefetch_nospec(&fsys_data);

	if (unlikely((u64) tv + sizeof(struct compat_timeval) >
					ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone) >
					ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(&ktv);
		if (unlikely(ret))
			ttable_entry1_gettimeofday((u64) tv, (u64) tz, ret);
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
notrace __section(".entry.text")
static inline int _compat_fast_sys_siggetmask(u32 __user *oset,
					size_t sigsetsize)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);
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
notrace __section(".entry.text")
static inline int _compat_fast_sys_getcontext(struct ucontext_32 __user *ucp,
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

#endif /* _ASM_E2K_FAST_SYSCALLS_H */
