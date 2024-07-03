/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_FAST_SYSCALLS_H
#define _ASM_E2K_FAST_SYSCALLS_H

#include <linux/time.h>
#include <linux/timekeeper_internal.h>
#include <linux/uaccess.h>

#include <asm/sections.h>
#include <asm/signal.h>
#include <asm/sclkr.h>
#include <asm/trap_table.h>
#include <asm/gregs.h>
#include <asm/hw_stacks.h>
#include <asm/ucontext.h>

struct fast_syscalls_data {
	u64 seq;
	u32 mult;
	u32 shift;
	struct clocksource *clock;
	struct timespec64 wall_time_coarse;
	u64	cycle_last;
	u64	sec;
	u64	nsec;
	long	w2m_sec;
	long	w2m_nsec;
};


static __always_inline u64 fastsys_read_begin(
		const struct fast_syscalls_data *data)
{
	u64 seq = 0;

	while ((seq = smp_load_acquire(&data->seq)) & 1)
		cpu_relax();

	return seq;
}

static __always_inline bool fastsys_read_retry(
		const struct fast_syscalls_data *data, u64 start)
{
	u64 seq;

	smp_rmb();
	seq = READ_ONCE(data->seq);
	return seq != start;
}

static __always_inline void fastsys_write_begin(struct fast_syscalls_data *data)
{
	WRITE_ONCE(data->seq, data->seq + 1);
	smp_wmb();
}

static __always_inline void fastsys_write_end(struct fast_syscalls_data *data)
{
	smp_store_release(&data->seq, data->seq + 1);
}

extern struct fast_syscalls_data fsys_data ____cacheline_aligned;

typedef void (*fast_system_call_func)(u64 arg1, u64 arg2);

extern const fast_system_call_func fast_sys_calls_table[NR_fast_syscalls];
extern const fast_system_call_func fast_sys_calls_table_32[NR_fast_syscalls];

int fast_sys_ni_syscall(void);

/* trap table entry started by direct branch (it is closer to fast system */
/* call wirthout switch and use user local data stack) */

#define	ttable_entry1_clock_gettime(which, time) \
		goto_ttable_entry1_args3(__NR_clock_gettime, which, time)
#define	ttable_entry1_gettimeofday(tv, tz) \
		goto_ttable_entry1_args3(__NR_gettimeofday, tv, tz)
#define	ttable_entry1_sigprocmask(how, nset, oset) \
		goto_ttable_entry1_args4(__NR_sigprocmask, how, nset, oset)

#define FAST_SYSTEM_CALL_TBL_ENTRY(sysname)	\
		(fast_system_call_func) sysname
#define COMPAT_FAST_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(fast_system_call_func) compat_##sysname
#define PROTECTED_FAST_SYSTEM_CALL_TBL_ENTRY(sysname) \
		(fast_system_call_func) protected_##sysname

int native_fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/fast_syscalls.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
/* it is native host kernel withounr virtualization */
/* or host kernel with virtualization support */

#ifdef CONFIG_KVM_HOST_MODE
extern long ret_from_fast_sys_call(void);

static __always_inline long kvm_return_from_fast_syscall(thread_info_t *ti, long arg1)
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
	AS(cr1_lo).psr = AW(E2K_KERNEL_PSR_DISABLED_ALL);
	AS(cr1_lo).cui = KERNEL_CODES_INDEX;

	WRITE_CR0_LO_REG(cr0_lo);
	WRITE_CR0_HI_REG(cr0_hi);
	WRITE_CR1_LO_REG(cr1_lo);
	WRITE_CR1_HI_REG(cr1_hi);

	return arg1;
}

static __always_inline long kvm_set_return_user_ip(thread_info_t *gti, u64 ip, int flags)
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
#define	goto_ttable_entry1_args3(sys_num, arg1, arg2) ({ \
	E2K_GOTO_ARG7(native_ttable_entry1, sys_num, arg1, arg2, 0, 0, 0, 0); \
	unreachable(); \
	/* For compatibility with paravirt version which returns a value */ \
	0; \
})

#define	goto_ttable_entry3_args3(sys_num, arg1, arg2) ({ \
	E2K_GOTO_ARG7(native_ttable_entry3, sys_num, arg1, arg2, 0, 0, 0, 0); \
	unreachable(); \
	/* For compatibility with paravirt version which returns a value */ \
	0; \
})

#endif	/* ! CONFIG_KVM_GUEST_KERNEL */


enum fast_gettime_return {
	FAST_SYS_OK,
	FAST_SYS_ERROR
};

static __always_inline enum fast_gettime_return fast_get_time_precise(
		time64_t *ts_tv_sec, long *ts_tv_nsec, bool monotonic)
{
	u64 cycles = 0, cycle_last = 0, mask = 0, seq;
	u32 mult, shift;
	enum fast_gettime_return ret = FAST_SYS_ERROR;
	long wall2mon_sec, wall2mon_nsec;
	u64 secs, nsecs;

	do {
		struct clocksource *clock;

		seq = fastsys_read_begin(&fsys_data);
		clock = fsys_data.clock;

		mult = fsys_data.mult;
		shift = fsys_data.shift;
		secs = fsys_data.sec;
		nsecs = fsys_data.nsec;
		if (monotonic) {
			wall2mon_sec = fsys_data.w2m_sec;
			wall2mon_nsec = fsys_data.w2m_nsec;
		}

		if (likely(clock == &clocksource_sclkr)) {
			cycle_last = fsys_data.cycle_last;
			mask = clock->mask;
			cycles = fast_syscall_read_sclkr();
			if (cycles)
				ret = FAST_SYS_OK;
		}
	} while (unlikely(fastsys_read_retry(&fsys_data, seq)));

	if (ret == FAST_SYS_OK) {
		nsecs = (((cycles - cycle_last) & mask) * mult + nsecs) >> shift;

		if (monotonic) {
			secs += wall2mon_sec;
			nsecs += wall2mon_nsec;
		}

		while (nsecs >= NSEC_PER_SEC) {
			++secs;
			nsecs -= NSEC_PER_SEC;
		}
	}

	*ts_tv_sec = secs;
	*ts_tv_nsec = nsecs;

	return ret;
}

static __always_inline int fast_get_time_coarse(
		time64_t *ts_tv_sec, long *ts_tv_nsec, bool monotonic)
{
	u64 secs, nsecs, seq;

	do {
		seq = fastsys_read_begin(&fsys_data);

		secs = fsys_data.wall_time_coarse.tv_sec;
		nsecs = fsys_data.wall_time_coarse.tv_nsec;

		if (monotonic) {
			secs += fsys_data.w2m_sec;
			nsecs += fsys_data.w2m_nsec;
		}
	} while (unlikely(fastsys_read_retry(&fsys_data, seq)));

	while (nsecs >= NSEC_PER_SEC) {
		++secs;
		nsecs -= NSEC_PER_SEC;
	}

	*ts_tv_sec = secs;
	*ts_tv_nsec = nsecs;

	return FAST_SYS_OK;
}

static __always_inline enum fast_gettime_return __fast_get_time(
		const clockid_t which_clock, time64_t *tp_tv_sec, long *tp_tv_nsec)
{
	time64_t ts_tv_sec;
	long ts_tv_nsec;
	enum fast_gettime_return ret;

	switch (which_clock) {
	case CLOCK_REALTIME:
	case CLOCK_MONOTONIC:
		ret = fast_get_time_precise(&ts_tv_sec, &ts_tv_nsec,
				which_clock == CLOCK_MONOTONIC);
		break;
	case CLOCK_REALTIME_COARSE:
	case CLOCK_MONOTONIC_COARSE:
		ret = fast_get_time_coarse(&ts_tv_sec, &ts_tv_nsec,
				which_clock == CLOCK_MONOTONIC_COARSE);
		break;
	default:
		ts_tv_sec = 0;
		ts_tv_nsec = 0;
		ret = FAST_SYS_ERROR;
		break;
	}

	if (unlikely(ret))
		return ret;

	*tp_tv_sec = ts_tv_sec;
	*tp_tv_nsec = ts_tv_nsec;

	return ret;
}

notrace __section(".entry.text")
static __always_inline enum fast_gettime_return fast_gettimeofday_user(
		struct __kernel_old_timeval __user *tv)
{
	time64_t ts_tv_sec;
	long ts_tv_nsec;
	enum fast_gettime_return fast_ret;

	fast_ret = fast_get_time_precise(&ts_tv_sec, &ts_tv_nsec, false);
	if (likely(!fast_ret)) {
		__put_user_switched_pt(ts_tv_sec, &tv->tv_sec);
		__put_user_switched_pt(ts_tv_nsec / 1000, &tv->tv_usec);
	}

	return fast_ret;
}

int fast_sys_clock_gettime(const clockid_t which_clock, struct timespec64 __user *tp);
struct timeval;
struct timezone;
int fast_sys_gettimeofday(struct __kernel_old_timeval __user *__restrict tv,
			  struct timezone __user *__restrict tz);
struct getcpu_cache;
int fast_sys_getcpu(unsigned __user *cpup, unsigned __user *nodep,
		struct getcpu_cache __user *unused);
int fast_sys_siggetmask(u64 __user *oset, size_t sigsetsize);
int fast_sys_set_return(u64 ip, int flags);

struct old_timespec32;
int compat_fast_sys_clock_gettime(const clockid_t which_clock,
		struct old_timespec32 __user *__restrict tp);
struct compat_timeval;
int compat_fast_sys_gettimeofday(struct old_timeval32 __user *__restrict tv,
				 struct timezone __user *__restrict tz);
int compat_fast_sys_siggetmask(u32 __user *oset, size_t sigsetsize);
int compat_fast_sys_set_return(u32 ip, int flags);

int protected_fast_sys_clock_gettime(u32 tags, u64 usd_lo, clockid_t which_clock,
		u64 arg3, u64 arg4, u64 arg5);
int protected_fast_sys_gettimeofday(u32 tags, u64 usd_lo,
		u64 arg2, u64 arg3, u64 arg4, u64 arg5);
int protected_fast_sys_getcpu(u32 tags, u64 usd_lo, u64 arg2, u64 arg3, u64 arg4, u64 arg5);
int protected_fast_sys_siggetmask(u32 tags, u64 usd_lo, u64 arg2, u64 arg3, size_t sigsetsize);
int protected_fast_sys_getcontext(u32 tags, u64 usd_lo, u64 arg2, u64 arg3, size_t sigsetsize);

/* Inlined handlers for fast syscalls */

notrace __section(".entry.text")
static __always_inline int fast_sys_getcontext(struct ucontext __user *ucp,
					size_t sigsetsize)
{
	struct thread_info *ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);

	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	u64 set, key;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	ucp = (typeof(ucp)) ((u64) ucp & E2K_VA_MASK);
	if (unlikely((u64) ucp + offsetofend(struct ucontext, uc_extra.pfpfr) >
			ti->addr_limit.seg))
		return -EFAULT;

	int ret = context_ti_key_fast_syscall(key, ti);
	if (unlikely(ret))
		return ret;

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	ret = __put_user_switched_pt(set, (u64 __user *) &ucp->uc_sigmask);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(key, &ucp->uc_mcontext.sbr);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(pcsp_lo, &ucp->uc_mcontext.pcsp_lo);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(pcsp_hi, &ucp->uc_mcontext.pcsp_hi);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(fpcr, &ucp->uc_extra.fpcr);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(fpsr, &ucp->uc_extra.fpsr);
	return unlikely(ret) ? ret : __put_user_switched_pt(pfpfr, &ucp->uc_extra.pfpfr);
}

notrace __section(".entry.text")
static __always_inline int native_do_fast_sys_set_return(u64 ip, int flags)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	struct task_struct *const task = thread_info_task(ti);
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_cr0_hi_t cr0_hi;
	e2k_mem_crs_t __user *frame, *base;
	u64 prev_ip, counter;
	int ret;

	E2K_FLUSHC;

	if (unlikely(flags))
		return -EINVAL;

	if (unlikely(ip >= USER_DS.seg))
		return -EFAULT;

	pcsp_hi = READ_PCSP_HI_REG(); /* We don't use %pcsp_hi.size */
	pcsp_lo = READ_PCSP_LO_REG();

	base = GET_PCS_BASE(&ti->u_hw_stack);
	frame = (e2k_mem_crs_t __user *) (AS(pcsp_lo).base + AS(pcsp_hi).ind);

	do {
		--frame;

		ret = __get_user_switched_pt(AW(cr0_hi), &AW(frame->cr0_hi));
		if (unlikely(ret))
			return ret;

		prev_ip = AS(cr0_hi).ip << 3;
	} while (unlikely(prev_ip >= TASK_SIZE && frame > base));

	/* No user frames above? */
	if (unlikely(prev_ip >= TASK_SIZE))
		return -EPERM;

	/* Modify stack */
	AS(cr0_hi).ip = ip >> 3;
	do {
		counter = READ_ONCE(task->thread.traps_count);

		E2K_FLUSHC;

		ret = __put_user_switched_pt(AW(cr0_hi), &AW(frame->cr0_hi));
		if (unlikely(ret))
			return ret;
	} while (unlikely(counter != READ_ONCE(task->thread.traps_count)));

	return 0;
}

/* Inlined handlers for compat fast syscalls */

#if _NSIG != 64
# error We read u64 value here...
#endif

#ifdef CONFIG_COMPAT
notrace __section(".entry.text")
static __always_inline int compat_fast_sys_getcontext(struct ucontext_32 __user *ucp,
					size_t sigsetsize)
{
	struct thread_info *ti = READ_CURRENT_REG();
	struct task_struct *task = thread_info_task(ti);
	u64 pcsp_lo, pcsp_hi;
	u32 fpcr, fpsr, pfpfr;
	int ret;
	union {
		u32 word[2];
		u64 whole;
	} set;
	u64 key;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set.whole = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	if (unlikely((u64) ucp + offsetofend(struct ucontext_32, uc_extra.pfpfr) >
					ti->addr_limit.seg
			|| (u64) ucp >= ti->addr_limit.seg))
		return -EFAULT;

	ret = context_ti_key_fast_syscall(key, ti);
	if (unlikely(ret))
		return ret;

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp_lo, pcsp_hi);

	/* We want stack to point to user frame that called us */
	pcsp_hi -= SZ_OF_CR;

	ret = __put_user_switched_pt(set.word[0], &((u32 *) &ucp->uc_sigmask)[0]);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(set.word[1],
						&((u32 *) &ucp->uc_sigmask)[1]);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(key, &ucp->uc_mcontext.sbr);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(pcsp_lo, &ucp->uc_mcontext.pcsp_lo);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(pcsp_hi, &ucp->uc_mcontext.pcsp_hi);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(fpcr, &ucp->uc_extra.fpcr);
	ret = unlikely(ret) ? ret : __put_user_switched_pt(fpsr, &ucp->uc_extra.fpsr);
	return unlikely(ret) ? ret : __put_user_switched_pt(pfpfr, &ucp->uc_extra.pfpfr);
}
#endif

#endif /* _ASM_E2K_FAST_SYSCALLS_H */
