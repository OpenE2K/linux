/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/compat.h>
#include <linux/uaccess.h>
#include <linux/time.h>

#include <asm/e2k_ptypes.h>
#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <asm/ucontext.h>
#include <asm/processor.h>

#define ARG_TAG(i)	((tags & (0xF << (4*(i)))) >> (4*(i)))


/**
 * get_ptr_from_args() -  The function extracts regular pointer from the couple of protected args.
 * @tags: is protected arg tags (32 bit is quite enough for fast syscaslls)
 * @arg_num: is low-argument number in the protected arg pair in a system call (1, 3, or 5)
 * @arg_lo: lower half of protected argument pair
 * @arg_hi: higher half
 * @min_size: is minimum required size of the pointer
 * @ptr_size: is extracted actual size of the pointer
 * @null_is_allowed: if the argument allowed to have gor NULL value
 *
 * Context: This is local function used in protected syscall wrappers.
 *
 * Return: Regular pointer similar to the one in the regular execution mode.
 */
static inline void __user *get_ptr_from_args(u32 tags, const int arg_num,
				      u64 arg_lo, u64 arg_hi,
				      const int min_size, int *ptr_size,
				      const int null_is_allowed)
{
#define _NULL_PTR_(n) ((ARG_TAG(n) == E2K_NULLPTR_ETAG) && (arg_lo == 0))
#define TAG_OF_ARG(i)	((tags & (0xFF << (4*(i)))) >> (4*(i)))
	void __user *ptr; /* result */
	e2k_ptr_t qarg = { .lo = arg_lo, .hi = arg_hi };

	if (unlikely(_NULL_PTR_(arg_num))) {
		ptr = NULL;
		*ptr_size = min_size * !!null_is_allowed;
	} else if (likely(IS_AP(qarg, TAG_OF_ARG(arg_num)))) {
		*ptr_size = AP_OBJ_SIZE(qarg);
		if (min_size && *ptr_size < min_size) {
			*ptr_size = 0;
			ptr = NULL;
		} else {
			ptr = (typeof(ptr)) AP_PTRC(qarg);
		}
	} else {
		ptr = NULL;
		*ptr_size = 0;
	}

	return ptr;
}



extern long ttable_entry8(int sys_num,
			  u64 r1, u64 r2, u64 r3, u64 r4, u64 r5, u64 r6, u64 r7);

/* This macro fills missing arguments with "(u64) (0)". */
#define EXPAND_SYSCALL_ARGS_TO_9(...) \
	__EXPAND_SYSCALL_ARGS_TO_9(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0, 0)
#define __EXPAND_SYSCALL_ARGS_TO_9(sys_num, tags, usd_lo, a2, a3, a4, a5, a6, a7, ...) \
		(sys_num), (tags), (usd_lo), (u64) (a2), (u64) (a3), (u64) (a4), \
		(u64) (a5), (u64) (a6), (u64) (a7)

/*
 * Besides jumping into ttable_entry8 this must also restore %usd.p value
 */
#define FASTSYS_PROTECTED_FALLBACK(sys_num, tags, usd_lo, ...) \
	_FASTSYS_PROTECTED_FALLBACK(EXPAND_SYSCALL_ARGS_TO_9(sys_num, tags, usd_lo ,##__VA_ARGS__))
/*
 * Needed because preprocessor checks for number of arguments before
 * expansion takes place, so without this define it would think that
 * __FASTSYS_PROTECTED_FALLBACK(EXPAND_SYSCALL_ARGS_TO_8(__VA_ARGS__))
 * is invoked with one argument.
 */
#define _FASTSYS_PROTECTED_FALLBACK(...) __FASTSYS_PROTECTED_FALLBACK(__VA_ARGS__)

notrace __interrupt __section(".entry.text")
int protected_fast_sys_clock_gettime(u32 tags, u64 usd_lo,
		clockid_t which_clock, u64 arg3, u64 arg4, u64 arg5)
{
	struct timespec64 __user *tp;
	time64_t kts64_tv_sec;
	long kts64_tv_nsec;
	int ret;
	enum fast_gettime_return fast_ret;
	int size;

	prefetch_nospec(&fsys_data);

	tp = get_ptr_from_args(tags, 4, arg4, arg5, sizeof(*tp), &size, 0);
	if (!size)
		return -EFAULT;

	if (unlikely((unsigned long) untagged_addr(tp) + sizeof(*tp) > user_addr_max()))
		return -EFAULT;

	fast_ret = __fast_get_time(which_clock, &kts64_tv_sec, &kts64_tv_nsec);
	if (unlikely(fast_ret))
		return FASTSYS_PROTECTED_FALLBACK(__NR_clock_gettime, tags,
					 usd_lo, which_clock, arg3, arg4, arg5);

	/* Can use `|=` because __put_user_switched_pt can return only -EFAULT error */
	ret = __put_user_switched_pt(kts64_tv_sec, &tp->tv_sec);
	return ret | __put_user_switched_pt(kts64_tv_nsec, &tp->tv_nsec);
}

notrace __interrupt __section(".entry.text")
int protected_fast_sys_gettimeofday(u32 tags, u64 usd_lo,
				    u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
	struct __kernel_old_timeval __user *tv;
	struct timezone __user *tz;
	int size;

	prefetch_nospec(&fsys_data);

	tv = get_ptr_from_args(tags, 2, arg2, arg3, sizeof(struct __kernel_old_timeval), &size, 1);
	if (!size)
		return -EFAULT;

	tz = get_ptr_from_args(tags, 4, arg4, arg5, sizeof(struct timezone), &size, 1);
	if (!size)
		return -EFAULT;

	if (unlikely((unsigned long)untagged_addr(tv) + sizeof(*tv) > user_addr_max() ||
		     (unsigned long)untagged_addr(tz) + sizeof(*tz) > user_addr_max()))
		return -EFAULT;

	if (likely(tv)) {
		enum fast_gettime_return fast_ret = fast_gettimeofday_user(tv);
		if (unlikely(fast_ret))
			return FASTSYS_PROTECTED_FALLBACK(__NR_gettimeofday, tags,
					usd_lo, arg2, arg3, arg4, arg5);
	}

	if (tz) {
		typeof(sys_tz.tz_minuteswest) minuteswest = sys_tz.tz_minuteswest;
		typeof(sys_tz.tz_dsttime) dsttime = sys_tz.tz_dsttime;
		/* Can use `|=` because __put_user_switched_pt can return only -EFAULT error */
		int ret = __put_user_switched_pt(minuteswest, &tz->tz_minuteswest);
		return ret | __put_user_switched_pt(dsttime, &tz->tz_dsttime);
	} else {
		return 0;
	}
}


notrace __interrupt __section(".entry.text")
int protected_fast_sys_getcpu(u32 tags, u64 usd_lo __always_unused,
			      u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
	const struct thread_info *ti = (struct thread_info *)read_CURRENT_reg_value();
	int cpu = task_cpu(thread_info_task(ti));
	int size;
	unsigned __user *cpup;
	unsigned __user *nodep;

	cpup = get_ptr_from_args(tags, 2, arg2, arg3, sizeof(unsigned int), &size, 1);
	if (!size)
		return -EFAULT;

	nodep = get_ptr_from_args(tags, 4, arg4, arg5, sizeof(unsigned int), &size, 1);
	if (!size)
		return -EFAULT;

	if (unlikely((unsigned long)untagged_addr(cpup) + sizeof(unsigned) > user_addr_max() ||
		     (unsigned long)untagged_addr(nodep) + sizeof(unsigned) > user_addr_max()))
		return -EFAULT;

	int ret = 0;
	if (nodep) {
		int node = cpu_to_node(cpu);
		ret = __put_user_switched_pt(node, nodep);
	}
	/* Can use `|=` because __put_user_switched_pt can return only -EFAULT error */
	if (cpup)
		ret |= __put_user_switched_pt(cpu, cpup);

	return 0;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(".entry.text")
int protected_fast_sys_siggetmask(u32 tags, u64 usd_lo __always_unused,
				  u64 arg2, u64 arg3, size_t sigsetsize)
{
	const struct thread_info *ti = (struct thread_info *)read_CURRENT_reg_value();
	const struct task_struct *task = thread_info_task(ti);
	u64 set;
	int size;
	u64 __user *oset;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	oset = get_ptr_from_args(tags, 2, arg2, arg3, sizeof(sigset_t), &size, 0);
	if (!size)
		return -EFAULT;

	if (unlikely((unsigned long)untagged_addr(oset) + sizeof(sigset_t) > user_addr_max()))
		return -EFAULT;

	return __put_user_switched_pt(set, oset);
}

#if _NSIG != 64
# error We read u64 value here...
#endif

notrace __interrupt __section(".entry.text")
int protected_fast_sys_getcontext(u32 tags, u64 usd_lo, u64 arg2, u64 arg3,
				  size_t sigsetsize, u64 unused __always_unused, u64 cr1_lo)
{
	struct thread_info *ti = (struct thread_info *)read_CURRENT_reg_value();
	const struct task_struct *task = thread_info_task(ti);
	e2k_pcsp_t pcsp;
	e2k_psp_t psp;
	u64 sbr, cr1_lo_cur;
	u32 fpcr, fpsr, pfpfr;
	u64 set, key;
	int size;
	struct ucontext_prot __user *ucp;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	ucp = get_ptr_from_args(tags, 2, arg2, arg3,
			offsetofend(struct ucontext_prot, uc_extra.pfpfr), &size, 0);
	if (!size)
		return -EFAULT;

	if (unlikely((unsigned long)untagged_addr(ucp) + offsetofend(struct ucontext_prot,
				uc_extra.pfpfr) > user_addr_max()
			|| (unsigned long)untagged_addr(ucp) >= user_addr_max()))
		return -EFAULT;

	int ret = context_ti_key_fast_syscall(key, ti);
	if (unlikely(ret))
		return ret;

	E2K_GETCONTEXT(fpcr, fpsr, pfpfr, pcsp, psp, sbr, cr1_lo_cur);

	/* We want stack to point to user frame that called us */
	pcsp = decr_pcsp_ind(pcsp, 2 * SZ_OF_CR);
	psp = decr_psp_ind(psp,
			(((e2k_cr1_t) { .lo = cr1_lo_cur, .hi = 0 }).wbs +
			 ((e2k_cr1_t) { .lo = cr1_lo, .hi = 0 }).wbs) * EXT_4_NR_SZ);

	/* Can use `|=` because __put_user_switched_pt can return only -EFAULT error */
	ret = __put_user_switched_pt(set, (u64 __user *) &ucp->uc_sigmask);
	ret |= __put_user_switched_pt(key, uc_coroutine_key_128(ucp));
	ret |= __put_user_switched_pt(LO(pcsp), &ucp->uc_mcontext.pcsp_lo);
	ret |= __put_user_switched_pt(HI(pcsp), &ucp->uc_mcontext.pcsp_hi);
	ret |= __put_user_switched_pt(LO(psp), &ucp->uc_mcontext.psp_lo);
	ret |= __put_user_switched_pt(HI(psp), &ucp->uc_mcontext.psp_hi);
	ret |= __put_user_switched_pt(sbr, &ucp->uc_mcontext.sbr);
	ret |= __put_user_switched_pt(fpcr, &ucp->uc_extra.fpcr);
	ret |= __put_user_switched_pt(fpsr, &ucp->uc_extra.fpsr);
	return ret | __put_user_switched_pt(pfpfr, &ucp->uc_extra.pfpfr);
}

