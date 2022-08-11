#include <linux/compat.h>
#include <linux/time.h>

#include <asm/e2k_ptypes.h>
#include <asm/fast_syscalls.h>
#include <asm/process.h>
#include <linux/uaccess.h>
#include <asm/ucontext.h>

static inline
unsigned long e2k_ptr_ptr(long low, long hiw, unsigned int min_size,
		const struct thread_info *ti)
{
	e2k_ptr_t ptr;
	unsigned int ptr_size;
	unsigned long va_ptr;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;
	ptr_size = AS(ptr).size - AS(ptr).curptr;

	if (ptr_size < min_size) {
		va_ptr = 0;
	} else {
		if (AS(ptr).itag == AP_ITAG)
			va_ptr = AS(ptr).ap.base + AS(ptr).curptr;
		else
			va_ptr = AS(ptr).sap.base + AS(ptr).curptr +
				 (ti->u_stack.bottom & 0xFFFF00000000UL);
	}

	return va_ptr;
}

static inline
unsigned int e2k_ptr_size(long low, long hiw, unsigned int min_size)
{
	e2k_ptr_hi_t hi;
	unsigned int ptr_size;

	AW(hi) = hiw;
	ptr_size = AS(hi).size - AS(hi).curptr;

	if (ptr_size < min_size)
		return 0;
	else
		return ptr_size;
}

#define ARG_TAG(i)	((tags & (0xF << (4*(i)))) >> (4*(i)))
#define NOT_PTR(i)	((tags & (0xFF << (4*(i)))) >> (4*(i)) != ETAGAPQ)
#define NULL_PTR(i) ((ARG_TAG(i) == E2K_NULLPTR_ETAG) && (arg##i == 0))

#define GET_PTR(ptr, size, i, j, min_size, null_is_allowed, ti) \
do { \
	if (unlikely(NULL_PTR(i))) { \
		ptr = 0; \
		size = min_size * !!null_is_allowed; \
	} else if (likely(!NOT_PTR(i))) { \
		ptr = (typeof(ptr)) e2k_ptr_ptr(arg##i, arg##j, min_size, ti); \
		size = e2k_ptr_size(arg##i, arg##j, min_size); \
	} else { \
		ptr = 0; \
		size = 0; \
	} \
} while (0)


extern long ttable_entry8(int sys_num,
		u64 r1, u64 r2, u64 r3, u64 r4, u64 r5, u64 r6, u64 r7);

/* This macro fills missing arguments with "(u64) (0)". */
#define EXPAND_SYSCALL_ARGS_TO_8(...) \
	__EXPAND_SYSCALL_ARGS_TO_8(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0)
#define __EXPAND_SYSCALL_ARGS_TO_8(sys_num, tags, a2, a3, a4, a5, a6, a7, ...) \
		(sys_num), (tags), (u64) (a2), (u64) (a3), (u64) (a4), \
		(u64) (a5), (u64) (a6), (u64) (a7)

#define PROTECTED_SYSCALL(sys_num, tags, ...) \
	_PROTECTED_SYSCALL(EXPAND_SYSCALL_ARGS_TO_8(sys_num, tags ,##__VA_ARGS__))
/*
 * Needed because preprocessor checks for number of arguments before
 * expansion takes place, so without this define it would think that
 * __PROTECTED_SYSCALL(EXPAND_SYSCALL_ARGS_TO_8(__VA_ARGS__))
 * is invoked with one argument.
 */
#define _PROTECTED_SYSCALL(...) __PROTECTED_SYSCALL(__VA_ARGS__)

#define __PROTECTED_SYSCALL(sys_num, tags, arg2, arg3, arg4, arg5, arg6, arg7) \
({ \
	long __ret; \
	u32 tag2 = ARG_TAG(2), tag3 = ARG_TAG(3), tag4 = ARG_TAG(4), \
	    tag5 = ARG_TAG(5), tag6 = ARG_TAG(6), tag7 = ARG_TAG(7); \
	asm volatile ("{\n" \
		      "nop 3\n" \
		      "disp %%ctpr1, %[_func]\n" \
		      "adds %[_sys_num], 0, %%b[0]\n" \
		      "puttagd %[_arg2], %[_tag2], %%db[2]\n" \
		      "puttagd %[_arg3], %[_tag3], %%db[3]\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %[_arg4], %[_tag4], %%db[4]\n" \
		      "puttagd %[_arg5], %[_tag5], %%db[5]\n" \
		      "}\n" \
		      "{\n" \
		      "puttagd %[_arg6], %[_tag6], %%db[6]\n" \
		      "puttagd %[_arg7], %[_tag7], %%db[7]\n" \
		      "call %%ctpr1, wbs=%#\n" \
		      "}\n" \
		      "addd %%db[0], 0, %[_ret]\n" \
		      : [_ret] "=r" (__ret) \
		      : [_func] "i" (&ttable_entry8), [_sys_num] "r" (sys_num), \
		        [_arg2] "r" (arg2), [_arg3] "r" (arg3), \
			[_arg4] "r" (arg4), [_arg5] "r" (arg5), \
			[_arg6] "r" (arg6), [_arg7] "r" (arg7), \
			[_tag2] "r" (tag2), [_tag3] "r" (tag3), \
			[_tag4] "r" (tag4), [_tag5] "r" (tag5), \
			[_tag6] "r" (tag6), [_tag7] "r" (tag7) \
		      : E2K_SYSCALL_CLOBBERS); \
	__ret; \
})

notrace __interrupt __section(".entry.text")
int protected_fast_sys_clock_gettime(u32 tags, clockid_t which_clock,
		u64 arg3, u64 arg4, u64 arg5)
{
	const struct thread_info *ti = READ_CURRENT_REG();
	struct timespec __user *tp;
	int size, ret;

	prefetchw(&fsys_data);

	GET_PTR(tp, size, 4, 5, sizeof(struct timespec), 0, ti);
	if (!size)
		return -EFAULT;

	if (unlikely((u64) tp + sizeof(struct timespec) > ti->addr_limit.seg))
		return -EFAULT;

	ret = do_fast_clock_gettime(which_clock, tp);
	if (unlikely(ret))
		ret = PROTECTED_SYSCALL(__NR_clock_gettime, tags,
				which_clock, arg3, arg4, arg5);

	return ret;
}

notrace __interrupt __section(".entry.text")
int protected_fast_sys_gettimeofday(u32 tags, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
	const struct thread_info *ti = READ_CURRENT_REG();
	struct timeval __user *tv;
	struct timezone __user *tz;
	int size, ret;

	prefetch_nospec(&fsys_data);

	GET_PTR(tv, size, 2, 3, sizeof(struct timeval), 1, ti);
	if (!size)
		return -EFAULT;

	GET_PTR(tz, size, 4, 5, sizeof(struct timezone), 1, ti);
	if (!size)
		return -EFAULT;

	if (unlikely((u64) tv + sizeof(struct compat_timeval) >
					ti->addr_limit.seg
			|| (u64) tz + sizeof(struct timezone) >
					ti->addr_limit.seg))
		return -EFAULT;

	if (likely(tv)) {
		ret = do_fast_gettimeofday(tv);
		if (unlikely(ret))
			return PROTECTED_SYSCALL(__NR_gettimeofday, tags,
					arg2, arg3, arg4, arg5);
	} else {
		ret = 0;
	}

	if (tz) {
		tz->tz_minuteswest = sys_tz.tz_minuteswest;
		tz->tz_dsttime = sys_tz.tz_dsttime;
	}

	return ret;
}


notrace __interrupt __section(".entry.text")
int protected_fast_sys_getcpu(u32 tags, u64 arg2, u64 arg3, u64 arg4, u64 arg5)
{
	const struct thread_info *ti = READ_CURRENT_REG();
	int cpu = task_cpu(thread_info_task(ti));
	int node, size;
	unsigned __user *cpup;
	unsigned __user *nodep;

	GET_PTR(cpup, size, 2, 3, sizeof(unsigned int), 1, ti);
	if (!size)
		return -EFAULT;

	GET_PTR(nodep, size, 4, 5, sizeof(unsigned int), 1, ti);
	if (!size)
		return -EFAULT;

	if (unlikely((u64) cpup + sizeof(unsigned) > ti->addr_limit.seg
			|| (u64) nodep + sizeof(unsigned) > ti->addr_limit.seg))
		return -EFAULT;

	if (nodep)
		node = cpu_to_node(cpu);

	if (nodep)
		*nodep = node;
	if (cpup)
		*cpup = cpu;

	return 0;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(".entry.text")
int protected_fast_sys_siggetmask(u32 tags, u64 arg2, u64 arg3, size_t sigsetsize)
{
	const struct thread_info *ti = READ_CURRENT_REG();
	const struct task_struct *task = thread_info_task(ti);
	u64 set;
	int size;
	u64 __user *oset;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	GET_PTR(oset, size, 2, 3, sizeof(sigset_t), 0, ti);
	if (!size)
		return -EFAULT;

	if (unlikely((u64) oset + sizeof(sigset_t) > ti->addr_limit.seg))
		return -EFAULT;

	*oset = set;

	return 0;
}

#if _NSIG != 64
# error We read u64 value here...
#endif
notrace __interrupt __section(".entry.text")
int protected_fast_sys_getcontext(u32 tags, u64 arg2, u64 arg3, size_t sigsetsize)
{
	const struct thread_info *ti = READ_CURRENT_REG();
	const struct task_struct *task = thread_info_task(ti);
	register u64 pcsp_lo, pcsp_hi;
	register u32 fpcr, fpsr, pfpfr;
	u64 set, key;
	int size, ret = 0;
	struct ucontext_prot __user *ucp;

	BUILD_BUG_ON(sizeof(task->blocked.sig[0]) != 8);
	set = task->blocked.sig[0];

	if (unlikely(sigsetsize != 8))
		return -EINVAL;

	GET_PTR(ucp, size, 2, 3, sizeof(struct ucontext_prot), 0, ti);
	if (!size)
		return -EFAULT;

	if (unlikely((u64) ucp + sizeof(struct ucontext_prot)
					> ti->addr_limit.seg
			|| (u64) ucp >= ti->addr_limit.seg))
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

	return ret;
}

