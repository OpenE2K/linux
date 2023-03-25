/* linux/arch/e2k/kernel/protected_timer_create.c, v 1.0 02/20/2019.
 *
 * This is implementation of the system calls timer_create and rt_sigtimedwait:
 *		int timer_create(clockid_t clockid, struct sigevent *sevp,
 *					timer_t *timerid);
 *		int rt_sigtimedwait(const sigset_t *set, siginfo_t *info,
 *					const struct timespec *timeout,
 *					size_t sigsetsize);
 * for E2K protected mode.
 *
 * Copyright (C) 2019 MCST
 */


#include <linux/syscalls.h>
#include <linux/compat.h>
#include <asm/e2k_debug.h>

#include <asm/signal.h>
#include <asm/syscalls.h>
#include <asm/convert_array.h>
#include <asm/protected_syscalls.h>


#ifdef CONFIG_PROTECTED_MODE


#if (DYNAMIC_DEBUG_SYSCALLP_ENABLED)
	/* NB> PM debug module must have been initialized by the moment
	 *     of invocation of any of the functions that follow;
	 *     we can use simple defines over here.
	 *     For full ones see <asm/protected_syscalls.h>.
	 */
#undef DbgSCP
#define DbgSCP(fmt, ...) \
do { \
	if (current->mm->context.pm_sc_debug_mode \
		& PM_SC_DBG_MODE_COMPLEX_WRAPPERS) \
		pr_info("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_ERR
#define DbgSCP_ERR(fmt, ...) \
do { \
	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK) \
		pr_err("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_ALERT
#define DbgSCP_ALERT(fmt, ...) \
do { \
	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK) \
		pr_alert("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_WARN
#define DbgSCP_WARN(fmt, ...) \
do { \
	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK) \
		pr_warn("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#undef PM_SYSCALL_WARN_ONLY
#define PM_SYSCALL_WARN_ONLY \
	(current->mm->context/pm_sc_debug_mode & PM_SC_DBG_MODE_WARN_ONLY)

#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */


#define get_user_space(x)	arch_compat_alloc_user_space(x)

static inline
unsigned long e2k_descriptor_size(long user_ptr_hi, unsigned int min_size)
{
	e2k_ptr_hi_t hi;
	unsigned int ptr_size;

	AW(hi) = user_ptr_hi;
	ptr_size = AS(hi).size - AS(hi).curptr;

	if (ptr_size < min_size) {
#define E2K_PTR_ERR_MSG \
		"Pointer is too small in protected timer_create(): %d < %d\n"
		DbgSCP_ALERT(E2K_PTR_ERR_MSG, ptr_size, min_size);
		return 0;
	} else {
		return ptr_size;
	}
}

/*
 * On success, timer_create() returns 0, and the ID of the new timer is
 * placed in *timerid.  On failure, -1 is returned, and errno is set to
 *                                                   indicate the error.
 */
long protected_sys_timer_create(clockid_t which_clock,
		prot_sigevent_t __user *user_sev, timer_t __user *timerid,
		u64 unused4, u64 unused5, u64 unused6, const struct pt_regs *regs)
{
#define MASK_SIGEVENT_TYPE_I   0x0
#define MASK_SIGEVENT_TYPE_P   0x3
#define MASK_SIGEVENT_TYPE_F   0x2
#define MASK_SIGEVENT_TYPE_xIIFP  0x380
#define MASK_SIGEVENT_ALIGN_THR   0xf3
#define MASK_SIGEVENT_ALIGN_TID   0x33
#define MASK_SIGEVENT_RW_NONE		0x288
#define MASK_SIGEVENT_RW_SIGNAL		0x280
#define MASK_SIGEVENT_RW_THREAD		0x000
#define MASK_SIGEVENT_RW_THREAD_ID	0x800
	sigevent_t __user *kernel_sev = NULL;
	unsigned long size;
	long mask_sigevent_type, mask_align, mask_rw_type;
	int field_num, user_notify, rval;
	u32 sival_ptr_tags;
	u64 user_ptr_lo, user_ptr_hi;

	DbgSCP("which_clock=%d, sevp=0x%px, timerid=0x%px\n",
			which_clock, user_sev, timerid);
	if (!user_sev)
		goto run_syscall;

	/* Detecting the type of the first field of the sigevent structure: */
	if (get_user_tagged_16(user_ptr_lo, user_ptr_hi,
				sival_ptr_tags, user_sev) ||
			get_user(user_notify, &user_sev->sigev_notify))
		return -EFAULT;

	/*
	 * Acqiure type mask in accordance with the data type
	 * in the union sigval: int/ptr
	 */
	switch (sival_ptr_tags) {
	case ETAGNUM:
		mask_sigevent_type = MASK_SIGEVENT_TYPE_I;
		break;
	case ETAGAPQ:
		mask_sigevent_type = MASK_SIGEVENT_TYPE_P;
		break;
	case ETAGPLD:
		mask_sigevent_type = MASK_SIGEVENT_TYPE_F;
		break;
	case ETAGPLQ: /* this is for future Elbrus arch V6 */
		DbgSCP_ERR("unsupported tag ETAGPLQ (0x%x)\n", sival_ptr_tags);
		DbgSCP("\tptr_lo=0x%llx ptr_hi=0x%llx\n", user_ptr_lo, user_ptr_hi);
		return -EINVAL;
	default:
		mask_sigevent_type = MASK_SIGEVENT_TYPE_I;
	}

	/* Calculating mask_rw_type on sevp.sigev_notify value: */
	switch (user_notify) {
	case SIGEV_NONE:
		mask_align = MASK_SIGEVENT_ALIGN_THR;
		mask_rw_type = MASK_SIGEVENT_RW_NONE;
		field_num = 3;
		break;
	case SIGEV_SIGNAL:
		mask_align = MASK_SIGEVENT_ALIGN_THR;
		mask_rw_type = MASK_SIGEVENT_RW_SIGNAL;
		field_num = 3;
		break;
	case SIGEV_THREAD:
		mask_sigevent_type |= MASK_SIGEVENT_TYPE_xIIFP;
		mask_align = MASK_SIGEVENT_ALIGN_THR;
		mask_rw_type = MASK_SIGEVENT_RW_THREAD;
		field_num = 5;
		break;
	case SIGEV_THREAD_ID:
		mask_align = MASK_SIGEVENT_ALIGN_TID;
		mask_rw_type = MASK_SIGEVENT_RW_THREAD_ID;
		field_num = 5; /* +1 extra field to have 8-order struct size */
		break;
	default:
		DbgSCP_ERR("unsupported sigev_notify value %d\n", user_notify);
		return -EINVAL;
	}

	/* Converting structure sigevent sev: */
	kernel_sev = get_user_space(sizeof(*kernel_sev));
	size = e2k_descriptor_size(regs->args[4], sizeof(*user_sev));
	if (!size)
		return -EINVAL;
	rval = convert_array_3((long __user *) user_sev, (long __user *) kernel_sev,
			size, field_num, 1,
			mask_sigevent_type, mask_align, mask_rw_type, 0);

	if (rval != 0) {
		DbgSCP_ERR("Bad structure sigevent\n");
		return -EINVAL;
	}
run_syscall:
	rval = sys_timer_create(which_clock, kernel_sev, timerid);
	if (rval)
		return rval;

	/* Save it in sival_ptr_list: */
	if (kernel_sev) {
		void __user *sival_ptr;
		if (get_user(sival_ptr, &kernel_sev->sigev_value.sival_ptr))
			return -EFAULT;

		store_descriptor_attrs(sival_ptr, user_ptr_lo, user_ptr_hi,
				       sival_ptr_tags, 0 /*signum*/);

		DbgSCP("\tkernel_ptr = %px\n", kernel_sev->sigev_value.sival_ptr);
		DbgSCP("\tuser_ptr_lo = 0x%llx\n", user_ptr_lo);
		DbgSCP("\tuser_ptr_hi = 0x%llx\n", user_ptr_hi);
		DbgSCP("\tuser_tags = 0x%x\n", sival_ptr_tags);
	}
	return 0;
}

/*
 * On success, rt_sigtimedwait() returns a signal number (positive value).
 * On failure it returns -1, with errno set to indicate the error.
 */
long protected_sys_rt_sigtimedwait(const sigset_t __user *set,
				   siginfo_t __user *info,
				   const struct __kernel_timespec __user *timeout,
				   size_t sigsetsize)
{
	struct sival_ptr_list *curr_el = NULL;
	void  __user *dscr_ptr;
	int rval, si_code, si_signo;

	DbgSCP("set= 0x%lx, info=0x%lx, timeout=0x%lx, sigsetsize=%ld\n",
			set, info, timeout, sigsetsize);

	rval = sys_rt_sigtimedwait(set, info, timeout, sigsetsize);
	if (rval <= 0) {
		DbgSCP("rt_sigtimedwait failed. rval = %d\n", rval);
		return rval;
	}
	if (!info)
		return rval;

	if (get_user(si_code, &info->si_code) ||
			get_user(si_signo, &info->si_signo) ||
			get_user(dscr_ptr, &info->si_ptr))
		return -EFAULT;

	DbgSCP("si_code = 0x%x\n", si_code);
	if (si_code > 0 && siginfo_layout(si_signo, si_code) != SIL_RT) {
		return rval;
	}
	if (dscr_ptr == NULL) {
		/*
		 * The 'si_ptr pointer' in the 'siginfo' structure
		 * appeared empty. So there is nothing to convert
		 * to descriptor for proper handling in the user space.
		 */
		return rval;
	}
	/*
	 * We need to pass si_ptr descriptor to user.
	 * We look for the descriptor in ti->sival_ptr_list:
	 */
	curr_el = get_descriptor_attrs(dscr_ptr, 0 /*signum*/);

#define ERRMSG_rt_sigtimedwait_ESPIPE \
"prot_sys_rt_sigtimedwait failed to find descriptor %px in ti->sival_ptr_list\n"
	if (curr_el == NULL) {
		DbgSCP_ALERT(ERRMSG_rt_sigtimedwait_ESPIPE, dscr_ptr);
		DbgSCP_ALERT("\treturning (-ESPIPE)\n");
		return -ESPIPE;
	}

	DbgSCP("curr_el:\nnext = %px\n", curr_el->link.next);
	DbgSCP("kernel_ptr = %px\n", curr_el->kernel_ptr);
	DbgSCP("user_ptr_lo = 0x%llx\n", curr_el->user_ptr_lo);
	DbgSCP("user_ptr_hi = 0x%llx\n", curr_el->user_ptr_hi);
	DbgSCP("user_tags = 0x%x\n", curr_el->user_tags);
	if (put_user_tagged_16(curr_el->user_ptr_lo, curr_el->user_ptr_hi,
			curr_el->user_tags, &info->si_ptr + 1))
		return -EFAULT;

	DbgSCP("info->si_code = 0x%x\n", si_code);
	return rval;
}

#endif  /* CONFIG_PROTECTED_MODE */
