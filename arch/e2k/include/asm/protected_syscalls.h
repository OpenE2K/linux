/* SPDX-License-Identifier: GPL-2.0 */
/*
 * arch/e2k/include/asm/protected_syscalls.h, v 1.0 25/12/2019.
 *
 * Copyright (C) 2019 MCST
 */

/****************** PROTECTED SYSTEM CALL DEBUG DEFINES *******************/

#ifndef _E2K_PROTECTED_SYSCALLS_H_
#define _E2K_PROTECTED_SYSCALLS_H_

#ifdef CONFIG_PROTECTED_MODE

#include <asm/mmu.h>
#include <asm/e2k_ptypes.h>

#undef	DYNAMIC_DEBUG_SYSCALLP_ENABLED
#define	DYNAMIC_DEBUG_SYSCALLP_ENABLED	1 /* Dynamic prot. syscalls control */

#if (!DYNAMIC_DEBUG_SYSCALLP_ENABLED)

/* Static debug defines (old style): */

#undef	DEBUG_SYSCALLP
#define	DEBUG_SYSCALLP	0	/* System Calls trace */
#undef	DEBUG_SYSCALLP_CHECK
#define	DEBUG_SYSCALLP_CHECK 1	/* Protected System Call args checks/warnings */
#define PM_SYSCALL_WARN_ONLY 1

#if DEBUG_SYSCALLP
#define DbgSCP printk
#else
#define DbgSCP(...)
#endif /* DEBUG_SYSCALLP */

#if DEBUG_SYSCALLP_CHECK
#define DbgSCP_ERR(fmt, ...) pr_err(fmt,  ##__VA_ARGS__)
#define DbgSCP_WARN(fmt, ...) pr_warn(fmt,  ##__VA_ARGS__)
#define DbgSCP_ALERT(fmt, ...) pr_alert(fmt,  ##__VA_ARGS__)
#else
#define DbgSC_ERR(...)
#define DbgSC_WARN(...)
#define DbgSC_ALERT(...)
#endif /* DEBUG_SYSCALLP_CHECK */

#else /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */

/* Dynamic debug defines (new style):
 * When enabled, environment variables control syscall
 *                             debug/diagnostic output.
 * To enable particular control: export <env.var.>=1
 * To disnable particular control: export <env.var.>=0
 *
 * The options are as follows:
 *
 * PM_SC_DBG_MODE_DEBUG - Output basic debug info on system calls to journal;
 *
 * PM_SC_DBG_MODE_COMPLEX_WRAPPERS - Output debug info on protected
 *                                   complex syscall wrappers to journal;
 * PM_SC_DBG_MODE_CHECK - Report issue to journal if syscall arg
 *                                              mismatch expected format;
 * PM_SC_DBG_MODE_WARN_ONLY - If error in arg format detected,
 *                                 don't block syscall but run it anyway;
 * PM_SC_DBG_MODE_CONV_STRUCT - Output to journal debug info on converting
 *                                            structures in syscall args;
 * PM_SC_DBG_MODE_SIGNALS - Output to system journal debug info related
 *                                               to signal manipulation;
 * PM_SC_DBG_MODE_NO_ERR_MESSAGES - Blocks diagnostic messages to journal
 *          (may be useful when running latency-sensitive tests/applications);
 *
 * PM_MM_CHECK_4_DANGLING_POINTERS - Enable check for dangling descriptors
 *                                   allocated with 'malloc' (libc specific);
 *
 * PM_SC_DBG_MODE_ALL - Enable all debug/diagnostic output to system journal;
 *
 * PM_SC_DBG_MODE_DISABLED - Disable debug/diagnostic output to system journal.
 */

#include "asm/syscalls.h"

#define DbgSCP(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_DEBUG)) \
		pr_info("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define DbgSCP_ERR(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CHECK) \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_err("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)
#define DbgSCP_ALERT(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CHECK) \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_alert("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)
#define DbgSCP_WARN(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CHECK) \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_warn("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define PM_SYSCALL_WARN_ONLY \
		(arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_WARN_ONLY))
 /* Backward compatibility with syscalls */
		/* NB> It may happen legacy s/w written incompatible with
		 *				context protection principles.
		 *	For example, tests for syscalls may be of that kind
		 *	to intentionally pass bad arguments to syscalls to check
		 *			if behavior is correct in that case.
		 *  This define, being activated, eases argument check control
		 *	when doing system calls in the protected execution mode:
		 *	- a warning still gets reported to the journal, but
		 *	- system call is not blocked at it is normally done.
		 */

#define	DEBUG_SYSCALLP_CHECK 1	/* protected syscall args checks enabled */

#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */

/* If running in the orthodox protected mode, deliver exception to break execution: */
#define PM_EXCEPTION_IF_ORTH_MODE(signo, code, errno) \
do { \
	if (!PM_SYSCALL_WARN_ONLY) \
		pm_deliver_exception(signo, code, errno); \
} while (0)

/**************************** END of DEBUG DEFINES ***********************/


static inline
long make_ap_lo(e2k_addr_t base, long size, long offset, int access)
{
	return MAKE_AP_LO(base, size, offset, access);
}

static inline
long make_ap_hi(e2k_addr_t base, long size, long offset, int access)
{
	return MAKE_AP_HI(base, size, offset, access);
}

static inline
int e2k_ptr_itag(long low)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;

	return AS(ptr).itag;
}

static inline
int e2k_ptr_rw(long low)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;

	return AS(ptr).rw;
}

static inline
unsigned long e2k_ptr_ptr(long low, long hiw, unsigned int min_size)
{
	e2k_ptr_t ptr;
	unsigned int ptr_size;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;
	ptr_size = AS(ptr).size - AS(ptr).curptr;

	if (ptr_size < min_size) {
		DbgSCP_ALERT("  Pointer is too small: %d < %d\n",
			     ptr_size, min_size);
		return 0;
	} else {
		return E2K_PTR_PTR(ptr, GET_SBR_HI());
	}
}

static inline
unsigned long e2k_ptr_curptr(long low, long hiw)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;

	return AS(ptr).curptr;
}

static inline
unsigned int e2k_ptr_size(long low, long hiw, unsigned int min_size)
{
	e2k_ptr_hi_t hi;
	unsigned int ptr_size;

	AW(hi) = hiw;
	ptr_size = AS(hi).size - AS(hi).curptr;

	if (ptr_size < min_size) {
		DbgSCP_ALERT("  Pointer is too small: %d < %d\n",
			     ptr_size, min_size);
		return 0;
	} else {
		return ptr_size;
	}
}

static inline int e2k_ptr_str_check(char __user *str, u64 max_size)
{
	long slen;

	slen = strnlen_user(str, max_size);

	if (unlikely(!slen || slen > max_size))
		return 1;

	return 0;
}

static inline char __user *e2k_ptr_str(long low, long hiw, u64 sbr_hi)
{
	char __user *str;
	e2k_ptr_hi_t hi = { .word = hiw };

	str = (char __user *) __E2K_PTR_PTR(low, hiw, sbr_hi);

	if (!e2k_ptr_str_check(str, AS(hi).size - AS(hi).curptr))
		return str;

	return NULL;
}

extern void pm_deliver_exception(int signo, int code, int errno);


#else /* #ifndef CONFIG_PROTECTED_MODE */

#define DbgSCP(...)
#define DbgSC_ERR(...)
#define DbgSC_WARN(...)
#define DbgSC_ALERT(...)

#endif /* CONFIG_PROTECTED_MODE */


#endif /* _E2K_PROTECTED_SYSCALLS_H_ */

