/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/****************** PROTECTED SYSTEM CALL DEBUG DEFINES *******************/

#ifndef _E2K_PROTECTED_SYSCALLS_H_
#define _E2K_PROTECTED_SYSCALLS_H_

#ifdef CONFIG_PROTECTED_MODE

#include <asm/mmu.h>
#include <asm/e2k_ptypes.h>
#include <asm/e2k_debug.h>
#include <asm/machdep.h>
#include <linux/version.h>
#include "asm/syscalls.h"
#include <asm/protected_mode.h>

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

#define PROTECTED_MODE_ALERT(...)
#define PROTECTED_MODE_WARNING(...)
#define PROTECTED_MODE_MESSAGE(...)

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
 * PM_SC_DBG_MODE_CHECK - Report issue if syscall arg mismatches expected format;
 *
 * PM_SC_DBG_MODE_WARN_ONLY - If error in arg format detected, report it, but
 *                                      don't block syscall and run it anyway;
 * ...
 *
 * For the full list of options see <asm/protected_mode.h>
 */

#define DbgSCP_ERR(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CHECK) \
		&& ((current->mm->context.pm_sc_debug_mode \
				& PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0)) \
		pr_err("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define DbgSCP_ALERT(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CHECK) \
		&& ((current->mm->context.pm_sc_debug_mode \
				& PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0)) \
		pr_alert("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define DbgSCP_WARN(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_CHECK) \
		&& ((current->mm->context.pm_sc_debug_mode \
				& PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0)) \
		pr_warn("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define PM_SYSCALL_WARN_ONLY \
		(arch_init_pm_sc_debug_mode(PROTECTED_MODE_SOFT))
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

#undef DbgSCP
#if defined(CONFIG_THREAD_INFO_IN_TASK) && defined(CONFIG_SMP)
#define DbgSCP(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("[%.3d#%d]: %s: " fmt, current->cpu, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)
#define DbgSCPanon(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("[%.3d#%d]: " fmt, current->cpu, current->pid, \
			##__VA_ARGS__); \
} while (0)
#else /* no 'cpu' field in 'struct task_struct' */
#define DbgSCP(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("%s [#%d]: %s: " fmt, current->comm, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)
#define DbgSCPanon(fmt, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("%s [#%d]: " fmt, current->comm, current->pid, \
			##__VA_ARGS__); \
} while (0)
#endif /* no 'cpu' field in 'struct task_struct' */

#undef PM_SYSCALL_WARN_ONLY
#define PM_SYSCALL_WARN_ONLY \
	(current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_WARN_ONLY)


#define PROTECTED_MODE_ALERT(MSG_ID, ...) \
do { \
	if (arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
		protected_mode_message(1, MSG_ID, ##__VA_ARGS__); \
} while (0)

#define PROTECTED_MODE_WARNING(MSG_ID, ...) \
do { \
	if ((arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
	    && IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS)) { \
		if (IF_PM_DBG_MODE(PM_SC_DBG_WARNINGS_AS_ERRORS)) { \
			protected_mode_message(1, MSG_ID, ##__VA_ARGS__); \
		} else { \
			protected_mode_message(2, MSG_ID, ##__VA_ARGS__); \
		} \
	} \
} while (0)

#define PROTECTED_MODE_MESSAGE(this_is_warning, MSG_ID, ...) \
do { \
	if (IF_PM_DBG_MODE(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0 \
	    && (!this_is_warning || IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS))) \
		protected_mode_message(0, MSG_ID, ##__VA_ARGS__); \
} while (0)

#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */


/* Protected mode diagnostic message ID's: */
enum pm_syscall_err_msg_id {
	PMSCERRMSG_ERR_ID,
	/* Syscall arg related messages: */
	PMSCERRMSG_UNEXP_ARG_TAG_ID,
	PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
	PMSCERRMSG_SC_ARGNAME_VAL_EXCEEDS_DSCR_MAX,
	PMSCERRMSG_SC_ARGNUM_VAL_EXCEEDS_DSCR_MAX,
	PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
	PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
	PMSCERRMSG_UNEXPECTED_DESCR_IN_SC_ARG,
	PMSCERRMSG_NOT_STRING_IN_SC_ARG,
	PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE,
	PMSCERRMSG_NEGATIVE_SIZE_VALUE,
	PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
	PMSCERRMSG_BAD_UNSUPP_VAL_IN_SC_ARG,
	PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
	PMSCERRMSG_SC_BAD_STRUCT_INT_FIELD,
	PMSCERRMSG_SC_NOT_FUNC_PTR_IN_ARG,
	PMSCERRMSG_SC_NOT_DESCR_IN_FIELD,
	PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,

	PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
	PMSCERRMSG_SC_BAD_FIELD_STRUCT_IN_ARG_NAME,
	PMSCERRMSG_SC_FAILED_TO_LOAD_LIBRARY,
	PMSCERRMSG_SC_BAD_ARG_VALUE,
	PMSCERRMSG_SC_ARG_SIZE_DIFFERS_STRUCT_SIZE,
	PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
	PMSCERRMSG_SC_FAILED_TO_UPDATE_STRUCT,
	PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
	PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
	PMSCERRMSG_SC_UNEXPECTED_ARG_VALUE,
	PMSCERRMSG_SC_CMD_WRONG_ARG_VALUE_LX,
	PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
	PMSCERRMSG_SC_ARG_VAL_UNSUPPORTED,
	PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
	PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,

	/* Structure analysis related messages: */
	PMSCERRMSG_STRUCT_UNALIGNED_DESCR,
	PMSCERRMSG_STRUCT_UNINIT_INT_FIELD,
	PMSCERRMSG_STRUCT_BAD_TAG_INT_FIELD,
	PMSCERRMSG_STRUCT_NOT_PL_IN_FIELD,
	PMSCERRMSG_STRUCT_NOT_DSCR_IN_FIELD,
	PMSCERRMSG_STRUCT_FAILED_TO_READ_FIELD,
	PMSCERRMSG_INSUFFICIENT_STRUCT_SIZE,

	/* convert_array related messages: */
	PMCNVSTRMSG_STRUCT_SIZE_EXCEEDS_MAX,
	PMCNVSTRMSG_STRUCT_DESCR_UNALIGNED,
	PMCNVSTRMSG_STRUCT_DOESNT_CONTAIN_DESCR,

	/* sigaltstack() related message: */
	PMSIGALTSTMSG_ERR_BOTH_SS_EMPTY,
	/* clean_descriptors related message: */
	PMCLNDSCRSMSG_WRONG_ARG_SIZE,
	PMCLNDSCRSMSG_EXITED_WITH_ERR,
	/* mmap() related messages: */
	PMMMAPMSG_ATTEMPT_TO_MAP_BYTES,
	PMMMAPMSG_CANT_MAP_OVER_2GB,
	PMMMAPMSG_CANT_REMAP_OVER_ALLOCATED,
	PMSCERRMSG_UNSUPPORTED_FLAG,
	/* mprotect() related message: */
	PMSCWARN_DSCR_PROT_MISMATCH,
	/* Other messages: */
	PMSCERRMSG_EMPTY_STRUCTURE_FIELD,
	PMSCERRMSG_COUNT_EXCEEDS_LIMIT,
	PMSCERRMSG_UNEXPECTED_FIELD_TAG,
	/* Warnings: */
	PMMMAPMSG_DSCR_WITHOUT_ACCESS_RIGHTS,
	PMSCWARN_SOCKETCALL_FAILED_TO_UPDATE_FLD,
	PMSCWARN_PROC_RETURNED_ERROR,
	PMSCWARN_TAGS_GET_LOST_WHEN_READ,
	PMSCWARN_NEGATIVE_DSCR_SIZE,
	PMSCWARN_ADDR_IN_SIGINFO,

	PMSCERRMSG_SC_NOT_AVAILABLE_IN_PM,
	PMSCERRMSG_FUNC_NOT_AVAILABLE_IN_PM,
	PMSCERRMSG_FATAL_READ_FROM,
	PMSCERRMSG_FATAL_READ_ERR_FROM,
	PMSCERRMSG_FATAL_WRITE_AT,
	PMSCERRMSG_FATAL_WRITE_AT_FIELD,
	PMSCERRMSG_FATAL_DESCR_IN_STACK,

	PMSCERRMSG_EXECUTION_TERMINATED,

	/* Comment messages: */
	PMSCERRMSG_SC_ARG_COUNT_TRUNCATED,
	PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT,
	PMSCERRMSG_STRUCT_FIELD_VAL_IGNORED,
	PMSCWARN_DSCR_COMPONENTS,

	/* read/write related message: */
	PMSCERRMSG_DSCR_WITHOUT_READ_PERM,
	PMSCERRMSG_DSCR_WITHOUT_WRITE_PERM,
	PMSCERRMSG_UNEXPECTED_TAG_IN_BUFF,

	/* NB> New messages to add above this line */

	/* Intro diagnostic messages: */
	PMSCERRMSG_RUNTIME_ERROR,
	PMSCERRMSG_RUNTIME_WARNING,

	/* Total message number: */
	PMSCERRMSG_NUMBER,
};
#define PMSCERRMSG_FINAL PMSCERRMSG_EXECUTION_TERMINATED

extern char const **protected_error_list;


static inline
void __user *arch_protected_alloc_user_data_stack(unsigned long len)
{
	 /* Make sure the resulting pointer is properly aligned */
	len = round_up(len, sizeof(e2k_ptr_t));

	return e2k_alloc_user_data_stack(len);
}

#if KERNEL_VERSION(5, 11, 0) <= LINUX_VERSION_CODE
#define __get_user_space(x)	arch_protected_alloc_user_data_stack(x)
#else /* LINUX_VERSION_CODE < [5.11] */
extern void __user *arch_alloc_protected_user_space(unsigned long len,
					const int reserve_space_4_diag_msgs);
#define __get_user_space(x)	arch_alloc_protected_user_space(x, 1)
#endif /* LINUX_VERSION_CODE */


/* NB> 'n' below is syscall argument number;
 *     'i' - is register number.
 */
#define PROT_SC_ARG_TAGS(n)	((regs->tags >> 8*(n)) & 0xff)
#define NOT_PTR(n)	(PROT_SC_ARG_TAGS(n) != ETAGAPQ)
#define NULL_PTR(n, i) ((((regs->tags >> (8*(n))) & 0xf) == E2K_NULLPTR_ETAG) \
							&& (arg##i == 0))
/* Descriptor structure size is sizeof(void *) in the protected mode: */
#define DESCRIPTOR_SIZE        sizeof(e2k_ptr_t)


extern void pm_deliver_exception(int signo, int code, int errno) __cold;
extern void pm_deliver_sig_bnderr(int argno, const struct pt_regs *regs) __cold;

extern int get_prot_sigevent(sigevent_t *k, const struct prot_sigevent __user *u, size_t sz,
			     const int arg_num, const struct pt_regs *regs);


/* If running in the orthodox protected mode, deliver exception to break execution: */
#define PM_EXCEPTION_IF_ORTH_MODE(signo, code, errno) \
do { \
	if (PM_SYSCALL_WARN_ONLY == 0) \
		pm_deliver_exception(signo, code, errno); \
} while (0)

/* Ditto for warnings: */
#define PM_EXCEPTION_ON_WARNING(signo, code, errno) \
do { \
	if ((PM_SYSCALL_WARN_ONLY == 0) && IF_PM_DBG_MODE(PM_SC_DBG_WARNINGS_AS_ERRORS)) \
		pm_deliver_exception(signo, code, errno); \
} while (0)

#define PM_BNDERR_EXCEPTION_IF_ORTH_MODE(arg_num, regs) \
do { \
	if (PM_SYSCALL_WARN_ONLY == 0) \
		pm_deliver_sig_bnderr(arg_num, regs); \
} while (0)

/* Ditto for warnings: */
#define PM_BNDERR_EXCEPTION_ON_WARNING(arg_num, regs) \
do { \
	if ((PM_SYSCALL_WARN_ONLY == 0) && IF_PM_DBG_MODE(PM_SC_DBG_WARNINGS_AS_ERRORS)) \
		pm_deliver_sig_bnderr(arg_num, regs); \
} while (0)


/**************************** END of DEBUG DEFINES ***********************/

/* Delivering diagnostic messages that protected mode issues:
 * header_type: 0 - no header; 1 - error header; 2 - warning header.
 */
extern void protected_mode_message(int header_type,
				   enum pm_syscall_err_msg_id MSG_ID, ...) __cold;



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
	ptr.lo = low;
	return ptr.itag;
}

static inline
int e2k_ptr_rw(long low)
{
	e2k_ptr_t ptr;
	ptr.lo = low;
	return ptr.rw;
}

static inline
unsigned long e2k_ptr_ptr(u64 low, u64 hiw, unsigned int min_size)
{
	e2k_ptr_t ptr;
	int ptr_size;

	ptr.lo = low;
	ptr.hi = hiw;
	ptr_size = ptr.size - ptr.curptr;

	if (ptr_size < min_size) {
		DbgSCP_ALERT("  Pointer is too small: %d < %d\n",
			     ptr_size, min_size);
		return 0;
	} else {
		return ptr.base + ptr.curptr;
	}
}

static inline
int e2k_ptr_curptr(u64 low, u64 hiw)
{
	e2k_ptr_t ptr;

	ptr.lo = low;
	ptr.hi = hiw;
	return ptr.curptr;
}

static inline
unsigned int e2k_ptr_size(u64 low, u64 hiw, unsigned int min_size)
{
	e2k_ptr_hi_t hi;
	int ptr_size;

	hi.word = hiw;
	ptr_size = hi.size - hi.curptr;
	if (unlikely(ptr_size < min_size)) {
		DbgSCP_ALERT("  Pointer is too small: %d < %d\n",
			     ptr_size, min_size);
		return 0;
	} else {
		return ptr_size;
	}
}

static inline bool e2k_ptr_str_check(char __user *str, u64 max_size)
{
	long slen;

	slen = strnlen_user(str, max_size);

	if (unlikely(!slen || slen > max_size))
		return true;

	return false;
}

static inline char __user *e2k_ptr_str(long low, long hiw)
{
	char __user *str;
	e2k_ptr_hi_t hi = { .word = hiw };

	str = (char __user *) __E2K_PTR_PTR(low, hiw);

	if (!e2k_ptr_str_check(str, hi.size - hi.curptr))
		return str;

	return NULL;
}


static inline long  ptr128_2_ptr64(long __user *pdescr)
/* extracts and returns pointer from the given descriptor.
 * returns 0 if 'pdescr' is not pointer to descriptor;
 * returns -EFAULT if bad address.
 */
{
	e2k_ptr_t descr, pdcopy;
	int tag = 0;

	if (copy_from_user_with_tags(&pdcopy, pdescr, 16) != 0) {
		DbgSCP_ALERT("%s failed with pdescr == 0x%lx\n", __func__, pdescr);
		return -EFAULT;
	}


	if ((tag != ETAGAPQ))
		return 0;

	return descr.base + descr.curptr;
}

static inline int this_is_descriptor(long __user *pdescr, const int ret_val_zero)
/* extracts and returns pointer from the given descriptor.
 * if pdescr is empty, return ret_val_zero.
 * returns 1 if 'pdescr' is pointer to descriptor; 0 - otherwise.
 * returns -EFAULT if bad address.
 */
{
	e2k_ptr_t descr;
	int tag;
	if (get_user_tagged_16(descr.lo, descr.hi, tag, pdescr)) {
		DbgSCP_ALERT("%s failed with pdescr == 0x%lx\n", __func__, pdescr);
		return -EFAULT;
	}

	if (ret_val_zero) {
		return (tag == ETAGNPQ) && !descr.lo;
	}
	return (tag == ETAGAPQ);
}

#define CHECK4DESCR_SILENT	0
#define CHECK4DESCR_WARNING	1
#define CHECK4DESCR_ERROR	2
static inline int warn_if_not_descr(const int		n,
				    const int		exception, /* _WARNING/_ERROR */
				const struct pt_regs	*regs)
{
	if (NOT_PTR(n)) {
		if (exception == CHECK4DESCR_ERROR) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], n);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
		} else if (exception) { /* this is warning */
			PROTECTED_MODE_WARNING(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], n);
			if (exception)
				PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
		}
		return 1;
	}
	return 0;
}


/* Returns 1 if 'size' exceeds max allowed descriptor size; 0 - otherwise */
static inline int size_exceeds_descr_max_capacity(const size_t size,
					   const char *arg_name,
					   const size_t arg_val,
					   const struct pt_regs *regs)
{
	if (size >> 31) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGNAME_VAL_EXCEEDS_DSCR_MAX,
			regs->sys_num, sys_call_ID_to_name[regs->sys_num], arg_val, arg_name);
		return 1;
	}
	return 0;
}


#define THIS_IS_DESCRIPTOR(pdescr) this_is_descriptor(pdescr, 0)
#define THIS_IS_ZERO_DESCRIPTOR(pdescr) this_is_descriptor(pdescr, 1)


static inline
char *strcopy_from_user_prot_arg(const char __user	*ufilename,
				 const struct pt_regs	*regs,
				 const int		arg_num)
{
	char *kfilename; /* copy of the given user string in the kernel space */
	int fname_size;
	long copied;
#define PATH_LIMIT 128

	fname_size = e2k_ptr_size(regs->args[arg_num * 2 - 1], regs->args[arg_num * 2], 0);
	if (!fname_size)
		return NULL;
	if (fname_size > PATH_LIMIT)
		fname_size = PATH_LIMIT;
	kfilename = kmalloc(fname_size, GFP_KERNEL);
	if (!kfilename)
		return NULL;
	copied = strncpy_from_user(kfilename, ufilename, fname_size - 1);
	if (unlikely(!copied)) {
		kfree(kfilename);
		return NULL;
	}
	kfilename[copied] = '\0';
	return kfilename;
}

/* 'arg64_from_regs' translates couple of protected syscall args into single regular one.
 * 'arg_num' - is natural arg number (i.e. first arg number is '1', and not '0').
 */
static inline
unsigned long arg64_from_regs(const struct pt_regs	*regs,
			      const int			arg_num)
{
	u8 tag = (regs->tags >> (arg_num * 8)) & 0xff;

	if (tag == ETAGAPQ)
		return e2k_ptr_ptr(regs->args[arg_num * 2 - 1], regs->args[arg_num * 2], 0);
	else
		return regs->args[arg_num * 2 - 1];
}

#else /* #ifndef CONFIG_PROTECTED_MODE */

#define DbgSCP(...)
#define DbgSC_ERR(...)
#define DbgSC_WARN(...)
#define DbgSC_ALERT(...)

#endif /* CONFIG_PROTECTED_MODE */


#endif /* _E2K_PROTECTED_SYSCALLS_H_ */

