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
#include <asm/mman.h>
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

static inline
int check_pm_sc_debug_mode(const int debug_mask)
{
	return current->mm->context.pm_sc_debug_mode & debug_mask;
}

#define DbgSCP_ERR(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
		pr_err("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define DbgSCP_ALERT(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
		pr_alert("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define DbgSCP_WARN(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
		pr_warn("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#define PM_SYSCALL_WARN_ONLY \
		(check_pm_sc_debug_mode(PROTECTED_MODE_SOFT))
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


#define PROTECTED_MODE_ALERT(MSG_ID, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
		protected_mode_message(1, MSG_ID, ##__VA_ARGS__); \
} while (0)

#define PM_SC_DBG_MODE_MSG_TYPE_INFO		0
#define PM_SC_DBG_MODE_MSG_TYPE_ERROR           1
#define PM_SC_DBG_MODE_MSG_TYPE_WARNING		2
#define PM_SC_DBG_MODE_MSG_TYPE_PWARNING	3 /* maybe programmer's error */

#define PROTECTED_MODE_WARNING(MSG_ID, ...) \
do { \
	if ((check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
	    && IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS)) { \
		if (IF_PM_DBG_MODE(PM_SC_DBG_WARNINGS_AS_ERRORS)) { \
			protected_mode_message(PM_SC_DBG_MODE_MSG_TYPE_ERROR, \
						MSG_ID, ##__VA_ARGS__); \
		} else { \
			protected_mode_message(PM_SC_DBG_MODE_MSG_TYPE_WARNING, \
						MSG_ID, ##__VA_ARGS__); \
		} \
	} \
} while (0)

#define PROTECTED_MODE_PWARNING(MSG_ID, ...) \
do { \
	if ((check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
				&& IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS)) { \
		protected_mode_message(PM_SC_DBG_MODE_MSG_TYPE_PWARNING, \
					MSG_ID, ##__VA_ARGS__); \
	} \
} while (0)

#define PROTECTED_MODE_MESSAGE(this_is_warning, MSG_ID, ...) \
do { \
	if (IF_PM_DBG_MODE(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0 \
	    && (!this_is_warning || IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS))) \
		protected_mode_message(0, MSG_ID, ##__VA_ARGS__); \
} while (0)


#undef DbgSCP
#if defined(CONFIG_THREAD_INFO_IN_TASK) && defined(CONFIG_SMP)
#define DbgSCP(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("[%.3d#%d]: %s: " fmt, current_thread_info()->cpu, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)
#define DbgSCPanon(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("[%.3d#%d]: " fmt, current_thread_info()->cpu, current->pid, \
			##__VA_ARGS__); \
} while (0)
#else /* no 'cpu' field in 'struct task_struct' */
#define DbgSCP(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("%s [#%d]: %s: " fmt, current->comm, current->pid, \
				__func__,  ##__VA_ARGS__); \
} while (0)
#define DbgSCPanon(fmt, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) \
		pr_info("%s [#%d]: " fmt, current->comm, current->pid, \
			##__VA_ARGS__); \
} while (0)
#endif /* no 'cpu' field in 'struct task_struct' */

#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */

/*
 * Protected mode diagnostic message ID's:
 * NB> Add new messages at the bottom of the array only !!!
 *	ID's are fixed as these are used in qualification tests.
 */
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
	PMSCERRMSG_SC_UNEXPECTED_FUNC_IN_ARG,
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
	PMSCERRMSG_CUI_NOT_FOUND,
	PMSCERRMSG_CUI_MISMATCH_IN_PL_IP,

	PMSCERRMSG_SC_NOT_DSCR_TAG_STRCT_FLD_VAL,
	PMSCERRMSG_SC_NOT_YET_SUPPORTED_IN_PM,
	PMSCERRMSG_SC_BRK_NON_ZERO_ARG_IN_PM,

	/* iset-specific messages: */
	/* __iset__ >= 6 */
	PMSCWARN_MMAP_SHARED_FLAG,

	/* MISC: */
	PMSCWARN_UNALIGNED_PL_IN_ARG,
	PMSCERRMSG_SC_NOT_ENABLED,
	PMSCWARN_UNALIGNED_DSCR_IN_ARG,
	PMSCERRMSG_SC_ALLOWED_IN_SOFT_MODE,

	/* NB> New messages to add above this line */
	/* Unclassified */ PMSCERRMSG_FILLING_FREED_MEM_BLOCKED,
	/* Unclassified */ PMSCERRMSG_FILLING_FREED_MEM_IN_NON_HM,

	/* Intro diagnostic messages: */
	PMSCERRMSG_RUNTIME_ERROR,
	PMSCERRMSG_RUNTIME_WARNING,
	PMSCERRMSG_RUNTIME_PWARNING,

	/* Total message number: */
	PMSCERRMSG_NUMBER,

};
#define PMSC_NO_ID_ERRMSG_START1 PMSCERRMSG_EXECUTION_TERMINATED
#define PMSC_NO_ID_ERRMSG_FINAL1 PMSCERRMSG_CUI_MISMATCH_IN_PL_IP
#define PMSC_NO_ID_ERRMSG_START2 PMSCERRMSG_RUNTIME_ERROR
#define PMSC_NO_ID_ERRMSG_FINAL2 PMSCERRMSG_NUMBER


extern char const **protected_error_list;


/* Delivering diagnostic messages that protected mode issues:
 * header_type: 0 - no header; 1 - error header; 2 - warning header.
 */
extern void protected_mode_message(int header_type,
				   enum pm_syscall_err_msg_id MSG_ID, ...) __cold;

extern ssize_t protected_mode_write_to_current_stderr(const char *message, size_t msglen);

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


/* NB> 'arg_num' below is syscall argument number as it is in glibc wrappers. */
/* NB> 'arg_num' is natural number (starts with '1', not '0') */
static inline
int prot_sc_arg_tag(const int arg_num, const struct pt_regs *regs)
{
	int tags = (regs->tags >> (8 * arg_num)) & 0xff;

	if (!(tags & 0xf0)) /* argument looks like of integral type */
		return tags;

	/* Check if there is trash in the 'hi' part of the argument: */
	return (tags & 0xf) ? tags : 0;
}
static inline
int prot_sc_arg_not_ptr(const int arg_num, const struct pt_regs *regs)
{
	return !IS_AP(regs->qargs[arg_num - 1], prot_sc_arg_tag(arg_num, regs));
}
static inline
int prot_sc_arg_is_ap(const int arg_num, const struct pt_regs *regs)
{
	return IS_AP(regs->qargs[arg_num - 1], prot_sc_arg_tag(arg_num, regs));
}
static inline
int prot_sc_arg_NULL_ptr(const int arg_num, const struct pt_regs *regs)
{
	return (((regs->tags >> (8*(arg_num))) & 0xf) == E2K_NULLPTR_ETAG) \
					&& (regs->dargs[2 * (arg_num - 1)] == 0);
}

/* Descriptor structure size is sizeof(void *) in the protected mode: */
#define DESCRIPTOR_SIZE        sizeof(e2k_ptr_t)


extern void pm_deliver_exception(int signo, int code, int errno) __cold;
extern void pm_deliver_sig_bnderr(int argno, const struct pt_regs *regs) __cold;

extern int get_prot_sigevent(sigevent_t *k, const struct prot_sigevent __user *u, size_t sz,
			     const int arg_num, const struct pt_regs *regs);

typedef unsigned long (*protected_system_call_func)(unsigned long arg1,
			unsigned long arg2, unsigned long arg3, unsigned long arg4,
			unsigned long arg5, unsigned long arg6, struct pt_regs *regs);

extern const protected_system_call_func sys_call_table_entry8[NR_syscalls];

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


static __always_inline
unsigned long e2k_ptr_objptr(e2k_ap_t p, unsigned long min_size)
{
	if (min_size && min_size > AP_OBJ_SIZE(p))
		return 0;

	return AP_PTR(p);
}

static inline bool e2k_ptr_str_check(char __user *str, u64 max_size)
{
	long slen;

	if (unlikely(str == NULL))
		return false;
	str = untagged_addr(str);
	slen = strnlen_user(str, max_size);

	if (unlikely(slen > max_size))
		return true;

	return false;
}

static inline char __user *e2k_ptr_str(e2k_ap_t ap)
{
	char __user *str = (char __user *) AP_PTR(ap);

	if (!e2k_ptr_str_check(str, AP_OBJ_SIZE(ap)))
		return str;

	return NULL;
}


static inline long  ptr128_2_ptr64(long __user *pdescr)
/* extracts and returns pointer from the given descriptor.
 * returns 0 if 'pdescr' is not pointer to descriptor;
 * returns -EFAULT if bad address.
 */
{
	e2k_ptr_t descr;
	int tag;

	if (get_user_tagged_16(descr.qword, tag, pdescr)) {
		DbgSCP_ALERT("%s failed with pdescr == 0x%px\n", __func__, pdescr);
		return -EFAULT;
	}

	if (unlikely(!IS_AP(descr, tag)))
		return 0;

	return AP_PTR(descr);
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

	if (get_user_tagged_16(descr.qword, tag, pdescr)) {
		DbgSCP_ALERT("%s failed with pdescr == 0x%px\n", __func__, pdescr);
		return -EFAULT;
	}

	if (ret_val_zero) {
		return (tag == ETAGNPQ) && !descr.lo;
	}
	return IS_AP(descr, tag);
}

#define CHECK4DESCR_SILENT	0
#define CHECK4DESCR_WARNING	1
#define CHECK4DESCR_ERROR	2
static inline int warn_if_not_descr(const int		n,
				    const int		exception, /* _WARNING/_ERROR */
				const struct pt_regs	*regs)
{
	if (prot_sc_arg_not_ptr(n, regs)) {
		int tags = exception ? prot_sc_arg_tag(n, regs) : 0;

		if ((tags & 0x3) && (tags & 0x3) != ETAGEWD)
			PROTECTED_MODE_WARNING(PMSCERRMSG_UNEXP_ARG_TAG_ID,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], tags, n);

		if (exception == CHECK4DESCR_ERROR) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], n);
			if ((tags & 0x3) == ETAGEWD)
				PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT, n);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
		} else if (exception) { /* this is warning */
			PROTECTED_MODE_WARNING(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], n);
			if ((tags & 0x3) == ETAGEWD)
				PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT, n);
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
	if (cpu_has(CPU_FEAT_V7_CPU_REGS)) {
		if (size < E2K_VA_END) {
			return 0;
		}
	} else {
		if (!(size >> 31)) {
			return 0;
		}
	}
	PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGNAME_VAL_EXCEEDS_DSCR_MAX,
		regs->sys_num, sys_call_ID_to_name[regs->sys_num], arg_val, arg_name);
	return 1;
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

	fname_size = AP_OBJ_SIZE(regs->qargs[arg_num - 1]);
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
		return AP_PTR(regs->qargs[arg_num - 1]);
	else
		return regs->qargs[arg_num - 1].lo;
}


static inline
int prot_arg_is_ap(const struct pt_regs *regs,
		   int arg_num) /* argument # in syscall */
/* Checks that argument #argnum is descriptor: */
{
	int tag = (regs->tags >> (arg_num * 8)) & 0xff;

	return (tag == ETAGAPQ);
}

static inline
int prot_arg_is_int(const struct pt_regs *regs,
		    int arg_num) /* argument # in syscall */
/* Checks that argument #argnum is of type 'int': */
{
	int tag = (regs->tags >> (arg_num * 8)) & 0xff;

	return ((tag & 3) == 0);
}


/* Here we check that descriptor specified in argument #arg_num is read-able: */
static inline
int check_buffer_is_readable(const struct pt_regs	*regs,
			     const int			arg_num)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		if (regs->qargs[arg_num - 1].rw_v7 & PROT_READ)
			return 1;
	} else {
		if (regs->qargs[arg_num - 1].rw_v6 & PROT_READ)
			return 1;
	}
	PROTECTED_MODE_ALERT(PMSCERRMSG_DSCR_WITHOUT_READ_PERM,
			     sys_call_ID_to_name[regs->sys_num], arg_num);
	return 0;
}

/* Here we check that descriptor specified in argument #arg_num is write-able: */
static inline
int check_buffer_is_writeable(const struct pt_regs	*regs,
			      const int			arg_num)
{
	if (cpu_has(CPU_FEAT_ISET_V7)) {
		if (regs->qargs[arg_num - 1].rw_v7 & PROT_WRITE)
			return 1;
	} else {
		if (regs->qargs[arg_num - 1].rw_v6 & PROT_WRITE)
			return 1;
	}

	PROTECTED_MODE_ALERT(PMSCERRMSG_DSCR_WITHOUT_WRITE_PERM,
			     sys_call_ID_to_name[regs->sys_num], arg_num);
	return 0;
}

#else /* #ifndef CONFIG_PROTECTED_MODE */

#define DbgSCP(...)		do { } while (0)
#define DbgSC_ERR(...)		do { } while (0)
#define DbgSC_WARN(...)		do { } while (0)
#define DbgSC_ALERT(...)	do { } while (0)

#define PM_EXCEPTION_ON_WARNING(...)	do { } while (0)
#define PROTECTED_MODE_ALERT(...)	do { } while (0)
#define PROTECTED_MODE_WARNING(...)	do { } while (0)
#define PROTECTED_MODE_MESSAGE(...)	do { } while (0)

static inline unsigned long arg64_from_regs(const struct pt_regs *regs, int arg_num)
{
	return regs->dargs[arg_num];
}

#endif /* CONFIG_PROTECTED_MODE */


#endif /* _E2K_PROTECTED_SYSCALLS_H_ */

