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
#include <linux/eventpoll.h>
#include "asm/syscalls.h"
#include <asm/protected_mode.h>
#include <asm/protected_diag_msg_ids.h>

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
#else
#define DbgSC_ERR(...)
#define DbgSC_WARN(...)
#endif /* DEBUG_SYSCALLP_CHECK */

#define PROTECTED_MODE_ERROR(...)
#define PROTECTED_MODE_WARNING(...)
#define PROTECTED_MODE_WARN_ONCE(...)
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


#define PROTECTED_MODE_ERROR(MSG_ID, ...) \
do { \
	if (check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
		protected_mode_message(1, MSG_ID, ##__VA_ARGS__); \
} while (0)

#define PROTECTED_MODE_ERR_ONCE(MSG_ID, ...) \
do { \
	if (!__test_and_set_bit(MSG_ID, current->mm->context.pm_sc_warned_once_msgs)) \
		PROTECTED_MODE_ERROR(MSG_ID, ##__VA_ARGS__); \
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

#define PROTECTED_MODE_WARN_ONCE(MSG_ID, ...) \
do { \
	if ((check_pm_sc_debug_mode(PM_SC_DBG_MODE_NO_ERR_MESSAGES) == 0) \
				&& IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS)) { \
		if (!__test_and_set_bit(MSG_ID, current->mm->context.pm_sc_warned_once_msgs)) { \
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
int prot_sc_arg_is_ap(const int arg_num, const struct pt_regs *regs)
{
	return IS_AP(regs->qargs[arg_num - 1], prot_sc_arg_tag(arg_num, regs));
}
static inline
int prot_sc_arg_not_ptr(const int arg_num, const struct pt_regs *regs)
{
	return !prot_sc_arg_is_ap(arg_num, regs);
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
	if ((PM_SYSCALL_WARN_ONLY == 0) || IF_PM_DBG_MODE(PM_SC_DBG_WARNINGS_AS_ERRORS)) \
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
	if ((PM_SYSCALL_WARN_ONLY == 0) || IF_PM_DBG_MODE(PM_SC_DBG_WARNINGS_AS_ERRORS)) \
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
	char __user *str = (char __user __force *) AP_PTR(ap);

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
		DbgSCP_ERR("%s failed with pdescr == 0x%px\n", __func__, pdescr);
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
		DbgSCP_ERR("%s failed with pdescr == 0x%px\n", __func__, pdescr);
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
				    const int		msg_type, /* _WARNING/_ERROR */
				    const struct pt_regs	*regs)
{
	int tags;

	if (!prot_sc_arg_not_ptr(n, regs))
		return 0;
	else if (!msg_type)
		return 1;

	tags = prot_sc_arg_tag(n, regs);

	if (tags & 0x3) {
		if ((tags & 0x3) == ETAGEWS)
			PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT, n);
		else
			PROTECTED_MODE_WARNING(PMSCERRMSG_UNEXP_ARG_TAG_ID,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], tags, n);
	}

	if (msg_type == CHECK4DESCR_ERROR) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num], n);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
	} else { /* this is warning */
		PROTECTED_MODE_WARNING(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				       regs->sys_num, sys_call_ID_to_name[regs->sys_num], n);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
	}

	return 1;
}


/**
 * size_exceeds_descr_max_capacity() - Checks if 'size' exceeds max allowed descriptor size.
 * @size: value to check.
 * @arg_name: syscall argument name for error message.
 * @arg_val: argument value - this is either same as 'size' or
 *		 multiplicator for array of items if it's too big.
 * @regs: 'pt_regs' structure (syscall context).
 *
 * Return: 1 (true) if 'size' exceeds max allowed descriptor size; 0 - otherwise.
 */
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
	PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGNAME_VAL_EXCEEDS_DSCR_MAX,
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
	PROTECTED_MODE_ERROR(PMSCERRMSG_DSCR_WITHOUT_READ_PERM,
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

	PROTECTED_MODE_ERROR(PMSCERRMSG_DSCR_WITHOUT_WRITE_PERM,
			     sys_call_ID_to_name[regs->sys_num], arg_num);
	return 0;
}

extern int add_2_prot_epoll_descr_bt(int epfd, u64 addr, e2k_ptr_t descr);
extern int fill_user_descr_in_prot_epoll_events(int epfd,
					 struct prot_epoll_event __user *events_128,
					 const int count);

#else /* #ifndef CONFIG_PROTECTED_MODE */

#define DbgSCP(...)		do { } while (0)
#define DbgSC_ERR(...)		do { } while (0)
#define DbgSC_WARN(...)		do { } while (0)

#define PM_EXCEPTION_ON_WARNING(...)	do { } while (0)
#define PROTECTED_MODE_ERROR(...)	do { } while (0)
#define PROTECTED_MODE_WARNING(...)	do { } while (0)
#define PROTECTED_MODE_MESSAGE(...)	do { } while (0)

static inline unsigned long arg64_from_regs(const struct pt_regs *regs, int arg_num)
{
	return regs->dargs[arg_num];
}

#endif /* CONFIG_PROTECTED_MODE */


#endif /* _E2K_PROTECTED_SYSCALLS_H_ */

