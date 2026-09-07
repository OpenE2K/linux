/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is implementation of system call handlers for E2K protected mode:
 *	int protected_sys_<syscallname>(const long a1, ... a6,
 *					const struct pt_regs *regs);
 */

#include "linux/export.h"
#include <linux/syscalls.h>
#include <asm/e2k_debug.h>

#include <asm/mman.h>
#include <asm/convert_array.h>
#include <asm/prot_loader.h>
#include <asm/syscalls.h>
#include <asm/shmbuf.h>
#include <asm/prot_compat.h>

#include <linux/eventpoll.h>
#include <linux/fdtable.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/keyctl.h>
#include <linux/prctl.h>
#include <linux/if.h>

#include <linux/msg.h>
#include <linux/mqueue.h>
#include <uapi/linux/io_uring.h>
#include <uapi/linux/sched/types.h>
#include <linux/kexec.h>
#include <linux/types.h>

#ifdef CONFIG_PROTECTED_MODE

#include <asm/protected_syscalls.h>

/*
 * pm_abort_exception() - Terminates execution of the current thread.
 * @errno: error number  to report.
 *
 * Return: nothing to return.
 */
static void pm_abort_execution(int errno)
{
	PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_EXECUTION_TERMINATED,
			       current->pid, current->comm, errno);
	force_sig(SIGABRT);
}

/*
 * pm_deliver_exception() - Delivers exception to end up execution of the current thread.
 * @signo: signal to deliver.
 * @code: this is for 'si_code' field of struct kernel_siginfo.
 * @errno: error number  to report or EINVAL if (signo == SIGABRT).
 *
 * Return: nothing to return.
 */
void pm_deliver_exception(int signo, int code, int errno)
{
	struct kernel_siginfo info;
	int ret;

	if (signo == SIGABRT) {
		/* NB> It might be good idea to deliver 'errno' over here but
		 *     we intentionally deliver 'EINVAL' instead because of
		 *     experiment showed up that many LTP protected tests
		 *     expected EINVAL code in this case.
		 *     If 'errno' delivered, we would have to add more wrappers for prot.syscalls.
		 */
		PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_EXECUTION_TERMINATED,
				       current->pid, current->comm, EINVAL);
		force_sig(SIGABRT);
		return;
	}

	/* Deliver exception: */
	clear_siginfo(&info);
	info.si_signo = signo;	/* f.e. SIGILL */
	info.si_code = code;	/* f.e. ILL_ILLOPN - "illegal operand" */
	info.si_errno = errno;	/* f.e. -EINVAL */

	ret = force_sig_info(&info);
	if (ret)
		pr_alert("%s:%d : force_sig_info(signo=%d) failed with error %d\n",
			 __FILE__, __LINE__, signo, ret);
}

void pm_deliver_sig_bnderr(const int arg_num,
			   const struct pt_regs *regs)
{
	e2k_ap_t ptr = regs->qargs[arg_num - 1];

	PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_EXECUTION_TERMINATED,
			       current->pid, current->comm, EINVAL);

	force_sig_bnderr(U_AP_PTR(ptr), (void __user __force *)AP_BASE(ptr),
			 (void __user __force *)AP_BASE(ptr) + AP_SIZE(ptr));
}


static void __user *get_user_space(unsigned long len)
{
	void __user *uspace;
	long ret;

	uspace = __get_user_space(len);
	if (!uspace) {
		pr_alert("%s:%d : %s() failed to allocate %lu bytes of user stack\n",
			 __FILE__, __LINE__, __func__, len);
		pm_deliver_exception(SIGABRT, SI_KERNEL, ENOMEM);
		return NULL;
	}
	ret = clear_user(uspace, len);
	if (ret) {
		pr_alert("%s() failed to clear %lu bytes at %s:%d\n",
			 __func__, ret, __FILE__, __LINE__);
		pm_deliver_exception(SIGABRT, SI_KERNEL, EFAULT);
		return NULL;
	}

	return uspace;
}

/*
 * Counts the number of descriptors in array, which is terminated by NULL
 * (For counting of elements in argv and envp arrays)
 * NB> Final NULL descriptor is not accounted !
 */
notrace __section(".entry.text")
static int count_descriptors(const long __user *prot_array, const int prot_array_size)
{
	int i;
	long tmp[1];

	if (prot_array == NULL)
		return 0;

	/* Ensure that protected array is aligned and sized properly */
	if (!IS_ALIGNED((unsigned long) prot_array, sizeof(e2k_ptr_t)))
		return -EINVAL;

	/* Read each entry */
	for (i = 0; 8 * i + sizeof(e2k_ptr_t) <= prot_array_size; i += 2) {
		long lo;
		int ltag;

		if (copy_from_user_tagged(tmp, &prot_array[i], sizeof(e2k_ptr_t)))
			return -EFAULT;

		NATIVE_LOAD_VAL_AND_TAGD(tmp, lo, ltag);

		/* If zero is met, it is the end of array.
		 * NB> Rear user makes difference between zero and NULL.
		 *	It may happen input array end up with zero, not NULL.
		 *	Therefore we're looking for the first 0x0L in the array.
		 */
		if (lo == 0 && ltag == 0)
			return i / 2;
	}

	return -EINVAL;
}


static inline
int check_pm_sc_debug_feature(const int debug_mask)
{
	return current->mm->context.pm_sc_debug_mode & debug_mask;
}


/**
 * print_prot_message() - Prints diagnostic messages.
 *
 * @msg_status: PM_SC_DBG_MODE_MSG_TYPE_INFO/ERROR/WARNING/PWARNING.
 * @message: message to print.
 */
static inline
void print_prot_message(const int msg_status, const char *message)
{
	switch (msg_status) {
	case PM_SC_DBG_MODE_MSG_TYPE_INFO:
		pr_info("%s", message);
		break;
	case PM_SC_DBG_MODE_MSG_TYPE_ERROR:
		pr_err("%s", message);
		break;
	case PM_SC_DBG_MODE_MSG_TYPE_WARNING:
	case PM_SC_DBG_MODE_MSG_TYPE_PWARNING:
		pr_warn("%s", message);
		break;
	default:
		pr_err("%s:%d : unknown messafe type in %s(%d, ...)\n",
				__FILE__, __LINE__, __func__, msg_status);
		pr_notice("%s", message);
		break;
	}
}

/**
 * protected_mode_write_to_current_stderr() - Write a string to the current's stderr.
 * @message: Text to write.
 *
 * Return: Number of bytes written.
 */
ssize_t protected_mode_write_to_current_stderr(const char *message, size_t msglen)
{
	struct file *fstderr = fget(2);

	if (!fstderr) {
		pr_err_ratelimited("%s:%d : kernel_write(fstderr, 0x%px, %zd) - could not write to stderr since it is not available\n",
				__FILE__, __LINE__, &message, msglen);
		return -EBADF;
	}

	ssize_t ret = kernel_write(fstderr, message, msglen, NULL);
	fput(fstderr);

	if (ret == -ERESTARTSYS || ret == -ERESTARTNOINTR ||
	    ret == -ERESTARTNOHAND || ret == -ERESTART_RESTARTBLOCK) {
		/* Write to tty will not go through anyway
		 * if signal_pending() so just return - we
		 * will get here again after syscall restart. */
	} else if (ret <= 0 &&
		   check_pm_sc_debug_feature(PM_SC_DBG_WARNINGS)) {
		pr_err("%s:%d : kernel_write(2, 0x%px, %zd) failed with error code (%ld)\n",
				__FILE__, __LINE__, &message, msglen, ret);
	} else if (ret < msglen) {
		pr_err("%s:%d : kernel_write(2, 0x%px, %zd) failed; %ld of %zd bytes written\n",
				__FILE__, __LINE__, &message, msglen, ret, msglen);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(protected_mode_write_to_current_stderr);

/**
 * issue_prot_message_vl() - Delivers diagnostic messages that protected arg control issues.
 *
 * @msg_status: PM_SC_DBG_MODE_MSG_TYPE_INFO/ERROR/WARNING/PWARNING.
 * @MSG_ID: message ID (f.e. PMSCERRMSG_UNEXP_ARG_TAG_ID).
 * @fmt: message print format that follows with arguments.
 */
static
int issue_prot_message_vl(const int msg_status, const int msg_ID,
			  const char *fmt, va_list argptr)
{
#define MSG_BUFF_SIZE 512
	char message[MSG_BUFF_SIZE];
	int ret = 0;

	message[0] = '\0';
	if (!msg_ID ||
		(msg_ID >= PMSC_NO_ID_ERRMSG_START1 && msg_ID <= PMSC_NO_ID_ERRMSG_FINAL1) ||
		(msg_ID >= PMSC_NO_ID_ERRMSG_START2 && msg_ID <= PMSC_NO_ID_ERRMSG_FINAL2)) {
		/* no error ID required */
		ret = vsnprintf(message, MSG_BUFF_SIZE, fmt, argptr);
	} else { /* adding error ID to the message */
		char *msg_id_text = (msg_status == PM_SC_DBG_MODE_MSG_TYPE_ERROR) ? "[ePM#%d] "
				: ((msg_status == PM_SC_DBG_MODE_MSG_TYPE_INFO) ? "[iPM#%d] "
				: "[wPM#%d] ");

		ret = snprintf(message, MSG_BUFF_SIZE, msg_id_text, msg_ID);
		if (ret > 0)
			ret = vsnprintf(&message[ret], MSG_BUFF_SIZE - ret, fmt, argptr);
	}
	if (ret <= 0) {
		pr_err("%s:%d : %s//vsprintf() failed with error code (%d)\n",
			       __FILE__, __LINE__, __func__, ret);
		return ret;
	}

	if (check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_JOURNAL))
		print_prot_message(msg_status, message);

	if (check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_STDERR)) {
		if (protected_mode_write_to_current_stderr(message, strlen(message)) &&
		    check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_JOURNAL) == 0)
			print_prot_message(msg_status, message);
	}

	return ret;
}

/**
 * issue_prot_message() - Delivers diagnostic messages that protected arg control issues.
 *
 * @msg_status: PM_SC_DBG_MODE_MSG_TYPE_INFO/ERROR/WARNING/PWARNING.
 * fmt: message print format that follows with arguments.
 */
static inline
int issue_prot_message(const int msg_status, const char *fmt, ...)
{
	va_list argptr;
	int ret;

	va_start(argptr, fmt);
	ret = issue_prot_message_vl(msg_status, 0, fmt, argptr);
	va_end(argptr);

	return ret;
}

/*
 * protected_mode_message() - Delivers diagnostic messages that protected arg control issues.
 *
 * @header_type: PM_SC_DBG_MODE_MSG_TYPE_INFO/ERROR/WARNING/PWARNING.
 * @MSG_ID: message ID (f.e. PMSCERRMSG_UNEXP_ARG_TAG_ID).
 */

void protected_mode_message(int header_type,
			    enum pm_syscall_err_msg_id MSG_ID, ...)
{
	va_list argptr;
	if ((check_pm_sc_debug_feature(PM_SC_DBG_MODE_CHECK
					| PM_DIAG_MESSAGES_IN_JOURNAL
					| PM_DIAG_MESSAGES_IN_STDERR) == 0)
		|| unlikely(current->mm->context.pm_sc_debug_mode
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES))
		return;

	if (header_type) {
		enum pm_syscall_err_msg_id header_id;

		switch (header_type) {
		case PM_SC_DBG_MODE_MSG_TYPE_ERROR:
			header_id = PMSCERRMSG_RUNTIME_ERROR;
			break;
		case PM_SC_DBG_MODE_MSG_TYPE_WARNING:
			header_id = PMSCERRMSG_RUNTIME_WARNING;
			break;
		case PM_SC_DBG_MODE_MSG_TYPE_PWARNING:
			header_id = PMSCERRMSG_RUNTIME_PWARNING;
			break;
		default:
			header_id = PMSCERRMSG_ERR_ID;
			break;
		}

		issue_prot_message(header_type, "[PID#%d] %s: %s\n",
				   current->pid, current->comm, protected_error_list[header_id]);
	}

	if ((MSG_ID <= 0) || (MSG_ID >= PMSCERRMSG_NUMBER)) {
		pr_err("%s:%d %s (%d)\n", __FILE__, __LINE__,
		       protected_error_list[PMSCERRMSG_ERR_ID], MSG_ID);
		return;
	}

	va_start(argptr, MSG_ID);
	issue_prot_message_vl(header_type, MSG_ID, protected_error_list[MSG_ID], argptr);
	va_end(argptr);
}

#if (!DYNAMIC_DEBUG_SYSCALLP_ENABLED)
#define print_buffer(a1, a2, a3)
#else
static void print_buffer(const char	*title,
			 void __user	*buffer,
			 const int	buff_size)
{
	unsigned long __user *arr;
	e2k_ptr_t descr;
	int size = buff_size, err = 0, tags;
	unsigned long vlong;

	if (!check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))
		return;

	arr = (unsigned long __user *)buffer;
	if (title)
		pr_info("\t##### %s[%d] : 0x%px #####\n", title, size, buffer);

	for (; size > 0; size -= 8, arr++) {
		if (size < 16 || (unsigned long)arr & 0xf) {
			err = get_user_tagged_8(vlong, tags, arr);
			if (err)
				break;
			pr_info("\t[0x%.2x] 0x%.8lx\n", tags, vlong);
		} else {
			err = get_user_tagged_16(descr.qword, tags, arr);
			if (err)
				break;
			pr_info("\t[0x%.2x] 0x%.8x.%.8x    0x%.8x.%.8x\n", tags,
				(int)(descr.qword.lo >> 32), (int)(descr.qword.lo),
				(int)(descr.qword.hi >> 32), (int)(descr.qword.hi));
			size -= 8;
			arr++;
		}
	}
	if (err)
		pr_err("\tError 0x%x while reading from 0x%lx\n",
			err, (unsigned long) arr);

}
#endif /* print_buffer  */


/*
 * NB> According to the agreement with rev@mcst @ RM-34655,
 *	'iovec' structures to be converted at arch-independent part of kernel
 *	alike handling 'compat'-format structures.
 */
static int convert_iov(const void __user *iov128, const void __user *iov64,
		       const size_t iov_len, bool ignore_zero_len)
{
	struct prot_iovec __user *iovec_p128 = (struct prot_iovec __user *)iov128;
	struct iovec __user *iovec_p64 = (struct iovec __user *)iov64;
	e2k_ap_t buff;
	__kernel_size_t buff_len;
	void __user *ptr;
	int tags, i;
	long  err;

	for (i = 0; i < iov_len; i++) {
		err = get_user_tagged_16(buff.qword, tags, &iovec_p128->iov_base);
		err = err ?: get_user(buff_len, &iovec_p128->iov_len);
		if (unlikely(err))
			return -EFAULT;
		if (buff_len || ignore_zero_len) {
			if (unlikely((long)buff_len < 0)) {
				return -EINVAL;
			}
			if (unlikely(!IS_AP(buff, tags))) {
				DbgSCP("bad iov_base 0x%llx:0x%llx tags 0x%x\n",
				       buff.lo, buff.hi, tags);
				return -EFAULT;
			}
			if (unlikely(buff_len > AP_OBJ_SIZE(buff))) {
				PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
				     "iov", (size_t) AP_OBJ_SIZE(buff), buff_len);
				return -EFAULT;
			}
			ptr = U_AP_PTR(buff);
		} else if (!AP_NULL(buff, tags)) {
			DbgSCP("bad iov_base 0x%llx:0x%llx tags 0x%x or iov_len=%zd\n",
			       buff.lo, buff.hi, tags, buff_len);
			return -EFAULT;
		} else {
			ptr = NULL;
		}
		err = put_user(ptr, &iovec_p64->iov_base);
		err = err ?: put_user(buff_len, &iovec_p64->iov_len);
		if (unlikely(err))
			return -EFAULT;
		iovec_p128++;
		iovec_p64++;
	}

	print_buffer("convert_iov//iov128 :",
		(void __user *) iov128, iov_len * sizeof(struct prot_iovec));
	print_buffer("convert_iov//iov64 :",
		(void __user *) iov64, iov_len * sizeof(struct iovec));

	return 0;
}

/*
 * NB> According to the agreement with rev@mcst @ RM-34655, protected
 *	'iovec' structures to be converted at arch-independent part of kernel
 *	alike handling 'compat'-format structures.
 * Here we just check for the protected structure consistency.
 */
static int check_for_iov128_consistency(const void __user *iov128,
					const size_t iov_count,
					const struct pt_regs	*regs)
{
	struct prot_iovec __user *iovec_p128 = (struct prot_iovec __user *)iov128;
	e2k_ap_t dscr;
	__kernel_size_t iov_len;
	long  err;
	int tags, i;
	int out_warning = 1; /* we report warning only once */

	if (iov128 && iov_count)
		print_buffer("check_for_iov128_consistency :",
			(void __user *) iov128, iov_count * sizeof(struct prot_iovec));

	for (i = 0; i < iov_count; i++) {
		err = get_user_tagged_16(dscr.qword, tags, &iovec_p128->iov_base);
		err = err ?: get_user(iov_len, &iovec_p128->iov_len);
		if (unlikely(err))
			return -EFAULT;
		if (iov_len) {
			if (unlikely((long)iov_len < 0)) {
				return -EINVAL;
			}
			if (IS_AP(dscr, tags)) {
				if (unlikely(iov_len > AP_OBJ_SIZE(dscr))) {
					PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
						__func__, "iov", (size_t) AP_OBJ_SIZE(dscr),
						iov_len);
					return -EFAULT;
				}
			} else {
				if (out_warning) {
					out_warning = 0;
					PROTECTED_MODE_WARNING(
						PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
						sys_call_ID_to_name[regs->sys_num], tags,
						"iovec", "iov_base", (unsigned long)dscr.lo,
							(unsigned long)dscr.hi);
				}
				/* This may be address, not descriptor. */
				if (dscr.hi)
					DbgSCP("bad iov_base 0x%llx:0x%llx tags 0x%x\n",
					       dscr.lo, dscr.hi, tags);
				if (!check_pm_sc_debug_feature(PROTECTED_MODE_SOFT))
					return -EFAULT;
				/* NB> We can try on this in the 'soft' execution mode. */
			}
		} else { /* nothing to read/write */
			DbgSCP("iov_base 0x%llx:0x%llx tags 0x%x iov_len=%zd\n",
			       dscr.lo, dscr.hi, tags, iov_len);
		}
		iovec_p128++;
	}

	return 0;
}

static inline
int sizeof_msghdr64(const int count)
{
	return sizeof(struct user_msghdr) * count;
}

static struct user_msghdr __user *convert_msghdr128(
			struct protected_user_msghdr __user	*msghdr_p128,
			struct user_msghdr __user		*msghdr_p64,
			const char		*syscall_name,
			const char		*arg_name,
			const struct pt_regs	*regs)
/* Converts user protected msghdr structure to the 64-bit format;
 * checks for issues in the structure including 'iovec' pointers.
 * Outputs converted structure (allocated in user space if (user_buff == NULL)).
 * 'msghdr_p128' - protected message header structure.
 */
{
	e2k_ap_t dscr;
	int tags;
	__kernel_size_t dscr_len, iov_len;
	long  err;

	 /* Structure 'user_msghdr' contains pointers inside;
	  * therefore they need to be converted to 64-bit mode
	  * and results to be saved in these structures afterwards.
	  *
	  * Here we convert prot structure 'msghdr_p128' into the kernel structure 'm64'
	  * and then copy structure 'm64' to the user address space ('msghdr_p64').
	  */
	if (msghdr_p64 == NULL) {
		int size = sizeof_msghdr64(1);
		msghdr_p64 = (struct user_msghdr __user *) get_user_space(size);
		if (msghdr_p64 == NULL) {
			err = -ENOMEM;
			goto out_err;
		}
	}

	/* Check for proper msg_name fields: */
	err = get_user(dscr_len, &msghdr_p128->msg_namelen);
	if (unlikely(err))
		goto out_err;
	if (dscr_len) {
		if ((int)dscr_len < 0) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_FIELD_STRUCT_IN_ARG_NAME,
					syscall_name, "msg_namelen", "msghdr", "message");
			protected_mode_message(0, PMSCERRMSG_STRUCT_BAD_TAG_INT_FIELD,
					"user_msghdr", 0, 2, (long)(int)dscr_len);
			err = -EINVAL;
			goto out_err;
		}
		err = get_user_tagged_16(dscr.qword, tags, &msghdr_p128->msg_name);
		if (err)
			goto out_err;
		if (unlikely(!IS_AP(dscr, tags))) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
					       syscall_name, tags, "user_msghdr",
					       "msg_name", dscr.lo, dscr.hi);
			err = -EFAULT;
			goto out_err;
		}
		if (dscr_len > AP_OBJ_SIZE(dscr)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
					syscall_name, "msghdr",
					(size_t) AP_OBJ_SIZE(dscr), "msg_name", dscr_len);
			DbgSCP("bad msg_name 0x%lld:0x%lld dscr_len %zd\n",
			       dscr.lo, dscr.hi, dscr_len);
			err = -EINVAL;
			goto out_err;
		}
		err = put_user(U_AP_PTR(dscr), &msghdr_p64->msg_name);
		err = err ?: put_user(dscr_len, &msghdr_p64->msg_namelen);
		if (err)
			return (struct user_msghdr __user __force *)err;
	} else {
		err = put_user(NULL, &msghdr_p64->msg_name);
		err = err ?: put_user(0UL, &msghdr_p64->msg_namelen);
		if (err)
			return (struct user_msghdr __user __force *)err;
	}

	/* Filling in msg_iov/msg_iovlen fields: */
	err = get_user_tagged_16(dscr.qword, tags, &msghdr_p128->msg_iov);
	err = err ?: get_user(iov_len, &msghdr_p128->msg_iovlen);
	if (unlikely(err))
		goto out_err;
	if (unlikely(iov_len < 0) || unlikely(iov_len > SOMAXCONN)) {
		err = -EMSGSIZE;
		goto out_err;
	}
	if (unlikely(iov_len == 0)) {
		err = put_user(NULL, &msghdr_p64->msg_iov);
		err = err ?: put_user(0UL, &msghdr_p64->msg_iovlen);
		if (err)
			return (struct user_msghdr __user __force *)err;
	} else {
		void __user *iov128;

		if (unlikely(!IS_AP(dscr, tags))) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
					       syscall_name, tags, "user_msghdr",
					       "msg_iov", dscr.lo, dscr.hi);
			err = -EFAULT;
			goto out_err;
		}
		iov128 = U_AP_PTR(dscr);
		err = put_user(iov128, &msghdr_p64->msg_iov);
		err = err ?: put_user(iov_len, &msghdr_p64->msg_iovlen);
		if (err)
			return (struct user_msghdr __user __force *)err;
		if (AP_OBJ_SIZE(dscr) < iov_len * sizeof(struct prot_iovec)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
					syscall_name, "msghdr",
					(size_t) AP_OBJ_SIZE(dscr), "msg_iov", iov_len);
			DbgSCP("iov size < iovlen :: iov 0x%lld:0x%lld dscr_len %zd\n",
			       dscr.lo, dscr.hi, AP_OBJ_SIZE(dscr));
			err = -EFAULT;
			goto out_err;
		}
		err = check_for_iov128_consistency(iov128, iov_len, regs);
		if (unlikely(err)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				     sys_call_ID_to_name[regs->sys_num], "msg_iov", arg_name);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			goto out_err;
		}
	}

	/* Check for proper msg_control fields: */
	err = get_user(dscr_len, &msghdr_p128->msg_controllen);
	if (unlikely(err))
		goto out_err;
	if (dscr_len) {
		if (get_user_tagged_16(dscr.qword, tags, &msghdr_p128->msg_control)) {
			err = -EFAULT;
			goto out_err;
		}
		if (unlikely(!IS_AP(dscr, tags))) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
					       syscall_name, tags, "user_msghdr",
					       "msg_control", dscr.lo, dscr.hi);
			err = -EFAULT;
			goto out_err;
		}
		if (dscr_len > AP_OBJ_SIZE(dscr)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
					"msg_control",
					(size_t) AP_OBJ_SIZE(dscr), dscr_len);
			DbgSCP("bad msg_control 0x%lld:0x%lld dscr_len %zd\n",
			       dscr.lo, dscr.hi, dscr_len);
			if (PM_SYSCALL_WARN_ONLY == 0) {
				err = -EFAULT;
				goto out_err;
			}
			dscr_len = AP_OBJ_SIZE(dscr);
			PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED, dscr_len);
		}
		err = put_user(U_AP_PTR(dscr), &msghdr_p64->msg_control);
		err = err ?: put_user(dscr_len, &msghdr_p64->msg_controllen);
		if (err)
			return (struct user_msghdr __user __force *)err;
	} else {
		err = put_user(NULL, &msghdr_p64->msg_control);
		err = err ?: put_user(0UL, &msghdr_p64->msg_controllen);
		if (err)
			return (struct user_msghdr __user __force *)err;
	}

	print_buffer("convert_msghdr128//msghdr128 :",
		(void __user *) msghdr_p128, sizeof(struct protected_user_msghdr));
	print_buffer("convert_msghdr128//msghdr64 :",
		(void __user *) msghdr_p64, sizeof(struct user_msghdr));

	return msghdr_p64;

out_err:
	PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
			     syscall_name, "protected_msghdr", "msghdr", arg_name);
	PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	return (struct user_msghdr __user __force *)ERR_PTR(err);
}

static inline
long sizeof_mmsghdr64(int count)
{
	return sizeof(struct mmsghdr) * count;
}

static int convert_mmsghdr(const struct protected_mmsghdr __user *prot_mmsghdr,
			   struct mmsghdr __user	*mmsghdr_p64,
			   const int			count,
			   const char		*syscall_name,
			   const char		*arg_name,
			   const struct pt_regs	*regs)
/* Converts user mmsghdr structure from protected to regular format.
 * Outputs error number or '0' if OK.
 * 'prot_mmsghdr' - protected message header structure.
 * 'mmsghdr_p64'  - 64-bit message header structure.
 */
{
	struct protected_mmsghdr __user *mmsghdr128 = (void __user *) prot_mmsghdr;
	struct mmsghdr __user *mmsghdr64 = mmsghdr_p64;
	struct user_msghdr __user	*ptr64;
	int i;

	/* NB> According to the agreement with rev@mcst @ RM-34655,
	 *	'iovec' structures to be converted at arch-independent part of kernel
	 *	alike handling 'compat'-format structures.
	 */

	for (i = 0; i < count; i++, mmsghdr128++, mmsghdr64++) {
		ptr64 = convert_msghdr128(&mmsghdr128->msg_hdr, &mmsghdr64->msg_hdr,
					    syscall_name, arg_name, regs);
		if (IS_ERR(ptr64))
			return (int)(unsigned long)ptr64;
	}
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_COMPLEX_WRAPPERS)) {
		print_buffer("convert_mmsghdr//mmsghdr128 :",
			(void __user *) prot_mmsghdr, count * sizeof(struct protected_mmsghdr));
		print_buffer("convert_mmsghdr//mmsghdr64 :",
			(void __user *) mmsghdr_p64, count * sizeof(struct mmsghdr));
	}

	return 0;
}

notrace __section(".entry.text")
long protected_syscall_notyetsupported(const unsigned long unused_a1,
				       const unsigned long unused_a2,
				       const unsigned long unused_a3,
				       const unsigned long unused_a4,
				       const unsigned long unused_a5,
				       const unsigned long unused_a6,
				       struct pt_regs	*regs)
{
	PROTECTED_MODE_ERROR(PMSCERRMSG_SC_NOT_YET_SUPPORTED_IN_PM,
			     regs->sys_num, sys_call_ID_to_name[regs->sys_num]);
	return sys_ni_syscall();
}

notrace __section(".entry.text")
long protected_sys_clean_descriptors(void __user *addr,
				     unsigned long	size,
				     const unsigned long flags,
				     const unsigned long unused_a4,
				     const unsigned long unused_a5,
				     const unsigned long unused_a6,
				     struct pt_regs	*regs)
/* If (!flags) then 'addr' is a pointer to list of descriptors to clean. */
{
	long rval = 0; /* syscall return value */
	long		descr_size;
	unsigned long	size_to_clean = size;

	if (check_pm_sc_debug_mode(PM_SC_NO_CLEAN_DESCRIPTORS)) /* No action required */
		return rval;

	DbgSCP("addr=0x%lx, size=%ld, flags=0x%lx", (unsigned long)addr, size, flags);

	if (unlikely(!addr || !size))
		return 0L;

	if (prot_sc_arg_not_ptr(1, regs)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG,
				regs->dargs[0], regs->dargs[1], 1);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EFAULT;
	} else {
		descr_size = AP_OBJ_SIZE(regs->qargs[0]);
	}
	if (!(flags & CLEAN_DESCRIPTORS_SINGLE))
		size_to_clean *= sizeof(e2k_ptr_t);
	if (descr_size < size_to_clean) {
		PROTECTED_MODE_ERROR(PMCLNDSCRSMSG_WRONG_ARG_SIZE,
				regs->dargs[0], regs->dargs[1], size, descr_size);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EFAULT;
	}

	if ((flags & (CLEAN_DESCRIPTORS_SINGLE | CLEAN_DESCRIPTORS_NO_GARB_COLL)) ==
			(CLEAN_DESCRIPTORS_SINGLE | CLEAN_DESCRIPTORS_NO_GARB_COLL)) {
		rval = mem_set_empty_tagged_dw(addr, size, 0x0baddead0baddeadUL);
	} else if (flags & CLEAN_DESCRIPTORS_SINGLE) {
		e2k_ptr_t old_descriptor;

		old_descriptor.lo = regs->dargs[0];
		old_descriptor.hi = regs->dargs[1];
		rval = clean_single_descriptor(old_descriptor);
	} else if (!flags) {
		rval = clean_descriptors(addr, size);
	} else {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     "clean_descriptors", "flags", flags);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	if (rval == -EFAULT)
		send_sig_info(SIGSEGV, SEND_SIG_PRIV, current);
	return rval;
}


notrace __section(".entry.text")
long protected_sys_clone(const unsigned long	a1,	/* flags */
			 const unsigned long	a2,	/* new_stackptr */
			 const unsigned long a3,/* parent_tidptr */
			 const unsigned long a4,/*  child_tidptr */
			 const unsigned long a5,/* tls */
			 const unsigned long	a6,	/* unused */
			 struct pt_regs	*regs)
{
	int rval; /* syscall return value */
	long offset = 0;
	struct kernel_clone_args args = {};

	DbgSCP("(fl=0x%lx, newsp=0x%lx, p/ch_tidptr=0x%lx/0x%lx, tls=0x%lx)\n",
		a1, a2, a3, a4, a5);
	if (a2) {
		long size; /* total size of the child stack */

		if (warn_if_not_descr(2, CHECK4DESCR_ERROR, regs)) {
			rval = -EINVAL;
			goto out;
		}
		offset = AP_IND(regs->qargs[1]);
		size = AP_SIZE(regs->qargs[1]);
		if (offset < 0 || offset > size) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
				sys_call_ID_to_name[regs->sys_num], "stack", a2,
				prot_sc_arg_tag(2, regs));
			protected_mode_message(0, PMSCWARN_DSCR_COMPONENTS,
				a2, (long)size, (long)offset);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
				return -EINVAL;
			rval = -EINVAL;
			goto out;
		}
	}
	/*
	 * User may choose to not pass additional arguments
	 * (tls, tid) at all for historical and compatibility
	 * reasons, so we do not fail if (a3), (a4), and (a5)
	 * pointers are bad.
	 *
	 * The fifth argument (tls) requires special handling:
	 */
	if (a1 & CLONE_SETTLS) {
		long tls_size = 0;

		if (a5 && !warn_if_not_descr(5, CHECK4DESCR_ERROR, regs))
			tls_size = AP_OBJ_SIZE(regs->qargs[4]);

		if (!tls_size) { /* bad pointer ? */
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
					     sys_call_ID_to_name[regs->sys_num],
					     "tls", a5, prot_sc_arg_tag(5, regs));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}
	}

	args.flags	 = (a1 & ~CSIGNAL);
	args.pidfd	 = (int __user *)a3;
	args.child_tid	 = (int __user *)a4;
	args.parent_tid	 = (int __user *)a3;
	args.exit_signal = (a1 & CSIGNAL);
	/* NB> In PM argument 'new_stackptr' contains info on the child stack size.
	 *     As far as user always submits the topmost address of the memory space
	 *     set up for the child stack, the size of the allocated child stack is
	 *     actually equal to the offset (i.e. currptr component of descriptor).
	 */
	args.stack	 = a2; /* NB> 'kernel_clone' expects higher stack bound over here */
	if (IF_PM_DBG_MODE(PROTECTED_MODE_SOFT) &&
			IF_PM_DBG_MODE(PM_SC_COMPATIBLE_CLONE)) {
		/* NB> Old syscall clone() does not provide a means whereby the caller
		 *     can inform the kernel of the size of the stack area.
		 *     Kernel allocates maximum possible area for the child stack.
		 */
		offset = 0;
	}
	args.stack_size	 = offset;
	args.tls	 = a5;

	rval = kernel_clone(&args);
out:
	DbgSCP("rval = %d, sys_num = %d size=%lx\n", rval, regs->sys_num, offset);
	return rval;
}


/*
 * get_u64_from_user() - Reads dword from the given user pointer.
 * @u64_uptr: user pointer to read from.
 * @pu64: pointer to dword read from user memory (main result).
 * @arg_name: argument name to report in error message if any.
 * @struct_name: structure name for error messaging.
 * @field_name: name of field structure for error messaging.
 * @regs: 'pt_regs' structure.
 *
 * Return: error number or '0' if no issue encountered.
 */
static inline int get_u64_from_user(u64 __user *u64_uptr, u64 *pu64,
				    char *arg_name, char *struct_name, char *field_name,
				    struct pt_regs	*regs)
{
	int tags, ret;
	u64 uval64;

	if ((unsigned long)u64_uptr & 0xf) { /* unaligned address */
		ret = get_user_tagged_8(uval64, tags, u64_uptr);
	} else { /* aligned address */
		e2k_ptr_t descr;

		ret = get_user_tagged_16(descr.qword, tags, u64_uptr);
		if (ret == EFAULT) { /* seems there is no extra 8 bytes in the buffer */
			ret = get_user_tagged_8(uval64, tags, u64_uptr);
		} else {
			tags &= 0xf; /* Here we check for lower dword tag */
			uval64 = descr.qword.lo;
		}
	}

	if (unlikely(ret)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_FROM,
				sys_call_ID_to_name[regs->sys_num], (unsigned long)u64_uptr);
		protected_mode_message(0, PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				sys_call_ID_to_name[regs->sys_num], field_name, arg_name);
		if (PM_SYSCALL_WARN_ONLY == 0)
			pm_abort_execution(ret);
		*pu64 = 0UL;
		return ret;
	} else if (unlikely(tags)) {
		if ((tags & 0x3) == ETAGNUM) {
			/* This is 'int' value with trash in the higher part of dword */
			uval64 = (u64)(short)uval64;
		}
		PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXPECTED_FIELD_TAG,
				sys_call_ID_to_name[regs->sys_num], tags,
				field_name, struct_name, arg_name);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	}
	*pu64 = uval64;
	return 0;
}

/*
 * get_descriptor_from_user() - Reads descriptor from the given user pointer.
 * @dscr_uptr: user pointer to read descriptor from.
 * @pdescr: user pointer to descriptor read from the given user pointer.
 * @min_size: minimum required descriptor size (for a proper field/argument).
 * @arg_name: argument name to report in error message if any.
 * @struct_name: structure name for error messaging.
 * @field_name: name of field structure for error messaging.
 * @pu64: pointer to dword read from user memory (main result).
 * @regs: 'pt_regs' structure.
 *
 * Return: error number or '0' if no issue encountered.
 */
static inline
int get_descriptor_from_user(e2k_ptr_t __user *dscr_uptr, e2k_ptr_t *pdescr, long min_size,
			     char *arg_name, char *struct_name, char *field_name,
			     struct pt_regs	*regs)
{
	int tags, ret;

	ret = get_user_tagged_16(pdescr->qword, tags, dscr_uptr);

	if (unlikely(ret)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_FROM,
				sys_call_ID_to_name[regs->sys_num], (unsigned long)dscr_uptr);
		protected_mode_message(0, PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				sys_call_ID_to_name[regs->sys_num], field_name, arg_name);
		if (PM_SYSCALL_WARN_ONLY == 0)
			pm_abort_execution(ret);
		return ret;
	} else if ((pdescr->lo || tags) && unlikely(!IS_AP(*pdescr, tags))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
				sys_call_ID_to_name[regs->sys_num], tags,
				struct_name, field_name,
				(long)pdescr->lo, (long)pdescr->hi);
		return -EINVAL;
	} else if (pdescr->lo && AP_OBJ_SIZE(*pdescr) < (signed) min_size) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_INSUFFICIENT_STRUCT_SIZE,
				sys_call_ID_to_name[regs->sys_num], field_name,
				AP_OBJ_SIZE(*pdescr), min_size);
		return -EINVAL;
	}

	return 0;
}

struct protected_clone_args {
	__aligned_u64 flags;
	e2k_ptr_t     pidfd;
	e2k_ptr_t     child_tid;
	e2k_ptr_t     parent_tid;
	__aligned_u64 exit_signal;
	e2k_ptr_t     stack;
	__aligned_u64 stack_size;
	e2k_ptr_t     tls;
	e2k_ptr_t     set_tid;
	__aligned_u64 set_tid_size;
	__aligned_u64 cgroup;
};

/*
 * protected_clone_args_to_uargs64() - Converts protected structure 'prot_uargs'
 *					into 64-bit mode structure 'uargs_64'.
 * @prot_uargs: input protected argument structure ('uargs') to 'clone3'.
 * @uargs64: output 64-bit mode argument structure ('uargs') to 'clone3'
 * @size128: size of the input 'prot_uargs' structure.
 * @psize64: calculated effective size of structure 'uargs64'.
 * @regs: 'pt_regs' structure.
 *
 * Return: error number or '0' if no issue encountered.
 */
static inline
int protected_clone_args_to_uargs64(struct protected_clone_args __user	*prot_uargs,
				    struct clone_args		__user	*uargs64,
				    const size_t			size128,
				    size_t				*psize64,
				    struct pt_regs	*regs)
{
	e2k_ptr_t descr;
	u64 uval64;
	size_t size64 = 0; /* size of the converted uargs structure */
	int ret;

	/* Copying structure fields from 'prot_uargs' into 'uargs64': */

	/* u64 flags;         Flags bit mask */
	ret = get_u64_from_user(&prot_uargs->flags, &uval64,
				   "uargs", "clone_args", "uargs->flags", regs);
	ret = ret ?: put_user(uval64, &uargs64->flags);
	if (unlikely(ret))
		goto err_out;

	/* u64 pidfd;        / * Where to store PID file descriptor (int *) */
	ret = get_descriptor_from_user(&prot_uargs->pidfd, &descr, sizeof(int),
				       "uargs", "pidfd", "uargs->pidfd", regs);
	if (unlikely(ret))
		goto err_out;
	uval64 = AP_PTR(descr);
	ret = put_user(uval64, &uargs64->pidfd);
	if (unlikely(ret))
		goto err_out;

	/* u64 child_tid;     Where to store child TID, in child's memory (pid_t *) */
	ret = get_descriptor_from_user(&prot_uargs->child_tid, &descr, sizeof(pid_t),
				       "uargs", "child_tid", "uargs->child_tid", regs);
	if (unlikely(ret))
		goto err_out;
	uval64 = AP_PTR(descr);
	ret = put_user(uval64, &uargs64->child_tid);
	if (unlikely(ret))
		goto err_out;

	/* u64 parent_tid;    Where to store child TID, in parent's memory (pid_t *) */
	ret = get_descriptor_from_user(&prot_uargs->parent_tid, &descr, sizeof(pid_t),
				       "uargs", "parent_tid", "uargs->parent_tid", regs);
	if (unlikely(ret))
		goto err_out;
	uval64 = AP_PTR(descr);
	ret = put_user(uval64, &uargs64->parent_tid);
	if (unlikely(ret))
		goto err_out;

	/* u64 exit_signal;  / * Signal to deliver to parent on child termination */
	ret = get_u64_from_user(&prot_uargs->exit_signal, &uval64,
				   "uargs", "clone_args", "exit_signal", regs);
	ret = ret ?: put_user(uval64, &uargs64->exit_signal);
	if (unlikely(ret))
		goto err_out;

	/* u64 stack;         Pointer to lowest byte of stack */
	ret = get_descriptor_from_user(&prot_uargs->stack, &descr, 0/*size*/,
				       "uargs", "stack", "uargs->stack", regs);
	if (unlikely(ret))
		goto err_out;
	uval64 = AP_PTR(descr);
	ret = put_user(uval64, &uargs64->stack);
	if (unlikely(ret))
		goto err_out;

	/* u64 stack_size;    Size of stack */
	ret = get_u64_from_user(&prot_uargs->stack_size, &uval64,
				   "uargs", "clone_args", "stack_size", regs);
	if (unlikely(ret))
		goto err_out;
	/* We should check that the given size doesn't exceed stack size: */
	if ((long)uval64 > AP_OBJ_SIZE(descr)) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
				       sys_call_ID_to_name[regs->sys_num],
				       "uargs->stack_size", (long)uval64,
				       "uargs->stack", (short)AP_OBJ_SIZE(descr));
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		uval64 = AP_OBJ_SIZE(descr);
		if (!uval64) {
			ret = -EINVAL;
			goto err_out;
		}
		PROTECTED_MODE_MESSAGE(1, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED, (short)uval64);
	}
	ret = put_user(uval64, &uargs64->stack_size);
	if (unlikely(ret))
		goto err_out;
	size64 = offsetof(struct clone_args, tls); /* min required struct fields are available */
	if (unlikely(size128 <= offsetof(struct protected_clone_args, tls)))
		goto done;

	/* u64 tls;          Location of new TLS */
	ret = get_descriptor_from_user(&prot_uargs->tls, &descr, 0/*size*/,
				       "uargs", "tls", "uargs->tls", regs);
	if (unlikely(ret))
		goto err_out;
	uval64 = AP_PTR(descr);
	ret = put_user(uval64, &uargs64->tls);
	if (unlikely(ret))
		goto err_out;
	size64 += sizeof(u64);
	if (size128 <= offsetof(struct protected_clone_args, set_tid))
		goto done;

	/* u64 set_tid;      Pointer to a pid_t array (since Linux 5.5) */
	ret = get_descriptor_from_user(&prot_uargs->set_tid, &descr, 0/*size*/,
				       "uargs", "set_tid", "uargs->set_tid", regs);
	if (unlikely(ret))
		goto err_out;
	uval64 = AP_PTR(descr);
	ret = put_user(uval64, &uargs64->set_tid);
	if (unlikely(ret))
		goto err_out;
	size64 += sizeof(u64);
	if (size128 <= offsetof(struct protected_clone_args, set_tid_size))
		goto done;

	/* u64 set_tid_size; Number of elements in set_tid (since Linux 5.5) */
	ret = get_u64_from_user(&prot_uargs->set_tid_size, &uval64,
				   "uargs", "clone_args", "set_tid_size", regs);
	ret = ret ?: put_user(uval64, &uargs64->set_tid_size);
	if (unlikely(ret))
		goto err_out;
	/* Checking that 'tid' is capable to store 'uval64' elements: */
	if (uval64 && descr.lo) {
		if ((uval64 * sizeof(pid_t)) > AP_OBJ_SIZE(descr)) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
				       sys_call_ID_to_name[regs->sys_num],
				       "uargs->set_tid_sizesize", (long)uval64,
				       "uargs->set_tid", (short)AP_OBJ_SIZE(descr));
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
			uval64 = AP_OBJ_SIZE(descr) / sizeof(pid_t);
			PROTECTED_MODE_MESSAGE(1, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED, (short)uval64);
			ret = -EINVAL;
			goto err_out;
		}
	}
	size64 += sizeof(u64);
	if (size128 <= offsetof(struct protected_clone_args, cgroup))
		goto done;

	/* u64 cgroup;       File descriptor for target cgroup of child (since Linux 5.7) */
	ret = get_u64_from_user(&prot_uargs->cgroup, &uval64,
				   "uargs", "clone_args", "cgroup", regs);
	ret = ret ?: put_user(uval64, &uargs64->cgroup);
	size64 += sizeof(u64);

err_out:
	if (unlikely(ret))
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, -ret);
done:
	DbgSCP("size64 = 0x%zx / %zd   ret = %d\n", size64, size64 / 8, ret);

	/* Converted array contents: */
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		u64 __user *uarr = (u64 __user *)uargs64;
		size_t str_size = sizeof(struct clone_args);
		int err, i;

		pr_info("Converted uargs64 [size: 0x%zx/%zd]: unused bytes are all '0xff'\n",
			size64, size64 / 8);
		for (i = 0; i < (str_size / 8); i++) {
			err = get_user(uval64, &uarr[i]);
			if (unlikely(err)) {
				pr_info("[#%d] failed to read: ret=%d\n", i, err);
				break;
			}
			pr_info("[#%d] 0x%llx\n", i, uval64);
		}
	}

	if (psize64)
		*psize64 = size64;
	if (ret == -EFAULT) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_ERR_FROM,
				     "sys_clone3", (unsigned long)prot_uargs);
	}
	return ret;
}

notrace __section(".entry.text")
long protected_sys_clone3(void __user	*uargs,
			  const size_t	size,
			  const unsigned long unused3,
			  const unsigned long unused4,
			  const unsigned long unused5,
			  const unsigned long unused6,
			  struct pt_regs	*regs)
{
	struct protected_clone_args __user *prot_uargs =
				(struct protected_clone_args __user *) uargs;
	int rval = -EINVAL; /* syscall return value if bad 'uargs' */
	long args_size, size64;
	struct clone_args __user *uargs64; /* protected 'uargs' converted to regular mode */
	int ret;

#define MIN_UARG_SIZE offsetof(struct protected_clone_args, set_tid)
	/* NB> This is minimum allowed 'size' value according to LTP tests for 'clone3' */

	DbgSCP("(uargs=0x%lx/0x%lx, size=0x%zx) = %d\n",
	       regs->dargs[0], regs->dargs[1], size, rval);

	if (prot_sc_arg_not_ptr(1, regs))
		goto out;

	args_size = AP_OBJ_SIZE(regs->qargs[0]);
	if (unlikely(args_size < size)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
				     sys_call_ID_to_name[regs->sys_num], "size", (long)size,
				     "uargs", (unsigned int)args_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out;
	} else if (unlikely(size & 0x7 ||
			args_size < size ||
			args_size < MIN_UARG_SIZE ||
			size < MIN_UARG_SIZE)) {
		/* NB> No sense to run the syscall: it would fail anyway' */
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
			     sys_call_ID_to_name[regs->sys_num], "size", (long)size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out;
	} else if (unlikely((unsigned long)prot_uargs & 0x7)) {
		/* NB> No sense to run the syscall: it would fail anyway' */
		PROTECTED_MODE_ERROR(PMCNVSTRMSG_STRUCT_DESCR_UNALIGNED,
			     sys_call_ID_to_name[regs->sys_num], "uargs",
			     (unsigned long)prot_uargs);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out;
	}

	/* Copying strucrure fields from 'prot_uargs' to 'uargs64': */
	uargs64 = get_user_space(sizeof(*uargs64));
	if (!uargs64) {
		rval = -ENOMEM;
		goto out;
	}
	if (unlikely(check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))) {
		/* NB> In debug print unfilled structure bytes to be marked with 0xff */
		ret = fill_user(uargs64, sizeof(*uargs64), 0xff);
	}
	ret = protected_clone_args_to_uargs64(prot_uargs, uargs64, size, &size64, regs);

	if (ret) {
		rval = ret;
		goto out;
	}
	rval = sys_clone3(uargs64, size64);
	DbgSCP("sys_clone3(uargs64=0x%px, size64=0x%zx) = %d\n", uargs64, size64, rval);

out:
	return rval;
}


notrace __section(".entry.text")
long protected_sys_execve(const char __user *filename,
		const void __user *u_argv, const void __user *u_envp,
		unsigned long unused4, unsigned long unused5,
		unsigned long unused6, const struct pt_regs *regs)
{
	unsigned long __user *buf;
	unsigned long __user *argv;
	unsigned long __user *envp;
	long size = 0, size2 = 0;
	int argc = 0, envc = 0;
	long rval; /* syscall return value */

	/* Path to executable */
	if (!filename)
		return -EINVAL;

	/* argv */
	if (u_argv) {
		size = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
		if (!size)
			return -EINVAL;
	}

	/* envp */
	if (u_envp) {
		size2 = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (!size2)
			return -EINVAL;
	}
	/*
	 * Note in the release 5.00 of the Linux man-pages:
	 *	The use of a third argument to the main function
	 *	is not specified in POSIX.1; according to POSIX.1,
	 *	the environment should be accessed via the external
	 *	variable environ(7).
	 */

	/* Count real number of entries in argv */
	argc = count_descriptors(u_argv, size);
	if (argc < 0)
		return (long)argc;

	/* Count real number of entries in envc */
	if (size2) {
		envc = count_descriptors(u_envp, size2);
		if (envc < 0)
			return (long)envc;
	}

	/*
	 * Allocate space on user stack for converting of
	 * descriptors in argv and envp to ints
	 */
	buf = get_user_space((argc + envc + 2) * sizeof(size_t));
	if (!buf)
		return -ENOMEM;

	argv = buf;
	envp = &buf[argc + 1];

	/*
	 * Convert descriptors in argv to longs (address).
	 * For statically-linked executables missing argv is allowed,
	 * therefore kernel doesn't return error in this case.
	 * For dynamically-linked executables missing argv is not
	 * allowed, because at least argv[0] is required by ldso for
	 * loading of executable. Protected ldso must check argv.
	 */
	if (argc) {
		rval = get_pm_struct(u_argv, argv, argc * sizeof(e2k_ptr_t),
				     1, argc, 0x87, 0x3, 0, 0, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "argv[]", 2);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
	}
	/* The array argv must be terminated by zero */
	if (put_user(0, &argv[argc]))
		return -EFAULT;

	/*
	 * Convert descriptors in envp to longs (address).
	 * envc can be zero without problems
	 */
	if (envc) {
		rval = get_pm_struct(u_envp, envp, envc * sizeof(e2k_ptr_t),
				     1, envc, 0x3, 0x3, 0, 0, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "envp[]", 3);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
	}
	/* The array envp must be terminated by zero */
	if (put_user(0, &envp[envc]))
		return -EFAULT;

	rval = sys_execve(filename, (const char __user *const __user *) argv,
			  (const char __user *const __user *) envp);

	if (current->mm->context.pm_sc_debug_mode
			& PM_SC_DBG_MODE_COMPLEX_WRAPPERS) {
		char *kfname = strcopy_from_user_prot_arg(filename, regs, 1);

		if (kfname) {
			DbgSCP(" rval = %ld filename=%s argv=%p envp=%p\n",
				rval, kfname, argv, envp);
			kfree(kfname);
		}
	}
	return rval;
}

notrace __section(".entry.text")
long protected_sys_execveat(int dirfd, const char __user *filename,
		const void __user *u_argv, const void __user *u_envp,
		int flags, unsigned long unused6, const struct pt_regs *regs)
{
	unsigned long __user *buf;
	unsigned long __user *kargv;
	unsigned long __user *kenvp;
	long size = 0, size2 = 0;
	int argc = 0, envc = 0;
	long rval; /* syscall return value */

	if (current->mm->context.pm_sc_debug_mode
			& PM_SC_DBG_MODE_COMPLEX_WRAPPERS) {
		char *kfname = strcopy_from_user_prot_arg(filename, regs, 2);

		if (kfname) {
			DbgSCP(" dirfd=%d path=%s argv=0x%px envp=0x%px flags=0x%x\n",
				dirfd, kfname, u_argv, u_envp, flags);
			kfree(kfname);
		}
	}

	/* Path to executable */
	if (!filename)
		return -EINVAL;

	/* argv */
	if (u_argv) {
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (!size)
			return -EINVAL;

		/* Count real number of entries in argv */
		argc = count_descriptors(u_argv, size);
		if (argc < 0)
			return -EINVAL;
	}

	/* envp */
	if (u_envp) {
		size2 = (prot_sc_arg_not_ptr(4, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[3]);
		if (!size2)
			return -EINVAL;

		/* Count real number of entries in envc */
		envc = count_descriptors(u_envp, size2);
		if (envc < 0)
			return -EINVAL;
	}

	DbgSCP(" argc=%d envc=%d\n", argc, envc);

	/*
	 * Allocate space on user stack for converting of
	 * descriptors in argv and envp to ints
	 */
	buf = get_user_space((argc + envc + 2) << 3);
	if (!buf)
		return -ENOMEM;
	kargv = buf;
	kenvp = &buf[argc + 1];

	/*
	 * Convert descriptors in argv to ints.
	 * For statically-linked executables missing argv is allowed,
	 * therefore kernel doesn't return error in this case.
	 * For dynamically-linked executables missing argv is not
	 * allowed, because at least argv[0] is required by ldso for
	 * loading of executable. Protected ldso must check argv.
	 */
	if (argc) {
		rval = get_pm_struct(u_argv, kargv,
				argc << 4, 1, argc, 0x87, 0x3, 0, 0, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "argv[]", 3);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
	}
	/* The array argv must be terminated by zero */
	if (put_user(0, &kargv[argc]))
		return -EFAULT;

	/*
	 * Convert descriptors in envp to ints
	 * envc can be zero without problems
	 */
	if (envc) {
		rval = get_pm_struct(u_envp, kenvp,
				envc << 4, 1, envc, 0x3, 0x3, 0, 0, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "envp[]", 4);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
	}
	/* The array envp must be terminated by zero */
	if (put_user(0, &kenvp[envc]))
		return -EFAULT;

	rval = sys_execveat(dirfd, filename, (char const __user *const __user *) kargv,
			    (char const __user *const __user *) kenvp, flags);

	if (current->mm->context.pm_sc_debug_mode
			& PM_SC_DBG_MODE_COMPLEX_WRAPPERS) {
		char *kfname = strcopy_from_user_prot_arg(filename, regs, 2);

		if (kfname) {
			DbgSCP(" rval = %ld filename=%s argv=%p envp=%p\n",
				rval, kfname, kargv, kenvp);
			kfree(kfname);
		}
	}
	return rval;
}


static inline int check_prot_futex_arg_uninititialized(const long sys_num,
						       const long tags,
						       const int arg_num)
/* Returns 1 if arg is uninitialized; 0  otherwise */
{
	u8 tag = (tags >> (arg_num * 8)) & 0xf;

	if ((tag & 0x3) == ETAGDWS) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXP_ARG_TAG_ID,
			sys_num, sys_call_ID_to_name[sys_num], (u8)tag, arg_num);
		PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT,
				       arg_num);
		return 1;
	}
	return 0;
}

notrace __section(".entry.text")
long protected_sys_futex(const unsigned long a1,	/* uaddr */
			 const unsigned long	a2,	/* futex_op */
			 const unsigned long	a3,	/* val */
			 const unsigned long la4, /* timeout/val2 */
			 const unsigned long la5, /* uaddr2 */
			 const unsigned long	a6,	/* val3 */
			 const struct pt_regs	*regs)
{
	int cmd;
	unsigned long a4 = la4;
	unsigned long a5 = la5;
	long sys_num = regs->sys_num;
	long rval = 0;
	long tags = regs->tags;

	cmd = a2 & FUTEX_CMD_MASK;

	/* Check for optional args must be initialized: */

	switch (cmd) {
	case FUTEX_FD:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_UNLOCK_PI:
	case FUTEX_WAKE:
		break; /* The arguments timeout, uaddr2, and val3 are ignored. */

	case FUTEX_WAIT:
		rval = check_prot_futex_arg_uninititialized(sys_num, tags, 4 /*timeout*/);
		/* The arguments uaddr2, and val3 are ignored. */
		break;

	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_REQUEUE:
		rval = check_prot_futex_arg_uninititialized(sys_num, tags, 4 /*timeout*/);
		rval |= check_prot_futex_arg_uninititialized(sys_num, tags, 5 /*uaddr2*/);
		/* The argument val3 is ignored. */
		break;

	case FUTEX_CMP_REQUEUE:
	case FUTEX_CMP_REQUEUE_PI:
	case FUTEX_WAKE_OP:
		/* ALL ARGUMENYS ARE USED */
		rval = check_prot_futex_arg_uninititialized(sys_num, tags, 4 /*timeout*/);
		rval |= check_prot_futex_arg_uninititialized(sys_num, tags, 5 /*uaddr2*/);
		rval |= check_prot_futex_arg_uninititialized(sys_num, tags, 6 /*val3*/);
		break;

	case FUTEX_WAIT_BITSET:
		rval = check_prot_futex_arg_uninititialized(sys_num, tags, 4 /*timeout*/);
		/* The argument uaddr2 is ignored. */
		rval |= check_prot_futex_arg_uninititialized(sys_num, tags, 6 /*val3*/);
		break;

	case FUTEX_WAKE_BITSET:
		/* The argument timeout is ignored. */
		/* The argument uaddr2 is ignored. */
		rval |= check_prot_futex_arg_uninititialized(sys_num, tags, 6 /*val3*/);
		break;

	case FUTEX_LOCK_PI:
/*	case FUTEX_LOCK_PI2:	*/
		rval = check_prot_futex_arg_uninititialized(sys_num, tags, 4 /*timeout*/);
		/* The arguments val, uaddr2, and val3 are ignored. */
		break;
	}
	if (rval)
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, 0, EFAULT);

	if (la4 && (cmd == FUTEX_WAIT ||
		cmd == FUTEX_WAIT_BITSET ||
		cmd == FUTEX_LOCK_PI ||
		cmd == FUTEX_WAIT_REQUEUE_PI)) {
		/*
		 * These commands assume la4 must be a pointer. Let's check it:
		 */
		if (prot_sc_arg_not_ptr(4, regs) && !prot_sc_arg_NULL_ptr(4, regs)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
					     sys_call_ID_to_name[sys_num],
					     "timeout", prot_sc_arg_tag(4, regs));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			rval = -EINVAL;
		}
	}
	if (la5 && (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE ||
	    cmd == FUTEX_CMP_REQUEUE_PI || cmd == FUTEX_WAKE_OP ||
	    cmd == FUTEX_WAIT_REQUEUE_PI)) {
		/*
		 * These commands assume la5 must be a pointer. Let's check it:
		 */
		if (prot_sc_arg_not_ptr(5, regs) && !prot_sc_arg_NULL_ptr(5, regs)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
					     sys_call_ID_to_name[sys_num],
					     "uaddr2", prot_sc_arg_tag(5, regs));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			rval = -EINVAL;
		}
	}
	rval = sys_futex((u32 __user *) a1, a2, a3,
			 (struct __kernel_timespec __user *) a4,
			 (u32 __user *) a5, a6);
	return rval;
}


notrace __section(".entry.text")
long protected_sys_getgroups(const long			a1, /* size */
			    const unsigned long a2, /* list[] */
			    const unsigned long unused3,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs      *regs)
{
	long rval; /* syscall return value */
	long bufsize;

	DbgSCP(" (size=%ld, list[]=0x%lx) ", a1, a2);

	if (a1 < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "size", a1);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	}
	if (a2 && unlikely(!IS_AP(regs->qargs[1], prot_sc_arg_tag(2, regs)))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "list[]", prot_sc_arg_tag(2, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EFAULT;
	}
	/*
	 * Here we check that list size is enough to receive 'size' gid's:
	 */
	bufsize = AP_OBJ_SIZE(regs->qargs[1]);
	if ((a1 > 0) && (bufsize < (a1 * sizeof(gid_t)))) {
		if (!size_exceeds_descr_max_capacity((a1 * sizeof(gid_t)), "size", a1, regs))
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "list[]", bufsize, (size_t)(a1 * sizeof(gid_t)));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}

	rval = sys_getgroups(a1, (gid_t __user *) a2);
	DbgSCP("rval = %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_setgroups(const long			a1, /* size */
			     const unsigned long a2, /* list[] */
			     const unsigned long unused3,
			     const unsigned long unused4,
			     const unsigned long unused5,
			     const unsigned long unused6,
			     const struct pt_regs	*regs)
{
	long rval; /* syscall return value */
	long bufsize;

	DbgSCP(" (size=%ld, list[]=0x%lx) ", a1, a2);

	if (a1 < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
				     sys_call_ID_to_name[regs->sys_num], "size", a1);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	}
	if (a2 && unlikely(!IS_AP(regs->qargs[1], prot_sc_arg_tag(2, regs)))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "list[]", prot_sc_arg_tag(2, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EFAULT;
	}
	/*
	 * Here we check that list size is enough to receive 'size' gid's:
	 */
	bufsize = AP_OBJ_SIZE(regs->qargs[1]);
	if ((a1 > 0) && (bufsize < (a1 * sizeof(gid_t)))) {
		if (!size_exceeds_descr_max_capacity((a1 * sizeof(gid_t)), "size", a1, regs))
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "list[]", bufsize, (size_t)(a1 * sizeof(gid_t)));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}

	rval = sys_setgroups(a1, (gid_t __user *) a2);
	DbgSCP("rval = %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_open(const char __user *pathname,
			int		flags,
			mode_t		mode,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
			const struct pt_regs	*regs)
{
	long rval; /* syscall return value */

	/* NB> Basic check is done for first two args. Here we are to check 'mode'. */

	if (unlikely(!prot_arg_is_int(regs, 3))) {
		if (flags & (O_CREAT | O_TMPFILE)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXP_ARG_TAG_ID,
					regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					(regs->tags >> (3 * 8)) & 0xff/*tag*/, 3/*arg#*/);
			PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_MISSED_OR_UNINIT, 3/*arg#*/);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		}
		mode = 0;
	}

	rval = sys_open(pathname, flags, mode);

	DbgSCP(" rval = %ld\n", rval);
	return rval;
}


/**
 * check_convert_iovec128_array() - converts protected structure 'iov' into 64-bit one
 *		alone with the check for validity of iov/iovcnt arguments to system calls,
 *		taking iovec structure at input (like readv/writev and so).
 * @iov: input 128-bit user 'iovec' structure pointer.
 * @iovcnt: number of buffers from the file assiciated to read/write.
 * @mode_convert: 1 - convert input structure; 0 - check for proper structure, no conversion.
 * @arg_num: argument number for error messaging.
 * @arg_name: argument name for error messaging.
 * @regs: 'pt_regs' structure (syscall context).
 *
 * Return: Converted 64-bit structure pointer if OK; NULL pointer otherwise.
 */
static struct iovec __user *check_convert_iovec128_array(const void __user *iov,
				       const unsigned long	iovcnt,
				       const unsigned int	mode_convert,
				       const unsigned long	arg_num,
				       const unsigned char	*arg_name,
				       const struct pt_regs	*regs)
{
	const int nr_segs = iovcnt;
	void __user *new_arg = NULL;
	long size;
	long rval; /* syscall return value */

	if (unlikely(nr_segs > UIO_MAXIOV)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_LIMIT,
				     sys_call_ID_to_name[regs->sys_num], nr_segs, UIO_MAXIOV);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return (void __user __force *) (long) (-EINVAL);
	} else if (unlikely(nr_segs < 0)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NEGATIVE_SIZE_VALUE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num], iovcnt, arg_num + 1);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return (void __user __force *) (long) (-EINVAL);
	}

	size = (prot_sc_arg_not_ptr(arg_num, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[arg_num - 1]);
	if (size < (sizeof(struct prot_iovec) * nr_segs)) {
		if (!size_exceeds_descr_max_capacity((sizeof(struct prot_iovec) * iovcnt),
								"iovcnt", iovcnt, regs))
			PROTECTED_MODE_ERROR(PMSCERRMSG_INSUFFICIENT_STRUCT_SIZE,
				     sys_call_ID_to_name[regs->sys_num], "iov",
				     size, (sizeof(struct prot_iovec) * nr_segs));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(arg_num, regs);
		return NULL;
	}

	if (mode_convert) {
		new_arg = get_user_space(nr_segs * sizeof(struct iovec));
		if (!new_arg)
			return (void __user __force *) (long) (-ENOMEM);
		rval = convert_iov(iov, new_arg, nr_segs, false);
	} else {
		new_arg = NULL;
		rval = check_for_iov128_consistency(iov, nr_segs, regs);
	}
	if (rval) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				     sys_call_ID_to_name[regs->sys_num], "iov", arg_name);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return (void __user __force *) (long) (rval);
	}
	return new_arg;
}


notrace __section(".entry.text")
long protected_sys_readv(unsigned long fd, const void __user *vec,
			 int vlen, unsigned long a4,
			 unsigned long a5, unsigned long a6,
			 const struct pt_regs *regs)
{
	e2k_ap_t ap;
	long rval; /* syscall return value */

	if ((long)fd < 0)
		return -EBADF;
	else if (vlen == 0)
		return 0;
	else if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs) || vlen < 0)
		return -EINVAL;

	ap = regs->qargs[1];
	if (AP_OBJ_SIZE(ap) < vlen * sizeof(struct prot_iovec)) {
		return -EFAULT;
	}

	rval = sys_readv(fd, U_AP_PTR(ap), vlen);

	DbgSCP("(fd=%ld, vec=%px, vlen=0x%x) rval = %ld\n", fd, vec, vlen, rval);
	return rval;
}


notrace __section(".entry.text")
long protected_sys_preadv(unsigned long fd, const void __user *vec,
			  int vlen, unsigned long pos_l,
			  unsigned long pos_h, unsigned long a6,
			  const struct pt_regs *regs)
{
	e2k_ap_t ap;
	long rval; /* syscall return value */

	if (vlen == 0)
		return 0;
	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs) || vlen < 0) {
		return -EINVAL;
	}
	ap = regs->qargs[1];
	if (AP_OBJ_SIZE(ap) < vlen * sizeof(struct prot_iovec)) {
		return -EFAULT;
	}
	set_ap_u_border(ap);

	rval = sys_preadv(fd, vec, vlen, pos_l, pos_h);

	DbgSCP(" rval = %ld new_arg= 0x%llx\n", rval, AP_PTR(ap));
	return rval;
}

/* Here we check for tagged words in the given buffer intended for write: */
static void check_buffer_for_tags(const void __user	*buff,
				  const size_t		count,
				  const struct pt_regs	*regs)
{
	const void __user *const orig_buff = buff;
	e2k_qreg_t qword;
	int offset, val_int, tag, i;
	long val_long;
	long cnt;

	if (!count)
		return;

	/* NB> We check word-aligned area within the buffer: */
	offset = (unsigned long)buff & (sizeof(int) - 1);
	buff += offset;
	cnt = count - offset;

	if (cnt <= 0)
		return;

	/* 1a) Check leading word if any: */
	offset = (unsigned long)buff & (sizeof(unsigned long) - 1);
	if (offset) {
		if (get_user_tagged_4(val_int, tag, (__u32 __user *) buff))
			goto err_read;
		if (tag)
			goto err_out;
		buff += sizeof(int);
		cnt -= sizeof(int);
		if (cnt <= 0)
			return;
	}

	/* 1b) Check leading double-word if any: */
	offset = (unsigned long)buff & (DESCRIPTOR_SIZE - 1);
	if (cnt >= sizeof(unsigned long) && offset) {
		if (get_user_tagged_8(val_long, tag, (__u64 __user *) buff))
			goto err_read;
		if (tag)
			goto err_out;
		buff += sizeof(unsigned long);
		cnt -= sizeof(unsigned long);
		if (cnt <= 0)
			return;
	}

	/* 2) Check main big buffer body: */
	for (i = cnt / DESCRIPTOR_SIZE; i > 0; i--) {
		if (get_user_tagged_16(qword, tag, (e2k_ptr_t __user *) buff))
			goto err_read;
		if (tag)
			goto err_out;
		buff += DESCRIPTOR_SIZE;
		cnt -= DESCRIPTOR_SIZE;
	}

	if (cnt <= 0)
		return;

	/* 3a) Check trailing double-word if any: */
	if (cnt >= sizeof(unsigned long)) {
		if (get_user_tagged_8(val_long, tag, (__u64 __user *) buff))
			goto err_read;
		if (tag)
			goto err_out;
		buff += sizeof(unsigned long);
		cnt -= sizeof(unsigned long);
	}

	/* 3b) Check trailing word if any: */
	if (cnt > 0) {
		if (get_user_tagged_4(val_int, tag, (__u32 __user *) buff))
			goto err_read;
		if (tag)
			goto err_out;
	}

	return; /* no tag found */

err_read:
	PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_ERR_FROM,
			     __func__, (unsigned long)buff);
	return;
err_out:
	if (tag) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_UNEXPECTED_TAG_IN_BUFF,
			regs->sys_num, sys_call_ID_to_name[regs->sys_num],
			tag, (unsigned long)orig_buff, (int)count, (unsigned long)buff);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	}
}

notrace __section(".entry.text")
long protected_sys_write(const unsigned int	fd,
			 const void __user	*buff,
			 const size_t		count,
			  const unsigned long	a4,	/* unused */
			  const unsigned long	a5,	/* unused */
			  const unsigned long	a6,	/* unused */
			  const struct pt_regs	*regs)
{
	long rval; /* syscall return value */

	/* NB> Argument correctness has been checked by generic checks in ttable_entry8_C() */

	if (count && !check_buffer_is_readable(regs, 2))
		return -EFAULT;

	if (unlikely(current->mm->context.pm_sc_debug_mode & PM_SC_CHECK4TAGS_IN_BUFF)
			&& count != 0
			&& current->mm->context.pm_sc_check4tags_max_size >= count)
		check_buffer_for_tags(buff, count, regs);

	rval = sys_write(fd, buff, count);

	DbgSCP(" rval = %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_writev(unsigned long fd, const void __user *vec,
			  int vlen, unsigned long a4,
			  unsigned long a5, unsigned long a6,
			  const struct pt_regs *regs)
{

	e2k_ap_t ap;
	long rval; /* syscall return value */

	if (vlen == 0)
		return 0;
	if (vlen < 0)
		return -EINVAL;
	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		return -EINVAL;
	}
	ap = regs->qargs[1];
	if (AP_OBJ_SIZE(ap) < vlen * sizeof(struct prot_iovec)) {
		return -EFAULT;
	}

	rval = sys_writev(fd, U_AP_PTR(ap), vlen);

	DbgSCP(" rval = %ld new_arg= 0x%llx\n", rval, AP_PTR(ap));
	return rval;
}

notrace __section(".entry.text")
long protected_sys_pwritev(unsigned long fd, const void __user *vec,
		int vlen, unsigned long pos_l, unsigned long pos_h,
		unsigned long a6, const struct pt_regs *regs)
{
	e2k_ap_t ap;
	long rval; /* syscall return value */

	if (vlen == 0)
		return 0;
	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		return -EINVAL;
	}
	if (vlen < 0)
		return -EINVAL;
	ap = regs->qargs[1];
	if (AP_OBJ_SIZE(ap) < vlen * sizeof(struct prot_iovec)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     sys_call_ID_to_name[regs->sys_num], "vec", AP_OBJ_SIZE(ap),
				     "vlen", sizeof(struct prot_iovec) * vlen);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EFAULT;
	}

	rval = sys_pwritev(fd, vec, vlen, pos_l, pos_h);

	DbgSCP(" rval = %ld new_arg= 0x%llx\n", rval, AP_PTR(ap));
	return rval;
}

notrace __section(".entry.text")
long protected_sys_preadv2(unsigned long fd, const void __user *vec,
		int vlen, unsigned long pos_l, unsigned long pos_h,
		rwf_t flags, const struct pt_regs *regs)
{
	e2k_ap_t ap;
	long rval; /* syscall return value */

	if (vlen == 0)
		return 0;
	if (vlen == 0)
		return 0;
	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		return -EINVAL;
	}
	if (vlen < 0)
		return -EINVAL;
	ap = regs->qargs[1];
	if (AP_OBJ_SIZE(ap) < vlen * sizeof(struct prot_iovec)) {
		return -EFAULT;
	}

	rval = sys_preadv2(fd, U_AP_PTR(ap), vlen, pos_l, pos_h, flags);

	DbgSCP(" rval = %ld new_arg= 0x%llx\n", rval, AP_PTR(ap));
	return rval;
}

notrace __section(".entry.text")
long protected_sys_pwritev2(unsigned long fd, const void __user *vec,
			    int vlen, unsigned long offset_l,
			    unsigned long offset_h, rwf_t flags,
			    struct pt_regs *regs)
{
	e2k_ap_t ap;
	long rval; /* syscall return value */

	if (vlen == 0)
		return 0;
	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		return -EINVAL;
	}
	if (vlen < 0)
		return -EINVAL;
	ap = regs->qargs[1];
	if (AP_OBJ_SIZE(ap) < vlen * sizeof(struct prot_iovec)) {
		return -EFAULT;
	}

	rval = sys_pwritev2(fd, U_AP_PTR(ap), vlen, offset_l, offset_h, flags);

	DbgSCP(" rval = %ld new_arg= 0x%llx\n", rval, AP_PTR(ap));
	return rval;
}

notrace __section(".entry.text")
long protected_sys_socketcall(const unsigned long        call,
			      const unsigned long __user *args,
			      const unsigned long unused3,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs)
{
#define ETAGINT (ETAGEWD << 4)
	long ret = -EINVAL; /* default error result */
	struct pt_regs new_regs;
	long args_size;
	unsigned long arg64[6], arg_tags;
	protected_system_call_func sys_call = (protected_system_call_func) (void *) sys_ni_syscall;
	int sys_num, tag, argN, ind;
	int top_64bit_args_num = 6; /* 64-bit interface by default  */
	int extra_64bit_arg_num = -1; /* second int arg in 128-bit interface; f.e. see 'send' */

	if (!args)
		goto out_err;
	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs)) {
		ret = -EFAULT;
		goto out_err;
	}
	args_size = AP_OBJ_SIZE(regs->qargs[1]);
	if (args_size <= 0)
		goto out_err;

	/*
	 * NB> 'top_64bit_args_num' specifies the number of the top 8-bit arguments
	 *	in the 'args' array; other arguments store 128-bit pointers (descriptors).
	 *	Zero value means every argument occupies 16 bytes per arg.
	 *	Value 4 means first four args are integers, 8 bytes per arg;
	 *		and 5th and 6th args are pointers, 16 bytes each.
	 *	Value 6 means all args are of integer type and occupy 8 bytes per arg.
	 * NB> 'extra_64bit_arg_num' is double int arg number (starting from 1) stored along
	 *	with another int arg in 128-bit interface. For example:
	 *	27   struct
	 *	28   {
	 *	29     long int a; <-- arg #1
	 *	30     void *b;
	 *	31     long int c; <-- arg #3
	 *	32     long int d; <-- extra_64bit_arg_num == 4
	 *	33     void *e;
	 *	34     long int f;
	 *	35   }
	 */
	switch (call) {
	case SYS_ACCEPT:
		sys_num = __NR_accept;
		top_64bit_args_num = 0;
		break;
	case SYS_ACCEPT4:
		sys_num = __NR_accept4;
		top_64bit_args_num = 0;
		extra_64bit_arg_num = 4;
		break;
	case SYS_BIND:
		sys_num = __NR_bind;
		top_64bit_args_num = 0;
		break;
	case SYS_CONNECT:
		sys_num = __NR_connect;
		top_64bit_args_num = 0;
		break;
	case SYS_GETPEERNAME:
		sys_num = __NR_getpeername;
		top_64bit_args_num = 0;
		break;
	case SYS_GETSOCKNAME:
		sys_num = __NR_getsockname;
		top_64bit_args_num = 0;
		break;
	case SYS_GETSOCKOPT:
		sys_num = __NR_getsockopt;
		top_64bit_args_num = 3;
		break;
	case SYS_LISTEN:
		sys_num = __NR_listen;
		top_64bit_args_num = 2;
		break;
	case SYS_RECV:
	case SYS_RECVFROM:
		sys_num = __NR_recvfrom;
		top_64bit_args_num = 0;
		extra_64bit_arg_num = 4;
		break;
	case SYS_RECVMSG:
		sys_num = __NR_recvmsg;
		top_64bit_args_num = 0;
		break;
	case SYS_RECVMMSG:
		sys_num = __NR_recvmmsg;
		top_64bit_args_num = 0;
		extra_64bit_arg_num = 4;
		break;
	case SYS_SENDMSG:
		sys_num = __NR_sendmsg;
		top_64bit_args_num = 0;
		break;
	case SYS_SENDMMSG:
		sys_num = __NR_sendmmsg;
		top_64bit_args_num = 0;
		extra_64bit_arg_num = 4;
		break;
	case SYS_SEND:
	case SYS_SENDTO:
		sys_num = __NR_sendto;
		top_64bit_args_num = 0;
		extra_64bit_arg_num = 4;
		break;
	case SYS_SETSOCKOPT:
		sys_num = __NR_setsockopt;
		top_64bit_args_num = 3;
		break;
	case SYS_SHUTDOWN:
		sys_num = __NR_shutdown;
		break;
	case SYS_SOCKET:
		sys_num = __NR_socket;
		break;
	case SYS_SOCKETPAIR:
		sys_num = __NR_socketpair;
		top_64bit_args_num = 3;
		break;
	default:
		/* unsupported call: */
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_UNSUPPORTED,
				     sys_call_ID_to_name[regs->sys_num], "call", (int)call);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	new_regs.sys_num = sys_num;

	/* Extracting 'args' into 'arg64[]' array: */

	memset(&arg64[0], 0, sizeof(arg64));
	DbgSCP("(call=%ld, args=0x%lx) args_size=%ld\n", call, (unsigned long) args, args_size);
	print_buffer("### args: ###", (void __user *)args,
		     (args_size < 96 ? args_size : 96)); /* 16*6 */
	DbgSCP("\t### new_regs/args:\n");
	argN = 0; /* argyment number */
	ind = 0; /* index (in long's) in 'args' */
	for (arg_tags = 0; argN < 6; argN++, args_size -= 8, ind++) {
		e2k_ptr_t descr;

		if (top_64bit_args_num && argN < top_64bit_args_num) {
			/* this is 8 byte arg section: */
			if (args_size < 8)
				break;
			ret = get_user_tagged_8(arg64[argN], tag, (long __user *) &args[ind]);
			if (ret) {
				DbgSCP("\t[#%d]: get_user_tagged_8(args[0x%x]) returned %ld\n",
				       argN, ind, ret);
				goto out_err;
			}
			if (tag == ETAGINT) { /* 0x50 */
				arg64[argN] &= 0xffffffff; /* zeroing trash in higher word */
			} else if (tag) {
				goto bad_arg_tag;
			}
			DbgSCP("\t[0x%x#%d] %ld / 0x%lx\n", ind, argN, arg64[argN], arg64[argN]);
			new_regs.dargs[argN * 2] = arg64[argN];
			new_regs.dargs[argN * 2 + 1] = 0L;
		} else { /* this is descriptor section */
			/* Fixing alignment if any: */
			if (argN == top_64bit_args_num && (argN & 1)) { /* even number */
				args_size -= 8;
				ind++;
			}
			if (args_size < 16)
				break;
			/* Extracting argument out of 'args': */
			ret = get_user_tagged_16(descr.qword, tag, (long __user *) &args[ind]);
			if (ret)
				goto out_err;
			if (tag == ETAGAPQ) {
				arg64[argN] = AP_PTR(descr);
				new_regs.qargs[argN] = descr;
				if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_COMPLEX_WRAPPERS) &&
						arg64[argN] & 0xf) {
					long size = AP_OBJ_SIZE(descr);

					if (size > 8)
						PROTECTED_MODE_WARNING(
							PMSCWARN_UNALIGNED_DSCR_IN_ARG,
							sys_call_ID_to_name[regs->sys_num],
							arg64[argN], argN);
				}
				DbgSCP("\t[0x%x#%d] 0x%llx : 0x%llx\n",
				       ind, argN, descr.lo, descr.hi);
			} else if (tag == ETAGINT) { /* 0x50 */
				arg64[argN] = (unsigned long) (int) descr.lo;
				new_regs.dargs[argN * 2] = arg64[argN];
				new_regs.dargs[argN * 2 + 1] = 0L;
				DbgSCP("\t[0x%x#%d] %lld / 0x%llx\n",
				       ind, argN, descr.lo, descr.lo);
			} else if (tag) {
				goto bad_arg_tag;
			} else {
				arg64[argN] = descr.lo;
				new_regs.dargs[argN * 2] = arg64[argN];
				new_regs.dargs[argN * 2 + 1] = 0L;
				DbgSCP("\t[0x%x#%d] %lld / 0x%llx\n",
				       ind, argN, descr.lo, descr.lo);
				if ((argN + 2) == extra_64bit_arg_num) {
					argN++;
					arg64[argN] = descr.hi;
					new_regs.dargs[argN * 2] = arg64[argN];
					new_regs.dargs[argN * 2 + 1] = 0L;
					DbgSCP("\t[#%d] %lld / 0x%llx\n", argN, descr.hi, descr.hi);
				}
			}
			args_size -= 8;
			ind++;
		}
		arg_tags |= ((unsigned long)tag) << ((argN + 1) * 8);
		DbgSCP("\t\ttag=0x%x argN=%d arg_tags=0x%lx\n", tag, argN, arg_tags);
	}

	if (!argN) { /* failed to read from 'args' */
		ret = -EFAULT;
		goto out_err;
	}

	new_regs.tags = arg_tags;

	sys_call = sys_call_table_entry8[sys_num];

	DbgSCP("==> #%d/%s(0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx) arg_tags=0x%lx\n",
	       sys_num, sys_call_ID_to_name[sys_num],
	       arg64[0], arg64[1], arg64[2], arg64[3], arg64[4], arg64[5], arg_tags);

	ret = sys_call(arg64[0], arg64[1], arg64[2], arg64[3], arg64[4], arg64[5], &new_regs);
	DbgSCP("rval = %ld\n", ret);

	return ret;

bad_arg_tag:
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_DEBUG))
		pr_err("%s :: [#%d] bad arg tag 0x%x\n", __func__, argN, tag);
out_err:
	PROTECTED_MODE_WARNING(PMSCERRMSG_SC_CMD_WRONG_ARG_VALUE_LX,
			       sys_call_ID_to_name[regs->sys_num],
			       "call", (int) call, "args", args);
	PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	return ret;
}


static inline
int check_for_socketcall_args(void __user *addr_val, long *addr_len,
			const int argN, const char *addrValArgName,
			const char *addrLenArgName, int expected_error,
			const struct pt_regs *regs)
{
	long dlen;
	int out_error = expected_error ? expected_error : EINVAL;

	if (!addr_val)
		return 0; /* 'addr_val' may be NULL */

	if (warn_if_not_descr(argN, CHECK4DESCR_WARNING, regs))
		return (out_error > 0) ? -out_error : out_error;

	dlen = AP_OBJ_SIZE(regs->qargs[argN - 1]);
	if (dlen < *addr_len) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
				     sys_call_ID_to_name[regs->sys_num],
				     addrLenArgName, *addr_len, addrValArgName, (unsigned int)dlen);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(argN, regs);
		if (dlen)
			*addr_len = dlen; /* not user address */
		PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED, dlen);
	}
	/* Check for proper alignment of 'addr_val': */
	if (!IS_ALIGNED((unsigned long)addr_val, 16)) {
		long size = AP_OBJ_SIZE(regs->qargs[argN - 1]);

		if (size > 8) {
			PROTECTED_MODE_WARNING(PMSCWARN_UNALIGNED_DSCR_IN_ARG,
						sys_call_ID_to_name[regs->sys_num],
						(unsigned long)addr_val, argN);
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		}
	}

	return 0;
}

static inline
int check_for_socketcall_args_long_len(void __user *addr_val, long __user *addr_len,
			const int argN, const char *addrValArgName, const char *addrLenArgName,
			const struct pt_regs *regs)
{
	long alen, ulen, ret;

	if (!addr_val)
		return 0; /* 'addr_val' may be NULL */
	else if (!addr_len)
		return -EFAULT;

	ret = get_user(alen, addr_len);
	if (ret)
		return ret;
	ulen = alen;
	ret = check_for_socketcall_args(addr_val, &ulen,
					argN, addrValArgName, addrLenArgName, 0, regs);
	if (alen != ulen) {
		ret = put_user(ulen, addr_len);
		if (ret)
			return (int)ret;
	}

	return 0;
}

static inline
int check_for_socketcall_args_int_len(void __user *addr_val, int __user *addr_len,
			const int argN, const char *addrValArgName, const char *addrLenArgName,
			const struct pt_regs *regs)
{
	long llen;
	int ilen = 0, ret;

	if (!addr_val)
		return 0;
	else if (!addr_len)
		return -EFAULT;

	ret = get_user(llen, addr_len);
	if (ret)
		return ret;
	llen = ilen;

	ret = check_for_socketcall_args(addr_val, &llen,
					argN, addrValArgName, addrLenArgName, 0, regs);
	if (ret)
		return ret;

	if (ilen != (int)llen) {
		ilen = (int)llen;
		ret = put_user(ilen, addr_len);
		if (ret)
			return ret;
	}
	return 0;
}

notrace __section(".entry.text")
long protected_sys_accept(const int sockfd, struct sockaddr __user *addr, int __user *addrlen,
			const unsigned long unused4,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long ret;

	ret =  check_for_socketcall_args_int_len(addr, addrlen, 2, "addr", "addrlen", regs);
	if (ret)
		return ret;

	ret = sys_accept(sockfd, addr, addrlen);
	DbgSCP("(sfd=%d, addr=%px, alen) rval = %ld\n", sockfd, addr, ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_accept4(const int sockfd, struct sockaddr __user *addr, int __user *addrlen,
			   const int flags,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long ret;

	ret =  check_for_socketcall_args_int_len(addr, addrlen, 2, "addr", "addrlen", regs);
	if (ret)
		return ret;

	ret = sys_accept4(sockfd, addr, addrlen, flags);
	DbgSCP("(sfd=%d, addr=%px, alen, fl=0x%x) rval = %ld\n", sockfd, addr, flags, ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_getpeername(const int sockfd,
			       struct sockaddr __user *addr, int __user *addrlen,
			const unsigned long unused4,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long ret;

	ret =  check_for_socketcall_args_int_len(addr, addrlen, 2, "addr", "addrlen", regs);
	if (!ret)
		ret = sys_getpeername(sockfd, addr, addrlen);
	DbgSCP("(sfd=%d, addr=%px, addrlen=%px) rval = %ld\n", sockfd, addr, addrlen, ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_getsockname(const int sockfd,
			       struct sockaddr __user *addr, int __user *addrlen,
			const unsigned long unused4,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long ret;

	ret =  check_for_socketcall_args_int_len(addr, addrlen, 2, "addr", "addrlen", regs);
	if (!ret)
		ret = sys_getsockname(sockfd, addr, addrlen);
	DbgSCP("(sfd=%d, addr=%px, addrlen=%px) rval = %ld\n", sockfd, addr, addrlen, ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_getsockopt(const int sockfd, const int level, const int optname,
			      char __user *optval,
			      int __user *restrict optlen,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long ret;

	ret =  check_for_socketcall_args_int_len(optval, optlen, 4, "optval", "optlen", regs);
	if (ret)
		return ret;

	ret = sys_getsockopt(sockfd, level, optname, optval, optlen);
	DbgSCP("(sfd=%d, level=%d, oname=%d, oval=%px, olen) rval = %ld\n",
	       sockfd, level, optname, optval, ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_setsockopt(const int sockfd, const int level, const int optname,
			      char __user	*optval,
			      int		optlen,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long ret;
	long ulen = (long)optlen;

	DbgSCP("(sfd=%d, level=%d, oname=%d, oval=%px, olen=%d)\n",
	       sockfd, level, optname, optval, optlen);

	ret =  check_for_socketcall_args(optval, &ulen, 4, "optval", "optlen", 0, regs);
	if (ret)
		return ret;

	ret = sys_setsockopt(sockfd, level, optname, optval, (int)ulen);
	DbgSCP("rval = %ld\n", ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_uselib(const char __user *library,
			  const unsigned long a2, /* umdd */
			const unsigned long unused3,
			const unsigned long unused4,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs	*regs)
{
	umdd_t __user *umdd = (umdd_t __user *) a2;
	kmdd_t kmdd;
	int rval; /* syscall return value */

	if (!library || !a2 || !e2k_ptr_str(regs->qargs[0]))
		return -EINVAL;

	if (current->thread.flags & E2K_FLAG_3P_ELF32)
		rval = sys_load_cu_elf32_3P(library, &kmdd);
	else
		rval = sys_load_cu_elf64_3P(library, &kmdd);

	if (rval) {
		unsigned long slen = AP_OBJ_SIZE(regs->qargs[0]);
		char *libr_path;

		if (slen <= 0) {
			libr_path = "NULL";
		} else {
			libr_path = (char *)kmalloc(slen, GFP_KERNEL);
			if (!strncpy_from_user(libr_path, library, slen)) {
				pr_err("%s :: failed to copy library path\n", __func__);
				kfree(libr_path);
				return rval;
			}
		}
		DbgSCP("could not load library '%s' err #%d\n", libr_path, rval);

		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_FAILED_TO_LOAD_LIBRARY,
				       sys_call_ID_to_name[regs->sys_num],
				       libr_path);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		if (slen)
			kfree(libr_path);
		return rval;
	}
	BUG_ON(kmdd.cui == 0);

	rval = PUT_USER_AP(&umdd->mdd_got, kmdd.got_addr, kmdd.got_len, 0, RW_ENABLE);

	if (kmdd.init_got_point) {
		rval = rval ?: PUT_USER_PL(&umdd->mdd_init_got,
					kmdd.init_got_point,
					kmdd.cui);
	} else {
		rval = rval ?: put_user(0L, &LO(umdd->mdd_init_got));
		rval = rval ?: put_user(0L, &HI(umdd->mdd_init_got));
	}
	if (rval) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_FATAL_WRITE_AT,
				       sys_call_ID_to_name[regs->sys_num], umdd);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
	}

	return rval;
}

long protected_sys_mremap(const unsigned long old_address,
			  const unsigned long	old_size,
			  const unsigned long	new_size,
			  const unsigned long	flags,
			  const unsigned long new_address,
			  const unsigned long	unused6,
			  struct pt_regs	*regs)
{
	long rval = -EINVAL;
	long ptr_size;
	e2k_addr_t base;

	if (old_address & ~PAGE_MASK)
		goto nr_mremap_err;
	ptr_size = AP_OBJ_SIZE(regs->qargs[0]);

	DbgSCP("old_address=0x%lx old_size=0x%lx new_size=0x%lx flags=0x%lx new_address=0x%lx\n",
	       old_address, old_size, new_size, flags, new_address);

	if (old_size && ptr_size < old_size) {
		/* Reject, if user tries to remap more than allocated. */
		PROTECTED_MODE_WARNING(PMMMAPMSG_CANT_REMAP_OVER_ALLOCATED,
				       sys_call_ID_to_name[regs->sys_num], old_size, ptr_size);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		rval = -EFAULT;
		goto nr_mremap_err;
	}

	base = sys_mremap(old_address, old_size, new_size, flags, new_address);
	if (base & ~PAGE_MASK) { /* this is error code */
		rval = base;
		goto nr_mremap_err;
	}
	e2k_ap_t ap = MAKE_AP_RW(base, new_size, 0, AP_RW(regs->qargs[0]));
	regs->rval1 = LO(ap);
	regs->rval2 = HI(ap);
	regs->rv1_tag = E2K_AP_LO_ETAG;
	regs->rv2_tag = E2K_AP_HI_ETAG;
	regs->return_desk = 1;
	rval = 0;
	if (old_address != base
			&& check_pm_sc_debug_feature(PM_MM_CHECK_4_DANGLING_POINTERS)) {
		e2k_ptr_t old_descriptor;

		old_descriptor.lo = regs->dargs[0];
		old_descriptor.hi = regs->dargs[1];
		rval = clean_single_descriptor(old_descriptor);
		if (rval) {
			PROTECTED_MODE_WARNING(PMSCWARN_PROC_RETURNED_ERROR,
				sys_call_ID_to_name[regs->sys_num],
				"clean_single_descriptor()", rval);
			PROTECTED_MODE_MESSAGE(1, PMCLNDSCRSMSG_EXITED_WITH_ERR,
				sys_call_ID_to_name[regs->sys_num],
				old_address, old_size, rval);
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
			rval = 0;
		}
	}

	DbgSCP("rval = %ld regs->rval = 0x%lx : 0x%lx\n",
	       rval, regs->rval1, regs->rval2);
	return rval;

nr_mremap_err:
	regs->rval1 = rval;
	regs->rval2 = 0;
	regs->rv1_tag = E2K_NUMERIC_ETAG;
	regs->rv2_tag = E2K_NUMERIC_ETAG;
	regs->return_desk = 1;
	DbgSCP("rval = %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_sendmsg(const unsigned int		sockfd,
			   const void __user		*msg,
			   const unsigned int		flags,
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs)
{
	long rval; /* syscall return value */
	struct user_msghdr __user *converted_msghdr;

	converted_msghdr = convert_msghdr128((struct protected_user_msghdr __user *)msg,
					       NULL, "sendmsg", "msg", regs);
	if (IS_ERR(converted_msghdr))
		return PTR_ERR(converted_msghdr);

	 /* Call socketcall handler function: */
	rval = sys_sendmsg(sockfd, converted_msghdr, flags);

	DbgSCP("(sfd=%d, msg=%px, fl=0x%x) rval = %ld\n", sockfd, msg, flags, rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_recvfrom(const int sockfd,
			    void __user *buff, size_t size, const unsigned flags,
			    struct sockaddr __user *src_addr, int __user *strlen,
				const struct pt_regs	*regs)
{
	long ret;
	long usize = size;

	ret =  check_for_socketcall_args(buff, &usize, 2, "buff", "size", EFAULT, regs);
	if (ret)
		return ret;
	ret =  check_for_socketcall_args_int_len(src_addr, strlen, 5, "addr", "addrlen", regs);
	if (ret) {
		if (ret == -EFAULT) /* NB> LTP expects another error cade in this case */
		return -ENOTSOCK;
	}

	ret = sys_recvfrom(sockfd, buff, usize, flags, src_addr, strlen);
	DbgSCP("(sfd=%d, buff=%px, size=0x%zx, fl=0x%x, addr=%px, strlen) rval = %ld\n",
	       sockfd, buff, size, flags, src_addr, ret);

	return ret;
}

notrace __section(".entry.text")
long protected_sys_recvmsg(const unsigned int		socket,
			   const void __user		*message,
			   const unsigned int		flags,
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs)
{
	long rval; /* syscall return value */
	struct user_msghdr __user *converted_msghdr;
	struct protected_user_msghdr __user *prot_msghdr =
					(struct protected_user_msghdr __user *)message;

	converted_msghdr = convert_msghdr128(prot_msghdr, NULL, "recvmsg", "message", regs);
	if (IS_ERR(converted_msghdr))
		return PTR_ERR(converted_msghdr);
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		DbgSCP("Syscall recvmsg(%d, 0x%lx, 0x%x)::\n",
				socket, (unsigned long)converted_msghdr, flags);
		print_buffer("ptr128_msghdr:",
			     (void __user *) message, sizeof(struct protected_user_msghdr));
		print_buffer("ptr64_msghdr:",
			     (void __user *) converted_msghdr, sizeof(struct user_msghdr));
	}

	 /* Call socketcall handler function: */
	rval = sys_recvmsg(socket, converted_msghdr, flags);
	DbgSCP("Syscall recvmsg(%d, 0x%lx, 0x%x) returned %ld\n",
				socket, (unsigned long)converted_msghdr, flags, rval);

	if (rval >= 0) {
		long ret;

		if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_COMPLEX_WRAPPERS) {
			unsigned int ival;
			unsigned long lval;

			if (!get_user(ival, &converted_msghdr->msg_flags))
				DbgSCP("Syscall recvmsg() returned msg_flags: 0x%x\n", ival);
			if (!get_user(lval, &converted_msghdr->msg_controllen))
				DbgSCP("Syscall recvmsg() returned 'controllen': %ld\n", lval);

		}
		/* Updating the 'msg_flags' field @ user space: */
		ret = copy_in_user(&prot_msghdr->msg_flags, &converted_msghdr->msg_flags,
							sizeof(prot_msghdr->msg_flags));
		if (ret) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_FATAL_WRITE_AT_FIELD,
					       sys_call_ID_to_name[regs->sys_num],
					       &prot_msghdr->msg_flags, "user_msghdr->msg_flags");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
			rval = ret;
		}
		/* Updating the 'controllen' field @ user space: */
		ret = copy_in_user(&prot_msghdr->msg_controllen, &converted_msghdr->msg_controllen,
							sizeof(converted_msghdr->msg_controllen));
		if (ret) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_FATAL_WRITE_AT_FIELD,
				sys_call_ID_to_name[regs->sys_num],
				&prot_msghdr->msg_controllen, "user_msghdr->msg_controllen");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
			rval = ret;
		}
	}

	DbgSCP(" returned %ld\n", rval);
	return rval;
}


#if (!DYNAMIC_DEBUG_SYSCALLP_ENABLED)
#define print_mmsghdr_struct(a1, a2, a3)
#else
static void print_mmsghdr_struct(const char *title,
				 struct mmsghdr __user *mmsghdr_arr,
				 const int vlen)
{
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		int i;

		pr_info("\t##### %s #####\n", title);
		for (i = 0; i < vlen; i++) {
			pr_info("\t##### mmsghdr[%d] : 0x%lx #####\n", i,
				(unsigned long) &mmsghdr_arr[i]);
			print_buffer(NULL, (void __user *) &mmsghdr_arr[i], sizeof(struct mmsghdr));
		}
	}
}
#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */

static long update_prot_mmsghdr_struct(int write,
				       struct mmsghdr      __user *mmsghdr_arr,
				       struct protected_mmsghdr __user *prot_msgvec,
				       const int vlen)
/* This is post-syscall post-processing procedure.
 * Propagate .msg_len values from processed 'mmsghdr_arr' back to 'prot_msgvec'.
 * 'write' - 1 - this is 'sendmmsg' call; 0- this is 'recvmmsg' call.
 * 'vlen' - number of elements in the array.
 * Returns error code or 0 if OK.
 */
{
	long val;
	int flags, i;

	print_mmsghdr_struct("### mmsghdr_arr[#]: ###", mmsghdr_arr, vlen);

	for (i = 0; i < vlen; i++) {
		if (get_user(val, &mmsghdr_arr[i].msg_len)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_FROM, __func__,
					(unsigned long) &mmsghdr_arr[i].msg_len);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
		DbgSCP("mmsghdr[%d].msg_len = %ld\n", i, val);
		if (put_user(val, &prot_msgvec[i].msg_len)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_WRITE_AT,
					     __func__, (unsigned long) &prot_msgvec[i].msg_len);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
		if (write)
			continue;
		if (get_user(flags, &mmsghdr_arr[i].msg_hdr.msg_flags)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_FROM, __func__,
					(unsigned long) &mmsghdr_arr[i].msg_hdr.msg_flags);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
		DbgSCP("mmsghdr[%d].msg_flags = 0x%x\n", i, flags);
		if (put_user(flags, &prot_msgvec[i].msg_hdr.msg_flags)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_WRITE_AT,
					     __func__, (unsigned long) &prot_msgvec[i].msg_hdr.msg_flags);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
	}

	return 0;
}


notrace __section(".entry.text")
long protected_sys_sendmmsg(const unsigned int		sockfd,
			    struct protected_mmsghdr __user	*msgvec,
			    const unsigned int		vlen, /* vector lngth */
			    const unsigned int		flags,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs		*regs)
{
	long size;
	long rval; /* syscall return value */
	int tag;
	struct mmsghdr __user *mmsghdr64;

	DbgSCP(" sockfd=%d  vlen=0x%x\n", sockfd, vlen);

	tag = (regs->tags >> 16 /*2x8*/) & 0xff;
	if (!IS_AP(regs->qargs[1], tag))
		return -EINVAL;

	size = AP_OBJ_SIZE(regs->qargs[1]);
	if (size < vlen *sizeof(struct protected_mmsghdr)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     "sendmmsg", "msgvec", size,
				     "vlen", vlen * sizeof(struct protected_mmsghdr));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EFAULT;
	}

	size = sizeof_mmsghdr64(vlen);
	mmsghdr64 = get_user_space(size);
	if (!mmsghdr64) {
		pr_err("%s:%d : FATAL ERROR: failed to allocate %ld bytes on stack",
		       __FILE__, __LINE__, size);
		return -ENOMEM;
	}

	rval = convert_mmsghdr(msgvec, mmsghdr64, vlen, "sendmmsg", "msgvec", regs);
	if (rval)
		goto out;

	rval = sys_sendmmsg(sockfd, mmsghdr64, vlen, flags);
	DbgSCP("sys_sendmmsg(%d, %px, 0x%x, 0x%x) returned %ld\n",
	       sockfd, mmsghdr64, vlen, flags, rval);

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))
		print_mmsghdr_struct("prot.sendmmsg: post-syscall mmsghdr",
				     mmsghdr64, vlen);
out:
	if (rval <= 0) {
		DbgSCP("failed with error code %ld\n", rval);
	} else {
		/* Propagating .msg_len values back to 'msgvec' */
		long ret;

		ret = update_prot_mmsghdr_struct(1, (struct mmsghdr __user *)mmsghdr64,
						 msgvec, rval);
		if (ret)
			rval = ret;
	}
	DbgSCP(" returned %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_recvmmsg(const unsigned long	sockfd,
			    const struct protected_mmsghdr __user *msgvec,
			    const unsigned int	vlen, /* vector length */
			    const unsigned int	flags,
			    const unsigned long timeout,
			    const unsigned long unused6,
			    const struct pt_regs	*regs)
{
	long size;
	long rval; /* syscall return value */
	struct mmsghdr __user *mmsghdr64;

	DbgSCP(" sockfd=%ld  vlen=%d\n", sockfd, vlen);

	size = AP_OBJ_SIZE(regs->qargs[1]);
	if (size < vlen * sizeof(struct protected_mmsghdr)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     "recvmmsg", "msgvec", size,
				     "vlen", vlen * sizeof(struct protected_mmsghdr));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EINVAL;
	}

	size = sizeof_mmsghdr64(vlen);
	mmsghdr64 = get_user_space(size);
	if (!mmsghdr64) {
		pr_err("%s:%d : FATAL ERROR: failed to allocate %ld bytes on stack",
		       __FILE__, __LINE__, size);
		return -ENOMEM;
	}

	rval = convert_mmsghdr(msgvec, mmsghdr64, vlen, "recvmmsg", "msgvec", regs);
	if (rval)
		goto out;

	rval = sys_recvmmsg(sockfd, mmsghdr64, vlen, flags,
			    (struct __kernel_timespec __user *)timeout);
	DbgSCP("sys_recvmmsg(%ld, %px, 0x%x, 0x%x) returned %ld\n",
	       sockfd, mmsghdr64, vlen, flags, rval);
out:
	if (rval <= 0) {
		DbgSCP("failed with error code %ld\n", rval);
	} else { /* (rval > 0) */
		long ret;

		ret = update_prot_mmsghdr_struct(0, (struct mmsghdr __user *)mmsghdr64,
						 (struct protected_mmsghdr __user *)msgvec, rval);
		if (ret)
			rval = ret;
	}

	return rval;
}


/*
 * Selecting proper convert_array masks (type and align) and argument number
 * to convert protected array of arguments to the corresponding sys_ipc syscall.
 * NB> Elements of the array are normally of types long and descriptor.
 */
notrace __section(".entry.text")
static inline void get_ipc_mask(long call, long *mask_type, long *mask_align,
				int *fields)
{
	/* According to sys_ipc () these are SEMTIMEDOP and (MSGRCV |
	 * (1 << 16))' (see below on why MSGRCV is not useful in PM) calls that
	 * make use of FIFTH argument. Both of them interpret it as a long. Thus
	 * all other calls may be considered as 4-argument ones. Some of them
	 * may accept less than 4 arguments.
	 */
	switch (call) {
	case (MSGRCV | (1 << 16)):
		/* Instead it's much more handy to pass MSGP as PTR (aka FOURTH)
		 * and MSGTYP as FIFTH. `1 << 16' makes it clear to `sys_ipc ()'
		 * that this way of passing arguments is used.
		 */
	case SEMTIMEDOP:
		*mask_type = 0x3d5;
		*mask_align = 0x3f5;
		*fields = 5;
		break;
	case SHMAT:
		/* SHMAT is special because it interprets the THIRD argument as
		 *		a pointer to which AP should be stored in PM.
		 */
		*mask_type = 0xf5;
		*mask_align = 0xfd;
		*fields = 3;
		break;
	case SEMGET:
	case SHMGET:
		*mask_type = 0x15;
		*mask_align = 0x15;
		*fields = 3;
		break;
	case MSGGET:
		*mask_type = 0x5;
		*mask_align = 0x5;
		*fields = 2;
		break;
	default:
		*mask_type = 0xd5;
		*mask_align = 0xf5;
		*fields = 4;
		DbgSCP("default ipc masks used in the ipc call %ld\n", call);
	}
	DbgSCP("call=%ld mask_type=0x%lx mask_align=0x%lx fields=%d\n",
	       call, *mask_type, *mask_align, *fields);
}


static inline
int check_prot_semun_struct(const struct pt_regs *regs,
			    int arg_num, /* argument # in syscall */
			    size_t size) /* min size of descriptor */
/* Returns: 1 - if check passed OK; 0 - otherwise */
{
	/* Check that union semun arg #arg_num contains proper pointer: */
	if (!prot_arg_is_ap(regs, arg_num)) {
		unsigned long ptr = e2k_ptr_objptr(regs->qargs[arg_num - 1], 0);

		DbgSCP("semun = 0x%llx:0x%llx, tag=0x%lx\n",
		       regs->qargs[arg_num - 1].lo, regs->qargs[arg_num - 1].hi,
		       (regs->tags >> (arg_num * 8)) & 0xff);
		PROTECTED_MODE_ERROR(PMCNVSTRMSG_STRUCT_DOESNT_CONTAIN_DESCR,
				     "semun", ptr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return 0;
	}
	if (size) {
		long dscr_size;

		dscr_size = AP_OBJ_SIZE(regs->qargs[arg_num - 1]);
		if (dscr_size < size) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     "semun", dscr_size, size);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return 0;
		}
	}
	return 1;
}

notrace __section(".entry.text")
long protected_sys_semctl(const long	semid,	/* a1 */
			  const long	semnum,	/* a2 */
			  const long	cmd,	/* a3 */
			  void __user	*ptr,	/* a4 */
			  const unsigned long unused5,
			  const unsigned long unused6,
			  const struct pt_regs	*regs)
{
	void __user *fourth = NULL; /* fourth arg to 'semctl' syscall */
	long rval; /* syscall return value */

	if (semid < 0) {
		rval = -EINVAL;
		goto out;
	}

	/* Fields of union semun depend on the 'cmd' parameter */
	switch (cmd & ~IPC_64) {
	/* Pointer in union semun required */
	case IPC_STAT:
	case IPC_SET:
	case SEM_STAT:
	case SEM_STAT_ANY:
		if (!check_prot_semun_struct(regs, 4/*arg#*/, sizeof(struct semid64_ds))) {
			rval = -EFAULT;
			goto out;
		}
		fourth = ptr;
		break;
	case SETALL:
	case GETALL:
		if (!check_prot_semun_struct(regs, 4/*arg#*/, 0/*size*/)) {
			rval = -EFAULT;
			goto out;
		}
		fourth = ptr;
		break;
	case IPC_INFO:
	case SEM_INFO:
		if (!check_prot_semun_struct(regs, 4/*arg#*/, sizeof(struct seminfo))) {
			rval = -EFAULT;
			goto out;
		}
		fourth = ptr;
		break;
	/* Int value in union semun required */
	case SETVAL:
		if (!prot_arg_is_int(regs, 4)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXP_ARG_TAG_ID,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				(regs->tags >> (4 * 8)) & 0xff/*tag*/, 4/*arg#*/);
			rval = -EFAULT;
			goto out;
		}
		fourth = ptr;
		break;
	/* No 'semun' argument */
	default:
		break;
	}

	rval = sys_semctl((int) semid, (int) semnum, (int) cmd, (unsigned long) fourth);
out:
	DbgSCP("(cmd=%d, semnum=%d, semun=0x%px) returned %ld\n",
	       (int) cmd, (int) semnum, fourth, rval);
	return rval;
}

/* long sys_shmat(int shmid, char __user *shmaddr, int shmflg); */
notrace __section(".entry.text")
long protected_sys_shmat(const long		shmid,		/* a1 */
			 const unsigned long	shmaddr,	/* a2 */
			 const long		shmflg,		/* a3 */
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 struct pt_regs		*regs)
{
	unsigned long segm_size = 0;
	ulong base = 0;
	e2k_ap_t ap = (e2k_ap_t){ 0 };
	int  rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;
	long rval; /* syscall return value */

	segm_size = get_shm_segm_size(shmid);
	DbgSCP("(%ld): segm_size = %ld\n", shmid, segm_size);
	if (IS_ERR_VALUE(segm_size)) {
		rval = (long) segm_size;
		goto err_out;
	}
	if (cpu_has(CPU_FEAT_ISET_V7) &&
	    (shmaddr & ap_align_mask(segm_size) || segm_size & ap_align_mask(segm_size))) {
		rval = -ENOTSUPP;
		goto err_out;
	}
	rval = sys_shmat((int) shmid, (char __user *) shmaddr, (int) shmflg);

	if (IS_ERR_VALUE(rval))
		goto err_out;
	base = (ulong) rval;

	/*
	 * 'shmat' syscall post-processing for protected execution mode:
	 * We need to convert obtained shm pointer to descriptor
	 */

	ap = MAKE_AP(base, segm_size); 
	rv1_tag = E2K_AP_LO_ETAG;
	rv2_tag = E2K_AP_HI_ETAG;
	rval = 0;
err_out:
	regs->return_desk = 1;
	regs->rval1 = ap.lo;
	regs->rval2 = ap.hi;
	regs->rv1_tag = rv1_tag;
	regs->rv2_tag = rv2_tag;
	DbgSCP("rval = %ld (hex: %lx) - 0x%llx : 0x%llx    t1/t2=0x%x/0x%x\n",
				rval, rval, ap.lo, ap.hi, rv1_tag, rv2_tag);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_ipc(const unsigned long call, /* a1 */
		       long		first,	/* a2 */
		       unsigned long	second,	/* a3 */
		       unsigned long	third,	/* a4 */
		       void __user	*ptr,	/* a5/fourth */
		       long		fifth,	/* a6 */
		       const struct pt_regs	*regs)
{
	long mask_type, mask_align;
	int fields;
	void __user *fourth = ptr; /* fourth arg to 'ipc' syscall */
	long rval; /* syscall return value */

DbgSCP("%s called with call %ld\n", __func__, call);
return -ENOSYS;
	get_ipc_mask(call, &mask_type, &mask_align, &fields);
	if ((fields == 0) || (unlikely(fields > 5))) {
		pr_err("%s:%d : Bad syscall_ipc field number %ld\n",
		       __FILE__, __LINE__, call);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	/* Syscalls that follow require converting arg-structures: */
	switch (call) {
	case SEMCTL: {
		/* NB> Union semun (5-th argument) contains pointer.
		 * Effective field of union semun depends on cmd parameter:
		 */
		switch (third & ~IPC_64) {
		/* Pointer in union semun required */
		case IPC_STAT:
		case IPC_SET:
		case SEM_STAT:
		case SEM_STAT_ANY:
			if (!check_prot_semun_struct(regs, 5/*arg#*/,
							sizeof(struct semid_ds))) {
				rval = -EFAULT;
				goto out;
			}
			fourth = ptr;
			break;
		case SETALL:
		case GETALL:
			if (!check_prot_semun_struct(regs, 5/*arg#*/, 0/*size*/)) {
				rval = -EFAULT;
				goto out;
			}
			fourth = ptr;
			break;
		case IPC_INFO:
		case SEM_INFO:
			if (!check_prot_semun_struct(regs, 5/*arg#*/,
							sizeof(struct seminfo))) {
				rval = -EFAULT;
				goto out;
			}
			fourth = ptr;
			break;
		/* Int value in union semun required */
		case SETVAL:
			if (!prot_arg_is_int(regs, 5)) {
				PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXP_ARG_TAG_ID,
					regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					(regs->tags >> (5 * 8)) & 0xff/*tag*/, 5/*arg#*/);
				rval = -EFAULT;
				goto out;
			}
			fourth = ptr;
			break;
		/* No union semun as argument */
		default:
			break;
		}
		break;
	}
	case MSGRCV: {
#define MASK_MSG_BUF_PTR_TYPE   0x7 /* type mask for struct msg_buf */
#define MASK_MSG_BUF_PTR_ALIGN  0x7 /* alignment mask for struct msg_buf */
#define SIZE_MSG_BUF_PTR        32  /* size of struct msg_buf with pointer */
		/*
		 * NB> Library uses different msg structure,
		 *		not the one sys_msgrcv syscall uses.
		 * Struct new_msg_buf (ipc_kludge) contains pointer
		 * inside, therefore it needs to be additionally
		 * converted with saving results in these struct
		 */
		struct ipc_kludge __user *converted_new_msg_buf;

		converted_new_msg_buf = get_user_space(sizeof(struct ipc_kludge));
		if (!converted_new_msg_buf)
			return -ENOMEM;
		rval = convert_array(ptr, converted_new_msg_buf,
					SIZE_MSG_BUF_PTR, 2, 1,
					MASK_MSG_BUF_PTR_TYPE,
					MASK_MSG_BUF_PTR_ALIGN, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
					"ipc(MSGRCV, ...)", "ptr", (unsigned long) ptr);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}

		/*
		 * Assign args[3] to pointer to converted new_msg_buf
		 */
		fourth = converted_new_msg_buf;
		break;
	}
	case SHMAT:
		DbgSCP("%s 1: first=0x%lx, ptr=%p, second=0x%lx, third=0x%lx\n",
		       __func__, first, ptr, second, third);
		if (unlikely(!prot_arg_is_ap(regs, 4))) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "third", prot_sc_arg_tag(4, regs));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}
		unsigned long raddr;
		rval = do_shmat(first, (char __user *)ptr, second, &raddr, SHMLBA);
		if (rval)
			return rval;
		e2k_ap_t ap;
		int tag;
		unsigned long segm_size = get_shm_segm_size(first);
		if (IS_ERR_VALUE(segm_size))
			return (long) segm_size;
		DbgSCP("%s 4: rval=0x%lx, raddr=0x%lx, size=0x%lx\n",
			__func__, rval, raddr, segm_size);
		MAKE_TAGGED_AP(ap, tag, raddr, segm_size, 0); 
		return put_user_tagged_16(ap.qword, tag, (void __user *) third);
	default: /* other options don't require extra arg processing */
		break;
	}

	/*
	 * Call syscall_ipc handler function with passing of
	 * arguments to it
	 */

	DbgSCP(" call:%d 1st:0x%x 2nd:0x%lx 3rd:0x%lx\nptr:%p 5th:0x%lx\n",
		(u32) call, (int) first, (unsigned long) second,
		(unsigned long) third, fourth, fifth);

	rval = sys_ipc((u32) call, (int) first, (unsigned long) second,
			(unsigned long) third, fourth, fifth);

out:
	DbgSCP("(%d) returned %ld\n", (int) call, rval);
	return rval;
}

__section(".entry.text")
static long prot_sys_mmap(const unsigned long start,
		unsigned long length, const unsigned long prot,
		const unsigned long flags, const unsigned long fd,
		const unsigned long offset, const int offset_in_bytes,
		struct pt_regs *regs)
{
	long rval = -EINVAL; /* syscall return value */
	e2k_addr_t base;
	e2k_ap_t ap;
	unsigned long initial_length = round_up(length, PAGE_SIZE);
	unsigned long align_mask = 0;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;
	unsigned long size;

	DbgSCP("start = %ld, len = %ld (0x%lx), prot = 0x%lx ", start, length, length, prot);
	DbgSCP("flags = 0x%lx, fd = 0x%lx, off = %ld, in_bytes=%d",
	       flags, fd, offset, offset_in_bytes);
	if (!length)
		goto nr_mmap_err;

	if (cpu_has(CPU_FEAT_ISET_V7)) {
		align_mask = ap_align_mask(length);
		length = (length + align_mask) & ~align_mask;
		if (length >= E2K_VA_END) {
			PROTECTED_MODE_ERROR(PMMMAPMSG_ATTEMPT_TO_MAP_BYTES,
				     "mmap()", length, length);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			goto nr_mmap_enomem;
		}
		if (flags & MAP_FIXED && start & align_mask) {
			goto nr_mmap_enomem;
		}
	} else {
		if (length >> 31) {
			/* NB> For details on this limitation see bug #99875 */
			PROTECTED_MODE_ERROR(PMMMAPMSG_ATTEMPT_TO_MAP_BYTES,
				     "mmap()", length, length);
			PROTECTED_MODE_MESSAGE(0, PMMMAPMSG_CANT_MAP_OVER_2GB);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			/* NB> We cannot simply return error code as
			 *     this syscall returns structured result.
			 */
			goto nr_mmap_enomem;
		}
	}
	size = offset_in_bytes ? offset : (offset * PAGE_SIZE);
	if (size_exceeds_descr_max_capacity(size, "offset", size, regs)) {
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
		goto nr_mmap_enomem;
	}

	if (offset_in_bytes)
		base = sys_mmap((unsigned long) start, (unsigned long) length,
				(unsigned long) prot, (unsigned long) flags,
				(unsigned long) fd, (unsigned long) offset);
	else /* this is __NR_mmap2 */
		base = sys_mmap2((unsigned long) start, (unsigned long) length,
				(unsigned long) prot, (unsigned long) flags,
				(unsigned long) fd, (unsigned long) offset);
	DbgSCP("base = 0x%lx\n", (unsigned long)base);
	if (base & ~PAGE_MASK) { /* this is error code */
		rval = base;
		goto nr_mmap_err;
	}
	if (base & align_mask) {
		/* file operations entry point get_unmaped_area() of requested file does not
		 * support v7 AP alignment rules
		 */
		rval = ENOTSUPP;
		goto nr_mmap_err;
	}
	if (cpu_has(CPU_FEAT_ISET_V7) && length > initial_length) {
		sys_mprotect(base + initial_length, length - initial_length, PROT_NONE);
	}

	if ((flags & MAP_SHARED) /*&& cpu_has(CPU_FEAT_ISET_V6)*/) {
		PROTECTED_MODE_WARN_ONCE(PMSCWARN_MMAP_SHARED_FLAG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], (long)base);
	}

	ap = MAKE_AP(base, length);
	rv1_tag = E2K_AP_LO_ETAG;
	rv2_tag = E2K_AP_HI_ETAG;
	rval = 0;
nr_mmap_out:
	DbgSCP("rval = %ld (0x%lx) dscr = 0x%llx : 0x%llx.%.llx  t1/t2=0x%x/0x%x\n",
	       rval, rval, AP_BASE(ap), (u64)AP_SIZE(ap), (u64)AP_IND(ap), rv1_tag, rv2_tag);
	regs->return_desk = 1;
	regs->rval1 = ap.lo;
	regs->rval2 = ap.hi;
	regs->rv1_tag = rv1_tag;
	regs->rv2_tag = rv2_tag;
	return rval;
nr_mmap_enomem:
	rval = -ENOMEM;
nr_mmap_err:
	ap.lo = 0;
	ap.hi = 0;
	goto nr_mmap_out;
}

__section(".entry.text")
long protected_sys_mmap(const unsigned long	a1, /* start */
			const unsigned long	a2, /* length */
			const unsigned long	a3, /* prot */
			const unsigned long	a4, /* flags */
			const unsigned long	a5, /* fd */
			const unsigned long	a6, /* offset */
				struct pt_regs	*regs)
{
	if (a2 < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], a2, 2/*argnum*/);
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
	}
	if (a6 < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], a6, 6/*argnum*/);
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
	}
	return prot_sys_mmap(a1, a2, a3, a4, a5, a6, 1, regs);
}

__section(".entry.text")
long protected_sys_mmap2(const unsigned long	a1, /* start */
			const unsigned long	a2, /* length */
			const unsigned long	a3, /* prot */
			const unsigned long	a4, /* flags */
			const unsigned long	a5, /* fd */
			const unsigned long	a6, /* offset */
				struct pt_regs	*regs)
{
	if (a2 < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], a2, 2/*argnum*/);
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
	}
	if (a6 < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], a6, 6/*argnum*/);
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
	}
	return prot_sys_mmap(a1, a2, a3, a4, a5, a6, 0, regs);
}


notrace __section(".entry.text")
long protected_sys_unuselib(const unsigned long a1, /* address of module */
			const unsigned long	unused2,
			const unsigned long	unused3,
			const unsigned long	unused4,
			const unsigned long	unused5,
			const unsigned long	unused6,
				struct pt_regs  *regs)
{
	unsigned long rval;
	/* Base address of module data segment */
	unsigned long glob_base = a1;
	/* Size of module data segment */
	size_t glob_size;

	if (warn_if_not_descr(1, CHECK4DESCR_SILENT, regs))
		return -EFAULT;
	glob_size = AP_OBJ_SIZE(regs->qargs[0]);

	/* Unload module from memory */
	if (current->thread.flags & E2K_FLAG_3P_ELF32)
		rval = sys_unload_cu_elf32_3P(glob_base,
						glob_size);
	else
		rval = sys_unload_cu_elf64_3P(glob_base,
						glob_size);

	if (rval) {
		DbgSCP("failed, could not unload module with"
			" data_base = 0x%lx , data_size = 0x%lx\n",
			glob_base, glob_size);
	}

	return rval;
}

notrace __section(".entry.text")
long protected_sys_munmap(const unsigned long	addr,	/* a1 */
			  unsigned long		length,	/* a2 */
			  const unsigned long unused3,
			  const unsigned long unused4,
			  const unsigned long unused5,
			  const unsigned long unused6,
				struct pt_regs	*regs)
{
	long rval; /* syscall return value */

	DbgSCP("(addr=0x%lx, len=0x%lx) ", addr, length);

	if (!addr || !length)
		return -EINVAL;

	if (warn_if_not_descr(1, CHECK4DESCR_SILENT, regs))
		return -EINVAL;

	if (AP_ITAG(regs->qargs[0]) != ITAG_AP) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_DESCR_IN_STACK,
				     sys_call_ID_to_name[regs->sys_num], addr, "addr");
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

/*
 * NB> It is not an error if the indicated range does not contain any mapped pages.
 *     Here we deliver warning just for a case if length exceeds descriptor size.
 */
	if (IF_PM_DBG_MODE(PM_SC_DBG_ISSUE_WARNINGS) &&
		!IF_PM_DBG_MODE(PM_SC_DBG_MODE_NO_ERR_MESSAGES)) {
		size_t dsize = AP_OBJ_SIZE(regs->qargs[0]);

		if (dsize < length)
			PROTECTED_MODE_PWARNING(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE,
			     (u32)regs->sys_num, sys_call_ID_to_name[regs->sys_num],
			     length, dsize, 2 /*arg_num*/);
	}

	rval = sys_munmap(addr, length);
	DbgSCP("rval = %ld (hex: 0x%lx)\n", rval, rval);
	return rval;
}


notrace __section(".entry.text")
long protected_sys_get_backtrace(const unsigned long buf, /* a1 */
				 size_t count, size_t skip,      /* a2,3 */
				 unsigned long flags,            /* a4 */
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs)
{
	long size;

	DbgSCP("(buf=0x%lx, count=%ld, skip=%ld, flags=0x%lx)\n",
	       buf, count, skip, flags);
	size = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);
	if (size < (count * 8)) {
		if (!size_exceeds_descr_max_capacity((count * 8), "count", count, regs))
			PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE,
				     regs->sys_num, "get_backtrace", (count * 8), size, 1);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}
	return sys_get_backtrace((unsigned long *) buf, count, skip, flags);
}

notrace __section(".entry.text")
long protected_sys_set_backtrace(const unsigned long buf, /* a1 */
				 size_t count, size_t skip,      /* a2,3 */
				 unsigned long flags,            /* a4 */
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs)
{
	long size;

	DbgSCP("(buf=0x%lx, count=%ld, skip=%ld, flags=0x%lx)\n",
	       buf, count, skip, flags);
	size = AP_OBJ_SIZE(regs->qargs[0]);
	if (size < (count * 8)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num],
				     (count * 8), size, 1);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}
	return sys_set_backtrace((unsigned long *) buf, count, skip, flags);
}

struct prot_robust_list {
	e2k_ptr_t	next;
};

struct prot_robust_list_head {
	struct prot_robust_list		list;
	long				futex_offset;
	e2k_ptr_t			list_op_pending;
};

#define SIZEOF_PROT_HEAD_STRUCT	(sizeof(struct prot_robust_list_head))

notrace __section(".entry.text")
long protected_sys_set_robust_list(const unsigned long listhead, /* a1 */
				 const size_t len,	/* a2 */
				 const unsigned long unused3,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs)
{
	DbgSCP("(head=0x%lx, len=%zd)\n", listhead, len);

	if (unlikely(len != SIZEOF_PROT_HEAD_STRUCT)) {
		if ((long)len < 0)
			PROTECTED_MODE_ERROR(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     (long)len, 2);
		else
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_DIFFERS_STRUCT_SIZE,
				     sys_call_ID_to_name[regs->sys_num],
				     "len", len, "robust_list_head",
				     SIZEOF_PROT_HEAD_STRUCT);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	if (AP_OBJ_SIZE(regs->qargs[0]) < SIZEOF_PROT_HEAD_STRUCT) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_DIFFERS_STRUCT_SIZE,
				     sys_call_ID_to_name[regs->sys_num],
				     "dsk_len", AP_OBJ_SIZE(regs->qargs[0]),
				     "robust_list_head", SIZEOF_PROT_HEAD_STRUCT);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	current_thread_info()->pm_robust_list.lo = regs->dargs[0];
	current_thread_info()->pm_robust_list.hi = regs->dargs[1];

	return 0;
}


notrace __section(".entry.text")
long protected_sys_get_robust_list(const unsigned long pid,
		e2k_ptr_t __user *head_ptr, size_t __user *len_ptr)
{
	unsigned long ret; /* result of the function */
	struct task_struct *p;
	e2k_ptr_t dscr;
	long len;

	DbgSCP("(pid=%ld, head_ptr=0x%px, len_ptr=0x%px)\n",
	       pid, head_ptr, len_ptr);

	rcu_read_lock();

	ret = -ESRCH;
	if (!pid) {
		p = current;
	} else {
		p = find_task_by_vpid(pid);
		if (!p)
			goto err_unlock;
	}

	ret = -EPERM;
	if (!ptrace_may_access(p, PTRACE_MODE_READ_REALCREDS))
		goto err_unlock;

	dscr = task_thread_info(p)->pm_robust_list;
	rcu_read_unlock();

	if (!dscr.lo) {
		DbgSCP("robust_list is not set yet\n");
		len = sizeof(dscr);
		memset(&dscr, 0, len);
		ret = 0;
		goto empty_list_out;
	}

	len = AP_OBJ_SIZE(dscr);
	DbgSCP("list head stored: lo=0x%llx hi=0x%llx  len=%ld\n",
		dscr.lo, dscr.hi, len);
	if (unlikely(len < SIZEOF_PROT_HEAD_STRUCT)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
				     "robust_list_head", len,
				     (size_t) SIZEOF_PROT_HEAD_STRUCT);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EFAULT;
	}

	DbgSCP("robust_list head: lo=0x%llx  hi=0x%llx  len=%ld\n",
		dscr.lo, dscr.hi, len);

	len = SIZEOF_PROT_HEAD_STRUCT;
empty_list_out:
	if (put_user_tagged_16(dscr.qword, ETAGAPQ, head_ptr) ||
			put_user(len, len_ptr))
		return -EFAULT;

	return 0;

err_unlock:
	rcu_read_unlock();

	return ret;
}

notrace __section(".entry.text")
static
long protected_sys_process_vm_readwritev(const unsigned long pid,
				 const struct prot_iovec __user *lvec,
				 unsigned long           liovcnt,
				 const struct prot_iovec __user *rvec,
				 unsigned long           riovcnt,
				 unsigned long             flags,
				 const struct pt_regs      *regs,
				 const int              vm_write)
{
	pid_t id = pid;
	long rval;

	if (!check_pm_sc_debug_mode(PROTECTED_MODE_SOFT)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ALLOWED_IN_SOFT_MODE,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num]);
		return -ENOSYS;
	}

	DbgSCP("(%ld, lvec=0x%px, lcnt=%ld, rvec=0x%px, rcnt=%ld, flg=0x%lx)\n",
	       pid, lvec, liovcnt, rvec, riovcnt, flags);
	if (liovcnt) {
		if (prot_sc_arg_not_ptr(2, regs))
			return -EFAULT;
		if (AP_OBJ_SIZE(regs->qargs[1]) < (sizeof(struct prot_iovec) * liovcnt)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     sys_call_ID_to_name[regs->sys_num], "lvec",
				     AP_OBJ_SIZE(regs->qargs[1]),
				     "liovcnt", sizeof(struct prot_iovec) * liovcnt);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
			return -EFAULT;
		}
		rval = check_for_iov128_consistency(lvec, liovcnt, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				sys_call_ID_to_name[regs->sys_num], "iovec",  "lvec");
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
			return rval;
		}
	}
	if (riovcnt) {
		if (prot_sc_arg_not_ptr(4, regs))
			return -EFAULT;
		if (AP_OBJ_SIZE(regs->qargs[3]) < (sizeof(struct prot_iovec) * riovcnt)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     sys_call_ID_to_name[regs->sys_num], "rvec",
				     AP_OBJ_SIZE(regs->qargs[3]),
				     "riovcnt", sizeof(struct prot_iovec) * riovcnt);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(4/*arg_num*/, regs);
			return -EFAULT;
		}
		rval = check_for_iov128_consistency(rvec, riovcnt, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				sys_call_ID_to_name[regs->sys_num], "iovec",  "rvec");
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(4/*arg_num*/, regs);
			return rval;
		}
	}

	if (vm_write)
		rval = sys_process_vm_writev(id, (const struct iovec __user *)lvec, liovcnt,
					     (const struct iovec __user *)rvec, riovcnt, flags);
	else
		rval = sys_process_vm_readv(id, (const struct iovec __user *)lvec, liovcnt,
					    (const struct iovec __user *)rvec, riovcnt, flags);
	print_buffer("process_vm_readwritev :: lvec", (void __user *)lvec,
		     liovcnt * sizeof(struct prot_iovec));
	print_buffer("process_vm_readwritev :: rvec", (void __user *)rvec,
		     riovcnt * sizeof(struct prot_iovec));

	return rval;
}

notrace __section(".entry.text")
long protected_sys_process_vm_readv(const unsigned long          pid, /* a1 */
				    const struct prot_iovec __user  *lvec, /* a2 */
				    unsigned long            liovcnt, /* a3 */
				    const struct prot_iovec __user  *rvec, /* a4 */
				    unsigned long            riovcnt, /* a5 */
				    unsigned long              flags, /* a6 */
				    const struct pt_regs       *regs)
{
	return protected_sys_process_vm_readwritev(pid,
						   lvec, liovcnt,
						   rvec, riovcnt,
						   flags, regs, 0);
}

notrace __section(".entry.text")
long protected_sys_process_vm_writev(const unsigned long         pid, /* a1 */
				     const struct prot_iovec __user *lvec, /* a2 */
				     unsigned long           liovcnt, /* a3 */
				     const struct prot_iovec __user *rvec, /* a4 */
				     unsigned long           riovcnt, /* a5 */
				     unsigned long             flags, /* a6 */
				     const struct pt_regs      *regs)
{
	return protected_sys_process_vm_readwritev(pid,
						   lvec, liovcnt,
						   rvec, riovcnt,
						   flags, regs, 1);
}


notrace __section(".entry.text")
long protected_sys_vmsplice(int				fd,      /* a1 */
			 const struct prot_iovec __user	*iov,    /* a2 */
			 unsigned long			nr_segs, /* a3 */
			 unsigned int			flags,   /* a4 */
			 const unsigned long		unused5,
			 const unsigned long		unused6,
			 const struct pt_regs		*regs)
{
	long rval = -EINVAL;
	long size;

	DbgSCP("(fd=%d, iov=0x%px, nr_segs=%ld, flg=0x%x)\n", fd, iov, nr_segs, flags);

	if (fd < 0)
		return -EBADF;
	if (nr_segs == 0)
		return 0;

	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EINVAL;

	size = AP_OBJ_SIZE(regs->qargs[1]);
	if (size < sizeof(struct prot_iovec) * nr_segs) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "iov", size, sizeof(struct iovec));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return rval;
	}
	rval = sys_vmsplice(fd, U_AP_PTR(regs->qargs[1]), nr_segs, flags);
	return rval;
}


notrace __section(".entry.text")
long protected_sys_keyctl(const int	operation,
			const unsigned long	arg2,
			const unsigned long	arg3,
			const unsigned long	arg4,
			const unsigned long	arg5,
			const unsigned long	unused6,
			const struct pt_regs	*regs)
{
	long rval = -EINVAL;
	long size;
	struct iovec __user *iov;
	struct iovec __user *kiov;
	struct keyctl_kdf_params __user *ukdf_params;
	struct keyctl_kdf_params __user *kkdf_params;
	char *str_name;

	switch (operation) {
	case KEYCTL_INSTANTIATE_IOV:
		iov = (struct iovec __user *) arg3;
		if (!iov)
			break;
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < sizeof(struct iovec)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "iov", size, sizeof(struct iovec));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return rval;
		}
		kiov = get_user_space(size);
		if (!kiov)
			return -ENOMEM;
		rval = convert_array(iov, kiov, size, 2, 1/*nr_segs*/, 0x7, 0x7, regs);
		if (rval) {
			str_name = "iov";
			goto err_out;
		}
		return sys_keyctl(operation, arg2, (unsigned long) kiov,
				  arg4, arg5);
	case KEYCTL_DH_COMPUTE:
		ukdf_params = (struct keyctl_kdf_params __user *) arg5;
		if (!ukdf_params)
			break;
		size = (prot_sc_arg_not_ptr(5, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[4]);
		if (size < sizeof(struct keyctl_kdf_params)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					sys_call_ID_to_name[regs->sys_num], "keyctl_kdf_params",
					size, sizeof(struct keyctl_kdf_params));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(5/*arg_num*/, regs);
			return rval;
		}
		kkdf_params = get_user_space(size);
		if (!kkdf_params)
			return -ENOMEM;
		rval = convert_array(ukdf_params, kkdf_params,
				     size, 3, 1/*nr_segs*/, 0x1f, 0x1f, regs);
		if (rval) {
			str_name = "keyctl_kdf_params";
			goto err_out;
		}
		return sys_keyctl(operation, arg2, arg3, arg4,
						(unsigned long) kkdf_params);
	}

	return sys_keyctl(operation, arg2, arg3, arg4, arg5);

err_out:
	PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
			     regs->sys_num, sys_call_ID_to_name[regs->sys_num], str_name, 2);
	PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_prctl(const int	option,
			const unsigned long	arg2,
			const unsigned long	arg3,
			const unsigned long	arg4,
			const unsigned long	arg5,
			const unsigned long	unused6,
			const struct pt_regs	*regs)
{
	long rval = -EINVAL;
	int size, min_size;
	void __user *intptr128;
	void __user *uintptr64;
	char *str_name;

	switch (option) {
	case PR_GET_CHILD_SUBREAPER:
	case PR_GET_ENDIAN:
	case PR_GET_FPEMU:
	case PR_GET_FPEXC:
	case PR_GET_PDEATHSIG:
	case PR_GET_TSC:
	case PR_GET_UNALIGN:
		if (!arg2)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		size = AP_SIZE(regs->qargs[1]);
		if (size < sizeof(int)) {
			str_name = "(int *) arg2";
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, sizeof(int));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		set_ap_u_border(regs->qargs[1]);
		break;

	case PR_GET_NAME:
		if (!arg2)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		size = AP_SIZE(regs->qargs[1]);
		min_size = 16; /* this is specified in Linux Pages */
		if (size < min_size) {
			str_name = "(char *) arg2";
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, min_size);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		set_ap_u_border(regs->qargs[1]);
		break;
	case PR_SET_NAME:
		if (!arg2)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		size = AP_SIZE(regs->qargs[1]);
		if (e2k_ptr_str_check((char __user *) arg2, size)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_STRING_IN_SC_ARG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], 2/*arg#*/);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		}
		set_ap_u_border(regs->qargs[1]);
		break;

	case PR_GET_TID_ADDRESS:
		if (!arg2)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		str_name = "(int **) arg2";
		size = AP_SIZE(regs->qargs[1]);
		if (size < sizeof(int **)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, sizeof(int **));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		intptr128 = (void __user *) arg2;
		uintptr64 = get_user_space(size);
		if (!uintptr64)
			rval = -ENOMEM;
		else
			rval = convert_array(intptr128, uintptr64,
				     size, 1, 1/*nr_segs*/, 0x3, 0x3, regs);
		if (rval)
			goto err_out;
		set_ap_u_border(regs->qargs[1]);
		return sys_prctl(option, (unsigned long) uintptr64, arg3,
				 arg4, arg5);

	case PR_SET_SECCOMP:
		if (!arg3)
			break;
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		str_name = "(sock_fprog *) arg3";
		size = AP_SIZE(regs->qargs[2]);
		if (size < sizeof(struct sock_fprog)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, sizeof(struct sock_fprog));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		/* NB> Filter structure conversion is done in seccomp_prepare_user_filter() */
		set_ap_u_border(regs->qargs[2]);
		return sys_prctl(option, arg2, arg3, arg4, arg5);
	}

	rval = sys_prctl(option, arg2, arg3, arg4, arg5);

	if (rval < 0) {
		char str_args[64] = " ";

		snprintf(str_args, sizeof(str_args), "cmd = %d, arg2 = 0x%lx, arg3 = 0x%lx",
			 option, arg2, arg3);
		PROTECTED_MODE_WARNING(PMSCWARN_PROC_RETURNED_ERROR,
				sys_call_ID_to_name[regs->sys_num], str_args, rval);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, rval);
	}
	DbgSCP("rval = %ld (hex: 0x%lx)\n", rval, rval);
	return rval;

err_out:
	PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
			     regs->sys_num, sys_call_ID_to_name[regs->sys_num], str_name, 2);
	PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_bpf(const int cmd,			/* a1 */
		       void		__user *attr,	/* a2 */
		       const unsigned int attr_size,	/* a3 */
			 const unsigned long unused4,
			 const unsigned long unused5,
			 const unsigned long unused6,
			 const struct pt_regs *regs)
{
	void __user *attr_64 = attr;
	long size_128, size_64 = sizeof(union bpf_attr);
	unsigned int size = attr_size;
	long rval = 0;

	DbgSCP("(cmd=0x%x, attr=0x%lx, size=%d) tags=0x%lx\n",
	       cmd, (unsigned long) attr, size, regs->tags);

	if (attr) {
		int tag = (regs->tags >> 16 /*2x8*/) & 0xff;

		if (IS_AP(regs->qargs[1], tag)) {
			size_128 = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
			if (size_128 < size) {
				PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
					"bpf", "size", (long) size, "attr", (long) size_128);
				DbgSCP("\t\tsize_128=%ld, size_64=%ld, size=%d\n",
					size_128, size_64, size);
				PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
				rval = -EINVAL;
				goto out;
			}
			if (size < size_64)
				size = size_64;
		}
		attr_64 = get_user_space(size);
		if (!attr_64)
			return -ENOMEM;
		/* NB> BPF requires unused attr fields must be zeroed! */
		/* memset(attr_64, 0, size); <-- this is done in get_user_space() */
		switch (cmd) {
		case BPF_MAP_CREATE:
		case BPF_PROG_ATTACH:
		case BPF_PROG_DETACH:
		case BPF_PROG_GET_NEXT_ID:
		case BPF_MAP_GET_NEXT_ID:
		case BPF_PROG_GET_FD_BY_ID:
		case BPF_MAP_GET_FD_BY_ID:
		case BPF_RAW_TRACEPOINT_OPEN:
			/* No pointer in 'attr' for these commands */
			attr_64 = attr;
			break;

		case BPF_MAP_LOOKUP_ELEM:
		case BPF_MAP_UPDATE_ELEM:
		case BPF_MAP_DELETE_ELEM:
		case BPF_MAP_LOOKUP_AND_DELETE_ELEM:
		case BPF_MAP_GET_NEXT_KEY:
#define BPF_MAP_x_ELEM_FIELDS	4
#define BPF_MAP_x_ELEM_MTYPE	0x1330
#define BPF_MAP_x_ELEM_MALIGN	0x1333
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_MAP_x_ELEM_FIELDS, 1/*items*/,
					BPF_MAP_x_ELEM_MTYPE,
					BPF_MAP_x_ELEM_MALIGN, regs);
			break;

		case BPF_PROG_LOAD:
#define BPF_PROG_LOAD_FIELDS	14
#define BPF_PROG_LOAD_MTYPE	0x03131111131331UL
#define BPF_PROG_LOAD_MALIGN	0x03333111133333UL
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_PROG_LOAD_FIELDS, 1/*items*/,
					BPF_PROG_LOAD_MTYPE,
					BPF_PROG_LOAD_MALIGN, regs);
			break;

		case BPF_OBJ_PIN:
		case BPF_OBJ_GET:
#define BPF_OBJ_x_FIELDS	2
#define BPF_OBJ_x_MTYPE		0x13
#define BPF_OBJ_x_MALIGN	0x13
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_OBJ_x_FIELDS, 1/*items*/,
					BPF_OBJ_x_MTYPE,
					BPF_OBJ_x_MALIGN, regs);
			break;

		case BPF_PROG_TEST_RUN:
#define BPF_PTEST_RUN_FIELDS	8
#define BPF_PTEST_RUN_MTYPE	0x33113311
#define BPF_PTEST_RUN_MALIGN	0x33113311
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_PTEST_RUN_FIELDS, 1/*items*/,
					BPF_PTEST_RUN_MTYPE,
					BPF_PTEST_RUN_MALIGN, regs);
			break;

		case BPF_OBJ_GET_INFO_BY_FD:
#define BPF_OBJ_GET_INFO_FIELDS	2
#define BPF_OBJ_GET_INFO_MTYPE	0x31
#define BPF_OBJ_GET_INFO_MALIGN	0x33
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_OBJ_GET_INFO_FIELDS, 1/*items*/,
					BPF_OBJ_GET_INFO_MTYPE,
					BPF_OBJ_GET_INFO_MALIGN, regs);
			break;

		case BPF_PROG_QUERY:
#define BPF_PROG_QUERY_FIELDS	4
#define BPF_PROG_QUERY_MTYPE	0x0311
#define BPF_PROG_QUERY_MALIGN	0x1311
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_PROG_QUERY_FIELDS, 1/*items*/,
					BPF_PROG_QUERY_MTYPE,
					BPF_PROG_QUERY_MALIGN, regs);
			break;

		case BPF_BTF_LOAD:
#define BPF_BTF_LOAD_FIELDS	4
#define BPF_BTF_LOAD_MTYPE	0x0133
#define BPF_BTF_LOAD_MALIGN	0x1133
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_BTF_LOAD_FIELDS, 1/*items*/,
					BPF_BTF_LOAD_MTYPE,
					BPF_BTF_LOAD_MALIGN, regs);
			break;

		case BPF_TASK_FD_QUERY:
#define BPF_TASK_FD_QUERY_FIELDS	6
#define BPF_TASK_FD_QUERY_MTYPE		0x111311
#define BPF_TASK_FD_QUERY_MALIGN	0x1113311
			rval = get_pm_struct_simple(attr, attr_64, size,
					BPF_TASK_FD_QUERY_FIELDS, 1/*items*/,
					BPF_TASK_FD_QUERY_MTYPE,
					BPF_TASK_FD_QUERY_MALIGN, regs);
			break;

		case BPF_BTF_GET_FD_BY_ID:
		case BPF_MAP_FREEZE:
		case BPF_BTF_GET_NEXT_ID:
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_UNSUPPORTED,
					     "bpf()", "CMD", cmd);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			rval = -ENOTSUPP;
			goto out;

		default:
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
					     "bpf()", "cmd", (long) cmd);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			rval = -EINVAL;
			goto out;
		}
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_CMD_WRONG_ARG_VALUE_LX,
					     "bpf", "cmd", cmd, "attr", attr);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			goto out;
		}
	}
	rval = sys_bpf(cmd, (union bpf_attr __user *) attr_64, size);

out:
	DbgSCP("\treturned %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_select(int				nfds,		/* a1 */
			  fd_set __user			*readfds,	/* a2 */
			  fd_set __user			*writefds,	/* a3 */
			  fd_set __user			*exceptfds,	/* a4 */
			  struct __kernel_old_timeval __user *timeout,	/* a5 */
			  const unsigned long		unused6,	/* a6 */
			  const struct pt_regs *regs)
{
	long size;
	int max_fds, expected_size;
	struct fdtable *fdt;
	long rval;

	if (nfds < 0)
		return -EINVAL;

	/* max_fds can increase, so grab it once to avoid race */
	rcu_read_lock();
	fdt = files_fdtable(current->files);
	max_fds = fdt->max_fds;
	rcu_read_unlock();
	if (nfds > max_fds)
		nfds = max_fds;
	expected_size = (nfds + 7) / 8;

	/* Check descriptor's size of 2nd argument. */
	size = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
	if (size && size < expected_size) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "readfds", size, (size_t) expected_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	/* Check descriptor's size of 3rd argument. */
	size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
	if (size && size < expected_size) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "writefds", size, (size_t) expected_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	/* Check descriptor's size of 4th argument. */
	size = (prot_sc_arg_not_ptr(4, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[3]);
	if (size && size < expected_size) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "exceptfds", size, (size_t) expected_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	rval = sys_select(nfds, readfds, writefds, exceptfds, timeout);
	DbgSCP("sys_select(nfds=%d, ...) returned %ld\n", nfds, rval);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_pselect6(const long			nfds,		/* a1 */
			    const unsigned long readfds,		/* a2 */
			    const unsigned long writefds,	/* a3 */
			    const unsigned long exceptfds,	/* a4 */
			    const unsigned long timeout,		/* a5 */
			    const unsigned long sigmask,		/* a6 */
			    const struct pt_regs *regs)
{
	long size;
	void __user *sigmask_ptr64 = NULL;
	long rval;

	DbgSCP("(nfds=%ld, ...)\n", nfds);

	if (sigmask) {
#define STRUCT_SIGSET6_FIELDS		2
#define STRUCT_SIGSET6_MASK_TYPE	0x7
#define STRUCT_SIGSET6_MASK_ALIGN	0x7
#define STRUCT_SIGSET6_PROT_SIZE	24 /* sizeof(modified sigmask) in PM */

		/* Check descriptor's size of 6th argument. */
		size = (prot_sc_arg_not_ptr(6, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[5]);
		if (size < STRUCT_SIGSET6_PROT_SIZE) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					     __func__, "'sigmask'", size,
					(size_t) STRUCT_SIGSET6_PROT_SIZE);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}

		/* Translate struct sigmask from user128 to kernel64 mode. */
		sigmask_ptr64 = get_user_space(size);
		if (!sigmask_ptr64)
			return -ENOMEM;
		rval = convert_array((long __user *)sigmask, sigmask_ptr64,
				     size, STRUCT_SIGSET6_FIELDS, 1 /*items*/,
					STRUCT_SIGSET6_MASK_TYPE,
					STRUCT_SIGSET6_MASK_ALIGN, regs);
		if (rval) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "sigmask", 6);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
	}

	rval = sys_pselect6((int) nfds, (void __user *) readfds, (void __user *) writefds,
			    (void __user *) exceptfds, (void __user *) timeout,
			    (void __user *) sigmask_ptr64);
	DbgSCP("sys_pselect6(nfds=%ld, ...) returned %ld\n", nfds, rval);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_mincore(const unsigned long	addr,	/* a1 */
			   size_t		length,	/* a2 */
			   unsigned char __user	*vec,	/* a3 */
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs *regs)
{
	long rval;
	long size;
	size_t min_length = (length + PAGE_SIZE - 1) / PAGE_SIZE;

	size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
	DbgSCP("addr=0x%lx length=0x%zx vec=0x%px size=0x%lx min_length=0x%zx",
	       addr, length, vec, size, min_length);
	if (size > 0 && size < min_length) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     size, min_length, 3/*arg_num*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		rval = -ENOMEM;
	} else {
		rval = sys_mincore(addr, length, vec);
	}
	DbgSCP("sys_mincore(addr=0x%lx, length=0x%zx, vec=0x%px) returned %ld\n",
		addr, length, vec, rval);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_process_madvise(const long		pidfd,		/* a1 */
				   void __user		*vec,		/* a2 */
				   const long		vlen,		/* a3 */
				   const unsigned long	behavior,	/* a4 */
				   const unsigned long	flags,		/* a5 */
				   const unsigned long unused6,		/* a6 */
				   const struct pt_regs *regs)
{
	long rval;

	if (vec) {
		if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs) || vlen < 0)
			return -EINVAL;
		rval = (unsigned long) check_convert_iovec128_array(vec, vlen, 0, 2, "vec", regs);
		if (unlikely(rval)) {
			return rval;
		}
	} else {
		DbgSCP("Empty struct \'iovec\' in %s\n", __func__);
	}

	rval = sys_process_madvise(pidfd, vec, vlen, behavior, flags);
	DbgSCP("%s(pidfd=%ld, ...) returned %ld\n", __func__, pidfd, rval);

	return rval;
}

/* Post-processor aimed to return syscall termination status
 *          from temporal structure used to run syscall back
 *            to original protected structure.
 * 'update_all' - update whole structure (all fields); top only otherwise.
 * Returns error code from put_user() or 0 if OK.
 */
static
int update_protected_siginfo_t(void __user *siginfo64,
			       void __user *siginfo128)
{
	int rval = 0;
	/*
	  Structure siginfo_t consists of 5 'int's + ptr/int + ...

		-= 128 bit format: =-			-= 64 bit format: =-
	63            32               0      63            32               0
	+===============|===============+     +===============|===============+
	|   si_errno    |   si_signo    |  0  |   si_errno    |   si_signo    |
	+===============|===============+     +===============|===============+
	| XXXXXXXXXXXXX |   si_code     |  1  | XXXXXXXXXXXXX |   si_code     |
	+===============|===============+     +===============|===============+
	|     _uid      |      _pid     |  2  |     _uid      |      _pid     |
	+===============|===============+     +===============|===============+
	| XXXXXXXXXXXXX |   si_status   |  3  |  sigval_t: {si_status/si_ptr} |
	+===============|===============+     +===============|===============+
	| sigval_t: {status/si_ptr(lo)} |  4  |              ...              |
	+---------------|---------------+
	|         sival_ptr(hi)         |  5
	+===============|===============+
	|              ...              |  6
	*/

	if (!siginfo64 || !siginfo128) {
		DbgSCP("Empty input: siginfo64=0x%px siginfo128=0x%px\n",
		       siginfo64, siginfo128);
		return rval;
	}

	if (copy_in_user(siginfo128, siginfo64, 32)) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_FATAL_WRITE_AT, __func__,
				(unsigned long) siginfo128);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
		return -EFAULT;
	}
	return 0;
}


notrace __section(".entry.text")
long protected_sys_waitid(const long		which,		/* a1 */
			  const long		pid,		/* a2 */
			  void		__user *infop,		/* a3 */
			  const long		options,	/* a4 */
			  void		__user *ru,		/* a5 */
			  const unsigned long unused6,
			  const struct pt_regs *regs)
{
	void __user *siginfo64 = NULL;
	long rval;

	DbgSCP("which=%ld, pid=%ld, infop=0x%lx, options=0x%x, ru=0x%px\n",
	       which, pid, (unsigned long) infop, (int) options, ru);

	if (infop) {
		long size;

		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < sizeof(siginfo_t)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					     __func__, "'infop'",
						size, sizeof(siginfo_t));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		/* NB> The syscall only updates the 'infop' structure.
		 *     Therefore we don't need to convert input 'infop' structure.
		 */
		siginfo64 = get_user_space(sizeof(siginfo_t));
		if (!siginfo64)
			return -ENOMEM;
	}

	rval = sys_waitid((int) which, (pid_t) pid,
			  (struct siginfo __user *) siginfo64,
			  (int) options, (struct rusage __user *) ru);
	if (!rval)
		(void) update_protected_siginfo_t(siginfo64, infop);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_io_submit(const aio_context_t	ctx_id,	/* a1 */
			     const long			nr,	/* a2 */
			     const struct iocb __user * __user *iocbpp,	/* a3 */
			     const unsigned long unused4,
			     const unsigned long unused5,
			     const unsigned long unused6,
			     const struct pt_regs *regs)
{
	long ret;
	long size;
	struct iocb __user * __user *iocbpp64;

	if (!iocbpp || !nr)
		return 0;

	if (nr < 0)
		return -EINVAL;

	if (warn_if_not_descr(3, CHECK4DESCR_SILENT, regs))
		return -EFAULT;

	size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
	if (size < nr * sizeof(e2k_ptr_t)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "iocbpp", size, nr * sizeof(e2k_ptr_t));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return -EFAULT;
	}

	iocbpp64 = get_user_space(nr * sizeof(*iocbpp64));
	ret = iocbpp64 ? convert_array(iocbpp, iocbpp64, size, 1, nr, 0x3, 0x3, regs)
			: -ENOMEM;
	if (ret)
		return ret;
	return sys_io_submit(ctx_id, nr, iocbpp64);
}

notrace __section(".entry.text")
long protected_sys_io_uring_register(unsigned int fd,
				     unsigned int opcode,	/* a2 */
				     void __user *arg,		/* a3 */
				     unsigned int nr_args,	/* a4 */
				     const unsigned long unused5,
				     const unsigned long unused6,
				     const struct pt_regs *regs)
{
	long rval;
	long size;

	DbgSCP("fd=%d, opcode=%d, arg=0x%px, nr_args=0x%x\n",
	       fd, opcode, arg, nr_args);

	if (!arg)
		goto run_syscall;

	switch (opcode) {
	case IORING_REGISTER_BUFFERS:
		/* arg points to a struct iovec array of nr_args entries */
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EFAULT;

		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < (DESCRIPTOR_SIZE * nr_args)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				sys_call_ID_to_name[regs->sys_num], "'arg'", size,
				(DESCRIPTOR_SIZE * nr_args));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		/* NB> Function io_copy_iov() takes 64-bit 'iovec' structure. */
		arg = check_convert_iovec128_array(arg, nr_args, 1, 3, "arg", regs);
		if (unlikely(IS_ERR(arg))) {
			return PTR_ERR(arg);
		}
		if (!arg) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "arg");
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}
		break;
	case IORING_REGISTER_FILES:
		/* arg contains a pointer to an array of nr_args file ids
		 * (signed 32 bit integers) */
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EINVAL;
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < (sizeof(int) * nr_args)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					sys_call_ID_to_name[regs->sys_num], "'arg'", size,
					(sizeof(int) * nr_args));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		break;
	case IORING_REGISTER_EVENTFD:
	case IORING_REGISTER_EVENTFD_ASYNC:
		/* arg must contain a pointer to the eventfd file descriptor,
		 * and nr_args must be 1 */
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EINVAL;
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < (sizeof(int))) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					sys_call_ID_to_name[regs->sys_num], "'arg'",
					size, sizeof(int));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		break;
	case IORING_REGISTER_RESTRICTIONS:
		/* arg points to a struct io_uring_restriction array of nr_args entries */
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EINVAL;
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < (nr_args * sizeof(struct io_uring_restriction))) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					sys_call_ID_to_name[regs->sys_num], "'arg'", size,
					(nr_args * sizeof(struct io_uring_restriction)));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		break;
	default:
		PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_UNSUPP_VAL_IN_SC_ARG,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     "opcode", opcode, 2);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return -EINVAL;
	}

run_syscall:
	rval = sys_io_uring_register(fd, opcode,
				     arg, (unsigned int) nr_args);

	return rval;
}


struct prot_io_uring_getevents_arg {
	__u64		sigmask;
	__u32		sigmask_sz;
	__u32		pad;
	e2k_ap_t	ts;
};

/**
 * get_ptr64_struct_io_uring_getevents_arg() - Converts 128-bit structure to the 64-bit format one
 *								allocated in user stack area.
 * @uargp128: pointer to protected structure 'io_uring_getevents_arg'.
 * @uargp64: pointer to allocated 64-bit structure 'io_uring_getevents_arg'.
 * @arg_num: argument number in the syscall (for error reporting).
 * @argsz64: pointer to the total memory size allocated in user stack area.
 * @regs: 'pt_regs' structure (syscall context).
 *
 * Return: Error number or 0 if conversion succeeded.
 */
static inline
long get_ptr64_struct_io_uring_getevents_arg(const void __user		*uargp128,
					  void __user			**uargp64,
					  const int			arg_num,
					  size_t			*argsz64,
					  const struct pt_regs		*regs)
{
	struct prot_io_uring_getevents_arg __user *argp128 =
				(struct prot_io_uring_getevents_arg __user *)uargp128;
	struct io_uring_getevents_arg __user *argp64 = NULL;
	e2k_ap_t dscr;
	int tags;
	size_t size, uargp64_size;
	long err;

	/* NB> Structure 'sigmask' is optional size one.
	 *	Size may differ from kernel one and be user-defined.
	 *	Therefore we copy 'sigmask' field as is (using size of 'sigmask_sz')
	 *	and then add 'ts' pointer and other stuff extracted from the 'ts' structure.
	 */

	err = get_user_tagged_16(dscr.qword, tags, &argp128->ts);
	if (err)
		return err;
	if ((!tags && dscr.qword.lo) || (tags && tags != ETAGAPQ)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num], "argp", tags);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		err = -EINVAL;
		return err;
	} else if (IS_AP(regs->qargs[1], tags)) {
		if (AP_OBJ_SIZE(regs->qargs[arg_num - 1]) <
					(sizeof(struct prot_io_uring_getevents_arg))) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				AP_OBJ_SIZE(regs->qargs[arg_num - 1]),
				sizeof(struct prot_io_uring_getevents_arg), arg_num);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
			return -EFAULT;
		}
	}

	/* 'ts' is a valid pointer to struct prot_io_uring_getevents_arg. */

	uargp64_size = sizeof(struct io_uring_getevents_arg);
	argp64 = (struct io_uring_getevents_arg __user *) get_user_space(uargp64_size);
	if (!argp64)
		return -ENOMEM;

	/* Copying structure up to 'ts' field as is: */

	size = offsetof(struct io_uring_getevents_arg, ts);
	err = copy_in_user((void __user *)argp64, (void __user *)argp128, size);
	if (err)
		return err;

	/* Adding 'ts' pointer to 'argp64': */

	err = put_user(AP_PTR(dscr), &(argp64->ts));
	if (err)
		return err;

	if (uargp64)
		*uargp64 = argp64;
	if (argsz64)
		*argsz64 = uargp64_size;

	return err;
}

notrace __section(".entry.text")
long protected_sys_io_uring_enter(unsigned int fd, u32 to_submit,
				  u32 min_complete, u32 flags,
				  const void __user *argp,      /* a5 */
				  size_t argsz,                 /* a6 */
				  const struct pt_regs *regs)
{
	long rval;
	void __user *argp64;
	size_t argsz64;

	DbgSCP("(fd=0x%x, to_submit=0x%x, min_complete=0x%x, flags=0x%x, argp=0x%p, argsz=%zd)\n",
		fd, to_submit, min_complete, flags, argp, argsz);

	if (prot_sc_arg_not_ptr(5, regs)) {
		/* NB> This is 'io_uring_enter(1)' call with numeric value in 'argp': */
		rval = sys_io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz);
		goto out;
	}

	if (!(flags & IORING_ENTER_EXT_ARG)) { /* check for proper descriptor size */
		int size, argp_size;

		argp_size = AP_SIZE(regs->qargs[5]);
		size = argsz ? argsz : sizeof(sigset_t);
		if (size < argp_size) {
			if (size) {
				if (!size_exceeds_descr_max_capacity(size, "argp", size, regs))
					PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     (int) size, argp_size, 5);
				PM_BNDERR_EXCEPTION_IF_ORTH_MODE(5/*arg_num*/, regs);
			}
		}
	}

	if (!argsz || !(flags & IORING_ENTER_EXT_ARG)) {
		/* NB> This is 'io_uring_enter' syscall format: */
		rval = sys_io_uring_enter(fd, to_submit, min_complete, flags, argp, argsz);
		goto out;
	}

	/* NB> This is 'io_uring_enter2' syscall format with IORING_ENTER_EXT_ARG flag set: */

	rval = get_ptr64_struct_io_uring_getevents_arg((void __user *)argp,
						       (void __user **)&argp64,
						       5, &argsz64, regs);
	rval = rval ?: sys_io_uring_enter(fd, to_submit, min_complete, flags, argp64, argsz64);

out:	DbgSCP("rval = %ld\n", rval);
	return rval;
}


notrace __section(".entry.text")
long protected_sys_kexec_load(unsigned long entry, unsigned long nr_segments,
			      unsigned long segments, unsigned long flags,
			      unsigned long unused5, unsigned long unused6,
			      const struct pt_regs *regs)
{
	void __user *segments64;
	long rval;
	long size, size128;
#define KEXEC_SEGMENT_STRUCT_SIZE128 64 /* protected segment structure size */
#define KEXEC_SEGMENT_T 0x3131
#define KEXEC_SEGMENT_A 0x3331
	DbgSCP("entry=%ld, nr_segments=%ld, segments=0x%lx, flags=0x%lx\n",
	       entry, nr_segments, segments, flags);

	if (!segments || !nr_segments) {
		DbgSCP("Empty segments/nr_segments: 0x%lx / %ld\n", segments, nr_segments);
		return -EADDRNOTAVAIL;
	}

	size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
	size128 = KEXEC_SEGMENT_STRUCT_SIZE128 * nr_segments;
	if (size < size128) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num], "'segments'",
					size, (size_t) size128);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return -EADDRNOTAVAIL;
	}

	segments64 = get_user_space(size128);
	if (!segments64)
		return -ENOMEM;
	rval = get_pm_struct((const void __user *) segments, segments64, size,
				    4, nr_segments, KEXEC_SEGMENT_T, KEXEC_SEGMENT_A,
				    0, 0, regs);
	if (rval) {
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return rval;
	}

	rval = sys_kexec_load(entry, nr_segments, segments64, flags);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_ptrace(long		request,
			  long		pid,
			  unsigned long	addr,
			  unsigned long	data,
			const unsigned long unused5,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	long rval;
	int ret;

	if (check_pm_sc_debug_mode(PM_SC_PTRACE_ENABLED) == 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_ENABLED,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num]);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EPERM);
		return sys_ni_syscall();
	}

	/* Check for descriptors in 'addr'/'data': */
	switch (request) {
	case PTRACE_PEEKTEXT:
	case PTRACE_PEEKDATA:
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		break;
	case PTRACE_POKETEXT:
	case PTRACE_POKEDATA:
	case PTRACE_PEEKSIGINFO:
		ret = warn_if_not_descr(3, CHECK4DESCR_WARNING, regs);
		ret = ret ?: warn_if_not_descr(4, CHECK4DESCR_WARNING, regs);
		if (ret)
			return -EFAULT;
		break;
	case PTRACE_GETREGSET:
	case PTRACE_GETREGS:
	case PTRACE_SETREGS:
	case PTRACE_SETSIGINFO:
	case PTRACE_GETSIGMASK:
	case PTRACE_SETSIGMASK:
	case PTRACE_SECCOMP_GET_FILTER:
	case PTRACE_GET_THREAD_AREA:
	case PTRACE_SET_THREAD_AREA:
	case PTRACE_GET_SYSCALL_INFO:
		if (warn_if_not_descr(4, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		break;
/* not available in e2k:
 *	case PTRACE_GETFPREGS:
 *	case PTRACE_SETFPREGS:
 */
	}

	if (request == PTRACE_GETREGSET || request == PTRACE_SETREGSET) {
		struct iovec __user *iovec64;
		iovec64 = get_user_space(sizeof(struct iovec));
		__kernel_size_t iov_len;

		if (!iovec64)
			return -ENOMEM;
		/* Convert struct iovec from msghdr->msg_iov */
		ret = convert_iov((void __user *)data, (void __user *)iovec64, 1, true);
		if (ret) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
					     sys_call_ID_to_name[regs->sys_num], "iovec", "data");
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		}
		rval = sys_ptrace(request, pid, addr, (unsigned long)iovec64);
		if (!rval) {
			/* Updating field 'iov_len' in the iovec structute (arg 'data'): */
			ret = get_user(iov_len, &iovec64->iov_len);
			ret = ret ?: put_user(iov_len,
					&((struct prot_iovec __user *)data)->iov_len);
			rval = (long)ret;
		}
	} else {
		rval = sys_ptrace(request, pid, addr, data);
	}

	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_COMPLEX_WRAPPERS) {
		if (rval == -ESRCH)
			DbgSCP("ESRCH error: Ptracee is not ready for ptrace operation??\n");

	}
	DbgSCP(" rval = %ld\n", rval);
	return rval;
}

#define ISSUE_SIVAL_PTR_NOTE \
	DbgSCP("'sigev_value.sival_ptr' must point to a cookie that is %d bytes long\n", \
	       NOTIFY_COOKIE_LEN)

int get_prot_sigevent(struct sigevent *event,
		const struct prot_sigevent __user *u_event,
		size_t sigval_sz,
		const int arg_num, /* syscall arg# this event came from */
		const struct pt_regs *regs)
{
	DbgSCP("uevent=0x%px, sigval_sz=%zd\n", u_event, sigval_sz);
	memset(event, 0, sizeof(*event));
	if (!access_ok(u_event, sizeof(*u_event)) ||
		__get_user(event->sigev_value.sival_int,
			&u_event->sigev_value.sival_int) ||
		__get_user(event->sigev_signo, &u_event->sigev_signo) ||
		__get_user(event->sigev_notify, &u_event->sigev_notify) ||
		__get_user(event->sigev_notify_thread_id,
			&u_event->sigev_notify_thread_id)) {
		return -EFAULT;
	}
	DbgSCP("sigev_notify=%d thread_id=%d\n",
	       event->sigev_notify, event->sigev_notify_thread_id);
	if (sigval_sz > 0) {
		int tags;
		unsigned long p;
		e2k_ptr_t descr;

		if (get_user_tagged_16(descr.qword, tags, &u_event->sigev_value.sival_ptr)) {
			return -EFAULT;

		}
		DbgSCP("tags=0x%x lo=0x%llx hi=0x%llx\n", tags, descr.lo, descr.hi);
		if (!IS_AP(descr, tags)) {
			if (event->sigev_notify == SIGEV_THREAD)
				return -EINVAL;
			return 0; /* nothing to convert */
		}
		p = e2k_ptr_objptr(descr, sigval_sz);
		if (p == 0) {
			size_t size = AP_OBJ_SIZE(descr);
			/* NB> See SIGEV_THREAD implementation statement: */
			ISSUE_SIVAL_PTR_NOTE;
			PROTECTED_MODE_WARNING(PMSCERRMSG_INSUFFICIENT_STRUCT_SIZE,
					       sys_call_ID_to_name[regs->sys_num],
					       "sigev_value.sival_ptr", size, sigval_sz);
			PM_BNDERR_EXCEPTION_ON_WARNING(arg_num, regs);
			if (!size || PM_SYSCALL_WARN_ONLY == 0)
				return -EINVAL;
			p = e2k_ptr_objptr(descr, 0);
		}
		PROTECTED_MODE_WARNING(PMSCWARN_ADDR_IN_SIGINFO,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				(unsigned long)u_event, p);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		event->sigev_value.sival_ptr = (void __user *)p;
	}
	return 0;
}


notrace __section(".entry.text")
long protected_sys_mprotect(void		*addr,
			    size_t		len,
			    unsigned long	prot,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs *regs)
{
	e2k_ap_t ap = { .lo = regs->dargs[0], .hi = regs->dargs[1] };

	DbgSCP("addr=0x%lx/tag=0x%x, len=0x%zx, prot=0x%lx\n",
	       (long)addr, prot_sc_arg_tag(1, regs), len, prot);
	if (IS_AP(ap, prot_sc_arg_tag(1, regs))) {
		long size = AP_OBJ_SIZE(ap);
		if (size < len) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
					sys_call_ID_to_name[regs->sys_num], "len", len,
					"addr", size);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
			return -EFAULT;
		}

		DbgSCP("descr.rw = %d\n", AP_RW(ap));
		/* Checking that 'prot' flags don't conflict descriptor access rights: */
		if ((!(AP_RW(ap) & R_ENABLE) && (prot & PROT_READ)) ||
		    (!(AP_RW(ap) & W_ENABLE) && (prot & PROT_WRITE))) {
			PROTECTED_MODE_WARNING(PMSCWARN_DSCR_PROT_MISMATCH,
				sys_call_ID_to_name[regs->sys_num], "prot");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
		}
	}

	return sys_mprotect((unsigned long) addr, len, prot);
}

static inline
int this_is_non_empty_tag(int tag, long val)
{
	if (!tag)
		return 0;
	/* Checking lower word tag: */
	if (tag & 0x3) {
		if ((tag & 0x3) != ETAGDWS)
			return 1;
		if ((int) (val & ITAG_MASK))
			return 1; /* this is diagnostic tag */
	}
	/* Checking higher word tag: */
	if (tag >> 2) {
		if ((tag >> 2) != ETAGDWS)
			return 1;
		if ((val & ITAG_MASK) >> 32)
			return 1; /* this is diagnostic tag */
	}
	return 0;
}

notrace __section(".entry.text")
long protected_sys_add_key(const char __user *type,
			   const char __user *description,
			   const void __user *payload,
			   size_t plen,
			   key_serial_t destringid,
			const unsigned long unused6,
			const struct pt_regs *regs)
{
	char __user *array;

	if (plen && payload) {
		long size;
		size_t offset;
		int val_int, tag;
		long val_long;

		if (warn_if_not_descr(3, CHECK4DESCR_SILENT, regs))
			return -EFAULT;
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < plen) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num],
				     plen, size, 1);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
			return -EINVAL;
		}
		/* Checking that payload contains tags:
		 * NB> Empty tags are ignored.
		 */
		array = (char __user *)payload;
		size = plen;
		/* NB> We can check only aligned part of the payload area */
		/* First, we skip a few leading bytes of amount less that sizeof(int): */
		offset = (uintptr_t)array & 0x3;
		if (offset) {
			offset = 4 - offset;
			array += offset;
			size -= offset;
		}
		/* At this point array is properly word-aligned */
		/* Scanning leading unaligned word (int) if any: */
		if ((uintptr_t)array & 0x7) {
			if (get_user_tagged_4(val_int, tag, (int __user *) array))
				goto out_error;
			if (this_is_non_empty_tag(tag, (long) val_int))
				goto out_warn;
			array += 4;
			size -= 4;
		}
		/* At this point array is properly dword-aligned */
		/* Scanning leading unaligned dword (long) if any: */
		if ((uintptr_t)array & 0xf) {
			if (get_user_tagged_8(val_long, tag, (long __user *) array))
				goto out_error;
			if (this_is_non_empty_tag(tag, val_long))
				goto out_warn;
			array += 8;
			size -= 8;
		}
		/* At this point array is properly qword-aligned */
		/* Check for tags in qwords: */
		for (; size >= 16; size -= 16) {
			e2k_qreg_t qword;
			if (get_user_tagged_16(qword, tag, (long __user *) array))
				goto out_error;
			if (this_is_non_empty_tag(tag, qword.lo) ||
			    this_is_non_empty_tag(tag >> 4, qword.hi))
				goto out_warn;
			array += 16;
		}
		/* Scanning unaligned tail dword if any: */
		if (size >= 8) {
			if (get_user_tagged_8(val_long, tag, (long __user *) array))
				goto out_error;
			if (this_is_non_empty_tag(tag, val_long))
				goto out_warn;
			array += 8;
			size -= 8;
		}
		/* Scanning unaligned tail word if any: */
		if (size >= 4) {
			if (get_user_tagged_4(val_int, tag, (int __user *) array))
				goto out_error;
			if (this_is_non_empty_tag(tag, (long) val_int))
				goto out_warn;
		}
	}

out_syscall:
	return sys_add_key(type, description, payload, plen, destringid);

out_error:
	PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_READ_FROM,
			     "add_key", (unsigned long) array);
	PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
	return -EFAULT;
out_warn:
	PROTECTED_MODE_WARNING(PMSCWARN_TAGS_GET_LOST_WHEN_READ,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				"payload", (unsigned long) array);
	PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
	goto out_syscall;
}

/* Returns: 1 if user memory is empty within given indexes (excluded); 0 otherwise */
static int user_prot_mem_interval_zeroed(void __user *ptr, unsigned int from, unsigned int upto)
{
	char *buff;
	int size, i;

	size = upto - from - 1;
	if (size < 0)
		return 1; /* odd boundaries specified */
	else if (!size)
		return 0;

	buff = kmalloc(size, GFP_KERNEL);
	if (!buff)
		return 0; /* out of kernel memory */
	i = copy_from_user(buff, ((char __user *)ptr + from), size);
	if (i) { /* fails to copy user memory */
		return 0;
	}

	for (i = 0; i < size; i++)
		if (buff[i]) {
			kfree(buff);
			return 0; /* non-empty byte found */
		}

	kfree(buff);
	return 1; /* yes, it's zeroed */
}

static int check_sched_attr_struct(pid_t pid,
				   struct sched_attr __user *attr,
				   unsigned int size,
				   unsigned int flags,
				   unsigned int arg_num,
				   const struct pt_regs *regs)
{
	long attr_size;

	if (!attr || pid < 0 || flags)
		return -EINVAL;

	attr_size = (prot_sc_arg_not_ptr(arg_num, regs)) ? 0 :
						AP_OBJ_SIZE(regs->qargs[arg_num - 1]);
	if (attr_size < SCHED_ATTR_SIZE_VER0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
				       regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				       attr_size, (size_t) SCHED_ATTR_SIZE_VER0, arg_num);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL; /* check failed */
	}

	if (!size /* size is encoded within the sched_attr structure */
			&& get_user(size, &attr->size))
		return -EINVAL; /* check failed */

	if (size > attr_size) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
				       regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				       attr_size, (size_t) size, arg_num);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL; /* check failed */
	}

	if (attr_size == SCHED_ATTR_SIZE_VER0 || attr_size == SCHED_ATTR_SIZE_VER1)
		return 0;

	if (attr_size > SCHED_ATTR_SIZE_VER0 && attr_size < SCHED_ATTR_SIZE_VER1) {
		if (user_prot_mem_interval_zeroed(attr, SCHED_ATTR_SIZE_VER0, attr_size))
			return 0;
		PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     "sched_attr", arg_num);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return -E2BIG; /* check failed */
	}

	if (attr_size > SCHED_ATTR_SIZE_VER1) {
		if (user_prot_mem_interval_zeroed(attr, SCHED_ATTR_SIZE_VER1, attr_size))
			return 0;
		PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     "sched_attr", arg_num);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return -E2BIG; /* check failed */
	}

	return 0; /* check passed OK */
}

notrace __section(".entry.text")
long protected_sys_sched_setattr(pid_t pid,
				 struct sched_attr __user *attr,
				 unsigned int flags,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs)
{
	int errnum;

	errnum = check_sched_attr_struct(pid, attr, 0, flags, 2, regs);
	if (errnum)
		return errnum;

	return sys_sched_setattr(pid, attr, flags);
}

notrace __section(".entry.text")
long protected_sys_sched_getattr(pid_t pid,
				 struct sched_attr __user *attr,
				 unsigned int size,
				 unsigned int flags,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs *regs)
{
	int errnum;

	errnum = check_sched_attr_struct(pid, attr, size, flags, 2, regs);
	if (errnum)
		return errnum;

	return sys_sched_getattr(pid, attr, size, flags);
}


static inline
int convert_futex_waitv_128_to_64(struct prot_futex_waitv __user *waiters_128,
				  struct futex_waitv __user	**waiters_64,
				  int nr_futexes,
				  const struct pt_regs *regs)
{
	struct prot_futex_waitv __user *w_128 = waiters_128;
	struct futex_waitv __user *w_64;
	e2k_ptr_t descr;
	u64 val64;
	u32 val32;
	int err = 0, i, tags;
	unsigned long p;

	print_buffer("Input waiters_128", waiters_128,
		     nr_futexes * sizeof(struct prot_futex_waitv));

	w_64 = get_user_space(nr_futexes * sizeof(struct futex_waitv));
	if (!w_64)
		return -ENOMEM;
	*waiters_64 = w_64;
	for (i = 0; i < nr_futexes; i++) {
		err = get_user(val64, &w_128->val);
		err = err ?: put_user(val64, &w_64->val);
		err = err ?: get_user(val32, &w_128->flags);
		err = err ?: put_user(val32, &w_64->flags);
		err = err ?: get_user_tagged_16(descr.qword, tags, &w_128->uaddr);
		if (err)
			return err;
		if (descr.lo) {
			if (IS_AP(descr, tags))
				p = e2k_ptr_objptr(descr, 0);
			else
				goto err_not_descr;
		} else if (tags) {
			goto err_not_descr;
		} else {
			p = 0UL;
		}
		err = put_user(p, &w_64->uaddr);
		if (err)
			break;

		w_128++;
		w_64++;
	}

	print_buffer("Output waiters_64", *waiters_64,
		     nr_futexes * sizeof(struct futex_waitv));

	if (err)
		*waiters_64 = NULL;
	return err;

err_not_descr:
	PROTECTED_MODE_ERROR(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
			     sys_call_ID_to_name[regs->sys_num],
			     tags, "waiters", "uaddr", descr.lo, descr.hi);
	PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg#*/, regs);
	return -EFAULT; /* NB> This is what the syscall expected to report on empty 'addr' */
}

notrace __section(".entry.text")
long protected_sys_futex_waitv(struct prot_futex_waitv __user	*waiters,
			       unsigned int			nr_futexes,
			       unsigned int			flags,
			       struct __kernel_timespec __user	*timeout,
			       clockid_t			clockid,
					const unsigned long unused6,
					const struct pt_regs *regs)
{
	size_t wsize;
	struct futex_waitv __user *waiters_64;
	int err;

	if (waiters && unlikely(!IS_AP(regs->qargs[0], prot_sc_arg_tag(1, regs)))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "waiters", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	wsize = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);
	if (wsize < (nr_futexes * sizeof(struct prot_futex_waitv))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num], "waiters", wsize,
				     (size_t)(nr_futexes * sizeof(struct futex_waitv)));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}

	if (prot_sc_arg_not_ptr(4, regs) && !prot_sc_arg_NULL_ptr(4, regs)) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "timeout", prot_sc_arg_tag(4, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	err = convert_futex_waitv_128_to_64(waiters, &waiters_64, nr_futexes, regs);
	if (err) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     "waiters", 1/*arg_num*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, err);
		return -EINVAL;
	}
	return sys_futex_waitv(waiters_64, nr_futexes, flags, timeout, clockid);
}


notrace __section(".entry.text")
long protected_sys_set_mempolicy_home_node(void __user *start,
					   unsigned long len,
					   unsigned long home_node,
					   unsigned long flags,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	unsigned long addr;
	size_t size;

	if (start && unlikely(!IS_AP(regs->qargs[0], prot_sc_arg_tag(1, regs)))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "start", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	size = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);
	if (size < len) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
			sys_call_ID_to_name[regs->sys_num], "start", size, (size_t)len);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}
	addr = AP_PTR(regs->qargs[0]);

	return sys_set_mempolicy_home_node(addr, len, home_node, flags);
}


notrace __section(".entry.text")
long protected_sys_mlock(unsigned long	addr,
			 size_t		len,
				const unsigned long unused3,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	if (!addr) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num], "addr");
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	if (unlikely(!IS_AP(regs->qargs[0], prot_sc_arg_tag(1, regs)))) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "addr", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	} else {
		size_t size = AP_OBJ_SIZE(regs->qargs[0]);

		if (size < len) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				sys_call_ID_to_name[regs->sys_num], "addr", size, (size_t)len);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
			return -ENOMEM;
		}
	}

	return sys_mlock(addr, len);
}

notrace __section(".entry.text")
long protected_sys_mlock2(unsigned long	addr,
			  size_t	len,
			  unsigned int	flags,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	if (!addr) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num], "addr");
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	if (unlikely(!IS_AP(regs->qargs[0], prot_sc_arg_tag(1, regs)))) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "addr", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	} else {
		size_t size = AP_OBJ_SIZE(regs->qargs[0]);

		if (size < len) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				sys_call_ID_to_name[regs->sys_num], "addr", size, (size_t)len);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
			return -ENOMEM;
		}
	}

	return sys_mlock2(addr, len, flags);
}

notrace __section(".entry.text")
long protected_sys_munlock(unsigned long	addr,
			   size_t		len,
				const unsigned long unused3,
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	if (!addr) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num], "addr");
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	if (unlikely(!IS_AP(regs->qargs[0], prot_sc_arg_tag(1, regs)))) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "addr", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	} else {
		size_t size = AP_OBJ_SIZE(regs->qargs[0]);

		if (size < len) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				sys_call_ID_to_name[regs->sys_num], "addr", size, (size_t)len);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
			return -ENOMEM;
		}
	}

	return sys_munlock(addr, len);
}

notrace __section(".entry.text")
long protected_sys_brk(unsigned long uaddr,
				const unsigned long unused_a2,
				const unsigned long unused_a3,
				const unsigned long unused_a4,
				const unsigned long unused_a5,
				const unsigned long unused_a6,
			struct pt_regs	*regs)
{
	e2k_addr_t addr, br_addr = 0;
	struct mm_struct *mm = current->mm;
	mm_context_t *context = &mm->context;
	int cui;
	e2k_cute_t __priv *ucute_p;
	e2k_cute_t cute_p;
	long rval = 0;

	if (uaddr) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_SC_BRK_NON_ZERO_ARG_IN_PM,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num], uaddr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, ENOSYS);
		rval = -ENOMEM;
		goto out;
	}

	/* Calculating end of GD area: */

	down_read(&context->cut_mask_lock);
	for_each_used_cui(cui, context) {
		ucute_p = get_cut_entry_pointer(cui, NULL /*&page*/);
		DbgSCP(":: cui=0x%x cute_p=0x%lx\n", cui, (unsigned long)ucute_p);
		if (!ucute_p)
			continue;
		rval =  copy_from_priv(&cute_p, ucute_p, sizeof(cute_p));
		if (rval) {
			rval = -ESRCH;
			break;
		}

		DbgSCP("\tcute_p: gd=0x%llx:0x%llx cud=0x%llx:0x%llx\n",
		       cute_p.gd.lo, cute_p.gd.hi, cute_p.cud.lo, cute_p.cud.hi);
		/* Looking for boundaries in GD: */
		addr = GD_BASE(cute_p.gd) + GD_SIZE(cute_p.gd);
		if (addr > br_addr)
			br_addr = addr;
	}
	up_read(&context->cut_mask_lock);

	if (!rval)
		rval = br_addr;
out:
	DbgSCP("(0x%ld) ==> rval=0x%lx\n", uaddr, rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_move_pages(int pid,
				unsigned long nr_pages,
				const void __user * __user *pages,
				const int __user *nodes,
				int __user *status,
				int flags,
				const struct pt_regs *regs)
{
	int size;
	const void __user * __user *pages64;
	long ret;

	if (!nr_pages) {
		pages64 = pages;
		goto out;
	}

	/* Check that size of 'pages' fits to keep 'nr_pages' pointers: */

	size = AP_OBJ_SIZE(regs->qargs[2]);
	if (size < (nr_pages * sizeof(e2k_ptr_t))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num],
				     nr_pages * sizeof(e2k_ptr_t), size, 3);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return -EINVAL;
	}

	/* Converting 'pages-128' into 'pages-64': */

	pages64 = get_user_space(sizeof(void *) * nr_pages);
	if (!pages64)
		return -ENOMEM;
	ret = convert_array(pages, pages64, size, 1, nr_pages, 0x3, 0x3, regs);
	if (ret) {
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return ret;
	}

	/* Check that size of 'nodes' fits to keep 'nr_pages' elements: */

	size = AP_OBJ_SIZE(regs->qargs[3]);
	if (size < (nr_pages * sizeof(*nodes))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num],
				     nr_pages * sizeof(*nodes), size, 4);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(4/*arg_num*/, regs);
		return -EINVAL;
	}

	/* Check that size of 'status' fits to keep 'nr_pages' elements: */

	size = AP_OBJ_SIZE(regs->qargs[4]);
	if (size < (nr_pages * sizeof(*status))) {
		PROTECTED_MODE_ERROR(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num],
				     nr_pages * sizeof(*status), size, 5);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(5/*arg_num*/, regs);
		return -EINVAL;
	}

out:
	return sys_move_pages(pid, nr_pages, pages, nodes, status, flags);
}


notrace __section(".entry.text")
long protected_sys_msgctl(int msgid, int cmd, void __user *buf,
		      long a4, long a5, long a6, const struct pt_regs *regs)
{
	e2k_ap_t ap = regs->qargs[2];

	set_ap_u_border(ap);
	return sys_msgctl(msgid, cmd, U_AP_PTR(ap));
}


#if (DYNAMIC_DEBUG_SYSCALLP_ENABLED)
static void print_epoll_event64(struct epoll_event __user *ptr,
				const char *header, const char *comm)
{
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		u64 data;
		unsigned events;
		int ret;

		ret  = get_user(data, &ptr->data);
		ret |= get_user(events, &ptr->events);
		if (ret) {
			pr_err("%s: failed to read from %p (err=%d)\n",
				__func__, ptr, ret);
			return;
		}
		pr_info("%s%s: %p :: events=0x%.4x, data=0x%.8llx\n",
			header, comm, ptr, events, data);
	}
}

static void print_epoll_event128(struct prot_epoll_event __user *ptr,
				 const char *header, const char *comm)
{
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		u64 addr;
		unsigned events;
		e2k_ptr_t dscr;
		int ret, tag;

		ret  = get_user(addr, &ptr->address);
		ret |= get_user(events, &ptr->events);
		if (ret) {
			pr_err("%s: failed to read from %px (err=%d)\n",
				__func__, ptr, ret);
			return;
		}
		pr_info("%s%s: %px :: events=0x%.4x, address=0x%.8llx\n",
			header, comm, ptr, events, addr);

		ret  = get_user_tagged_16(dscr.qword, tag, &ptr->data.descr);
		if (ret) {
			pr_err("%s: failed to read from %px (err=%d)\n",
				__func__, &ptr->data.descr, ret);
			return;
		}
		pr_info("%s%s: %px :: dscr.lo = 0x%.8llx .hi = 0x%.8llx\n",
			header, comm, &ptr->data.descr, dscr.qword.lo, dscr.qword.hi);
	}
}
#else
static inline
void print_epoll_event64(struct epoll_event __user *ptr,
			 const char *header, const char *comm)
{
}
static inline
void print_epoll_event128(struct prot_epoll_event __user *ptr,
			  const char *header, const char *comm)
{
}
#endif /* debug print */


/* Converting user protected event structure into (user) regular structure:
 * NB> We exploit the fact that protected epoll event structure size is
 *     twice bigger than the regular structure size.
 *     Therefore we can fill in alignment dword in the protected structure with address
 *     while keeping descriptor field untouched, and use it as input regular epoll_event structure.
 * Returns error number or 0 if OK.
 */
static int fill_64bit_fields_in_epoll_event_128(const unsigned long epfd,
					 struct prot_epoll_event __user *event_128,
					 const struct pt_regs *regs, const int arg_num)
{
	e2k_ap_t data;
	unsigned long address;
	int tags = 0, rval = 0;

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		DbgSCP("(epfd=0x%lx, event128=0x%lx, regs, argN=%d)\n",
		       epfd, (unsigned long)event_128, arg_num);
		print_epoll_event128(event_128, __func__, "[->128]");
	}

	if (!event_128)
		return 0;
	if (((unsigned long)&event_128->data) & (DESCRIPTOR_SIZE - 1)) {
		/* descriptor 'event' appeared improperly aligned */
		rval = -EINVAL;
		PROTECTED_MODE_ERROR(PMCNVSTRMSG_STRUCT_DESCR_UNALIGNED,
				sys_call_ID_to_name[regs->sys_num],
				"event_128->data", (unsigned long)&event_128->data);
		goto err_out;
	}

	rval = rval ?: get_user_tagged_16(data.qword, tags, &event_128->data);
	if (unlikely(rval))
		goto err_out;

	if (IS_AP(data, tags)) {
		/* This is pointer; saving the addr-descr pair: */
		address = AP_PTR(data);
		if (add_2_prot_epoll_descr_bt(epfd, (u64) address, data))
			goto err_out;
	} else if (tags & 0x3) { /* Non-numerical tag in the lowest word */
		PROTECTED_MODE_ERROR(PMSCERRMSG_UNEXPECTED_FIELD_TAG,
				sys_call_ID_to_name[regs->sys_num], tags,
				"data", "event", arg_num);
		goto err_out;
	} else {
		address = (unsigned long) data.qword.lo;
	}

	/* Filling regular epoll_event fields in: */
	rval = put_user(address, &event_128->address);
	rval = rval ?: put_user(tags, &event_128->tags);
	print_epoll_event128(event_128, __func__, "[128]");
	if (likely(!rval))
		return 0;

err_out:
	PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
	     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
	     "epoll_event", arg_num);
	PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	return rval;
}

/* Updating (user) protected event structure with the data captured by a syscall: */
static int copy_epoll_event_64_to_128(struct epoll_event __user *event64,
				      struct prot_epoll_event __user *event128,
				      const int epfd,
				      const struct pt_regs *regs)
{
	u64 address;
	__poll_t events;
	int ret, tags;

	ret = get_user(events, &event64->events);
	ret = ret ?: get_user(address, &event64->data);
	ret = ret ?: get_user(tags, &((struct prot_epoll_event __user *)event64)->tags);
	ret = ret ?: put_user(events, &event128->events);
	ret = ret ?: put_user(address, &event128->address);
	if (!ret) {
		print_epoll_event64(event64, __func__, "[64]");
	} else {
		DbgSCP("(event64=0x%lx, event128=0x%lx, epfd=%d, regs) returned %d\n",
		       (unsigned long)event64, (unsigned long)event128, epfd, ret);
		PROTECTED_MODE_ERROR(PMSCERRMSG_FATAL_WRITE_AT, __func__, (unsigned long) event128);
		return ret;
	}
	print_epoll_event128(event128, __func__, "[128]");

	/* NB> Here we fill in 'address' and 'tags' fields ony.
	 *	Forming the 'data' field of the protected structure to be done later on.
	 */

	return ret;
}

/* Converting user protected event structures into (user) regular structures: */
static
int epoll_events_64_to_128(const unsigned int epfd,
			   struct epoll_event __user *events_64,
			   struct prot_epoll_event __user *events_128,
			   const int count,
			   const struct pt_regs *regs, const int arg_num)
{
	int rval = 0, i;

	if (!events_128 || !events_64 || !count)
		return 0;

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))
		DbgSCP("(epfd=%d, events64=0x%lx, events128=0x%lx, count=%d, regs, argN=%d)\n",
		       epfd, (unsigned long)events_64, (unsigned long)events_128, count, arg_num);

	for (i = 0; i < count; i++) {
		rval = copy_epoll_event_64_to_128(&events_64[i], &events_128[i],
						  epfd, regs);
		if (unlikely(rval)) {
			PROTECTED_MODE_ERROR(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
			     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
			     "epoll_event", arg_num);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, rval);
			break;
		}
		cond_resched();
	}
	rval = fill_user_descr_in_prot_epoll_events(epfd, events_128, count);

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		struct epoll_event __user *e64;
		struct prot_epoll_event __user *e128;

		for (i = 0, e64 = events_64, e128 = events_128;
		     i < count;
		     i++, e64++, e128++) {
			pr_info("[%d] ::\tevent-64 ==> events-128\n", i);
			print_epoll_event64(e64, __func__, "[64]");
			print_epoll_event128(e128, __func__, "[128]");
		}
	}

	return rval >= 0 ? 0 : rval;
}

notrace __section(".entry.text")
long protected_sys_epoll_ctl(const unsigned long epfd,	/* a1 */
			     const unsigned long op,	/* a2 */
			     const unsigned long fd,	/* a3 */
			     void __user	*event,	/* a4 */
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	long rval;

	DbgSCP("(epfd=0x%lx, op=0x%lx, fd=0x%lx, event=%p)\n", epfd, op, fd, event);

/* Linux Programmer's Manual for epoll_ctl states:
 * NB> In kernel versions before 2.6.9, the EPOLL_CTL_DEL operation
 *     required a non-null pointer in event, even though this argument
 *     is ignored.  Since Linux 2.6.9, event can be specified as NULL
 *     when using EPOLL_CTL_DEL.  Applications that need to be portable
 *     to kernels before 2.6.9 should specify a non-null pointer in event.
 */
	if (ep_op_has_event(op)) {
		rval = fill_64bit_fields_in_epoll_event_128(epfd, event, regs, 4/*arg_num*/);
		if (rval)
			return rval;
	}

	rval = sys_epoll_ctl(epfd, op, fd, event);
	DbgSCP("(epfd=0x%lx, op=0x%lx, fd=0x%lx, event=0x%px) == %ld\n",
					epfd, op, fd, event, rval);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_epoll_wait(const unsigned long epfd,		/* a1 */
			      void __user	*events128,	/* a2 */
			      const long	maxevents,	/* a3 */
			      const long	timeout,	/* a4 */
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	long rval;
	size_t events_size, size;
	void __user *events64; /* converted array of epoll events */
	int ret;

	DbgSCP("(epfd=0x%lx, events=0x%lx, maxevents=%ld, timeout=%ld)\n",
					epfd, (unsigned long)events128, maxevents, timeout);
	if (maxevents <= 0)
		return -EINVAL;

	size = AP_OBJ_SIZE(regs->qargs[1]);
	events_size = sizeof(struct epoll_event) * maxevents;
	if (size < events_size) {
		if (size) {
			if (!size_exceeds_descr_max_capacity(events_size, "maxevents",
							     events_size, regs))
				PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     (int) size, events_size, 2);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		}
		return -EFAULT;
	}

	events64 = get_user_space(events_size);
	ret = events64 ? sys_epoll_wait(epfd, events64, maxevents, timeout) : -ENOMEM;
	if (ret < 0)
		return ret;

	rval = epoll_events_64_to_128(epfd, events64, events128, maxevents, regs, 2/*arg_num*/);
	if (rval)
		return rval;

	return ret;
}

notrace __section(".entry.text")
long protected_sys_epoll_pwait(const unsigned long	epfd,		/* a1 */
			       void __user		*event,		/* a2 */
			       const long		maxevents,	/* a3 */
			       const long		timeout,	/* a4 */
			       const unsigned long	sigmask,	/* a5 */
			       const unsigned long	sigsetsize,	/* a6 */
			       const struct pt_regs *regs)
{
	long rval;
	size_t events_size, size;
	void __user *events64; /* converted array of epoll events */
	int ret;

	DbgSCP("(epfd=0x%lx, event=0x%px, maxevents=%ld, timeout=%ld, sigmask, sigsetsize=%ld)\n",
		epfd, event, maxevents, timeout, sigsetsize);

	if (maxevents <= 0)
		return -EINVAL;

	size = AP_OBJ_SIZE(regs->qargs[1]);
	events_size = sizeof(struct epoll_event) * maxevents;
	if (size < events_size) {
		if (size) {
			if (!size_exceeds_descr_max_capacity(events_size, "maxevents",
							     events_size, regs))
				PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     (int) size, events_size, 2);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		}
		return -EFAULT;
	}

	events64 = get_user_space(events_size);
	ret = events64 ? sys_epoll_pwait(epfd, events64, maxevents,
					 timeout, (sigset_t __user *) sigmask, sigsetsize)
			: -ENOMEM;
	if (ret < 0)
		return ret;

	rval = epoll_events_64_to_128(epfd, events64, event, maxevents, regs, 2/*arg_num*/);
	if (rval)
		return rval;

	return ret;
}

notrace __section(".entry.text")
long protected_sys_epoll_pwait2(const unsigned long  epfd,	/* a1 */
		void __user	*event,				/* a2 */
		const long	maxevents,			/* a3 */
		const unsigned long  timeout,		/* a4 */
		const unsigned long  sigmask,		/* a5 */
		const unsigned long  sigsetsize,		/* a6 */
		const struct pt_regs *regs)
{
	long rval;
	size_t events_size;
	void __user *events64; /* converted array of epoll events */
	int size, ret;

	DbgSCP("(epfd=0x%lx, event=0x%px, maxevents=%ld, timeout=%ld, sigmask, sigsetsize=%ld)\n",
		epfd, event, maxevents, timeout, sigsetsize);

	if (maxevents <= 0)
		return -EINVAL;

	size = AP_SIZE(regs->qargs[2]);
	events_size = sizeof(struct epoll_event) * maxevents;
	if (size < events_size) {
		if (size) {
			if (!size_exceeds_descr_max_capacity(events_size, "maxevents",
							     events_size, regs))
				PROTECTED_MODE_ERROR(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     (int) size, events_size, 2);
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		}
		return -EINVAL;
	}

	events64 = get_user_space(events_size);
	ret = events64 ? sys_epoll_pwait2(epfd, events64, maxevents,
					(struct __kernel_timespec __user *) timeout,
					(sigset_t __user *) sigmask, sigsetsize)
			: -ENOMEM;
	if (ret < 0)
		return ret;

	rval = epoll_events_64_to_128(epfd, events64, event, maxevents, regs, 2/*arg_num*/);
	if (rval)
		return rval;

	return ret;
}

#endif /* CONFIG_PROTECTED_MODE */
