/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This is implementation of system call handlers for E2K protected mode:
 *	int protected_sys_<syscallname>(const long a1, ... a6,
 *					const struct pt_regs *regs);
 */

#include <linux/syscalls.h>
#include <asm/e2k_debug.h>

#include <asm/mman.h>
#include <asm/convert_array.h>
#include <asm/prot_loader.h>
#include <asm/syscalls.h>
#include <asm/shmbuf.h>
#include <asm/prot_compat.h>

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

	force_sig_bnderr((void __user *)AP_PTR(ptr), (void __user *)AP_BASE(ptr),
			 (void __user *)AP_BASE(ptr) + AP_SIZE(ptr));
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
	}
	ret = clear_user(uspace, len);
	if (ret) {
		pr_alert("%s() failed to clear %lu bytes at %s:%d\n",
			 __func__, ret, __FILE__, __LINE__);
		pm_deliver_exception(SIGABRT, SI_KERNEL, EFAULT);
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

		if (copy_from_user_with_tags(tmp, &prot_array[i], sizeof(e2k_ptr_t)))
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

static
int issue_prot_message_vl(const int msg_ID, const char *fmt, va_list argptr)
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
		ret = snprintf(message, MSG_BUFF_SIZE, "[EPM#%d] ", msg_ID); /* offset */
		if (ret > 0)
			ret = vsnprintf(&message[ret], MSG_BUFF_SIZE - ret, fmt, argptr);
	}
	if (ret <= 0) {
		pr_err("%s:%d : %s//vsprintf() failed with error code (%d)\n",
			       __FILE__, __LINE__, __func__, ret);
		return ret;
	}

	if (check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_JOURNAL))
		pr_err("%s", message);

	if (check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_STDERR)) {
		struct file *fstderr = fget(2);
		size_t msglen = strlen(message);

		if (!fstderr) {
			pr_err_ratelimited("%s:%d : kernel_write(fstderr, 0x%px, %zd) - could not write to stderr since it is not available\n",
					__FILE__, __LINE__, &message, msglen);
			return -EBADF;
		}

		ret = kernel_write(fstderr, message, msglen, NULL);
		fput(fstderr);

		if (ret == -ERESTARTSYS || ret == -ERESTARTNOINTR ||
				ret == -ERESTARTNOHAND || ret == -ERESTART_RESTARTBLOCK) {
			/* Write to tty will not go through anyway
			 * if signal_pending() so just return - we
			 * will get here again after syscall restart. */
		} else if (ret <= 0) {
			pr_err("%s:%d : kernel_write(2, 0x%px, %zd) failed with error code (%d)\n",
				       __FILE__, __LINE__, &message, msglen, ret);
			if (check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_JOURNAL) == 0)
				pr_err("%s", message);
		} else if (ret < msglen) {
			pr_err("%s:%d : kernel_write(2, 0x%px, %zd) failed; %d of %zd bytes written\n",
					__FILE__, __LINE__, &message, msglen, ret, msglen);
			if (check_pm_sc_debug_feature(PM_DIAG_MESSAGES_IN_JOURNAL) == 0)
				pr_err("%s", message);
		}
	}

	return ret;
}

static inline
int issue_prot_message(const char *fmt, ...)
{
	va_list argptr;
	int ret;

	va_start(argptr, fmt);
	ret = issue_prot_message_vl(0, fmt, argptr);
	va_end(argptr);

	return ret;
}

/* Delivering diagnostic messages that protected mode issues:
 * header_type: 0 - no header; 1 - error header; 2 - warning header; 3 - program warning.
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

		issue_prot_message("[PID#%d] %s: %s\n",
				   current->pid, current->comm, protected_error_list[header_id]);
	}

	if ((MSG_ID <= 0) || (MSG_ID >= PMSCERRMSG_NUMBER)) {
		pr_err("%s:%d %s (%d)\n", __FILE__, __LINE__,
		       protected_error_list[PMSCERRMSG_ERR_ID], MSG_ID);
		return;
	}

	va_start(argptr, MSG_ID);
	issue_prot_message_vl(MSG_ID, protected_error_list[MSG_ID], argptr);
	va_end(argptr);
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

#if (!DYNAMIC_DEBUG_SYSCALLP_ENABLED)
#define print_buffer(a1, a2, a3)
#else
static void print_buffer(const char	*title,
			 void		*buffer,
			 const int	buff_size)
{
	unsigned long *arr;
	e2k_ptr_t descr;
	int size = buff_size, err = 0, tags;
	unsigned long vlong;

	arr = (unsigned long *)buffer;
	pr_info("\t##### %s[%d] : 0x%lx #####\n", title, size, buffer);

	for (; size > 0; size -= 8, arr++) {
		if (size < 16 || (unsigned long)arr & 0xf) {
			err = get_user_tagged_8(vlong, tags, arr);
			if (err)
				break;
			pr_info("\t[0x%.2x] 0x%.8x\n", tags, (int)vlong);
		} else {
			err = get_user_tagged_16(descr.qword, tags, arr);
			if (err)
				break;
			pr_info("\t[0x%.2x] 0x%.8x.%.8x    0x%.8x.%.8x\n", tags,
				(int)(descr.qword.lo), (int)(descr.qword.lo >> 32),
				(int)(descr.qword.hi), (int)(descr.qword.hi >> 32));
			size -= 8;
			arr++;
		}
	}
	if (err)
		pr_info("\t!!!!! Error 0x%x while reading from 0x%lx !!!!!\n",
			err, (unsigned long) arr);

}
#endif /* print_buffer  */

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


/* Converts protected iov structure(s) to regular one(s):
 * iov128 - protected array of iov structures;
 * iov64 - regular array of iov structures;
 * iov_len - # of iov elements in the input array.
 * Result: error number or zero if converted OK.
 */
static int convert_iov(const void __user *iov128, const void __user *iov64,
		       const size_t iov_len)
{
	struct prot_iovec __user *iovec_p128 = (struct prot_iovec __user *)iov128;
	struct iovec __user *iovec_p64 = (struct iovec __user *)iov64;
	e2k_ptr_t buff;
	__kernel_size_t buff_len;
	void __user *ptr;
	int tags, err = 0, i;

	for (i = 0; i < iov_len; i++) {
		err = get_user_tagged_16(buff.qword, tags, &iovec_p128->iov_base);
		err = err ?: get_user(buff_len, &iovec_p128->iov_len);
		if (err)
			return err;
		if (buff_len) {
			if (unlikely((long)buff_len < 0)) {
				return -EINVAL;
			} else if (unlikely(!IS_AP(buff, tags))) {
				DbgSCP("bad iov_base 0x%llx:0x%llx tags 0x%x\n",
				       buff.lo, buff.hi, tags);
				return -EFAULT;
			} else if (unlikely(buff_len > AP_OBJ_SIZE(buff))) {
				PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
				     "iov", buff_len, (size_t) AP_OBJ_SIZE(buff));
				return -EFAULT;
			}
		} else if (unlikely(tags && !IS_AP(buff, tags) && buff.lo)) {
			DbgSCP("bad iov_base 0x%llx:0x%llx tags 0x%x or iov_len=%zd\n",
			       buff.lo, buff.hi, tags, buff_len);
			return -EFAULT;
		}
		if (AP_OBJ_SIZE(buff) < buff_len) {
			DbgSCP("bad iov_base 0x%llx:0x%llx insufficient iov_len=%zd\n",
			       buff.lo, buff.hi, buff_len);
			return -EFAULT;
		}
		ptr = (void __user *)e2k_ptr_objptr(buff, 0);
		err = put_user(ptr, &iovec_p64->iov_base);
		err = err ?: put_user(buff_len, &iovec_p64->iov_len);
		if (err)
			return err;
		iovec_p128 = (struct prot_iovec __user *)
			((char __user *)iovec_p128 + sizeof(struct prot_iovec));
		iovec_p64 = (struct iovec __user *)
			((char __user *)iovec_p64 + sizeof(struct iovec));
	}

	return err;
}

/* # elements in msg_iov field of protected msghdr structure: */
static long get_prot_msghdr_iovlen(const struct protected_user_msghdr __user *umsghdr)
{
	long iovlen;
	int err;

	if (unlikely(!umsghdr))
		return 0L;
	err = get_user(iovlen, &umsghdr->msg_iovlen);
	if (unlikely(err)) {
		return (long)err;
	} else if (unlikely(iovlen <= 0)) { /* checking if 'iov' isn't empty */
		e2k_ptr_t iov;
		int tags;

		err = get_user_tagged_16(iov.qword, tags, &umsghdr->msg_iov);
		if (unlikely(err))
			return (long)err;
		if (unlikely(tags && !IS_AP(iov, tags)))
			iovlen = -EINVAL;
		else if (!tags)
			iovlen = 0;
		else
			iovlen = -EMSGSIZE;
	} else if (unlikely(iovlen > SOMAXCONN)) {
		iovlen = -EMSGSIZE;
	}

	return iovlen;
}

static struct user_msghdr __user *convert_msghdr(
			const void	__user *prot_msghdr,
			unsigned int		size,
			const char		*syscall_name,
			const char		*arg_name,
			void		__user	*user_buff,
			const struct pt_regs	*regs)
/* Converts user msghdr structure from protected to regular structure format.
 * Outputs converted structure (allocated in user space if (user_buff == NULL)).
 * 'prot_msghdr' - protected message header structure.
 * 'size' - size of the input structure.
 * 'user_buff' - buffer for converted structure in user space.
 */
{
	long __user *args = (long __user *) user_buff;
	struct protected_user_msghdr __user *msghdr_p128 =
				(struct protected_user_msghdr __user *) prot_msghdr;
	struct user_msghdr __user *msghdr_p64 = NULL;
	struct prot_iovec __user *msg_iov;
	e2k_ptr_t buff;
	__kernel_size_t buff_len;
	long iovlen;
	int tags, err;

#define MASK_MSGHDR_TYPE     0x0773 /* type mask for struct msghdr */
#define MASK_MSGHDR_ALIGN    0x17ff /* alignment mask for msghdr structure */
#define MASK_MSGHDR_RW       0x2000 /* WRITE-only msg_flags field */
#define SIZE_MSGHDR          sizeof(struct protected_user_msghdr)

	if (!prot_msghdr)
		return NULL;
	if (size < SIZE_MSGHDR) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
				     "msghdr", size, SIZE_MSGHDR);
		err = -EFAULT;
		goto out_err;
	}

	/*
	 * Structures 'user_msghdr' and 'iovec' contain pointers inside;
	 * therefore they need to be converted to 64-bit mode
	 * and results to be saved in these structures afterwards.
	 */

	iovlen = get_prot_msghdr_iovlen(prot_msghdr);
	if (unlikely(iovlen < 0)) {
		DbgSCP("get_prot_msghdr_iovlen(0x%ld) returned %ld\n",
				(unsigned long)prot_msghdr, iovlen);
		return (void __user *) iovlen;
	}

	/* Check for proper msg_control fields: */
	err = get_user_tagged_16(buff.qword, tags, &msghdr_p128->msg_control);
	err = err ?: get_user(buff_len, &msghdr_p128->msg_controllen);
	if (err)
		return (void __user *) (long) err;
	if (buff_len) {
		if (unlikely(!IS_AP(buff, tags))) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
					       syscall_name, tags, "user_msghdr",
					       "msg_control", buff.lo, buff.hi);
			err = -EFAULT;
			goto out_err;
		} else if (buff_len > AP_OBJ_SIZE(buff)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
					"msg_control",
					(size_t) AP_OBJ_SIZE(buff), buff_len);
			DbgSCP("bad msg_control 0x%lld:0x%lld buff_len %zd\n",
			       buff.lo, buff.hi, buff_len);
			if (PM_SYSCALL_WARN_ONLY == 0) {
				err = -EFAULT;
				goto out_err;
			}
			buff_len = AP_OBJ_SIZE(buff);
			PROTECTED_MODE_MESSAGE(0, PMSCERRMSG_SC_ARG_COUNT_TRUNCATED, buff_len);
		}
	}

	/* Allocating space on user stack for converted structures: */
	if (!args)
		args = get_user_space(sizeof(struct user_msghdr) +
					iovlen * sizeof(struct iovec));

	/* Convert struct msghdr: */
	msghdr_p64 = (struct user_msghdr __user *) args;
	err = convert_array_3(prot_msghdr, args, SIZE_MSGHDR, 7, 1, MASK_MSGHDR_TYPE,
			      MASK_MSGHDR_ALIGN, MASK_MSGHDR_RW, CONV_ARR_WRONG_DSCR_FLD,
			      regs);
	if (err)
		goto out_err;

	err = get_user(msg_iov, &msghdr_p64->msg_iov);
	if (err) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_ERR_FROM,
				     __func__, (unsigned long) &msghdr_p64->msg_iov);
		return  (void __user *) (long) err;
	}
	if (msg_iov) {
		struct iovec __user *iovec_p64;

		/* Converting struct iovec from msghdr->msg_iov: */
		iovec_p64 = (struct iovec __user *)
			((char __user *) msghdr_p64 + sizeof(struct user_msghdr));
		err = convert_iov(msg_iov, iovec_p64, iovlen);
		if (err) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_FIELD_STRUCT_IN_ARG_NAME,
					syscall_name, "iovec", "user_msghdr", arg_name);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return  (void __user *) (long) err;
		}

		/* Assign converted iovec pointer to converted msghdr structure: */
		err = put_user(iovec_p64, &msghdr_p64->msg_iov);
		if (err) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_WRITE_AT,
				     __func__, (unsigned long) &msghdr_p64->msg_iov);
			goto out_err;
		}
	} else {
		PROTECTED_MODE_WARNING(PMSCERRMSG_EMPTY_STRUCTURE_FIELD,
				       syscall_name, "msg_iov", "user_msghdr", "msghdr");
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
	}

	return (struct user_msghdr __user *) args;

out_err:
	PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
			     syscall_name, "protected_msghdr", "msghdr", arg_name);
	PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	return  (void __user *) (long) err;
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
	PROTECTED_MODE_ALERT(PMSCERRMSG_SC_NOT_YET_SUPPORTED_IN_PM,
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

	DbgSCP("addr=0x%lx, size=%ld, flags=0x%lx", (unsigned long)addr, size, flags);

	if (unlikely(!addr || !size))
		return 0L;

	descr_size = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);
	if (!(flags & CLEAN_DESCRIPTORS_SINGLE))
		size_to_clean *= sizeof(e2k_ptr_t);
	if (descr_size < size_to_clean) {
		PROTECTED_MODE_ALERT(PMCLNDSCRSMSG_WRONG_ARG_SIZE,
				regs->dargs[0], regs->dargs[1], size, descr_size);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EFAULT;
	}

	if (flags & (CLEAN_DESCRIPTORS_SINGLE | CLEAN_DESCRIPTORS_NO_GARB_COLL) ==
		(CLEAN_DESCRIPTORS_SINGLE | CLEAN_DESCRIPTORS_NO_GARB_COLL)) {
		rval = mem_set_empty_tagged_dw(addr, size, 0x0baddead0baddead);
	} else if (flags & CLEAN_DESCRIPTORS_SINGLE) {
		e2k_ptr_t old_descriptor;

		old_descriptor.lo = regs->dargs[0];
		old_descriptor.hi = regs->dargs[1];
		rval = clean_single_descriptor(old_descriptor);
	} else if (!flags) {
		rval = clean_descriptors(addr, size);
	} else {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX_TAG,
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

	if ((long)u64_uptr & 0xf) { /* unaligned address */
		ret = get_user_tagged_8(uval64, tags, u64_uptr);
	} else { /* aligned address */
		e2k_ptr_t descr;

		ret = get_user_tagged_16(descr.qword, tags, (void *)u64_uptr);
		if (ret == EFAULT) { /* seems there is no extra 8 bytes in the buffer */
			ret = get_user_tagged_8(uval64, tags, u64_uptr);
		} else {
			tags &= 0xf; /* Here we check for lower dword tag */
			uval64 = descr.qword.lo;
		}
	}

	if (unlikely(ret)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM,
				sys_call_ID_to_name[regs->sys_num], (long)u64_uptr);
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXPECTED_FIELD_TAG,
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
int get_descriptor_from_user(e2k_ptr_t __user *dscr_uptr, e2k_ptr_t *pdescr, size_t min_size,
			     char *arg_name, char *struct_name, char *field_name,
			     struct pt_regs	*regs)
{
	int tags, ret;

	ret = get_user_tagged_16(pdescr->qword, tags, dscr_uptr);

	if (unlikely(ret)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM,
				sys_call_ID_to_name[regs->sys_num], (long)dscr_uptr);
		protected_mode_message(0, PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				sys_call_ID_to_name[regs->sys_num], field_name, arg_name);
		if (PM_SYSCALL_WARN_ONLY == 0)
			pm_abort_execution(ret);
		return ret;
	} else if ((pdescr->lo || tags) && unlikely(!IS_AP(*pdescr, tags))) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
				sys_call_ID_to_name[regs->sys_num], tags,
				struct_name, field_name,
				(long)pdescr->lo, (long)pdescr->hi);
		return -EINVAL;
	} else if (pdescr->lo && AP_OBJ_SIZE(*pdescr) < min_size) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_INSUFFICIENT_STRUCT_SIZE,
				sys_call_ID_to_name[regs->sys_num], field_name,
				AP_OBJ_SIZE(*pdescr), min_size);
		return -EINVAL;
	}

	return 0;
}

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
		u64 *uarr = (u64 *)uargs64;
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_ERR_FROM,
				     "sys_clone3", (unsigned long)prot_uargs);
	}
	return ret;
}

notrace __section(".entry.text")
long protected_sys_clone3(struct protected_clone_args __user	*prot_uargs,
			  const size_t				size,
			  const unsigned long unused3,
			  const unsigned long unused4,
			  const unsigned long unused5,
			  const unsigned long unused6,
			  struct pt_regs	*regs)
{
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
				     sys_call_ID_to_name[regs->sys_num], "size", (long)size,
				     "uargs", (unsigned int)args_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out;
	} else if (unlikely(size & 0x7 ||
			args_size < size ||
			args_size < MIN_UARG_SIZE ||
			size < MIN_UARG_SIZE)) {
		/* NB> No sense to run the syscall: it would fail anyway' */
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
			     sys_call_ID_to_name[regs->sys_num], "size", (long)size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out;
	} else if (unlikely((unsigned long)prot_uargs & 0x7)) {
		/* NB> No sense to run the syscall: it would fail anyway' */
		PROTECTED_MODE_ALERT(PMCNVSTRMSG_STRUCT_DESCR_UNALIGNED,
			     sys_call_ID_to_name[regs->sys_num], "uargs",
			     (unsigned long)prot_uargs);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto out;
	}

	/* Copying strucrure fields from 'prot_uargs' to 'uargs64': */
	uargs64 = get_user_space(sizeof(*uargs64));
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
	DbgSCP("sys_clone3(uargs64=0x%lx, size64=0x%zx) = %d\n", uargs64, size64, rval);

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
			PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
			DbgSCP(" dirfd=%d path=%s argv=0x%lx envp=0x%lx flags=0x%x\n",
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID,
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


/*
 * This function converts protected structure 'iov' into regular one
 * alone with the check for validity of iov/iovcnt arguments to system calls,
 *                 taking iovec structure at input (like readv/writev and so).
 * iovcnt - number of buffers from the file assiciated to read/write.
 * It returns converted structure pointer if OK; NULL pointer otherwise.
 */
static struct iovec __user *convert_prot_iovec_struct(const void __user *iov,
				       const unsigned long        iovcnt,
				       const unsigned long         arg_num,
				       const unsigned char       *arg_name,
				       const struct pt_regs      *regs)
{
	const int nr_segs = iovcnt;
	void __user *new_arg = NULL;
	long size;
	long rval; /* syscall return value */

	if (unlikely(nr_segs > UIO_MAXIOV)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_COUNT_EXCEEDS_LIMIT,
				     sys_call_ID_to_name[regs->sys_num], nr_segs, UIO_MAXIOV);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return (void __user *) (long) (-EINVAL);
	} else if (unlikely(nr_segs < 0)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_NEGATIVE_SIZE_VALUE, regs->sys_num,
				     sys_call_ID_to_name[regs->sys_num], iovcnt, 2/*arg#*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return (void __user *) (long) (-EINVAL);
	}

	size = (prot_sc_arg_not_ptr(arg_num, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[arg_num - 1]);
	if (size < (sizeof(struct prot_iovec) * nr_segs)) {
		if (!size_exceeds_descr_max_capacity((sizeof(struct prot_iovec) * iovcnt),
							"iovcnt", iovcnt, regs))
			PROTECTED_MODE_ALERT(PMSCERRMSG_INSUFFICIENT_STRUCT_SIZE,
				     sys_call_ID_to_name[regs->sys_num], "iov",
				     size, (sizeof(struct prot_iovec) * nr_segs));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(arg_num, regs);
		return NULL;
	}

	new_arg = get_user_space(nr_segs * sizeof(struct iovec));
	rval = convert_iov(iov, new_arg, nr_segs);
	if (rval) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				     sys_call_ID_to_name[regs->sys_num], "iov", arg_name);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return (void __user *) (long) (rval);
	}
	return new_arg;
}


notrace __section(".entry.text")
long protected_sys_readv(unsigned long fd, const void __user *vec,
			 unsigned long vlen, unsigned long a4,
			 unsigned long a5, unsigned long a6,
			 const struct pt_regs *regs)
{
	const struct iovec __user *k_vec;
	long rval; /* syscall return value */

	if (!vlen)
		return 0;
	if ((int) fd < 0)
		return -EBADF;
	if ((int)vlen < 0)
		return -EINVAL;

	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		k_vec = vec;
	} else {
		k_vec = convert_prot_iovec_struct(vec, vlen, 2, "iov", regs);
		if (unlikely(IS_ERR(k_vec)))
			return PTR_ERR(k_vec);
		else if (!k_vec)
			return -EFAULT;
	}

	rval = sys_readv(fd, k_vec, vlen);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, k_vec);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_preadv(unsigned long fd, const void __user *vec,
			  unsigned long vlen, unsigned long pos_l,
			  unsigned long pos_h, unsigned long a6,
			  const struct pt_regs *regs)
{
	const struct iovec __user *k_vec;
	long rval; /* syscall return value */

	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		k_vec = vec;
	} else {
		k_vec = convert_prot_iovec_struct(vec, vlen, 2, "iov", regs);
		if (unlikely(IS_ERR(k_vec)))
			return PTR_ERR(k_vec);
		else if (!k_vec)
			return -EFAULT;
	}

	rval = sys_preadv(fd, k_vec, vlen, pos_l, pos_h);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, k_vec);
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
	PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_ERR_FROM,
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
			  unsigned long vlen, unsigned long a4,
			  unsigned long a5, unsigned long a6,
			  const struct pt_regs *regs)
{
	const struct iovec __user *k_vec;
	long rval; /* syscall return value */

	if (!vlen)
		return 0;

	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		k_vec = vec;
	} else {
		k_vec = convert_prot_iovec_struct(vec, vlen, 2, "iov", regs);
		if (unlikely(IS_ERR(k_vec)))
			return PTR_ERR(k_vec);
		else if (!k_vec)
			return -EFAULT;
	}

	rval = sys_writev(fd, k_vec, vlen);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, k_vec);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_pwritev(unsigned long fd, const void __user *vec,
		unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
		unsigned long a6, const struct pt_regs *regs)
{
	const struct iovec __user *k_vec;
	long rval; /* syscall return value */

	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		k_vec = vec;
	} else {
		k_vec = convert_prot_iovec_struct(vec, vlen, 2, "iov", regs);
		if (unlikely(IS_ERR(k_vec)))
			return PTR_ERR(k_vec);
		else if (!k_vec)
			return -EFAULT;
	}

	rval = sys_pwritev(fd, k_vec, vlen, pos_l, pos_h);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, k_vec);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_preadv2(unsigned long fd, const void __user *vec,
		unsigned long vlen, unsigned long pos_l, unsigned long pos_h,
		rwf_t flags, const struct pt_regs *regs)
{
	const struct iovec __user *k_vec;
	long rval; /* syscall return value */

	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		k_vec = vec;
	} else {
		k_vec = convert_prot_iovec_struct(vec, vlen, 2, "iov", regs);
		if (unlikely(IS_ERR(k_vec)))
			return PTR_ERR(k_vec);
		else if (!k_vec)
			return -EINVAL;
	}

	rval = sys_preadv2(fd, k_vec, vlen, pos_l, pos_h, flags);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, k_vec);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_pwritev2(unsigned long fd, const void __user *vec,
			    unsigned long vlen, unsigned long offset_l,
			    unsigned long offset_h, rwf_t flags,
			    struct pt_regs *regs)
{
	const struct iovec __user *k_vec;
	long rval; /* syscall return value */

	if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs)) {
		k_vec = vec;
	} else {
		k_vec = convert_prot_iovec_struct(vec, vlen, 2, "iov", regs);
		if (unlikely(IS_ERR(k_vec)))
			return PTR_ERR(k_vec);
		else if (!k_vec)
			return -EINVAL;
	}

	rval = sys_pwritev2(fd, k_vec, vlen, offset_l, offset_h, flags);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, k_vec);
	return rval;
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
				DbgSCP("failed to copy library path !!!\n");
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

	ptr_size = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);

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

	if (AP_ITAG(regs->qargs[0]) != ITAG_AP) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_DESCR_IN_STACK,
				     sys_call_ID_to_name[regs->sys_num],
				     old_address, "old_address");
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		goto nr_mremap_err;
	}
	base = sys_mremap(old_address, old_size, new_size, flags, new_address);
	if (base & ~PAGE_MASK) { /* this is error code */
		rval = base;
		goto nr_mremap_err;
	} else {
		e2k_ap_t ap = new_ap(base, new_size, 0, AP_RW(regs->qargs[0]));
		regs->rval1 = ap.lo;
		regs->rval2 = ap.hi;
		regs->rv1_tag = E2K_AP_LO_ETAG;
		regs->rv2_tag = E2K_AP_HI_ETAG;
		regs->return_desk = 1;
		rval = 0;
	}
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

/*
 * The structure of the second argument to socket call depends on
 *                                         the socket call number.
 * This function calculates mask/align type arguments to process
 *                               the structure by 'convert+array'.
 */
notrace __section(".entry.text")
static void get_socketcall_mask(long call, long *mask_type, long *mask_align,
				int *fields)
{
	switch (call) {
/*	Following calls don't require args conversion:
 *	case SYS_SOCKET:
 *		err = sys_socket(a[0], a[1], a[2]);
 *	case SYS_LISTEN:
 *		err = sys_listen(a[0], a[1]);
 *	case SYS_SHUTDOWN:
 *		err = sys_shutdown(a[0], a[1]);
 *		break;
 */
	case SYS_BIND:
		/* err = sys_bind(a[0],				*/
		/*	(struct sockaddr __user *) a[1], a[2]); */
	case SYS_CONNECT:
		/* err = sys_connect(a[0],			*/
		/*	(struct sockaddr __user *) a[1], a[2]); */
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
		break;
	case SYS_ACCEPT:
		/* err = sys_accept(a[0],				*/
		/*		(struct sockaddr __user *) a[1],	*/
		/*		(int __user*) a[2]);			*/
	case SYS_GETSOCKNAME:
		/* err = sys_getsockname(a[0],				*/
		/*		(struct sockaddr __user*) a[1],		*/
		/*		(int __user *) a[2]);			*/
	case SYS_GETPEERNAME:
		/* err = sys_getpeername(a[0],				*/
		/*		(struct sockaddr __user *) a[1],	*/
		/*		(int __user *)a[2]);			*/
		*mask_type = 0x3d;
		*mask_align = 0x3f;
		*fields = 3;
		break;
	case SYS_ACCEPT4:
		*mask_type = 0x7d;
		*mask_align = 0xff;
		*fields = 4;
		/* err = sys_accept4(a[0],				*/
		/*		(struct sockaddr __user *) a[1],	*/
		/*		(int	__user*)	a[2]		*/
		/*		(int)			a[3]);		*/
		break;
	case SYS_SOCKETPAIR:
		*mask_type = 0xd5;
		*mask_align = 0xf5;
		*fields = 4;
		/*err = sys_socketpair(a[0], a[1], a[2],	*/
		/*			(int __user *)a[3]);	*/
		break;
	case SYS_SEND:
		*mask_type = 0x5d;
		*mask_align = 0x5f;
		*fields = 4;
		/* err = sys_send(a[0], (void __user *) a[1], a[2],	*/
		/*					a[3]);		*/
		break;
	case SYS_SENDTO:
		*mask_type = 0x75d;
		*mask_align = 0x7df;
		*fields = 6;
		/* err = sys_sendto(a[0], (void __user *) a[1], a[2],	*/
		/* a[3], (struct sockaddr __user *) a[4], a[5]);	*/
		break;
	case SYS_RECV:
		*mask_type = 0x5d;
		*mask_align = 0x5f;
		*fields = 4;
		/* err = sys_recv(a[0], (void __user *) a[1],	*/
		/*			a[2], a[3]);		*/
		break;
	case SYS_RECVFROM:
		*mask_type = 0xf5d;
		*mask_align = 0xfdf;
		*fields = 6;
		/* err = sys_recvfrom(a[0], (void __user *) a[1], a[2],	*/
		/*		a[3], (struct sockaddr __user *) a[4],	*/
		/*		(int __user *) a[5]);			*/
		break;
	case SYS_SETSOCKOPT:
		*mask_type = 0x1d5;
		*mask_align = 0x1f5;
		*fields = 5;
		/* err = sys_setsockopt(a[0], a[1], a[2],	*/
		/*		(char __user *)a[3], a[4]);	*/
		break;
	case SYS_GETSOCKOPT:
		*mask_type = 0x3d5;
		*mask_align = 0x3f5;
		*fields = 5;
		/* err = sys_getsockopt(a[0], a[1], a[2],		*/
		/*	(char __user *) a[3], (int __user *)a[4]);	*/
		break;
	case SYS_SENDMSG:
		/* err = sys_sendmsg(a[0],				*/
		/*		(struct msghdr __user *) a[1], a[2]);	*/
	case SYS_RECVMSG:
		/* err = sys_recvmsg(a[0],				*/
		/*		(struct msghdr __user *) a[1], a[2]);	*/
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
		break;
	default:
		DbgSCP("Empty masks used for socketcall #%ld\n", call);
		*mask_type = 0x0;
		*mask_align = 0x0;
		*fields = 0;
		break;
	}
}

notrace __section(".entry.text")
long protected_sys_socketcall(const unsigned long        a1, /* call */
			      const unsigned long __user *a2, /* args */
			      const unsigned long unused3,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs)
{
	unsigned long __user *args;
	long size;
	long mask_type, mask_align;
	int fields;
	long rval; /* syscall return value */
	struct protected_user_msghdr __user *prot_msghdr;
	struct user_msghdr __user *converted_msghdr;

	get_socketcall_mask(a1, &mask_type, &mask_align, &fields);

	if (!a2) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_CMD_WRONG_ARG_VALUE_LX,
				       sys_call_ID_to_name[regs->sys_num],
				       "call", (int) a1, "args", a2);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return -EFAULT;
	}
	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EFAULT;
	size = AP_OBJ_SIZE(regs->qargs[1]);
	/* NB> `convert_array' below will check if size is large
	 *                               enough for this request.
	 *
	 * Need an additional conversions of arguments
	 * for syscalls recvmsg/sendmsg
	 */
	if ((a1 == SYS_SENDMSG) || (a1 == SYS_RECVMSG)) {
		e2k_ptr_t descr; /* protected_user_msghdr in the arg array */
		void __user *ptr;
		long iov_len;
		int tags;

		rval = get_user_tagged_16(descr.qword, tags, &a2[2]);
		if (unlikely(rval)) {
			goto err_out_bad_array;
		} else if (unlikely(!IS_AP(regs->qargs[1], tags))) {
			rval = -EFAULT;
			goto err_out_bad_array;
		}
		ptr = (void __user *)e2k_ptr_objptr(descr, 0);
		iov_len = get_prot_msghdr_iovlen(ptr);
		if (iov_len < 0) {
			rval = iov_len;
			goto err_out_bad_array;
		}
		/*
		 * Allocate space in user stack for args conversion.
		 * NB> We allocate extra field for final zero-element.
		 */
		args = get_user_space(((fields + 1) * sizeof(args[0])) +
			sizeof(struct user_msghdr) + iov_len * sizeof(struct iovec));
		/* Convert args array for socketcall from ptr */
		rval = convert_array_3(a2, args, size, fields, 1,
					mask_type, mask_align, 0,
					CONV_ARR_WRONG_DSCR_FLD, regs);

		if (unlikely(rval))
			goto err_out_bad_array;

		/* Convert struct msghdr from args[1] */
		if (get_user(prot_msghdr,
				(struct protected_user_msghdr __user * __user *) &args[1]))
			return -EFAULT;
		converted_msghdr = (struct user_msghdr __user *) (args + (fields + 1));
		if (prot_msghdr) {
			converted_msghdr = convert_msghdr(prot_msghdr,
				SIZE_MSGHDR, "socketcall", "args[1]", converted_msghdr, regs);
			if (IS_ERR(converted_msghdr))
				return PTR_ERR(converted_msghdr);
			/* Set args[1] to pointer to converted structure */
			if (put_user((unsigned long) converted_msghdr, &args[1]))
				return -EFAULT;
		} else {
			if (put_user(0, &args[1]))
				return -EFAULT;
			DbgSCP("Empty user_msghdr in args[1]\n");
		}
	/* Other socketcalls */
	} else {
		if (fields) {
			/* Allocate space on user stack for args array */
			args = get_user_space((fields + 1) * sizeof(args[0]));
			/* Convert args array for socketcall from ptr */
			rval = convert_array(a2, args, size,
					fields, 1, mask_type, mask_align, regs);
			if (rval)
				goto err_out_bad_array;
		} else {
			DbgSCP("Using args as is; convert_array not called.\n");
			args = (unsigned long __user *) a2;
		}
	}

	/* Calling regular socketcall function with converted arguments: */
	rval = sys_socketcall((int) a1, args);

	if (!rval && (a1 == SYS_RECVMSG)) {
		long ret;
		rval = copy_in_user(&prot_msghdr->msg_flags, &converted_msghdr->msg_flags,
						sizeof(converted_msghdr->msg_flags));
		if (rval) {
			PROTECTED_MODE_WARNING(PMSCWARN_SOCKETCALL_FAILED_TO_UPDATE_FLD,
					       "msg_flags");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		}
		ret = copy_in_user(&prot_msghdr->msg_controllen,
				   &converted_msghdr->msg_controllen,
				   sizeof(converted_msghdr->msg_controllen));
		if (ret) {
			PROTECTED_MODE_WARNING(PMSCWARN_SOCKETCALL_FAILED_TO_UPDATE_FLD,
					       "controllen");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
			rval = ret;
		}
	}

	DbgSCP(" (%d) returned %ld\n", (int) a1, rval);
	return rval;

err_out_bad_array:
	PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
			     regs->sys_num, sys_call_ID_to_name[regs->sys_num], "args", 2);
	PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_sendmsg(const unsigned long		sockfd,
			   const void __user		*msg,
			   const unsigned long		flags,
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs)
{
	long size;
	long rval; /* syscall return value */
	struct user_msghdr __user *converted_msghdr;
	long iovlen;

	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EFAULT;
	size = AP_OBJ_SIZE(regs->qargs[1]);
	iovlen = get_prot_msghdr_iovlen(msg);
	if (unlikely(iovlen < 0)) {
		DbgSCP("get_prot_msghdr_iovlen(%ld) returned %ld\n", (unsigned long)msg, iovlen);
		return iovlen;
	}
	converted_msghdr = get_user_space(sizeof(struct user_msghdr) +
						iovlen * sizeof(struct iovec));
	converted_msghdr = convert_msghdr(msg, size, "sendmsg", "msg", converted_msghdr, regs);
	if (IS_ERR(converted_msghdr))
		return PTR_ERR(converted_msghdr);

	 /* Call socketcall handler function: */
	rval = sys_sendmsg(sockfd, converted_msghdr, flags);

	DbgSCP(" returned %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_recvmsg(const unsigned long		socket,
			   const void __user		*message,
			   const unsigned long		flags,
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs)
{
	long size;
	long rval; /* syscall return value */
	struct user_msghdr __user *converted_msghdr;
	struct protected_user_msghdr __user *prot_msghdr =
					(struct protected_user_msghdr __user *)message;
	long iovlen;

	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EFAULT;
	size = AP_OBJ_SIZE(regs->qargs[1]);
	iovlen = get_prot_msghdr_iovlen(message);
	if (unlikely(iovlen < 0)) {
		DbgSCP("get_prot_msghdr_iovlen(%ld) returned %ld\n",
				(unsigned long)message, iovlen);
		return iovlen;
	}
	converted_msghdr = get_user_space(sizeof(struct user_msghdr) +
						iovlen * sizeof(struct iovec));
	converted_msghdr = convert_msghdr(prot_msghdr, size, "recvmsg", "message",
					  converted_msghdr, regs);
	if (IS_ERR(converted_msghdr))
		return PTR_ERR(converted_msghdr);

	 /* Call socketcall handler function: */
	rval = sys_recvmsg(socket, converted_msghdr, flags);
	DbgSCP("Syscall recvmsg(%ld, 0x%lx, 0x%lx) returned %ld\n",
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


/* Calculates total iovec buff number in the 'mmsghdr' structure.
 * Returns: total iovec buff number in the 'mmsghdr' structure;
 *       or (-1) if size of 'mmsghdr' exceeds the one required by 'vlen';
 *       or negative error number to report.
 */
static long iovec_num_in_mmsghdr(const void __user *prot_mmsghdr,
				 const unsigned long prot_mmsghdr_size,
				 const unsigned int vlen)
{
	void __user *msghdr128 = (void __user *)prot_mmsghdr;
	long iov_len, iovec_num = 0;
	long size = prot_mmsghdr_size;
	int i;

	for (i = 0; i < vlen; i++) {
		iov_len = get_prot_msghdr_iovlen(msghdr128);
		if (iov_len < 0)
			return iov_len;
		iovec_num += iov_len;
		msghdr128 += sizeof(struct protected_mmsghdr);
		size -= sizeof(struct protected_mmsghdr);
		if (i < (vlen - 1) && size < sizeof(struct protected_mmsghdr))
			return -1L;
	}

	return iovec_num;
}

#define MMSGHDR_STRUCT_SIZE_LONGS \
	(sizeof(struct mmsghdr) / sizeof(long))
#define MMSGHDR_VECT_SIZE_LONGS(vlen) \
	((sizeof(struct mmsghdr) * vlen) / sizeof(long))

static long convert_mmsghdr(void __user *prot_mmsghdr,
			    void __user *kernel_mmsghdr,
			    unsigned int		size,
			    unsigned int		vlen,
			    const char			*syscall_name,
			    const struct pt_regs	*regs)
/* Converts user msghdr structure from protected to regular structure format.
 * Outputs: 0 if converted OK; error code otherwise.
 * 'prot_msghdr' - protected message header structure.
 * 'kernel_mmsghdr' - converted structure (to be allocated in syscall
 *                    to avoid re-using stack area if allocated over here).
 * 'size' - size of the input structure.
 * 'vlen' - vector length if vector of structures is converted.
 * 'syscall_name' - reference to particular syscall in diagnostic output.
 */
{
	long __user *args = kernel_mmsghdr;
	long __user *v_mmsrhdr;
	struct mmsghdr __user *converted_mmsghdr;
	struct user_msghdr __user *converted_msghdr;
	long __user *converted_iovec;
	int err, iov_len, i;

#define MASK_MMSGHDR_TYPE     0x0773 /* type mask for struct mmsghdr */
#define MASK_MMSGHDR_ALIGN    0xd7ff /* alignment mask for mmsghdr structure */
#define MASK_MMSGHDR_RW       MASK_MSGHDR_RW
	/*
	 * Structures user_msghdr and iovec contain pointers
	 * inside, therefore they need to be additionally
	 * converted with saving results in these structures
	 */

	/* (1) Converting 'mmsghdr' structure array: */

	converted_mmsghdr = (struct mmsghdr __user *) args;
	err = convert_array_3(prot_mmsghdr, (long __user *) converted_mmsghdr,
				size, 8, vlen, MASK_MMSGHDR_TYPE,
				MASK_MMSGHDR_ALIGN, MASK_MMSGHDR_RW,
				CONV_ARR_WRONG_DSCR_FLD, regs);
	if (err) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
				     syscall_name, "mmsghdr", "msgvec");
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	/* (2) Converting struct iovec fields in msghdr structures
	 *            (msghdr->msg_iov):
	 */
	converted_iovec = args + MMSGHDR_VECT_SIZE_LONGS(vlen);
	for (i = 0, v_mmsrhdr = args; i < vlen; i++) {
		struct iovec __user *msg_iov;

		converted_mmsghdr = (struct mmsghdr __user *) v_mmsrhdr;
		converted_msghdr = &converted_mmsghdr->msg_hdr;
		if (get_user(iov_len, &converted_msghdr->msg_iovlen)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM, __func__,
					(unsigned long) &converted_msghdr->msg_iovlen);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
		if (get_user(msg_iov, &converted_msghdr->msg_iov)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM,
					__func__, (unsigned long) &converted_msghdr->msg_iov);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
		if (msg_iov) {
			err = convert_iov(msg_iov, converted_iovec, iov_len);
			if (err) {
				PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_FIELD_STRUCT_IN_ARG_NAME,
						     syscall_name, "iovec", "mmsghdr", "mmsghdr");
				PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			}
		} else {
			PROTECTED_MODE_WARNING(PMSCERRMSG_EMPTY_STRUCTURE_FIELD,
					       syscall_name, "msg_iov", "user_msghdr", "mmsghdr");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
			converted_iovec = NULL;
		}

		/* Replacing iovec pointer in converted msghdr structure: */
		if (put_user((void __user *) converted_iovec,
				&converted_msghdr->msg_iov)) {
			PROTECTED_MODE_WARNING(PMSCERRMSG_FATAL_WRITE_AT_FIELD,
				syscall_name, &converted_msghdr->msg_iov, "msghdr->msg_iov");
			PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}

		v_mmsrhdr += MMSGHDR_STRUCT_SIZE_LONGS;
		converted_iovec += iov_len * sizeof(struct iovec) / sizeof(long);
	}

	return 0;
}

#if 1
#define print_mmsghdr_struct(a1, a2, a3)
#else
static void print_mmsghdr_struct(const char *title,
				 long __user *mmsghdr_arr,
				 const int vlen)
{
	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		long __user *larr = mmsghdr_arr;
		struct mmsghdr __user *mmsghdrp;
		struct iovec __user *iovp;
		long lval;
		int i, j;

		/* Print structure content: */
		pr_info("%s[%d]:\n", title, vlen);
		for (i = 0; i < vlen; i++) {
			mmsghdrp = (struct mmsghdr *)larr;
			pr_info("\t##### mmsghdr[%d] : 0x%lx #####\n",
				i, (long)mmsghdrp);
			for (j = 0; j < MMSGHDR_STRUCT_SIZE_LONGS; j++) {
				pr_info("\t0x%.8x.%.8x\n",
					(int)(*larr), (int)(*larr >> 32));
				lar++;
			}
			iovp = mmsghdrp->msg_hdr.msg_iov;
			for (j = 0; j < mmsghdrp->msg_hdr.msg_iovlen; j++) {
				lval = (long) iovp;
				pr_info("\t->msg_iov[%d: 0x%lx]: base = 0x%lx  len = %ld\n",
					j, lval,
					(long)iovp->iov_base, iovp->iov_len);
				lval += sizeof(struct iovec);
				iovp = (struct iovec *)lval;
			}
		}
	}
}
#endif /* print_mmsghdr_struct */

static long update_prot_mmsghdr_struct(long __user *mmsghdr_arr,
				       long __user *prot_msgvec,
				       const int vlen)
/* This is post-syscall post-processing procedure.
 * Propagate .msg_len values from processed 'mmsghdr_arr' back to 'prot_msgvec'.
 * 'vlen' - number of elements in the array.
 * Returns error code or 0 if OK.
 */
{
#define MMSGHDR_STR_LEN_OFFSET 96
	/* .msg_len field offset in the protected structure */
#define PROT_MMSGHDR_SIZE     sizeof(struct protected_mmsghdr)
	/* size of struct mmsghdr in prot. user space */
	long __user *from = mmsghdr_arr;
	long __user *to = prot_msgvec;
	struct mmsghdr __user *mmsghdr_from;
	long val;
	int i;

	to += MMSGHDR_STR_LEN_OFFSET / sizeof(long);

	for (i = 0; i < vlen; i++) {
		mmsghdr_from = (struct mmsghdr __user *) from;
		if (get_user(val, &mmsghdr_from->msg_len)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM, __func__,
					(unsigned long) &mmsghdr_from->msg_len);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}
		DbgSCP("mmsghdr[%d].msg_len = %ld\n", i, val);
		if (put_user(val, to)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_WRITE_AT,
					     __func__, (unsigned long) to);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
			return -EFAULT;
		}

		from += MMSGHDR_STRUCT_SIZE_LONGS;
		to += PROT_MMSGHDR_SIZE / sizeof(long);
	}

	return 0;
}

#define PROTECTED_MMSGHDR_SIZE(vlen) \
			(PROT_MMSGHDR_SIZE * vlen)

notrace __section(".entry.text")
long protected_sys_sendmmsg(const unsigned long		sockfd,
			    void __user			*msgvec,
			    const unsigned long		vlen, /* vector lngth */
			    const unsigned long		flags,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs		*regs)
{
	long size;
	long rval; /* syscall return value */
	long iov_total_num;
	void __user *kernel_mmsghdr;

	DbgSCP(" sockfd=%ld  vlen=%ld\n", sockfd, vlen);

	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EINVAL;
	size = AP_OBJ_SIZE(regs->qargs[1]);
	if (size < PROTECTED_MMSGHDR_SIZE(vlen)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
			"sendmmsg", "msgvec", size, "vlen", PROTECTED_MMSGHDR_SIZE(vlen));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EINVAL;
	}

	iov_total_num = iovec_num_in_mmsghdr(msgvec, size, vlen);
	if (unlikely(iov_total_num == -1)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
			"sendmmsg", "msgvec", size, "vlen", PROTECTED_MMSGHDR_SIZE(vlen));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EINVAL;
	} else if (unlikely(iov_total_num < 0)) {
		return iov_total_num;
	}
	/* NB> For the sake of performance we don't calculate exact vector size.
	 *     Instead, we allocate same space as in PM, which is bigger
	 *     and is quite enough for kernel structire for sure.
	 */
	kernel_mmsghdr = get_user_space(size + (iov_total_num * sizeof(struct iovec)));
	if (!kernel_mmsghdr) {
		pr_err("%s:%d : FATAL ERROR: failed to allocate %ld bytes on stack !!!",
		       __FILE__, __LINE__, size);
		return -EINVAL;
	}

	if (convert_mmsghdr(msgvec, kernel_mmsghdr, size, vlen, "sendmmsg", regs))
		return -EINVAL;

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))
		print_mmsghdr_struct("protected sendmmsg: converted mmsghdr",
				     kernel_mmsghdr, vlen);

	rval = sys_sendmmsg(sockfd, kernel_mmsghdr, vlen, flags);
	if (rval <= 0)
		DbgSCP("sys_sendmmsg() failed with error code %ld\n", rval);

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))
		print_mmsghdr_struct("protected sendmmsg: post-syscall mmsghdr",
				     kernel_mmsghdr, vlen);

	if (rval > 0) {
		/* Propagating .msg_len values back to 'msgvec' */
		long ret;

		ret = update_prot_mmsghdr_struct(kernel_mmsghdr, msgvec, (int) vlen);
		if (ret)
			rval = ret;
	}

	DbgSCP(" returned %ld\n", rval);
	return rval;
}

notrace __section(".entry.text")
long protected_sys_recvmmsg(const unsigned long		sockfd,
			    const unsigned long msgvec,
			    const unsigned long		vlen, /* vector lngth */
			    const unsigned long		flags,
			    const unsigned long timeout,
			    const unsigned long unused6,
			    const struct pt_regs		*regs)
{
	long size;
	long rval; /* syscall return value */
	long iov_total_num;
	long __user *kernel_mmsghdr;

	DbgSCP(" sockfd=%ld  vlen=%ld\n", sockfd, vlen);

	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EFAULT;
	size = AP_OBJ_SIZE(regs->qargs[1]);
	if (size < PROTECTED_MMSGHDR_SIZE(vlen)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
			"recvmmsg", "msgvec", size, "vlen", PROTECTED_MMSGHDR_SIZE(vlen));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EINVAL;
	}

	iov_total_num = iovec_num_in_mmsghdr((void __user *)msgvec, size, vlen);
	if (unlikely(iov_total_num == -1)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
			"sendmmsg", "msgvec", size, "vlen", PROTECTED_MMSGHDR_SIZE(vlen));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EINVAL;
	} else if (unlikely(iov_total_num < 0)) {
		return iov_total_num;
	}

	/* NB> For the sake of performance we allocate same space as in PM. */
	kernel_mmsghdr = get_user_space(size + (iov_total_num * sizeof(struct iovec)));
	if (!kernel_mmsghdr) {
		pr_err("%s:%d : FATAL ERROR: failed to allocate %ld bytes on stack !!!",
		       __FILE__, __LINE__,  size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	if (convert_mmsghdr((long __user *) msgvec, kernel_mmsghdr,
					size, vlen, "recvmmsg", regs))
		return -EINVAL;

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT))
		print_mmsghdr_struct("protected recvmmsg: converted mmsghdr",
				     kernel_mmsghdr, vlen);

	rval = sys_recvmmsg(sockfd, (struct mmsghdr __user *) kernel_mmsghdr, vlen,
			    flags, (struct __kernel_timespec __user *) timeout);

	if (rval <= 0) {
		DbgSCP("sys_recvmmsg() failed with error code %ld\n", rval);
	} else { /* (rval > 0) */
		long ret;

		ret = update_prot_mmsghdr_struct(kernel_mmsghdr,
						 (long __user *)msgvec, (int)vlen);
		if (ret)
			rval = ret;
	}

	DbgSCP(" returned %ld\n", rval);
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

static long process_shmat_syscall_result(const int shmid, const int shmflg,
							ulong __user *raddr)
{
	/* This is 'shmat' syscall post-processing for protected execution mode.
	 * We need to convert obtained shm pointer to descriptor
	 *          (must have been available in *raddr) and pass it to 'raddr':
	 */
	unsigned long segm_size;
	ulong base;
	e2k_ptr_t dscr;
	int access;
	long rval; /* return value */

	/* taking shm parameters from shmid: */
	segm_size = get_shm_segm_size(shmid);
	DbgSCP("(%d): segm_size = %ld\n", shmid, segm_size);

	if (IS_ERR_VALUE(segm_size))
		return (long) segm_size;

	access = (shmflg & SHM_RDONLY) ? R_ENABLE : RW_ENABLE;

	if (get_user(base, raddr))
		return -EFAULT;

	dscr = new_ap(base, segm_size, 0, access);

	DbgSCP("(%d): lo = 0x%llx  hi = 0x%llx\n", shmid, dscr.lo, dscr.hi);

	rval = put_user_tagged_16(dscr.qword, ETAGAPQ, raddr);
	DbgSCP("(%d) returned %ld\n", shmid, rval);
	return rval;
}

static inline
int check_prot_semun_struct(const struct pt_regs *regs,
			    int arg_num, /* argument # in syscall */
			    size_t size) /* min size of descriptor */
/* Returns: 1 - if check passed OK; 0 - otherwise */
{
	if (!regs->qargs[arg_num - 1].lo) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
			regs->sys_num, sys_call_ID_to_name[regs->sys_num], "semun", arg_num);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return 0;
	}
	/* Check that union semun arg #arg_num contains proper pointer: */
	if (!prot_arg_is_ap(regs, arg_num)) {
		unsigned long ptr = e2k_ptr_objptr(regs->qargs[arg_num - 1], 0);

		DbgSCP("semun = 0x%llx:0x%llx, tag=0x%lx\n",
		       regs->qargs[arg_num - 1].lo, regs->qargs[arg_num - 1].hi,
		       (regs->tags >> (arg_num * 8)) & 0xff);
		PROTECTED_MODE_ALERT(PMCNVSTRMSG_STRUCT_DOESNT_CONTAIN_DESCR,
				     "semun", ptr);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return 0;
	}
	if (size) {
		long dscr_size;

		dscr_size = AP_OBJ_SIZE(regs->qargs[arg_num - 1]);
		if (dscr_size < size) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
		if (!check_prot_semun_struct(regs, 4/*arg#*/, sizeof(struct semid_ds))) {
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID,
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

	rval = sys_old_semctl((int) semid, (int) semnum, (int) cmd, (unsigned long) fourth);
out:
	DbgSCP("(cmd=%d, semnum=%d, semun=0x%lx) returned %ld\n",
	       (int) cmd, (int) semnum, fourth, rval);
	return rval;
}

/* long sys_shmat(int shmid, char __user *shmaddr, int shmflg); */
notrace __section(".entry.text")
long protected_sys_shmat(const long		shmid,		/* a1 */
			 const unsigned long shmaddr,	/* a2 */
			 const long		shmflg,		/* a3 */
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 struct pt_regs		*regs)
{
	unsigned long segm_size;
	ulong base;
	e2k_ap_t ap;
	int access;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;
	long rval; /* syscall return value */

	rval = sys_shmat((int) shmid, (char __user *) shmaddr, (int) shmflg);

	if (IS_ERR_VALUE(rval))
		goto err_out;
	base = (ulong) rval;

	/*
	 * 'shmat' syscall post-processing for protected execution mode:
	 * We need to convert obtained shm pointer to descriptor
	 */

	segm_size = get_shm_segm_size(shmid);
	DbgSCP("(%ld): segm_size = %ld\n", shmid, segm_size);

	if (IS_ERR_VALUE(segm_size)) {
		rval = (long) segm_size;
		goto err_out;
	}

	access = (shmflg & SHM_RDONLY) ? R_ENABLE : RW_ENABLE;

	ap = new_ap(base, segm_size, 0, access);

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
				PROTECTED_MODE_ALERT(PMSCERRMSG_UNEXP_ARG_TAG_ID,
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

		converted_new_msg_buf =
				get_user_space(sizeof(struct ipc_kludge));
		rval = convert_array(ptr, converted_new_msg_buf,
					SIZE_MSG_BUF_PTR, 2, 1,
					MASK_MSG_BUF_PTR_TYPE,
					MASK_MSG_BUF_PTR_ALIGN, regs);
		if (rval) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
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
		if (unlikely(third && !prot_arg_is_ap(regs, 4))) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "third", prot_sc_arg_tag(4, regs));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}
		break;
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

	if (!IS_ERR_VALUE(rval) && (call == SHMAT)) {
		/* we need to return descriptor to pointer in args[1] */
		rval = process_shmat_syscall_result(
			(int) first /*shmid*/,
			(int) second /*shmflg*/,
			(ulong __user *) third /**raddr*/);
	}
out:
	DbgSCP("(%d) returned %ld\n", (int) call, rval);
	return rval;
}

__section(".entry.text")
static long prot_sys_mmap(const unsigned long start,
		const unsigned long length, const unsigned long prot,
		const unsigned long flags, const unsigned long fd,
		const unsigned long offset, const int offset_in_bytes,
		struct pt_regs *regs)
{
	long rval = -EINVAL; /* syscall return value */
	e2k_addr_t base;
	e2k_ap_t ap;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;

	DbgSCP("start = %ld, len = %ld (0x%lx), prot = 0x%lx ", start, length, length, prot);
	DbgSCP("flags = 0x%lx, fd = 0x%lx, off = %ld, in_bytes=%d",
	       flags, fd, offset, offset_in_bytes);
	if (!length)
		goto nr_mmap_err;

	if ((length > 0) && (length >> 31) && unlikely(cpu_has(CPU_FEAT_ISET_V7))) {
		/* NB> For details on this limitation see bug #99875 */
		PROTECTED_MODE_ALERT(PMMMAPMSG_ATTEMPT_TO_MAP_BYTES,
				     "mmap()", length, length);
		PROTECTED_MODE_MESSAGE(0, PMMMAPMSG_CANT_MAP_OVER_2GB);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		/* NB> We cannot simply return error code as
		 *     this syscall returns structured result.
		 */
		goto nr_mmap_err;
	}
	if (offset < 0) {
		PROTECTED_MODE_WARNING(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				offset, 2/*argnum*/);
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
		goto nr_mmap_err;
	}
	if (size_exceeds_descr_max_capacity((offset_in_bytes ? offset : (offset * PAGE_SIZE)),
						"offset", offset, regs)) {
		PM_EXCEPTION_ON_WARNING(SIGABRT, 0, EINVAL);
		goto nr_mmap_err;
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

	if (unlikely(cpu_has(CPU_FEAT_ISET_V7)) && flags & MAP_SHARED)
		PROTECTED_MODE_WARNING(PMSCWARN_MMAP_SHARED_FLAG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], (long)base);

	ap = new_ap(base, length, 0, RW_ENABLE);
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_DESCR_IN_STACK,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
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

static struct prot_robust_list_head {
	struct prot_robust_list		list;
	long				futex_offset;
	e2k_ptr_t			list_op_pending;
} prot_robust_list_head_t;

#define SIZEOF_PROT_HEAD_STRUCT	(sizeof(prot_robust_list_head_t))

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
			PROTECTED_MODE_ALERT(PMSCERRMSG_NEGATIVE_SIZE_VALUE,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     (long)len, 2);
		else
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_DIFFERS_STRUCT_SIZE,
				     sys_call_ID_to_name[regs->sys_num],
				     "len", len, "robust_list_head",
				     SIZEOF_PROT_HEAD_STRUCT);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	if (AP_OBJ_SIZE(regs->qargs[0]) < SIZEOF_PROT_HEAD_STRUCT) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_DIFFERS_STRUCT_SIZE,
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

	DbgSCP("(pid=%ld, head_ptr=0x%lx, len_ptr=0x%lx)\n",
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE, __func__,
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
	long lsize, rsize;
	struct iovec __user *lv = NULL;
	struct iovec __user *rv = NULL;
	long rval;

	DbgSCP("(%ld, lvec=0x%lx, lcnt=%ld, rvec=0x%lx, rcnt=%ld, flg=0x%lx)\n",
	       pid, lvec, liovcnt, rvec, riovcnt, flags);

	lsize = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
	if (lsize < (sizeof(struct prot_iovec) * liovcnt)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     sys_call_ID_to_name[regs->sys_num], "lvec", lsize,
				     "liovcnt", sizeof(struct prot_iovec) * liovcnt);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return -EFAULT;
	}
	rsize = (prot_sc_arg_not_ptr(4, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[3]);
	if (rsize < (sizeof(struct prot_iovec) * riovcnt)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_MISMATCHES_FIELD_VAL,
				     sys_call_ID_to_name[regs->sys_num], "rvec", rsize,
				     "riovcnt", sizeof(struct prot_iovec) * riovcnt);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(4/*arg_num*/, regs);
		return -EFAULT;
	}

	if (liovcnt || riovcnt) {
		char __user *new_arg;

		new_arg = get_user_space(lsize + rsize);
		lv = (struct iovec __user *) new_arg;
		rv = (struct iovec __user *)(new_arg + lsize);

		if (liovcnt) {
			rval = get_pm_struct(lvec, lv, lsize, 2, liovcnt/*nr_segs*/,
					     0x13, 0x33, 0x0, 0x0, regs);
			if (rval) {
				PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
						     sys_call_ID_to_name[regs->sys_num],
						     "iovec", "lvec");
				PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
				return -EINVAL;
			}
		}

		if (riovcnt) {
			rval = get_pm_struct(rvec, rv, rsize, 2, riovcnt/*nr_segs*/,
					     0x15, 0x33, 0x0, 0x0, regs);
			if (rval) {
				PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
						     sys_call_ID_to_name[regs->sys_num],
						     "iovec", "rvec");
				PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
				return -EINVAL;
			}
		}
	}

	if (vm_write)
		rval = sys_process_vm_writev(id, lv, liovcnt,
						rv, riovcnt, flags);
	else
		rval = sys_process_vm_readv(id, lv, liovcnt,
						rv, riovcnt, flags);

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
	struct iovec __user *kiov;

	DbgSCP("(fd=%d, iov=0x%lx, nr_segs=%ld, flg=0x%x)\n", fd, iov, nr_segs, flags);

	if (fd < 0)
		return -EBADF;
	if (!iov || nr_segs < 0)
		return -EINVAL;

	if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
		return -EINVAL;

	size = AP_OBJ_SIZE(regs->qargs[1]);
	if (size < sizeof(struct iovec)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "iov", size, sizeof(struct iovec));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(2/*arg_num*/, regs);
		return rval;
	}

	kiov = get_user_space(size);
	rval = convert_array(iov, kiov, size, 2, 1/*nr_segs*/, 0x7, 0x7, regs);
	if (rval) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
			regs->sys_num, sys_call_ID_to_name[regs->sys_num], "iovec", 2);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	rval = sys_vmsplice(fd, kiov, nr_segs, flags);
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "iov", size, sizeof(struct iovec));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return rval;
		}
		kiov = get_user_space(size);
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					sys_call_ID_to_name[regs->sys_num], "keyctl_kdf_params",
					size, sizeof(struct keyctl_kdf_params));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(5/*arg_num*/, regs);
			return rval;
		}
		kkdf_params = get_user_space(size);
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
	PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
	long size, min_size;
	void __user *intptr;
	void __user *kintptr;
	struct sock_fprog __user *sfprog;
	struct sock_fprog __user *ksfprog;
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
		size = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
		if (size < sizeof(int)) {
			str_name = "(int *) arg2";
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, sizeof(int));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		break;
	case PR_GET_NAME:
		if (!arg2)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		size = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
		min_size = 16; /* this is specified in Linux Pages */
		if (size < min_size) {
			str_name = "(char *) arg2";
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, min_size);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		break;
	case PR_SET_NAME:
		if (!arg2)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		size = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
		if (e2k_ptr_str_check((char __user *) arg2, size)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_STRING_IN_SC_ARG,
				regs->sys_num, sys_call_ID_to_name[regs->sys_num], 2/*arg#*/);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		}
		break;
	case PR_GET_TID_ADDRESS:
		intptr = (void __user *) arg2;
		if (!intptr)
			break;
		if (warn_if_not_descr(2, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		str_name = "(int **) arg2";
		size = (prot_sc_arg_not_ptr(2, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[1]);
		if (size < sizeof(int **)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, sizeof(int **));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		kintptr = get_user_space(size);
		rval = convert_array(intptr, kintptr,
				     size, 1, 1/*nr_segs*/, 0x3, 0x3, regs);
		if (rval)
			goto err_out;
		return sys_prctl(option, (unsigned long) kintptr, arg3,
				 arg4, arg5);
	case PR_SET_SECCOMP:
		sfprog = (struct sock_fprog __user *) arg3;
		if (!sfprog)
			break;
		if (warn_if_not_descr(3, CHECK4DESCR_WARNING, regs))
			return -EFAULT;
		str_name = "(sock_fprog *) arg3";
		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < sizeof(struct sock_fprog)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
					     sys_call_ID_to_name[regs->sys_num],
					     str_name, size, sizeof(struct sock_fprog));
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return rval;
		}
		ksfprog = get_user_space(size);
		rval = convert_array(sfprog, ksfprog, size, 2, 1/*nr_segs*/, 0xc, 0xf, regs);
		if (rval)
			goto err_out;
		return sys_prctl(option, arg2, (unsigned long) ksfprog,
				 arg4, arg5);
	}

	return sys_prctl(option, arg2, arg3, arg4, arg5);

err_out:
	PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
				PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
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
#define BPF_PROG_LOAD_MTYPE	0x03131111131331
#define BPF_PROG_LOAD_MALIGN	0x03333111133333
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_VAL_UNSUPPORTED,
					     "bpf()", "CMD", cmd);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			rval = -ENOTSUPP;
			goto out;

		default:
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_WRONG_ARG_VALUE_LX,
					     "bpf()", "cmd", (long) cmd);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			rval = -EINVAL;
			goto out;
		}
		if (rval) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_CMD_WRONG_ARG_VALUE_LX,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "readfds", size, (size_t) expected_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	/* Check descriptor's size of 3rd argument. */
	size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
	if (size && size < expected_size) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "writefds", size, (size_t) expected_size);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	/* Check descriptor's size of 4th argument. */
	size = (prot_sc_arg_not_ptr(4, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[3]);
	if (size && size < expected_size) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					     __func__, "'sigmask'", size,
					(size_t) STRUCT_SIGSET6_PROT_SIZE);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
			return -EINVAL;
		}

		/* Translate struct sigmask from user128 to kernel64 mode. */
		sigmask_ptr64 = get_user_space(size);
		rval = convert_array((long __user *)sigmask, sigmask_ptr64,
				     size, STRUCT_SIGSET6_FIELDS, 1 /*items*/,
					STRUCT_SIGSET6_MASK_TYPE,
					STRUCT_SIGSET6_MASK_ALIGN, regs);
		if (rval) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
	DbgSCP("addr=0x%lx length=0x%zx vec=0x%lx size=0x%lx min_length=0x%zx",
	       addr, length, vec, size, min_length);
	if (size > 0 && size < min_length) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_SIZE_TOO_LITTLE,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     size, min_length, 3/*arg_num*/);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		rval = -ENOMEM;
	} else {
		rval = sys_mincore(addr, length, vec);
	}
	DbgSCP("sys_mincore(addr=0x%lx, length=0x%zx, vec=0x%lx) returned %ld\n",
		addr, length, vec, rval);

	return rval;
}

notrace __section(".entry.text")
long protected_sys_process_madvise(const long		pidfd,		/* a1 */
				   void __user		*vec,		/* a2 */
				   const unsigned long	vlen,		/* a3 */
				   const unsigned long	behavior,	/* a4 */
				   const unsigned long	flags,		/* a5 */
				   const unsigned long unused6,		/* a6 */
				   const struct pt_regs *regs)
{
	struct iovec __user *converted_vec = NULL;
	long rval;
	int err_iov;

	if (vec) {
		if (warn_if_not_descr(2, CHECK4DESCR_SILENT, regs))
			return -EINVAL;
		/* Converting iovec structure: */
		/* Allocating space on user stack for converted_iovec: */
		converted_vec = get_user_space(vlen * sizeof(struct iovec));
		err_iov = convert_iov(vec, converted_vec, vlen);
		if (err_iov) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
					     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
					     "iovec", 2);
			PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		}
	} else {
		DbgSCP("Empty struct \'iovec\' in %s\n", __func__);
	}

	rval = sys_process_madvise(pidfd, converted_vec, vlen, behavior, flags);
	DbgSCP("%s(pidfd=%ld, ...) returned %ld\n", __func__, pidfd, rval);

	return rval;
}

/*
 * Converting protected structure siginfo_t into 64-bit format.
 * Allocates converted structure on user stack and returns it in the 2nd arg.
 * Returns error code or 0 if converted OK.
 */

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
		DbgSCP("Empty input: siginfo64=0x%lx siginfo128=0x%lx\n",
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

/* rt_sigqueueinfo/rt_tgsigqueueinfo conversion masks siginfo_t structure: */
#define MASK_SIGINFO_T_RT_PID_UID	0xc9c400088 /* field type mask */
#define MASK_SIGINFO_T_RT		0xc9c488088 /* field type mask */

static inline
unsigned long get_siginfo_mask_on_layout(int signo, int code)
/* This function implements check similar to the one in has_si_pid_and_uid() */
{
	unsigned long mask;

	switch (siginfo_layout(signo, code)) {
	case SIL_KILL:
	case SIL_CHLD:
	case SIL_RT:
		mask = MASK_SIGINFO_T_RT_PID_UID;
		break;
	default:
		mask = MASK_SIGINFO_T_RT;
		break;
	}

	return mask;
}

static inline
unsigned long get_siginfo_mask_on_siginfo(const int __user *usiginfo)
{
	int signo, code;
	long mask;

	if (get_user(signo, usiginfo) || get_user(code, usiginfo + 8)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM,
				     __func__, (unsigned long) usiginfo);
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EFAULT);
		return 0L;
	}

	mask =  get_siginfo_mask_on_layout(signo, code);
	DbgSCP("signo=%d, code=%d ==> mask = 0x%lx\n", signo, code, mask);

	return mask;
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

	DbgSCP("which=%ld, pid=%ld, infop=0x%lx, options=0x%x, ru=0x%lx\n",
	       which, pid, (unsigned long) infop, (int) options, ru);

	if (infop) {
		long size;

		size = (prot_sc_arg_not_ptr(3, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[2]);
		if (size < sizeof(siginfo_t)) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					     __func__, "'infop'",
						size, sizeof(siginfo_t));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		/* NB> The syscall only updates the 'infop' structure.
		 *     Therefore we don't need to convert input 'infop' structure.
		 */
		siginfo64 = get_user_space(sizeof(siginfo_t));
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num],
				     "iocbpp", size, nr * sizeof(e2k_ptr_t));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return -EFAULT;
	}

	iocbpp64 = get_user_space(nr * sizeof(*iocbpp64));
	ret = convert_array(iocbpp, iocbpp64, size, 1, nr, 0x3, 0x3, regs);
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

	DbgSCP("fd=%d, opcode=%d, arg=0x%lx, nr_args=0x%x\n",
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				sys_call_ID_to_name[regs->sys_num], "'arg'", size,
				(DESCRIPTOR_SIZE * nr_args));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		arg = convert_prot_iovec_struct(arg, nr_args, 3, "arg", regs);
		if (unlikely(IS_ERR(arg))) {
			return PTR_ERR(arg);
		}
		if (!arg) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
					sys_call_ID_to_name[regs->sys_num], "'arg'", size,
					(nr_args * sizeof(struct io_uring_restriction)));
			PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
			return -EINVAL;
		}
		break;
	default:
		PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_UNSUPP_VAL_IN_SC_ARG,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_PTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num], "'segments'",
					size, (size_t) size128);
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(3/*arg_num*/, regs);
		return -EADDRNOTAVAIL;
	}

	segments64 = get_user_space(size128);
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
		PROTECTED_MODE_WARNING(PMSCERRMSG_SC_NOT_AVAILABLE_IN_PM,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num]);
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

		/* Convert struct iovec from msghdr->msg_iov */
		ret = convert_iov((void __user *)data, (void __user *)iovec64, 1);
		if (ret) {
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BAD_STRUCT_IN_ARG_NAME,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARG_VAL_EXCEEDS_DSCR_SIZE,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_COUNT_EXCEEDS_DESCR_SIZE, regs->sys_num,
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
	PROTECTED_MODE_ALERT(PMSCERRMSG_FATAL_READ_FROM,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
				     regs->sys_num, sys_call_ID_to_name[regs->sys_num],
				     "sched_attr", arg_num);
		PM_EXCEPTION_ON_WARNING(SIGABRT, SI_KERNEL, EINVAL);
		return -E2BIG; /* check failed */
	}

	if (attr_size > SCHED_ATTR_SIZE_VER1) {
		if (user_prot_mem_interval_zeroed(attr, SCHED_ATTR_SIZE_VER1, attr_size))
			return 0;
		PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		print_buffer("Input waiters_128", waiters_128,
			     nr_futexes * sizeof(struct prot_futex_waitv));
	}

	w_64 = get_user_space(nr_futexes * sizeof(struct futex_waitv));
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

	if (check_pm_sc_debug_feature(PM_SC_DBG_MODE_CONV_STRUCT)) {
		print_buffer("Output waiters_64", *waiters_64,
			     nr_futexes * sizeof(struct futex_waitv));
	}

	if (err)
		*waiters_64 = NULL;
	return err;

err_not_descr:
	PROTECTED_MODE_ALERT(PMSCERRMSG_SC_NOT_DESCR_IN_STRUCT_FIELD,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "waiters", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	wsize = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);
	if (wsize < (nr_futexes * sizeof(struct prot_futex_waitv))) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
				     sys_call_ID_to_name[regs->sys_num], "waiters", wsize,
				     (size_t)(nr_futexes * sizeof(struct futex_waitv)));
		PM_BNDERR_EXCEPTION_IF_ORTH_MODE(1/*arg_num*/, regs);
		return -EINVAL;
	}

	if (prot_sc_arg_not_ptr(4, regs) && !prot_sc_arg_NULL_ptr(4, regs)) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "timeout", prot_sc_arg_tag(4, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}

	err = convert_futex_waitv_128_to_64(waiters, &waiters_64, nr_futexes, regs);
	if (err) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_BAD_STRUCT_IN_SC_ARG,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME_TAG,
				     sys_call_ID_to_name[regs->sys_num],
				     "start", prot_sc_arg_tag(1, regs));
		PM_EXCEPTION_IF_ORTH_MODE(SIGABRT, SI_KERNEL, EINVAL);
		return -EINVAL;
	}
	size = (prot_sc_arg_not_ptr(1, regs)) ? 0 : AP_OBJ_SIZE(regs->qargs[0]);
	if (size < len) {
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_NOT_DESCR_IN_SC_ARG_NAME,
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
			PROTECTED_MODE_ALERT(PMSCERRMSG_SC_ARGPTR_SIZE_TOO_LITTLE,
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
		PROTECTED_MODE_ALERT(PMSCERRMSG_SC_BRK_NON_ZERO_ARG_IN_PM,
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

#endif /* CONFIG_PROTECTED_MODE */
