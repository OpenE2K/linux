/* linux/arch/e2k/kernel/protected_syscalls.c, v 1.0 03/25/2019.
 *
 * This is implementation of system call handlers for E2K protected mode:
 *	int protected_sys_<syscallname>(const long a1, ... a6,
 *					const struct pt_regs *regs);
 *
 * Copyright (C) 2019 MCST
 */


#include <linux/syscalls.h>
#include <asm/compat.h>
#include <asm/e2k_debug.h>

#include <asm/mman.h>
#include <asm/convert_array.h>
#include <asm/prot_loader.h>
#include <asm/convert_array.h>
#include <asm/syscalls.h>
#include <asm/shmbuf.h>
#include <asm/protected_syscalls.h>

#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/net.h>
#include <linux/mman.h>
#include <linux/keyctl.h>
#include <linux/prctl.h>
#include <linux/if.h>

#include <linux/msg.h>

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

#undef DbgSCP_ERROR
#define DbgSCP_ERROR(fmt, ...) \
do { \
	if ((current->mm->context.pm_sc_debug_mode & \
		(PM_SC_DBG_MODE_CHECK | PM_SC_DBG_MODE_NO_ERR_MESSAGES)) == \
			PM_SC_DBG_MODE_CHECK) \
		pr_err(fmt, ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_ERR
#define DbgSCP_ERR(fmt, ...) \
	DbgSCP_ERROR("%s: " fmt, __func__, ##__VA_ARGS__)

#undef DbgSCP_ALERT
#define DbgSCP_ALERT(fmt, ...) \
do { \
	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_alert("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#undef DbgSCP_WARN
#define DbgSCP_WARN(fmt, ...) \
do { \
	if (current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_CHECK \
		&& !(current->mm->context.pm_sc_debug_mode \
					& PM_SC_DBG_MODE_NO_ERR_MESSAGES)) \
		pr_warn("%s: " fmt, __func__,  ##__VA_ARGS__); \
} while (0)

#undef PM_SYSCALL_WARN_ONLY
#define PM_SYSCALL_WARN_ONLY \
	(current->mm->context.pm_sc_debug_mode & PM_SC_DBG_MODE_WARN_ONLY)

#endif /* DYNAMIC_DEBUG_SYSCALLP_ENABLED */


#define get_user_space(x)	arch_compat_alloc_user_space(x)

#define ARG_TAG(i)	((tags >> (4*(i))) & 0xF)
#define ARG_TAGS(i)	((tags >> (4*(i))) & 0xFF)
#define NOT_PTR(i)	(ARG_TAGS(i) != ETAGAPQ)
#define NULL_PTR(i) ((ARG_TAG(i) == E2K_NULLPTR_ETAG) && (arg##i == 0))


static inline
int e2k_ptr_itag(long low)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;

	return AS(ptr).itag;
}

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


/*
 * Outputs size of protected descriptor specified in low/high pair:
 */
static inline
unsigned int e2k_ptr_size(long low, long hiw, unsigned int min_size)
{
	e2k_ptr_hi_t hi;
	unsigned int ptr_size;

	AW(hi) = hiw;
	ptr_size = AS(hi).size - AS(hi).curptr;

	if (ptr_size < min_size) {
		DbgSCP_ALERT("  Pointer is too small: %u < %u\n",
			     ptr_size, min_size);
		return 0;
	}
	return ptr_size;
}

static inline
int e2k_ptr_rw(long low)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;

	return AS(ptr).rw;
}

static inline
unsigned long e2k_ptr_curptr(long low, long hiw)
{
	e2k_ptr_t ptr;

	AW(ptr).lo = low;
	AW(ptr).hi = hiw;

	return AS(ptr).curptr;
}

/*
 * Counts the number of descriptors in array, which is terminated by NULL
 * (For counting of elements in argv and envp arrays)
 */
notrace __section(.entry_handlers)
static int count_descriptors(long __user *prot_array, const int prot_array_size)
{
	int i;
	long tmp[2];

	if (prot_array == NULL)
		return 0;

	/* Ensure that protected array is aligned and sized properly */
	if (!IS_ALIGNED((u64) prot_array, 16))
		return -EINVAL;

	/* Read each entry */
	for (i = 0; 8 * i + 16 <= prot_array_size; i += 2) {
		long hi, lo;
		int htag, ltag;

		if (copy_from_user_with_tags(tmp, &prot_array[i], 16))
			return -EFAULT;

		NATIVE_LOAD_VAL_AND_TAGD(tmp, lo, ltag);
		NATIVE_LOAD_VAL_AND_TAGD(&tmp[1], hi, htag);

		/* If zero is met, it is the end of array*/
		if (lo == 0 && hi == 0 && ltag == 0 && htag == 0)
			return i >> 1;
	}

	return -EINVAL;
}


/*
 * Scans environment for the given env var.
 * Reports: value of the given env var; 0 - if doesn't exist.
 */
static inline
char *pm_getenv(const char *env_var_name, const size_t max_len)
{
	/* NB> Length of the environment record expected less that 'max_len'. */
	unsigned long __user uenvp;
	size_t len, lenvar;
	unsigned long kenvp;
	unsigned long lmax = 128;
	long copied;

	if (!current->mm || !current->mm->env_start)
		return 0;
	if (current->mm->env_start >= current->mm->env_end)
		return 0;
	lenvar = strlen(env_var_name);
	kenvp = (unsigned long)kmalloc(lmax, GFP_KERNEL);
	for (uenvp = current->mm->env_start;
	     uenvp < current->mm->env_end;
	     uenvp += len) /* strnlen_user accounts terminating '\0' */ {
		len = strnlen_user((void __user *)uenvp,
					current->mm->env_end - uenvp);
		if (!len)
			break;
		else if ((len < lenvar) || (len > max_len))
			continue;
		if (lmax < len) {
			lmax = (len + 127) & 0xffffff80;
			kenvp = (unsigned long)krealloc((void *)kenvp,
							lmax, GFP_KERNEL);
		}
		copied = strncpy_from_user((void *)kenvp,
					(void __user *)uenvp, len);
		if (!copied)
			continue;
		else if (copied < 0) {
			pr_alert("%s:%d: Cannot strncpy_from_user(len = %zd)\n",
				 __func__, __LINE__, len);
			break;
		}
		if (!strncmp(env_var_name, (void *)kenvp, min(lenvar, len))) {
			if (current->mm->context.pm_sc_debug_mode
						& PM_SC_DBG_MODE_DEBUG)
				pr_info("ENVP: %s\n", (char *)kenvp);
			if (*((char *)(kenvp + lenvar)) == '=')
				return (char *)(kenvp + lenvar + 1);
			pr_alert("Wrong env var found: %s\n", (char *)kenvp);
		}
	}
	kfree((void *)kenvp);
	return 0;
}

/*
 * Checks for PM debug mode env var setup and outputs corresponding debug mask.
 * 'max_len' - maximum expected env var length.
 * Returns: mask to apply to 'pm_sc_debug_mode' if env var is "set";
 *           0 - otherwise.
 */
static
unsigned long check_debug_mask(const char *env_var_name, const size_t max_len,
				const unsigned long mask)
{
	char *env_val;

	env_val = pm_getenv(env_var_name, max_len);
	if (!env_val)
		return 0;
	if (!*env_val || env_val[1]) /* single char expected as env var value */
		goto wrong_val_out;

	if ((*env_val == '1') || (*env_val == 'y') || (*env_val == 'Y'))
		return mask;
	if ((*env_val == '0') || (*env_val == 'n') || (*env_val == 'N'))
		return ~mask;

wrong_val_out:
	pr_alert("Wrong value of the env var %s = %s\n",
			 env_var_name, env_val);
	pr_alert("Legal values: 0/1/y/n/Y/N\n");
	return 0;
}

#define CHECK_DEBUG_MASK(mask_name) \
do { \
	mask = check_debug_mask(#mask_name, 48, mask_name); \
	if (mask) { \
		if (mask & mask_name) /* positive mask */ \
			context->pm_sc_debug_mode |= mask; \
		else /* negative mask */ \
			context->pm_sc_debug_mode &= mask; \
	} \
} while (0)

/* Checks if the given env var is defined in the environment.
 * Returns: 1 - if "reset/disabled" env var found; 0 - otherwise.
 */
static inline
int pm_sc_debug_envp_check(mm_context_t *context)
{
	unsigned long mask;

	/* Checking for env vars: */
	mask = check_debug_mask("PM_SC_DBG_MODE_DISABLED", 48,
				PM_SC_DBG_MODE_INIT);
	if (mask & PM_SC_DBG_MODE_INIT) { /* positive mask */
		context->pm_sc_debug_mode = PM_SC_DBG_MODE_INIT;
		return 1;
	}

	mask = check_debug_mask("PM_SC_DBG_MODE_ALL", 48,
				PM_SC_DBG_MODE_ALL);
	if (mask & PM_SC_DBG_MODE_ALL) { /* positive mask */
		context->pm_sc_debug_mode |= PM_SC_DBG_MODE_ALL;
		pr_info("ENVP: PM_SC_DBG_MODE_ALL=1\n");
		return 0;
	}

	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_DEBUG);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_COMPLEX_WRAPPERS);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_CHECK);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_WARN_ONLY);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_CONV_STRUCT);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_SIGNALS);
	CHECK_DEBUG_MASK(PM_SC_DBG_MODE_NO_ERR_MESSAGES);
	/* libc mmu control stuff: */
	CHECK_DEBUG_MASK(PM_MM_CHECK_4_DANGLING_POINTERS);
	CHECK_DEBUG_MASK(PM_MM_EMPTYING_FREED_POINTERS);
	CHECK_DEBUG_MASK(PM_MM_ZEROING_FREED_POINTERS);

	context->pm_sc_debug_mode |= PM_SC_DBG_MODE_INIT;

	if (IF_PM_DBG_MODE(PM_SC_DBG_MODE_DEBUG))
		pr_info("\tpm_sc_debug_mode = 0x%lx\n",
					context->pm_sc_debug_mode);

	return 0;
}

int arch_init_pm_sc_debug_mode(const int debug_mask)
{
	mm_context_t *context = &current->mm->context;

	if (context->pm_sc_debug_mode & PM_SC_DBG_MODE_INIT)
		return context->pm_sc_debug_mode & debug_mask;

	/* Checking for env vars: */
	if (pm_sc_debug_envp_check(context))
		return 0;

	return context->pm_sc_debug_mode & debug_mask;
}



notrace __section(.entry_handlers)
long protected_sys_sigaltstack(const unsigned long __user a1,  /* ss */
				const unsigned long __user a2, /* oss */
				const unsigned long	a3, /* not used */
				const unsigned long	a4, /* not used */
				const unsigned long	a5, /* not used */
				const unsigned long	a6, /* not used */
				const struct pt_regs	*regs)
{
#define SIGALTSTACK_MASK_TYPE     0x13
#define SIGALTSTACK_MASK_ALIGN    0x17
#define SIGALTSTACK_STRING1 "Bad 1-st stack descriptor for sigaltstack\n"
#define SIGALTSTACK_STRING2 "Bad 2-st stack descriptor for sigaltstack\n"
	void *ss = NULL;
	void *old_ss = NULL;
	unsigned int size = 0, size2 = 0;
	long rval = -EINVAL; /* syscall return value */

	if (!a1 && !a2)
		return -EINVAL;

	if (a1) {
		size = e2k_ptr_size(regs->args[1], regs->args[2],
				    sizeof(stack_t));
		if (!size)
			return -EINVAL;
	}

	if (a2) {
		size2 = e2k_ptr_size(regs->args[3], regs->args[4],
				     sizeof(stack_t));
		if (!size2)
			return -EINVAL;
	}

	ss = get_user_space(size + size2);

	if (a1) {
		/* Struct ss contains pointer in the first field */
		rval = convert_array((long *) a1, ss, size, 3, 1,
			SIGALTSTACK_MASK_TYPE, SIGALTSTACK_MASK_ALIGN);
		if (rval) {
			DbgSCP_ALERT(SIGALTSTACK_STRING1);
			return rval;
		}
	}

	if (a2) {
		old_ss = ss + size;
		/* Struct old_ss contains pointer in the first field */
		rval = convert_array((long *) a2, old_ss, size2, 3, 1,
			SIGALTSTACK_MASK_TYPE, SIGALTSTACK_MASK_ALIGN);
		if (rval) {
			DbgSCP_ALERT(SIGALTSTACK_STRING2);
			return rval;
		}
	}

	rval = sys_sigaltstack((stack_t *) ss,
			       (stack_t *) old_ss);

	return rval;
}


notrace __section(.entry_handlers)
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
	unsigned int	descr_size;
	unsigned long	size_to_clean = size;

	DbgSCP("addr = 0x%p, size = %ld  ", addr, size);

	descr_size = e2k_ptr_size(regs->args[1], regs->args[2], 0);
	if (!(flags & CLEAN_DESCRIPTORS_SINGLE))
		size_to_clean *= sizeof(e2k_ptr_t);
	if (descr_size < size_to_clean) {
		DbgSCP_ERROR("clean_descriptors(ptr=0x%lx:0x%lx, size=%ld): 'size' exceeds length of 'ptr'",
				regs->args[1], regs->args[2], size);
		return -EFAULT;
	}

	if (flags & (CLEAN_DESCRIPTORS_SINGLE | CLEAN_DESCRIPTORS_NO_GARB_COLL) ==
		(CLEAN_DESCRIPTORS_SINGLE | CLEAN_DESCRIPTORS_NO_GARB_COLL)) {
		rval = mem_set_empty_tagged_dw(addr, size, 0x0baddead0baddead);
	} else if (!flags) {
		rval = clean_descriptors(addr, size);
	} else {
		DbgSCP_ERR("wrong flags value 0x%lx", flags);
		return -EINVAL;
	}
	if (rval == -EFAULT)
			send_sig_info(SIGSEGV, SEND_SIG_PRIV, current);
	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_clone(const unsigned long	a1,	/* flags */
			 const unsigned long	a2,	/* new_stackptr */
			 const unsigned long __user a3,/* parent_tidptr */
			 const unsigned long __user a4,/*  child_tidptr */
			 const unsigned long __user a5,/* tls */
			 const unsigned long	a6,	/* unused */
			 struct pt_regs	*regs)
{
	long rval; /* syscall return value */
	unsigned int size;
	struct kernel_clone_args args;

	DbgSCP("(fl=0x%lx, newsp=0x%lx, p/ch_tidptr=0x%lx/0x%lx, tls=0x%lx)\n",
		a1, a2, a3, a4, a5);
	/*
	 * User may choose to not pass additional arguments
	 * (tls, tid) at all for historical and compatibility
	 * reasons, so we do not fail if (a3), (a4), and (a5)
	 * pointers are bad.
	 *
	 * The fifth argument (tls) requires special handling:
	 */
	if (a1 & CLONE_SETTLS) {
		unsigned int tls_size;

		/* TLS argument passed thru arg9,10: */
		tls_size = (a5 == 0) ? 0 : e2k_ptr_size(regs->args[9],
							regs->args[10],
							sizeof(int));
		/* Check that the pointer is good. */
		if (!tls_size) {
			long tags = regs->tags >> 4;

			DbgSCP_ALERT(" Bad TLS pointer: size=%d, tags=%lx\n",
				     tls_size, ARG_TAGS(9));
			return -EINVAL;
		}
	}

	/*
	 * Multithreading support - change all SAP to AP in globals
	 * to guarantee correct access to memory
	 */
	if (a1 & CLONE_VM)
		mark_all_global_sp(regs, current->pid);

	size = e2k_ptr_curptr(regs->args[3], regs->args[4]);

	args.flags	 = (a1 & ~CSIGNAL);
	args.pidfd	 = (int *)a3;
	args.child_tid	 = (int *)a4;
	args.parent_tid	 = (int *)a3;
	args.exit_signal = (a1 & CSIGNAL);
	args.stack	 = a2 - size;
	args.stack_size	 = size;
	args.tls	 = a5;

	/* passing size of array */
	rval = _do_fork(&args);
	DbgSCP("rval = %ld, sys_num = %d size=%d\n", rval, regs->sys_num, size);

	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_execve(const unsigned long __user a1,/* filename*/
			  const unsigned long __user a2,/* argv[] */
			  const unsigned long __user a3,/* envp[] */
			  const unsigned long	a4,	/* not used */
			  const unsigned long	a5,	/* not used */
			  const unsigned long	a6,	/* not used*/
			  const struct pt_regs	*regs)
{
	char __user *filename = (char *) a1;
	unsigned long *buf;
	unsigned long *argv, *envp;
	unsigned long __user *u_argv = (unsigned long *) a2;
	unsigned long __user *u_envp = (unsigned long *) a3;
	unsigned int size = 0, size2 = 0;
	int argc = 0, envc = 0;
	long rval; /* syscall return value */

	/* Path to executable */
	if (!filename)
		return -EINVAL;

	/* argv */
	if (u_argv) {
		size = e2k_ptr_size(regs->args[3], regs->args[4], 0);
		if (!size)
			return -EINVAL;
	}

	/* envp */
	if (u_envp) {
		size2 = e2k_ptr_size(regs->args[5], regs->args[6], 0);
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
	argc = count_descriptors((long *) u_argv, size);
	if (argc < 0)
		return -EINVAL;

	/* Count real number of entries in envc */
	if (size2) {
		envc = count_descriptors((long *) u_envp, size2);
		if (envc < 0)
			return -EINVAL;
	}

	/*
	 * Allocate space on user stack for converting of
	 * descriptors in argv and envp to ints
	 */
	buf = get_user_space((argc + envc + 2) << 3);
	argv = buf;
	envp = &buf[argc + 1];

	/*
	 * Convert descriptors in argv to ints.
	 * For statically-linked executables missing argv is allowed,
	 * therefore kernel doesn't return error in this case.
	 * For dynamically-linked executables missing argv is not
	 * allowed, because at least argv[0] is required by ldso for
	 * loading of executable. Protected ldso must check argv.
	 */
	if (argc) {
		rval = convert_array((long *) u_argv, argv,
				argc << 4, 1, argc, 0x3, 0x3);
		if (rval) {
			DbgSCP_ALERT("Bad argv in protected execve syscall\n");
			return rval;
		}
	}
	/* The array argv must be terminated by zero */
	argv[argc] = 0;

	/*
	 * Convert descriptors in envp to ints
	 * envc can be zero without problems
	 */
	if (envc) {
		rval = convert_array(u_envp, envp,
				envc << 4, 1, envc, 0x3, 0x3);
		if (rval) {
			DbgSCP_ALERT("Bad envp in protected execve syscall\n");
			return rval;
		}
	}
	/* The array envp must be terminated by zero */
	envp[envc] = 0;

	rval = e2k_sys_execve(filename, (char **) argv,
			      (char **) envp);

	DbgSCP(" rval = %ld filename=%s argv=%p envp=%p\n",
	       rval, filename, argv, envp);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_execveat(const unsigned long dirfd,		/*a1 */
			    const unsigned long __user pathname,/* a2 */
			    const unsigned long __user argv,	/* a3 */
			    const unsigned long __user envp,	/* a4 */
			    const unsigned long	flags,		/* a5 */
			    const unsigned long	unused6,
			    const struct pt_regs	*regs)
{
	char __user *filename = (char *) pathname;
	unsigned long *buf;
	unsigned long *kargv, *kenvp;
	unsigned long __user *u_argv = (unsigned long *) argv;
	unsigned long __user *u_envp = (unsigned long *) envp;
	unsigned int size = 0, size2 = 0;
	int argc = 0, envc = 0;
	long rval; /* syscall return value */

	DbgSCP(" dirfd=%ld path=%s argv=0x%lx envp=0x%lx flags=0x%lx\n",
	       dirfd, (char *)pathname, argv, envp, flags);

	/* Path to executable */
	if (!filename)
		return -EINVAL;

	/* argv */
	if (u_argv) {
		size = e2k_ptr_size(regs->args[5], regs->args[6], 0);
		if (!size)
			return -EINVAL;

		/* Count real number of entries in argv */
		argc = count_descriptors((long *) u_argv, size);
		if (argc < 0)
			return -EINVAL;
	}

	/* envp */
	if (u_envp) {
		size2 = e2k_ptr_size(regs->args[7], regs->args[8], 0);
		if (!size2)
			return -EINVAL;

		/* Count real number of entries in envc */
		envc = count_descriptors((long *) u_envp, size2);
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
		rval = convert_array(u_argv, kargv,
				argc << 4, 1, argc, 0x3, 0x3);
		if (rval) {
			DbgSCP_ALERT("Bad argv in protected execveat\n");
			return rval;
		}
	}
	/* The array argv must be terminated by zero */
	kargv[argc] = 0;

	/*
	 * Convert descriptors in envp to ints
	 * envc can be zero without problems
	 */
	if (envc) {
		rval = convert_array(u_envp, kenvp,
				envc << 4, 1, envc, 0x3, 0x3);
		if (rval) {
			DbgSCP_ALERT("Bad envp in protected execveat\n");
			return rval;
		}
	}
	/* The array envp must be terminated by zero */
	kenvp[envc] = 0;

	rval = e2k_sys_execveat(dirfd, filename, (char **) kargv,
						(char **) kenvp, flags);

	DbgSCP(" rval = %ld filename=%s argv=%p envp=%p\n",
	       rval, filename, kargv, kenvp);
	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_futex(const unsigned long __user a1,	/* uaddr */
			 const unsigned long	a2,	/* futex_op */
			 const unsigned long	a3,	/* val */
			 const unsigned long	la4,	/* timeout/val2 */
			 const unsigned long __user la5, /* uaddr2 */
			 const unsigned long	a6,	/* val3 */
			 const struct pt_regs	*regs)
{
#define ERROR_MESSAGE_FUTEX " NULL pointer is not allowed (sys_num %ld).\n"
	int cmd;
	unsigned long a4 = la4;
	unsigned long __user a5 = la5;
	long tags;
	long sys_num;
	long rval = 0; /* syscall return value */

	cmd = a2 & FUTEX_CMD_MASK;
	if (la4 && (cmd == FUTEX_WAIT ||
		cmd == FUTEX_WAIT_BITSET ||
		cmd == FUTEX_LOCK_PI ||
		cmd == FUTEX_WAIT_REQUEUE_PI)) {
		/*
		 * These commands assume la4 must be a pointer. Let's check it:
		 */
		unsigned long arg7 = regs->args[7];

		tags = regs->tags >> 4;
		sys_num = regs->sys_num;
		if (NOT_PTR(7) && !NULL_PTR(7)) {
			DbgSCP_ALERT("7 8" ERROR_MESSAGE_FUTEX, sys_num);
			rval = -EINVAL;
		}
	}
	if (la5 && (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE ||
	    cmd == FUTEX_CMP_REQUEUE_PI || cmd == FUTEX_WAKE_OP ||
	    cmd == FUTEX_WAIT_REQUEUE_PI)) {
		/*
		 * These commands assume la5 must be a pointer. Let's check it:
		 */
		unsigned long arg9 = regs->args[9];

		tags = regs->tags >> 4;
		sys_num = regs->sys_num;
		if (NOT_PTR(9) && !NULL_PTR(9)) {
			DbgSCP_ALERT("9 10" ERROR_MESSAGE_FUTEX, sys_num);
			rval = -EINVAL;
		}
	}
	rval = sys_futex((u32 *) a1, a2, a3, (struct __kernel_timespec *) a4,
			 (u32 *) a5, a6);
	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_getgroups(const unsigned long       a1, /* size */
			    const unsigned long __user a2, /* list[] */
			    const unsigned long unused3,
			    const unsigned long unused4,
			    const unsigned long unused5,
			    const unsigned long unused6,
			    const struct pt_regs      *regs)
{
	long rval; /* syscall return value */
	unsigned int bufsize;

	DbgSCP(" (size=%lu, list[]=0x%lx) ", a1, a2);

	/*
	 * Here we check that list size is enough to receive 'size' gid's:
	 */
	bufsize = e2k_ptr_size(regs->args[3], regs->args[4], 0);
	if (bufsize < (a1 * sizeof(gid_t))) {
		DbgSCP_ALERT(
			"Insufficient list size in getgroups: %d < %zu\n",
				bufsize, (size_t)(a1 * sizeof(gid_t)));
		return -EINVAL;
	}

	rval = sys_getgroups(a1, (gid_t *) a2);
	DbgSCP("rval = %ld\n", rval);
	return rval;
}


/*
 * This function converts protected structure 'iov' into regular one
 * alone with the check for validity of iov/iovcnt arguments to system calls,
 *                 taking iovec structure at input (like readv/writev and so).
 * iovcnt - number of buffers from the file assiciated to read/write.
 * It returns converted structure pointer if OK; NULL pointer otherwise.
 */
static inline
long *convert_prot_iovec_struct(const unsigned long __user iov,
				const unsigned long        iovcnt,
				const struct pt_regs       *regs)
{
	const int nr_segs = iovcnt;
	long *new_arg = NULL;
	unsigned int size;
	long rval; /* syscall return value */

	if (((unsigned int) nr_segs) > UIO_MAXIOV) {
		DbgSCP_ALERT("Bad iov count number (%d) in iov structure\n",
			     nr_segs);
		return NULL;
	}

	/*
	 * One could use 0 in place `32 * nr_segs' here as the size
	 * will be checked below in `convert_array ()'.
	 */
	size = e2k_ptr_size(regs->args[3], regs->args[4], 0);
	if (size < (32 * nr_segs)) {
		DbgSCP_ALERT("Bad iov structure size: %u < %d\n",
			     size, 32 * nr_segs);
		return NULL;
	}

	new_arg = get_user_space(nr_segs * 2 * 8);
	rval = convert_array((long *) iov, new_arg, size,
					2, nr_segs, 0x7, 0xf);
	if (rval) {
		DbgSCP_ALERT("Bad iov structure in protected sysctl\n");
		return NULL;
	}
	return new_arg;
}


notrace __section(.entry_handlers)
long protected_sys_readv(const unsigned long        a1, /* fd */
			 const unsigned long __user a2, /* iov */
			 const unsigned long        a3, /* iovcnt */
			 const unsigned long	a4,	/* unused */
			 const unsigned long	a5,	/* unused */
			 const unsigned long	a6,	/* unused */
			 const struct pt_regs	*regs)
{
	/*
	 * sys_readv(unsigned long fd, const struct iovec __user *vec,
	 *		unsigned long nr_segs)
	 * struct iovec {
	 *	 void __user *iov_base;
	 *	 __kernel_size_t iov_len;
	 * };
	 */
	const int nr_segs = (int) a3;
	long *new_arg;
	long rval; /* syscall return value */

	if (!nr_segs)
		return 0;

	new_arg = convert_prot_iovec_struct(a2, a3, regs);
	if (!new_arg)
		return -EINVAL;

	rval = sys_readv(a1, (const struct iovec *) new_arg, nr_segs);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_preadv(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long        a4, /* offset_l */
			  const unsigned long        a5, /* offset_h */
			  const unsigned long	a6,	/* unused */
			  const struct pt_regs	*regs)
{
	const int nr_segs = (int) a3;
	long *new_arg;
	long rval; /* syscall return value */

	new_arg = convert_prot_iovec_struct(a2, a3, regs);
	if (!new_arg)
		return -EINVAL;

	rval = sys_preadv(a1, (const struct iovec *) new_arg, nr_segs, a4, a5);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_writev(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long	a4,	/* unused */
			  const unsigned long	a5,	/* unused */
			  const unsigned long	a6,	/* unused */
			  const struct pt_regs	*regs)
{
	const int nr_segs = (int) a3;
	long *new_arg;
	long rval; /* syscall return value */

	if (!nr_segs)
		return 0;

	new_arg = convert_prot_iovec_struct(a2, a3, regs);
	if (!new_arg)
		return -EINVAL;

	rval = sys_writev(a1, (const struct iovec *) new_arg, nr_segs);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_pwritev(const unsigned long        a1, /* fd */
			   const unsigned long __user a2, /* iov */
			   const unsigned long        a3, /* iovcnt */
			   const unsigned long        a4, /* offset_l */
			   const unsigned long        a5, /* offset_h */
			   const unsigned long	a6,	/* unused */
			   const struct pt_regs	*regs)
{
	const int nr_segs = (int) a3;
	long *new_arg;
	long rval; /* syscall return value */

	new_arg = convert_prot_iovec_struct(a2, a3, regs);
	if (!new_arg)
		return -EINVAL;

	rval = sys_pwritev(a1, (const struct iovec *) new_arg, nr_segs, a4, a5);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_preadv2(const unsigned long        a1, /* fd */
			  const unsigned long __user a2, /* iov */
			  const unsigned long        a3, /* iovcnt */
			  const unsigned long        a4, /* offset_l */
			  const unsigned long        a5, /* offset_h*/
			  const unsigned long        a6, /* flags */
			  const struct pt_regs	*regs)
{
	const int nr_segs = (int) a3;
	long *new_arg;
	long rval; /* syscall return value */

	new_arg = convert_prot_iovec_struct(a2, a3, regs);
	if (!new_arg)
		return -EINVAL;

	rval = sys_preadv2(a1, (const struct iovec *) new_arg, nr_segs,
			   a4, a5, a6);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_pwritev2(const unsigned long        a1, /* fd */
			   const unsigned long __user a2, /* iov */
			   const unsigned long        a3, /* iovcnt */
			   const unsigned long        a4, /* offset_l */
			   const unsigned long        a5, /* offset_h*/
			   const unsigned long        a6, /* flags */
			   const struct pt_regs	*regs)
{
	const int nr_segs = (int) a3;
	long *new_arg;
	long rval; /* syscall return value */

	new_arg = convert_prot_iovec_struct(a2, a3, regs);
	if (!new_arg)
		return -EINVAL;

	rval = sys_pwritev2(a1, (const struct iovec *) new_arg, nr_segs,
			    a4, a5, a6);

	DbgSCP(" rval = %ld new_arg=%px\n", rval, new_arg);
	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_sysctl(const unsigned long __user arg1)
{
#define	SYSCTL_ARGS_STRUCT_SIZE 88; /* size of the protected structure used */
	long __user *ptr = (long *)arg1;
	int rval = 0; /* syscall return value */
	struct __sysctl_args *new_arg;
	size_t size = SYSCTL_ARGS_STRUCT_SIZE;

	if (!ptr)
		return -EINVAL;

	new_arg = get_user_space(sizeof(struct __sysctl_args));
	if ((rval = convert_array((long *) ptr, (long *)new_arg, size,
				  6, 1, 0x7f3, 0x7ff))) {
		DbgSCP("convert_array returned %d\n", rval);
		DbgSCP_ALERT("Bad struct args in protected sysctl syscall\n");
		return -EINVAL;
	}

	rval = sys_sysctl(new_arg);
	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_olduselib(const unsigned long __user a1, /* library */
			const unsigned long __user a2) /* umdd */
{
	char *str = (char *)a1;
	umdd_old_t *umdd = (umdd_old_t *) a2;
	kmdd_t kmdd;
	int rval; /* syscall return value */

	if (IS_CPU_ISET_V6())
		return -ENOSYS;

	if (!a1 || !a2)
		return -EINVAL;

	if (current->thread.flags & E2K_FLAG_3P_ELF32)
		rval = sys_load_cu_elf32_3P(str, &kmdd);
	else
		rval = sys_load_cu_elf64_3P(str, &kmdd);

	if (rval) {
		DbgSCP_ERR("failed, could not load\n");
		return rval;
	}

	rval |= PUT_USER_AP(&umdd->mdd_got, kmdd.got_addr,
			    kmdd.got_len, 0, RW_ENABLE);
	if (kmdd.init_got_point)
		rval |= PUT_USER_PL_V2(&umdd->mdd_init_got,
					kmdd.init_got_point);
	else
		rval |= put_user(0L, &umdd->mdd_init_got.word);

	if (kmdd.entry_point)
		rval |= PUT_USER_PL_V2(&umdd->mdd_start,
					kmdd.entry_point);
	else
		rval |= put_user(0L, &umdd->mdd_start.word);

	if (kmdd.init_point)
		rval |= PUT_USER_PL_V2(&umdd->mdd_init,
					kmdd.init_point);
	else
		rval |= put_user(0L, &umdd->mdd_init.word);

	if (kmdd.fini_point)
		rval |= PUT_USER_PL_V2(&umdd->mdd_fini,
					kmdd.fini_point);
	else
		rval |= put_user(0L, &umdd->mdd_fini.word);

	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_uselib(const unsigned long __user a1, /* library */
			const unsigned long __user a2) /* umdd */
{
	char *str = (char *)a1;
	umdd_t *umdd = (umdd_t *) a2;
	kmdd_t kmdd;
	int rval; /* syscall return value */

	if (!a1 || !a2)
		return -EINVAL;

	if (current->thread.flags & E2K_FLAG_3P_ELF32)
		rval = sys_load_cu_elf32_3P(str, &kmdd);
	else
		rval = sys_load_cu_elf64_3P(str, &kmdd);

	if (rval) {
		DbgSCP("could not load '%s' err #%d\n", str, rval);
		return rval;
	}
	BUG_ON(kmdd.cui == 0);

	rval |= PUT_USER_AP(&umdd->mdd_got, kmdd.got_addr,
			    kmdd.got_len, 0, RW_ENABLE);

	if (kmdd.init_got_point) {
		rval |= PUT_USER_PL(&umdd->mdd_init_got,
					kmdd.init_got_point,
					kmdd.cui);
	} else {
		rval |= put_user(0L, &umdd->mdd_init_got.PLLO_value);
		rval |= put_user(0L, &umdd->mdd_init_got.PLHI_value);
	}

	return rval;
}

long protected_sys_mremap(const unsigned long	__user old_address,
			const unsigned long	old_size,
			const unsigned long	new_size,
			const unsigned long	flags,
			const unsigned long	__user new_address,
			const unsigned long	a6,	/* unused */
			struct pt_regs		*regs)
{
	long rval = -EINVAL;
	unsigned int ptr_size;
	e2k_addr_t base;
	e2k_ptr_t old_descriptor;

	if (old_address & ~PAGE_MASK)
		goto nr_mremap_err;

	AW(old_descriptor).lo = regs->args[1];
	AW(old_descriptor).hi = regs->args[2];
	ptr_size = e2k_ptr_size(regs->args[1], regs->args[2], 0);
	if (ptr_size < old_size) {
		/* Reject, if user tries to remap more than allocated. */
		DbgSCP_ALERT("mremap cannot remap more than available\n");
		DbgSCP_ALERT("old_size (%lu) > descriptor size (%u)\n",
			     old_size, ptr_size);
		rval = -EFAULT;
		goto nr_mremap_err;
	}
	if (flags & MREMAP_FIXED) {
		DbgSCP_ALERT("MREMAP_FIXED flag is not supported in PM\n");
		goto nr_mremap_err;
	}
	if (e2k_ptr_itag(regs->args[1]) != AP_ITAG) {
		DbgSCP_ALERT("mremap cannot remap descriptor in stack\n");
		goto nr_mremap_err;
	}
	base = sys_mremap(old_address, old_size, new_size, flags,
				/*
				 * MREMAP_FIXED is not supported in PM,
				 * therefore pass an invalid value for
				 * new_address.
				 */
				0);
	if (base & ~PAGE_MASK) { /* this is error code */
		rval = base;
		goto nr_mremap_err;
	} else {
		regs->rval1 = make_ap_lo(base, new_size, 0,
					 e2k_ptr_rw(regs->args[1]));
		regs->rval2 = make_ap_hi(base, new_size, 0,
					 e2k_ptr_rw(regs->args[1]));
		regs->rv1_tag = E2K_AP_LO_ETAG;
		regs->rv2_tag = E2K_AP_HI_ETAG;
		regs->return_desk = 1;
		rval = 0;
	}
	if (old_address != base || old_size > new_size)
		clean_single_descriptor(old_descriptor);

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
notrace __section(.entry_handlers)
static void get_socketcall_mask(long call, long *mask_type, long *mask_align,
				int *fields)
{
	switch (call) {
	case SYS_SOCKET:
		*mask_type = 0x15;
		*mask_align = 0x15;
		*fields = 3;
		/* err = sys_socket(a[0], a[1], a[2]); */
		break;
	case SYS_BIND:
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
		/* err = sys_bind(a[0],				*/
		/*	(struct sockaddr __user *) a[1], a[2]); */
		break;
	case SYS_CONNECT:
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
		/* err = sys_connect(a[0],			*/
		/*	(struct sockaddr __user *) a[1], a[2]); */
		break;
	case SYS_LISTEN:
		*mask_type = 0x5;
		*mask_align = 0x5;
		*fields = 2;
		/* err = sys_listen(a[0], a[1]); */
		break;
	case SYS_ACCEPT:
		*mask_type = 0x3d;
		*mask_align = 0x3f;
		*fields = 3;
		/* err = sys_accept(a[0],				*/
		/*		(struct sockaddr __user *) a[1],	*/
		/*		(int __user*) a[2]);			*/
		break;
	case SYS_GETSOCKNAME:
		*mask_type = 0x3d;
		*mask_align = 0x3f;
		*fields = 3;
		/* err = sys_getsockname(a[0],			*/
		/*	(struct sockaddr __user*) a[1],		*/
		/*	(int __user *) a[2]);			*/
		break;
	case SYS_GETPEERNAME:
		*mask_type = 0x3d;
		*mask_align = 0x3f;
		*fields = 3;
		/* err = sys_getpeername(a[0],				*/
		/*		(struct sockaddr __user *) a[1],	*/
		/*		(int __user *)a[2]);			*/
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
	case SYS_SHUTDOWN:
		*mask_type = 0x5;
		*mask_align = 0x5;
		*fields = 2;
		/* err = sys_shutdown(a[0], a[1]); */
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
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
		/* err = sys_sendmsg(a[0],				*/
		/*		(struct msghdr __user *) a[1], a[2]);	*/
		break;
	case SYS_RECVMSG:
		*mask_type = 0x1d;
		*mask_align = 0x1f;
		*fields = 3;
		/* err = sys_recvmsg(a[0],			*/
		/*	(struct msghdr __user *) a[1], a[2]);	*/
		break;
	default:
		DbgSCP("Empty masks used for socketcall #%ld\n", call);
		*mask_type = 0x0;
		*mask_align = 0x0;
		*fields = 0;
		break;
	}
}

notrace __section(.entry_handlers)
long protected_sys_socketcall(const unsigned long        a1, /* call */
			      const unsigned long __user a2, /* args */
			      const unsigned long unused3,
			      const unsigned long unused4,
			      const unsigned long unused5,
			      const unsigned long unused6,
			      const struct pt_regs	*regs)
{
	long __user *args;
	unsigned int size;
	long mask_type, mask_align;
	int fields;
	long rval; /* syscall return value */
	long __user *prot_msghdr;
	struct user_msghdr __user *converted_msghdr;

	get_socketcall_mask(a1, &mask_type, &mask_align, &fields);

	if (fields == 0) {
		DbgSCP_ALERT("Bad socketcall number %ld\n", a1);
		return -EINVAL;
	}

	if (!a2) {
		DbgSCP_ALERT("NULL pointer passed to socketcall (%d)\n",
			     (int)a1);
		return -EFAULT;
	}
	size = e2k_ptr_size(regs->args[3], regs->args[4], 1 /*min_size*/);
	/* NB> `convert_array' below will check if size is large
	 *                               enough for this request.
	 *
	 * Need an additional conversions of arguments
	 * for syscalls recvmsg/sendmsg
	 */
	if ((a1 == SYS_SENDMSG) || (a1 == SYS_RECVMSG)) {
#define MASK_MSGHDR_TYPE     0x773  /* type mask for struct msghdr */
#define MASK_MSGHDR_ALIGN    0x17ff /* alignment mask for msghdr structure */
#define MASK_MSGHDR_RW       0x2000 /* WRITE-only msg_flags field */
#define SIZE_MSGHDR          96     /* size of struct msghdr in user space */
#define MASK_IOVEC_TYPE      0x7    /* mask for converting of struct iovec */
#define MASK_IOVEC_ALIGN     0xf    /* alignment mask for struct iovec */
#define SIZE_IOVEC           32     /* size of struct iovec in user space */
		/*
		 * Structures user_msghdr and iovec contain pointers
		 * inside, therefore they need to be additionally
		 * converted with saving results in these structures
		 */
		struct iovec __user *converted_iovec;
		int err_mh, err_iov;

		/*
		 * Allocate space on user stack for additional
		 * structures for saving of converted parameters
		 */
		args = get_user_space((fields * 8) +
			sizeof(struct user_msghdr) +
			sizeof(struct iovec));
		/* Convert args array for socketcall from ptr */
		rval = convert_array_3((long *) a2, args, size, fields, 1,
					mask_type, mask_align, 0,
					CONV_ARR_WRONG_DSCR_FLD);

		if (rval)
			goto err_out_bad_array;

		/* Convert struct msghdr from args[1] */
		prot_msghdr = (long *) args[1];
		converted_msghdr = (struct user_msghdr *) (args + (fields));
		if (prot_msghdr) {
			args[1] = (long) converted_msghdr;
			err_mh = convert_array_3(prot_msghdr,
					(long *) converted_msghdr,
					SIZE_MSGHDR, 7, 1, MASK_MSGHDR_TYPE,
					MASK_MSGHDR_ALIGN, MASK_MSGHDR_RW,
					CONV_ARR_WRONG_DSCR_FLD);
			if (err_mh)
				DbgSCP_ALERT("Bad user_msghdr in args[1]\n");
		} else {
			args[1] = 0;
			DbgSCP_ALERT("Empty user_msghdr in args[1]\n");
			goto run_syscall;
		}

		if (converted_msghdr->msg_iov) {
			/* Convert struct iovec from msghdr->msg_iov */
			converted_iovec = (struct iovec *)
						((char *)converted_msghdr +
						sizeof(struct user_msghdr));
			err_iov = convert_array_3(
					(long *) converted_msghdr->msg_iov,
					(long *) converted_iovec,
					SIZE_IOVEC, 2, 1, MASK_IOVEC_TYPE,
					MASK_IOVEC_ALIGN, 0,
					CONV_ARR_WRONG_DSCR_FLD);
			if (err_iov)
				DbgSCP_ALERT("Bad struct iovec in msghdr\n");
		} else {
			DbgSCP_ALERT("Empty struct iovec in msghdr\n");
			converted_iovec = NULL;
		}

		/* Assign args[1] to pointers to converted structures */
		converted_msghdr->msg_iov = converted_iovec;

	/* Other socketcalls */
	} else {
		if (fields) {
			/* Allocate space on user stack for args array */
			args = get_user_space(fields * 8);
			/* Convert args array for socketcall from ptr */
			rval = convert_array((long *) a2, args, size,
					fields, 1, mask_type,
					mask_align);
			if (rval)
				goto err_out_bad_array;
		} else {
			DbgSCP_ERR("Using args as is; convert_array not called.\n");
			args = get_user_space(size);
			if (copy_from_user(args, (void *) a2, size))
				return -EFAULT;
		}
	}

	/*
	 * Call socketcall handler function with passing of
	 * arguments to it
	 */
run_syscall:
	rval = sys_socketcall((int) a1, (unsigned long *) args);

	if (!rval && (a1 == SYS_RECVMSG)) {
#define PROT_MSG_FLAGS_FIELD_OFFSET 11
		/* Updating the msg_flags field @ user space: */
		DbgSCP("Socket call RECVMSG returned msg_flags: 0x%x\n",
		       converted_msghdr->msg_flags);
		rval = copy_to_user(prot_msghdr + PROT_MSG_FLAGS_FIELD_OFFSET,
					&converted_msghdr->msg_flags,
					sizeof(converted_msghdr->msg_flags));
		if (rval) {
			DbgSCP_ERR("Socket call RECVMSG: faled to return msg_flags\n");
			rval = -EFAULT;
		}
	}

	DbgSCP(" (%d) returned %ld\n", (int) a1, rval);
	return rval;

err_out_bad_array:
	DbgSCP_ALERT("Bad array for (%ld): size=%d\n", a1, size);
	return rval;
}

notrace __section(.entry_handlers)
static long __user *convert_msghdr(long __user *prot_msghdr,
				   unsigned int size,
				   const char *syscall_name)
/* Converts user msghdr structure from protected to regular structure format.
 * Outputs converted structure (allocated in user space).
 * 'prot_msghdr' - protected message header structure.
 * 'size' - size of the input structure.
 */
{
	long __user *args;
	struct user_msghdr __user *converted_msghdr = NULL;
	struct iovec __user *converted_iovec;
	int err_mh, err_iov;

#define MASK_MSGHDR_TYPE     0x773  /* type mask for struct msghdr */
#define MASK_MSGHDR_ALIGN    0x17ff /* alignment mask for msghdr structure */
#define MASK_MSGHDR_RW       0x2000 /* WRITE-only msg_flags field */
#define SIZE_MSGHDR          96     /* size of struct msghdr in user space */
#define MASK_IOVEC_TYPE      0x7    /* mask for converting of struct iovec */
#define MASK_IOVEC_ALIGN     0xf    /* alignment mask for struct iovec */
#define SIZE_IOVEC           32     /* size of struct iovec in user space */
	/*
	 * Structures user_msghdr and iovec contain pointers
	 * inside, therefore they need to be additionally
	 * converted with saving results in these structures
	 */

	 /* Allocating space on user stack for converted structures: */
	args = get_user_space(sizeof(struct user_msghdr) +
				sizeof(struct iovec));

	/* Convert struct msghdr: */
	converted_msghdr = (struct user_msghdr *) args;
	err_mh = convert_array_3(prot_msghdr, (long *) converted_msghdr,
				SIZE_MSGHDR, 7, 1, MASK_MSGHDR_TYPE,
				MASK_MSGHDR_ALIGN, MASK_MSGHDR_RW,
				CONV_ARR_WRONG_DSCR_FLD);
	if (err_mh)
		DbgSCP_ALERT("Bad user_msghdr in syscall \'%s\'\n",
			     syscall_name);

	if (converted_msghdr->msg_iov) {
		/* Convert struct iovec from msghdr->msg_iov */
		converted_iovec = (struct iovec *)
					((char *)converted_msghdr +
					sizeof(struct user_msghdr));
		err_iov = convert_array_3((long *) converted_msghdr->msg_iov,
					  (long *) converted_iovec,
					  SIZE_IOVEC, 2, 1, MASK_IOVEC_TYPE,
					  MASK_IOVEC_ALIGN, 0,
					  CONV_ARR_WRONG_DSCR_FLD);
		if (err_iov) {
			DbgSCP_ALERT("Bad struct iovec in msghdr (syscall \'%s\')\n",
				     syscall_name);
		}
	} else {
			DbgSCP_ALERT("Empty struct iovec in msghdr (syscall \'%s\')\n",
				     syscall_name);
			converted_iovec = NULL;
	}

	/* Assign converted iovec pointer to converted msghdr structure: */
	converted_msghdr->msg_iov = converted_iovec;

	return args;
}

notrace __section(.entry_handlers)
long protected_sys_sendmsg(const unsigned long		sockfd,
			   const unsigned long __user msg,
			   const unsigned long		flags,
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs)
{
	unsigned int size;
	long rval; /* syscall return value */
	long __user *converted_msghdr;

	size = e2k_ptr_size(regs->args[3], regs->args[4], 1 /*min_size*/);
	converted_msghdr = convert_msghdr((long *) msg, size, "sendmsg");

	 /* Call socketcall handler function: */
	rval = sys_sendmsg(sockfd, (struct user_msghdr *) converted_msghdr,
			   flags);

	DbgSCP(" returned %ld\n", rval);
	return rval;
}


notrace __section(.entry_handlers)
long protected_sys_recvmsg(const unsigned long		socket,
			   const unsigned long __user message,
			   const unsigned long		flags,
			   const unsigned long unused4,
			   const unsigned long unused5,
			   const unsigned long unused6,
			   const struct pt_regs		*regs)
{
	unsigned int size;
	long rval; /* syscall return value */
	struct user_msghdr __user *converted_msghdr;

	size = e2k_ptr_size(regs->args[3], regs->args[4], 1 /*min_size*/);
	converted_msghdr = (struct user_msghdr *)
			convert_msghdr((long *) message, size, "recvmsg");

	 /* Call socketcall handler function: */
	rval = sys_recvmsg(socket, converted_msghdr, flags);

	if (!rval) {
		/* Updating the msg_flags field @ user space: */
		DbgSCP("Socket call 'recvmsg' returned msg_flags: 0x%x\n",
		       converted_msghdr->msg_flags);
		rval = copy_to_user((void *)
					(message + PROT_MSG_FLAGS_FIELD_OFFSET),
					&converted_msghdr->msg_flags,
					sizeof(converted_msghdr->msg_flags));
		if (rval) {
			DbgSCP_ERR("Socket call 'recvmsg' faled to return msg_flags\n");
			rval = -EFAULT;
		}
	}

	DbgSCP(" returned %ld\n", rval);
	return rval;
}


/*
 * Selecting proper convert_array masks (type and align) and argument number
 * to convert protected array of arguments to the corresponding sys_ipc syscall.
 * NB> Elements of the array are normally of types long and descriptor.
 */
notrace __section(.entry_handlers)
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
	unsigned long lo, hi;
	int access;
	long rval; /* return value */

	/* taking shm parameters from shmid: */
	segm_size = get_shm_segm_size(shmid);
	DbgSCP("(%d): segm_size = %ld\n", shmid, segm_size);

	if (IS_ERR_VALUE(segm_size))
		return (long) segm_size;

	access = (shmflg & SHM_RDONLY) ? R_ENABLE : RW_ENABLE;

	base = *raddr;

	lo = make_ap_lo(base, segm_size, 0, access);
	hi = make_ap_hi(base, segm_size, 0, access);
	NATIVE_STORE_VALUE_WITH_TAG(&AWP(&dscr).hi, hi, E2K_AP_HI_ETAG);
	NATIVE_STORE_VALUE_WITH_TAG(&AWP(&dscr).lo, lo, E2K_AP_LO_ETAG);

	DbgSCP("(%d): lo = 0x%lx  hi = 0x%lx\n", shmid, lo, hi);

	rval = copy_to_user_with_tags(raddr, &dscr, sizeof(dscr));
	if (rval)
		rval = -EFAULT;

	DbgSCP("(%d) returned %ld\n", shmid, rval);
	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_semctl(const long	semid,	/* a1 */
			  const long	semnum,	/* a2 */
			  const long	cmd,	/* a3 */
			  const unsigned long __user ptr, /* a4 */
			  const unsigned long unused5,
			  const unsigned long unused6,
			  const struct pt_regs	*regs)
{
	union semun *converted_semun;
	unsigned long fourth = 0; /* fourth arg to 'semctl' syscall */
	long rval; /* syscall return value */

#define MASK_SEMUN_PTR_TYPE  0x3 /* mask for union semun with pointer */
#define MASK_SEMUN_PTR_ALIGN 0x3 /* alignment mask for union semun with ptr */
#define SEMUN_STR_SIZE       16  /* size of union semun */
#define MASK_SEMUN_INT_TYPE  0x0 /* mask for union semun with int */
#define MASK_SEMUN_INT_ALIGN 0x3 /* alignment mask for union semun with int */
	/*
	 * Union semun (4-th parameter) contains pointers
	 * inside, therefore they need to be additionally
	 * converted depended on corresponding types
	 */
	converted_semun = get_user_space(sizeof(union semun));

	/* Fields of union semun depend on the 'cmd' parameter */
	switch (cmd & ~IPC_64) {
	/* Pointer in union semun required */
	case IPC_STAT:
	case IPC_SET:
	case IPC_INFO:
	case GETALL:
	case SEM_INFO:
	case SEM_STAT:
	case SEM_STAT_ANY:
	case SETALL:
		if (!ptr) {
			DbgSCP_ERR(" Bad semun parameter for semctl");
			return -EINVAL;
		}
		fourth = ptr;
		break;
	/* Int value in union semun required */
	case SETVAL:
		fourth = ptr;
		break;
	/* No 'semun' argument */
	default:
		break;
	}

	DbgSCP(" semid:%ld semnum:%ld cmd:%ld semun:0x:%lx\n",
		semid, semnum, cmd, fourth);

	rval = sys_old_semctl((int) semid, (int) semnum, (int) cmd, fourth);

	DbgSCP("(%d) returned %ld\n", (int) cmd, rval);
	return rval;
}

/* long sys_shmat(int shmid, char __user *shmaddr, int shmflg); */
notrace __section(.entry_handlers)
long protected_sys_shmat(const long		shmid,		/* a1 */
			 const unsigned long __user shmaddr,	/* a2 */
			 const long		shmflg,		/* a3 */
			 const unsigned long	unused4,
			 const unsigned long	unused5,
			 const unsigned long	unused6,
			 struct pt_regs		*regs)
{
	unsigned long segm_size;
	ulong base;
	unsigned long lo = 0, hi = 0;
	int access;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;
	long rval; /* syscall return value */

	rval = sys_shmat((int) shmid, (char *) shmaddr, (int) shmflg);

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

	lo = make_ap_lo(base, segm_size, 0, access);
	hi = make_ap_hi(base, segm_size, 0, access);

	rv1_tag = E2K_AP_LO_ETAG;
	rv2_tag = E2K_AP_HI_ETAG;
	rval = 0;
err_out:
	regs->return_desk = 1;
	regs->rval1 = lo;
	regs->rval2 = hi;
	regs->rv1_tag = rv1_tag;
	regs->rv2_tag = rv2_tag;
	DbgSCP("rval = %ld (hex: %lx) - 0x%lx : 0x%lx    t1/t2=0x%x/0x%x\n",
				rval, rval, lo, hi, rv1_tag, rv2_tag);

	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_ipc(const unsigned long	call,	/* a1 */
		       const long		first,	/* a2 */
		       const unsigned long	second,	/* a3 */
		       const unsigned long	third,	/* a4 */
		       const unsigned long __user ptr,	/* a5 */
		       const long		fifth,	/* a6 */
		       const struct pt_regs	*regs)
{
	long mask_type, mask_align;
	int fields;
	void *fourth = (void *) ptr; /* fourth arg to 'ipc' syscall */
	long rval; /* syscall return value */

#define MASK_SEMUN_PTR_TYPE  0x3 /* mask for union semun with pointer */
#define MASK_SEMUN_PTR_ALIGN 0x3 /* alignment mask for union semun with ptr */
#define SEMUN_STR_SIZE       16  /* size of union semun */
#define MASK_SEMUN_INT_TYPE  0x0 /* mask for union semun with int */
#define MASK_SEMUN_INT_ALIGN 0x3 /* alignment mask for union semun with int */

	get_ipc_mask(call, &mask_type, &mask_align, &fields);
	if ((fields == 0) || (unlikely(fields > 5))) {
		DbgSCP_ALERT("Bad syscall_ipc number %ld\n", call);
		return -EINVAL;
	}

	if (check_args_array(&regs->args[3], regs->tags >> 16, fields,
				mask_type, 0, "Syscall ipc()")) {
		DbgSCP_ERR("Bad args to syscall_ipc #%ld\n", call);
		return -EINVAL;
	}

	/* Syscalls that follow require converting arg-structures: */
	switch (call) {
	case SEMCTL: {
		/*
		 * Union semun (5-th parameter) contains pointers
		 * inside, therefore they need to be additionally
		 * converted depended on corresponding types
		 */
		union semun *converted_semun;

		converted_semun = get_user_space(sizeof(union semun));

		/* Fields of union semun depend on cmd parameter */
		switch (third & ~IPC_64) {
		/* Pointer in union semun required */
		case IPC_STAT:
		case IPC_SET:
		case IPC_INFO:
		case GETALL:
		case SEM_INFO:
		case SEM_STAT:
		case SEM_STAT_ANY:
		case SETALL:
			if (!ptr)
				return -EINVAL;
			rval = convert_array((long *) ptr,
					(long *) converted_semun,
					SEMUN_STR_SIZE, 1, 1,
					MASK_SEMUN_PTR_TYPE,
					MASK_SEMUN_PTR_ALIGN);
			if (rval) {
				DbgSCP_ERR(" Bad semun parameter for semctl");
				return -EINVAL;
			}
			/*
			 * Assign args[3] to pointer to
			 * converted union
			 */
			fourth = (void *) converted_semun;
			break;
		/* Int value in union semun required */
		case SETVAL:
			rval = convert_array((long *) ptr,
					(long *) converted_semun,
					SEMUN_STR_SIZE, 1, 1,
					MASK_SEMUN_INT_TYPE,
					MASK_SEMUN_INT_ALIGN);
			if (rval) {
				DbgSCP_ERR(" Bad semun parameter for semctl");
				return -EINVAL;
			}
			/*
			 * Assign args[3] to pointer to
			 * converted union
			 */
			fourth = (void *) converted_semun;
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
		struct ipc_kludge *converted_new_msg_buf;

		converted_new_msg_buf =
				get_user_space(sizeof(struct ipc_kludge));
		rval = convert_array((long *) ptr,
					(long *) converted_new_msg_buf,
					SIZE_MSG_BUF_PTR, 2, 1,
					MASK_MSG_BUF_PTR_TYPE,
					MASK_MSG_BUF_PTR_ALIGN);
		if (rval) {
			DbgSCP_ERR("Bad msg_buf parameter for msgrcv\n");
			return -EINVAL;
		}

		/*
		 * Assign args[3] to pointer to converted new_msg_buf
		 */
		fourth = (void *) converted_new_msg_buf;
		break;
	}
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
			(ulong *) third /**raddr*/);
	}

	DbgSCP("(%d) returned %ld\n", (int) call, rval);
	return rval;
}

__section(.entry_handlers)
static long prot_sys_mmap(const unsigned long start,
		const unsigned long length, const unsigned long prot,
		const unsigned long flags, const unsigned long fd,
		const unsigned long offset, const int offset_in_bytes,
		struct pt_regs *regs)
{
	unsigned long length2map;
	long rval = -EINVAL; /* syscall return value */
	e2k_addr_t base;
	unsigned int enable = 0;
	long rval1 = 0, rval2 = 0;
	int rv1_tag = E2K_NUMERIC_ETAG, rv2_tag = E2K_NUMERIC_ETAG;

	DbgSCP("start = %ld, len = %ld, prot = 0x%lx ", start, length, prot);
	DbgSCP("flags = 0x%lx, fd = 0x%lx, off = %ld, in_bytes=%d",
					flags, fd, offset, offset_in_bytes);
	if (!length)
		goto nr_mmap_out;

	length2map = offset_in_bytes ? length : (length * 0x1000);
	if (length2map > 0x7fffffffL) {
		/* NB> For details on this limitation see bug #99875 */
		DbgSCP_ERR("trying to map %ld (0x%lx) bytes\n",
			   length2map, length2map);
		DbgSCP_WARN("cannot allocate over 2**31 bytes (2Gb) in protected mode\n");
		/* NB> We cannot simply return error code as
		 *     this syscall returns structured result.
		 */
		goto nr_mmap_out;
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
		goto nr_mmap_out;
	}
	base += (unsigned long) offset & PAGE_MASK;

	if (!prot) {
		DbgSCP_WARN("delivered descriptor without access rights:\n");
		DbgSCP_WARN("\tbase = 0x%lx  size = 0x%lx  prot = 0\n",
				(unsigned long)base, length);
	}

	if (prot & PROT_READ)
		enable |= R_ENABLE;
	if (prot & PROT_WRITE)
		enable |= W_ENABLE;

	rval1 = make_ap_lo(base, length, 0, enable);
	rval2 = make_ap_hi(base, length, 0, enable);
	rv1_tag = E2K_AP_LO_ETAG;
	rv2_tag = E2K_AP_HI_ETAG;
	rval = 0;
nr_mmap_out:
	regs->return_desk = 1;
	regs->rval1 = rval1;
	regs->rval2 = rval2;
	regs->rv1_tag = rv1_tag;
	regs->rv2_tag = rv2_tag;
	DbgSCP("rval = %ld (hex: %lx) - 0x%lx : 0x%lx    t1/t2=0x%x/0x%x\n",
				rval, rval, rval1, rval2, rv1_tag, rv2_tag);
	return rval;
}

__section(.entry_handlers)
long protected_sys_mmap(const unsigned long	a1, /* start */
			const unsigned long	a2, /* length */
			const unsigned long	a3, /* prot */
			const unsigned long	a4, /* flags */
			const unsigned long	a5, /* fd */
			const unsigned long	a6, /* offset */
				struct pt_regs	*regs)
{
	return prot_sys_mmap(a1, a2, a3, a4, a5, a6, 1, regs);
}

__section(.entry_handlers)
long protected_sys_mmap2(const unsigned long	a1, /* start */
			const unsigned long	a2, /* length */
			const unsigned long	a3, /* prot */
			const unsigned long	a4, /* flags */
			const unsigned long	a5, /* fd */
			const unsigned long	a6, /* offset */
				struct pt_regs	*regs)
{
	return prot_sys_mmap(a1, a2, a3, a4, a5, a6, 0, regs);
}


notrace __section(.entry_handlers)
long protected_sys_unuselib(const unsigned long	a1, /* address of module */
			const unsigned long	a2,
			const unsigned long	a3,
			const unsigned long	a4,
			const unsigned long	a5,
			const unsigned long	a6,
				struct pt_regs  *regs)
{
	unsigned long rval;
	/* Base address of module data segment */
	unsigned long glob_base = a1;
	/* Size of module data segment */
	size_t glob_size = e2k_ptr_size(regs->args[1], regs->args[2],
					1 /*min_size*/);

	/* Unload module module from memory */
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

notrace __section(.entry_handlers)
long protected_sys_munmap(const unsigned long __user a1, /* addr */
			  const unsigned long        a2, /* length */
			  const unsigned long unused3,
			  const unsigned long unused4,
			  const unsigned long unused5,
			  const unsigned long unused6,
				struct pt_regs	*regs)
{
	long rval = -EINVAL; /* syscall return value */
	unsigned int addr_size;

	DbgSCP("(addr=%lx, len=%lx) ", a1, a2);

	if (!a1 || !a2)
		return -EINVAL;

	addr_size = e2k_ptr_size(regs->args[1], regs->args[2], 0);
	if (addr_size < a2) {
		DbgSCP_ALERT("Length bigger than descr size: %ld > %d\n",
								a2, addr_size);
		return -EINVAL;
	}

	if (e2k_ptr_itag(regs->args[1]) != AP_ITAG) {
		DbgSCP_ALERT("Desc in stack (SAP, not AP): 0x%lx\n", a1);
		return -EINVAL;
	}

	rval = sys_munmap(a1, a2);
	DbgSCP("rval = %ld (hex: %lx)\n", rval, rval);
	return rval;
}



notrace __section(.entry_handlers)
long protected_sys_get_backtrace(const unsigned long __user buf, /* a1 */
				 size_t count, size_t skip,      /* a2,3 */
				 unsigned long flags,            /* a4 */
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs)
{
	unsigned int size;

	DbgSCP("(buf=0x%lx, count=%ld, skip=%ld, flags=0x%lx)\n",
	       buf, count, skip, flags);
	size = e2k_ptr_size(regs->args[1], regs->args[2], 0);
	if (size < (count * 8)) {
		DbgSCP_ALERT("Count bigger than buf size: %ld > %d\n",
							(count * 8), size);
		return -EINVAL;
	}
	return sys_get_backtrace((unsigned long *) buf, count, skip, flags);
}

notrace __section(.entry_handlers)
long protected_sys_set_backtrace(const unsigned long __user buf, /* a1 */
				 size_t count, size_t skip,      /* a2,3 */
				 unsigned long flags,            /* a4 */
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs)
{
	unsigned int size;

	DbgSCP("(buf=0x%lx, count=%ld, skip=%ld, flags=0x%lx)\n",
	       buf, count, skip, flags);
	size = e2k_ptr_size(regs->args[1], regs->args[2], 0);
	if (size < (count * 8)) {
		DbgSCP_ALERT("Count bigger than buf size: %ld > %d\n",
							(count * 8), size);
		return -EINVAL;
	}
	return sys_set_backtrace((unsigned long *) buf, count, skip, flags);
}


notrace __section(.entry_handlers)
long protected_sys_set_robust_list(const unsigned long __user listhead, /* a1 */
				 const size_t len,	/* a2 */
				 const unsigned long unused3,
				 const unsigned long unused4,
				 const unsigned long unused5,
				 const unsigned long unused6,
				 const struct pt_regs	*regs)
{
	DbgSCP("(head=0x%lx, len=%zd)\n", listhead, len);

	if (!futex_cmpxchg_enabled) {
		DbgSCP_ALERT("futex_cmpxchg is not enabled\n");
		return -ENOSYS;
	}

	/* In glibc side `sizeof (struct robust_list_head) == 0x30'.  */
	if (unlikely(len != 0x30)) {
		DbgSCP_ALERT("len (0x%zx) != sizeof(struct robust_list_head)\n",
			     len);
		return -EINVAL;
	}

	current_thread_info()->pm_robust_list = (long __user *) listhead;

	/* We need to save the original descriptor
	 * to return it in protected_sys_get_robust_list:
	 */
	store_descriptor_attrs((void *)listhead, regs->args[1], regs->args[2],
			       (regs->tags >> 8) & 0xFF, 0 /*signum*/);

	DbgSCP("tags = 0x%lx  /  ret = 0\n", (regs->tags >> 8));
	return 0;
}

notrace __section(.entry_handlers)
long protected_sys_get_robust_list(const unsigned long pid,
				 unsigned long __user head_ptr,
				 unsigned long __user len_ptr)
{
	/* In glibc side `sizeof (struct robust_list_head) == 0x30'.  */
#define SIZEOF_PROT_HEAD_STRUCT 0x30
	long __user *head;
	unsigned long ret; /* result of the function */
	struct task_struct *p;
	struct sival_ptr_list *dscr_attrs;
	e2k_ptr_t dscr;
	size_t len;

	DbgSCP("(pid=%ld, head_ptr=0x%lx, len_ptr=0x%lx)\n",
	       pid, head_ptr, len_ptr);

	if (!futex_cmpxchg_enabled) {
		DbgSCP("futex_cmpxchg is not enabled\n");
		return -ENOSYS;
	}

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

	head = task_thread_info(p)->pm_robust_list;
	rcu_read_unlock();

	if (!head) {
		DbgSCP("robust_list is not set yet\n");
		len = sizeof(dscr);
		memset(&dscr, 0, len);
		ret = 0;
		goto empty_list_out;
	}

	/* We need to return the original descriptor;
	 * restoring it from the pointer saved in task_struct:
	 */
	dscr_attrs = get_descriptor_attrs((void *)head, 0 /* signum */);
	if (!dscr_attrs) {
		DbgSCP_ALERT("Failed to restore descriptor attributes "
						"on pointer 0x%lx\n", head);
		return -EFAULT;
	}
	DbgSCP("dscr_attrs = 0x%p\n", dscr_attrs);

	len = e2k_ptr_size(dscr_attrs->user_ptr_lo, dscr_attrs->user_ptr_hi, 0);
	DbgSCP("list head stored: lo=0x%llx hi=0x%llx tags=0x%x len=%zd\n",
		dscr_attrs->user_ptr_lo, dscr_attrs->user_ptr_hi,
		dscr_attrs->user_tags, len);
	if (unlikely(len < SIZEOF_PROT_HEAD_STRUCT)) {
		DbgSCP_ALERT("len (0x%zx) < sizeof(struct robust_list_head)\n",
			     len);
		return -EFAULT;
	}

	TRY_USR_PFAULT {
		NATIVE_STORE_VALUE_WITH_TAG(&AWP(&dscr).hi,
					    dscr_attrs->user_ptr_hi,
					    dscr_attrs->user_tags >> 4);
		NATIVE_STORE_VALUE_WITH_TAG(&AWP(&dscr).lo,
					    dscr_attrs->user_ptr_lo,
					    dscr_attrs->user_tags & 0xF);
	} CATCH_USR_PFAULT {
		return -EFAULT;
	} END_USR_PFAULT

	DbgSCP("robust_list head: lo=0x%lx  hi=0x%lx  tags=0x%x  len=%zd\n",
		AWP(&dscr).lo, AWP(&dscr).hi, dscr_attrs->user_tags, len);
	ret = 0;

	len = SIZEOF_PROT_HEAD_STRUCT;
empty_list_out:
	if (copy_to_user((void *)len_ptr, &len, sizeof(len)))
		return -EFAULT;
	if (copy_to_user_with_tags((void *)head_ptr, &dscr, sizeof(dscr)))
		return -EFAULT;
	return ret;

err_unlock:
	rcu_read_unlock();

	return ret;
}

#define PROCESS_VM_RW_V_PROC \
	(regs->sys_num == __NR_process_vm_readv) ? \
	"process_vm_readv" : "process_vm_writev"
#define BAD_IOVEC_STR_MSG \
	"Bad %s iovec structure in protected %s\n"

notrace __section(.entry_handlers)
static
long protected_sys_process_vm_readwritev(const unsigned long pid,
				 const struct iovec __user *lvec,
				 unsigned long           liovcnt,
				 const struct iovec __user *rvec,
				 unsigned long           riovcnt,
				 unsigned long             flags,
				 const struct pt_regs      *regs,
				 const int              vm_write)
{
	pid_t id = pid;
	size_t lsize, rsize;
	struct iovec *lv = NULL, *rv = NULL;
	long rval;

	DbgSCP("(%ld, lvec=0x%lx, lcnt=%ld, rvec=0x%lx, rcnt=%ld, flg=0x%lx)\n",
	       pid, lvec, liovcnt, rvec, riovcnt, flags);

	lsize = e2k_ptr_size(regs->args[3], regs->args[4], 0);
	if (lsize < (sizeof(struct iovec) * liovcnt)) {
		DbgSCP_ALERT("Insufficient lvec size: %zd < %ld\n",
			     lsize, sizeof(struct iovec) * liovcnt);
		return -EFAULT;
	}
	rsize = e2k_ptr_size(regs->args[7], regs->args[8], 0);
	if (rsize < (sizeof(struct iovec) * riovcnt)) {
		DbgSCP_ALERT("Insufficient rvec size: %zd < %ld\n",
			     rsize, sizeof(struct iovec) * riovcnt);
		return -EFAULT;
	}

	if (liovcnt || riovcnt) {
		char *new_arg;

		new_arg = get_user_space(lsize + rsize);
		lv = (struct iovec *)new_arg;
		rv = (struct iovec *)(new_arg + lsize);

		if (liovcnt) {
			rval = convert_array((long *) lvec, (long *) lv, lsize,
					2, liovcnt/*nr_segs*/, 0x7, 0xf);
			if (rval) {
				DbgSCP_ALERT(BAD_IOVEC_STR_MSG, "local",
						PROCESS_VM_RW_V_PROC);
				return -EINVAL;
			}
		}

		if (riovcnt) {
			rval = convert_array((long *) rvec, (long *) rv, rsize,
					2, riovcnt/*nr_segs*/, 0x7, 0xf);
			if (rval) {
				DbgSCP_ALERT(BAD_IOVEC_STR_MSG, "remote",
						PROCESS_VM_RW_V_PROC);
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

notrace __section(.entry_handlers)
long protected_sys_process_vm_readv(const unsigned long          pid, /* a1 */
				    const struct iovec __user  *lvec, /* a2 */
				    unsigned long            liovcnt, /* a3 */
				    const struct iovec __user  *rvec, /* a4 */
				    unsigned long            riovcnt, /* a5 */
				    unsigned long              flags, /* a6 */
				    const struct pt_regs       *regs)
{
	return protected_sys_process_vm_readwritev(pid,
						   lvec, liovcnt,
						   rvec, riovcnt,
						   flags, regs, 0);
}

notrace __section(.entry_handlers)
long protected_sys_process_vm_writev(const unsigned long         pid, /* a1 */
				     const struct iovec __user *lvec, /* a2 */
				     unsigned long           liovcnt, /* a3 */
				     const struct iovec __user *rvec, /* a4 */
				     unsigned long           riovcnt, /* a5 */
				     unsigned long             flags, /* a6 */
				     const struct pt_regs      *regs)
{
	return protected_sys_process_vm_readwritev(pid,
						   lvec, liovcnt,
						   rvec, riovcnt,
						   flags, regs, 1);
}


notrace __section(.entry_handlers)
long protected_sys_vmsplice(int				fd,      /* a1 */
			 const struct iovec __user	*iov,    /* a2 */
			 unsigned long			nr_segs, /* a3 */
			 unsigned int			flags,   /* a4 */
			 const unsigned long		unused5,
			 const unsigned long		unused6,
			 const struct pt_regs		*regs)
{
	long rval = -EINVAL;
	size_t size;
	struct iovec *kiov;

	DbgSCP("(fd=%d, iov=0x%lx, nr_segs=%ld, flg=0x%x)\n",
	       fd, iov, nr_segs, flags);

	if (!iov)
		goto err_out;

	size = e2k_ptr_size(regs->args[3], regs->args[4], 0);
	if (size < sizeof(struct iovec)) {
		DbgSCP_ALERT("Insufficient iov size: %zd < %ld\n",
					size, sizeof(struct iovec));
		return rval;
	}

	kiov = get_user_space(size);
	rval = convert_array((long *) iov, (long *) kiov, size,
					2, 1/*nr_segs*/, 0x7, 0x7);
	if (rval)
		goto err_out;

	rval = sys_vmsplice(fd, kiov, nr_segs, flags);
	return rval;

err_out:
	DbgSCP_ALERT("Bad iovec structure in protected vmsplice syscall\n");
	return -EINVAL;
}


notrace __section(.entry_handlers)
long protected_sys_keyctl(const int	operation,
			const unsigned long	arg2,
			const unsigned long	arg3,
			const unsigned long	arg4,
			const unsigned long	arg5,
			const unsigned long	unused6,
			const struct pt_regs	*regs)
{
	long rval = -EINVAL;
	size_t size;
	struct iovec __user *iov;
	struct iovec *kiov;
	struct keyctl_kdf_params __user *ukdf_params;
	struct keyctl_kdf_params *kkdf_params;

	switch (operation) {
	case KEYCTL_INSTANTIATE_IOV:
		iov = (struct iovec __user *) arg3;
		if (!iov)
			break;
		size = e2k_ptr_size(regs->args[5], regs->args[6], 0);
		if (size < sizeof(struct iovec)) {
			DbgSCP_ALERT("Insufficient iov size: %zd < %ld\n",
						size, sizeof(struct iovec));
			return rval;
		}
		kiov = get_user_space(size);
		rval = convert_array((long *) iov, (long *) kiov, size,
						2, 1/*nr_segs*/, 0x7, 0x7);
		if (rval)
			return rval;
		return sys_keyctl(operation, arg2, (unsigned long)kiov,
				  arg4, arg5);
	case KEYCTL_DH_COMPUTE:
		ukdf_params = (struct keyctl_kdf_params __user *) arg5;
		if (!ukdf_params)
			break;
		size = e2k_ptr_size(regs->args[9], regs->args[10], 0);
		if (size < sizeof(struct keyctl_kdf_params)) {
			DbgSCP_ALERT("Insufficient keyctl_kdf_params size: %zd < %ld\n",
					size, sizeof(struct keyctl_kdf_params));
			return rval;
		}
		kkdf_params = get_user_space(size);
		rval = convert_array((long *) ukdf_params, (long *) kkdf_params,
					size, 3, 1/*nr_segs*/, 0x1f, 0x1f);
		if (rval)
			return rval;
		return sys_keyctl(operation, arg2, arg3, arg4,
						(unsigned long)kkdf_params);
	}

	return sys_keyctl(operation, arg2, arg3, arg4, arg5);
}


notrace __section(.entry_handlers)
long protected_sys_prctl(const int	option,
			const unsigned long	arg2,
			const unsigned long	arg3,
			const unsigned long	arg4,
			const unsigned long	arg5,
			const unsigned long	unused6,
			const struct pt_regs	*regs)
{
	long rval = -EINVAL;
	size_t size;
	int __user **intptr;
	int **kintptr;
	struct sock_fprog __user *sfprog;
	struct sock_fprog *ksfprog;

	switch (option) {
	case PR_GET_TID_ADDRESS:
		intptr = (int __user **) arg2;
		if (!intptr)
			break;
		size = e2k_ptr_size(regs->args[3], regs->args[4], 0);
		if (size < 16) {
			DbgSCP_ALERT("Insufficient (int **) arg2 size: %zd < 16\n",
						size);
			return rval;
		}
		kintptr = get_user_space(size);
		rval = convert_array((long *) intptr, (long *) kintptr, size,
						1, 1/*nr_segs*/, 0x3, 0x3);
		if (rval)
			return rval;
		return sys_prctl(option, (unsigned long) kintptr, arg3,
				 arg4, arg5);
	case PR_SET_SECCOMP:
		sfprog = (struct sock_fprog __user *) arg3;
		if (!sfprog)
			break;
		size = e2k_ptr_size(regs->args[5], regs->args[6], 0);
		if (size < sizeof(struct sock_fprog)) {
			DbgSCP_ALERT("Insufficient (sock_fprog *) arg3 size: %zd < %ld\n",
					size, sizeof(struct sock_fprog));
			return rval;
		}
		ksfprog = get_user_space(size);
		rval = convert_array((long *) sfprog, (long *) ksfprog, size,
						2, 1/*nr_segs*/, 0xc, 0xf);
		if (rval)
			return rval;
		return sys_prctl(option, arg2, (unsigned long) ksfprog,
				 arg4, arg5);
	}

	return sys_prctl(option, arg2, arg3, arg4, arg5);
}

notrace __section(.entry_handlers)
long protected_sys_ioctl(const int fd,				/* a1 */
				const unsigned long request,	/* a2 */
				void *argp,			/* a3 */
				const unsigned long unused4,
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	unsigned int size;
	long rval;

	DbgSCP("(fd=0x%x, request=0x%lx, argp=0x%lx)\n",
					fd, request, (unsigned long) argp);

	switch (request) {
	case SIOCGIFCONF: {
#define STRUCT_IFCONF_FIELDS		2
#define STRUCT_IFCONF_ITEMS		1
#define STRUCT_IFCONF_MASK_TYPE		0xc
#define STRUCT_IFCONF_MASK_ALIGN	0xf

/* sizeof(struct ifconf) in user128 protected mode space */
#define STRUCT_IFCONF_PROT_SIZE		32
/* sizeof(struct ifreq) in user128 protected mode space */
#define STRUCT_IFREQ_PROT_SIZE		48

		/* Pointer to user128 struct ifconf */
		void *ifc128 = argp;
		/* Pointer to user128 array of ifreq structures */
		void *ifr128;

		/* Pointer to temporary64 translated struct ifconf */
		struct ifconf *ifc64;
		/* Pointer to temporary64 array of ifreq structures */
		struct ifreq *ifr64;

		/*
		 * Lengths in terms of bytes of user128 and temporary64 array
		 * of ifreq structures
		 */
		int ifc_len128, ifc_len64;
		int i;

		/* Check descriptor's size of user128 struct ifconf. */
		size = e2k_ptr_size(regs->args[5], regs->args[6], 0);
		if (size < STRUCT_IFCONF_PROT_SIZE) {
			DbgSCP_ALERT("ifconf ptr is too little: %d < %d\n",
				size, STRUCT_IFCONF_PROT_SIZE);
			return -EINVAL;
		}

		/* Translate struct ifconf from user128 to kernel64 mode. */
		ifc64 = get_user_space(sizeof(struct ifconf));
		rval = convert_array(ifc128, (long *) ifc64, size,
				STRUCT_IFCONF_FIELDS, STRUCT_IFCONF_ITEMS,
				STRUCT_IFCONF_MASK_TYPE,
				STRUCT_IFCONF_MASK_ALIGN);
		if (rval) {
			DbgSCP_ALERT("Bad struct ifconf for ioctl SIOCGIFCONF");
			return rval;
		}

		/* Save pointer to user128's array of ifreq structures. */
		ifr128 = ifc64->ifc_req;

		/*
		 * Count length of temporary64 array of ifreq structures.
		 * It differs from user128 one, because struct ifreq contains
		 * pointers.
		 */
		ifc_len128 = ifc64->ifc_len;
		ifc_len64 = ifc_len128 * sizeof(struct ifreq) /
							STRUCT_IFREQ_PROT_SIZE;

		/*
		 * Initialize temporary64 struct ifconf with translated values.
		 */
		ifc64->ifc_len = ifc_len64;
		ifr64 = get_user_space(ifc_len64);
		ifc64->ifc_req = ifr64;

		/* Do the ioctl(). */
		rval = sys_ioctl(fd, request, (unsigned long) ifc64);
		DbgSCP("%s:%d sys_ioctl(%d, %ld, 0x%lx) returns %ld\n",
				__FILE__, __LINE__,
				fd, request, (unsigned long) ifc64, rval);
		if (rval)
			return rval;

		/*
		 * Kernel writes actual length of array of ifreq structures
		 * in ifc_len. Translate it to actual length of user128 array.
		 */
		ifc_len64 = ifc64->ifc_len;
		ifc_len128 = ifc_len64 * STRUCT_IFREQ_PROT_SIZE /
						sizeof(struct ifreq);
		/*
		 * Sys_ioctl writes an array of stucts ifreq in ifc_req buffer.
		 * In our case it does not contais pointers,
		 * but still sizeof(struct ifreq64) > sizeof(struct ifreq128),
		 * so we need to copy it one by one.
		 */
		for (i = 0; i < ifc_len128; i += STRUCT_IFREQ_PROT_SIZE) {
			if (copy_to_user(ifr128 + i, ifr64++,
						sizeof(struct ifreq))) {
				DbgSCP_ALERT("%s:%d copy_to_user() failed\n",
						__FILE__, __LINE__);
				return -EFAULT;
			}
		}

		/*
		 * Write actual length of array of ifreq structures to user128
		 * struct ifconf.
		 */
		if (put_user(ifc_len128, (int *) ifc128)) {
			DbgSCP_ALERT("%s:%d put_user() failed\n",
					__FILE__, __LINE__);
			return -EFAULT;
		}

		break;
	}
	default:
		rval = sys_ioctl(fd, request, (unsigned long) argp);
	}

	return rval;
}


#if 0
static void print_epoll_kevent(void *kevent, int count)
{
	int *kptr;
	int i, j;

	if (!arch_init_pm_sc_debug_mode(PM_SC_DBG_MODE_COMPLEX_WRAPPERS))
		return;

	pr_info("%s:: kevent = 0x%lx:\n", __func__, kevent);
	for (j = 0; j < count; j++) {
		if (count > 1)
			pr_info("\t[instance #%d:]\n", j);
		for (i = 0, kptr = kevent;
		     i < sizeof(struct epoll_event) / sizeof(int);
		     i++) {
			pr_info("\t\t0x%.8x\n", *kptr);
			kptr++;
		}
	}
}
#endif

#define EPOLL_EVENT_PROT_DATA_OFFSET 16 /* field offset in prot struct */
#define SIZEOF_EPOLL_EVENT_KDWRD (sizeof(struct epoll_event) / sizeof(long))
#define SIZEOF_EPOLL_EVENT_UDWRD 4 /* protected size in double words */

/* Converting user (protected) event structure to kernel structure: */
static
struct epoll_event *convert_epoll_event(void __user *event, int count,
					size_t max_size)
{
	void *kevent = NULL;
	int rval;

	if (!event)
		return kevent;

	kevent = get_user_space(sizeof(struct epoll_event) * count);
	rval = convert_array_3((long *)event, (long *)kevent, max_size,
			       2 /*fields*/, count /*items*/,
			       0xc /*mask_type*/, 0xf /*mask_align*/,
			       0 /*mask_rw*/, CONV_ARR_IGNORE_DSCR_FLD_ERR);
	if (rval) {
		DbgSCP_ALERT("Bad epoll_event structure");
		return NULL;
	}

	return kevent;
}

/* Updating user (protected) event structure on modified kernel structure: */
static int update_epoll_event(void __user *event, void *kevent, int count)
{
	long lval;
	int tag;
	int j, ret;
	long *klarr;
	long __user *ularr;
	long __user *pfield;

	if (!event || !kevent)
		return -1; /* something's wrong */

	DbgSCP("(event=0x%lx, kevent=0x%lx, count=%d)\n", event, kevent, count);
	/* print_epoll_kevent(kevent, count); */

	klarr = (long *)kevent;
	ularr = (long *)event;
	for (j = 0, ret = 0;
	     j < count;
	     j++, klarr += SIZEOF_EPOLL_EVENT_KDWRD,
		  ularr += SIZEOF_EPOLL_EVENT_UDWRD) {
		lval = (long)(((struct epoll_event *)klarr)->events);
		pfield = (long *)((long)ularr);
		if (put_user(lval, pfield)) {
			DbgSCP("put_user() failed at %s:%d\n",
					__FILE__, __LINE__);
			return -EFAULT;
		}
		ret++;

		/* Checking if struct field 'data' is descriptor: */
		NATIVE_LOAD_VAL_AND_TAGD((long)ularr +
				EPOLL_EVENT_PROT_DATA_OFFSET, lval, tag);
		if (tag != ETAGNVD) { /* this must be descriptor */
			DbgSCP("lval=0x%lx  tag=0x%x  update skipped\n",
			       lval, tag);
			continue; /* skipping it for now */
		}

		lval = (long)(((struct epoll_event *)klarr)->data);
		pfield = (long *)((long)ularr + EPOLL_EVENT_PROT_DATA_OFFSET);
		if (put_user(lval, pfield)) {
			DbgSCP("%s:%d put_user() failed\n",
				     __FILE__, __LINE__);
			return -EFAULT;
		}
		ret++;
	}

	return ret; /* # fields updated */
}

notrace __section(.entry_handlers)
long protected_sys_epoll_ctl(const unsigned long epfd,	/* a1 */
			     const unsigned long op,	/* a2 */
			     const unsigned long fd,	/* a3 */
			     void __user	*event,	/* a4 */
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	void *kevent;
	long rval;
#define EVENT_STRUCT_PROT_SIZE 32
	DbgSCP("(epfd=0x%lx, op=0x%lx, fd=0x%lx, event=0x%lx)\n",
					epfd, op, fd, event);

	kevent = convert_epoll_event(event, 1, EVENT_STRUCT_PROT_SIZE);

	rval = sys_epoll_ctl(epfd, op, fd, (struct epoll_event *) kevent);

	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_epoll_wait(const unsigned long epfd,		/* a1 */
			      void __user	*event,		/* a2 */
			      const long	maxevents,	/* a3 */
			      const long	timeout,	/* a4 */
				const unsigned long unused5,
				const unsigned long unused6,
				const struct pt_regs *regs)
{
	void *kevent;
	long rval;
	size_t size;

	DbgSCP("(epfd=0x%lx, event=0x%lx, maxevents=%ld, timeout=%ld)\n",
					epfd, event, maxevents, timeout);

	if (maxevents <= 0)
		return -EINVAL;

	size = e2k_ptr_size(regs->args[3], regs->args[4], 0);
	if (size < (EVENT_STRUCT_PROT_SIZE * maxevents)) {
		if (size)
			DbgSCP_ALERT("Wrong event structure size (%zd < %ld)\n",
				     size, EVENT_STRUCT_PROT_SIZE * maxevents);
		return -EINVAL;
	}

	kevent = convert_epoll_event(event, maxevents, size);

	rval = sys_epoll_wait(epfd, (struct epoll_event *) kevent,
			      maxevents, timeout);
	if (rval <= 0)
		return rval;

	/* 'kevent' structure may have been modified; updating user struct: */
	if (update_epoll_event(event, kevent, maxevents) < 0)
		rval = -EFAULT;

	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_epoll_pwait(const unsigned long epfd,	/* a1 */
			       void __user	*event,		/* a2 */
			       const long	maxevents,	/* a3 */
			       const long	timeout,	/* a4 */
			       const unsigned long sigmask,	/* a5 */
			       const unsigned long sigsetsize,	/* a6 */
			       const struct pt_regs *regs)
{
	void *kevent;
	long rval;
	size_t size;

	DbgSCP("(epfd=0x%lx, event=0x%lx, maxevents=%ld, timeout=%ld, sigmask, sigsetsize=%ld)\n",
		epfd, event, maxevents, timeout, sigsetsize);

	if (maxevents <= 0)
		return -EINVAL;

	size = e2k_ptr_size(regs->args[3], regs->args[4], 0);
	if (size < (EVENT_STRUCT_PROT_SIZE * maxevents)) {
		if (size)
			DbgSCP_ALERT("Wrong event structure size (%zd < %ld)\n",
				     size, EVENT_STRUCT_PROT_SIZE * maxevents);
		return -EINVAL;
	}

	kevent = convert_epoll_event(event, maxevents, size);

	rval = sys_epoll_pwait(epfd, (struct epoll_event *) kevent, maxevents,
			       timeout, (sigset_t *) sigmask, sigsetsize);
	if (rval <= 0)
		return rval;

	/* 'kevent' structure may have been modified; updating user struct: */
	if (update_epoll_event(event, kevent, maxevents) < 0)
		rval = -EFAULT;

	return rval;
}

notrace __section(.entry_handlers)
long protected_sys_pselect6(const long		nfds,		/* a1 */
			    const unsigned long readfds,	/* a2 */
			    const unsigned long writefds,	/* a3 */
			    const unsigned long exceptfds,	/* a4 */
			    const unsigned long timeout,	/* a5 */
			    const unsigned long sigmask,	/* a6 */
			    const struct pt_regs *regs)
{
	unsigned int size;
	void *sigmask_ptr64 = NULL;
	long rval;

	DbgSCP("(nfds=%ld, ...)\n", nfds);

	if (sigmask) {
#define STRUCT_SIGSET6_FIELDS		2
#define STRUCT_SIGSET6_MASK_TYPE	0x7
#define STRUCT_SIGSET6_MASK_ALIGN	0x7
#define STRUCT_SIGSET6_PROT_SIZE	24 /* sizeof(modified sigmask) in PM */

		/* Check descriptor's size of 6th argument. */
		size = e2k_ptr_size(regs->args[11], regs->args[12], 0);
		if (size < STRUCT_SIGSET6_PROT_SIZE) {
			DbgSCP_ALERT("'sigmask' pointer size is too little: %d < %d\n",
				size, STRUCT_SIGSET6_PROT_SIZE);
			return -EINVAL;
		}

		/* Translate struct sigmask from user128 to kernel64 mode. */
		sigmask_ptr64 = get_user_space(size);
		rval = convert_array((long *)sigmask, (long *) sigmask_ptr64,
				     size, STRUCT_SIGSET6_FIELDS, 1 /*items*/,
					STRUCT_SIGSET6_MASK_TYPE,
					STRUCT_SIGSET6_MASK_ALIGN);
		if (rval) {
			DbgSCP_ALERT("Bad struct 'sigmask' for pselect6() syscall");
			return rval;
		}
	}

	rval = sys_pselect6((int) nfds, (void *) readfds, (void *) writefds,
			    (void *) exceptfds, (void *) timeout,
			    (void *) sigmask_ptr64);
	DbgSCP("sys_pselect6(nfds=%ld, ...) returned %ld\n", nfds, rval);

	return rval;
}

#endif /* CONFIG_PROTECTED_MODE */
