/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _LINUX_PROT_SIGNAL_H
#define _LINUX_PROT_SIGNAL_H
/*
 * These are the type definitions for the architecture specific
 * syscall compatibility layer.
 */

#ifdef CONFIG_PROTECTED_MODE

#include <linux/types.h>
#include <linux/time.h>

#include <linux/stat.h>
#include <linux/param.h>	/* for HZ */
#include <linux/sem.h>
#include <linux/socket.h>
#include <linux/if.h>
#include <linux/fs.h>
#include <linux/aio_abi.h>	/* for aio_context_t */
#include <linux/uaccess.h>
#include <linux/unistd.h>

#include <asm/compat.h>

#include <asm/siginfo.h>
#include <asm/signal.h>

#ifdef CONFIG_ARCH_HAS_SYSCALL_WRAPPER
/*
 * It may be useful for an architecture to override the definitions of the
 * COMPAT_SYSCALL_DEFINE0 and COMPAT_SYSCALL_DEFINEx() macros, in particular
 * to use a different calling convention for syscalls. To allow for that,
 + the prototypes for the compat_sys_*() functions below will *not* be included
 * if CONFIG_ARCH_HAS_SYSCALL_WRAPPER is enabled.
 */
#include <asm/syscall_wrapper.h>
#endif /* CONFIG_ARCH_HAS_SYSCALL_WRAPPER */


struct prot_sigaction {
	e2k_pl_t			sa_handler;
	ulong				sa_flags;
#ifdef __ARCH_HAS_SA_RESTORER
	e2k_ptr_t			sa_restorer;
#endif
	sigset_t			sa_mask __packed;
};


typedef union prot_sigval {
	int	sival_int;
	e2k_ptr_t	sival_ptr;
} prot_sigval_t;


#define __PROT_SI_MAX_SIZE   128
# define __PROT_SI_PAD_SIZE  ((__PROT_SI_MAX_SIZE / sizeof(int)) - 4)


struct prot_siginfo {
	int si_signo;
#ifndef __ARCH_HAS_SWAPPED_SIGINFO
	int si_errno;
	int si_code;
#else
	int si_code;
	int si_errno;
#endif

	union {
		int _pad[__PROT_SI_PAD_SIZE];

		/* kill() */
		struct {
			pid_t _pid;	/* sender's pid */
			uid_t _uid;	/* sender's uid */
		} _kill;

		/* POSIX.1b timers */
		struct {
			timer_t _tid;		/* timer id */
			int _overrun;		/* overrun count */
			prot_sigval_t _sigval;	/* same as below */
		} _timer;

		/* POSIX.1b signals */
		struct {
			pid_t _pid;	/* sender's pid */
			uid_t _uid;	/* sender's uid */
			prot_sigval_t _sigval;
		} _rt;

		/* SIGCHLD */
		struct {
			pid_t _pid;	/* which child */
			uid_t _uid;	/* sender's uid */
			int _status;		/* exit code */
			clock_t _utime;
			clock_t _stime;
		} _sigchld;


		/* SIGILL, SIGFPE, SIGSEGV, SIGBUS, SIGTRAP, SIGEMT */
		struct {
			void *_addr;	/* faulting insn/memory ref. */
#ifdef __ARCH_SI_TRAPNO
			int _trapno;    /* TRAP # which caused the signal */
#endif
			short int _addr_lsb;	/* Valid LSB of the reported address. */
			union {
				/*
				 * used when si_code=BUS_MCEERR_AR or
				 * used when si_code=BUS_MCEERR_AO
				 */
				/* used when si_code=SEGV_BNDERR */
				struct {
					void *_lower;
					void *_upper;
				} _addr_bnd;
				/* used when si_code=SEGV_PKUERR */
				struct {
					u32 _pkey;
				} _addr_pkey;
			};
		} _sigfault;

		/* SIGPOLL */
		struct {
			__ARCH_SI_BAND_T _band;	/* POLL_IN, POLL_OUT, POLL_MSG */
			int _fd;
		} _sigpoll;

		/* SIGSYS */
		struct {
			void *_call_addr; /* calling user insn */
			int _syscall;	/* triggering system call number */
			unsigned int _arch;	/* AUDIT_ARCH_* of syscall */
		} _sigsys;
	} _sifields;
};


#define PROT_SIGEV_MAX_SIZE 64
#define PROT_SIGEV_PAD_SIZE \
	((PROT_SIGEV_MAX_SIZE - (sizeof(int) * 2 + \
	sizeof(prot_sigval_t))) / sizeof(int))


struct prot_sigevent {
	prot_sigval_t sigev_value;
	int	 sigev_signo;
	int	 sigev_notify;
	union {
		int _pad[PROT_SIGEV_PAD_SIZE];
		int _tid;

		struct {
			e2k_pl_t _function;
			e2k_ptr_t _attribute;
		} _sigev_thread;
	} _sigev_un;
};


extern int copy_siginfo_to_prot_user(struct prot_siginfo __user *to,
			const struct kernel_siginfo *from);


#endif /* CONFIG_PROTECTED_MODE */

#endif /* _LINUX_PROT_SIGNAL_H */
