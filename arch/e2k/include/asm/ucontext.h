/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_UCONTEXT_H
#define _E2K_UCONTEXT_H

#include <linux/compat.h>
#include <uapi/asm/ucontext.h>
#include <asm/prot_compat.h>
#include <asm/prot_signal.h>

struct ucontext_32 {
	unsigned int	  uc_flags;
	unsigned int	  uc_link;
	compat_stack_t    uc_stack;
	struct sigcontext uc_mcontext;
	union {
		compat_sigset_t uc_sigmask;/* mask last for extensibility */
		unsigned long long pad[16];
	};
	struct extra_ucontext	  uc_extra; /* for compatibility */
};

struct ucontext_prot {
	unsigned long	  uc_flags;
	unsigned long	  __align;
	e2k_ptr_t	  uc_link;
	struct prot_stack uc_stack;
	struct sigcontext_prot uc_mcontext;
	union {
		sigset_t	  uc_sigmask;
		unsigned long long pad[16];
	};
	struct extra_ucontext	  uc_extra; /* for compatibility */
};

/*
 * To avoid breaking backwards compatiblity we cannot add an extra
 * field to ucontext for coroutine's key, because application can
 * be compiled with older headers without the new field.  Instead
 * we store the key in a field that makes no sense for a [fast]
 * system call.
 */
static __always_inline u64 __user *uc_coroutine_key_32(const struct ucontext_32 __user *ucp)
{
	return (u64 __user *) &ucp->uc_mcontext.nr_TIRs;
}
static __always_inline u64 __user *uc_coroutine_key_64(const struct ucontext __user *ucp)
{
	return (u64 __user *) &ucp->uc_mcontext.nr_TIRs;
}
#ifdef CONFIG_PROTECTED_MODE
static __always_inline u64 __user *uc_coroutine_key_128(const struct ucontext_prot __user *ucp)
{
	/* No uc_mcontext.nr_TIRs in protected mode so use newer field */
	return (u64 __user *) &ucp->uc_extra.ctpr1;
}
#endif	/* CONFIG_PROTECTED_MODE */

typedef struct rt_sigframe {
	u64 __pad_args[8]; /* Reserve space in data stack for the handler */
	union {
		siginfo_t		info;
		compat_siginfo_t	compat_info;
#ifdef CONFIG_PROTECTED_MODE
		struct prot_siginfo	prot_siginfo;
#endif
	};
	union {
		struct ucontext		uc;
		struct ucontext_32	uc_32;
#ifdef CONFIG_PROTECTED_MODE
		struct ucontext_prot	uc_prot;
#endif
	};

	/* Remember original return IP, so that we can detect whether
	 * signal handler has changed it (in which case we should skip trap
	 * cellar handling in sys_sigreturn). */
	u64 orig_return_ip;
} rt_sigframe_t;

extern int restore_rt_frame(const rt_sigframe_t __user *, struct k_sigaction *);

#endif	/* ! _E2K_UCONTEXT_H */
