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

#ifdef CONFIG_COMPAT
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
#endif

#ifdef CONFIG_PROTECTED_MODE
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
#endif	/* CONFIG_PROTECTED_MODE */

typedef struct rt_sigframe {
	u64 __pad_args[8]; /* Reserve space in data stack for the handler */
	union {
		siginfo_t		info;
#ifdef CONFIG_COMPAT
		compat_siginfo_t	compat_info;
#endif
#ifdef CONFIG_PROTECTED_MODE
		struct prot_siginfo	prot_siginfo;
#endif
	};
	union {
		struct ucontext		uc;
#ifdef CONFIG_COMPAT
		struct ucontext_32	uc_32;
#endif
#ifdef CONFIG_PROTECTED_MODE
		struct ucontext_prot	uc_prot;
#endif
	};
} rt_sigframe_t;

extern int restore_rt_frame(rt_sigframe_t __user *frame, struct k_sigaction *);

#endif	/* ! _E2K_UCONTEXT_H */
