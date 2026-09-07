/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef _UAPI_E2K_UCONTEXT_H
#define _UAPI_E2K_UCONTEXT_H

/*
 * If signal handler sets this when changing return IP in
 * ucontext.uc_mcontext.cr0_hi then sys_sigreturn will handle
 * remaining trap cellar entries.
 */
#define UC_HANDLE_SIGRETURN_CELLAR	1

struct ucontext {
	unsigned long	  uc_flags;
	struct ucontext  *uc_link;
	stack_t		  uc_stack;
	struct sigcontext uc_mcontext;
	union {
		sigset_t	  uc_sigmask;/* mask last for extensibility */
		unsigned long long pad[16];
	};
	struct extra_ucontext	  uc_extra; /* for compatibility */
};

#endif /* _UAPI_E2K_UCONTEXT_H */
