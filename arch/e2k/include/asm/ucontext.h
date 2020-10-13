#ifndef _E2K_UCONTEXT_H
#define _E2K_UCONTEXT_H

#include <uapi/asm/ucontext.h>

struct ucontext_32 {
	unsigned int	  uc_flags;
	unsigned int	  uc_link;
	compat_stack_t    uc_stack;
	struct sigcontext uc_mcontext;
	union {
		sigset32_t	  uc_sigmask;/* mask last for extensibility */
		unsigned long long pad[16];
	};
	struct extra_ucontext	  uc_extra; /* for compatibility */
};

#ifdef CONFIG_PROTECTED_MODE
struct ucontext_prot {
	unsigned long	  uc_flags;
	unsigned long	  __align;
	e2k_ptr_t	  uc_link;
	stack_prot_t	  uc_stack;
	struct sigcontext_prot uc_mcontext;
	union {
		sigset_t	  uc_sigmask;
		unsigned long long pad[16];
	};
	struct extra_ucontext	  uc_extra; /* for compatibility */
};
#endif	/* CONFIG_PROTECTED_MODE */
#endif	/* ! _E2K_UCONTEXT_H */
