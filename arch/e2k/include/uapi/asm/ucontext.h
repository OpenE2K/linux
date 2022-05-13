#ifndef _UAPI_E2K_UCONTEXT_H
#define _UAPI_E2K_UCONTEXT_H

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
