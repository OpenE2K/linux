#ifndef _E2K_SIGCONTEXT_H_
#define _E2K_SIGCONTEXT_H_

#include <uapi/asm/sigcontext.h>

#ifdef CONFIG_PROTECTED_MODE
struct sigcontext_prot {
	unsigned long long	cr0_lo;
	unsigned long long	cr0_hi;
	unsigned long long	cr1_lo;
	unsigned long long	cr1_hi;
	unsigned long long	sbr;	 /* 21 Stack base register: top of */
					 /*    local data (user) stack */
	unsigned long long	usd_lo;	 /* 22 Local data (user) stack */
	unsigned long long	usd_hi;	 /* 23 descriptor: base & size */
	unsigned long long	psp_lo;	 /* 24 Procedure stack pointer: */
	unsigned long long	psp_hi;	 /* 25 base & index & size */
	unsigned long long	pcsp_lo; /* 26 Procedure chain stack */
	unsigned long long	pcsp_hi; /* 27 pointer: base & index & size */
};
#endif
#endif /* _E2K_SIGCONTEXT_H_ */
