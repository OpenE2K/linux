#ifndef _E2K_SIGINFO_H_
#define _E2K_SIGINFO_H_

#include <linux/types.h>
#include <asm/signal.h>

#define __ARCH_SI_PREAMBLE_SIZE	(4 * sizeof(int))
#define __ARCH_SI_TRAPNO
#define __ARCH_SI_BAND_T int

#include <asm-generic/siginfo.h>

#define SI_SEGV32	0x4	/* Flag to determine SIGSEGV that comes
				 * from overflow bounds in secondary space
				 */
#define SI_EXC		0x1	/* Flag to determine signal that comes
				 * from exception handler
				 */

#define SI_PAD_SIZE32	((SI_MAX_SIZE/sizeof(int)) - 3)
#define SIGEV_PAD_SIZE32 ((SIGEV_MAX_SIZE/sizeof(int)) - 3)

/*
 * SIGSEGV si_codes
 */
#define SEGV_BOUNDS	(__SI_FAULT|3)  /* Bounds overflow */
#undef	NSIGSEGV
#define NSIGSEGV	3

#endif /* _E2K_SIGINFO_H_ */
