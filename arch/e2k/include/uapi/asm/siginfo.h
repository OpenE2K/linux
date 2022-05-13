#ifndef _E2K_SIGINFO_H_
#define _E2K_SIGINFO_H_

#include <linux/types.h>
#include <asm/signal.h>

#define __ARCH_SI_TRAPNO
#define __ARCH_SI_BAND_T int

#include <asm-generic/siginfo.h>

#define SI_PAD_SIZE32	((SI_MAX_SIZE/sizeof(int)) - 3)
#define SIGEV_PAD_SIZE32 ((SIGEV_MAX_SIZE/sizeof(int)) - 3)

/*
 * SIGTRAP si_codes
 */
#define DIAG_CT		3  /* Diagnostic CT condition */
#define DIAG_ADDR	4  /* Diagnostic address */
#define DIAG_PRED	5  /* Diagnostic predicate */
#define DIAG_OP		6  /* Diagnostic operand */
#define MEM_LOCK	7  /* Memory lock */
#undef	NSIGTRAP
#define NSIGTRAP	6

#endif /* _E2K_SIGINFO_H_ */
