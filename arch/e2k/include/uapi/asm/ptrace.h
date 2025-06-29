/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef _UAPI_E2K_PTRACE_H
#define _UAPI_E2K_PTRACE_H


#ifndef __ASSEMBLY__

/* 0x4200-0x4300 are reserved for architecture-independent additions.  */
#define PTRACE_SETOPTIONS         0x4200

struct e2k_debug_regs {
	unsigned long long dibcr;
	unsigned long long ddbcr;
	unsigned long long dibar[4];
	unsigned long long ddbar[4];
	unsigned long long dimcr;
	unsigned long long ddmcr;
	unsigned long long dimar[2];
	unsigned long long ddmar[2];
	unsigned long long dibsr;
	unsigned long long ddbsr;

/*
 * iset v6 additions
 */
	unsigned long long dimtp_lo;
	unsigned long long dimtp_hi;

/*
 * iset v7 additions
 */
	unsigned long long ddmcr1;
	unsigned long long ddmar2;
	unsigned long long ddmar3;

	unsigned long long dimcr1;
	unsigned long long dimar2;
	unsigned long long dimar3;
};

#endif /* __ASSEMBLY__ */
#endif /* _UAPI_E2K_PTRACE_H */
