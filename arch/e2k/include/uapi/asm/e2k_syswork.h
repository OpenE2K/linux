/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef _UAPI_E2K_SYSWORK_H_
#define _UAPI_E2K_SYSWORK_H_

#include <asm/unistd.h>
#include <asm/e2k_api.h>

/*
 * works for e2k_syswork
 */
#define PRINT_STACK		2
#define GET_ADDR_PROT		4

#define PRINT_REGS		6
#define FLUSH_CMD_CACHES	8
#define START_CLI_INFO		24
#define PRINT_CLI_INFO		25
#define PRINT_INTERRUPT_INFO	40
#define CLEAR_INTERRUPT_INFO	41
#define STOP_INTERRUPT_INFO	42
#define GET_CONTEXT		57
#define FAST_RETURN             58	/* Using to estimate time needed */
					/* for entering to OS */
#define E2K_ACCESS_VM		60      /* Deprecated */
#define PRINT_CPU_REGS		63

/* modes for sys_access_hw_stacks */
enum {
	/* Deprecated */
	E2K_READ_CHAIN_STACK,
	/* Deprecated */
	E2K_READ_PROCEDURE_STACK,
	E2K_WRITE_PROCEDURE_STACK,
	E2K_GET_CHAIN_STACK_OFFSET,
	E2K_GET_CHAIN_STACK_SIZE,
	E2K_GET_PROCEDURE_STACK_SIZE,
	/* Read chain stack in (<= iset v6) format with 32 bit `ussz` field */
	E2K_READ_CHAIN_STACK_EX,
	E2K_READ_PROCEDURE_STACK_EX,
	E2K_WRITE_PROCEDURE_STACK_EX,
	E2K_WRITE_CHAIN_STACK_EX,
	/* Read chain stack in current architecture format */
	E2K_READ_CHAIN_STACK_NATIVE,
	E2K_SYS_ACCESS_HW_STACKS_MAX,	/* must be last */
};

typedef struct icache_range {
	unsigned long long	start;
	unsigned long long	end;
} icache_range_t;

#ifndef __ptr128__
#define e2k_syswork(arg1, arg2, arg3)                                   \
({                                                                      \
	long __res;                                                     \
	__res = E2K_SYSCALL(LINUX_SYSCALL_TRAPNUM, __NR_e2k_syswork, 3, \
			arg1, arg2, arg3);                              \
	(int)__res;                                                     \
})
#endif

#endif /* _UAPI_E2K_SYSWORK_H_ */
