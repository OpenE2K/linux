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
#define PRINT_MMAP		1
#define PRINT_STACK		2
#define PRINT_TASKS		3
#define GET_ADDR_PROT		4
#define PRINT_REGS		6
#define PRINT_ALL_MMAP		7
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
#define USER_CONTROL_INTERRUPT	62      /* user can control all interrupts */
					/* (for degugging hardware) */


/* modes for sys_access_hw_stacks */
enum {
	E2K_READ_CHAIN_STACK,
	E2K_READ_PROCEDURE_STACK,
	E2K_WRITE_PROCEDURE_STACK,
	E2K_GET_CHAIN_STACK_OFFSET,
	E2K_GET_CHAIN_STACK_SIZE,
	E2K_GET_PROCEDURE_STACK_SIZE,
	E2K_READ_CHAIN_STACK_EX,
	E2K_READ_PROCEDURE_STACK_EX,
	E2K_WRITE_PROCEDURE_STACK_EX,
	E2K_WRITE_CHAIN_STACK_EX,
};

typedef struct icache_range {
	unsigned long long	start;
	unsigned long long	end;
} icache_range_t;

#define e2k_syswork(arg1, arg2, arg3)                                   \
({                                                                      \
	long __res;                                                     \
	__res = E2K_SYSCALL(LINUX_SYSCALL_TRAPNUM, __NR_e2k_syswork, 3, \
			arg1, arg2, arg3);                              \
	(int)__res;                                                     \
})

#endif /* _UAPI_E2K_SYSWORK_H_ */
