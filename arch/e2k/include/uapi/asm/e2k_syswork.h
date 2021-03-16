#ifndef _UAPI_E2K_SYSWORK_H_
#define _UAPI_E2K_SYSWORK_H_

#include <asm/unistd.h>
#include <asm/e2k_api.h>

/*
 * IDE info
 */
#define ALL_IDE		1
#define USING_DMA	2

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
#define SET_TAGS		17
#define CHECK_TAGS		18
#define IDE_INFO		20
#define INSTR_EXEC		21
#define IREQ_SET_TO_CPU		22
#define PRINT_T_TRUSS		23
#define START_CLI_INFO		24
#define PRINT_CLI_INFO		25
#define SYS_MKNOD		26
#define SET_DBG_MODE		27
#define E2K_SC_RESTART		28
#define PRINT_PIDS		29
#define ADD_END_OF_WORK		30
#define GET_END_OF_WORK		31
#define START_OF_WORK		32
#define DO_E2K_HALT		33
#ifdef CONFIG_PROC_FS
#define PRINT_STATM		35
#endif
#define	READ_ECMOS		36
#define	WRITE_ECMOS		37
#define KERNEL_TRACE_BEGIN	38
#define KERNEL_TRACE_END	39
#define PRINT_INTERRUPT_INFO	40
#define CLEAR_INTERRUPT_INFO	41
#define STOP_INTERRUPT_INFO	42
#define START_TRACE_EVENT       45
#define STOP_TRACE_EVENT        46
#define START_TRACE_LAST_EVENT  48
#define STOP_TRACE_LAST_EVENT   49
#define READ_BOOT		53
#define WRITE_BOOT		54
#define READ_PTRACE_REGS	55
#define WRITE_PTRACE_REGS	56
#define GET_CONTEXT		57
#define FAST_RETURN             58	/* Using to estimate time needed */
					/* for entering to OS */
#define TEST_OVERFLOW		59	/* To test kernel procedure/chain */
					/* stack overflow */
#define E2K_ACCESS_VM		60      /* Read/write current procedure */
					/* stack */
#define KERNEL_FTRACE		61
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
