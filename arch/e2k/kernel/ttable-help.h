/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Defenition of traps handling routines.
 */

#ifndef _E2K_KERNEL_TTABLE_HELP_H
#define _E2K_KERNEL_TTABLE_HELP_H

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/trap_def.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>

#include <asm/kvm/ttable-help.h>


#ifdef CONFIG_KVM_GUEST_KERNEL

/* Non-privileged guest kernel has its kernel's
 * registers cleaned by hypervisor when it restores
 * guest user context upon return from guest kernel,
 * so it should not clear anything. */
# define USER_TRAP_HANDLER_SIZE 0x1
# define TTABLE_ENTRY_8_SIZE 0x1
# define RET_FROM_FORK_SIZE 0x1
# define HANDLE_SYS_CALL_SIZE 0x1
# define DO_SIGRETURN_SIZE 0x1
# define KVM_TRAP_HANDLER_SIZE 0x1
# define RETURN_PV_VCPU_TRAP_SIZE 0x1
# define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
# define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
# define FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE 0x1
# define FINISH_SYSCALL_SW_FILL_SIZE 0x1
# define RETURN_TO_INJECTED_SYSCALL_SW_FILL_SIZE 0x1

# define CLEAR_USER_TRAP_HANDLER_WINDOW()	NATIVE_RETURN()
# define CLEAR_TTABLE_ENTRY_8_WINDOW(r0)	E2K_SYSCALL_RETURN(r0)
# define CLEAR_TTABLE_ENTRY_8_WINDOW_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_PSYSCALL_RETURN(r0, r1, r2, r3, tag2, tag3)
# define CLEAR_RET_FROM_FORK_WINDOW(r0)		E2K_SYSCALL_RETURN(r0)
# define CLEAR_HANDLE_SYS_CALL_WINDOW(r0)	E2K_SYSCALL_RETURN(r0)
# define CLEAR_DO_SIGRETURN_INTERRUPT()		NATIVE_RETURN()
# define CLEAR_DO_SIGRETURN_SYSCALL(r0)		E2K_SYSCALL_RETURN(r0)
# define CLEAR_DO_SIGRETURN_SYSCALL_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_PSYSCALL_RETURN(r0, r1, r2, r3, tag2, tag3)

#elif defined CONFIG_CPU_HW_CLEAR_RF

# if defined GENERATING_HEADER
#  define USER_TRAP_HANDLER_SIZE 0x1
#  define TTABLE_ENTRY_8_SIZE 0x1
#  define RET_FROM_FORK_SIZE 0x1
#  define HANDLE_SYS_CALL_SIZE 0x1
#  define DO_SIGRETURN_SIZE 0x1
#  define KVM_TRAP_HANDLER_SIZE 0x1
#  define RETURN_PV_VCPU_TRAP_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
#  define FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE 0x1
#  define FINISH_SYSCALL_SW_FILL_SIZE 0x1
#  define RETURN_TO_INJECTED_SYSCALL_SW_FILL_SIZE 0x1
# else
#  include "ttable_wbs.h"
# endif

# define CLEAR_USER_TRAP_HANDLER_WINDOW()	E2K_DONE()
# define CLEAR_TTABLE_ENTRY_8_WINDOW(r0)	E2K_SYSCALL_RETURN(r0)
# define CLEAR_TTABLE_ENTRY_8_WINDOW_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_PSYSCALL_RETURN(r0, r1, r2, r3, tag2, tag3)
# define CLEAR_RET_FROM_FORK_WINDOW(r0)		E2K_SYSCALL_RETURN(r0)
# define CLEAR_HANDLE_SYS_CALL_WINDOW(r0)	E2K_SYSCALL_RETURN(r0)
# define CLEAR_DO_SIGRETURN_INTERRUPT()		E2K_DONE()
# define CLEAR_DO_SIGRETURN_SYSCALL(r0)		E2K_SYSCALL_RETURN(r0)
# define CLEAR_DO_SIGRETURN_SYSCALL_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_PSYSCALL_RETURN(r0, r1, r2, r3, tag2, tag3)

#else	/* ! CONFIG_CPU_HW_CLEAR_RF */

# ifdef GENERATING_HEADER
#  define CLEAR_USER_TRAP_HANDLER_WINDOW()	E2K_EMPTY_CMD(: "ctpr3")
#  define CLEAR_TTABLE_ENTRY_8_WINDOW(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
#  define CLEAR_TTABLE_ENTRY_8_WINDOW_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_EMPTY_CMD([_r0] "ir" (r0), [_r1] "ir" (r1), \
			      [_r2] "ir" (r2), [_r3] "ir" (r3), \
			      [_tag2] "ir" (tag2), [_tag3] "ir" (tag3) \
			      : "ctpr3")
#  define CLEAR_RET_FROM_FORK_WINDOW(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
#  define CLEAR_HANDLE_SYS_CALL_WINDOW(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
#  define CLEAR_DO_SIGRETURN_INTERRUPT()	E2K_EMPTY_CMD(: "ctpr3")
#  define CLEAR_DO_SIGRETURN_SYSCALL(r0) \
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
#  define CLEAR_DO_SIGRETURN_SYSCALL_PROT(r0, r1, r2, r3, tag2, tag3) \
		E2K_EMPTY_CMD([_r0] "ir" (r0), [_r1] "ir" (r1), \
			      [_r2] "ir" (r2), [_r3] "ir" (r3), \
			      [_tag2] "ir" (tag2), [_tag3] "ir" (tag3) \
			      : "ctpr3")
#  define USER_TRAP_HANDLER_SIZE 0x1
#  define TTABLE_ENTRY_8_SIZE 0x1
#  define RET_FROM_FORK_SIZE 0x1
#  define HANDLE_SYS_CALL_SIZE 0x1
#  define DO_SIGRETURN_SIZE 0x1
#  define KVM_TRAP_HANDLER_SIZE 0x1
#  define RETURN_PV_VCPU_TRAP_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
#  define FINISH_USER_TRAP_HANDLER_SW_FILL_SIZE 0x1
#  define FINISH_SYSCALL_SW_FILL_SIZE 0x1
#  define RETURN_TO_INJECTED_SYSCALL_SW_FILL_SIZE 0x1
# else
#  include "ttable_asm.h"
#  include "ttable_wbs.h"
# endif

#endif	/* CONFIG_CPU_HW_CLEAR_RF */

#endif	/* _E2K_KERNEL_TTABLE_HELP_H */
