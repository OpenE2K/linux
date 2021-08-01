/*
 *
 * Copyright (C) 2020 MCST
 *
 * Definitions of KVM traps handling routines.
 */

#ifndef _E2K_KVM_TTABLE_HELP_H
#define _E2K_KVM_TTABLE_HELP_H

#ifdef	CONFIG_KVM_HOST_MODE
/* it is native kernel with virtualization support (hypervisor) */

#ifdef CONFIG_CPU_HW_CLEAR_RF

# ifdef GENERATING_HEADER
#  define RETURN_PV_VCPU_TRAP_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
# endif

# define CLEAR_RETURN_PV_VCPU_TRAP_WINDOW()		E2K_DONE()
# define CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(r0)	E2K_SYSCALL_RETURN(r0)
# define CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(r0)	E2K_SYSCALL_RETURN(r0)

#else	/* ! CONFIG_CPU_HW_CLEAR_RF */

# ifdef GENERATING_HEADER
#  define CLEAR_RETURN_PV_VCPU_TRAP_WINDOW()	E2K_EMPTY_CMD(: "ctpr3")
#  define CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(r0)	\
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
#  define CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(r0)	\
		E2K_EMPTY_CMD([_r0] "ir" (r0) : "ctpr3")
#  define RETURN_PV_VCPU_TRAP_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
# endif

#endif	/* CONFIG_CPU_HW_CLEAR_RF */

#else	/* !CONFIG_KVM_HOST_MODE */
/* It is native guest kernel whithout virtualization support */
/* Virtualiztion in guest mode cannot be supported */

# define CLEAR_RETURN_PV_VCPU_TRAP_WINDOW()
# define CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(rval)
# define CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(rval)

#endif	/* CONFIG_KVM_HOST_MODE */

#endif	/* _E2K_KVM_TTABLE_HELP_H */
