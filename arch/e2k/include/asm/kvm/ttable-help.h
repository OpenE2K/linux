/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Definitions of KVM traps handling routines.
 */

#ifndef _E2K_KVM_TTABLE_HELP_H
#define _E2K_KVM_TTABLE_HELP_H

#ifdef	CONFIG_KVM_HOST_KERNEL
/* it is native kernel with virtualization support (hypervisor) */

#ifdef CONFIG_CPU_HW_CLEAR_RF

# ifdef GENERATING_HEADER
#  define RETURN_PV_VCPU_TRAP_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
# endif

# define CLEAR_RETURN_PV_VCPU_TRAP_WINDOW_ASM		E2K_DONE_RNDPR_ASM
# define CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(r0, rndpr) E2K_SYSCALL_RETURN(r0, rndpr)
# define CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(r0, rndpr) E2K_SYSCALL_RETURN(r0, rndpr)

#else	/* ! CONFIG_CPU_HW_CLEAR_RF */

# ifdef GENERATING_HEADER
#  define CLEAR_RETURN_PV_VCPU_TRAP_WINDOW(_rndpr) \
		E2K_DUMMY_CLEARWINDOW([rndpr] "ir" (AW(_rndpr)) : "ctpr3")
#  define CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(r0, _rndpr)	\
		E2K_DUMMY_CLEARWINDOW([_r0] "ir" (r0), [rndpr] "ir" (AW(_rndpr)) : "ctpr3")
#  define CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(r0, _rndpr)	\
		E2K_DUMMY_CLEARWINDOW([_r0] "ir" (r0), [rndpr] "ir" (AW(_rndpr)) : "ctpr3")
#  define RETURN_PV_VCPU_TRAP_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_CALL_SIZE 0x1
#  define HANDLE_PV_VCPU_SYS_FORK_SIZE 0x1
# endif

#endif	/* CONFIG_CPU_HW_CLEAR_RF */

#else	/* !CONFIG_KVM_HOST_KERNEL */
/* It is native guest kernel whithout virtualization support */
/* Virtualiztion in guest mode cannot be supported */

# define CLEAR_RETURN_PV_VCPU_TRAP_WINDOW(rndpr)
# define CLEAR_HANDLE_PV_VCPU_SYS_CALL_WINDOW(rval, rndpr)
# define CLEAR_HANDLE_PV_VCPU_SYS_FORK_WINDOW(rval, rndpr)

#endif	/* CONFIG_KVM_HOST_KERNEL */

#endif	/* _E2K_KVM_TTABLE_HELP_H */
