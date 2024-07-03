/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H
#define _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H

#include <linux/time.h>
#include <asm/sections.h>
#include <asm/signal.h>

int kvm_fast_sys_set_return(u64 ip, int flags);

#ifdef	CONFIG_KVM_GUEST_KERNEL

#define	goto_ttable_entry1_args3(sys_num, arg1, arg2)	\
		E2K_SCALL_ARG7(1, sys_num, arg1, arg2, 0, 0, 0, 0)
#define	goto_ttable_entry1_args4(sys_num, arg1, arg2, arg3)	\
		E2K_SCALL_ARG7(1, sys_num, arg1, arg2, arg3, 0, 0, 0)

#define	goto_ttable_entry3_args3(sys_num, arg1, arg2)	\
		E2K_SCALL_ARG7(3, sys_num, arg1, arg2, 0, 0, 0, 0)
#define	goto_ttable_entry3_args4(sys_num, arg1, arg2, arg3)	\
		E2K_SCALL_ARG7(3, sys_num, arg1, arg2, arg3, 0, 0, 0)

#endif	/* ! CONFIG_KVM_GUEST_KERNEL */

#endif /* _ASM_E2K_KVM_GUEST_FAST_SYSCALLS_H */
