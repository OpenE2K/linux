/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Defenition of kvm guest kernel traps handling routines.
 */

#ifndef _E2K_KVM_GUEST_TRAPS_H
#define _E2K_KVM_GUEST_TRAPS_H

#include <asm/cpu_regs_types.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/ptrace.h>
#include <asm/kvm/cpu_regs_access.h>

#include "cpu.h"

#define	KVM_SAVE_GREGS_AND_SET(thread_info)				\
({									\
	thread_info_t *__ti = (thread_info);				\
									\
	/* user global registers were saved by host kernel and will */	\
	/* be restored by host */					\
	ONLY_SET_KERNEL_GREGS(__ti);					\
})

#define	kvm_from_user_IP(cr0_hi)	\
		is_from_user_IP(cr0_hi, GUEST_TASK_SIZE)
#define	kvm_from_kernel_IP(cr0_hi)	\
		is_from_kernel_IP(cr0_hi, GUEST_TASK_SIZE)
#define	kvm_user_mode(regs)	kvm_from_user_IP((regs)->crs.cr0_hi)
#define	kvm_call_from_user_mode()					\
({									\
	e2k_cr0_hi_t cr0_hi;						\
	bool ret;							\
	cr0_hi = NATIVE_READ_CR0_HI_REG();				\
	ret = kvm_from_user_IP(cr0_hi);					\
	ret;								\
})

#endif	/* _E2K_KVM_GUEST_TRAPS_H */
