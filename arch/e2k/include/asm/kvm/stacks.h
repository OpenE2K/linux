/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest stacks support
 */

#ifndef _E2K_KVM_STACKS_H
#define _E2K_KVM_STACKS_H

#include <asm/kvm/guest/stacks.h>

#ifdef	CONFIG_VIRTUALIZATION
#ifdef	CONFIG_KVM_GUEST

/* Guest kernel thread stacks descriptions */
#define	VIRT_KERNEL_C_STACK_SIZE	\
		(KVM_GUEST_KERNEL_C_STACK_SIZE + KVM_GUEST_K_DATA_GAP_SIZE)
#define	VIRT_KERNEL_PS_SIZE		KVM_GUEST_KERNEL_PS_SIZE
#define	VIRT_KERNEL_PCS_SIZE		KVM_GUEST_KERNEL_PCS_SIZE

#else	/* ! CONFIG_KVM_GUEST */
 #error	"Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST*/

#else	/* ! CONFIG_VIRTUALIZATION */
#define	VIRT_KERNEL_C_STACK_SIZE	0
#define VIRT_KERNEL_P_STACK_PAGES	0
#define VIRT_KERNEL_PC_STACK_PAGES	0
#endif	/* CONFIG_VIRTUALIZATION */

#endif /* ! _E2K_KVM_STACKS_H */
