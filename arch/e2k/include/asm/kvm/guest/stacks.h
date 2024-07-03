/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest stacks support
 */

#ifndef _E2K_KVM_GUEST_STACKS_H
#define _E2K_KVM_GUEST_STACKS_H

#include <linux/types.h>
#include <asm/kvm/stacks.h>

/*
 * Guest kernel thread stacks descriptions
 */
#define KVM_GUEST_K_DATA_GAP_SIZE	\
		NATIVE_K_DATA_GAP_SIZE			/* same as on host */
#define	KVM_GUEST_KERNEL_C_STACK_SIZE	\
		(NATIVE_KERNEL_C_STACK_SIZE + 4 * PAGE_SIZE)	/* a few more */ \
								/* than host */
#define	KVM_GUEST_KERNEL_PS_SIZE	(16 * PAGE_SIZE)	/* 64 KBytes */
#define	KVM_GUEST_KERNEL_PCS_SIZE	(2 * PAGE_SIZE)		/*  8 KBytes */

/*
 * Guest user task stacks descriptions
 */
#define	KVM_GUEST_USER_DATA_STACK_SIZE	\
		DEFAULT_USER_DATA_STACK_SIZE			/* as on host */
#define	KVM_GUEST_USER_PS_MAX_SIZE	USER_P_STACK_SIZE	/* as on host */
#define	KVM_GUEST_USER_PS_INIT_SIZE	USER_P_STACK_INIT_SIZE	/* as on host */
#define	KVM_GUEST_USER_PS_PRESENT_SIZE	USER_P_STACK_PRESENT_SIZE /* --''-- */
#define	KVM_GUEST_USER_PCS_MAX_SIZE	USER_PC_STACK_SIZE	/* as on host */
#define	KVM_GUEST_USER_PCS_INIT_SIZE	USER_PC_STACK_INIT_SIZE	/* as on host */
#define	KVM_GUEST_USER_PCS_PRESENT_SIZE	USER_PC_STACK_PRESENT_SIZE /* --''-- */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* pure guest kernel (not common host & guest paravirtualized) */
#define K_DATA_GAP_SIZE		KVM_GUEST_K_DATA_GAP_SIZE
#define	KERNEL_C_STACK_SIZE	KVM_GUEST_KERNEL_C_STACK_SIZE

#define	KERNEL_P_STACK_SIZE	KVM_GUEST_KERNEL_PS_SIZE
#define	KERNEL_PC_STACK_SIZE	KVM_GUEST_KERNEL_PCS_SIZE

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_GUEST_STACKS_H */
