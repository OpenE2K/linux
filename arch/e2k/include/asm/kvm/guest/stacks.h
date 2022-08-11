/*
 * KVM guest stacks support
 * Copyright 2017 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_GUEST_STACKS_H
#define _E2K_KVM_GUEST_STACKS_H

#include <linux/types.h>
#include <asm/kvm/stacks.h>

/*
 * Guest kernel thread stacks descriptions
 */
#define	KVM_GUEST_KERNEL_C_STACK_SIZE	KERNEL_C_STACK_SIZE	/* as on host */
#define	KVM_GUEST_KERNEL_PS_SIZE	(16 * PAGE_SIZE)	/* 64 KBytes */
#define	KVM_GUEST_KERNEL_PS_INIT_SIZE	(1 * PAGE_SIZE)		/*  4 KBytes */
#define	KVM_GUEST_KERNEL_PCS_SIZE	(2 * PAGE_SIZE)		/*  8 KBytes */
#define	KVM_GUEST_KERNEL_PCS_INIT_SIZE	(1 * PAGE_SIZE)		/*  4 KBytes */

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

#endif /* ! _E2K_KVM_GUEST_STACKS_H */
