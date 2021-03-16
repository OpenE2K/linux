/*
 *
 * Copyright (C) 2018 MCST
 *
 * Defenition of guest kernel traps handling routines.
 */

#ifndef _E2K_KVM_GUEST_TRAP_TABLE_ASM_H
#define _E2K_KVM_GUEST_TRAP_TABLE_ASM_H

#ifdef	__ASSEMBLY__

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is guest virtualized kernel */

/*
 * goto guest kernel system call table entry, if system call is from guest user
 * rti: register of current_thread_info()
 * rtmp0 rtmp1 rtmp2: temporary registers
 * ptmp0 ptmp1: temporary predicates
 */
.macro	KVM_GOTO_PV_VCPU_KERNEL_TTABLE entry_num rti rtmp0 rtmp1 rtmp2 \
						ptmp0 ptmp1
	/* not used */
.endm	/* GOTO_GUEST_KERNEL_TTABLE */

#ifdef	CONFIG_KVM_GUEST_HW_PV
/* guest virtualization based on hardware virtualized hypervisor */

.macro	NEED_SAVE_CUR_AND_VCPU_STATE_GREGS drti, predV5, \
					drtmp0, drtmp1, predtmp, \
					predCUR, predVCPU, predEXTk
	/*
	 * Native trap handler and these macroses is used only
	 *	if IS_HW_GM() == true
	 * so need not any additional conditions to calculate.
	 * drti - pointer to thread_info
	 * predV5 - ISET is >= V5
	 * predCUR - is now set to true (trap from user) and cannot be updated:
	 *    trap on guest user and (GCURTI & GCURTASK & CPU_ID & CPU_OFF)
	 *    should be saved same as native or host mode
	 * %predVCPU - save VCPU state pointer regs:
	 *    set same as %predCUR
	 * predEXTk - need save kernel (predCUR) & need save extention (!predV5)
	 */
	{
	pass	\predV5, @p0;
	pass	\predCUR, @p1;
	landp	@p1, @p1, @p5;
	landp	~@p0, @p1, @p4;
	pass	@p5, \predVCPU;
	pass	@p4, \predEXTk;
	}
.endm	/* NEED_SAVE_CUR_AND_VCPU_STATE_GREGS */

/* guest VCPU state registers are saved at thread_info->h_gregs */
/* same as by host for paravirtualized guest */

.macro	DO_SAVE_HOST_GREGS_V2 gvcpu_lo, gvcpu_hi, hvcpu_lo, hvcpu_hi \
				drti, predSAVE, drtmp, rtmp0, rtmp1
	/* drtmp: thread_info->h_gregs.g */
	addd	\drti, TI_HOST_GREGS_TO_VIRT, \drtmp ? \predSAVE;
	SAVE_GREGS_PAIR_COND_V2 \gvcpu_lo, \gvcpu_hi, \hvcpu_lo, \hvcpu_hi, \
		\drtmp,		/* thread_info->h_gregs.g base address */ \
		\predSAVE, \
		\rtmp0, \rtmp1
.endm	/* DO_SAVE_HOST_GREGS_V2 */

.macro	DO_SAVE_HOST_GREGS_V5 gvcpu_lo, gvcpu_hi, hvcpu_lo, hvcpu_hi \
				drti, predSAVE, drtmp
	/* drtmp: thread_info->h_gregs.g */
	addd	\drti, TI_HOST_GREGS_TO_VIRT, \drtmp ? \predSAVE;
	SAVE_GREGS_PAIR_COND_V5 \gvcpu_lo, \gvcpu_hi, \hvcpu_lo, \hvcpu_hi, \
		\drtmp,		/* thread_info->h_gregs.g base address */ \
		\predSAVE
.endm	/* DO_SAVE_HOST_GREGS_V5 */

.macro	SAVE_HOST_GREGS_V2 drti, predSAVE, drtmp, rtmp0, rtmp1
	DO_SAVE_HOST_GREGS_V2 \
		GUEST_VCPU_STATE_GREG, GUEST_VCPU_STATE_UNUSED_GREG, \
		VCPU_STATE_GREGS_PAIRS_INDEX, VCPU_STATE_GREGS_PAIRS_HI_INDEX, \
		\drti, \predSAVE, \
		\drtmp, \rtmp0, \rtmp1
.endm	/* SAVE_HOST_GREGS_V2 */

.macro	SAVE_HOST_GREGS_V5 drti, predSAVE, drtmp
	DO_SAVE_HOST_GREGS_V5 \
		GUEST_VCPU_STATE_GREG, GUEST_VCPU_STATE_UNUSED_GREG, \
		VCPU_STATE_GREGS_PAIRS_INDEX, VCPU_STATE_GREGS_PAIRS_HI_INDEX, \
		\drti, \predSAVE, \
		\drtmp,
.endm	/* SAVE_HOST_GREGS_V5 */

.macro	SAVE_HOST_GREGS_UNEXT gvcpu, hvcpu, drti, drtmp
	/* drtmp: thread_info->h_gregs.g */
	addd	\drti, TI_HOST_GREGS_TO_VIRT, \drtmp;
	SAVE_GREG_UNEXT \gvcpu, \hvcpu, \drtmp
.endm	/* SAVE_HOST_GREGS_UNEXT */

.global	vcpus_state;

.macro	SET_VCPU_STATE_GREGS drti, predSAVE, drtmp
	ldw	[ \drti + TSK_TI_CPU_DELTA ], \drtmp ? \predSAVE /* VCPU # */
	shld	\drtmp, 3, \drtmp ? \predSAVE
	ldd	[ \drtmp + vcpus_state ], GVCPUSTATE ? \predSAVE
.endm	/* SET_VCPU_STATE_GREGS */

.macro	SET_VCPU_STATE_GREGS_UNCOND drti, drtmp
	ldw	[ \drti + TSK_TI_CPU_DELTA ], \drtmp	/* VCPU # */
	shld	\drtmp, 3, \drtmp
	ldd	[ \drtmp + vcpus_state ], GVCPUSTATE
.endm	/* SET_VCPU_STATE_GREGS */

.macro	SAVE_HOST_GREGS_TO_VIRT_V2 drti, predSAVE, drtmp, rtmp0, rtmp1
		SAVE_HOST_GREGS_V2 \drti, \predSAVE, \drtmp, \rtmp0, \rtmp1
		SET_VCPU_STATE_GREGS \drti, \predSAVE, \drtmp
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V2 */

.macro	SAVE_HOST_GREGS_TO_VIRT_V5 drti, predSAVE, drtmp
		SAVE_HOST_GREGS_V5 \drti, \predSAVE, \drtmp
		SET_VCPU_STATE_GREGS \drti, \predSAVE, \drtmp
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V5 */

.macro	SAVE_HOST_GREGS_TO_VIRT_UNEXT drti, drtmp
		SAVE_HOST_GREGS_UNEXT GVCPUSTATE, \
				VCPU_STATE_GREGS_PAIRS_INDEX, \
				\drti, \drtmp
		SET_VCPU_STATE_GREGS_UNCOND \drti, \drtmp
.endm	/* SAVE_HOST_GREGS_TO_VIRT_UNEXT */

#else	/* ! CONFIG_KVM_GUEST_HW_PV */
/* It is virtualized guest based on paravirtualized hypervisor */
/* without hardware support of virtualization */

.macro	NEED_SAVE_CUR_AND_VCPU_STATE_GREGS drti, predV5, \
					drtmp0, drtmp1, predtmp, \
					predCUR, predVCPU, predEXTk
	/* not used */
.endm	/* NEED_SAVE_CUR_AND_VCPU_STATE_GREGS */

.macro	SAVE_HOST_GREGS_TO_VIRT_V2 drti, predSAVE, drtmp, rtmp0, rtmp1
	/* not used */
.endm	/* SAVE_VCPU_STATE_GREGS */

.macro	SAVE_HOST_GREGS_TO_VIRT_V5 drti, predSAVE, drtmp
	/* not used */
.endm	/* SAVE_GREGS_TO_VIRT */

.macro	SAVE_HOST_GREGS_TO_VIRT_UNEXT drti, drtmp
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_UNEXT */

#endif	/* CONFIG_KVM_GUEST_HW_PV */
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASSEMBLY__ */

#endif	/* _E2K_KVM_GUEST_TRAP_TABLE_ASM_H */
