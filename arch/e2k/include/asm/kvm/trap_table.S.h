/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Defenition of traps handling routines.
 */

#ifndef _E2K_KVM_TRAP_TABLE_ASM_H
#define _E2K_KVM_TRAP_TABLE_ASM_H

#include <asm/asm-offsets.h>

#if defined CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
#else
# define SMP_ONLY(...)
#endif

/*
 * Save current state of pair of global registers with tags and extensions
 * gpair_lo/gpair_hi	is pair of adjacent global registers, lo is even
 *			and hi is odd (for example GCURTI/GCURTASK)
 * kreg_lo, kreg_hi	is pair of indexes of global registers into structure
 *			to save these k_gregs.g[kregd_lo/kreg_hi]
 * rbase		is register containing base address to save global
 *			registers pair values (for example glob_regs_t structure
 *			or thread_info_t thread_info->k_gregs/h_gregs)
 * predSAVE		conditional save on this predicate
 * rtmp0/rtmp1		two temporary registers (for example %dr20, %dr21)
 */

.macro	SAVE_GREGS_PAIR_COND_V3 gpair_lo, gpair_hi, kreg_lo, kreg_hi, rbase, \
				predSAVE, rtmp0, rtmp1
{
	strd,2	%dg\gpair_lo, [\rbase + (TAGGED_MEM_STORE_REC_OPC + \
					\kreg_lo * GLOB_REG_SIZE + \
					GLOB_REG_BASE)] ? \predSAVE;
	strd,5	%dg\gpair_hi, [\rbase + (TAGGED_MEM_STORE_REC_OPC + \
					\kreg_hi * GLOB_REG_SIZE + \
					GLOB_REG_BASE)] ? \predSAVE;
	movfi,1	%dg\gpair_lo, \rtmp0 ? \predSAVE;
	movfi,4	%dg\gpair_hi, \rtmp1 ? \predSAVE;
}
{
	sth	\rtmp0, [\rbase + (\kreg_lo * GLOB_REG_SIZE + \
						GLOB_REG_EXT)] ? \predSAVE;
	sth	\rtmp1, [\rbase + (\kreg_hi * GLOB_REG_SIZE + \
						GLOB_REG_EXT)] ? \predSAVE;
}
.endm	/* SAVE_GREGS_PAIR_COND_V3 */

/* Bug 116851 - all strqp must be speculative if dealing with tags */
.macro	SAVE_GREGS_PAIR_COND_V5 gpair_lo, gpair_hi, kreg_lo, kreg_hi, rbase, \
				predSAVE
{
	strqp,2,sm %dg\gpair_lo, [\rbase + (TAGGED_MEM_STORE_REC_OPC + \
						\kreg_lo * GLOB_REG_SIZE + \
						GLOB_REG_BASE)] ? \predSAVE;
	strqp,5,sm %dg\gpair_hi, [\rbase + (TAGGED_MEM_STORE_REC_OPC + \
						\kreg_hi * GLOB_REG_SIZE + \
						GLOB_REG_BASE)] ? \predSAVE;
}
.endm	/* SAVE_GREGS_PAIR_COND_V5 */

.macro	SAVE_GREG_UNEXT greg, kreg, rbase
	strqp,sm \greg, [\rbase + (TAGGED_MEM_STORE_REC_OPC + \
					\kreg * GLOB_REG_SIZE + \
					GLOB_REG_BASE)];
.endm	/* SAVE_GREG_UNEXT */

.macro	SAVE_GREGS_PAIR_UNEXT greg1, greg2, kreg1, kreg2, rbase
{
	SAVE_GREG_UNEXT \greg1, kreg1, rbase
	SAVE_GREG_UNEXT \greg2, kreg2, rbase
}
.endm	/* SAVE_GREGS_PAIR_UNEXT */

.macro	ASM_SET_KERNEL_GREGS_PAIR gpair_lo, gpair_hi, rval_lo, rval_hi
{
	addd	\rval_lo, 0, %dg\gpair_lo;
	addd	\rval_hi, 0, %dg\gpair_hi;
}
.endm	/* ASM_SET_CURRENTS_GREGS_PAIR */

.macro	DO_ASM_SET_KERNEL_GREGS_PAIR gpair_lo, gpair_hi, rval_lo, rval_hi
		ASM_SET_KERNEL_GREGS_PAIR \gpair_lo, \gpair_hi, \
						\rval_lo, \rval_hi
.endm	/* DO_ASM_SET_KERNEL_GREGS_PAIR */

.macro	SET_KERNEL_GREGS runused, rtask, rpercpu_off, rcpu
	DO_ASM_SET_KERNEL_GREGS_PAIR \
		GUEST_VCPU_STATE_GREG, CURRENT_TASK_GREG, \
		\runused, \rtask
	DO_ASM_SET_KERNEL_GREGS_PAIR \
		MY_CPU_OFFSET_GREG, SMP_CPU_ID_GREG, \
		\rpercpu_off, \rcpu
.endm	/* SET_KERNEL_GREGS */

.macro	ONLY_SET_KERNEL_GREGS runused, rtask, rpercpu_off, rcpu
		SET_KERNEL_GREGS \runused, \rtask, \rpercpu_off, \rcpu
.endm	/* ONLY_SET_KERNEL_GREGS */

#ifdef	CONFIG_KVM_HOST_KERNEL
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */
.macro	DO_SAVE_HOST_GREGS_V3 gvcpu_lo, gvcpu_hi, hvcpu_lo, hvcpu_hi \
				drti, predSAVE, drtmp, rtmp0, rtmp1
	/* drtmp: thread_info->h_gregs.g */
	addd	\drti, TI_HOST_GREGS_TO_VIRT, \drtmp ? \predSAVE;
	SAVE_GREGS_PAIR_COND_V3 \gvcpu_lo, \gvcpu_hi, \hvcpu_lo, \hvcpu_hi, \
		\drtmp,		/* thread_info->h_gregs.g base address */ \
		\predSAVE, \
		\rtmp0, \rtmp1
.endm	/* DO_SAVE_HOST_GREGS_V3 */

.macro	DO_SAVE_HOST_GREGS_V5 gvcpu_lo, gvcpu_hi, hvcpu_lo, hvcpu_hi \
				drti, predSAVE, drtmp
	/* drtmp: thread_info->h_gregs.g */
	addd	\drti, TI_HOST_GREGS_TO_VIRT, \drtmp ? \predSAVE;
	SAVE_GREGS_PAIR_COND_V5 \gvcpu_lo, \gvcpu_hi, \hvcpu_lo, \hvcpu_hi, \
		\drtmp,		/* thread_info->h_gregs.g base address */ \
		\predSAVE
.endm	/* DO_SAVE_HOST_GREGS_V5 */

.macro	SAVE_HOST_GREGS_V3 drti, predSAVE, drtmp, rtmp0, rtmp1
	DO_SAVE_HOST_GREGS_V3 \
		GUEST_VCPU_STATE_GREG, GUEST_VCPU_STATE_UNUSED_GREG, \
		VCPU_STATE_GREGS_PAIRS_INDEX, VCPU_STATE_GREGS_PAIRS_HI_INDEX, \
		\drti, \predSAVE, \
		\drtmp, \rtmp0, \rtmp1
.endm	/* SAVE_HOST_GREGS_V3 */

.macro	SAVE_HOST_GREGS_V5 drti, predSAVE, drtmp
	DO_SAVE_HOST_GREGS_V5 \
		GUEST_VCPU_STATE_GREG, GUEST_VCPU_STATE_UNUSED_GREG, \
		VCPU_STATE_GREGS_PAIRS_INDEX, VCPU_STATE_GREGS_PAIRS_HI_INDEX, \
		\drti, \predSAVE, \
		\drtmp,
.endm	/* SAVE_HOST_GREGS_V5 */

.macro	SAVE_HOST_GREGS_TO_VIRT_V3 drti, predSAVE, drtmp, rtmp0, rtmp1
		SAVE_HOST_GREGS_V3 \drti, \predSAVE, \drtmp, \rtmp0, \rtmp1
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V3 */

.macro	SAVE_HOST_GREGS_TO_VIRT_V5 drti, predSAVE, drtmp
		SAVE_HOST_GREGS_V5 \drti, \predSAVE, \drtmp
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V5 */

.macro	SAVE_HOST_GREGS_TO_VIRT_UNEXT drti, drtmp
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_UNEXT */

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/trap_table.S.h>
#else	/* ! CONFIG_KVM_HOST_KERNEL && ! CONFIG_KVM_GUEST_KERNEL */
/* It is native host kernel without any virtualization */
.macro	SAVE_HOST_GREGS_TO_VIRT_V3 drti, predSAVE, drtmp, rtmp0, rtmp1
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V3 */

.macro	SAVE_HOST_GREGS_TO_VIRT_V5 drti, predSAVE, drtmp
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V5 */

.macro	SAVE_HOST_GREGS_TO_VIRT_UNEXT drti, drtmp
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_UNEXT */

#endif	/* CONFIG_KVM_HOST_KERNEL */

#endif	/* _E2K_KVM_TRAP_TABLE_ASM_H */
