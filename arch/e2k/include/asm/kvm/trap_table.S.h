/*
 *
 * Copyright (C) 2015 MCST
 *
 * Defenition of traps handling routines.
 */

#ifndef _E2K_KVM_TRAP_TABLE_ASM_H
#define _E2K_KVM_TRAP_TABLE_ASM_H

#ifdef	__ASSEMBLY__

#include <asm/thread_info.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/glob_regs.h>
#include <asm/mmu_regs_types.h>

#include <generated/asm-offsets.h>

#if defined CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
#else
# define SMP_ONLY(...)
#endif

#ifdef	CONFIG_KVM_HOST_MODE
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */

.macro	DO_SWITCH_TO_KERNEL_IMAGE_PGD rti, predN, rtmp0, rtmp1, rtmp2
	/* do switch to host kernel image			*/
	/* thread_info_t *ti = rti				*/
	/* %pred_no is true to switch to kernel image pgd	*/
	/* if guest and host kernel images are loaded to equal	*/
	/* addresses, then switch from one to another must	*/
	/* flush all caches, including TLB			*/
	/* if (%pred_no) {					*/
	/*	native_flush_TLB_all();				*/
	/*	native_flush_CACHE_all();			*/
	/*	E2K_WAIT_FLUSH;					*/
	/* }							*/
{
	ldd	[\rti + TI_KERNEL_IMAGE_PGD_P], \rtmp1 ? \predN;
	ldd	[\rti + TI_KERNEL_IMAGE_PGD], \rtmp2 ? \predN;
	addd	0, 0, \rtmp0 ? \predN;
}
{
	std,2	\rtmp0, [_FLUSH_TLB_ALL_OP] MAS_TLB_FLUSH ? \predN;
	std	\rtmp2, [\rtmp1] ? \predN;
}
{
	std,2	\rtmp0, [_FLUSH_CACHE_L12_OP] MAS_CACHE_FLUSH ? \predN;
}
	wait	fl_c = 1;
.endm	/* DO_SWITCH_TO_KERNEL_IMAGE_PGD */

.macro	SWITCH_TO_KERNEL_IMAGE_PGD rti predN rtmp0, rtmp1, rtmp2
	/* switch to host kernel image				*/
	/* thread_info_t *ti = rti;				*/
	/* if (ti->flags & _TIF_PARAVIRT_GUEST) {		*/
	/*	*ti->kernel_image_pgd_p = ti->kernel_image_pgd;	*/
	/*	native_flush_TLB_all();				*/
	/*	native_flush_CACHE_all();			*/
	/*	E2K_WAIT_FLUSH;					*/
	/* }							*/
	/* rti: current_thread_info				*/
	ldd	[\rti + TI_FLAGS], \rtmp0;
	cmpandedb \rtmp0, _TIF_PARAVIRT_GUEST, \predN;
{
	pass	\predN, @p0;
	landp	~@p0, ~@p0, @p4;
	pass	@p4, \predN;
}
	DO_SWITCH_TO_KERNEL_IMAGE_PGD \rti, \predN, \rtmp0, \rtmp1, \rtmp2
.endm

/*
 * goto guest kernel system call table entry, if system call is from guest user
 * rti: register of current_thread_info()
 * rtmp0 rtmp1 rtmp2: temporary registers
 * ptmp0 ptmp1 ptmp2: temporary predicates
 */
.macro	GOTO_GUEST_KERNEL_TTABLE entry_num rti rtmp0 rtmp1 rtmp2	\
						ptmp0 ptmp1 ptmp2
	/* thread_info_t *ti = %dr7				*/
	/* e2k_cr1_lo_t cr1_lo = NATIVE_READ_CR1_LO_REG();	*/
	/*							*/
	/* if ((ti->flags & _TIF_VIRTUALIZED_GUEST)) && {	*/
	/*	!(cr1_lo.CR1_lo_psr & PSR_PM)) {		*/
	/*	if (ti->flags & _TIF_PARAVIRT_GUEST) {		*/
	/*		DO_SWITCH_TO_KERNEL_IMAGE_PGD()		*/
	/*	}						*/
	/*	goto goto_guest_kernel_ttable_C(		*/
	/*			sys_num << 32 | entry,		*/
	/*			arg1, arg2, arg3, arg4,		*/
	/*			arg5, arg6);			*/
	/* }							*/

.global	goto_guest_kernel_ttable_C;
{
	rrd	%cr1.lo, \rtmp1;
	ldd	[\rti + TI_FLAGS], \rtmp0;
	sxt	2, %r0, %dr0;
}
{
	cmpandedb \rtmp1, CR1_LO_PSR_PM_MASK, \ptmp1;
	cmpandedb \rtmp0, _TIF_VIRTUALIZED_GUEST, \ptmp0;
	cmpandedb \rtmp0, _TIF_PARAVIRT_GUEST, \ptmp2;
}
{
	pass	\ptmp0, @p0;
	pass	\ptmp1, @p1;
	landp	~@p0, @p1, @p4;
	pass	@p4, \ptmp0;
	pass	\ptmp2, @p2;
	landp	~@p2, ~@p2, @p5;
	pass	@p5, \ptmp1;
}
{
	puttagd	%dr1, 0, %dr1 ? \ptmp0;
	puttagd	%dr2, 0, %dr2 ? \ptmp0;
	shld	%dr0, 32, %dr0 ? \ptmp0;
}
{
	SMP_ONLY(shld,1 GCPUID, 3, GCPUOFFSET ? \ptmp0)
	puttagd	%dr3, 0, %dr3 ? \ptmp0;
	puttagd	%dr4, 0, %dr4 ? \ptmp0;
	ord	%dr0, \entry_num, %dr0 ? \ptmp0;
}
{
	puttagd	%dr5, 0, %dr5 ? \ptmp0;
	puttagd	%dr6, 0, %dr6 ? \ptmp0;
}
	/* rti: current_thread_info */
	/* ptmp1 : predicate is true if need switch kernel image pgd */
	/* rtmp0, rtmp1, rtmp2: temporary registers */
	DO_SWITCH_TO_KERNEL_IMAGE_PGD \rti, \ptmp1, \rtmp0, \rtmp1, \rtmp2
{
	SMP_ONLY(ldd,2 [ __per_cpu_offset + GCPUOFFSET ], GCPUOFFSET ? \ptmp0)
	puttagd	%dr7, 0, %dr7 ? \ptmp0;
	ibranch	goto_guest_kernel_ttable_C ? \ptmp0;
}
.endm	/* GOTO_GUEST_KERNEL_TTABLE */

# ifdef CONFIG_PARAVIRT_GUEST
/*
 * goto guest kernel system call table entry, if system call is from guest user
 * rti: register of current_thread_info()
 * rtmp0 rtmp1 rtmp2: temporary registers
 * ptmp0 ptmp1: temporary predicates
 */
.macro	GOTO_PV_VCPU_KERNEL_TTABLE rti rtmp0 rtmp1 rtmp2 ptmp1
	/* thread_info_t *ti = %dr7				*/
	/* e2k_cr1_lo_t cr1_lo = NATIVE_READ_CR1_LO_REG();	*/
	/*							*/
	/*	if (ti->flags & _TIF_PARAVIRT_GUEST) {		*/
	/*		DO_SWITCH_TO_KERNEL_IMAGE_PGD()		*/
	/*	}						*/

{
	ldd	[\rti + TI_FLAGS], \rtmp0;
	sxt	2, %r0, %dr0;
}
{
	cmpandedb \rtmp0, _TIF_PARAVIRT_GUEST, \ptmp1;
}
{
	pass	\ptmp1, @p2;
	landp	~@p2, ~@p2, @p5;
	pass	@p5, \ptmp1;
}
	/* rti: current_thread_info */
	/* ptmp1 : predicate is true if need switch kernel image pgd */
	/* rtmp0, rtmp1, rtmp2: temporary registers */
	DO_SWITCH_TO_KERNEL_IMAGE_PGD \rti, \ptmp1, \rtmp0, \rtmp1, \rtmp2
.endm	/* GOTO_GUEST_KERNEL_TTABLE */
# else
.macro	GOTO_PV_VCPU_KERNEL_TTABLE rti rtmp0 rtmp1 rtmp2 ptmp1
.endm
# endif /* CONFIG_PARAVIRT_GUEST */

/*
 * goto guest kernel fast system call table entry, if system call is
 * from guest user
 * rtmpti: temporary register to read current_thread_info()
 * rtmp0 rtmp1 rtmp2: temporary registers
 * ptmp0 ptmp1 ptmp2: temporary predicates
 */
.macro	GOTO_GUEST_KERNEL_FAST_TTABLE entry_num rtmpti rtmp0 rtmp1 rtmp2 \
						ptmp0 ptmp1 ptmp2
{
	setwd	wsz = 8, nfx = 1;
	nop 1;
	rrd	%osr0, \rtmpti;
	ipd 2;
}
	GOTO_GUEST_KERNEL_TTABLE \entry_num, \rtmpti, \rtmp0, \rtmp1, \rtmp2, \
						\ptmp0, \ptmp1, \ptmp2
.endm	/* GOTO_GUEST_KERNEL_FAST_TTABLE */

/*
 * goto guest kernel protected system call table entry, if system call is
 * from guest user
 * rti: register of current_thread_info()
 * rtmp0 rtmp1 rtmp2: temporary registers
 * ptmp0 ptmp1 ptmp2: temporary predicates
 * FIXME: is not implemented
 */
.macro	GOTO_GUEST_KERNEL_PROT_TTABLE entry_num rti rtmp0 rtmp1 rtmp2 \
						ptmp0 ptmp1 ptmp2
	GOTO_GUEST_KERNEL_TTABLE \entry_num, \rti, \rtmp0, \rtmp1, \rtmp2, \
						\ptmp0, \ptmp1, \ptmp2
.endm	/* GOTO_GUEST_KERNEL_PROT_TTABLE */

#else	/* ! CONFIG_KVM_HOST_MODE */
.macro	SWITCH_TO_KERNEL_IMAGE_PGD rti predN rtmp0, rtmp1, rtmp2
	/* not used */
.endm	/* SWITCH_TO_KERNEL_IMAGE_PGD */

.macro	GOTO_GUEST_KERNEL_TTABLE entry_num rti rtmp0 rtmp1 rtmp2	\
						ptmp0 ptmp1 ptmp2
	/* not used */
.endm	/* GOTO_GUEST_KERNEL_TTABLE */
.macro	GOTO_GUEST_KERNEL_FAST_TTABLE entry_num rtmpti rtmp0 rtmp1 rtmp2 \
						ptmp0 ptmp1 ptmp2
	/* not used */
.endm	/* GOTO_GUEST_KERNEL_FAST_TTABLE */
.macro	GOTO_GUEST_KERNEL_PROT_TTABLE entry_num rti rtmp0 rtmp1 rtmp2 \
						ptmp0 ptmp1 ptmp2
	/* not used */
.endm	/* GOTO_GUEST_KERNEL_PROT_TTABLE */
.macro	GOTO_PV_VCPU_KERNEL_TTABLE entry_num rti rtmp0 rtmp1 rtmp2 \
						ptmp0 ptmp1
	/* not used */
.endm	/* GOTO_PV_VCPU_KERNEL_TTABLE */
#endif	/* CONFIG_KVM_HOST_MODE */

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

.macro	SAVE_GREGS_PAIR_COND_V2 gpair_lo, gpair_hi, kreg_lo, kreg_hi, rbase, \
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
.endm	/* SAVE_GREGS_PAIR_COND_V2 */

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

#ifdef	CONFIG_KVM_HOST_MODE
/* it is host kernel with virtualization support */
/* or paravirtualized host and guest kernel */
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

.macro	SAVE_HOST_GREGS_TO_VIRT_V2 drti, predSAVE, drtmp, rtmp0, rtmp1
		SAVE_HOST_GREGS_V2 \drti, \predSAVE, \drtmp, \rtmp0, \rtmp1
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V2 */

.macro	SAVE_HOST_GREGS_TO_VIRT_V5 drti, predSAVE, drtmp
		SAVE_HOST_GREGS_V5 \drti, \predSAVE, \drtmp
.endm	/* SAVE_HOST_GREGS_TO_VIRT_V5 */

.macro	SAVE_HOST_GREGS_TO_VIRT_UNEXT drti, drtmp
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_UNEXT */

#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/trap_table.S.h>
#else	/* ! CONFIG_KVM_HOST_MODE && ! CONFIG_KVM_GUEST_KERNEL */
/* It is native host kernel without any virtualization */
.macro	SAVE_HOST_GREGS_TO_VIRT_V2 drti, predSAVE, drtmp, rtmp0, rtmp1
	/* not used */
.endm	/* SAVE_VCPU_STATE_GREGS */

.macro	SAVE_HOST_GREGS_TO_VIRT_V5 drti, predSAVE, drtmp
	/* not used */
.endm	/* SAVE_GREGS_TO_VIRT */

.macro	SAVE_HOST_GREGS_TO_VIRT_UNEXT drti, drtmp
	/* not used */
.endm	/* SAVE_HOST_GREGS_TO_VIRT_UNEXT */

#endif	/* CONFIG_KVM_HOST_MODE */

/*
 * same as C function above but as result should be set %pred28
 * argument sys_num_reg_no is assembler register number containing # of
 * system call (for example %r0)
 * %pred28 == 1 if system call is generic and doesn use pt_regs structure
 */
.macro IS_SYS_CALL_GENERIC sys_num_reg_no
	cmpesb	sys_num_reg_no, __NR_clone, %pred0;
	cmpesb	sys_num_reg_no, __NR_clone_thread, %pred1;
	cmpesb	sys_num_reg_no, __NR_fork, %pred2;
	cmpesb	sys_num_reg_no, __NR_vfork, %pred3;
{
	pass	%pred0, @p0;
	pass	%pred1, @p1;
	pass	%pred2,	@p2;
	pass	%pred3, @p3;
	andp	~@p0, ~@p1, @p4;
	andp	~@p2, ~@p3, @p5;
	andp	@p4, @p5, @p6;
	pass	@p6, %pred27;
}
	cmpesb	sys_num_reg_no, __NR_execve, %pred4;
	cmpesb	sys_num_reg_no, __NR_rt_sigreturn, %pred5;
	cmpesb	sys_num_reg_no, __NR_e2k_sigsetjmp, %pred6;
	cmpesb	sys_num_reg_no, __NR_e2k_longjmp, %pred7;
{
	pass	%pred4, @p0;
	pass	%pred5, @p1;
	pass	%pred6,	@p2;
	pass	%pred7, @p3;
	andp	~@p0, ~@p1, @p4;
	andp	~@p2, ~@p3, @p5;
	andp	@p4, @p5, @p6;
	pass	@p6, %pred30;
}
	cmpesb	sys_num_reg_no, __NR_e2k_longjmp2, %pred8;
	cmpesb	sys_num_reg_no, __NR_sigaltstack, %pred9;
	cmpesb	sys_num_reg_no, __NR_rt_sigaction, %pred10;
	cmpesb	sys_num_reg_no, __NR_rt_sigsuspend, %pred11;
{
	pass	%pred8, @p0;
	pass	%pred9, @p1;
	pass	%pred10, @p2;
	pass	%pred11, @p3;
	andp	~@p0, ~@p1, @p4;
	andp	~@p2, ~@p3, @p5;
	andp	@p4, @p5, @p6;
	pass	@p6, %pred29;
}
{
	nop	2;
	pass	%pred27, @p0;
	pass	%pred30, @p1;
	pass	%pred29, @p2;
	andp	@p0, @p1, @p4;
	andp	@p2, @p4, @p5;
	pass	@p5, %pred28;
}
	cmpesb	sys_num_reg_no, __NR_ioctl, %pred13;
	cmpesb	sys_num_reg_no, __NR_ipc, %pred14;
{
	pass	%pred13, @p0;
	pass	%pred14, @p1;
	pass	%pred28, @p2;
	andp	~@p0, ~@p1, @p4;
	andp	@p2, @p4, @p5;
	pass	@p5, %pred28;
}
.endm	/* IS_SYS_CALL_GENERIC */

#endif	/* __ASSEMBLY__ */

#endif	/* _E2K_KVM_TRAP_TABLE_ASM_H */
