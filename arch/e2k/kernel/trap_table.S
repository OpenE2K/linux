/*
 * Trap table entries implemented on assembler
 */

#include <asm/page.h>
#include <asm/unistd.h>
#include <asm/mmu_regs.h>
#include <asm/asm-offsets.h>
#include <asm/thread_info.h>
#include <asm/cpu_regs.h>
#include <asm/e2k_api.h>

.global	user_trap_handler;
.global	kernel_trap_handler;
.global	ttable_entry0;
.global fast_sys_call_table;
.global __per_cpu_offset;
.global kernel_data_stack_overflow;

#ifdef	CONFIG_CHECK_KERNEL_USD_SIZE
#define	CHECK_KERNEL_USD_SIZE(ti, usd_lo, usd_hi, k_stk_sz, k_stk_base,\
			      tmp1, tmp2) \
	ldd,0	[ti + TI_FLAGS], tmp1;	/* tmp1: thread_info->flags */ \
	disp	%ctpr1, 1f;						\
	shrd	usd_hi, 32, tmp2;	/* usd_hi.USD_hi_size */ \
	cmpbedb	tmp2, k_stk_sz, %pred0;	/*  <= k_stk_sz */	\
	ord	tmp1, _TIF_BAD_USD_SIZE, tmp1;/* flags |= _TIF_BAD_USD_SIZE */ \
	ct	%ctpr1 ? %pred0;	/* goto GOOD USD_size */ \
	shld	k_stk_sz, 32, usd_hi;	/* usd_hi.USD_hi_size = k_stk_sz */ \
	addd	k_stk_base, k_stk_sz, usd_lo;/* usd_lo.USD_lo_base = k_stk_base + k_stk_sz */ \
	std	tmp1, [ti + TI_FLAGS];	/* thread_info->flags = flags */ \
1:
#else	/* ! CONFIG_CHECK_KERNEL_USD_SIZE */
#define	CHECK_KERNEL_USD_SIZE(...)
#endif	/* CONFIG_CHECK_KERNEL_USD_SIZE */

					   /* current->ptrace*/
#define GET_PTRACE(task, rr)	ldw, 5 	[task + TSK_PTRACE], rr

.section .ttable_entry0, "ax",@progbits
.align 8
.type ttable_entry0,@function
ttable_entry0:
#ifdef CONFIG_E2S_CPU_RF_BUG
	{
	/* Store all user windows before setwd */
	flushr
	}
	{
	setwd	wsz = 17, nfx = 1;
	}
	{
	movtq %qg16, %qr26
	movtq %qg18, %qr28
	}
	{
	movtq %qg20, %qr30
	movtq %qg22, %qr32
	}
	{
#else
	{
	setwd	wsz = 13, nfx = 1;
#endif
	rrd	%sbr, %dr14;
#ifdef	CONFIG_CLW_ENABLE
	// Read CLW unit registers state for protected mode
	addd,3	0, _CLW_REG_NO_TO_MU_ADDR_VAL(US_CL_M0_NO), %dr8  // us_cl_m0 #
	addd,4	0, _CLW_REG_NO_TO_MU_ADDR_VAL(US_CL_M1_NO), %dr9  // us_cl_m1 #
	addd,5	0, _CLW_REG_NO_TO_MU_ADDR_VAL(US_CL_M2_NO), %dr10 // us_cl_m2 #
	addd	0, _CLW_REG_NO_TO_MU_ADDR_VAL(US_CL_M3_NO), %dr11 // us_cl_m3 #
#endif	/* CONFIG_CLW_ENABLE */
	}
	{
	rrd	%osr0, %dr1;			// %dr1: current_thread_info
#ifdef	CONFIG_CLW_ENABLE
	addd	0, _CLW_REG_NO_TO_MU_ADDR_VAL(US_CL_UP_NO), %dr12
	addd	0, _CLW_REG_NO_TO_MU_ADDR_VAL(US_CL_B_NO), %dr13
	ldd,5	[%dr8] MAS_CLW_REG, %dr8;	// us_cl_m0 value
#endif	/* CONFIG_CLW_ENABLE */
	}
	{
#ifdef CONFIG_MCST_RT
	rrd %clkr, %dr0
#endif
#ifdef	CONFIG_CLW_ENABLE
	ldd,5	[%dr9] MAS_CLW_REG, %dr9;	// us_cl_m1 value
#endif	/* CONFIG_CLW_ENABLE */
	cmpbedb,1 %dr14, TASK_SIZE - 1, %pred0;		// sbr < TASK_SIZE
	}
	{
	rrd	%ctpr1, %dr6;
#ifdef	CONFIG_CLW_ENABLE
	ldd,5	[%dr10] MAS_CLW_REG, %dr10;	// us_cl_m2 value
#endif	/* CONFIG_CLW_ENABLE */
	}
	{
	rrd	%usd.hi, %dr7;
	ipd 0
	disp	%ctpr1, 2f
#ifdef	CONFIG_CLW_ENABLE
	ldd,5	[%dr11] MAS_CLW_REG, %dr11 ? %pred0;	// us_cl_m3 value
	addd	0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), %dr20 ? %pred0
	addd	0, 1, %dr21 ? %pred0
#endif	/* CONFIG_CLW_ENABLE */
	}
	{
	rrd	%ctpr2, %dr5;
	ldd	[%dr1 + TI_K_STK_BASE], %dr14 ? %pred0;	// %dr14: k_stk_base
	ldd	[%dr1 + TI_K_STK_SZ], %dr15 ? %pred0	// %dr15: k_stk_sz
#ifdef	CONFIG_CLW_ENABLE
	ldd,5	[%dr12] MAS_CLW_REG, %dr12 ? %pred0	// us_cl_up value
#endif	/* CONFIG_CLW_ENABLE */
	}
	{
	rrd	%ctpr3, %dr3;
	/* Assume 8Kb are enough for interrupt handling */
	cmpbedb,1 %dr7, (PTRACE_SZOF + 8192) << 32, %pred1 ? ~ %pred0
	ldd	[%dr1 + TI_K_USD_LO], %dr19 ? %pred0;	// %dr19: usd_lo
	ldd	[%dr1 + TI_K_USD_HI], %dr18 ? %pred0;	// %dr18: usd_hi
#ifdef	CONFIG_CLW_ENABLE
	ldd,5	[%dr13] MAS_CLW_REG, %dr13 ? %pred0	// us_cl_b  value
#endif	/* CONFIG_CLW_ENABLE */
	}
	{
	rrd	%usd.lo, %dr2;
#ifdef	CONFIG_CLW_ENABLE
	/* Disable CLW unit for nonprotected mode, we must do it before
	 * data stack switching. There is no need for an explicit
	 * 'wait all_e' as it is done by hardware on trap enter. */
	std,2	%dr21, [%dr20] MAS_MMU_REG ? %pred0
#endif
#ifdef CONFIG_MCST_RT
	std	%dr0, [%dr1 + TI_IRQ_ENTER_CLK] /* ti->irq_enter_clk = %clkr */
#endif
	ct	%ctpr1 ? ~ %pred0;			// kernel_trap_handler()
	}

/* user */
	CHECK_KERNEL_USD_SIZE(%dr1, %dr19, %dr18, %dr15, %dr14, %dr20, %dr21)

	// Switch to kernel local data stack
	{
	disp	%ctpr1, user_trap_handler;
	rwd	%dr18, %usd.hi;			// WRITE_USD_REG(usd_hi,usd_lo)
	addd,1	%dr14, %dr15, %dr0;		// sbr = k_stk_base + k_stk_sz
	}
	{
	rwd	%dr0, %sbr			// WRITE_SBR_REG_VALUE(sbr)

	/* Set current and current_thread_info */
	strd,2 %g16, [ %dr1 + (TAGGED_MEM_STORE_REC_OPC | TI_G16) ]
	strd,5 %g17, [ %dr1 + (TAGGED_MEM_STORE_REC_OPC | TI_G17) ]
	movfi,1 %g16, %r20
	movfi,4 %g17, %r21
	}
	{
	rwd	%dr19, %usd.lo
	strd,2 %g18, [ %dr1 + (TAGGED_MEM_STORE_REC_OPC | TI_G18) ]
	strd,5 %g19, [ %dr1 + (TAGGED_MEM_STORE_REC_OPC | TI_G19) ]
	movfi,1 %g18, %r22
	movfi,4 %g19, %r23
	}
	{
	rrd	%lsr, %dr16
	ldw,3 [ %dr1 + TI_CPU ], %dr24
	gettagd %dg16, %g16
	gettagd %dg17, %g17
	}
	{
	rrd	%ilcr, %dr4;
	gettagd %dg18, %g18
	gettagd %dg19, %g19
	}
	{
	shls	%g17, 8, %g17
	}
	{
	shls	%g18, 16, %g18
	shls	%g19, 24, %g19
	}
	{
	sxt,0	6, %r20, %dr20
	sxt,3	6, %r21, %dr21
	}
	{
	getsp   -(PTRACE_SZOF + AAU_SZOF + TRAP_PTREGS_SZOF + 3 * 7), %dr0;
	ors,2	%g16, %g17, %g16
	sxt,1	6, %r22, %dr22
	sxt,4	6, %r23, %dr23
	shld,3	%dr21, 16, %dr21;
	}
	{
	ors,1	%g18, %g19, %g18
	std	%dr6, [%dr0 + PT_CTRP1];	// regs->ctpr1 = ctpr1
	std	%dr5, [%dr0 + PT_CTRP2];	// regs->ctpr2 = ctpr2
	shld,3	%dr22, 32, %dr22
	shld,4	%dr23, 48, %dr23
	}
	{
	std	%dr3, [%dr0 + PT_CTRP3];	// regs->ctpr3 = ctpr3
	std	%dr16, [%dr0 + PT_LSR];		// regs->lsr = lsr
	ord,3	%dr20, %dr21, %dr20
	ord,4	%dr22, %dr23, %dr22
	}
	{
	ors,1	%g16, %g18, %g16
	std	%dr4, [%dr0 + PT_ILCR];		// regs->ilcr = ilcr
	std	%dr7, [%dr0 + PT_STACK+ST_USD_HI]; // regs->stacks.usd_hi = usd.hi
	ord,3	%dr20, %dr22, %dr20
	}
	{
	addd	%dr24, 0, %dg19
	shld,3	%dr24, 3, %dr24
	stw	%g16, [ %dr1 + TI_G16_TAG ]
	std	%dr20, [ %dr1 + TI_G16_EXT ]
	}
#ifdef CONFIG_CLW_ENABLE
	{
	std	%dr10, [%dr0 + PT_US_CL_M2]
	std	%dr11, [%dr0 + PT_US_CL_M3]
	}
	{
	std	%dr8, [%dr0 + PT_US_CL_M0]
	std	%dr9, [%dr0 + PT_US_CL_M1]
	}
	{
	std	%dr12, [%dr0 + PT_US_CL_UP]
	std	%dr13, [%dr0 + PT_US_CL_B]
	}
#endif
#ifdef CONFIG_E2S_CPU_RF_BUG
	/* These will be corrupted by setwd if we don't save them... */
	{
	strd %dr26, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G16) ]
	strd %dr27, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G17) ]
	}
	{
	strd %dr28, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G18) ]
	strd %dr29, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G19) ]
	}
	{
	strd %dr30, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G20) ]
	strd %dr31, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G21) ]
	}
	{
	strd %dr32, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G22) ]
	strd %dr33, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G23) ]
	}
#endif
	{
	getsp   -64, %empty;	   // reserve stack for function arguments
	addd,1	%dr1, 0, %g16
	ldd,2	[ %dr1 + TI_TASK ], %g17
	ldd,3	[ __per_cpu_offset + %dr24 ], %dg18
	std,5	%dr2, [%dr0 + PT_STACK+ST_USD_LO]; // regs->stacks.usd_lo = usd.lo
	ct	%ctpr1;				// user_trap_handler()
	}

/* kernel */
2:
	// if (READ_SBR_REG() >= TASK_SIZE)
	//	kernel_trap_handler();
	{
	getsp   -(PTRACE_SZOF + TRAP_PTREGS_SZOF + 2 * 7), %dr0 ? ~ %pred1
	disp	%ctpr1, kernel_trap_handler;
	}
	{
	rrd	%lsr, %dr16
	ibranch kernel_data_stack_overflow ? %pred1
	}
	{
	rrd	%ilcr, %dr4;
	}
	{
	std	%dr6, [%dr0 + PT_CTRP1] ;	// regs->ctpr1 = ctpr1
	}
	{
	std	%dr5, [%dr0 + PT_CTRP2] ;	// regs->ctpr2 = ctpr2
 	std	%dr3, [%dr0 + PT_CTRP3] ;	// regs->ctpr3 = ctpr3
	}
	{
	std	%dr7, [%dr0 + PT_STACK+ST_USD_HI]
	std	%dr2, [%dr0 + PT_STACK+ST_USD_LO]
	}
#ifdef CONFIG_E2S_CPU_RF_BUG
	/* These will be corrupted by setwd if we don't save them... */
	{
	strd %dr26, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G16) ]
	strd %dr27, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G17) ]
	}
	{
	strd %dr28, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G18) ]
	strd %dr29, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G19) ]
	}
	{
	strd %dr30, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G20) ]
	strd %dr31, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G21) ]
	}
	{
	strd %dr32, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G22) ]
	strd %dr33, [ %dr0 + (TAGGED_MEM_STORE_REC_OPC | PT_G23) ]
	}
#endif
	{
	std	%dr4, [%dr0 + PT_ILCR]
	std	%dr16,[%dr0 + PT_LSR]
	getsp   -64, %empty;	   // reserve stack for function arguments
	ct	%ctpr1;				  // kernel_trap_handler()
	}


#define WSZ 10
#define SYS_CALL(sys_call_table, FORMAT_32)		   		\
	{								\
		setwd	wsz = WSZ, nfx = 1;				\
		nop 1;							\
		rrd	%osr0, %dr7;					\
		cmpesb,4 FORMAT_32, 1, %pred2; 	/* 32 bit system call */ \
		puttags,5 %r0, 0, %r0;					\
		disp %ctpr1, simple_sys_calls;				\
	}								\
	{								\
		ldd,0	[%dr7 + TI_K_USD_HI], %dr8; 			\
		ldd,2	[%dr7 + TI_K_USD_LO], %dr9;			\
		cmpbsb,3 %r0, NR_syscalls,%pred3; /* sys_num < NR_syscalls */ \
		sxt,4	2, %r0, %dr0;					\
	}								\
	{								\
		ldd,0	[%dr7 + TI_K_STK_BASE], %dr10;			\
		ldd,2	[%dr7 + TI_K_STK_SZ], %dr11;			\
		shld,4	%dr0, 3, %dr14;		/* sys_num * 8 */	\
		puttagd	%dr1, 0, %dr1;					\
	}								\
	CHECK_KERNEL_USD_SIZE(%dr7, %dr9, %dr8, %dr11, %dr10, %dr12, %dr13);\
	{								\
		rrs	%upsr, %r15;					\
		shld,1	1, 56, %dr14 ? ~ %pred3;			\
		puttagd	%dr2, 0, %dr2;					\
		ldd,5	[sys_call_table + %dr14], %dr14 ? %pred3;	\
	}								\
	{								\
		/* Set current and current_thread_info */		\
		strd,2 %g18, [ %dr7 + (TAGGED_MEM_STORE_REC_OPC | TI_G18) ]; \
		strd,5 %g19, [ %dr7 + (TAGGED_MEM_STORE_REC_OPC | TI_G19) ]; \
		/* Wait for FPU exceptions before switching stacks */	\
		wait all_e = 1;						\
	}								\
	{								\
		rwd	%dr8, %usd.hi;					\
		ldw,2 [ %dr7 + TI_CPU ], %dg19;				\
		strd,5 %g17, [ %dr7 + (TAGGED_MEM_STORE_REC_OPC | TI_G17) ]; \
	}								\
	{								\
		rwd	%dr9, %usd.lo;					\
		ldd,3	[%dr7 + TI_TASK], %dg17;			\
		puttagd	%dr3, 0, %dr3;					\
		puttagd	%dr4, 0, %dr4;					\
	}								\
	{								\
		strd,2 %g16, [ %dr7 + (TAGGED_MEM_STORE_REC_OPC | TI_G16) ]; \
		puttagd	%dr5, 0, %dr5;					\
	}								\
	{								\
		addd %dr7, 0, %g16;					\
		puttagd	%dr6, 0, %dr6;					\
	}								\
	{								\
		rws	E2K_KERNEL_UPSR_ENABLED,  %upsr;		\
		shrd,4	%dr14, 56, %dr16;				\
		andd,5 	%dr14, 0xffffffffffffff, %dr14;			\
		sxt	6, %r1, %dr1 ? %pred2;				\
		sxt	6, %r2, %dr2 ? %pred2;				\
		sxt	6, %r3, %dr3 ? %pred2;				\
	}								\
	{								\
		addd	%dr10, %dr11, %dr12; /* sbr = k_stk_base + k_stk_sz */ \
		cmpedb,4 %dr16, 1,%pred4; /*fast_sys_call_table[sys_num]==1*/ \
		sxt	6, %r4, %dr4 ? %pred2;				\
		sxt	6, %r5, %dr5 ? %pred2;				\
		sxt	6, %r6, %dr6 ? %pred2;				\
	}								\
	{								\
		rwd	%dr12, %sbr;					\
		shld,1 %dg19, 3, %dg18;					\
		stw	%r15, [%dr7 + TI_UPSR];				\
	}								\
	{								\
		getsp	-(PTRACE_SZOF + 64), %dr7;			\
		ldd,2 [ __per_cpu_offset + %dg18 ], %dg18;		\
	}								\
	{								\
		addd,1	%dr7, 64, %dr7;					\
		std,2	%dr0, [ %dr7 + (PT_SYS_NUM + 64) ];		\
		ord,4	%dr14, FORMAT_32 << 56, %dr0;			\
		ibranch	hard_sys_calls ? %pred4;			\
	}								\
	{								\
		/* Do not insert NOPs as we are just enabling interrupts */ \
		rwd E2K_KERNEL_PSR_ENABLED, %psr;			\
		ct %ctpr1;						\
	}								\

$.Lfe0:
.size	 $ttable_entry0,$.Lfe0-$ttable_entry0

.global sys_call_table;
.global sys_call_table_32;
.global	ttable_entry1;
.global	simple_sys_calls;
.global	hard_sys_calls;

.section	.ttable_entry1, "ax",@progbits
.align	8
.type	 ttable_entry1,@function
ttable_entry1:
	SYS_CALL(sys_call_table_32, 1)


$.Lfe1:
.size	 ttable_entry1,$.Lfe1-$ttable_entry1

.global	ttable_entry3;

.section	.ttable_entry3, "ax",@progbits
.align	8
.type	 ttable_entry3,@function
ttable_entry3:
	SYS_CALL(sys_call_table, 0)


$.Lfe3:
	.size	 $ttable_entry3,$.Lfe3-$ttable_entry3


.global	ttable_entry4;

.section	.ttable_entry4, "ax",@progbits
	.align	8
	.type	 ttable_entry4,@function
ttable_entry4:
	{
		/* wsz here must be not smaller than in ttable_entry3
		 * and SYS_CALL() to workaround hw bug #68012 */
		setwd	wsz = WSZ, nfx = 1
		ipd 0
		disp	%ctpr1, compatibility_call
		/* %dr7 = current_thread_info() */
		rrd	%osr0, %dr7
	}
	{
		puttagd,2 %dr0, 0, %dr0
		ipd 1
		disp	%ctpr2, ttable_entry3
		/* %dr7 = current */
		ldd,0	[%dr7 + TI_TASK], %dr7
	}
	{
		nop 2
		/* %dr7 = current->thread.flags */
		ldd,0	[%dr7 + TSK_THREAD_FLAGS], %dr7
		/* %pred1 = sys_num < 0 */
		cmplsb,1	%r0, 0, %pred1
	}
	{
		/* pred2 = !(current->thread.flags & E2K_FLAG_32BIT) */
		cmpandedb %dr7, E2K_FLAG_32BIT, %pred2
	}
	{
		/* sys_num = -sys_num */
		subs,1	0, %r0, %r0 ? %pred1
		/* if (sys_num < 0) goto compatibility_call */
		ct	%ctpr1 ? %pred1
	}
	{
		/* Wait for %pred2 */
		addd 0x0, 0x0, %empty
	}
	{
	/* if (!(current->thread.flags & E2K_FLAG_32BIT)) goto ttable_entry3 */
		ct	%ctpr2 ? %pred2
	}
compatibility_call:
	SYS_CALL(sys_call_table_deprecated, 2)
$.Lfe2:
	.size	 $ttable_entry4,$.Lfe2-$ttable_entry4


.global fast_sys_calls_table_32;
.global ttable_entry5;

.section	.ttable_entry5, "ax",@progbits
	.align	8
	.type	ttable_entry5,@function
ttable_entry5:
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid. */
{
	setwd		wsz = 0x4
}
{
	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,0		%dr0, NR_fast_syscalls_mask, %dr0
}
{
	shld,0		%dr0, 3, %dr0
	puttagd,2 	%dr1, 0, %dr1
}
{
	ldd,0		[fast_sys_calls_table_32 + %dr0], %dr3
	sxt,1		6, %dr1, %dr0
	puttagd,2	%dr2, 0, %dr2
}
{
	ipd		2
	movtd,0		%dr3, %ctpr1

	sxt,1		6, %dr2, %dr1
}
	ct		%ctpr1
.size	 $ttable_entry5, . -$ttable_entry5


.global fast_sys_calls_table;
.global ttable_entry6;

.section	.ttable_entry6, "ax",@progbits
	.align	8
	.type	ttable_entry6,@function
ttable_entry6:
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid. */
{
	setwd		wsz = 0x4
}
{
	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,0		%dr0, NR_fast_syscalls_mask, %dr0
}
{
	shld,0		%dr0, 3, %dr0
}
{
	ldd,0		[fast_sys_calls_table + %dr0], %dr3
	puttagd,2 	%dr1, 0, %dr0
}
{
	ipd		2
	movtd,0		%dr3, %ctpr1

	puttagd,2	%dr2, 0, %dr1
}
	ct		%ctpr1
.size	 $ttable_entry6, . -$ttable_entry6


.global fast_sys_calls_table_128;
.global ttable_entry7;

.section	.ttable_entry7, "ax",@progbits
	.align	8
	.type	ttable_entry7,@function
ttable_entry7:
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid. */
{
	setwd		wsz = 0x7
}

	/* Read tags of %dr1 - %dr5 and pack them by forths in %r0.
	 * Clear any speculative tags in arguments, which can be unused
	 * by some system calls. */
{
	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,0		%dr0, NR_fast_syscalls_mask, %dr0

	gettagd,2	%dr1, %r9
	gettagd,5	%dr2, %r10
}
{
	shld,0		%dr0, 3, %dr0

	shls,1		%r9, 4, %r9
	shls,3		%r10, 8, %r10
	gettagd,2	%dr3, %r11
	gettagd,5	%dr4, %r12
}
{
	ldd,0		[fast_sys_calls_table_128 + %dr0], %dr8

	shls,1		%r11, 12, %r11
	shls,3		%r12, 16, %r12
	gettagd,2	%dr5, %r13
}
{
	ipd		2
	movtd,0		%dr8, %ctpr1

	ors,1		%r9, %r11, %r9
	shls,2		%r13, 20, %r13
}
{
	ors,0		%r9, %r13, %r9
	puttagd,2	%dr1, 0, %dr1
	puttagd,5	%dr2, 0, %dr2
}
{
	ors,0		%r9, %r10, %r9
	puttagd,2	%dr3, 0, %dr3
	puttagd,5	%dr4, 0, %dr4
}
{
	ors,0		%r9, %r12, %r9
	puttagd,2	%dr5, 0, %dr5
}
{
	adds,0		%r9, 0, %r0
	ct		%ctpr1
}
.size	 $ttable_entry7, . -$ttable_entry7


#ifdef CONFIG_PROTECTED_MODE
.global	ttable_entry10_C;
.global	ttable_entry10;

.section	.ttable_entry10, "ax",@progbits
	.align	8
	.type	 ttable_entry10,@function
ttable_entry10:
	{
		setwd	wsz = 9, nfx = 1
		addd	0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), %dr16
		addd	0, 1, %dr17
	}

	/* Read tags of %dr0 - %dr7 and pack them by forths in %dr8.
	 * Clear any speculative tags in arguments, which can be unused
	 * by some system calls. */
	{
		disp %ctpr1, ttable_entry10_C
		gettagd,2 %dr1, %r9
		gettagd,5 %dr2, %r10
	}
	{
		shls,0 %r9, 4, %r9
		gettagd,2 %dr0, %r8
		shls,1 %r10, 8, %r10
		gettagd,5 %dr3, %r11
	}
	{
		ors,0 %r8, %r9, %r8
		gettagd,2 %dr4, %r12
		shls,3 %r11, 12, %r11
		gettagd,5 %dr5, %r13
	}
	{
		ors,0 %r8, %r10, %r8
		shls,1 %r12, 16, %r12
		gettagd,2 %dr6, %r14
		shls,3 %r13, 20, %r13
		gettagd,5 %dr7, %r15
	}
	{
		ors,0 %r8, %r11, %r8
		puttagd,2 %dr0, 0, %dr0
		shls,1 %r15, 28, %r15
		puttagd,5 %dr1, 0, %dr1
		shls,3 %r14, 24, %r14
	}
	{
		ors,0 %r8, %r12, %r8
		sxt,1 2, %r0, %dr0
		puttagd,2 %dr2, 0, %dr2
		puttagd,5 %dr3, 0, %dr3
	}
	{
		// Save PUSD.psl field in the left part of sys_num
		// sys_num |= READ_PUSD_LO_REG().PUSD_lo_psl;
		rrd	%usd.lo, %dr10

		ors,1 %r8, %r13, %r8
		puttagd,2 %dr4, 0, %dr4
		puttagd,5 %dr5, 0, %dr5
	}
	{
		// sys_num |= READ_PUSD_LO_REG().PUSD_lo_psl;
		andd,1	%dr10, 0xffffffff00000000 ,%dr10

		ors,0 %r8, %r14, %r8
		puttagd,2 %dr6, 0, %dr6
		puttagd,5 %dr7, 0, %dr7
	}
	{
		// sys_num |= READ_PUSD_LO_REG().PUSD_lo_psl;
		ord,1	%dr0, %dr10, %dr0
		ors,0 %r8, %r15, %r8
		/* Wait for FPU exceptions _and_ for CLW work completion */
		wait	all_e = 1
	}
	{
		/* %dr13: current_thread_info */
		rrd	%osr0, %dr13

		/* Disable CLW unit for nonprotected mode */
		std,2	%dr17, 0, [%dr16] MAS_MMU_REG
	}
	//	thread_info = current_thread_info();
	//	usd_lo = thread_info->k_usd_lo;
	//	usd_hi = thread_info->k_usd_hi;
	//	WRITE_USD_REG(usd_hi, usd_lo);
	//	WRITE_SBR_REG_VALUE(
	//		(thread_info->k_stk_base + thread_info->k_stk_sz));

	// Switch to kernel local data stack
	{
		ldd,0	[%dr13 + TI_K_USD_HI], %dr9	// %dr9: usd_hi
		ldd,2	[%dr13 + TI_K_USD_LO], %dr10	// %dr10: usd_lo
		ldd,3	[%dr13 + TI_K_STK_BASE], %dr11	// %dr11: k_stk_base
		ldd,5	[%dr13 + TI_K_STK_SZ], %dr12	// %dr12: k_stk_sz
	}
	//CHECK_KERNEL_USD_SIZE(%dr13, %dr10, %dr9, %dr12, %dr11, %dr14, %dr15)
	rwd	%dr9, %usd.hi			// WRITE_USD_REG(usd_hi, usd_lo)
	rwd	%dr10, %usd.lo
	{
		addd,1	%dr11, %dr12, %dr12    /* sbr = k_stk_base + k_stk_sz */
		ldd	[%dr13 + TI_TASK], %dr14	/* %dr14: current */
		ldw	[%dr13 + TI_CPU ], %dr15
	}
	rwd	%dr12, %sbr			// WRITE_SBR_REG_VALUE(sbr)

	{
		addd %dr15, 0, %dg19
		shld %dr15, 3, %dr15
		strd,2 %g18, [ %dr13 + (TAGGED_MEM_STORE_REC_OPC | TI_G18) ]
		strd,5 %g19, [ %dr13 + (TAGGED_MEM_STORE_REC_OPC | TI_G19) ]
	}

	/* Reserve memory for 'struct pt_regs' and parameters and put in
	 * there the last argument 'tags' (cannot put it in %dr8 since the
	 * size of the register window for C functions is only 8 dregs). */
	{
		getsp	-(6 * 8), %dr9
		ldd [ __per_cpu_offset + %dr15 ], %dg18
	}
	{
		getsp   -(PTRACE_SZOF + 64), %dr7;
		strd,2 %g16, [ %dr13 + (TAGGED_MEM_STORE_REC_OPC | TI_G16) ]
		std	%dr7, [%dr9]
	}
	{
		/* Set current and current_thread_info */
		strd,5 %g17, [ %dr13 + (TAGGED_MEM_STORE_REC_OPC | TI_G17) ]
		addd %dr13, 0, %g16
		addd %dr14, 0, %g17

		/* Go to main protected system call handler */
		stw	%r8, [%dr9 + 8]
		addd	%dr7, 64, %dr7
		ct	%ctpr1
	}

$.Lfe5:
	.size	 $ttable_entry10,$.Lfe5-$ttable_entry10
#endif /* CONFIG_PROTECTED_MODE */

