/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Trap table entries implemented on assembler
 */

#include <linux/linkage.h>
#include <asm/unistd.h>
#include <generated/asm-offsets.h>
#include <asm/pv_info.h>
#include <asm/mmu_types.h>
#include <asm/trap_table.h>
#include <asm/trap_table.S.h>
#include <asm/thread_info.h>

.global	user_trap_handler;
.global	kernel_trap_handler;
.global	ttable_entry0;
.global __per_cpu_offset;
.global kernel_data_stack_overflow;
.global machine;

#ifdef CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
#else
# define SMP_ONLY(...)
#endif

#ifdef CONFIG_CLW_ENABLE
# define CLW_ONLY(...) __VA_ARGS__
#else
# define CLW_ONLY(...)
#endif

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
# define PV_VCPU(...) __VA_ARGS__
#else
# define PV_VCPU(...)
#endif

#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
# define NOT_SEP_VIRT_SPACE_ONLY(...) __VA_ARGS__
#else
# define NOT_SEP_VIRT_SPACE_ONLY(...)
#endif

.section .ttable_entry0, "ax",@progbits
SYM_FUNC_START(ttable_entry0)
	{
		/* #80747: must repeat interrupted barriers */
		wait fl_c=1
	}
	/* Important: the first memory access in kernel is store, not load.
	 * This is needed to flush SLT before trying to load anything. */
	KERNEL_ENTRY(TSK_TI_TMP_, /* not a syscall */, 0 /* crp */)
	{
		nop 1
		rrd %sbr, GCURTASK
	}
	SWITCH_HW_STACKS(
		/* Switch only if we are on user stacks (sbr <= TASK_SIZE) */
		cmpbedb,1 GCURTASK, TASK_SIZE
	)
	{
	setwd	wsz = 20, nfx = 1;
	rrd	%ctpr1, %dr6;
	ldgdd	0, TSK_STACK, %dr1 ? %pred0; // %dr1: stack
	ldgdd	0, TSK_K_USD_LO, %dr23 ? %pred0;	// %dr23: usd_lo
	ldgdd	0, TSK_K_USD_HI, %dr22 ? %pred0;	// %dr22: usd_hi
	}

	ALTERNATIVE_1_ALTINSTR
		/* CPU_FEAT_TRAP_V5 version - save %lsr1, %ilcr1 */
		{
			rrd %lsr1, %dr14
		}
		{
			rrd %ilcr1, %dr15
			addd 0, 0, %dr17
			addd 0, 0, %dr18
			addd 0, 0, %dr19
		}
	ALTERNATIVE_2_ALTINSTR2
		/* CPU_FEAT_TRAP_V6 version - save %lsr1, %ilcr1, %ctpr<j>.hi */
		{
			rrd %ctpr1.hi, %dr17
		}
		{
			rrd %ctpr2.hi, %dr18
		}
		{
			rrd %ctpr3.hi, %dr19
		}
		{
			rrd %lsr1, %dr14
		}
		{
			rrd %ilcr1, %dr15
		}
	ALTERNATIVE_3_OLDINSTR2
		/* iset v3 version */
		{
			addd 0, 0, %dr14
			addd 0, 0, %dr15
			addd 0, 0, %dr17
			addd 0, 0, %dr18
			addd 0, 0, %dr19
		}
	ALTERNATIVE_4_FEATURE2(CPU_FEAT_TRAP_V5, CPU_FEAT_TRAP_V6)

	{
	ipd 1
	disp %ctpr1, 2f
	rrd %clkr, %dr0
	CLW_ONLY(addd,1 0, 1, %dr21 ? %pred0)
	mmurr,2 %cont, %dr9 ? ~ %pred0
	CLW_ONLY(mmurr,5 %us_cl_m1, %dr9 ? %pred0)
	}

	ALTERNATIVE_1_ALTINSTR
		/* CPU_FEAT_SEP_VIRT_SPACE version - get kernel PT root from %os_pptb */
		{
			rrd %sbr, %dr26
			mmurr,2 %os_pptb, %dr36
			addd 0, E2K_KERNEL_CONTEXT, %dr37
			/* Read CLW unit registers state for protected mode */
			CLW_ONLY(mmurr,5 %us_cl_m0, %dr8 ? %pred0)
		}
	ALTERNATIVE_2_OLDINSTR
		/* Original instruction - get kernel PT root from memory */
		{
			rrd %sbr, %dr26
			NOT_SEP_VIRT_SPACE_ONLY(ldgdd 0, TSK_K_ROOT_PTB, %dr36)
			addd 0, E2K_KERNEL_CONTEXT, %dr37
			/* Read CLW unit registers state for protected mode */
			CLW_ONLY(mmurr,5 %us_cl_m0, %dr8 ? %pred0)
		}
	ALTERNATIVE_3_FEATURE(CPU_FEAT_SEP_VIRT_SPACE)

	{
	rrd %usd.hi, %dr7;
	mmurr,2 %root_ptb, %dr10 ? ~ %pred0
	CLW_ONLY(mmurr,5 %us_cl_m2, %dr10 ? %pred0)
	}
	{
	rrd	%ctpr2, %dr5;
	CLW_ONLY(mmurr,5 %us_cl_m3, %dr11 ? %pred0)
	}
	{
	rrd	%ctpr3, %dr3;

	std	%dr0, GCURTASK, TSK_IRQ_ENTER_CLK /* ti->irq_enter_clk = %clkr */
	/* Check for data stack overflow. Handler does not use stack at all
	 * so it is enough to catch biggest possible getsp that failed. */
	cmpbedb,1 %dr7, 4096ULL << 32, %pred1 ? ~ %pred0
	CLW_ONLY(mmurr,5 %us_cl_up, %dr12 ? %pred0)
	}
	{
	rrd	%usd.lo, %dr2;

	/* Disable CLW unit for nonprotected mode, we must do it before
	 * data stack switching. There is no need for an explicit
	 * 'wait all_e' for CLW as it is done by hardware on trap enter. */
	CLW_ONLY(mmurw,2 %dr21, %us_cl_d ? %pred0)
	CLW_ONLY(mmurr,5 %us_cl_b, %dr13 ? %pred0)
	ct	%ctpr1 ? ~ %pred0;			// kernel_trap_handler()
	}

/* user */

	/* set kernel state of UPSR to preserve FP disable exception */
	/* on movfi instructions */
	/* %r21 - user UPSR to save at thread_info structure */
	/* NMI disabled and can be enabled after TIRs parsing */
	/* SGI should be disabled and can be enabled later */
	{
	ipd 3
	disp	%ctpr1, user_trap_handler;

	rrs	%upsr, %r21;

	/* For user traps only since only then tmp_k_gregs is needed:
	 * thread_info->k_gregs = thread_info->tmp_k_gregs */
	ldrd,2 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_VCPU_STATE, %dr28
	ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_VCPU_STATE_EXT, %dr29
	}

	ALTERNATIVE_1_ALTINSTR
		/* PSR IRQ masks are global, UPSR masks are not used */
		{
			adds	0, E2K_KERNEL_UPSR_GLOB_IRQ_DISABLED_ALL, %r27
			ldgdw,3 0, TSK_PTRACE, %r20
		}
	ALTERNATIVE_2_OLDINSTR
		/* PSR IRQ mask is local and UPSR masks are used as global */
		{
			adds	0, E2K_KERNEL_UPSR_LOC_IRQ_DISABLED_ALL, %r27
			ldgdw,3 0, TSK_PTRACE, %r20
		}
	ALTERNATIVE_3_FEATURE(CPU_FEAT_GLOBAL_IRQ_MASK)

	{
	rws	%r27, %upsr;

	addd,1	%dr1, KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET, %dr1;
	stw,2	%r21, GCURTASK, TSK_UPSR;	/* thread_info->upsr = upsr */
	ldd,5	GCURTASK, TSK_U_STACK_TOP, %dr27
	}

	/* Switch to kernel local data stack */
	ALTERNATIVE_1_ALTINSTR
		/* CPU_HWBUG_USD_ALIGNMENT version */
		{
		/* sbr = stack + KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET */
		rwd	%dr1, %sbr
		ldrd,2 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_TASK, %dr30
		ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_TASK_EXT, %dr31
		nop 1;
		}
	ALTERNATIVE_2_OLDINSTR
		/* Default version */
		{
		/* sbr = stack + KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET */
		rwd	%dr1, %sbr
		ldrd,2 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_TASK, %dr30
		ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_TASK_EXT, %dr31
		}
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_USD_ALIGNMENT)
	{
	rwd	%dr23, %usd.lo
	ldrd,2 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_MY_CPU_OFFSET, %dr32
	ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_MY_CPU_OFFSET_EXT, %dr33
	}
	{
	rwd	%dr22, %usd.hi;
	ldrd,2 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_CPU_ID_PREEMPT, %dr34
	ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | TSK_TI_TMP_G_CPU_ID_PREEMPT_EXT, %dr35
	}
	{
	rrd	%lsr, %dr16
	}
	{
	rrd	%ilcr, %dr4;
	strd,2 %dr28, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_VCPU_STATE
	strd,5 %dr29, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_VCPU_STATE_EXT
	}
	{
	strd,2 %dr30, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_TASK
	strd,5 %dr31, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_TASK_EXT
	}
	{
	strd,2 %dr32, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_MY_CPU_OFFSET
	strd,5 %dr33, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_MY_CPU_OFFSET_EXT
	}
	{
	strd,2 %dr34, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_CPU_ID_PREEMPT
	strd,5 %dr35, GCURTASK, TAGGED_MEM_STORE_REC_OPC | TSK_TI_G_CPU_ID_PREEMPT_EXT
	}
	{
	/* MMU registers can be written only after disabling CLW/AAU */
	mmurw %dr37, %cont
	}
	{
	mmurw,2 %dr36, %root_ptb
	}
	{
	getsp   -(PTRACE_SZOF + TRAP_PTREGS_SZOF), %dr0
	/* mmurw -> memory access; getsp -> usage */
	nop 3
	wait all_c=1
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
	{
	std	%dr6, [%dr0 + PT_CTRP1];	// regs->ctpr1 = ctpr1
	std	%dr5, [%dr0 + PT_CTRP2];	// regs->ctpr2 = ctpr2
	}
	{
	std	%dr3, [%dr0 + PT_CTRP3];	// regs->ctpr3 = ctpr3
	std	%dr16, [%dr0 + PT_LSR];		// regs->lsr = lsr
	}
	{
	std	%dr4, [%dr0 + PT_ILCR];		// regs->ilcr = ilcr
	std     %dr27, [%dr0 + PT_STACK+ST_TOP]; /* regs->stacks.top = */
 	}
	{
	/* regs->g_stacks.sbr/top = %sbr */
	PV_VCPU(std	%dr26, [%dr0 + PT_G_STACK+G_ST_SBR])
	}
	{
	getsp   -64, %empty;	   // reserve stack for function arguments
	std	%dr2, [%dr0 + PT_STACK+ST_USD_LO]; // regs->stacks.usd_lo = usd.lo
	std	%dr7, [%dr0 + PT_STACK+ST_USD_HI]; // regs->stacks.usd_hi = usd.hi
	cmpesb,3 %r20, 0, %pred2
	}
	{
	std	%dr14, [%dr0 + PT_LSR1]
	std	%dr15, [%dr0 + PT_ILCR1]
	SMP_ONLY(shld,3 GCPUID_PREEMPT, 3, GCPUOFFSET)
	}
	{
	std	%dr17, [%dr0 + PT_CTPR1_HI]
	std	%dr18, [%dr0 + PT_CTPR2_HI]
	}
	{
	std,2	%dr19, [%dr0 + PT_CTPR3_HI]
	SMP_ONLY(ldd,5 GCPUOFFSET, __per_cpu_offset, GCPUOFFSET)
	ct	%ctpr1 ? %pred2 // user_trap_handler()
	}
	ibranch save_dam_and_jump_ctpr1

2: /* kernel */
	// if (READ_SBR_REG() >= TASK_SIZE)
	//	kernel_trap_handler();
	{
	ipd 2
	disp	%ctpr1, kernel_trap_handler;
	getsp   -(PTRACE_SZOF + TRAP_PTREGS_SZOF + 2 * 7), %dr0 ? ~ %pred1
	/* MMU registers can be written only after disabling CLW/AAU */
	mmurw %dr37, %cont
	}
	{
	rrd	%lsr, %dr16
	mmurw,2 %dr36, %root_ptb
	}
	{
	/* mmurw -> memory access */
	nop 3
	wait all_c=1
	}
	{
	rrd	%ilcr, %dr4;
	std	%dr6, [%dr0 + PT_CTRP1] ? ~ %pred1
	std	%dr5, [%dr0 + PT_CTRP2] ? ~ %pred1
	ibranch kernel_data_stack_overflow ? %pred1
	}
	{
 	std	%dr3, [%dr0 + PT_CTRP3] ;	// regs->ctpr3 = ctpr3
	std	%dr26,[%dr0 + PT_STACK+ST_TOP]
	}
	{
	getsp   -64, %empty;	   // reserve stack for function arguments
	std	%dr7, [%dr0 + PT_STACK+ST_USD_HI]
	std	%dr2, [%dr0 + PT_STACK+ST_USD_LO]
	}
	{
	std %dr14, [%dr0 + PT_LSR1]
	std %dr15, [%dr0 + PT_ILCR1]
	}
	{
	std %dr17, [%dr0 + PT_CTPR1_HI]
	std %dr18, [%dr0 + PT_CTPR2_HI]
	}
	{
	std %dr19, [%dr0 + PT_CTPR3_HI]
	}
	{
	std %dr9, [%dr0 + PT_CONT]
	std %dr10, [%dr0 + PT_U_ROOT_PTB]
	}
	{
	std %dr4, [%dr0 + PT_ILCR]
	std %dr16,[%dr0 + PT_LSR]
	ct %ctpr1;	// kernel_trap_handler()
	}
SYM_FUNC_END(ttable_entry0)

#define WSZ 11
#define SYS_CALL(sys_call_table, FORMAT_32, ENTRY) \
	{								\
		setwd	wsz = WSZ, nfx = 1;				\
		ldgdd,2	0, TSK_STACK, %dr10;				\
		ldgdd,3	0, TSK_K_USD_HI, %dr8; 				\
		puttags,5 %r0, 0, %r0;					\
	}								\
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_SEP_VIRT_SPACE version - get kernel PT root from %os_pptb */ \
		{ \
			nop 1; \
			ldgdd 0, TSK_K_USD_LO, %dr9; \
			mmurr %os_pptb, %dr12; \
			addd 0, E2K_KERNEL_CONTEXT, %dr13; \
			ldgdw,3 0, TSK_PTRACE, %r16; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - get kernel PT root from memory */ \
		{ \
			nop 1; \
			ldgdd 0, TSK_K_USD_LO, %dr9; \
			NOT_SEP_VIRT_SPACE_ONLY(ldgdd 0, TSK_K_ROOT_PTB, %dr12;) \
			addd 0, E2K_KERNEL_CONTEXT, %dr13; \
			ldgdw,3 0, TSK_PTRACE, %r16; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_SEP_VIRT_SPACE) \
									\
	{								\
		ipd 2;							\
		disp %ctpr1, handle_sys_call;				\
		PV_VCPU(rrd	%sbr, %dr21);				\
		cmpbsb,3 %r0, NR_syscalls,%pred3; /* sys_num < NR_syscalls */ \
		sxt,4	6, %r0, %dr0;					\
	}								\
	{								\
		rrd	%usd.lo, %dr19;					\
		ldd,2	GCURTASK, TSK_U_STACK_TOP, %dr11;		\
		shld,4	%dr0, 3, %dr14;		/* sys_num * 8 */	\
		puttagd,5 %dr1, 0, %dr1;				\
	}								\
	{								\
		rrd	%usd.hi, %dr20;					\
		addd,2	%dr10, KERNEL_C_STACK_SIZE +			\
			       KERNEL_C_STACK_OFFSET, %dr10;		\
		ldd,5	[sys_call_table + %dr14], %dr14 ? %pred3;	\
	}								\
	ALTERNATIVE_1_ALTINSTR						\
		/* CPU_HWBUG_USD_ALIGNMENT version */			\
		{							\
			rwd	%dr10, %sbr;				\
			cmpesb,1 FORMAT_32, 1, %pred2; 	/* 32 bit system call */ \
			puttagd,2 %dr2, 0, %dr2;			\
			addd,4 sys_ni_syscall, %dr14 ? ~ %pred3;	\
			nop 1;						\
		}							\
	ALTERNATIVE_2_OLDINSTR						\
		/* Default version */					\
		{							\
			rwd	%dr10, %sbr;				\
			cmpesb,1 FORMAT_32, 1, %pred2; 	/* 32 bit system call */ \
			puttagd,2 %dr2, 0, %dr2;			\
			addd,4 sys_ni_syscall, %dr14 ? ~ %pred3;	\
		}							\
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_USD_ALIGNMENT)			\
	{								\
		rwd	%dr9, %usd.lo;					\
		CLW_ONLY(addd,1	0, 1, %dr18;)				\
		puttagd,2 %dr3, 0, %dr3;				\
		puttagd,5 %dr4, 0, %dr4;				\
	}								\
	{								\
		/* nop 0; rwd %usd -> getsp */				\
		rwd	%dr8, %usd.hi;					\
		puttagd,5 %dr5, 0, %dr5;				\
	}								\
	{								\
		rrs	%upsr, %r15;					\
		CLW_ONLY(mmurw,2 %dr18, %us_cl_d;)			\
		addd GCURTASK, TSK_TI, %dr7;				\
	}								\
	{								\
		sxt,4	6, %r1, %dr1 ? %pred2;				\
		sxt,1	6, %r2, %dr2 ? %pred2;				\
		sxt,0	6, %r3, %dr3 ? %pred2;				\
		sxt,3	6, %r4, %dr4 ? %pred2;				\
		stw,2	%r15, GCURTASK, TSK_UPSR;			\
		puttagd,5 %dr6, 0, %dr6;				\
	}								\
	/*								\
	 * Guest under hardware virtualization support - IS_HV_GM()	\
	 * should save global registers used by host to support		\
	 * (para)virtualization. Saving is unconditional because of	\
	 * only such guest can be here.					\
	 * %dr7 - pointer to thread info				\
	 * %dr10 - temporary registers					\
	 */								\
	SAVE_HOST_GREGS_TO_VIRT_UNEXT %dr7, %dr10			\
	{								\
		/* MMU registers can be written only after disabling	\
		 * CLW/AAU (so at any point for a 32/64 bit syscall).	\
		 * "wait all_e" from MMURW_WAIT_ASYNC_TLB is done before \
		 * switching hardware stacks */				\
		mmurw %dr13, %cont;					\
	}								\
									\
	ALTERNATIVE_1_ALTINSTR						\
		/* PSR IRQ masks are global, UPSR masks are not used */	\
		{							\
			adds	0, E2K_KERNEL_UPSR_GLOB_IRQ_ENABLED, %r8 \
		}							\
	ALTERNATIVE_2_OLDINSTR						\
		/* PSR IRQ mask is local and UPSR masks are used as global */ \
		{							\
			adds	0, E2K_KERNEL_UPSR_LOC_IRQ_ENABLED, %r8	\
		}							\
	ALTERNATIVE_3_FEATURE(CPU_FEAT_GLOBAL_IRQ_MASK)			\
									\
	{								\
		rws	%r8,  %upsr;					\
		adds,1	0, ENTRY, %r8;					\
		mmurw %dr12, %root_ptb;					\
	}								\
	{								\
		/* mmurw -> memory access */				\
		nop 1;							\
		wait all_c=1;						\
	}								\
	{								\
		/* mmurw -> memory access, getsp -> usage */		\
		nop 1;							\
		getsp	-(PTRACE_SZOF + 64), %dr7;			\
	}								\
	{ \
		stw,2	%r0, [ (%dr7 + 64) + PT_SYS_NUM ];		\
		SMP_ONLY(shld,4 GCPUID_PREEMPT, 3, GCPUOFFSET);		\
	} \
	{								\
		stw,2	%r8, [ (%dr7 + 64) + PT_KERNEL_ENTRY ];		\
		SMP_ONLY(ldd,5 GCPUOFFSET, __per_cpu_offset, GCPUOFFSET); \
		cmpesb,3 %r16, 0, %pred4;				\
	} \
	{								\
		std,2	%dr19, [(%dr7 + 64) + PT_STACK+ST_USD_LO];	\
		std,5	%dr20, [(%dr7 + 64) + PT_STACK+ST_USD_HI];	\
		sxt,3	6, %r5, %dr5 ? %pred2;				\
		sxt,4	6, %r6, %dr6 ? %pred2;				\
	}								\
	{								\
		addd,1	%dr7, 64, %dr7;					\
		std,2	%dr11, [(%dr7 + 64) + PT_STACK+ST_TOP];		\
		addd,4	%dr14, 0, %dr0;					\
		/* regs->g_stacks.sbr/top = %sbr */			\
		PV_VCPU(std	%dr21, [(%dr7 + 64) + PT_G_STACK+G_ST_SBR]); \
		ct %ctpr1 ? %pred4;					\
	} \
	ibranch save_dam_and_jump_ctpr1

.section	.native_ttable_entry1, "ax",@progbits
SYM_FUNC_START(native_ttable_entry1)
	VFRPSZ_SETWD(4)
	SWITCH_HW_STACKS_SYSCALL()
	SYS_CALL(sys_call_table_32, 1, 1)
SYM_FUNC_END(native_ttable_entry1)

.section	.native_ttable_entry3, "ax",@progbits
SYM_FUNC_START(native_ttable_entry3)
	VFRPSZ_SETWD(4)
	SWITCH_HW_STACKS_SYSCALL()
SYM_INNER_LABEL(native_ttable_entry3_switched, SYM_L_GLOBAL)
	SYS_CALL(sys_call_table, 0, 3)
SYM_FUNC_END(native_ttable_entry3)


.section	.native_ttable_entry4, "ax",@progbits
SYM_FUNC_START(native_ttable_entry4)
	VFRPSZ_SETWD(4)
	SWITCH_HW_STACKS_SYSCALL()
	{
		/* wsz here must be not smaller than in ttable_entry3
		 * and SYS_CALL() to workaround hw bug #68012 */
		setwd	wsz = WSZ, nfx = 1
		ipd 0
		disp	%ctpr1, compatibility_call
		/* %dr7 = current->thread.flags */
		ldd,0	GCURTASK, TSK_THREAD_FLAGS, %dr7
	}
	{
		puttagd,2 %dr0, 0, %dr0
		ipd 1
		disp	%ctpr2, native_ttable_entry3_switched
	}
	{
		nop 2
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
	SYS_CALL(sys_call_table_deprecated, 2, 4)
SYM_FUNC_END(native_ttable_entry4)


.global fast_sys_calls_table_32;

.section	.ttable_entry5, "ax",@progbits
SYM_FUNC_START(ttable_entry5)
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid:
	 * dr0 - masked sys_num, dr1 - arg1, dr2 - arg2 */
{
	VFRPSZ(4)
	setwd		wsz = 0x8
	setbn		rbs = 0x4, rsz = 0x3, rcur = 0x0
}
{
	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,0		%dr0, NR_fast_syscalls_mask, %dr0
}
{
	/* Read pointer to host thread_info from osr0 reg */
	rrd,0 		%osr0, %dr3
}

	/*
	 * Check TS_HOST_AT_VCPU_MODE thread status flag.
	 * If flag is not set - host syscall, if set - guest syscall
	 */
{
	ldd,2		[ %dr3 + TI_STATUS ], %dr3
}
{
	andd,0 		%dr3, TS_HOST_AT_VCPU_MODE, %dr3
}
{
	cmpedb,0	%dr3, 0x0, %pred0
	disp 		%ctpr1, compat_guest_syscall
}
{
	ct 		%ctpr1 ? ~%pred0
}
	/*
	 * This syscall is from host user, goto fast syscall handler
	 * with 2 parameters. sys_num is index in fast_sys_calls_table_32
	 */
{
	shld,0          %dr0, 3, %dr0
}
{
	ldd,0 		[fast_sys_calls_table_32 + %dr0], %dr3
	puttagd,2       %dr1, 0, %dr0
}
{
	sxt,1           6, %dr0, %dr0
	puttagd,2       %dr2, 0, %dr1
}
{
	sxt,1		6, %dr1, %dr1
	movtd           %dr3, %ctpr1
}
{
	ct 		%ctpr1
}
compat_guest_syscall:
#ifdef CONFIG_KVM_HOST_MODE
	/*
	 * This sycall is from guest user. Guest ttable entry handler
	 * will be executed on current hw stack frame. Prepare parameters
	 * for it:
	 * %dr0 - sys_num, %dr1 - arg1, %dr2 - arg2
	 * Call special handle_guest_fast_sys_call function to pass
	 * control to guest ttable entry.
	 */
{
	puttagd,2       %dr1, 0, %dr1
	puttagd,5       %dr2, 0, %dr2
}
{
	sxt,3		6, %dr1, %dr1
	sxt,4		6, %dr2, %dr2
	disp 		%ctpr1, handle_compat_guest_fast_sys_call
}
{
	call		%ctpr1, wbs = 0x4
}
#endif /* CONFIG_KVM_HOST_MODE */
SYM_FUNC_END(ttable_entry5)


.global fast_sys_calls_table;
.global ttable_entry6;

.section	.ttable_entry6, "ax",@progbits
SYM_FUNC_START(ttable_entry6)
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid:
	 * dr0 - masked sys_num, dr1 - arg1, dr2 - arg2 */
{
	VFRPSZ(4)
	setwd		wsz = 0x8
	setbn		rbs = 0x4, rsz = 0x3, rcur = 0x0
}
{
	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,0		%dr0, NR_fast_syscalls_mask, %dr0
}
{
	/* Read pointer to host thread_info from osr0 reg */
	rrd,0 		%osr0, %dr3
}

	/*
	 * Check TS_HOST_AT_VCPU_MODE thread status flag.
	 * If flag is not set - host syscall, if set - guest syscall
	 */
{
	ldd,2		[ %dr3 + TI_STATUS ], %dr3
}
{
	andd,0 		%dr3, TS_HOST_AT_VCPU_MODE, %dr3
}
{
	cmpedb,0	%dr3, 0x0, %pred0
	disp 		%ctpr1, guest_syscall
}
{
	ct 		%ctpr1 ? ~%pred0
}
	/*
	 * This syscall is from host user, goto fast syscall handler
	 * with 2 parameters. sys_num is index in fast_sys_calls_table
	 */
{
	shld,0          %dr0, 3, %dr0
}
{
	ldd,0 		[fast_sys_calls_table + %dr0], %dr3
	puttagd,2       %dr1, 0, %dr0
	puttagd,5	%dr2, 0, %dr1
}
{
	movtd		%dr3, %ctpr1
}
{
	ct 		%ctpr1
}
guest_syscall:
#ifdef CONFIG_KVM_HOST_MODE
	/*
	 * This sycall is from guest user. Guest ttable entry handler
	 * will be executed on current hw stack frame. Prepare parameters
	 * for it:
	 * %dr0 - sys_num, %dr1 - arg1, %dr2 - arg2
	 * Call special handle_guest_fast_sys_call function to pass
	 * control to guest ttable entry.
	 */
{
	puttagd,2       %dr1, 0, %dr1
	puttagd,5       %dr2, 0, %dr2
	disp 		%ctpr1, handle_guest_fast_sys_call
}
{
	call		%ctpr1, wbs = 0x4
}
#endif /* CONFIG_KVM_HOST_MODE */
SYM_FUNC_END(ttable_entry6)

#ifdef CONFIG_KVM_HOST_MODE
/* Function to return to it from guest's fast syscall */
.global $ret_from_fast_sys_call;

SYM_FUNC_START(ret_from_fast_sys_call)
{
	nop 3
	addd,0,sm 0x0, %db[0], %dr3
	return %ctpr3
}
{
	addd,0,sm %dr3, 0x0, %dr0
}
{
	ct %ctpr3
}
SYM_FUNC_END(ret_from_fast_sys_call)
#endif /* CONFIG_KVM_HOST_MODE */

#ifdef CONFIG_PROTECTED_MODE
.global fast_sys_calls_table_128;

.section	.ttable_entry7, "ax",@progbits
SYM_FUNC_START(ttable_entry7)
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid.
	 *
	 * Read tags of %dr1 - %dr5 and pack them by forths in %r0.
	 * Clear any speculative tags in arguments, which can be unused
	 * by some system calls. */
{
	VFRPSZ(8)
	setwd wsz = 0xd
	setbn rsz=3, rbs=9, rcur=0

	rrd %sbr, %dr16

	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,1		%dr0, NR_fast_syscalls_mask, %dr0

	addd,2 0, 1, %dr17

	gettagd,5	%dr2, %r10
}
{
	wait all_e=1
	rrd %usd.lo, %dr15
}
{
	shld,1		%dr0, 3, %dr0

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
	nop 1
	mmurw,2 %dr17, %us_cl_d
	insfd,1 %dr16, 0x800, %dr15, %dr17
}
{
	movtd,0		%dr8, %ctpr1

	shls,2		%r13, 20, %r13
}
{
	nop 5
	rwd %dr17, %usd.lo

	ors,1		%r11, %r13, %r11
	addd		%dr15, 0, %db[1]
	puttagd,5	%dr2, 0, %db[2]
}
{
	ors,1		%r11, %r10, %r11
	puttagd,2	%dr3, 0, %db[3]
	puttagd,5	%dr4, 0, %db[4]
}
{
	ors,0		%r11, %r12, %r11
	puttagd,2	%dr5, 0, %db[5]
}
{
	adds,0		%r11, 0, %b[0]
	/* Use call instead of jump so that we can restore %usd.p here */
	call %ctpr1, wbs=9
}
{
	nop 7
	rwd %dr15, %usd.lo
	adds,1 0, %b[0], %r0
	addd,2 0, 0, %dr17
	return %ctpr3
}
{
	nop 2
	mmurw,2 %dr17, %us_cl_d
}
{
	ct %ctpr3
}
SYM_FUNC_END(ttable_entry7)

.global	ttable_entry8_C;

.section	.ttable_entry8, "ax",@progbits
SYM_FUNC_START(ttable_entry8)
	VFRPSZ_SETWD(8)
	/* Wait for CLW so that it does not force
	 * normal kernel accesses into trap cellar */
	wait all_e=1
	SWITCH_HW_STACKS_SYSCALL()
	{
		setwd	wsz = 18, nfx = 1
		ldgdd,0 TSK_STACK, %dr1
		ldgdd,3 TSK_K_USD_HI, %dr25
		addd,1	0, 1, %dr28
		/* Read tags of %dr2 - %dr5 and pack them by forths in %dr1.
		 * Clear any speculative tags in arguments, which can be unused
		 * by some system calls. */
		gettagd,2 %dr2, %r17
		gettagd,5 %dr3, %r18
		ipd 3;
		disp %ctpr1, ttable_entry8_C;
	}
	{
		rrd %usd.lo, %dr29
		ldgdd,3 0, TSK_K_USD_LO, %dr27
		gettagd,2 %dr4, %r19
		gettagd,5 %dr5, %r20
		shls,1 %r17, 8, %r17
		shls,4 %r18, 12, %r18
	}

	/* goto guest kernel system call table entry, */
	/* if system call is from guest user */
	/* %dr14, %dr15, %dr16: temporary registers */
	/* %pred0, %pred1, %pred2: temporary predicates */
	GOTO_GUEST_KERNEL_PROT_TTABLE 8, GCURTASK, %dr14, %dr15, %dr16,	\
						%pred0, %pred1, %pred2

	{
		rrd %usd.hi, %dr30
		shls,1 %r19, 16, %r19
		shls,4 %r20, 20, %r20
		gettagd,2 %dr6, %r21
		gettagd,5 %dr7, %r22
		ldgdw,3 0, TSK_PTRACE, %r16
	}
	{
		rrs	%upsr, %r31

		ldgdd,5 0, TSK_U_STACK_TOP, %dr15
		addd,4	0, E2K_KERNEL_CONTEXT, %dr33

		addd,1	%dr1, KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET, %dr1
		/* Disable CLW unit for nonprotected mode.
		 * "wait all_e" for FPU/CLW is done before switching hardware stacks */
		mmurw,2 %dr28, %us_cl_d
	}
	/* Switch to kernel local data stack */
	ALTERNATIVE_1_ALTINSTR
		/* CPU_HWBUG_USD_ALIGNMENT version */
		{
			rwd	%dr1, %sbr
			gettagd,2 %dr8, %r23
			gettagd,5 %dr9, %r24
			ors,1 %r17, %r19, %r19
			ors,4 %r18, %r20, %r20
			nop 1
		}
	ALTERNATIVE_2_OLDINSTR
		/* Default version */
		{
			rwd	%dr1, %sbr
			gettagd,2 %dr8, %r23
			gettagd,5 %dr9, %r24
			ors,1 %r17, %r19, %r19
			ors,4 %r18, %r20, %r20
		}
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_USD_ALIGNMENT)
	{
		rwd	%dr27, %usd.lo
		gettagd,2 %dr10, %r17
		gettagd,5 %dr11, %r18
		sxt,1 6, %r21, %dr21
		sxt,4 6, %r22, %dr22
	}
	ALTERNATIVE_1_ALTINSTR
		/* CPU_FEAT_SEP_VIRT_SPACE version - get kernel PT root from %os_pptb */
		{
			rwd     %dr25, %usd.hi
			puttagd,5 %dr2, 0, %dr2
			sxt,1 6, %r23, %dr23
			sxt,4 6, %r24, %dr24
			mmurr,2 %os_pptb, %dr32
		}
	ALTERNATIVE_2_OLDINSTR
		/* Original instruction - get kernel PT root from memory */
		{
			rwd     %dr25, %usd.hi
			puttagd,5 %dr2, 0, %dr2
			sxt,1 6, %r23, %dr23
			sxt,4 6, %r24, %dr24
			NOT_SEP_VIRT_SPACE_ONLY(ldgdd,2 0, TSK_K_ROOT_PTB, %dr32)
		}
	ALTERNATIVE_3_FEATURE(CPU_FEAT_SEP_VIRT_SPACE)
	{
		shld,0 %dr21, 24, %dr21
		shld,3 %dr22, 28, %dr22
		shld,1 %dr23, 32, %dr23
		shld,4 %dr24, 36, %dr24
		puttagd,2 %dr3, 0, %dr3
		puttagd,5 %dr4, 0, %dr4
	}

	ALTERNATIVE_1_ALTINSTR
		/* PSR IRQ masks are global, UPSR masks are not used */
		{
			adds	0, E2K_KERNEL_UPSR_GLOB_IRQ_ENABLED, %r1
			stw,5 %r31, GCURTASK, TSK_UPSR
		}
	ALTERNATIVE_2_OLDINSTR
		/* PSR IRQ mask is local and UPSR masks are used as global */
		{
			adds	0, E2K_KERNEL_UPSR_LOC_IRQ_ENABLED, %r1
			stw,5 %r31, GCURTASK, TSK_UPSR
		}
	ALTERNATIVE_3_FEATURE(CPU_FEAT_GLOBAL_IRQ_MASK)

	{
		rws	%r1, %upsr
		gettagd,2 %dr12, %r21
		gettagd,5 %dr13, %r22
		ord,1 %dr21, %dr23, %dr23
		ord,4 %dr22, %dr24, %dr24
	}
	{
		puttagd,2 %dr5, 0, %dr5
		ors,3 %r19, %r20, %r1
		sxt,1 6, %r17, %dr17
		sxt,4 6, %r18, %dr18
		sxt,0 6, %r21, %dr21
		sxt,5 6, %r22, %dr22
	}
	{
		/* MMU registers can be written only after disabling CLW/AAU;
		 * "wait all_e" from MMURW_WAIT_ASYNC_TLB is done before
		 * switching hardware stacks */
		mmurw %dr33, %cont
		puttagd,5 %dr6, 0, %dr6
		shld,1 %dr17, 40, %dr17
		shld,4 %dr18, 44, %dr18
		shld,0 %dr21, 48, %dr21
		shld,3 %dr22, 52, %dr22
	}
	{
		mmurw,2 %dr32, %root_ptb
		ord,1 %dr17, %dr21, %dr21
		ord,4 %dr18, %dr22, %dr22
		sxt,3 6, %r1, %dr1
	}
	{
		/* mmurw -> memory access */
		nop 2
		wait all_c=1

		puttagd,2 %dr7, 0, %dr7
		puttags,5 %r0, 0, %r0
	}

	/* Reserve memory for 'struct pt_regs' and parameters and put in
	 * there the last argument 'tags' (cannot put it in %dr8 since the
	 * size of the register window for C functions is only 8 dregs). */
	{
		getsp   -PTRACE_SZOF, %dr14;
		SMP_ONLY(shld,3 GCPUID_PREEMPT, 3, GCPUOFFSET)

		puttagd,2 %dr8, 0, %dr8
		puttagd,5 %dr9, 0, %dr9
	}
	{
		/* %dr20: current_thread_info */
		addd GCURTASK, TSK_TI, %dr20;
		sxt,4 6, %r0, %dr0

		SMP_ONLY(ldd,3 GCPUOFFSET, __per_cpu_offset, GCPUOFFSET)

		puttagd,2 %dr10, 0, %dr10
		puttagd,5 %dr11, 0, %dr11
	}
	/*
	 * Guest under hardware virtualization support - IS_HV_GM()
	 * should save global registers used by host to support
	 * (para)virtualization. Saving is unconditional because of
	 * only such guest can be here.
	 * %dr20 - pointer to thread info
	 * %dr17 - temporary registers
	 */
	SAVE_HOST_GREGS_TO_VIRT_UNEXT %dr20, %dr17

	/* Go to main protected system call handler.
	 * Do not store tags because we pass tags via %dr1 */
	{
		std,2 %dr29, [%dr14 + PT_STACK+ST_USD_LO]
		puttagd,5 %dr12, 0, %dr12
	}
	{
		getsp   -64, %empty;
		std,2 %dr30, [%dr14 + PT_STACK+ST_USD_HI]
		puttagd,5 %dr13, 0, %dr13
		ord,4 %dr23, %dr24, %dr24
	}
	{
		std,2 %dr6, [%dr14 + PT_ARG_5]
		std,5 %dr7, [%dr14 + PT_ARG_6]
		ord,4 %dr1, %dr24, %dr1
	}
	{
		adds,1 8, 0, %r8
		std,2 %dr8, [%dr14 + PT_ARG_7]
		std,5 %dr9, [%dr14 + PT_ARG_8]
		ord,4 %dr21, %dr22, %dr22
		cmpesb,3 %r16, 0, %pred4
	}
	{
		std,2 %dr10, [%dr14 + PT_ARG_9]
		std,5 %dr11, [%dr14 + PT_ARG_10]
		ord,4 %dr1, %dr22, %dr1
	}
	{
		std,2 %dr12, [%dr14 + PT_ARG_11]
		std,5 %dr13, [%dr14 + PT_ARG_12]
	}
	{
		addd,0 %dr14, 0, %dr6

		stw,2	%r8, [ %dr14 + PT_KERNEL_ENTRY ]
		std %dr15, [%dr14 + PT_STACK+ST_TOP]

		ct %ctpr1 ? %pred4
	}
	ibranch save_dam_and_jump_ctpr1
SYM_FUNC_END(ttable_entry8)

#endif /* CONFIG_PROTECTED_MODE */

.section ".ttable_entry11", "ax"
SYM_FUNC_START(osgd_to_gd)
	{
		nop 3
		return %ctpr3
	}
	ct %ctpr3
SYM_FUNC_END(osgd_to_gd)

.section ".text", "ax"
SYM_FUNC_START(save_dam_and_jump_ctpr1)
	SAVE_DAM(%dr8, %dr9, %dr10, %dr11)
	{
		ct %ctpr1
	}
SYM_FUNC_END(save_dam_and_jump_ctpr1)

SYM_FUNC_START(sys_backtrace_return)
	{
		nop 3
		return %ctpr3
	}
	ct %ctpr3
SYM_FUNC_END(sys_backtrace_return)

.section ".init.text", "ax"
.global __trampolines_start
.global __trampolines_end

#ifdef	CONFIG_KVM_HOST_MODE
# define KVM_TRAMPOLINE_END() \
	{ \
		nop 3; \
		return %ctpr3; \
	} \
	ct %ctpr3;

#else	/* !defined(CONFIG_KVM_HOST_MODE) */
# define KVM_TRAMPOLINE_END()
#endif	/* CONFIG_KVM_HOST_MODE */

.align 4096
__trampolines_start:

SYM_FUNC_START(sighandler_trampoline_32)
{
	nop 4
	setwd wsz=8
	setbn rsz=3, rbs=4, rcur=0
	sdisp %ctpr2, 1
}
{
	adds 0, __NR_sigreturn, %b[0]
	addd 0, 0, %db[1]
	call %ctpr2, wbs=4
}
	KVM_TRAMPOLINE_END()
	setsft
SYM_FUNC_END(sighandler_trampoline_32)

.align 256
SYM_FUNC_START(sighandler_trampoline_64)
{
	nop 4
	setwd wsz=8
	setbn rsz=3, rbs=4, rcur=0
	sdisp %ctpr2, 3
}
{
	adds 0, __NR_sigreturn, %b[0]
	addd 0, 0, %db[1]
	call %ctpr2, wbs=4
}
	KVM_TRAMPOLINE_END()
	setsft
SYM_FUNC_END(sighandler_trampoline_64)

.align 256
SYM_FUNC_START(sighandler_trampoline_128)
{
	nop 4
	setwd wsz=16
	setbn rsz=7, rbs=8, rcur=0
	sdisp %ctpr2, 8
}
{
	adds 0, __NR_sigreturn, %b[0]
	addd 0, 0, %db[2]
	call %ctpr2, wbs=8
}
	KVM_TRAMPOLINE_END()
	setsft
SYM_FUNC_END(sighandler_trampoline_128)

.align 256
SYM_FUNC_START(makecontext_trampoline_32)
{
	nop 4
	setwd wsz=8
	setbn rsz=3, rbs=4, rcur=0
	sdisp %ctpr2, 1
	cmpedb %dr0, 0, %pred0
}
{
	adds 0, __NR_setcontext, %b[0] ? ~ %pred0
	adds %dr0, 0, %b[1] ? ~ %pred0
	adds 0, 8, %b[2] ? ~ %pred0
	call %ctpr2, wbs=4 ? ~ %pred0
}
{
	nop 4
	sdisp %ctpr2, 1
	adds 0, 0, %b[0] ? %pred0
}
{
	adds 0, __NR_exit, %b[0]
	subs 0, %b[0], %b[1]
	call %ctpr2, wbs=4
}
	setsft
SYM_FUNC_END(makecontext_trampoline_32)

.align 256
SYM_FUNC_START(makecontext_trampoline_64)
{
	nop 4
	setwd wsz=8
	setbn rsz=3, rbs=4, rcur=0
	sdisp %ctpr2, 3
	cmpedb %dr0, 0, %pred0
}
{
	adds 0, __NR_setcontext, %b[0] ? ~ %pred0
	addd %dr0, 0, %db[1] ? ~ %pred0
	adds 0, 8, %b[2] ? ~ %pred0
	call %ctpr2, wbs=4 ? ~ %pred0
}
{
	nop 4
	sdisp %ctpr2, 3
	adds 0, 0, %b[0] ? %pred0
}
{
	adds 0, __NR_exit, %b[0]
	subs 0, %b[0], %b[1]
	call %ctpr2, wbs=4
}
	setsft
SYM_FUNC_END(makecontext_trampoline_64)

.align 256
SYM_FUNC_START(makecontext_trampoline_128)
{
	nop 1
	setwd wsz=16
	setbn rsz=7, rbs=8, rcur=0
	sdisp %ctpr2, 8
	getva %qr0, 0, %dr2
}
{
	nop 2
	cmpedb %dr2, 0, %pred0
}
{
	adds 0, __NR_setcontext, %b[0] ? ~ %pred0
	movtq %qr0, %qb[2] ? ~ %pred0
	adds 0, 8, %b[4] ? ~ %pred0
	call %ctpr2, wbs=8
}
{
	nop 4
	sdisp %ctpr2, 8
	adds 0, 0, %b[0] ? %pred0
}
{
	adds 0, __NR_exit, %b[0]
	subs 0, %b[0], %b[2]
	call %ctpr2, wbs=8
}
	setsft
SYM_FUNC_END(makecontext_trampoline_128)

__trampolines_end:
