/*
 * Trap table entries implemented on assembler
 */

#include <asm/alternative-asm.h>
#include <asm/unistd.h>
#include <asm/mmu_regs_types.h>
#include <generated/asm-offsets.h>
#include <asm/pv_info.h>
#include <asm/mmu_types.h>
#include <asm/e2k_api.h>
#include <asm/trap_table.h>
#include <asm/trap_table.S.h>

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

.section .ttable_entry0, "ax",@progbits
.align 8
.type ttable_entry0,@function
ttable_entry0:
	/*
	 * Important: the first memory access in kernel is store, not load.
	 * This is needed to flush SLT before trying to load anything.
	 */
	ALTERNATIVE_1_ALTINSTR
		/* iset v5 version - save qp registers extended part */
		{
			/* #80747: must repeat interrupted barriers */
			wait fl_c=1
			stgdq,sm %qg16, 0, TSK_TI_TMP_G_VCPU_STATE
			qpswitchd,1,sm GVCPUSTATE, GVCPUSTATE
			qpswitchd,4,sm GCURTASK, GCURTASK
		}
		{
			stgdq,sm %qg18, 0, TSK_TI_TMP_G_MY_CPU_OFFSET
			qpswitchd,1,sm GCPUOFFSET, GCPUOFFSET
			qpswitchd,4,sm GCPUID_PREEMPT, GCPUID_PREEMPT
		}
	ALTERNATIVE_2_OLDINSTR
		/* Original instruction - save only 16 bits */
		{
			/* #80747: must repeat interrupted barriers */
			wait fl_c=1
			stgdq,sm %qg16, 0, TSK_TI_TMP_G_VCPU_STATE
			movfi,1 GVCPUSTATE, GVCPUSTATE
			movfi,4 GCURTASK, GCURTASK
		}
		{
			stgdq,sm %qg18, 0, TSK_TI_TMP_G_MY_CPU_OFFSET
			nop 2
			movfi,1 GCPUOFFSET, GCPUOFFSET
			movfi,4 GCPUID_PREEMPT, GCPUID_PREEMPT
		}
	ALTERNATIVE_3_FEATURE(CPU_FEAT_QPREG)

	{
		rrd %sbr, GCURTASK
		stgdq,sm %qg16, 0, TSK_TI_TMP_G_TASK
		/* Do not restore %rpr (it's not clobbered by kernel entry) */
		cmpesb,3 0, 1, %pred1
	}
	{
		rrd %osr0, GVCPUSTATE
		stgdq,sm %qg18, 0, TSK_TI_TMP_G_CPU_ID_PREEMPT
	}
	{
		rrd %psp.hi, GCURTASK
		/* pred0 = sbr < TASK_SIZE */
		cmpbedb,1 GCURTASK, TASK_SIZE - 1, %pred0
	}
	SWITCH_HW_STACKS(TSK_TI_TMP_)
trap_handler_switched_stacks:
	{
	setwd	wsz = 18, nfx = 1;
	rrd	%ctpr1, %dr6;
	ldd	GCURTASK, TSK_STACK, %dr1 ? %pred0; // %dr1: stack
	ldd	GCURTASK, TSK_K_USD_LO, %dr23 ? %pred0;	// %dr23: usd_lo
	ldd	GCURTASK, TSK_K_USD_HI, %dr22 ? %pred0;	// %dr22: usd_hi
	}

	// trap can occur on guest kernel
	// %pred20, %dr15, %dr16, %dr17: temporary predicate and registers
	SWITCH_TO_KERNEL_IMAGE_PGD GCURTASK, %pred20, %dr15, %dr16, %dr17

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
		/* iset v2 version */
		{
			addd 0, 0, %dr14
			addd 0, 0, %dr15
			addd 0, 0, %dr17
			addd 0, 0, %dr18
			addd 0, 0, %dr19
		}
	ALTERNATIVE_4_FEATURE2(CPU_FEAT_TRAP_V5, CPU_FEAT_TRAP_V6)

	{
	rrd %clkr, %dr0
	ipd 1
	disp	%ctpr1, 2f
	/* Read CLW unit registers state for protected mode */
	CLW_ONLY(mmurr,5 %us_cl_m0, %dr8 ? %pred0)
	}
	{
	rrd %sbr, %dr26
	CLW_ONLY(mmurr,5 %us_cl_m1, %dr9 ? %pred0)
	}
	{
	rrd	%usd.hi, %dr7;
	CLW_ONLY(mmurr,5 %us_cl_m2, %dr10 ? %pred0)
	}
	{
	rrd	%ctpr2, %dr5;
	CLW_ONLY(addd,1 0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), %dr20 ? %pred0)
	CLW_ONLY(addd,2 0, 1, %dr21 ? %pred0)
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
	 * 'wait all_e' as it is done by hardware on trap enter. */
	CLW_ONLY(std,2	%dr21, [%dr20] MAS_MMU_REG ? %pred0)
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
	{
	rws	E2K_KERNEL_UPSR_DISABLED_ALL, %upsr;

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
	nop 1; /* getsp -> use */
	getsp   -(PTRACE_SZOF + AAU_SZOF + TRAP_PTREGS_SZOF + 3 * 7), %dr0
	}
#ifdef CONFIG_CLW_ENABLE
	{
	std	%dr10, [%dr0 + PT_US_CL_M2]
	}
	{
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
	ct	%ctpr1;				// user_trap_handler()
	}

2: /* kernel */
	// if (READ_SBR_REG() >= TASK_SIZE)
	//	kernel_trap_handler();
	{
	ipd 2
	disp	%ctpr1, kernel_trap_handler;
	getsp   -(PTRACE_SZOF + TRAP_PTREGS_SZOF + 2 * 7), %dr0 ? ~ %pred1
	}
	{
	rrd	%lsr, %dr16
	ibranch kernel_data_stack_overflow ? %pred1
	}
	{
	rrd	%ilcr, %dr4;
	std,2	%dr6, [%dr0 + PT_CTRP1] ;	// regs->ctpr1 = ctpr1
	}
	{
	std,2	%dr5, [%dr0 + PT_CTRP2] ;	// regs->ctpr2 = ctpr2
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
	std %dr4, [%dr0 + PT_ILCR]
	std %dr16,[%dr0 + PT_LSR]
	ct %ctpr1;	// kernel_trap_handler()
	}
.size $ttable_entry0, . - $ttable_entry0


#ifdef CONFIG_CLW_ENABLE
#define PREPARE_CLW_ADDR(addr_reg) \
	addd,1	0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), addr_reg;
#define PREPARE_CLW_VAL(val_reg) \
	addd,1	0, 1, val_reg;
#define STORE_CLW_VAL(val_reg, addr_reg) \
	std,2	val_reg, 0, [addr_reg] MAS_MMU_REG;
#else /* !CONFIG_CLW_ENABLE */
#define PREPARE_CLW_ADDR(addr_reg)
#define PREPARE_CLW_VAL(val_reg)
#define STORE_CLW_VAL(val_reg, addr_reg)
#endif /* CONFIG_CLW_ENABLE */

#define WSZ 11
#define SYS_CALL(sys_call_table, FORMAT_32, KERNEL_ENTRY)		\
	{								\
		setwd	wsz = WSZ, nfx = 1;				\
		nop 2;							\
		rrd	%osr0, %dr7;					\
		ldd,2	GCURTASK, TSK_STACK, %dr10;			\
		ldd,3	GCURTASK, TSK_K_USD_HI, %dr8; 			\
		puttags,5 %r0, 0, %r0;					\
	}								\
									\
	/* goto guest kernel system call table entry, */		\
	/* if system call is from guest user */				\
	/* %dr7: register of current_thread_info() */			\
	/* %dr18, %dr19, %dr11: temporary registers */			\
	/* %pred1: temporary predicates */				\
	GOTO_PV_VCPU_KERNEL_TTABLE %dr7, %dr18, %dr19, %dr11, %pred1	\
									\
	{								\
		ipd 2;							\
		disp %ctpr1, handle_sys_call;				\
		PV_VCPU(rrd	%sbr, %dr21);				\
		cmpbsb,3 %r0, NR_syscalls,%pred3; /* sys_num < NR_syscalls */ \
		sxt,4	6, %r0, %dr0;					\
		ldd,5	GCURTASK, TSK_K_USD_LO, %dr9;			\
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
		PREPARE_CLW_VAL(%dr18);					\
		puttagd,2 %dr3, 0, %dr3;				\
		puttagd,5 %dr4, 0, %dr4;				\
	}								\
	{								\
		nop 3; /* rwd %usd -> getsp */				\
		rwd	%dr8, %usd.hi;					\
		PREPARE_CLW_ADDR(%dr17);				\
		puttagd,5 %dr5, 0, %dr5;				\
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
		rrs	%upsr, %r15;					\
		STORE_CLW_VAL(%dr18, %dr17);				\
	}								\
	{								\
		rws	E2K_KERNEL_UPSR_ENABLED,  %upsr;		\
		stw	%r15, GCURTASK, TSK_UPSR;			\
		puttagd,5 %dr6, 0, %dr6;				\
	}								\
	{								\
		nop 1; /* getsp -> usage */				\
		getsp	-(PTRACE_SZOF + 64), %dr7;			\
		adds,1	0, KERNEL_ENTRY, %r8;				\
		sxt,3	6, %r1, %dr1 ? %pred2;				\
		sxt,4	6, %r2, %dr2 ? %pred2;				\
	}								\
	{								\
		addd,1	%dr7, 64, %dr7;					\
		stw,2	%r0, [ %dr7 + (PT_SYS_NUM + 64) ];		\
		sxt,3	6, %r3, %dr3 ? %pred2;				\
		sxt,4	6, %r4, %dr4 ? %pred2;				\
	}								\
	{								\
		stw,2	%r8, [ %dr7 + PT_KERNEL_ENTRY ];		\
		SMP_ONLY(shld,4 GCPUID_PREEMPT, 3, GCPUOFFSET);		\
		/* regs->g_stacks.sbr/top = %sbr */			\
		PV_VCPU(std	%dr21, [%dr7 + PT_G_STACK+G_ST_SBR]);	\
	}								\
	{								\
		std,2	%dr19, [%dr7 + PT_STACK+ST_USD_LO];		\
		std,5	%dr20, [%dr7 + PT_STACK+ST_USD_HI];		\
		sxt,3	6, %r5, %dr5 ? %pred2;				\
		sxt,4	6, %r6, %dr6 ? %pred2;				\
	}								\
	{								\
		std,2	%dr11, [%dr7 + PT_STACK+ST_TOP];		\
		SMP_ONLY(ldd,5 GCPUOFFSET, __per_cpu_offset, GCPUOFFSET); \
		addd,4	%dr14, 0, %dr0;					\
		ct %ctpr1;						\
	}

.global	native_ttable_entry1;
.section	.native_ttable_entry1, "ax",@progbits
.align	8
.type	 native_ttable_entry1,@function
native_ttable_entry1:
	SWITCH_HW_STACKS_FROM_USER()
	SYS_CALL(sys_call_table_32, 1, 1)
.size $native_ttable_entry1, . - $native_ttable_entry1

.global	native_ttable_entry3;
.global native_ttable_entry3_switched;

.section	.native_ttable_entry3, "ax",@progbits
.align	8
.type	 native_ttable_entry3,@function
native_ttable_entry3:
	SWITCH_HW_STACKS_FROM_USER()
native_ttable_entry3_switched:
	SYS_CALL(sys_call_table, 0, 3)
.size $native_ttable_entry3, . - $native_ttable_entry3


.global	native_ttable_entry4;
.section	.native_ttable_entry4, "ax",@progbits
	.align	8
	.type	 native_ttable_entry4,@function
native_ttable_entry4:
	SWITCH_HW_STACKS_FROM_USER()
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
.size $native_ttable_entry4, . - $native_ttable_entry4


.global ttable_entry5;
.section	.ttable_entry5, "ax",@progbits
	.align	8
	.type	ttable_entry5,@function
ttable_entry5:
	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid. */
{
	setwd	wsz = 0x4
}

	/* goto guest kernel system call table entry, */
	/* if system call is from guest user */
	/* %dr7: temporary register to read current_thread_info() */
	/* %dr8, %dr9, %dr10: temporary registers */
	/* %pred0, %pred1, %pred2: temporary predicates */
	GOTO_GUEST_KERNEL_FAST_TTABLE 5, %dr7, %dr8, %dr9, %dr10,	\
						%pred0, %pred1, %pred2

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

	/* goto guest kernel system call table entry, */
	/* if system call is from guest user */
	/* %dr7: temporary register to read current_thread_info() */
	/* %dr8, %dr9, %dr10: temporary registers */
	/* %pred0, %pred1, %pred2: temporary predicates */
	GOTO_GUEST_KERNEL_FAST_TTABLE 6, %dr7, %dr8, %dr9, %dr10,	\
						%pred0, %pred1, %pred2

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
	/* goto guest kernel system call table entry, */
	/* if system call is from guest user */
	/* %dr7: temporary register to read current_thread_info() */
	/* %dr8, %dr9, %dr10: temporary registers */
	/* %pred0, %pred1, %pred2: temporary predicates */
	GOTO_GUEST_KERNEL_FAST_TTABLE 7, %dr7, %dr8, %dr9, %dr10,	\
						%pred0, %pred1, %pred2

	/* We want to just jump right to the handler without
	 * doing anything, but at least we have to make sure
	 * that the passed parameters are valid.
	 *
	 * Read tags of %dr1 - %dr5 and pack them by forths in %r0.
	 * Clear any speculative tags in arguments, which can be unused
	 * by some system calls. */
{
	setwd		wsz = 0x8

	/* If dr0 holds value with a bad tag, we will be SIGILL'ed.
	 * If we are called with an empty register window (no %dr0
	 * yet), we will be SIGSEGV'ed. */
	andd,0		%dr0, NR_fast_syscalls_mask, %dr0

	gettagd,5	%dr2, %r10
}
{
	shld,0		%dr0, 3, %dr0

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
	nop 1 /* movtd -> ct */

	ipd		2
	movtd,0		%dr8, %ctpr1
	nop 1

	shls,2		%r13, 20, %r13
}
{
	ors,0		%r11, %r13, %r11
	puttagd,5	%dr2, 0, %dr1
}
{
	ors,0		%r11, %r10, %r11
	puttagd,2	%dr3, 0, %dr2
	puttagd,5	%dr4, 0, %dr3
}
{
	ors,0		%r11, %r12, %r11
	puttagd,2	%dr5, 0, %dr4
}
{
	adds,0		%r11, 0, %r0
	ct		%ctpr1
}
.size	 $ttable_entry7, . -$ttable_entry7


#ifdef CONFIG_PROTECTED_MODE
.global	ttable_entry8_C;
.global	ttable_entry8

.section	.ttable_entry8, "ax",@progbits
	.align	8
	.type	 ttable_entry8@function
ttable_entry8:
	SWITCH_HW_STACKS_FROM_USER(
		ldgdd TSK_STACK, %dr1;
		ipd 3;
		disp %ctpr1, ttable_entry8_C;
	)
	{
		setwd	wsz = 16, nfx = 1
		ldgdd,3 TSK_K_USD_HI, %dr25
		addd,0	0, 1, %dr28
		addd,1	0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), %dr26
		/* Read tags of %dr2 - %dr5 and pack them by forths in %dr1.
		 * Clear any speculative tags in arguments, which can be unused
		 * by some system calls. */
		gettagd,2 %dr2, %r17
		gettagd,5 %dr3, %r18
	}
	{
		rrd %usd.lo, %dr29
		ldd,3 GCURTASK, TSK_K_USD_LO, %dr27
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
		/* "wait all_e" is done before switching hardware stacks */
		rrd %usd.hi, %dr30
		shls,1 %r19, 16, %r19
		shls,4 %r20, 20, %r20
		gettagd,2 %dr6, %r21
		gettagd,5 %dr7, %r22
		ldd,3 GCURTASK, TSK_U_STACK_TOP, %dr15
	}
	{
		rrs	%upsr, %r31

		puttags,5 %r0, 0, %r0
		addd,1	%dr1, KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET, %dr1
		/* Disable CLW unit for nonprotected mode */
		std,2	%dr28, 0, [%dr26] MAS_MMU_REG
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
	{
		rwd	%dr25, %usd.hi
		sxt,3 6, %r0, %dr0
		puttagd,2 %dr2, 0, %dr2
		puttagd,5 %dr3, 0, %dr3
		sxt,1 6, %r23, %dr23
		sxt,4 6, %r24, %dr24
	}
	{
		shld,0 %dr21, 24, %dr21
		shld,3 %dr22, 28, %dr22
		shld,1 %dr23, 32, %dr23
		shld,4 %dr24, 36, %dr24
		puttagd,2 %dr4, 0, %dr4
		puttagd,5 %dr5, 0, %dr5
	}
	{
		rws	E2K_KERNEL_UPSR_ENABLED, %upsr
		gettagd,2 %dr12, %r21
		gettagd,5 %dr13, %r22
		ord,1 %dr21, %dr23, %dr23
		ord,4 %dr22, %dr24, %dr24
	}
	{
		ors,3 %r19, %r20, %r1
		sxt,1 6, %r17, %dr17
		sxt,4 6, %r18, %dr18
		sxt,2 6, %r21, %dr21
		sxt,5 6, %r22, %dr22
	}
	{
		puttagd,2 %dr6, 0, %dr6
		puttagd,5 %dr7, 0, %dr7
		shld,1 %dr17, 40, %dr17
		shld,4 %dr18, 44, %dr18
		shld,0 %dr21, 48, %dr21
		shld,3 %dr22, 52, %dr22
	}
	{
		ord,1 %dr17, %dr21, %dr21
		ord,4 %dr18, %dr22, %dr22
		stw,2 %r31, GCURTASK, TSK_UPSR
		sxt,3 6, %r1, %dr1
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
		rrd	%osr0, %dr20

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

		ct	%ctpr1
	}
.size $ttable_entry8, . - $ttable_entry8

.global	ttable_entry10_C;
.global	ttable_entry10;

.section	.ttable_entry10, "ax",@progbits
	.align	8
	.type	 ttable_entry10,@function
ttable_entry10:
	SWITCH_HW_STACKS_FROM_USER()
	{
		setwd	wsz = 11, nfx = 1
		addd	0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), %dr16
		addd	0, 1, %dr17
	}

	/* goto guest kernel system call table entry, */
	/* if system call is from guest user */
	/* %dr7: temporary register to read current_thread_info() */
	/* %dr8, %dr9, %dr10: temporary registers */
	/* %pred0, %pred1, %pred2: temporary predicates */
	GOTO_GUEST_KERNEL_PROT_TTABLE 10, GCURTASK, %dr8, %dr9, %dr10,	\
						%pred0, %pred1, %pred2

	/* Read tags of %dr0 - %dr7 and pack them by forths in %dr8.
	 * Clear any speculative tags in arguments, which can be unused
	 * by some system calls. */
	{
		ipd 2
		disp %ctpr1, ttable_entry10_C
		rrd %usd.lo, %dr18
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
		sxt,1 6, %r0, %dr0
		puttagd,2 %dr2, 0, %dr2
		puttagd,5 %dr3, 0, %dr3
	}
	{
		rrd %usd.hi, %dr19

		ors,1 %r8, %r13, %r8
		puttagd,2 %dr4, 0, %dr4
		puttagd,5 %dr5, 0, %dr5
	}
	{
		ors,0 %r8, %r14, %r8
		puttagd,2 %dr6, 0, %dr6
		puttagd,5 %dr7, 0, %dr7
	}
	{
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
	//	WRITE_SBR_REG_VALUE(stack + KERNEL_C_STACK_SIZE +
	//			    KERNEL_C_STACK_OFFSET);

	// Switch to kernel local data stack
	{
		ldd,0	GCURTASK, TSK_K_USD_HI, %dr9	// %dr9: usd_hi
		ldd,2	GCURTASK, TSK_K_USD_LO, %dr10	// %dr10: usd_lo
		ldd,3	GCURTASK, TSK_STACK, %dr11 // %dr11: stack
		ldd,5   GCURTASK, TSK_U_STACK_TOP, %dr16  // %dr16: u_stack.top
	}
	{
		addd,1 %dr11, KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET, %dr12
	}
	ALTERNATIVE_1_ALTINSTR
		/* CPU_HWBUG_USD_ALIGNMENT version */
		{
			rwd	%dr12, %sbr
			nop 1
		}
	ALTERNATIVE_2_OLDINSTR
		/* Default version */
		{
			rwd	%dr12, %sbr
		}
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_USD_ALIGNMENT)
	{
		rwd	%dr10, %usd.lo
	}
	{
		rwd	%dr9, %usd.hi
	}
	{
		rrs	%upsr, %r20
	}
	{
		nop 3
		rws	E2K_KERNEL_UPSR_ENABLED, %upsr
	}

	/* Reserve memory for 'struct pt_regs' and parameters and put in
	 * there the last argument 'tags' (cannot put it in %dr8 since the
	 * size of the register window for C functions is only 8 dregs). */
	{
		getsp	-(6 * 8), %dr9
		SMP_ONLY(shld,1 GCPUID_PREEMPT, 3, GCPUOFFSET)
	}
	{
		stw %r20, GCURTASK, TSK_UPSR
	}
	{
		getsp   -(PTRACE_SZOF + 64), %dr7;
		std	%dr7, [%dr9]
	}
	{
		SMP_ONLY(ldd,2 GCPUOFFSET, __per_cpu_offset, GCPUOFFSET)
		stw	%r8, [%dr9 + 8]
	}

	/*
	 * Guest under hardware virtualization support - IS_HV_GM()
	 * should save global registers used by host to support
	 * (para)virtualization. Saving is unconditional because of
	 * only such guest can be here.
	 * %dr13 - pointer to thread info
	 * %dr10 - temporary registers
	 */
	SAVE_HOST_GREGS_TO_VIRT_UNEXT %dr13, %dr10

	{
		addd	%dr7, 64, %dr7
		std %dr18, [%dr7 + PT_STACK+ST_USD_LO + 64]
		std %dr19, [%dr7 + PT_STACK+ST_USD_HI + 64]
	}
	{
		std %dr16, [%dr7 + PT_STACK+ST_TOP]
		/* Go to main protected system call handler */
		ct	%ctpr1
	}
.size $ttable_entry10, . - $ttable_entry10
#endif /* CONFIG_PROTECTED_MODE */

.global osgd_to_gd
.section ".ttable_entry11", "ax"
.type osgd_to_gd,@function
osgd_to_gd:
	{
		nop 3
		return %ctpr3
	}
	ct %ctpr3
.size $osgd_to_gd, . - $osgd_to_gd

.global sighandler_trampoline

.section ".entry.text", "ax"
.type sighandler_trampoline,@function
sighandler_trampoline:
	HANDLER_TRAMPOLINE	%ctpr2, 11, sighandler_trampoline_continue, 0
.size $sighandler_trampoline, . - $sighandler_trampoline

.global makecontext_trampoline

.section ".entry.text", "ax"
.type makecontext_trampoline,@function
makecontext_trampoline:
	HANDLER_TRAMPOLINE	%ctpr2, 11, makecontext_trampoline_continue, 4
.size $makecontext_trampoline, . - $makecontext_trampoline

.global makecontext_trampoline_protected

.section ".entry.text", "ax"
.type makecontext_trampoline_protected,@function
makecontext_trampoline_protected:
    HANDLER_TRAMPOLINE    %ctpr2, 11, makecontext_trampoline_continue, 8
.size $makecontext_trampoline_protected, . - $makecontext_trampoline_protected
