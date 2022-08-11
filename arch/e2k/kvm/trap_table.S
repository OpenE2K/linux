//
// Trap table entries implemented on assembler
//

#undef NATIVE_TASK_SIZE
#undef	HOST_TASK_SIZE
#undef	GUEST_TASK_SIZE
#include <asm/alternative-asm.h>
#include <asm/mmu_regs_types.h>
#include <asm/cpu_regs_types.h>
#include <asm/e2k_api.h>
#include <generated/asm-offsets.h>
#include <asm/pv_info.h>
#include <asm/trap_table.h>
#include <asm/trap_table.S.h>

.global kvm_light_hcalls;
.global	kvm_generic_hcalls;
.global dump_stack;
.global trap_handler_trampoline_continue;
.global syscall_handler_trampoline_continue;
.global syscall_fork_trampoline_continue;

#ifdef CONFIG_CLW_ENABLE
# define CLW_ONLY(...) __VA_ARGS__
#else
# define CLW_ONLY(...)
#endif

#define HCALL_WSZ 11

/* ttable_entry16/17 - wrappers for software paravirtualiation mode.
 * Hypervisor must use hret when entered from hcall, so we remember
 * whether guest used `hcall' or `sdisp' here. */
.global ttable_entry16
.section .ttable_entry16, "ax",@progbits
	.align	8
	.type	 ttable_entry16,@function	// hypercalls
ttable_entry16:
	{
	/* Disable load/store generations */
	crp
	}
	{
	setwd	wsz = HCALL_WSZ, nfx = 0
	rrd	%osr0, %dr17			// %dr17: current_thread_info
	shld 1, 63, %dr18
	}
	{
	/* Important: the first memory access in kernel is store.
	 * This is needed to flush SLT before trying to load anything. */
	stw,sm %r0, [slt_disable + 0]
	}

	// if (READ_SBR_REG() < NATIVE_TASK_SIZE) {
	//	thread_info = current_thread_info();
	//	sbr = current->stack +KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET
	//	usd_lo = thread_info->k_usd_lo;
	//	usd_hi = thread_info->k_usd_hi;
	//	WRITE_USBR_USD_REG(sbr, usd_hi, usd_lo);
	/*	FIXME: generic hypercalls do not increment hardware stacks now
	//	psp_hi = READ_PSP_HI_REG();
	//	pcsp_hi = READ_PCSP_HI_REG();
	//	psp_hi.PSP_hi_size += thread_info->k_ps_sz;
	//	pcsp_hi.PCSP_hi_size += thread_info->k_pcs_sz;
	//	WRITE_PSP_HI_REG(psp_hi);
	//	WRITE_PCSP_HI_REG(pcsp_hi);
	//	thread_info->upsr = NATIVE_READ_UPSR_REG_VALUE();
	 */
	// }

	/* flush hardware stacks to cause the possible page fault on guest */
	{
	flushc
	}
	{
	flushr
	}
	{
	wait	fl_c = 1
	}
	{
	rrd	%sbr, %dr7
	addd	0, NATIVE_TASK_SIZE - 1, %dr19
	}
	// %dr17: current_thread_info
	// %pred0, %dr10, %dr11, %dr12: temporary predicate and registers
	SWITCH_TO_KERNEL_IMAGE_PGD %dr17, %pred0, %dr10, %dr11, %dr12
	{
	ldd	[%dr17 + TSK_TI_STACK_DELTA], %dr10	// %dr10: stack
	ldd	[%dr17 + TI_K_USD_HI], %dr8		// %dr8: usd_hi
	ipd 0
	disp %ctpr1, bad_hcall
	}
	{
	nop 2
	rrd	%usd.hi, %dr20
	cmpbedb	%dr7, %dr19, %pred0	// sbr < NATIVE_TASK_SIZE
	ldd	[%dr17 + TI_K_USD_LO], %dr9	// %dr9: usd_lo
	disp %ctpr3, kvm_generic_hcalls
	}
	{
	addd	%dr10, KERNEL_C_STACK_SIZE + KERNEL_C_STACK_OFFSET, %dr10
	ldd [%dr17 + TI_VCPU], %dr19 ? %pred0
	ct %ctpr1 ? ~ %pred0
	}
	{
	rrd	%usd.lo, %dr21
	puttagd,5 %dr0, 0, %dr0
	}
	{
	rrs	%psr, %dr13		// psr = READ_PSR_REG_VALUE();
	puttagd,2 %dr1, 0, %dr1
	puttagd,5 %dr2, 0, %dr2
	}
	{
	puttagd,2 %dr3, 0, %dr3
	puttagd,5 %dr4, 0, %dr4
	}
	{
	puttagd,2 %dr5, 0, %dr5
	puttagd,5 %dr6, 0, %dr6
	}
	// Switch to kernel local data stack: WRITE_USBR_USD_REG(sbr, usd_hi, usd_lo)
	ALTERNATIVE_1_ALTINSTR
		/* CPU_HWBUG_USD_ALIGNMENT version */
		{
		rwd	%dr10, %sbr
		sxt 6, %r0, %dr0
		nop 1
		}
	ALTERNATIVE_2_OLDINSTR
		/* Default version */
		/* CPU_HWBUG_USD_ALIGNMENT version */
		{
		rwd	%dr10, %sbr
		sxt 6, %r0, %dr0
		}
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_USD_ALIGNMENT)
	{
	rwd	%dr9, %usd.lo
	andns	%dr13, PSR_SGE_AS, %dr13	// psr &= ~PSR_SGE;
	}
	{
	nop 4 /* usd->getsp */
	rwd	%dr8, %usd.hi
	ord %dr0, %dr18, %dr0
	std	%dr7, [ %dr19 + VCPU_ARCH_CTXT_SBR ]
	}

	/*
	 * Do not increment hardware stacks sizes on kernel resident part
	 * it should be done by appropriate trap handlers,
	 * but disable 'sge' flag to prevent from hardware stacks bounds traps
	 * while switch to host kernel context
	 * FIXME: 'sge' disabling should by done by hardware (as for traps)
	 */
	{
	rws	%dr13, %psr			// WRITE_PSR_REG_VALUE(psr);
	std	%dr20, [ %dr19 + VCPU_ARCH_CTXT_USD_HI ]
	std	%dr21, [ %dr19 + VCPU_ARCH_CTXT_USD_LO ]
	ct %ctpr3
	}

#if 0	/* FIXME: generic hypercalls do not increment hardware stacks now */
{
	rrd	%psp.hi, %dr13;			// %dr13: psp_hi
	ldw	[%dr17 + TI_K_PS_LIM], %dr15;	// %dr15: k_ps_limit
	ldw	[%dr17 + TI_K_PCS_LIM], %dr16;	// %dr16: k_pcs_limit
}
{
	/* ti->u_hw_stack.k_ps_reserved = k_ps_limit */
	/* ti->u_hw_stack.k_pcs_reserved = k_pcs_limit */
	stw	%dr15, [%dr1 + TI_K_PS_RES];
	stw	%dr16, [%dr1 + TI_K_PCS_RES];

     	rrd	%pcsp.hi, %dr14;		// %dr14: pcsp_hi

	shld	%dr15, 32, %dr15;
	shld	%dr16, 32, %dr16;
}
{
	addd	%dr13, %dr15, %dr13	// psp_hi.PSP_hi_size += k_ps_limit
	addd	%dr14, %dr16, %dr14	// pcsp_hi.PCSP_hi_size += k_pcs_limit
}
{
	rwd	%dr13, %psp.hi		// WRITE_PSP_HI_REG(psp_hi)
	rwd	%dr14, %pcsp.hi		// WRITE_PCSP_HI_REG(pcsp_hi)
}
#endif	/* 0 */	/* FIXME: generic hypercalls do not increment hardware */
	/* stacks now */

bad_hcall:
	/* error */
	rrd	%osr0, %dr7			// %dr7: current_thread_info
	subd	%dr7, TSK_TI, %dr8		// %dr8: current
#ifdef CONFIG_SMP
	ldw	[%dr7 + TSK_TI_CPU_DELTA], %r10	// %dr10: smp_processor_id()
	shld	%dr10, 3, %dr9
	ldd	[__per_cpu_offset + %dr9], %dr9	// %dr9: per CPU offset
#endif
	addd 0, 0, %dr7
	ONLY_SET_KERNEL_GREGS %dr7, %dr8, %dr9, %dr10
	ibranch	dump_stack
#ifdef CONFIG_CPU_HWBUG_IBRANCH
	{nop} {nop}
#endif
	.size ttable_entry16, . -$ttable_entry16

.global ttable_entry17
.section .ttable_entry17, "ax",@progbits
	.align	8
	.type	 ttable_entry17,@function	// light hypercalls
ttable_entry17:
	{
	/* Disable load/store generations */
	crp
	}
	{
	setwd	wsz = HCALL_WSZ, nfx = 0
	rrd	%osr0, %dr9			// %dr9: current_thread_info
	shld 1, 63, %dr18
	}
	{
	/* Important: the first memory access in kernel is store.
	 * This is needed to flush SLT before trying to load anything. */
	stw,sm %r0, [slt_disable + 0]
	}

	/* flush hardware stacks to cause the possible page fault on guest */
	{
	flushc
	}
	{
	flushr
	}
	{
	wait	fl_c = 1
	}

	// trap can occur on guest kernel
	// %dr9: current_thread_info
	// %pred0, %dr10, %dr11, %dr12: temporary predicate and registers
	SWITCH_TO_KERNEL_IMAGE_PGD %dr9, %pred0, %dr10, %dr11, %dr12

	/*
	 * Light hypercalls do not switch to kernel local data stack
	 * and do not increment hardware stacks sizes on kernel resident part
	 * but disable 'sge' flag to prevent from hardware stacks bounds traps
	 * while switch to host kernel context
	 * FIXME: 'sge' disabling should by done by hardware (as for traps)
	 */
	{
	rrs	%psr, %dr13			// psr = READ_PSR_REG_VALUE();
	puttagd,2 %dr0, 0, %dr0
	puttagd,5 %dr1, 0, %dr1
	disp %ctpr1, kvm_light_hcalls
	}
	{
	andns	%dr13, PSR_SGE_AS, %dr13	// psr &= ~PSR_SGE;
	puttagd,2 %dr2, 0, %dr2
	puttagd,5 %dr3, 0, %dr3
	}
	{
	rws	%dr13, %psr			// WRITE_PSR_REG_VALUE(psr);
	puttagd,2 %dr4, 0, %dr4
	puttagd,5 %dr5, 0, %dr5
	}
	{
	ord %dr0, %dr18, %dr0
	puttagd,2 %dr6, 0, %dr6
	ct %ctpr1
	}
	.size ttable_entry17, . -$ttable_entry17

.global slt_disable;

/*
 * lcc does not support setting __interrupt attribute on
 * kvm_light_hypercalls() - it is too complex - so just switch
 * the data stack the same way kvm_generic_hypercalls() does.
 * Also switch clw context for protected mode (kvm_switch_clw_regs)
 */
#define HW_HCALL(KERNEL_ENTRY) \
	{ \
		setwd wsz = HCALL_WSZ, nfx = 0; \
		rrd %rpr.lo, %dr20; \
	} \
	{ \
		rrd %rpr.hi, %dr21; \
		/* Disable load/store generations */ \
		crp; \
	} \
	{ \
		disp %ctpr3, KERNEL_ENTRY; \
		rrd %osr0, %dr17; /* %dr17: current_thread_info */ \
		/* Important: the first memory access in kernel is store. \
		 * This is needed to flush SLT before trying to load anything. */ \
		stw,sm %r0, [slt_disable + 0]; \
		CLW_ONLY(addd,1 0, _MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), %dr18); \
		CLW_ONLY(addd,2 0, 1, %dr16) \
	} \
	{ \
		rwd %dr20, %rpr.lo; \
		CLW_ONLY(ldd,2 [%dr18], %dr12 MAS_MMU_REG) \
	} \
	{ \
		nop 1; /* ldd */ \
		rwd %dr21, %rpr.hi; \
		ldd,2 [%dr17 + TI_VCPU], %dr19; \
	} \
	{ \
		CLW_ONLY(nop 2;) /* mmurw us_cl_d -> mmurr us_cl_* */ \
		rrd %sbr, %dr7; \
		puttagd,5 %dr0, 0, %dr0; \
		CLW_ONLY(std,2 %dr16, [%dr18] MAS_MMU_REG) \
	} \
	{ \
		rrd %usd.hi, %dr20; \
		puttagd,2 %dr1, 0, %dr1; \
		CLW_ONLY(mmurr,5 %us_cl_b, %dr13) \
	} \
	{ \
		puttagd,2 %dr2, 0, %dr2; \
		CLW_ONLY(mmurr,5 %us_cl_up, %dr14) \
	} \
	{ \
		ldd [%dr19 + VCPU_ARCH_CTXT_SBR], %dr10; \
		ldd [%dr19 + VCPU_ARCH_CTXT_USD_HI], %dr8; \
		ldd [%dr19 + VCPU_ARCH_CTXT_USD_LO], %dr9; \
		ldb [%dr19 + VCPU_ARCH_CTXT_SAVED_VALID], %r11; \
	} \
	{ \
		rrd %usd.lo, %dr21; \
		puttagd,2 %dr3, 0, %dr3; \
		CLW_ONLY(mmurr,5 %us_cl_m0, %dr15) \
	} \
	{ \
		puttagd,2 %dr4, 0, %dr4; \
		CLW_ONLY(mmurr,5 %us_cl_m1, %dr16) \
	} \
	{ \
		puttagd,2 %dr5, 0, %dr5; \
		CLW_ONLY(mmurr,5 %us_cl_m2, %dr17) \
	} \
	{ \
		puttagd,2 %dr6, 0, %dr6; \
		CLW_ONLY(mmurr,5 %us_cl_m3, %dr18;) \
	} \
	{ \
		CLW_ONLY(std %dr12, [ %dr19 + VCPU_ARCH_CTXT_US_CL_D ];) \
		CLW_ONLY(std %dr13, [ %dr19 + VCPU_ARCH_CTXT_US_CL_B ];) \
	} \
	{ \
		CLW_ONLY(std %dr14, [ %dr19 + VCPU_ARCH_CTXT_US_CL_UP ];) \
		CLW_ONLY(std %dr15, [ %dr19 + VCPU_ARCH_CTXT_US_CL_M0 ];) \
	} \
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_HWBUG_USD_ALIGNMENT version */ \
		{ \
			CLW_ONLY(std %dr16, [ %dr19 + VCPU_ARCH_CTXT_US_CL_M1 ];) \
			rwd %dr10, %sbr; \
			nop 1; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Default version */ \
		{ \
			CLW_ONLY(std %dr16, [ %dr19 + VCPU_ARCH_CTXT_US_CL_M1 ];) \
			rwd %dr10, %sbr; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_USD_ALIGNMENT) \
	{ \
		rwd %dr9, %usd.lo; \
		CLW_ONLY(std %dr17, [ %dr19 + VCPU_ARCH_CTXT_US_CL_M2 ];) \
		CLW_ONLY(std %dr18, [ %dr19 + VCPU_ARCH_CTXT_US_CL_M3 ];) \
	} \
	{ \
		rwd %dr8, %usd.hi; \
		nop 2; /* usd->getsp */ \
		sxt 6, %r0, %dr0; \
		std %dr7, [ %dr19 + VCPU_ARCH_CTXT_SBR ]; \
		cmpesb %r11, 0, %pred0; \
	} \
	{ \
		std %dr20, [ %dr19 + VCPU_ARCH_CTXT_USD_HI ]; \
		std %dr21, [ %dr19 + VCPU_ARCH_CTXT_USD_LO ]; \
		adds,1 0, 1, %r11; \
		ibranch  1f ? ~%pred0; \
	} \
	{ \
		stb,2 %r11, [ %dr19 + VCPU_ARCH_CTXT_SAVED_VALID ]; \
		std %dr10, [ %dr19 + VCPU_ARCH_CTXT_SAVED_SBR ]; \
	} \
	{ \
		std %dr8, [ %dr19 + VCPU_ARCH_CTXT_SAVED_USD_HI ]; \
		std %dr9, [ %dr19 + VCPU_ARCH_CTXT_SAVED_USD_LO ]; \
		ct %ctpr3; \
	} \
1: \
	{ \
		setsft; \
	}

.section .hcall_entry0, "ax",@progbits
	.align	8
	.type	hcall_entry0,@function	// hypercalls
hcall_entry0:
	HW_HCALL(kvm_generic_hcalls)
	.size hcall_entry0, . -$hcall_entry0

.section .hcall_entry1, "ax",@progbits
	.align	8
	.type	hcall_entry1,@function	// light hypercalls
hcall_entry1:
	HW_HCALL(kvm_light_hcalls)
	.size hcall_entry1, . -$hcall_entry1

.global trap_handler_trampoline
.section ".irqentry.text", "ax"
.type trap_handler_trampoline,@function
trap_handler_trampoline:
	HANDLER_TRAMPOLINE %ctpr2, 11, trap_handler_trampoline_continue, 0
trap_handler_switched_stacks:
{
	setsft;
}
.size $trap_handler_trampoline, . - $trap_handler_trampoline

.global syscall_handler_trampoline
.section ".entry.text", "ax"
.type syscall_handler_trampoline,@function
syscall_handler_trampoline:
	HANDLER_TRAMPOLINE %ctpr2, 11, syscall_handler_trampoline_continue, 1
syscall_handler_switched_stacks:
{
	setsft;
}
.size $syscall_handler_trampoline, . - $syscall_handler_trampoline

.global syscall_fork_trampoline
.section ".entry.text", "ax"
.type syscall_fork_trampoline,@function
syscall_fork_trampoline:
	HANDLER_TRAMPOLINE %ctpr2, 11, syscall_fork_trampoline_continue, 1
syscall_fork_switched_stacks:
{
	setsft;
}
.size $syscall_fork_trampoline, . - $syscall_fork_trampoline


/*
  The next function simulates guest trap table entry and calls function
  which returns to guest entry at point ttable_func
static long
as_guest_ttable_entry(int sys_num,
		u64 arg1, u64 arg2, u64 arg3, u64 arg4, u64 arg5, u64 arg6,
		unsigned long ttable_func)
{
	return_to_guest_ttable_entry(ttable_func);
	return (0);
}
 */
.global return_to_guest_ttable_entry
.global as_guest_ttable_entry

.section	.as_guest_ttable_entry, "ax",@progbits
	.align	8
	.type	.as_guest_ttable_entry,@function
as_guest_ttable_entry:
	setwd	wsz = 0x6, nfx = 0
	setbn	rsz = 0x1, rbs = 0x4, rcur = 0x0
	setbp	psz = 0x0
	disp	%ctpr1, return_to_guest_ttable_entry
{	/* tags should be zeroed */
	puttagd	%dr0, 0, %dr0
	puttagd	%dr1, 0, %dr1
}
{
	puttagd	%dr2, 0, %dr2
	puttagd	%dr3, 0, %dr3
}
{
	puttagd	%dr4, 0, %dr4
	puttagd	%dr5, 0, %dr5
}
{
	puttagd	%dr6, 0, %dr6
	addd	0, %dr7, %db[0]
}
	call	%ctpr1, wbs = 4
	return	%ctpr3
	ct	%ctpr3
$.Lfeas_gtt:
	.size	 as_guest_ttable_entry, $.Lfeas_gtt-$as_guest_ttable_entry
