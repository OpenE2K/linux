/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Defenition of traps handling routines.
 */

#ifndef _E2K_TRAP_TABLE_ASM_H
#define _E2K_TRAP_TABLE_ASM_H

#ifdef	__ASSEMBLY__

#include <linux/stringify.h>

#include <asm/alternative-asm.h>
#include <asm/glob_regs.h>
#include <asm/mmu_types.h>

#include <generated/asm-offsets.h>

#if defined CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
#else
# define SMP_ONLY(...)
#endif

#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
# define NOT_SEP_VIRT_SPACE_ONLY(...) __VA_ARGS__
#else
# define NOT_SEP_VIRT_SPACE_ONLY(...)
#endif

/* Make sure there are no surprises from improper parameter area size */
#define VFRPSZ_SETWD(size) { vfrpsz rpsz=size; setwd wsz=size; setbp psz=0 }
#define VFRPSZ(size) vfrpsz rpsz=size

#ifdef CONFIG_CPU_HAS_OSR1
# define CURRENT_REG %osr1
# define LOAD_TASK_FIELD_D(channel, offset, dst) \
	ldosrrd,channel 0, LDST_REC_D | (offset), dst
# define LOAD_TASK_FIELD_W(channel, offset, dst) \
	ldosrrd,channel 0, LDST_REC_W | (offset), dst
#else
# define CURRENT_REG %osr0
# define LOAD_TASK_FIELD_D(channel, offset, dst) \
	ldgdd,channel 0, (offset), dst
# define LOAD_TASK_FIELD_W(channel, offset, dst) \
	ldgdw,channel 0, (offset), dst
#endif


/*
 * Important: the first memory access in kernel is store, not load.
 * This is needed to flush SLT before trying to load anything.
 */
#define SWITCH_HW_STACKS_SYSCALL(tmp_pred) \
	KERNEL_ENTRY(TSK_TI_, %r0 /* syscall number */, 0 /* hw_trap */, tmp_pred)

/**
 * SWITCH_HW_STACKS - switch p[c]sp.{lo/hi} registers to kernel values
 * @pred: temporary predicate; will be set for user mode
 * @check_switch: set this to cmp instruction that indicates whether hardware
 *		  stacks are switched already
 *
 * Does the following:
 *
 * 1) Saves global registers either to 'thread_info.tmp_k_gregs' or to
 * 'thread_info.k_gregs'. The first area is used for trap handler since
 * we do not know whether it is from user or from kernel and whether
 * global registers have been saved already to 'thread_info.k_gregs'.
 *
 * 2) Saves stack registers to 'thread_info.tmp_user_stacks'. If this is
 * not a kernel trap then these values will be copied to pt_regs later.
 *
 * 3) Updates global and stack registers with kernel values
 */
#define SWITCH_HW_STACKS(pred, check_switch...) \
	{ \
		rrd %psp.hi, GCURTASK; \
		check_switch, pred; \
		ldgdd,2 0, TSK_TI_K_PSP_LO, GCPUOFFSET; \
		ldgdd,3 0, TSK_TI_K_PCSP_LO, GCPUID_PREEMPT; \
		ldgdd,5 0, TSK_TI_K_PSP_HI, GVCPUSTATE; \
	} \
	{ \
		rrd %psp.lo, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSP_HI; \
	} \
	{ \
		rrd %pcsp.hi, GCURTASK ? pred; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSP_LO ? pred; \
 \
		/* Restore my_cpu_offset as it was when entering kernel trap */ \
		SMP_ONLY(ldgdd,5 0, TSK_TI_TMP_G_MY_CPU_OFFSET, GCPUOFFSET ? ~ pred;) \
	} \
	{ \
		rrd %pcsp.lo, GCURTASK ? pred; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSP_HI ? pred; \
 \
		/* Restore preemption counter as it was when entering kernel trap */ \
		ldgdd,5 0, TSK_TI_TMP_G_CPU_ID_PREEMPT, GCPUID_PREEMPT ? ~ pred; \
	} \
	{ \
		rrd %pshtp, GCURTASK ? pred; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSP_LO ? pred; \
 \
		/* Executing all instructions below conditionally would \
		 * be faster but putting rwd of a privileged register \
		 * under predicate is disallowed and %ctpr's are not \
		 * available yet. */ \
		ibranch 0f ? ~ pred; \
	} \
	{ \
		rwd GCPUOFFSET, %psp.lo; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSHTP; \
		ldgdd,5 0, TSK_TI_K_PCSP_HI, GCPUOFFSET; \
	} \
	{ \
		/* `rwd %psp -> setwd` delay is 6 cycles with at least one \
		 * instruction without `nop X, X > 0`("Scheduling" 1.3.10) */ \
		rwd GVCPUSTATE, %psp.hi; \
	} \
	ALTERNATIVE "", "{ nop 2 }", CPU_FEAT_ISET_V7; \
	{ \
		rwd GCPUID_PREEMPT, %pcsp.lo; \
		SMP_ONLY(ldgdw,3 0, TSK_TI_CPU_DELTA, GCPUID_PREEMPT;) \
		NOT_SMP_ONLY(addd,3 0, 0, GCPUID_PREEMPT;) \
	} \
	{ \
		rrd %pcshtp, GCURTASK; \
	} \
	{ \
		rrd CURRENT_REG, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSHTP; \
	} \
	{ \
		rwd GCPUOFFSET, %pcsp.hi; \
	} \
0: /* skip_stacks_switch */ \
	{ \
		rrd CURRENT_REG, GCURTASK ? ~ pred; \
	}

#define KERNEL_ENTRY_OSR0(prefix, nr_syscall, hw_trap, pred) \
.ifnb nr_syscall; .ifne hw_trap; .error "@nr_syscall set with @hw_trap"; .endif; .endif; \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	{ \
.ifnb nr_syscall; \
		disp %ctpr1, 0f; \
		/* This check must correspond with the check in \
		 * arch_ptrace_stop() before clearing saved %g. */ \
		cmpesb nr_syscall, __NR_sigreturn, pred; \
.endif; \
	} \
	ALTERNATIVE_1_ALTINSTR \
		/* iset v5 version - save qp registers extended part */ \
		{ \
			stgdq,sm %qg18, 0, prefix##G_MY_CPU_OFFSET; \
			qpswitchd,1,sm GCPUOFFSET, GCPUOFFSET; \
			qpswitchd,4,sm GCPUID_PREEMPT, GCPUID_PREEMPT; \
		} \
		{ \
			stgdq,sm %qg16, 0, prefix##G_VCPU_STATE; \
			qpswitchd,1,sm GVCPUSTATE, GVCPUSTATE; \
			qpswitchd,4,sm GCURTASK, GCURTASK; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - save only 16 bits */ \
		{ \
			stgdq,sm %qg18, 0, prefix##G_MY_CPU_OFFSET; \
			movfi,1 GCPUOFFSET, GCPUOFFSET; \
			movfi,4 GCPUID_PREEMPT, GCPUID_PREEMPT; \
		} \
		{ \
			stgdq,sm %qg16, 0, prefix##G_VCPU_STATE; \
			movfi,1 GVCPUSTATE, GVCPUSTATE; \
			movfi,4 GCURTASK, GCURTASK; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_QPREG) \
	{ \
		rrd CURRENT_REG, %dg18; \
		stgdq,sm %qg18, 0, prefix##G_CPU_ID_PREEMPT; \
	} \
	{ \
		/* 'crp' instruction also clears %rpr besides the generations \
		 * table, so make sure we preserve %rpr value. */ \
		.ifeq hw_trap; rrd %rpr.lo, %dg16; .endif; \
		stgdq,sm %qg16, 0, prefix##G_TASK; \
	} \
	{ \
		/* #144498: wait for activity in DTLB/AAU to stop, which \
		 * must be done before accessing MMU registers (e.g. writing \
		 * %pid/%pptb right here) or flushing TLB. \
		 * For traps: \
		 *  - before iset v6 `aaurr %aasr` and `wait all_e` \
		 *    in adjacent instructions is enough; \
		 *  - since iset v6 waiting is implemented in hardware. \
		 * For syscalls: \
		 *  - `wait all_e` is enough, but not earlier then 5th \
		 *     (before v7) or 7th (since v7) handler's instruction. */ \
		aaurr,2 %aasr, %empty; \
	} \
.ifeq hw_trap; \
	{ \
		/* See comment for `aaurr %aasr` above.  This also  waits \
		 * for FPU exceptions before switching stacks and CLW. */ \
		wait all_e=1; \
		rrd %rpr.hi, %dg19; \
		/* Disable load/store generations */ \
		crp; \
	} \
	{ \
		rwd %dg16, %rpr.lo; \
	} \
	{ \
		rwd %dg19, %rpr.hi; \
		.ifnb nr_syscall; ct %ctpr1 ? ~ pred; .endif; \
	} \
.else; \
	/* CPU_HWBUG_INTERSECTING_L1_ACCESSES - \
	 * between `strd` above and `ldrd` below */ \
	{ \
		/* See comment for `aaurr %aasr` above.  This also  waits \
		 * for FPU exceptions before switching stacks and CLW. */ \
		wait all_e=1; \
	} \
.ifnb nr_syscall; .error "@nr_syscall set without @issue_crp"; .endif; \
.endif; \
	{ \
		ldrd,0 %dg18, TAGGED_MEM_LOAD_REC_OPC | prefix##G_VCPU_STATE_EXT, %dg16; \
		ldrd,2 %dg18, TAGGED_MEM_LOAD_REC_OPC | prefix##G_TASK, %dg17; \
	} \
	ALTERNATIVE "{ nop 2 }", "{ nop 3 }", CPU_FEAT_ISET_V6; \
	{ \
		addd,1 %dg18, 0, GCURTASK; \
		strd,2 %dg16, %dg18, TAGGED_MEM_STORE_REC_OPC | prefix##G_TASK; \
		strd,5 %dg17, %dg18, TAGGED_MEM_STORE_REC_OPC | prefix##G_VCPU_STATE_EXT; \
	} \
	{ \
		ldrd,0 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | prefix##G_MY_CPU_OFFSET_EXT, %dg18; \
		ldrd,2 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | prefix##G_CPU_ID_PREEMPT, %dg19; \
	} \
	ALTERNATIVE "{ nop 2 }", "{ nop 3 }", CPU_FEAT_ISET_V6; \
	{ \
		strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G_CPU_ID_PREEMPT; \
		strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G_MY_CPU_OFFSET_EXT; \
	} \
0: \
.ifne hw_trap; \
	{ \
		nop 1; \
		rrd %sbr, GCURTASK \
	} \
	SWITCH_HW_STACKS(pred, \
		/* Switch only if we are on user stacks (sbr <= TASK_SIZE) */ \
		cmpbedb,1 GCURTASK, TASK_SIZE \
	) \
.else; \
	SWITCH_HW_STACKS(pred, \
		/* switch unconditionally */ \
		cmpesb 0, 0 \
	) \
.endif;

/*
 * On v7 we can simplify kernel entry a lot thanks to
 * the new {ld/st}osrr{d/qp} instructions
 */
#define KERNEL_ENTRY_OSR1(prefix, nr_syscall, hw_trap, pred) \
.ifnb nr_syscall; .ifne hw_trap; .error "@nr_syscall set with @hw_trap"; .endif; .endif; \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	{ \
		.ifne hw_trap; rrd %sbr, GCURTASK; .endif; \
		stosrrqp,2,sm GVCPUSTATE, 0, LDST_REC_QP_Q | prefix##G_VCPU_STATE; \
		stosrrqp,5,sm GCURTASK, 0, LDST_REC_QP_Q | prefix##G_TASK; \
	} \
	{ \
		stosrrqp,2,sm GCPUOFFSET, 0, LDST_REC_QP_Q | prefix##G_MY_CPU_OFFSET; \
		stosrrqp,5,sm GCPUID_PREEMPT, 0, LDST_REC_QP_Q | prefix##G_CPU_ID_PREEMPT; \
	} \
.ifne hw_trap; \
	{ \
		/* Switch only if we are on user stacks (sbr <= TASK_SIZE) */ \
		cmpbedb,1 GCURTASK, TASK_SIZE, pred; \
		ldosrrd 0, LDST_REC_D | TSK_TI_K_PSP_LO, GCPUOFFSET; \
	} \
	{ \
		/* Restore my_cpu_offset and preemption counter as they were \
		 * when entering kernel trap */ \
		SMP_ONLY(ldosrrd,0 0, LDST_REC_D | TSK_TI_TMP_G_MY_CPU_OFFSET, GCPUOFFSET ? ~ pred;) \
		ldosrrd,2 0, LDST_REC_D | TSK_TI_TMP_G_CPU_ID_PREEMPT, GCPUID_PREEMPT ? ~ pred; \
	} \
	{ \
		rrd CURRENT_REG, GCURTASK ? ~ pred; \
		/* Note that %ctpr's are not available yet for traps. */ \
		ibranch 0f ? ~ pred; \
		ldosrrd,3 0, LDST_REC_D | TSK_TI_K_PCSP_LO, GCPUID_PREEMPT ? pred; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PSP_HI, GVCPUSTATE ? pred; \
	} \
.else; \
	{ \
		/* 'crp' instruction also clears %rpr besides the generations \
		 * table, so make sure we preserve %rpr value. */ \
		rrd %rpr.lo, GVCPUSTATE; \
		ldosrrd 0, LDST_REC_D | TSK_TI_K_PSP_LO, GCPUOFFSET; \
		/* System calls and trampolines are always from user */ \
		cmpesb 0, 0, pred; \
	} \
	/* See comment before `aaurr %aasr` in KERNEL_ENTRY_OSR0(). */ \
	{ nop } { nop } { nop } \
	{ \
		/* See comment before `aaurr %aasr` in KERNEL_ENTRY_OSR0(). \
		 * This also waits for FPU exceptions before switching \
		 * stacks and CLW. */ \
		wait all_e=1; \
		rrd %rpr.hi, GCPUID_PREEMPT; \
		/* Disable load/store generations */ \
		crp; \
	} \
	{ \
		rwd GVCPUSTATE, %rpr.lo; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PSP_HI, GVCPUSTATE; \
	} \
	{ \
		rwd GCPUID_PREEMPT, %rpr.hi; \
		ldosrrd,3 0, LDST_REC_D | TSK_TI_K_PCSP_LO, GCPUID_PREEMPT; \
	} \
.endif; \
	{ \
		rrd %psp.hi, GCURTASK; \
	} \
	{ \
		rrd %psp.lo, GCURTASK; \
		stosrrd,2 GCURTASK, 0, LDST_REC_D | TSK_TI_TMP_U_PSP_HI; \
	} \
	{ \
		rrd %pshtp, GCURTASK; \
		stosrrd,2 GCURTASK, 0, LDST_REC_D | TSK_TI_TMP_U_PSP_LO; \
	} \
	{ \
		rwd GCPUOFFSET, %psp.lo; \
		stosrrd,2 GCURTASK, 0,LDST_REC_D |  TSK_TI_TMP_U_PSHTP; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PCSP_HI, GCPUOFFSET; \
	} \
	{ \
		/* `rwd %psp -> setwd` delay is 6/8 cycles with at least one \
		 * instruction without `nop X, X > 0`("Scheduling" 1.3.10) */ \
		rwd GVCPUSTATE, %psp.hi; \
	} \
	{ \
		rrd %pcsp.lo, GCURTASK; \
	} \
	{ \
		rrd %pcsp.hi, GCURTASK; \
		stosrrd,2 GCURTASK, 0, LDST_REC_D | TSK_TI_TMP_U_PCSP_LO; \
	} \
	{ \
		rwd GCPUID_PREEMPT, %pcsp.lo; \
		SMP_ONLY(ldosrrd,3 0, LDST_REC_W | TSK_TI_CPU_DELTA, GCPUID_PREEMPT;) \
		NOT_SMP_ONLY(addd,3 0, 0, GCPUID_PREEMPT;) \
	} \
	{ \
		rrd %pcshtp, GCURTASK; \
		stosrrd,2 GCURTASK, 0, LDST_REC_D | TSK_TI_TMP_U_PCSP_HI; \
	} \
	{ \
		rrd CURRENT_REG, GCURTASK; \
		stosrrd,2 GCURTASK, 0, LDST_REC_D | TSK_TI_TMP_U_PCSHTP; \
	} \
	{ \
		rwd GCPUOFFSET, %pcsp.hi; \
	} \
0: /* skip_stacks_switch */ \

/**
 * KERNEL_ENTRY - prepare to switch hardware stacks and issue necessary barriers
 * @prefix: where to save %g to
 * @nr_syscall: pass syscall number if applicable; used to skip unneeded
 *		save & restore for all syscalls except sys_sigreturn
 * @hw_trap: pass 1 to indicate hardware trap entry, in this case we have
 *	     different scheduling rules
 * @pred: temporary predicate; if @hw_trap==1 then it'll be set for user mode
 *
 * This will:
 *  - save some %g to memory so that we have registers to execute upon and
 *    switch hardware stacks (this is skipped for all syscalls except sigreturn)
 *  - flush SLT by issuing a store before any loads;
 *  - flush generations table with `crp`;
 *  - wait for AAU/DTLB buffer to flush so that we can write MMU regs in kernel;
 *  - invoke SWITCH_HW_STACKS().
 *
 * Note that for syscalls %ctpr2 is not used so you can prefetch necessary
 * functions to it before invoking KERNEL_ENTRY().  For traps %ctpr registers
 * must not be used here as they are yet to be saved.
 */
#ifdef CONFIG_CPU_HAS_OSR1
# define KERNEL_ENTRY	KERNEL_ENTRY_OSR1
#else
# define KERNEL_ENTRY	KERNEL_ENTRY_OSR0
#endif

#define HANDLER_TRAMPOLINE(ctprN, scallN, fn, wbsL) \
	/* Force load OSGD->GD. Alternative is to use non-0 CUI for kernel */ \
	{ \
		sdisp ctprN, scallN; \
	} \
	/* CPU_HWBUG_VIRT_PSIZE_INTERCEPTION */ \
	{ nop } { nop } { nop } { nop } \
	call ctprN, wbs=wbsL; \
	{ \
		disp ctprN, fn; \
	} \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	KERNEL_ENTRY(TSK_TI_, /* not a syscall */, 0 /* hw_trap */, %pred0) \
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_SEP_VIRT_SPACE version - get kernel PT root from %os_pptb */ \
		{ \
			addd 0, 0, GVCPUSTATE; \
			mmurr %os_pptb, GVCPUSTATE; \
		} \
		{ \
			addd 0, E2K_KERNEL_CONTEXT, GVCPUSTATE; \
			mmurw GVCPUSTATE, %u_pptb; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - get kernel PT root from memory */ \
		{ \
			NOT_SEP_VIRT_SPACE_ONLY(ldgdd 0, TSK_K_ROOT_PTB, GVCPUSTATE;) \
		} \
		{ \
			addd 0, E2K_KERNEL_CONTEXT, GVCPUSTATE; \
			mmurw GVCPUSTATE, %root_ptb; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_SEP_VIRT_SPACE) \
	{ \
		mmurw GVCPUSTATE, %cont; \
	} \
	{ \
		/* mmurw -> memory access */ \
		nop 3; \
		wait all_c=1; \
 \
		SMP_ONLY(shld,1	GCPUID_PREEMPT, 3, GCPUOFFSET); \
	} \
	{ \
		SMP_ONLY(ldd,2	[ __per_cpu_offset + GCPUOFFSET ], GCPUOFFSET); \
		ct ctprN; \
	}

#define SAVE_DAM(r0, r1, r2, r3) \
	{ ldd,2 [ 0x4 ], mas = MAS_DAM_REG, r0; } \
	{ ldd,2 [ 0x84 ], mas = MAS_DAM_REG, r1; } \
	{ ldd,2 [ 0x104 ], mas = MAS_DAM_REG, r2; } \
	{ ldd,2 [ 0x184 ], mas = MAS_DAM_REG, r3; } \
	{ ldd,2 [ 0x204 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM ]; } \
	{ ldd,2 [ 0x284 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0x8]; } \
	{ ldd,2 [ 0x304 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0x10]; } \
	{ ldd,2 [ 0x384 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0x18]; } \
	{ ldd,2 [ 0x404 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM + 0x20]; } \
	{ ldd,2 [ 0x484 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0x28]; } \
	{ ldd,2 [ 0x504 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0x30]; } \
	{ ldd,2 [ 0x584 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0x38]; } \
	{ ldd,2 [ 0x604 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM + 0x40]; } \
	{ ldd,2 [ 0x684 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0x48]; } \
	{ ldd,2 [ 0x704 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0x50]; } \
	{ ldd,2 [ 0x784 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0x58]; } \
	{ ldd,2 [ 0x804 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM + 0x60]; } \
	{ ldd,2 [ 0x884 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0x68]; } \
	{ ldd,2 [ 0x904 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0x70]; } \
	{ ldd,2 [ 0x984 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0x78]; } \
	{ ldd,2 [ 0xa04 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM + 0x80]; } \
	{ ldd,2 [ 0xa84 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0x88]; } \
	{ ldd,2 [ 0xb04 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0x90]; } \
	{ ldd,2 [ 0xb84 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0x98]; } \
	{ ldd,2 [ 0xc04 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM + 0xa0]; } \
	{ ldd,2 [ 0xc84 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0xa8]; } \
	{ ldd,2 [ 0xd04 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0xb0]; } \
	{ ldd,2 [ 0xd84 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0xb8]; } \
	{ ldd,2 [ 0xe04 ], mas = MAS_DAM_REG, r0; \
	  std,5 r0, [ GCURTASK + TSK_DAM + 0xc0]; } \
	{ ldd,2 [ 0xe84 ], mas = MAS_DAM_REG, r1; \
	  std,5 r1, [ GCURTASK + TSK_DAM + 0xc8]; } \
	{ ldd,2 [ 0xf04 ], mas = MAS_DAM_REG, r2; \
	  std,5 r2, [ GCURTASK + TSK_DAM + 0xd0 ]; } \
	{ ldd,2 [ 0xf84 ], mas = MAS_DAM_REG, r3; \
	  std,5 r3, [ GCURTASK + TSK_DAM + 0xd8 ]; } \
	{ std,2 r0, [ GCURTASK + TSK_DAM + 0xe0 ]; } \
	{ std,2 r1, [ GCURTASK + TSK_DAM + 0xe8]; } \
	{ std,2 r2, [ GCURTASK + TSK_DAM + 0xf0 ]; } \
	{ std,2 r3, [ GCURTASK + TSK_DAM + 0xf8 ]; }

#endif	/* __ASSEMBLY__ */

#endif	/* _E2K_TRAP_TABLE_ASM_H */
