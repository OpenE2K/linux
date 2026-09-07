/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Defenition of traps handling routines.
 */

#ifndef _E2K_TRAP_TABLE_ASM_H
#define _E2K_TRAP_TABLE_ASM_H

#include <linux/stringify.h>

#include <asm/alternative-asm.h>
#include <asm/asm-offsets.h>
#include <asm/glob_regs.h>
#include <asm/kvm/trap_table.S.h>

/*
 * Global registers map used by kernel
 * Numbers of used global registers see at arch/e2k/include/asm/glob_regs.h
 */

#define	GET_GREG_MEMONIC(greg_no)	%dg ## greg_no
#define	DO_GET_GREG_MEMONIC(greg_no)	GET_GREG_MEMONIC(greg_no)

#define	GCURTASK	DO_GET_GREG_MEMONIC(CURRENT_TASK_GREG)
#define	GCPUOFFSET	DO_GET_GREG_MEMONIC(MY_CPU_OFFSET_GREG)
#define	GCPUID_PREEMPT	DO_GET_GREG_MEMONIC(SMP_CPU_ID_GREG)
/* Macroses for virtualization support on assembler */
#define	GVCPUSTATE	DO_GET_GREG_MEMONIC(GUEST_VCPU_STATE_GREG)

#if defined CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
# define NOT_SMP_ONLY(...)
#else
# define SMP_ONLY(...)
# define NOT_SMP_ONLY(...) __VA_ARGS__
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
#define SWITCH_HW_STACKS_SYSCALL(pred) \
	KERNEL_ENTRY(TSK_U_, %r0 /* syscall number */, 0 /* hw_trap */, pred)

#ifdef CONFIG_KVM_HOST_KERNEL
# define CHECK_HWBUG_HCALL_EXC_ILL_INSTR_ADDR(pred) \
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_HWBUG_HCALL_EXC_ILL_INSTR_ADDR version */ \
		{ \
			nop 1; /* rrd -> usage */ \
			rrd %cr0.hi, %g18; \
		} \
		{ \
			andd %g18, CR0_IP_MASK, %g18; \
		} \
		{ \
			cmpedb,0 %g18, [hcall_entry0], pred; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Default version - do nothing */ \
		{ \
			cmpedb,0 0, 1, pred; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_HWBUG_HCALL_EXC_ILL_INSTR_ADDR) \
	{ \
		ibranch done_to_hcall ? pred; \
	}
#else	/* !CONFIG_KVM_HOST_KERNEL */
# define CHECK_HWBUG_HCALL_EXC_ILL_INSTR_ADDR(pred)	;
#endif	/* CONFIG_KVM_HOST_KERNEL */

#define KERNEL_ENTRY_OSR0(prefix, nr_syscall, hw_trap, pred) \
.ifnb nr_syscall; .ifne hw_trap; .error "@nr_syscall set with @hw_trap"; .endif; .endif; \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_QPREG - save qp registers extended part */ \
		{ \
			stgdq,sm %qg16, 0, TSK_G_TMP_TAG; \
		} \
		{ \
			nop 1; \
			rrd CURRENT_REG, GCURTASK; \
			stgdqp,sm %qpg17, 0, prefix##G17; \
		} \
		/* Bug 116851 - all strqp must be speculative if dealing with tags */ \
		{ \
			nop 1; /* ldrd -> %g16 -> strd */ \
			strqp,2,sm %qpg16, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G16; \
			ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | (TSK_G_TMP_TAG + 8), %dg16; \
		} \
		{ \
			strqp,2,sm %qpg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G18; \
			strqp,5,sm %qpg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G19; \
		} \
		{ \
			strqp,2,sm %qpg20, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G20; \
			strqp,5,sm %qpg21, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G21; \
		} \
		{ \
			strqp,2,sm %qpg22, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G22; \
			strqp,5,sm %qpg23, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G23; \
		} \
		{ \
			rrs %bgr, %g16; \
			strd,2,sm %dg16, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G17; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - save only 16 bits */ \
		{ \
			nop 3; \
			stgdq,sm %qg16, 0, prefix##G16; \
			movfi,1 %xg16, %dg16; \
			movfi,4 %xg17, %dg17; \
		} \
		{ \
			rrd CURRENT_REG, GCURTASK; \
			stgdq,sm %qg16, 0, prefix##G17; \
		} \
		{ \
			strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G18; \
			strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G19; \
			movfi,1 %xg18, %dg18; \
			movfi,4 %xg19, %dg19; \
		} \
		{ \
			strd,2 %dg20, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G20; \
			strd,5 %dg21, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G21; \
			movfi,1 %xg20, %dg20; \
			movfi,4 %xg21, %dg21; \
		} \
		{ \
			nop 1; /* movfi -> strd */ \
			strd,2 %dg22, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G22; \
			strd,5 %dg23, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G23; \
			movfi,1 %xg22, %dg22; \
			movfi,4 %xg23, %dg23; \
		} \
		{ \
			strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G18_EXT; \
			strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G19_EXT; \
		} \
		{ \
			nop 2; /* ldrd -> g18,g19 -> strd */ \
			ldrd,0 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | prefix##G16_EXT, %dg18; \
			ldrd,3 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | prefix##G17, %dg19; \
		} \
		{ \
			strd,2 %dg20, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G20_EXT; \
			strd,5 %dg21, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G21_EXT; \
		} \
		{ \
			strd,2 %dg22, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G22_EXT; \
			strd,5 %dg23, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G23_EXT; \
		} \
		{ \
			rrs %bgr, %g16; \
			strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G17; \
			strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G16_EXT; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_QPREG) \
.ifne hw_trap; \
	/* Assumes that only %g16-%g17 has been modified with kernel \
	 * values above in CPU_FEAT_QPREG case.  Will modify %g18. */ \
	CHECK_HWBUG_HCALL_EXC_ILL_INSTR_ADDR(%pred3); \
.endif; \
	{ \
		rws 0xff, %bgr; \
		strd,2 %g16, GCURTASK, LDST_REC_W | prefix##BGR; \
	} \
	{ \
		/* 'crp' instruction also clears %rpr besides the generations \
		 * table, so make sure we preserve %rpr value. */ \
		.ifeq hw_trap; rrd %rpr.lo, %dg16; .endif; \
		/* #144498: wait for activity in DTLB/AAU to stop, which \
		 * must be done before accessing MMU registers (e.g. writing \
		 * %pid/%pptb right here) or flushing TLB. \
		 * For traps: \
		 *  - before iset v6 `aaurr %aasr` and `wait all_e` \
		 *    in adjacent instructions is enough; \
		 *  - since iset v6 waiting is implemented in hardware. \
		 * For syscalls: \
		 *  - `wait all_e` is enough, but not earlier then 5th \
		 *     (before v7) or 7th (since v7) handler's instruction. \
		 * For running older guests under virtualization must assume \
		 * the worst scheduling. */ \
		aaurr,2 %aasr, %empty; \
	} \
.ifeq hw_trap; \
	{ \
		/* See comment for `aaurr %aasr` above.  This also \
		 * waits for FPU exceptions before switching stacks \
		 * and CLW, and for %bgr write completion. */ \
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
	} \
.else; \
	/* CPU_HWBUG_INTERSECTING_L1_ACCESSES - \
	 * between `strd` above and `ldrd` below */ \
	{ \
		/* See comment for `aaurr %aasr` above.  This also waits \
		 * for FPU exceptions before switching stacks and CLW, \
		 * and for %bgr write completion. */ \
		wait all_e=1; \
 \
		nop 1; \
		rrd %sbr, %dg16; \
	} \
.endif; \
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_QPREG - save qp registers extended part */ \
		/* Bug 116851 - all strqp must be speculative if dealing with tags */ \
		{ \
			strqp,2,sm %qpg24, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G24; \
			strqp,5,sm %qpg25, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G25; \
		} \
		{ \
			strqp,2,sm %qpg26, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G26; \
			strqp,5,sm %qpg27, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G27; \
		} \
		{ \
			strqp,2,sm %qpg28, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G28; \
			strqp,5,sm %qpg29, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G29; \
		} \
		{ \
			strqp,2,sm %qpg30, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G30; \
			strqp,5,sm %qpg31, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G31; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - save only 16 bits */ \
		{ \
			strd,2 %dg24, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G24; \
			strd,5 %dg25, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G25; \
			movfi,1 %xg24, %dg24; \
			movfi,4 %xg25, %dg25; \
		} \
		{ \
			strd,2 %dg26, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G26; \
			strd,5 %dg27, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G27; \
			movfi,1 %xg26, %dg26; \
			movfi,4 %xg27, %dg27; \
		} \
		{ \
			strd,2 %dg28, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G28; \
			strd,5 %dg29, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G29; \
			movfi,1 %xg28, %dg28; \
			movfi,4 %xg29, %dg29; \
		} \
		{ \
			strd,2 %dg30, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G30; \
			strd,5 %dg31, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G31; \
			movfi,1 %xg30, %dg30; \
			movfi,4 %xg31, %dg31; \
		} \
		{ \
			strd,2 %dg24, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G24_EXT; \
			strd,5 %dg25, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G25_EXT; \
		} \
		{ \
			strd,2 %dg26, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G26_EXT; \
			strd,5 %dg27, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G27_EXT; \
		} \
		{ \
			strd,2 %dg28, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G28_EXT; \
			strd,5 %dg29, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G29_EXT; \
		} \
		{ \
			strd,2 %dg30, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G30_EXT; \
			strd,5 %dg31, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G31_EXT; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_QPREG) \
	{ \
.ifne hw_trap; \
		/* Switch hardware stacks only if we are on user stacks (sbr <= TASK_SIZE) */ \
		cmpbedb,1 %dg16, TASK_SIZE, pred; \
.else; \
		/* Switch unconditionally */ \
		cmpesb,1 0, 0, pred; \
.endif; \
		ldgdd,0 0, TSK_TI_K_PCSP_LO, %dg22; \
		ldgdd,2 0, TSK_TI_K_PCSP_HI, %dg23; \
		ldgdd,3 0, TSK_TI_K_PSP_LO, %dg24; \
		ldgdd,5 0, TSK_TI_K_PSP_HI, %dg25; \
	} \
	{ \
		rrd %psp.lo, %dg26; \
	} \
	{ \
		rrd %psp.hi, %dg27 ? pred; \
	} \
	{ \
		rrd %pcsp.lo, %dg28 ? pred; \
	} \
	{ \
		rrd %pcsp.hi, %dg29 ? pred; \
	} \
	{ \
		rrd %pshtp, %dg31 ? pred; \
	} \
.ifne hw_trap; \
	{ \
		/* Restore my_cpu_offset and preemption counter as they \
		 * were when entering kernel trap. \
		 *
		 * Executing all instructions after this conditionally \
		 * would be faster but putting rwd of a privileged \
		 * register under predicate is disallowed and %ctpr's \
		 * are not available yet. */ \
		SMP_ONLY(ldgdd,0 0, TSK_TMP_G18, GCPUOFFSET ? ~ pred;) \
		ldgdd,2 0, TSK_TMP_G19, GCPUID_PREEMPT ? ~ pred; \
		ldgdd,3 0, TSK_TMP_G20, %dg20 ? ~ pred; \
		ldgdd,5 0, TSK_TMP_G21, %dg21 ? ~ pred; \
		ibranch 0f ? ~ pred; \
	} \
.endif; \
	{ \
		rwd %dg24, %psp.lo; \
		mmurr %root_ptb, %dg21; \
		SMP_ONLY(ldgdw,3 0, TSK_TI_CPU_DELTA, GCPUID_PREEMPT;) \
		NOT_SMP_ONLY(addd,3 0, 0, GCPUID_PREEMPT;) \
	} \
	{ \
		rwd %dg25, %psp.hi; \
	} \
	{ \
		rwd %dg22, %pcsp.lo; \
	} \
	{ \
		rwd %dg23, %pcsp.hi; \
	} \
	{ \
		rrd %pcshtp, %dg30; \
	} \
	{ \
		stgdd,2 %dg26, 0, TSK_TMP_U_PSP_LO; \
		stgdd,5 %dg27, 0, TSK_TMP_U_PSP_HI; \
	} \
	{ \
		stgdd,2 %dg28, 0, TSK_TMP_U_PCSP_LO; \
		stgdd,5 %dg29, 0, TSK_TMP_U_PCSP_HI; \
	} \
	{ \
		stgdd,2 %dg30, 0, TSK_TMP_U_PCSHTP; \
		stgdd,5 %dg31, 0, TSK_TMP_U_PSHTP; \
	} \
	{ \
		wait all_e=1; /* rwd %psp -> setwd */ \
	} \
0: /* skip_stacks_switch */ \
.ifne hw_trap; \
	{ \
		/* Restore cpuhas gregs as they were when entering kernel trap. */ \
		ldgdd 0, TSK_TMP_G22, %dg22 ? ~ pred; \
		ldgdd 0, TSK_TMP_G23, %dg23 ? ~ pred; \
		ldgdd 0, TSK_TMP_G24, %dg24 ? ~ pred; \
	} \
.endif; \

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
		rrs %bgr, %g16; \
		stosrrqp,2,sm %qpg16, 0, LDST_REC_QP_Q | prefix##G16; \
		stosrrqp,5,sm %qpg17, 0, LDST_REC_QP_Q | prefix##G17; \
	} \
	{ \
		rws 0xff, %bgr; \
		stosrrqp,2,sm %qpg18, 0, LDST_REC_QP_Q | prefix##G18; \
	} \
.ifne hw_trap; \
	{ \
		rrd %sbr, %dg17; \
		stosrrd,2 %g16, 0, LDST_REC_W | prefix##BGR; \
		stosrrqp,5,sm %qpg19, 0, LDST_REC_QP_Q | prefix##G19; \
	} \
	{ \
		stosrrqp,2,sm %qpg20, 0, LDST_REC_QP_Q | prefix##G20; \
		stosrrqp,5,sm %qpg21, 0, LDST_REC_QP_Q | prefix##G21; \
	} \
	{ \
		/* Switch only if we are on user stacks (sbr <= TASK_SIZE) */ \
		cmpbedb,1 %dg17, TASK_SIZE, pred; \
	} \
	{ \
		ldosrrd,0 0, LDST_REC_D | TSK_TI_K_PSP_LO, %dg18 ? pred; \
		ldosrrd,2 0, LDST_REC_D | TSK_TI_K_PSP_HI, %dg19 ? pred; \
	} \
	{ \
		ldosrrd,0 0, LDST_REC_D | TSK_TI_K_PCSP_LO, %dg20 ? pred; \
		ldosrrd,2 0, LDST_REC_D | TSK_TI_K_PCSP_HI, %dg21 ? pred; \
	} \
	{ \
		stosrrqp,2,sm %qpg22, 0, LDST_REC_QP_Q | prefix##G22; \
		stosrrqp,5,sm %qpg23, 0, LDST_REC_QP_Q | prefix##G23; \
	} \
	{ \
		/* Wait after %bgr write */ \
		wait all_e=1; \
		stosrrqp,2,sm %qpg24, 0, LDST_REC_QP_Q | prefix##G24; \
		stosrrqp,5,sm %qpg25, 0, LDST_REC_QP_Q | prefix##G25; \
	} \
	{ \
		stosrrqp,2,sm %qpg26, 0, LDST_REC_QP_Q | prefix##G26; \
		stosrrqp,5,sm %qpg27, 0, LDST_REC_QP_Q | prefix##G27; \
	} \
	{ \
		stosrrqp,2,sm %qpg28, 0, LDST_REC_QP_Q | prefix##G28; \
		stosrrqp,5,sm %qpg29, 0, LDST_REC_QP_Q | prefix##G29; \
	} \
	{ \
		stosrrqp,2,sm %qpg30, 0, LDST_REC_QP_Q | prefix##G30; \
		stosrrqp,5,sm %qpg31, 0, LDST_REC_QP_Q | prefix##G31; \
		/* Restore %dg17 as it was when entering kernel trap */ \
		rrd CURRENT_REG, GCURTASK ? ~ pred; \
		/* Note that %ctpr's are not available yet */ \
		ibranch 0f ? ~ pred; \
	} \
.else; \
	{ \
		/* 'crp' instruction also clears %rpr besides the generations \
		 * table, so make sure we preserve %rpr value. */ \
		rrd %rpr.lo, %dg16; \
		stosrrd,2 %g16, 0, LDST_REC_W | prefix##BGR; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PSP_LO, %dg18; \
	} \
	{ \
		stosrrqp,2,sm %qpg19, 0, LDST_REC_QP_Q | prefix##G19; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PSP_HI, %dg19; \
	} \
	{ \
		stosrrqp,2,sm %qpg20, 0, LDST_REC_QP_Q | prefix##G20; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PCSP_LO, %dg20; \
	} \
	{ \
		stosrrqp,2,sm %qpg21, 0, LDST_REC_QP_Q | prefix##G21; \
		ldosrrd,5 0, LDST_REC_D | TSK_TI_K_PCSP_HI, %dg21; \
	} \
	{ \
		stosrrqp,2,sm %qpg22, 0, LDST_REC_QP_Q | prefix##G22; \
		stosrrqp,5,sm %qpg23, 0, LDST_REC_QP_Q | prefix##G23; \
	} \
	{ \
		/* See comment before `aaurr %aasr` in KERNEL_ENTRY_OSR0(). \
		 * This also waits for FPU exceptions before switching \
		 * stacks and CLW, and for %bgr write completion. */ \
		wait all_e=1; \
		rrd %rpr.hi, %dg17; \
		/* Disable load/store generations */ \
		crp; \
	} \
	{ \
		rwd %dg16, %rpr.lo; \
		stosrrqp,5,sm %qpg24, 0, LDST_REC_QP_Q | prefix##G24; \
	} \
	{ \
		rwd %dg17, %rpr.hi; \
		stosrrqp,5,sm %qpg25, 0, LDST_REC_QP_Q | prefix##G25; \
	} \
.endif; \
	{ \
		rrd %psp.hi, %dg17; \
	} \
	{ \
		rrd %psp.lo, %dg17; \
		stosrrd,2 %dg17, 0, LDST_REC_D | TSK_TMP_U_PSP_HI; \
	} \
	{ \
		rwd %dg18, %psp.lo; \
		stosrrd,2 %dg17, 0, LDST_REC_D | TSK_TMP_U_PSP_LO; \
	} \
	{ \
		rwd %dg19, %psp.hi; \
		stosrrqp,2,sm %qpg26, 0, LDST_REC_QP_Q | prefix##G26; \
		stosrrqp,5,sm %qpg27, 0, LDST_REC_QP_Q | prefix##G27; \
	} \
	{ \
		rrd %pcsp.lo, %dg17; \
		stosrrqp,2,sm %qpg28, 0, LDST_REC_QP_Q | prefix##G28; \
		stosrrqp,5,sm %qpg29, 0, LDST_REC_QP_Q | prefix##G29; \
	} \
	{ \
		rrd %pcsp.hi, %dg17; \
		stosrrd,2 %dg17, 0, LDST_REC_D | TSK_TMP_U_PCSP_LO; \
	} \
	{ \
		rwd %dg20, %pcsp.lo; \
		SMP_ONLY(ldosrrd,3 0, LDST_REC_W | TSK_TI_CPU_DELTA, GCPUID_PREEMPT;) \
		NOT_SMP_ONLY(addd,3 0, 0, GCPUID_PREEMPT;) \
	} \
	{ \
		rrd %pcshtp, %dg17; \
		stosrrd,2 %dg17, 0, LDST_REC_D | TSK_TMP_U_PCSP_HI; \
	} \
	{ \
		rrd %pshtp, %dg17; \
		stosrrd,2 %dg17, 0, LDST_REC_D | TSK_TMP_U_PCSHTP; \
	} \
	{ \
		rwd %dg21, %pcsp.hi; \
		stosrrd,2 %dg17, 0, LDST_REC_D |  TSK_TMP_U_PSHTP; \
		stosrrqp,5,sm %qpg30, 0, LDST_REC_QP_Q | prefix##G30; \
	} \
	{ \
		rrd CURRENT_REG, GCURTASK; \
		mmurr,2 %root_ptb, %dg21; \
		stosrrqp,5,sm %qpg31, 0, LDST_REC_QP_Q | prefix##G31; \
	} \
	{ \
		wait all_e=1; /* rwd %psp -> setwd */ \
	} \
0: /* skip_stacks_switch */

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
 *  - flush SLT by issuing a store before any loads;
 *  - flush generations table with `crp`;
 *  - wait for AAU/DTLB buffer to flush so that we can write MMU regs in kernel;
 *  - set %g17 (current) and %g18 (cpu and preempt_offset), leave %g19 (percpu
 *    offset) for later since it must be loaded from memory;
 *  - save %g16-%g31 to memory so that we have registers to execute upon and
 *    switch hardware stacks and can enable -fglobal-regs;
 *  - for traps they are saved to temporary 'tmp_k_gregs' since we do not know
 *    yet whether trap is from user or kernel;
 *  - save stack registers to temporary 'tmp_user_stacks' since pt_regs are
 *    not allocated yet;
 *  - update global and stack registers with kernel values.
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
	/* %pred5 == cpu_has(CPU_FEAT_SVSC) */ \
	ALTERNATIVE_1_ALTINSTR \
	/* CPU_FEAT_SVSC version */ \
		{ cmpesb 0, 0, %pred5 } \
	ALTERNATIVE_2_OLDINSTR \
	/* Default version */ \
		{ cmpesb 0, 1, %pred5 } \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_SVSC) \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	KERNEL_ENTRY(TSK_U_, /* not a syscall */, 0 /* hw_trap */, %pred0) \
	ALTERNATIVE_1_ALTINSTR \
		/* CPU_FEAT_SEP_VIRT_SPACE version - get kernel PT root from %os_pptb */ \
		{ \
			mmurr %os_pptb, GVCPUSTATE; \
		} \
		{ \
			addd 0, E2K_KERNEL_CONTEXT, GVCPUSTATE; \
			mmurw GVCPUSTATE, %u_pptb ? ~ %pred5; \
		} \
	ALTERNATIVE_2_OLDINSTR \
		/* Original instruction - get kernel PT root from memory */ \
		{ \
			NOT_SEP_VIRT_SPACE_ONLY(ldgdd 0, TSK_K_ROOT_PTB, GVCPUSTATE;) \
		} \
		{ \
			addd 0, E2K_KERNEL_CONTEXT, GVCPUSTATE; \
			mmurw GVCPUSTATE, %root_ptb ? ~ %pred5; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_SEP_VIRT_SPACE) \
	{ \
		mmurw GVCPUSTATE, %cont ? ~ %pred5; \
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

#endif	/* _E2K_TRAP_TABLE_ASM_H */
