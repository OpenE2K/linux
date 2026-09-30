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

/*
 * Important: the first memory access in kernel is store, not load.
 * This is needed to flush SLT before trying to load anything.
 */
#define SWITCH_HW_STACKS_SYSCALL() \
	KERNEL_ENTRY(TSK_TI_, %r0 /* syscall number */, 1 /* crp */, 0 /* hw_trap */) \
	SWITCH_HW_STACKS( \
		/* switch unconditionally */ \
		cmpesb 0, 0 \
	)

/**
 * SWITCH_HW_STACKS - switch p[c]sp.{lo/hi} registers to kernel values
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
#define SWITCH_HW_STACKS(check_switch...) \
	{ \
		rrd %psp.hi, GCURTASK; \
		check_switch, %pred0; \
		ldgdd,2 0, TSK_TI_K_PSP_LO, GCPUOFFSET; \
		ldgdd,3 0, TSK_TI_K_PCSP_LO, GCPUID_PREEMPT; \
		ldgdd,5 0, TSK_TI_K_PSP_HI, GVCPUSTATE; \
	} \
	{ \
		rrd %psp.lo, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSP_HI; \
	} \
	{ \
		rrd %pcsp.hi, GCURTASK ? %pred0; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSP_LO ? %pred0; \
 \
		/* Restore my_cpu_offset as it was when entering kernel trap */ \
		SMP_ONLY(ldgdd,5 0, TSK_TI_TMP_G_MY_CPU_OFFSET, GCPUOFFSET ? ~ %pred0;) \
	} \
	{ \
		rrd %pcsp.lo, GCURTASK ? %pred0; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSP_HI ? %pred0; \
 \
		/* Restore preemption counter as it was when entering kernel trap */ \
		ldgdd,5 0, TSK_TI_TMP_G_CPU_ID_PREEMPT, GCPUID_PREEMPT ? ~ %pred0; \
	} \
	{ \
		rrd %pshtp, GCURTASK ? %pred0; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSP_LO ? %pred0; \
 \
		/* Executing all instructions below conditinally would \
		 * be faster but putting rwd of a privileged register \
		 * under predicate is disallowed and %ctpr's are not \
		 * available yet. */ \
		ibranch 0f ? ~ %pred0; \
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
		rrd %osr0, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSHTP; \
	} \
	{ \
		rwd GCPUOFFSET, %pcsp.hi; \
	} \
0: /* skip_stacks_switch */ \
	{ \
		rrd %osr0, GCURTASK ? ~ %pred0; \
	}

#ifdef CONFIG_KVM_HOST_MODE
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
#else	/* !CONFIG_KVM_HOST_MODE */
# define CHECK_HWBUG_HCALL_EXC_ILL_INSTR_ADDR(pred)	;
#endif	/* CONFIG_KVM_HOST_MODE */

/**
 * KERNEL_ENTRY - prepare to switch hardware stacks and issue necessary barriers
 * @prefix: where to save %g to
 * @nr_syscall: pass syscall number if applicable; used to skip unneeded
 *		save & restore for all syscalls except sys_sigreturn
 * @issue_crp: pass 1 to issue 'crp' for clearing generations table;
 *	       can be skipped if this is hardware trap entry
 *
 * This will:
 *  - save some %g to memory so that we have registers to execute upon and
 *    switch hardware stacks (this is skipped for all syscalls except sigreturn)
 *  - flush SLT by issuing a store before any loads;
 *  - flush generations table with `crp`;
 *  - wait for AAU/DTLB buffer to flush so that we can write MMU regs in kernel.
 */
#define KERNEL_ENTRY(prefix, nr_syscall, issue_crp, hw_trap) \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	ALTERNATIVE_1_ALTINSTR \
		/* iset v5 version - save qp registers extended part */ \
		{ \
			stgdq,sm %qg16, 0, TSK_G_TMP_TAG; \
		} \
		{ \
			nop 1; \
			rrd %osr0, GCURTASK; \
			stgdqp,sm %qpg17, 0, prefix##G17; \
		} \
		/* Bug 116851 - all strqp must be speculative if dealing with tags */ \
		{ \
			strqp,2,sm %qpg16, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G16; \
			ldrd,5 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | (TSK_G_TMP_TAG + 8), %dg16; \
		} \
		{ \
			nop 3; \
			strqp,2,sm %qpg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G18; \
			strqp,5,sm %qpg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G19; \
		} \
		{ \
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
			rrd %osr0, GCURTASK; \
			stgdq,sm %qg16, 0, prefix##G17; \
		} \
		{ \
			nop 3; \
			strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G18; \
			strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G19; \
			movfi,1 %xg18, %dg18; \
			movfi,4 %xg19, %dg19; \
		} \
		{ \
			strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G18_EXT; \
			strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G19_EXT; \
		} \
		{ \
			nop 3; \
			ldrd,0 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | prefix##G16_EXT, %dg18; \
			ldrd,3 GCURTASK, TAGGED_MEM_LOAD_REC_OPC | prefix##G17, %dg19; \
		} \
		{ \
			strd,2 %dg18, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G17; \
			strd,5 %dg19, GCURTASK, TAGGED_MEM_STORE_REC_OPC | prefix##G16_EXT; \
		} \
	ALTERNATIVE_3_FEATURE(CPU_FEAT_QPREG) \
	{ \
		/* 'crp' instruction also clears %rpr besides the generations \
		 * table, so make sure we preserve %rpr value. */ \
		.if issue_crp; rrd %rpr.lo, %dg16; .endif; \
	} \
.ifne hw_trap; \
	/* Assumes that only %g16-%g17 has been modified with kernel \
	 * values above in CPU_FEAT_QPREG case.  Will modify %g18. */ \
	CHECK_HWBUG_HCALL_EXC_ILL_INSTR_ADDR(%pred3); \
.endif; \
	{ \
		/* #144498: wait for activity in DTLB/AAU to stop, which
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
.if issue_crp; \
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
.endif;

#define HANDLER_TRAMPOLINE(ctprN, scallN, fn, wbsL) \
	/* Force load OSGD->GD. Alternative is to use non-0 CUI for kernel */ \
	{ \
		sdisp ctprN, scallN; \
	} \
	/* CPU_HWBUG_VIRT_PSIZE_INTERCEPTION */ \
	{ nop } { nop } { nop } { nop } \
	call ctprN, wbs=wbsL; \
	/* \
	 * Important: the first memory access in kernel is store, not load. \
	 * This is needed to flush SLT before trying to load anything. \
	 */ \
	KERNEL_ENTRY(TSK_TI_, /* not a syscall */, 1 /* crp */, 0 /* hw_trap */) \
	{ \
		disp ctprN, fn; \
	} \
	SWITCH_HW_STACKS( \
		/* switch unconditionally */ \
		cmpesb 0, 0 \
	) \
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
