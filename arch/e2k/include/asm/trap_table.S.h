/*
 *
 * Copyright (C) 2020 MCST
 *
 * Defenition of traps handling routines.
 */

#ifndef _E2K_TRAP_TABLE_ASM_H
#define _E2K_TRAP_TABLE_ASM_H

#ifdef	__ASSEMBLY__

#include <asm/thread_info.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_types.h>
#include <asm/glob_regs.h>
#include <asm/mmu_types.h>

#include <generated/asm-offsets.h>

#if defined CONFIG_SMP
# define SMP_ONLY(...) __VA_ARGS__
#else
# define SMP_ONLY(...)
#endif

/*
 * Important: the first memory access in kernel is store, not load.
 * This is needed to flush SLT before trying to load anything.
 */
#define SWITCH_HW_STACKS_FROM_USER(...) \
	{ \
		/* Disable load/store generations */ \
		crp; \
	} \
	{ \
		/* Wait for FPU exceptions before switching stacks */ \
		wait all_e = 1; \
		rrd %osr0, GVCPUSTATE; \
		stgdq,sm %qg16, 0, TSK_TI_G_VCPU_STATE; \
	} \
	{ \
		rrd %psp.hi, GCURTASK; \
		stgdq,sm %qg18, 0, TSK_TI_G_MY_CPU_OFFSET; \
		cmpesb,1 0, 0, %pred0; \
	} \
	SWITCH_HW_STACKS(TSK_TI_, ##__VA_ARGS__)

/*
 * This assumes that GVCPUSTATE points to current_thread_info()
 * and %psp.hi has been read into GCURTASK
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
 * 3) Updates global and stack registers with kernel values (if not in
 * kernel trap where it's been done already)
 */
#define SWITCH_HW_STACKS(PREFIX, ...) \
	{ \
		ldd,0 GVCPUSTATE, TI_K_PSP_LO, GCPUOFFSET; \
		ldd,2 GVCPUSTATE, TI_K_PCSP_LO, GCPUID; \
		__VA_ARGS__ \
	} \
	{ \
		rrd %psp.lo, GCURTASK ? %pred0; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSP_HI ? %pred0; \
		SMP_ONLY(ldw,5 GVCPUSTATE, TSK_TI_CPU_DELTA, GCPUID ? ~ %pred0;) \
	} \
	{ \
		rrd %pcsp.hi, GCURTASK ? %pred0; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSP_LO ? %pred0; \
		/* Nothing to do if this is kernel (%pred0 == false) */ \
		subd,1 GVCPUSTATE, TSK_TI, GCURTASK ? ~ %pred0; \
		ibranch trap_handler_switched_stacks ? ~ %pred0; \
	} \
	{ \
		nop 1; /* ldd -> use */ \
		rrd %pcsp.lo, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSP_HI; \
	} \
	{ \
		rwd GCPUOFFSET, %psp.lo; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSP_LO; \
		ldrd,5 GVCPUSTATE, TAGGED_MEM_LOAD_REC_OPC | PREFIX##G_MY_CPU_OFFSET_EXT, GCPUOFFSET; \
	} \
	{ \
		rwd GCPUID, %pcsp.lo; \
		ldd,2 GVCPUSTATE, TI_K_PSP_HI, GCURTASK; \
		ldrd,5 GVCPUSTATE, TAGGED_MEM_LOAD_REC_OPC | PREFIX##G_VCPU_STATE_EXT, GCPUID; \
	} \
	{ \
		rwd GCURTASK, %psp.hi; \
		ldd,2 GVCPUSTATE, TI_K_PCSP_HI, GCURTASK; \
	} \
	{ \
		rwd GCURTASK, %pcsp.hi; \
	} \
	{ \
		rrd %pshtp, GCURTASK; \
	} \
	{ \
		ldrd,3 GVCPUSTATE, TAGGED_MEM_LOAD_REC_OPC | PREFIX##G_CPU_ID, GCPUOFFSET; \
		strd,5 GCPUOFFSET, GVCPUSTATE, TAGGED_MEM_STORE_REC_OPC | PREFIX##G_CPU_ID; \
	} \
	{ \
		ldrd,3 GVCPUSTATE, TAGGED_MEM_LOAD_REC_OPC | PREFIX##G_TASK, GCPUID; \
		strd,5 GCPUID, GVCPUSTATE, TAGGED_MEM_STORE_REC_OPC | PREFIX##G_TASK; \
	} \
	{ \
		nop 2; /* ld -> use  */ \
		rrd %pcshtp, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PSHTP; \
	} \
	{ \
		subd,1 GVCPUSTATE, TSK_TI, GCURTASK; \
		stgdd,2 GCURTASK, 0, TSK_TI_TMP_U_PCSHTP; \
		strd,5 GCPUOFFSET, GVCPUSTATE, TAGGED_MEM_STORE_REC_OPC | PREFIX##G_MY_CPU_OFFSET_EXT; \
	} \
	{ \
		SMP_ONLY(ldw,3 GVCPUSTATE, TSK_TI_CPU_DELTA, GCPUID;) \
		strd,5 GCPUID, GVCPUSTATE, TAGGED_MEM_STORE_REC_OPC | PREFIX##G_VCPU_STATE_EXT; \
	}

.macro	HANDLER_TRAMPOLINE ctprN, scallN, fn, wbsL
/* Force load OSGD->GD. Alternative is to use non-0 CUI for kernel */
{
	nop
	sdisp	\ctprN, \scallN
}
	call	\ctprN, wbs=\wbsL
	disp	\ctprN, \fn
	SWITCH_HW_STACKS_FROM_USER()
	SMP_ONLY(shld,1	GCPUID, 3, GCPUOFFSET)
{
	SMP_ONLY(ldd,2	[ __per_cpu_offset + GCPUOFFSET ], GCPUOFFSET)
	ct	\ctprN
}
.endm	/* HANDLER_TRAMPOLINE */

#endif	/* __ASSEMBLY__ */

#endif	/* _E2K_TRAP_TABLE_ASM_H */
