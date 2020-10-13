/* $Id: page_tables.S,v 1.10 2008/04/21 18:57:22 atic Exp $ */
//
// special page tables to support boot and kernel initialization
//

#include <asm/head.h>
#include <asm/page.h>
#include <asm/asm-offsets.h>
#include <asm/cpu_regs.h>
#include <asm/mmu_regs.h>
#include <asm/sections.h>


//	.section "data"

	__NODEDATA

	.align	PAGE_SIZE
	.global empty_zero_page
empty_zero_page:
	.skip	PAGE_SIZE

#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
	.global	swapper_pg_dir
	.align	PAGE_SIZE
swapper_pg_dir:
	.skip	PAGE_SIZE
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	.global all_cpus_swapper_pg_dir
all_cpus_swapper_pg_dir:
	.skip	PAGE_SIZE * NR_CPUS	/* each CPU has own copy of page dir */
#endif	/* ! COPY_USER_PGD_TO_KERNEL_ROOT_PT */

	.align	(1 << MMU_ALIGN_TRAP_POINT_BASE)	// 0x200
	.global kernel_trap_cellar
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
	.section "data"
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	__NODEDATA
#endif	/* ! COPY_USER_PGD_TO_KERNEL_ROOT_PT */
kernel_trap_cellar:
#ifndef	CONFIG_SMP
	.skip	MMU_TRAP_CELLAR_MAX_SIZE * 8		// 64 double-words
#else
	.skip	MMU_TRAP_CELLAR_MAX_SIZE * 8 * NR_CPUS	// 64 double-words
							// for each CPU
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
	.global	kernel_CUT
	.align	(1 << E2K_ALIGN_CUT)			// 32 bytes
kernel_CUT:
	.skip	KERNEL_CUT_BYTE_SIZE
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */


