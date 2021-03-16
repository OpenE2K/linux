/* $Id: page_tables.S,v 1.10 2008/04/21 18:57:22 atic Exp $ */
//
// special page tables to support boot and kernel initialization
//

#include <asm/head.h>
#include <asm/page.h>
#include <generated/asm-offsets.h>
#include <asm/pv_info.h>
#include <asm/cpu_regs_types.h>
#include <asm/mmu_types.h>
#include <asm/mmu_regs_types.h>
#include <asm/sections.h>


	__NODEDATA
#ifdef CONFIG_NUMA
	/* We want to map zero page with small pages to write-protect it,
	 * so in !NUMA case it goes into different section */
	.align	PAGE_SIZE
	.global empty_zero_page
empty_zero_page:
	.skip	PAGE_SIZE
#endif

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
#ifndef	CONFIG_NUMA
	.data
#else	/* CONFIG_NUMA */
	__NODEDATA
#endif	/* ! CONFIG_NUMA */

kernel_trap_cellar:
#ifndef	CONFIG_SMP
	.skip	MMU_TRAP_CELLAR_MAX_SIZE * 8		// 128 double-words
#else
	.skip	MMU_TRAP_CELLAR_MAX_SIZE * 8 * NR_CPUS	// 128 double-words
							// for each CPU
#endif	/* CONFIG_SMP */

	.global	kernel_CUT
	.align	(1 << E2K_ALIGN_CUT)			// 32 bytes
kernel_CUT:
	.skip	KERNEL_CUT_BYTE_SIZE

