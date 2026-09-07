/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Small boot for simulator
 */

#include <linux/types.h>

#ifndef _E2K_BOOT_BOOT_H_
#define _E2K_BOOT_BOOT_H_

#define E2S_CLN_BITS	4	/* 4 bits - cluster # */
#define E8C_CLN_BITS	2	/* 2 bits - cluster # */

#ifdef	CONFIG_NBSR_CFG_V4
/* field 'cln' has only 2 bits for iset version v4-v5 */
# undef  E2K_MAX_CL_NUM
# define E2K_MAX_CL_NUM	((1 << E8C_CLN_BITS) - 1)
#elif	defined(CONFIG_NBSR_CFG_V6)
/* field 'cln' does not used from NBSR iset version v6-* */
# undef  E2K_MAX_CL_NUM
# define E2K_MAX_CL_NUM	0
#else	/* iset < v4 */
/* field 'cln' has 4 bits for iset version v4-v5 */
# undef  E2K_MAX_CL_NUM
# define E2K_MAX_CL_NUM	((1 << E2S_CLN_BITS) - 1)
#endif /* CONFIG_E2K_CFG_V4 */

#define	NBSR_NODE_ID(cln, pln)	(((cln) << 2) | ((pln) & 0x3))

/*
 * E2K physical memory layout
 */

#define	E2K_MAIN_MEM_REGION_START	0x0000000000000000UL	/* from 0 */
#define	E2K_MAIN_MEM_REGION_END		0x0000000080000000UL	/* up to 2Gb */
#define	E2K_EXT_MEM_REGION_START	0x0000000100000000UL	/* from 4Gb */
#define	E2K_EXT_MEM_REGION_END		0x0000001000000000UL	/* up to 64Gb */

#define	EOS_RAM_BASE_LABEL	_data

#ifdef __ASSEMBLY__
# define EOS_RAM_BASE	[EOS_RAM_BASE_LABEL]
#else
# define EOS_RAM_BASE	((e2k_addr_t)&EOS_RAM_BASE_LABEL)

#include <asm/bootinfo.h>

extern void *malloc_aligned(int size, int alignment);
extern void *malloc(int size);
extern void bios_mem_init(long membase, long memsize);
extern e2k_addr_t get_busy_memory_end(void);

extern int  decompress_kernel(ulong base);
extern void rom_putc(char c);
extern int  rom_getc(void);
extern int  rom_tstc(void);

#ifdef	CONFIG_SMP
extern void smp_start_cpus(void);
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_STATE_SAVE
extern void load_machine_state_new(boot_info_t *boot_info);
#endif	/* CONFIG_STATE_SAVE */

#endif	/* !__ASSEMBLY__ */
#endif	/* _E2K_BOOT_BOOT_H_ */
