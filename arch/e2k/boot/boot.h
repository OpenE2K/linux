/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Small boot for simulator
 */

#include <linux/types.h>
#include <asm/bootinfo.h>

#ifndef _E2K_BOOT_BOOT_H_
#define _E2K_BOOT_BOOT_H_

/*
 * E2K physical memory layout
 */

#define	E2K_MAIN_MEM_REGION_START	0x0000000000000000UL	/* from 0 */
#define	E2K_MAIN_MEM_REGION_END		0x0000000080000000UL	/* up to 2Gb */
#define	E2K_EXT_MEM_REGION_START	0x0000000100000000UL	/* from 4Gb */
#define	E2K_EXT_MEM_REGION_END		0x0000001000000000UL	/* up to 64Gb */

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

#endif	/* _E2K_BOOT_BOOT_H_ */
