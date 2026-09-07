/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E8V7_H_
#define _ASM_E8V7_H_

struct pt_regs;

#ifdef CONFIG_CPU_E8V7
extern void boot_e8v7_setup_arch(void);
extern void e8v7_setup_machine(void);
#else
static inline void boot_e8v7_setup_arch(void) { }
static inline void e8v7_setup_machine(void) { }
#endif

#define	E8V7_NR_NODE_CPUS		8
#define	E8V7_MAX_NR_NODE_CPUS		64

#define	E8V7_NODE_IOLINKS		1

#define	E8V7_PCICFG_AREA_PHYS_BASE	0x0000000200000000UL
#define	E8V7_PCICFG_AREA_SIZE		0x0000000010000000UL

#define E8V7_NSR_AREA_PHYS_BASE		0x0000000110000000UL

#define E8V7_SIC_MC_SIZE		0x60
#define E8V7_SIC_MC_COUNT		2

#define E8V7_L3_CACHE_SHIFT		6
#define E8V7_L3_CACHE_BYTES		(1 << E8V7_L3_CACHE_SHIFT)

#define E8V7_QNR1_OFFSET		16
#endif /* _ASM_E8V7_H_ */
