/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E8V7_H_
#define _ASM_E8V7_H_

#ifndef __ASSEMBLY__
struct pt_regs;

#ifdef CONFIG_CPU_E8V7
extern void boot_e8v7_setup_arch(void);
extern void e8v7_setup_machine(void);
#else
static inline void boot_e8v7_setup_arch(void) { }
static inline void e8v7_setup_machine(void) { }
#endif
#endif

#define	E8V7_NR_NODE_CPUS		8
#define	E8V7_MAX_NR_NODE_CPUS		64

#define	E8V7_NODE_IOLINKS		1

#define	E8V7_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E8V7_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E8V7_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E8V7_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E8V7_SIC_MC_COUNT		E16C_SIC_MC_COUNT

#define E8V7_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E8V7_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#define E8V7_QNR1_OFFSET		E8C2_QNR1_OFFSET
#endif /* _ASM_E8V7_H_ */
