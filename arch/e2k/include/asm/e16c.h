/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E16C_H_
#define _ASM_E16C_H_

#ifndef __ASSEMBLY__
struct pt_regs;

#ifdef CONFIG_CPU_E16C
extern void boot_e16c_setup_arch(void);
extern void e16c_setup_machine(void);
#else
static inline void boot_e16c_setup_arch(void) { }
static inline void e16c_setup_machine(void) { }
#endif
#endif

#define	E16C_NR_NODE_CPUS		16
#define	E16C_MAX_NR_NODE_CPUS		16

#define	E16C_NODE_IOLINKS		1

#define	E16C_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E16C_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E16C_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E16C_SIC_MC_SIZE		0x60
#define E16C_SIC_MC_COUNT		8

#define E16C_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E16C_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#define E16C_QNR1_OFFSET		E8C2_QNR1_OFFSET
#endif /* _ASM_E16C_H_ */
