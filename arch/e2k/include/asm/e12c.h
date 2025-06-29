/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E12C_H_
#define _ASM_E12C_H_

#ifndef __ASSEMBLY__
struct pt_regs;

#ifdef CONFIG_CPU_E12C
extern void boot_e12c_setup_arch(void);
extern void e12c_setup_machine(void);
#else
static inline void boot_e12c_setup_arch(void) { }
static inline void e12c_setup_machine(void) { }
#endif
#endif

#define	E12C_NR_NODE_CPUS		12
#define	E12C_MAX_NR_NODE_CPUS		16

#define	E12C_NODE_IOLINKS		1

#define	E12C_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E12C_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E12C_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E12C_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E12C_SIC_MC_COUNT		2

#define E12C_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E12C_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#define E12C_QNR1_OFFSET		E8C2_QNR1_OFFSET
#endif /* _ASM_E12C_H_ */
