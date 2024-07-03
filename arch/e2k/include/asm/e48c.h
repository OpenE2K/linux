/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E48C_H_
#define _ASM_E48C_H_

#ifndef __ASSEMBLY__
struct pt_regs;

#ifdef CONFIG_CPU_E48C
extern void boot_e48c_setup_arch(void);
extern void e48c_setup_machine(void);
#else
static inline void boot_e48c_setup_arch(void) { }
static inline void e48c_setup_machine(void) { }
#endif
#endif

#define	E48C_NR_NODE_CPUS		48
#define	E48C_MAX_NR_NODE_CPUS		64

#define	E48C_NODE_IOLINKS		1

#define	E48C_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E48C_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E48C_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E48C_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E48C_SIC_MC_COUNT		E16C_SIC_MC_COUNT

#define E48C_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E48C_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#define E48C_QNR1_OFFSET		E8C2_QNR1_OFFSET
#endif /* _ASM_E48C_H_ */
