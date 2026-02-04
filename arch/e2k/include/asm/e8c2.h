/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E8C2_H_
#define _ASM_E8C2_H_

#ifndef __ASSEMBLY__
#ifdef CONFIG_CPU_E8C2
extern void boot_e8c2_setup_arch(void);
extern void e8c2_setup_machine(void);
#else
static inline void boot_e8c2_setup_arch(void) { }
static inline void e8c2_setup_machine(void) { }
#endif
#endif

#define	E8C2_NR_NODE_CPUS		E8C_NR_NODE_CPUS
#define	E8C2_MAX_NR_NODE_CPUS		E8C_MAX_NR_NODE_CPUS

#define	E8C2_NODE_IOLINKS		E8C_NODE_IOLINKS

#define	E8C2_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E8C2_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E8C2_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E8C2_SIC_MC_SIZE		0xf4
#define E8C2_SIC_MC_COUNT		E8C_SIC_MC_COUNT

#define E8C2_L3_CACHE_SHIFT		E8C_L3_CACHE_SHIFT
#define E8C2_L3_CACHE_BYTES		E8C_L3_CACHE_BYTES

#define E8C2_QNR1_OFFSET		16
#endif /* _ASM_E8C2_H_ */
