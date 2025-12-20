/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E8C_H_
#define _ASM_E8C_H_

#ifndef __ASSEMBLY__
#ifdef CONFIG_CPU_E8C
extern void boot_e8c_setup_arch(void);
extern void e8c_setup_machine(void);
#else
static inline void boot_e8c_setup_arch(void) { }
static inline void e8c_setup_machine(void) { }
#endif
#endif

#define	E8C_NR_NODE_CPUS		8
#define	E8C_MAX_NR_NODE_CPUS		16

#define	E8C_NODE_IOLINKS		1

#define	E8C_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E8C_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E8C_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E8C_SIC_MC_SIZE			0xe4
#define E8C_SIC_MC_COUNT		4

#define E8C_L3_CACHE_SHIFT		6
#define E8C_L3_CACHE_BYTES		(1 << E8C_L3_CACHE_SHIFT)

#define E8C_QNR1_OFFSET			E2S_QNR1_OFFSET
#endif /* _ASM_E8C_H_ */
