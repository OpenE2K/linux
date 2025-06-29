/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2S_H_
#define _ASM_E2S_H_

#ifndef __ASSEMBLY__
#ifdef CONFIG_CPU_E2S
extern void boot_e2s_setup_arch(void);
extern void e2s_setup_machine(void);
#else
static inline void boot_e2s_setup_arch(void) { }
static inline void e2s_setup_machine(void) { }
#endif
#endif

#define	E2S_NR_NODE_CPUS		4
#define	E2S_MAX_NR_NODE_CPUS		E2S_NR_NODE_CPUS

#define	E2S_NODE_IOLINKS		1

#define	E2S_PCICFG_AREA_PHYS_BASE	0x0000000200000000UL
#define	E2S_PCICFG_AREA_SIZE		0x0000000010000000UL

#define E2S_NSR_AREA_PHYS_BASE		0x0000000110000000UL

#define E2S_SIC_MC_SIZE			0xa4
#define E2S_SIC_MC_COUNT		3

#define E2S_QNR1_OFFSET			8
#endif /* _ASM_E2S_H_ */
