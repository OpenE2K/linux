/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E1CP_H_
#define _ASM_E1CP_H_

#ifndef __ASSEMBLY__
#ifdef CONFIG_CPU_E1CP
extern void boot_e1cp_setup_arch(void);
extern void e1cp_setup_machine(void);
#else
static inline void boot_e1cp_setup_arch(void) { }
static inline void e1cp_setup_machine(void) { }
#endif
#endif

#define E1CP_NR_NODE_CPUS		1
#define E1CP_MAX_NR_NODE_CPUS		E1CP_NR_NODE_CPUS

#define	E1CP_NODE_IOLINKS		2

#define	E1CP_PCICFG_AREA_PHYS_BASE	0x000000ff10000000UL
#define	E1CP_PCICFG_AREA_SIZE		0x0000000010000000UL

#define E1CP_SIC_MC_COUNT		2

#define E1CP_QNR1_OFFSET		E2S_QNR1_OFFSET
#endif /* _ASM_E1CP_H_ */
