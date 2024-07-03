/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2C3_H_
#define _ASM_E2C3_H_

#ifndef __ASSEMBLY__
#ifdef CONFIG_CPU_E2C3
extern void boot_e2c3_setup_arch(void);
extern void e2c3_setup_machine(void);
#else
static inline void boot_e2c3_setup_arch(void) { }
static inline void e2c3_setup_machine(void) { }
#endif
#endif

#define	E2C3_NR_NODE_CPUS		2
#define	E2C3_MAX_NR_NODE_CPUS		16

#define	E2C3_NODE_IOLINKS		1

#define	E2C3_PCICFG_AREA_PHYS_BASE	E2S_PCICFG_AREA_PHYS_BASE
#define	E2C3_PCICFG_AREA_SIZE		E2S_PCICFG_AREA_SIZE

#define E2C3_NSR_AREA_PHYS_BASE		E2S_NSR_AREA_PHYS_BASE

#define E2C3_SIC_MC_SIZE		E16C_SIC_MC_SIZE
#define E2C3_SIC_MC_COUNT		E12C_SIC_MC_COUNT

#define E2C3_QNR1_OFFSET		E8C2_QNR1_OFFSET
#endif /* _ASM_E2C3_H_ */
