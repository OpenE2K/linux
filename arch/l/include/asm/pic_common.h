/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_L_PIC_COMMON_H
#define __ASM_L_PIC_COMMON_H

/*
 * Common declarations for APIC and EPIC
 */

extern int nr_logical_cpuids;
extern int cpuid_to_picid[];
extern int allocate_logical_cpuid(int picid);

/* Convert logical CPU ID to physical APIC/short EPIC ID (ID < NR_CPUS) */
static inline int cpu_to_short_picid(unsigned int cpu)
{
	BUG_ON(cpu > nr_logical_cpuids);

	return cpuid_to_picid[cpu];
}

#endif /* __ASM_L_PIC_COMMON_H */
