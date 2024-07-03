/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_CPU_H_
#define _ASM_E2K_CPU_H_

#include <linux/cpu.h>

extern int arch_register_cpu(int num);
#ifdef CONFIG_HOTPLUG_CPU
extern void arch_unregister_cpu(int);
#endif

extern void store_cpu_info(int cpuid);

#endif /* _ASM_E2K_CPU_H_ */
