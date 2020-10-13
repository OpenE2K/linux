#ifndef _ASM_E2K_CPU_H_
#define _ASM_E2K_CPU_H_

#include <linux/cpu.h>

struct e2k_cpu {
	struct cpu cpu;
};

DECLARE_PER_CPU(int, cpu_state);

extern int arch_register_cpu(int num);
#ifdef CONFIG_HOTPLUG_CPU
extern void arch_unregister_cpu(int);
#endif

extern __init_recv unsigned long measure_cpu_freq(void);
extern __init_recv void store_cpu_info(int cpuid);

#endif /* _ASM_E2K_CPU_H_ */
