/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_L_HARDIRQ_H
#define __ASM_L_HARDIRQ_H

#include <linux/cache.h>
#include <linux/percpu.h>

typedef struct {
	unsigned int __softirq_pending;
#ifdef CONFIG_L_LOCAL_APIC
	unsigned int icr_read_retry_count;
#endif
#ifdef CONFIG_SMP
# ifdef CONFIG_E2K
	/*
	 * irq_tlb_count is double-counted in irq_call_count, so it must be
	 * subtracted from irq_call_count when displaying irq_call_count
	 */
	unsigned int irq_tlb_count;
# endif
#endif
} ____cacheline_aligned irq_cpustat_t;

DECLARE_PER_CPU_SHARED_ALIGNED(irq_cpustat_t, irq_stat);

extern void ack_bad_irq(unsigned int irq);

#define __ARCH_IRQ_STAT
#define __IRQ_STAT(cpu, member) (per_cpu(irq_stat, cpu).member)

#define inc_irq_stat(member)	__IRQ_STAT(raw_smp_processor_id(), member)++

extern u64 arch_irq_stat(void);
#define arch_irq_stat		arch_irq_stat

#endif /* __ASM_L_HARDIRQ_H */
