/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_IRQ_H_
#define _ASM_E2K_IRQ_H_

#include <linux/cpumask.h>

#define irq_canonicalize(irq)	(irq)

extern void __init init_IRQ(void);
extern int can_request_irq(unsigned int, unsigned long flags);
extern void arch_trigger_cpumask_backtrace(const cpumask_t *mask,
					   bool exclude_self) __cold;
#define arch_trigger_cpumask_backtrace arch_trigger_cpumask_backtrace

#ifdef CONFIG_SOFTIRQ_ON_OWN_STACK
extern int irq_init_percpu_irqstack(unsigned int cpu);

#define on_softirq_stack()	(current->thread.on_softirq_stack)

/* Add 'noinline' since it is called after switching stacks */
extern noinline void __do_softirq(void);
#else
static inline int irq_init_percpu_irqstack(unsigned int cpu)
{
	return 0;
}
static inline bool on_softirq_stack(void)
{
	return false;
}
#endif /* CONFIG_SOFTIRQ_ON_OWN_STACK */

#endif /* _ASM_E2K_IRQ_H_ */
