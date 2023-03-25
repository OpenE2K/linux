#ifndef _ASM_E2K_IRQ_H_
#define _ASM_E2K_IRQ_H_
/*
 *	(C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar
 *
 *	IRQ/IPI changes taken from work by Thomas Radke
 *	<tomsoft@informatik.tu-chemnitz.de>
 */

#include <asm/apicdef.h>
#include <asm/epicdef.h>
#include <asm/irq_vectors.h>
#include <linux/cpumask.h>

#define irq_canonicalize(irq)	(irq)

extern int can_request_irq(unsigned int, unsigned long flags);
extern void arch_trigger_cpumask_backtrace(const cpumask_t *mask,
					   bool exclude_self) __cold;
#define arch_trigger_cpumask_backtrace arch_trigger_cpumask_backtrace

#endif /* _ASM_E2K_IRQ_H_ */
