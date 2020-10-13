#ifndef _ASM_E2K_IRQ_H_
#define _ASM_E2K_IRQ_H_
/*
 *	(C) 1992, 1993 Linus Torvalds, (C) 1997 Ingo Molnar
 *
 *	IRQ/IPI changes taken from work by Thomas Radke
 *	<tomsoft@informatik.tu-chemnitz.de>
 */

#include <asm/apicdef.h>
#include <asm/irq_vectors.h>

#define irq_canonicalize(irq)	(irq)

extern int can_request_irq(unsigned int, unsigned long flags);

#ifdef CONFIG_HOTPLUG_CPU
#include <linux/cpumask.h>
extern int check_irq_vectors_for_cpu_disable(void);
extern void fixup_irqs(void);
extern void irq_force_complete_move(int);
#endif

#ifdef	CONFIG_RECOVERY
extern void recovery_IRQ(void);
#endif	/* CONFIG_RECOVERY */

extern void print_running_tasks(int show_reg_window);
#define arch_trigger_all_cpu_backtrace()  ({ print_running_tasks(0); true; })

#endif /* _ASM_E2K_IRQ_H_ */
