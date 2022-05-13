#ifndef _ASM_L_IRQ_WORK_H
#define _ASM_L_IRQ_WORK_H

static inline bool arch_irq_work_has_interrupt(void)
{
	//TODO only arm does it this way! (see bug 120742)
#ifdef CONFIG_SMP
	return true;
#else
	return false;
#endif
}

extern void arch_irq_work_raise(void);

#endif /* _ASM_L_IRQ_WORK_H */
