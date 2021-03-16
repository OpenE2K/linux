#ifndef _ASM_E2K_NMI_H
#define _ASM_E2K_NMI_H

#include <asm-l/nmi.h>

/*
 * ATTENTION nmi_call_function_xxx() are actually more limited
 * than smp_call_function_xxx().
 *
 * 1) You cannot use ANY drivers (since they are usually NOT async-safe).
 *
 * 2) You cannot use printk() (as a consequence of 1).
 *
 * 3) Function must be fast and non-blocking.
 *
 * So instead of using printk() it is better to save your message
 * into a temporary buffer and later print that buffer from the function
 * which called nmi_call_function_xxx().
 */
extern void nmi_call_function_init(void);
extern void nmi_call_function_interrupt(void);
#ifdef CONFIG_SMP
extern int nmi_call_function(void (*func)(void *), void *info, int wait,
		int timeout_msec);
extern int nmi_call_function_mask(const cpumask_t *mask, void (*func)(void *),
		void *info, int wait, int timeout_msec);
extern int nmi_call_function_single(int cpu, void (*func)(void *),
		void *info, int wait, int timeout_msec);
extern int nmi_call_function_single_offline(int cpu, void (*func)(void *),
		void *info, int wait, int timeout_msec);
# define nmi_on_each_cpu(func, info, wait, timeout_msec)		\
	({								\
		unsigned long __flags;					\
		WARN_ON_ONCE(raw_nmi_irqs_disabled());			\
		raw_local_irq_save(__flags);				\
		nmi_call_function(func, info, wait, timeout_msec);	\
		raw_all_irq_disable();					\
		func(info);						\
		if (!raw_irqs_disabled_flags(__flags))			\
			trace_hardirqs_on();				\
		raw_all_irq_restore(__flags);				\
		0;							\
	})
#else
static inline int nmi_call_function_mask(const cpumask_t *mask,
		void (*func)(void *), void *info, int wait, int timeout_msec)
{
	unsigned long flags;

	if (cpumask_test_cpu(0, mask)) {
		raw_all_irq_save(flags);
		func(info);
		raw_all_irq_restore(flags);
	}

	return 0;
}

static inline int nmi_call_function_single(int cpu, void (*func)(void *),
		void *info, int wait, int timeout_msec)
{
	unsigned long flags;

	WARN_ON(cpu != 0);

	raw_all_irq_save(flags);
	func(info);
	raw_all_irq_restore(flags);

	return 0;
}

static inline int nmi_call_function_single_offline(int cpu, void (*func)(void *),
		void *info, int wait, int timeout_msec)
{
	BUG();
}

static inline int up_nmi_call_function(void (*func)(void *), void *info)
{
	return 0;
}
# define nmi_call_function(func, info, wait, timeout) \
		(up_nmi_call_function(func, info))
# define nmi_on_each_cpu(func, info, wait, timeout) \
	({					\
		unsigned long __flags;		\
		raw_all_irq_save(__flags);	\
		func(info);			\
		raw_all_irq_restore(__flags);	\
		0;				\
	})
#endif

#endif /* _ASM_E2K_NMI_H */
