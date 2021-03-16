#pragma once
#include <asm/ptrace.h>

#define __ARCH_IRQ_EXIT_IRQS_DISABLED

extern void irq_enter(void);
extern void irq_exit(void);

#define l_irq_enter()	irq_enter()
#define l_irq_exit()	irq_exit()

#include <asm-l/hardirq.h>

static inline bool is_from_C1_wait_trap(const struct pt_regs *regs)
{
	unsigned long ip = get_return_ip(regs);

	return unlikely(ip >= (unsigned long) __C1_wait_trap_start &&
			ip < (unsigned long) __C1_wait_trap_end);
}
static inline bool is_from_C3_wait_trap(const struct pt_regs *regs)
{
	unsigned long ip = get_return_ip(regs);

	return unlikely(ip >= (unsigned long) __C3_wait_trap_start &&
			ip < (unsigned long) __C3_wait_trap_end);
}
static inline bool is_from_wait_trap(const struct pt_regs *regs)
{
	return is_from_C1_wait_trap(regs) || is_from_C3_wait_trap(regs);
}
extern void handle_wtrap(struct pt_regs *regs);
#define arch_nmi_enter() \
do { \
	inc_irq_stat(__nmi_count); \
	if (is_from_wait_trap(regs)) \
		handle_wtrap(regs); \
} while (0)

#define arch_nmi_exit()		do { } while (0)
