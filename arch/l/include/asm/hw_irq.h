#ifndef _ASM_L_HW_IRQ_H
#define _ASM_L_HW_IRQ_H

/* required by linux/irq.h */

#include <asm/irq_vectors.h>

#include <linux/interrupt.h>
#include <linux/profile.h>
#include <asm/atomic.h>
#include <asm/smp.h>
#include <asm/current.h>
#include <asm/sections.h>
#include <asm/page.h>

#ifdef CONFIG_L_LOCAL_APIC
#ifdef CONFIG_PIC
# define platform_legacy_irq(irq)	((irq) < 16)
#else
# define platform_legacy_irq(irq)	0
#endif
#endif

/*
 * Various low-level irq details needed by irq.c, process.c,
 * time.c, io_apic.c and smp.c
 *
 * Interrupt entry/exit code at both C and assembly level
 */

extern atomic_t irq_err_count;

/* IOAPIC */
#ifdef CONFIG_PIC
# define IO_APIC_IRQ(x) (((x) >= NR_IRQS_LEGACY) || ((1<<(x)) & io_apic_irqs))
extern unsigned long io_apic_irqs;
#else
# define IO_APIC_IRQ(x) 1
#endif

extern void disable_IO_APIC(void);

struct io_apic_irq_attr {
	int ioapic;
	int ioapic_pin;
	int trigger;
	int polarity;
};

static inline void set_io_apic_irq_attr(struct io_apic_irq_attr *irq_attr,
					int ioapic, int ioapic_pin,
					int trigger, int polarity)
{
	irq_attr->ioapic	= ioapic;
	irq_attr->ioapic_pin	= ioapic_pin;
	irq_attr->trigger	= trigger;
	irq_attr->polarity	= polarity;
}

/*
 * This is performance-critical, we want to do it O(1)
 *
 * Most irqs are mapped 1:1 with pins.
 */
struct irq_cfg {
	struct irq_pin_list	*irq_2_pin;
	cpumask_var_t		domain;
	cpumask_var_t		old_domain;
	u8			vector;
	u8			move_in_progress : 1;
#ifdef CONFIG_INTR_REMAP
	struct irq_2_iommu	irq_2_iommu;
#endif
};

extern int IO_APIC_get_PCI_irq_vector(int domain, int bus, int devfn, int pin, 
					struct io_apic_irq_attr *irq_attr);
extern int IO_APIC_get_fix_irq_vector(int domain, int bus, int slot, int func,
					int irq);

extern void (*interrupt[NR_VECTORS])(struct pt_regs *regs);
#ifdef CONFIG_TRACING
#define trace_interrupt interrupt
#endif

#define VECTOR_UNDEFINED	-1
#define VECTOR_RETRIGGERED	-2

typedef int vector_irq_t[NR_VECTORS];
DECLARE_PER_CPU(vector_irq_t, vector_irq);

extern void lock_vector_lock(void);
extern void unlock_vector_lock(void);
extern void __setup_vector_irq(int cpu);

#define IO_APIC_VECTOR(irq) ({ \
	struct irq_cfg *__cfg = irq_cfg(irq); \
	(__cfg) ? __cfg->vector : 0; \
})

extern void setup_ioapic_dest(void);

/* Statistics */
extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

/* EISA */
extern void eisa_set_level_irq(unsigned int irq);

/* SMP */
extern __visible void smp_apic_timer_interrupt(struct pt_regs *);
extern __visible void smp_spurious_interrupt(struct pt_regs *);
extern __visible void smp_error_interrupt(struct pt_regs *);
extern __visible void smp_irq_move_cleanup_interrupt(struct pt_regs *);
extern __visible void smp_irq_work_interrupt(struct pt_regs *);
#ifdef CONFIG_SMP
extern __visible void smp_reschedule_interrupt(struct pt_regs *regs);
extern __visible void smp_call_function_interrupt(struct pt_regs *regs);
extern __visible void smp_call_function_single_interrupt(struct pt_regs *regs);
#endif

#ifdef CONFIG_TRACING
/* Interrupt handlers registered during init_IRQ */
extern void smp_trace_apic_timer_interrupt(struct pt_regs *regs);
extern void smp_trace_error_interrupt(struct pt_regs *regs);
extern void smp_trace_irq_work_interrupt(struct pt_regs *regs);
extern void smp_trace_spurious_interrupt(struct pt_regs *regs);
extern void smp_trace_reschedule_interrupt(struct pt_regs *regs);
extern void smp_trace_call_function_interrupt(struct pt_regs *regs);
extern void smp_trace_call_function_single_interrupt(struct pt_regs *regs);
#define trace_irq_move_cleanup_interrupt  irq_move_cleanup_interrupt
#endif /* CONFIG_TRACING */

extern void do_nmi(struct pt_regs * regs);
extern void l_init_system_handlers_table(void);
extern void epic_init_system_handlers_table(void);
extern void setup_PIC_vector_handler(int vector,
		void (*handler)(struct pt_regs *), bool system, char *name);
extern void do_IRQ(struct pt_regs * regs, unsigned int vector);

#endif /* _ASM_L_HW_IRQ_H */
