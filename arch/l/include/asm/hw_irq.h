/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_HW_IRQ_H
#define _ASM_L_HW_IRQ_H

struct irq_data;
struct pci_dev;
struct msi_desc;

struct irq_cfg {
	unsigned int		dest_apicid;
	unsigned int		vector;
};

extern struct irq_cfg *irq_cfg(unsigned int irq);
extern struct irq_cfg *irqd_cfg(struct irq_data *irq_data);


#ifdef CONFIG_EPIC
#define NR_VECTORS			1024
#else
#define NR_VECTORS			256
#endif
#define IRQ_MATRIX_BITS                NR_VECTORS

/*
 * Size the maximum number of interrupts.
 *
 * If the irq_desc[] array has a sparse layout, we can size things
 * generously - it scales up linearly with the maximum number of CPUs,
 * and the maximum number of IO-APICs, whichever is higher.
 *
 * In other cases we size more conservatively, to not create too large
 * static arrays.
 */

#define CPU_VECTOR_LIMIT		(8 * NR_CPUS)
#define IO_APIC_VECTOR_LIMIT		(32 * MAX_IO_APICS)

#if defined(CONFIG_L_IO_APIC) && defined(CONFIG_PCI_MSI)
#define NR_IRQS                                                \
	(CPU_VECTOR_LIMIT > IO_APIC_VECTOR_LIMIT ?      \
		(NR_VECTORS + CPU_VECTOR_LIMIT)  :      \
		(NR_VECTORS + IO_APIC_VECTOR_LIMIT))
#elif defined(CONFIG_L_IO_APIC)
#define        NR_IRQS                         (NR_VECTORS + IO_APIC_VECTOR_LIMIT)
#elif defined(CONFIG_PCI_MSI)
#define NR_IRQS                                (NR_VECTORS + CPU_VECTOR_LIMIT)
#else /* !CONFIG_L_IO_APIC: */
# define NR_IRQS                       0
#endif


extern void (*interrupt[NR_VECTORS])(struct pt_regs *regs);

typedef struct irq_desc* vector_irq_t[NR_VECTORS];
DECLARE_PER_CPU(vector_irq_t, vector_irq);



/* Statistics */
extern atomic_t irq_err_count;
extern atomic_t irq_mis_count;

void lock_vector_lock(void);
void unlock_vector_lock(void);
#ifdef CONFIG_SMP
extern void send_cleanup_vector(struct irq_cfg *);
extern void irq_complete_move(struct irq_cfg *cfg);
#else
static inline void send_cleanup_vector(struct irq_cfg *c) { }
static inline void irq_complete_move(struct irq_cfg *c) { }
#endif

void do_nmi(struct pt_regs * regs);
void do_IRQ(struct pt_regs * regs, unsigned int vector);
#endif /* _ASM_L_HW_IRQ_H */
