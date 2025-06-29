/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */
#ifndef __ASM_L_PIC_COMMON_H
#define __ASM_L_PIC_COMMON_H

#include <linux/irq.h>

#ifdef CONFIG_SMP
int __init pic_init_smp(struct irq_domain *parent, struct device_node *np);
#else
# define pic_init_smp(parent, np) 0
#endif

noinline notrace void epic_do_nmi(struct pt_regs *regs);
noinline notrace void apic_do_nmi(struct pt_regs *regs);


extern int irq_move_cleanup_vector;
bool apic_check_vector_to_be_cleaned(unsigned vector);
bool epic_check_vector_to_be_cleaned(unsigned vector);

extern struct irq_chip lapic_controller;
extern struct irq_chip epic_controller;
int __init epic_init(struct device_node *np);

#ifdef CONFIG_SMP
int pic_set_affinity(struct irq_data *irqd,
			     const struct cpumask *dest, bool force);
void smp_irq_move_cleanup_interrupt(void);
#else
# define pic_set_affinity	NULL
#endif

struct pic_chip_data {
	struct irq_cfg		hw_irq_cfg;
	unsigned int		vector;
	unsigned int		prev_vector;
	unsigned int		cpu;
	unsigned int		prev_cpu;
	unsigned int		irq;
	struct hlist_node	clist;
	unsigned int		move_in_progress	: 1,
				is_managed		: 1,
				can_reserve		: 1,
				has_reserved		: 1;
};


static inline struct pic_chip_data *pic_chip_data(struct irq_data *irqd)
{
	if (!irqd)
		return NULL;

	while (irqd->parent_data)
		irqd = irqd->parent_data;

	return irqd->chip_data;
}


extern int nr_logical_cpuids;
extern int cpuid_to_picid[];
extern int allocate_logical_cpuid(int picid);

/* Convert logical CPU ID to physical APIC/short EPIC ID (ID < NR_CPUS) */
static inline int cpu_to_short_picid(unsigned int cpu)
{
	BUG_ON(cpu > nr_logical_cpuids);

	return cpuid_to_picid[cpu];
}

struct irq_desc *__setup_vector_irq(int vector);
u32 apic_default_calc_apicid(unsigned int cpu);
bool pic_check_vector_to_be_cleaned(unsigned vector);
int pic_get_vector_by_name(struct device_node *np, char *path,
				char *name, int *vec);
int pic_send_cleanup_vector(const struct cpumask *target);

/*
 * IDT vectors usable for external interrupt sources start
 * at 0x20:
 */
#define FIRST_EXTERNAL_VECTOR		0x20

#define FIRST_SYSTEM_VECTOR		0xef /*LOCAL_TIMER_VECTOR*/
#define FIRST_EPIC_SYSTEM_VECTOR	0x3c0/*LINP0_INTERRUPT_VECTOR*/

#define NMI_VECTOR			0x02


#define VECTOR_UNUSED		NULL
#define VECTOR_SHUTDOWN		((void *)-1L)
#define VECTOR_RETRIGGERED	((void *)-2L)

#endif /* __ASM_L_PIC_COMMON_H */