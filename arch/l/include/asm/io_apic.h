/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * IO-APIC support for SMP and UP systems.
 */

#ifndef _ASM_L_IO_APIC_H
#define _ASM_L_IO_APIC_H

#include <linux/types.h>
#include <asm/mpspec.h>
#include <asm/apicdef.h>
#include <asm/irq_vectors.h>

/* I/O Unit Redirection Table */
#define IO_APIC_REDIR_VECTOR_MASK	0x000FF
#define IO_APIC_REDIR_DEST_LOGICAL	0x00800
#define IO_APIC_REDIR_DEST_PHYSICAL	0x00000
#define IO_APIC_REDIR_SEND_PENDING	(1 << 12)
#define IO_APIC_REDIR_REMOTE_IRR	(1 << 14)
#define IO_APIC_REDIR_LEVEL_TRIGGER	(1 << 15)
#define IO_APIC_REDIR_MASKED		(1 << 16)

#define IOAPIC_AUTO     -1
#define IOAPIC_EDGE     0
#define IOAPIC_LEVEL    1

#ifdef CONFIG_L_IO_APIC

extern DECLARE_BITMAP(used_vectors, NR_VECTORS);

/*
 * # of IO-APICs and # of IRQ routing registers
 */
extern int nr_ioapics;

extern int mpc_ioapic_id(int ioapic);
extern unsigned long mpc_ioapic_addr(int ioapic);
extern struct mp_ioapic_gsi *mp_ioapic_gsi_routing(int ioapic);

#define MP_MAX_IOAPIC_PIN 127

/* # of MP IRQ source entries */
extern int mp_irq_entries;

/* MP IRQ source entries */
extern struct mpc_intsrc mp_irqs[];

/*
 * If we use the IO-APIC for IRQ routing, disable automatic
 * assignment of PCI IRQ's.
 */
#define io_apic_assign_pci_irqs mp_irq_entries

extern void setup_IO_APIC(void);

struct io_apic_irq_attr;
struct irq_cfg;
struct device;
extern int io_apic_set_pci_routing(struct device *dev, int irq,
		 struct io_apic_irq_attr *irq_attr);
void setup_IO_APIC_irq_extra(u32 gsi);

extern int native_setup_ioapic_entry(int, struct IO_APIC_route_entry *,
				     unsigned int, int,
				     struct io_apic_irq_attr *);
extern int native_setup_ioapic_entry(int, struct IO_APIC_route_entry *,
				     unsigned int, int,
				     struct io_apic_irq_attr *);
extern void eoi_ioapic_irq(unsigned int irq, struct irq_cfg *cfg);

struct pci_dev;
struct msi_msg;
extern void native_compose_msi_msg(struct pci_dev *pdev,
				   unsigned int irq, unsigned int dest,
				   struct msi_msg *msg, u8 hpet_id);
extern void native_eoi_ioapic_pin(int apic, int pin, int vector);
int io_apic_setup_irq_pin_once(unsigned int irq, int node, struct io_apic_irq_attr *attr);

extern void mask_ioapic_entries(void);

extern void probe_nr_irqs_gsi(void);
extern int get_nr_irqs_gsi(void);
extern int set_ioapic_affinity_irq(unsigned int, const struct cpumask *);

extern void setup_ioapic_ids_from_mpc_nocheck(void);

struct mp_ioapic_gsi{
	u32 gsi_base;
	u32 gsi_end;
};
extern struct mp_ioapic_gsi  mp_gsi_routing[];
extern u32 gsi_top;
int mp_find_ioapic(u32 gsi);
int mp_find_ioapic_pin(int ioapic, u32 gsi);
void __init mp_register_ioapic(int id, unsigned long address, u32 gsi_base);

extern unsigned int native_io_apic_read(unsigned int apic, unsigned int reg);
extern void native_io_apic_write(unsigned int apic, unsigned int reg, unsigned int val);
extern void native_io_apic_modify(unsigned int apic, unsigned int reg, unsigned int val);
extern void native_io_apic_print_entries(unsigned int apic, unsigned int nr_entries);
struct irq_data;
extern int native_ioapic_set_affinity(struct irq_data *,
				      const struct cpumask *,
				      bool);

static inline unsigned int io_apic_read(unsigned int apic, unsigned int reg)
{
	return native_io_apic_read(apic, reg);
}

static inline void io_apic_write(unsigned int apic, unsigned int reg, unsigned int value)
{
	native_io_apic_write(apic, reg, value);
}
static inline void io_apic_modify(unsigned int apic, unsigned int reg, unsigned int value)
{
	native_io_apic_modify(apic, reg, value);
}

extern void io_apic_eoi(unsigned int apic, unsigned int vector);

extern unsigned int __create_irqs(unsigned int from, unsigned int count,
					int node);
extern void destroy_irqs(unsigned int irq, unsigned int count);
extern int msi_compose_msg(struct pci_dev *pdev, unsigned int irq,
			   struct msi_msg *msg, u8 hpet_id);
extern int ioapic_retrigger_irq(struct irq_data *data);
extern int __ioapic_set_affinity(struct irq_data *data,
				const struct cpumask *mask,
				unsigned int *dest_id);
extern int __add_pin_to_irq_node(struct irq_cfg *cfg, int node, int apic,
				int pin);
extern unsigned int ioapic_cfg_get_pin(struct irq_cfg *cfg);
extern unsigned int ioapic_cfg_get_idx(struct irq_cfg *cfg);

#else  /* !CONFIG_L_IO_APIC */

#define io_apic_assign_pci_irqs 0
#define gsi_top 0
static inline int mp_find_ioapic(u32 gsi) { return 0; }

struct io_apic_irq_attr;
static inline int io_apic_set_pci_routing(struct device *dev, int irq,
		 struct io_apic_irq_attr *irq_attr) { return 0; }

static inline void mask_ioapic_entries(void) { }

#define native_io_apic_read		NULL
#define native_io_apic_write		NULL
#define native_io_apic_modify		NULL
#define native_io_apic_print_entries	NULL
#define native_ioapic_set_affinity	NULL
#define native_setup_ioapic_entry	NULL
#define native_compose_msi_msg		NULL
#define native_eoi_ioapic_pin		NULL
#endif

#endif /* _ASM_L_IO_APIC_H */
