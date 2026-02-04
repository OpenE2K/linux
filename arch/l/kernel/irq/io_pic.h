/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_IO_PIC_H
#define __ASM_IO_PIC_H

struct iopic;

struct iopic_chip {
	void (*iopic_get_id_ver_pins)(struct iopic *apic,
			int *id, int *version, int *pins);
	struct irq_chip *iopic_chip;
	int iopic_sizeof_entry;
};

struct iopic {
	/*
	 * # of IRQ routing registers
	 */
	int nr_pins;
	int id;
	int version;
	int node;
	/*
	 * Saved state during suspend/resume, or while enabling intr-remap.
	 */
	void *saved_registers;
	struct device_node **of_nodes;

	struct irq_domain *irqdomain;
	struct resource *iomem_res;
	void __iomem *regs;
	raw_spinlock_t lock;
	struct iopic_chip *iopic_chip;
};

struct iopic_chip_data {
	struct iopic *pic;
	int pin;
	unsigned passthrough : 1;
};

extern struct iopic_chip iopic_ioapic_chip;
extern struct iopic_chip iopic_ioepic_chip;


unsigned io_pic_read_by_id(unsigned id, unsigned reg);
void io_pic_write_by_id(unsigned id, unsigned reg, unsigned value);
unsigned long io_pic_base_by_id(int id);

#endif /* __ASM_IO_PIC_H */
