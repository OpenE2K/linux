#ifndef	_ASM_L_IO_EPIC_H
#define	_ASM_L_IO_EPIC_H

#include <linux/types.h>
#include <asm/mpspec.h>
#include <asm/epicdef.h>
#include <asm/irq_vectors.h>

#define	IOEPIC_ID	0x0
#define	IOEPIC_VERSION	0x4
#define	IOEPIC_INT_RID(pin)	(0x800 + 0x4 * pin)
#define	IOEPIC_TABLE_INT_CTRL(pin)	(0x20 + 0x1000 * pin)
#define	IOEPIC_TABLE_MSG_DATA(pin)	(0x24 + 0x1000 * pin)
#define	IOEPIC_TABLE_ADDR_HIGH(pin)	(0x28 + 0x1000 * pin)
#define	IOEPIC_TABLE_ADDR_LOW(pin)	(0x2c + 0x1000 * pin)

#define	MAX_IO_EPICS	(MAX_NUMIOLINKS + MAX_NUMNODES)

#define IOEPIC_AUTO     -1
#define IOEPIC_EDGE     0
#define IOEPIC_LEVEL    1

#define IOEPIC_VERSION_1	1
#define IOEPIC_VERSION_2	2	/* Fast level EOI (without reading int_ctrl) */

extern int nr_ioepics;
extern void setup_io_epic(void);
extern void __init mp_register_ioepic(int ver, int id, int node,
	unsigned long address, u32 gsi_base);
extern int ioepic_pin_to_irq(unsigned int pin, struct pci_dev *dev);

struct mp_ioepic_gsi {
	unsigned int gsi_base;
	unsigned int gsi_end;
};

/*
 * cpumask fields 'domain' and 'old_domain' from APIC irq_cfg are replaced with
 * int dest here. Similar to APIC in physical addressing mode, there is
 * no need for a cpumask, if only one CPU bit is set in it at all times
 */
struct epic_irq_cfg {
	unsigned short pin;
	unsigned short epic;
	unsigned short old_dest;
	unsigned short dest;
	unsigned short vector;
	unsigned char move_in_progress : 1;
#ifdef CONFIG_INTR_REMAP
	struct irq_2_iommu	irq_2_iommu;
#endif
};

#define IO_EPIC_VECTOR(irq) ({ \
	struct epic_irq_cfg *__cfg = irq_get_chip_data(irq); \
	(__cfg) ? __cfg->vector : 0; \
})

struct io_epic_irq_attr {
	int ioepic;
	int ioepic_pin;
	int trigger;
	int rid;
};

struct irq_chip;
extern struct irq_chip ioepic_chip;
extern unsigned long used_vectors[];

extern unsigned long io_epic_base_node(int node);
/* FIXME should be removed after proper passthrough implementation */
extern unsigned int io_epic_read(unsigned int epic, unsigned int reg);
extern void io_epic_write(unsigned int epic, unsigned int reg,
				unsigned int value);
extern int pirq_enable_irq(struct pci_dev *dev);

#endif	/* _ASM_L_IO_EPIC_H */
