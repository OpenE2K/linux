/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * IO-APIC support.
 */

#include <linux/mm.h>
#include <asm/acpi.h>
#include <linux/acpi.h>
#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/mc146818rtc.h>
#include <linux/compiler.h>
#include <linux/export.h>
#include <linux/syscore_ops.h>
#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>	/* time_after() */
#include <linux/slab.h>

#include <asm/io_apic.h>
#include <asm/io_epic.h>
#include <asm/epic.h>
#include <asm-l/idle.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/dma.h>
#include <asm/timer.h>
#include <asm/setup.h>
#include <asm/hw_irq.h>

#include <asm/gpio.h>
#include <asm-l/iolinkmask.h>

#include <asm-l/msidef.h>
#include <asm-l/sic_regs.h>
#include <asm-l/pic.h>

#ifdef CONFIG_E2K
#include <asm/nmi.h>
#endif

#ifdef CONFIG_E90S
#include <linux/irq.h>
# define acpi_ioapic 0
#endif

/* Number of additional (chained) interrupts */
#define I2C_SPI_IRQS_NUM	2

#define __apicdebuginit(type) static type

#define for_each_irq_pin(entry, head) \
	for (entry = head; entry; entry = entry->next)

static DEFINE_RAW_SPINLOCK(ioapic_lock);
static DEFINE_RAW_SPINLOCK(vector_lock);

DECLARE_BITMAP(used_vectors, NR_VECTORS);

static struct ioapic {
	/*
	 * # of IRQ routing registers
	 */
	int nr_registers;
	/*
	 * Saved state during suspend/resume, or while enabling intr-remap.
	 */
	struct IO_APIC_route_entry *saved_registers;
	/* I/O APIC config */
	struct mpc_ioapic mp_config;
	/* IO APIC gsi routing info */
	struct mp_ioapic_gsi  gsi_config;
	DECLARE_BITMAP(pin_programmed, MP_MAX_IOAPIC_PIN + 1);
} ioapics[MAX_IO_APICS];

#define mpc_ioapic_ver(ioapic_idx)	ioapics[ioapic_idx].mp_config.apicver

int mpc_ioapic_id(int ioapic_idx)
{
	return ioapics[ioapic_idx].mp_config.apicid;
}

unsigned long mpc_ioapic_addr(int ioapic_idx)
{
	return ioapics[ioapic_idx].mp_config.apicaddr;
}

struct mp_ioapic_gsi *mp_ioapic_gsi_routing(int ioapic_idx)
{
	return &ioapics[ioapic_idx].gsi_config;
}

int nr_ioapics;

/* The one past the highest gsi number used */
u32 gsi_top;

/* MP IRQ source entries */
struct mpc_intsrc mp_irqs[MAX_IRQ_SOURCES];

/* # of MP IRQ source entries */
int mp_irq_entries;

/* GSI interrupts */
static int nr_irqs_gsi = 0;

DECLARE_BITMAP(mp_bus_not_pci, MAX_MP_BUSSES);

#ifdef CONFIG_E2K
int e2k_msi_disabled = 0;
#endif

struct irq_pin_list {
	int apic, pin;
	struct irq_pin_list *next;
};

static struct irq_pin_list *alloc_irq_pin_list(int node)
{
	return kzalloc_node(sizeof(struct irq_pin_list), GFP_KERNEL, node);
}


int __init arch_early_irq_init(void)
{
	int i;

	for (i = 0; i < nr_ioapics; i++) {
		ioapics[i].saved_registers =
			kzalloc(sizeof(struct IO_APIC_route_entry) *
				ioapics[i].nr_registers, GFP_KERNEL);
		if (!ioapics[i].saved_registers)
			pr_err("IOAPIC %d: suspend/resume impossible!\n", i);
	}

	return 0;
}

static struct irq_cfg *irq_cfg(unsigned int irq)
{
	return irq_get_chip_data(irq);
}

static struct irq_cfg *alloc_irq_cfg(unsigned int irq, int node)
{
	struct irq_cfg *cfg;

	cfg = kzalloc_node(sizeof(*cfg), GFP_KERNEL, node);
	if (!cfg)
		return NULL;
	if (!zalloc_cpumask_var_node(&cfg->domain, GFP_KERNEL, node))
		goto out_cfg;
	if (!zalloc_cpumask_var_node(&cfg->old_domain, GFP_KERNEL, node))
		goto out_domain;
	return cfg;
out_domain:
	free_cpumask_var(cfg->domain);
out_cfg:
	kfree(cfg);
	return NULL;
}

static void free_irq_cfg(unsigned int at, struct irq_cfg *cfg)
{
	if (!cfg)
		return;
	irq_set_chip_data(at, NULL);
	free_cpumask_var(cfg->domain);
	free_cpumask_var(cfg->old_domain);
	kfree(cfg);
}

static struct irq_cfg *alloc_irq_and_cfg_at(unsigned int at, int node)
{
	int res = irq_alloc_desc_at(at, node);
	struct irq_cfg *cfg;

	if (res < 0) {
		if (res != -EEXIST)
			return NULL;
		cfg = irq_get_chip_data(at);
		if (cfg)
			return cfg;
	}

	cfg = alloc_irq_cfg(at, node);
	if (cfg)
		irq_set_chip_data(at, cfg);
	else
		irq_free_desc(at);
	return cfg;
}

static int alloc_irqs_from(unsigned int from, unsigned int count, int node)
{
	return irq_alloc_descs_from(from, count, node);
}

static void free_irq_at(unsigned int at, struct irq_cfg *cfg)
{
	free_irq_cfg(at, cfg);
	irq_free_desc(at);
}


struct io_apic {
	unsigned int index;
	unsigned int unused[3];
	unsigned int data;
	unsigned int unused2[11];
	unsigned int eoi;
};

static __attribute_const__ struct io_apic __iomem *io_apic_base(int idx)
{
	return (struct io_apic __iomem *) mpc_ioapic_addr(idx);
}

/* HACK! In arch/l we do not map this area anywhere, so we
 * have to access them directly by their physical address,
 * to do that we redefine writel/readl. */
#ifdef CONFIG_E2K
#define my_writel	boot_writel
#define my_readl	boot_readl
#elif defined CONFIG_E90S
#define my_writel	writel
#define my_readl	readl
#else
# error Unsupported architecture!
#endif

void io_apic_eoi(unsigned int apic, unsigned int vector)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);
	my_writel(vector, &io_apic->eoi);
}

unsigned int native_io_apic_read(unsigned int apic, unsigned int reg)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);
	my_writel(reg, &io_apic->index);
	return my_readl(&io_apic->data);
}

void native_io_apic_write(unsigned int apic, unsigned int reg, unsigned int value)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);

	my_writel(reg, &io_apic->index);
	my_writel(value, &io_apic->data);
}

/*
 * Re-write a value: to be used for read-modify-write
 * cycles where the read already set up the index register.
 *
 * Older SiS APIC requires we rewrite the index register
 */
void native_io_apic_modify(unsigned int apic, unsigned int reg, unsigned int value)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);

	my_writel(value, &io_apic->data);
}


union entry_union {
	struct { u32 w1, w2; };
	struct IO_APIC_route_entry entry;
};

static struct IO_APIC_route_entry __ioapic_read_entry(int apic, int pin)
{
	union entry_union eu;

	eu.w1 = io_apic_read(apic, 0x10 + 2 * pin);
	eu.w2 = io_apic_read(apic, 0x11 + 2 * pin);

	return eu.entry;
}

static struct IO_APIC_route_entry ioapic_read_entry(int apic, int pin)
{
	union entry_union eu;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	eu.entry = __ioapic_read_entry(apic, pin);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);

	return eu.entry;
}

/*
 * When we write a new IO APIC routing entry, we need to write the high
 * word first! If the mask bit in the low word is clear, we will enable
 * the interrupt, and we need to make sure the entry is fully populated
 * before that happens.
 */
static void __ioapic_write_entry(int apic, int pin, struct IO_APIC_route_entry e)
{
	union entry_union eu = {{0, 0}};

	eu.entry = e;
	io_apic_write(apic, 0x11 + 2*pin, eu.w2);
	io_apic_write(apic, 0x10 + 2*pin, eu.w1);
}

static void ioapic_write_entry(int apic, int pin, struct IO_APIC_route_entry e)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	__ioapic_write_entry(apic, pin, e);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
}

/*
 * When we mask an IO APIC routing entry, we need to write the low
 * word first, in order to set the mask bit before we change the
 * high bits!
 */
static void ioapic_mask_entry(int apic, int pin)
{
	unsigned long flags;
	union entry_union eu = { .entry.mask = 1 };

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	io_apic_write(apic, 0x10 + 2*pin, eu.w1);
	io_apic_write(apic, 0x11 + 2*pin, eu.w2);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
}

/*
 * The common case is 1:1 IRQ<->pin mappings. Sometimes there are
 * shared ISA-space IRQs, so we have to support them. We are super
 * fast in the common case, and fast for shared ISA-space IRQs.
 */
int __add_pin_to_irq_node(struct irq_cfg *cfg, int node, int apic, int pin)
{
	struct irq_pin_list **last, *entry;

	/* don't allow duplicates */
	last = &cfg->irq_2_pin;
	for_each_irq_pin(entry, cfg->irq_2_pin) {
		if (entry->apic == apic && entry->pin == pin)
			return 0;
		last = &entry->next;
	}

	entry = alloc_irq_pin_list(node);
	if (!entry) {
		pr_err("can not alloc irq_pin_list (%d,%d,%d)\n",
		       node, apic, pin);
		return -ENOMEM;
	}
	entry->apic = apic;
	entry->pin = pin;

	*last = entry;
	return 0;
}

static void __io_apic_modify_irq(struct irq_pin_list *entry,
				 int mask_and, int mask_or,
				 void (*final)(struct irq_pin_list *entry))
{
	unsigned int reg, pin;

	pin = entry->pin;
	reg = io_apic_read(entry->apic, 0x10 + pin * 2);
	reg &= mask_and;
	reg |= mask_or;
	io_apic_modify(entry->apic, 0x10 + pin * 2, reg);
	if (final)
		final(entry);
}

static void io_apic_modify_irq(struct irq_cfg *cfg,
			       int mask_and, int mask_or,
			       void (*final)(struct irq_pin_list *entry))
{
	struct irq_pin_list *entry;

	for_each_irq_pin(entry, cfg->irq_2_pin)
		__io_apic_modify_irq(entry, mask_and, mask_or, final);
}

static void io_apic_sync(struct irq_pin_list *entry)
{
	/*
	 * Synchronize the IO-APIC and the CPU by doing
	 * a dummy read from the IO-APIC
	 */
	struct io_apic __iomem *io_apic;

	io_apic = io_apic_base(entry->apic);
	my_readl(&io_apic->data);
}

static void mask_ioapic(struct irq_cfg *cfg)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	io_apic_modify_irq(cfg, ~0, IO_APIC_REDIR_MASKED, &io_apic_sync);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void mask_ioapic_irq(struct irq_data *data)
{
	mask_ioapic(data->chip_data);
}

static void __unmask_ioapic(struct irq_cfg *cfg)
{
	io_apic_modify_irq(cfg, ~IO_APIC_REDIR_MASKED, 0, NULL);
}

static void unmask_ioapic(struct irq_cfg *cfg)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	__unmask_ioapic(cfg);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void unmask_ioapic_irq(struct irq_data *data)
{
	unmask_ioapic(data->chip_data);
}

/*
 * IO-APIC versions below 0x20 don't support EOI register.
 * For the record, here is the information about various versions:
 *     0Xh     82489DX
 *     1Xh     I/OAPIC or I/O(x)APIC which are not PCI 2.2 Compliant
 *     2Xh     I/O(x)APIC which is PCI 2.2 Compliant
 *     30h-FFh Reserved
 *
 * Some of the Intel ICH Specs (ICH2 to ICH5) documents the io-apic
 * version as 0x2. This is an error with documentation and these ICH chips
 * use io-apic's of version 0x20.
 *
 * For IO-APIC's with EOI register, we use that to do an explicit EOI.
 * Otherwise, we simulate the EOI message manually by changing the trigger
 * mode to edge and then back to level, with RTE being masked during this.
 */
void native_eoi_ioapic_pin(int apic, int pin, int vector)
{
	if (mpc_ioapic_ver(apic) >= 0x20) {
		io_apic_eoi(apic, vector);
	} else {
		struct IO_APIC_route_entry entry, entry1;

		entry = entry1 = __ioapic_read_entry(apic, pin);

		/*
		 * Mask the entry and change the trigger mode to edge.
		 */
		entry1.mask = 1;
		entry1.trigger = IOAPIC_EDGE;

		__ioapic_write_entry(apic, pin, entry1);

		/*
		 * Restore the previous level triggered entry.
		 */
		__ioapic_write_entry(apic, pin, entry);
	}
}

void eoi_ioapic_irq(unsigned int irq, struct irq_cfg *cfg)
{
	struct irq_pin_list *entry;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	for_each_irq_pin(entry, cfg->irq_2_pin)
		native_eoi_ioapic_pin(entry->apic, entry->pin, cfg->vector);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void clear_IO_APIC_pin(unsigned int apic, unsigned int pin)
{
	struct IO_APIC_route_entry entry;

	/* Check delivery_mode to be sure we're not clearing an SMI pin */
	entry = ioapic_read_entry(apic, pin);
	if (entry.delivery_mode == dest_SMI)
		return;

	/*
	 * Make sure the entry is masked and re-read the contents to check
	 * if it is a level triggered pin and if the remote-IRR is set.
	 */
	if (!entry.mask) {
		entry.mask = 1;
		ioapic_write_entry(apic, pin, entry);
		entry = ioapic_read_entry(apic, pin);
	}

	if (entry.irr) {
		unsigned long flags;

		/*
		 * Make sure the trigger mode is set to level. Explicit EOI
		 * doesn't clear the remote-IRR if the trigger mode is not
		 * set to level.
		 */
		if (!entry.trigger) {
			entry.trigger = IOAPIC_LEVEL;
			ioapic_write_entry(apic, pin, entry);
		}

		raw_spin_lock_irqsave(&ioapic_lock, flags);
		native_eoi_ioapic_pin(apic, pin, entry.vector);
		raw_spin_unlock_irqrestore(&ioapic_lock, flags);
	}

	/*
	 * Clear the rest of the bits in the IO-APIC RTE except for the mask
	 * bit.
	 */
	ioapic_mask_entry(apic, pin);
	entry = ioapic_read_entry(apic, pin);
	if (entry.irr)
		pr_err("Unable to reset IRR for apic: %d, pin :%d\n",
		       mpc_ioapic_id(apic), pin);
}

static void clear_IO_APIC (void)
{
	int apic, pin;

	for (apic = 0; apic < nr_ioapics; apic++)
		for (pin = 0; pin < ioapics[apic].nr_registers; pin++)
			clear_IO_APIC_pin(apic, pin);
}

/*
 * Saves all the IO-APIC RTE's
 */
static int save_ioapic_entries(void)
{
	int apic, pin;
	int err = 0;

	for (apic = 0; apic < nr_ioapics; apic++) {
		if (!ioapics[apic].saved_registers) {
			err = -ENOMEM;
			continue;
		}

		for (pin = 0; pin < ioapics[apic].nr_registers; pin++)
			ioapics[apic].saved_registers[pin] =
				ioapic_read_entry(apic, pin);
	}

	return err;
}

/*
 * Mask all IO APIC entries.
 */
void mask_ioapic_entries(void)
{
	int apic, pin;

	for (apic = 0; apic < nr_ioapics; apic++) {
		if (!ioapics[apic].saved_registers)
			continue;

		for (pin = 0; pin < ioapics[apic].nr_registers; pin++) {
			struct IO_APIC_route_entry entry;

			entry = ioapics[apic].saved_registers[pin];
			if (!entry.mask) {
				entry.mask = 1;
				ioapic_write_entry(apic, pin, entry);
			}
		}
	}
}

/*
 * Restore IO APIC entries which was saved in the ioapic structure.
 */
static int restore_ioapic_entries(void)
{
	int apic, pin;

	for (apic = 0; apic < nr_ioapics; apic++) {
		if (!ioapics[apic].saved_registers)
			continue;

		for (pin = 0; pin < ioapics[apic].nr_registers; pin++)
			ioapic_write_entry(apic, pin,
					   ioapics[apic].saved_registers[pin]);
	}
	return 0;
}

/*
 * Find the IRQ entry number of a certain pin.
 */
static int find_irq_entry(int ioapic_idx, int pin, int type)
{
	int i;

	for (i = 0; i < mp_irq_entries; i++)
		if (mp_irqs[i].irqtype == type &&
		    (mp_irqs[i].dstapic == mpc_ioapic_id(ioapic_idx) ||
		     mp_irqs[i].dstapic == MP_APIC_ALL) &&
		    mp_irqs[i].dstirq == pin)
			return i;

	return -1;
}

/* ISA interrupts are always polarity zero edge triggered,
 * when listed as conforming in the MP table. */

#define default_ISA_trigger(idx)	(0)
#define default_ISA_polarity(idx)	(0)

/* PCI interrupts are always polarity one level triggered,
 * when listed as conforming in the MP table. */

#define default_PCI_trigger(idx)	(1)
#define default_PCI_polarity(idx)	(1)

static int irq_polarity(int idx)
{
	int bus = mp_irqs[idx].srcbus;
	int polarity;

	/*
	 * Determine IRQ line polarity (high active or low active):
	 */
	switch (mp_irqs[idx].irqflag & 3)
	{
		case 0: /* conforms, ie. bus-type dependent polarity */
			if (test_bit(bus, mp_bus_not_pci))
				polarity = default_ISA_polarity(idx);
			else
				polarity = default_PCI_polarity(idx);
			break;
		case 1: /* high active */
		{
			polarity = 0;
			break;
		}
		case 2: /* reserved */
		{
			pr_warn("broken BIOS!!\n");
			polarity = 1;
			break;
		}
		case 3: /* low active */
		{
			polarity = 1;
			break;
		}
		default: /* invalid */
		{
			pr_warn("broken BIOS!!\n");
			polarity = 1;
			break;
		}
	}
	return polarity;
}

static int irq_trigger(int idx)
{
	int bus = mp_irqs[idx].srcbus;
	int trigger;

	/*
	 * Determine IRQ trigger mode (edge or level sensitive):
	 */
	switch ((mp_irqs[idx].irqflag>>2) & 3)
	{
		case 0: /* conforms, ie. bus-type dependent */
			if (test_bit(bus, mp_bus_not_pci))
				trigger = default_ISA_trigger(idx);
			else
				trigger = default_PCI_trigger(idx);
			break;
		case 1: /* edge */
		{
			trigger = 0;
			break;
		}
		case 2: /* reserved */
		{
			pr_warn("broken BIOS!!\n");
			trigger = 1;
			break;
		}
		case 3: /* level */
		{
			trigger = 1;
			break;
		}
		default: /* invalid */
		{
			pr_warn("broken BIOS!!\n");
			trigger = 0;
			break;
		}
	}
	return trigger;
}

static int pin_2_irq(int idx, int apic, int pin)
{
	int irq;
	int bus = mp_irqs[idx].srcbus;
	struct mp_ioapic_gsi *gsi_cfg = mp_ioapic_gsi_routing(apic);

	/*
	 * Debugging check, we are in big trouble if this message pops up!
	 */
	if (mp_irqs[idx].dstirq != pin)
		pr_err("broken BIOS or MPTABLE parser, ayiee!!\n");

	/* ISA device interrupts are allowed only for the IO-APIC
	 * on BSP. if boot passes such interrupts for other IO-APICs
	 * then their IRQ numbers are calculated as for PCI devices.
	 * For example, system timer interrupt number is 26 on
	 * the second IO APIC but it is masked. */
	if (test_bit(bus, mp_bus_not_pci) && apic == 0 && !cpu_has_epic()) {
		irq = mp_irqs[idx].srcbusirq;
	} else {
		irq = gsi_cfg->gsi_base + pin;
	}

	return irq;
}

/*
 * Find a specific PCI IRQ entry.
 * Not an __init, possibly needed by modules
 */
int IO_APIC_get_PCI_irq_vector(int domain, int bus, int slot, int pin,
				struct io_apic_irq_attr *irq_attr)
{
	int ioapic_idx, i, best_guess = -1;

	apic_printk(APIC_DEBUG,
		    "querying PCI -> IRQ mapping bus:%d, slot:%d, pin:%d.\n",
		    bus, slot, pin);
	if (test_bit(bus, mp_bus_not_pci)) {
		apic_printk(APIC_VERBOSE,
			    "PCI BIOS passed nonexistent PCI bus %d!\n", bus);
		return -1;
	}

	for (i = 0; i < mp_irq_entries; i++) {
		int lbus = mp_irqs[i].srcbus, found = 0;

		apic_printk(APIC_DEBUG,
			"MP entry #%d src bus #%d PCI = %d dst APIC id %d "
			"irq type %d src bus irq %d dst bus irq %d\n",
			i, lbus, test_bit(lbus, mp_bus_not_pci), 
			mp_irqs[i].dstapic, mp_irqs[i].irqtype,
			mp_irqs[i].srcbusirq, mp_irqs[i].dstirq);
		for (ioapic_idx = 0; ioapic_idx < nr_ioapics; ioapic_idx++)
			if (mpc_ioapic_id(ioapic_idx) == mp_irqs[i].dstapic ||
			    mp_irqs[i].dstapic == MP_APIC_ALL) {
				found = 1;
				break;
		}
		if (!found)
			continue;

		if (!test_bit(lbus, mp_bus_not_pci) &&
		    !mp_irqs[i].irqtype &&
		    (bus == lbus) &&
		    (slot == ((mp_irqs[i].srcbusirq >> 2) & 0x1f))) {
			int irq = pin_2_irq(i, ioapic_idx, mp_irqs[i].dstirq);

			apic_printk(APIC_DEBUG, "Found our bus & pin -> IRQ %d\n", irq);

			if (pin == (mp_irqs[i].srcbusirq & 3)) {
				set_io_apic_irq_attr(irq_attr, ioapic_idx,
						     mp_irqs[i].dstirq,
						     irq_trigger(i),
						     irq_polarity(i));
				apic_printk(APIC_DEBUG, "pin %d == src bus irg %d, return IRQ %d\n",
						pin, (mp_irqs[i].srcbusirq & 3),
						irq);
				return irq;
			}
			/*
			 * Use the first all-but-pin matching entry as a
			 * best-guess fuzzy result for broken mptables.
			 */
			if (best_guess < 0) {
				set_io_apic_irq_attr(irq_attr, ioapic_idx,
						     mp_irqs[i].dstirq,
						     irq_trigger(i),
						     irq_polarity(i));
				apic_printk(APIC_DEBUG, "Use the first all-but-pin matching entry as a best-guess fuzzy result IRQ %d\n",
						irq);
				best_guess = irq;
			}
		}
	}
	apic_printk(APIC_DEBUG, "IO_APIC_get_PCI_irq_vector() Return IRQ %d\n",
			best_guess);
	return best_guess;
}
EXPORT_SYMBOL(IO_APIC_get_PCI_irq_vector);

int IO_APIC_get_fix_irq_vector(int domain, int bus, int slot, int func, int irq)
{
	int i;

	apic_printk(APIC_DEBUG, "IO_APIC_get_fix_irq_vector() domain:%d, "
		"bus:%d, irq:%d\n",
		domain, bus, irq);

	for (i = 0; i < mp_irq_entries; i++) {
		int lbus = mp_irqs[i].srcbus, found = 0, ioapic_idx;

		apic_printk(APIC_DEBUG, "MP entry #%d src bus #%d PCI = %d "
			"dst APIC id %d irq type %d src bus irq %d dst bus "
			"irq %d\n",
			i, lbus, test_bit(lbus, mp_bus_not_pci), 
			mp_irqs[i].dstapic, mp_irqs[i].irqtype,
			mp_irqs[i].srcbusirq, mp_irqs[i].dstirq);

		for (ioapic_idx = 0; ioapic_idx < nr_ioapics; ioapic_idx++)
			if (mpc_ioapic_id(ioapic_idx) == mp_irqs[i].dstapic ||
			    mp_irqs[i].dstapic == MP_APIC_ALL) {
				apic_printk(APIC_DEBUG,
					"IO APIC id %d found as #%d\n",
						mp_irqs[i].dstapic, ioapic_idx);
				found = 1;
				break;
		}
		if (!found)
			continue;

		if (!test_bit(lbus, mp_bus_not_pci) &&
				mp_irqs[i].irqtype == mp_FixINT &&
				bus == lbus &&
				PCI_SLOT(mp_irqs[i].srcbusirq) == slot &&
				PCI_FUNC(mp_irqs[i].srcbusirq) == func &&
				((irq == mp_irqs[i].dstirq) || irq == 0)) {
			irq = pin_2_irq(i, ioapic_idx, mp_irqs[i].dstirq);
			apic_printk(APIC_DEBUG, "Found our bus %d slot %d func %d IRQ %d\n",
				    lbus, slot, func, irq);
			return (irq);
		} else if (((test_bit(lbus, mp_bus_not_pci) &&
			     test_bit(bus, mp_bus_not_pci) &&
			     mp_irqs[i].irqtype == mp_FixINT) ||
			    (test_bit(lbus, mp_bus_not_pci) &&
			     mp_irqs[i].irqtype == mp_INT &&
			     irq != 0)) &&
			    irq == mp_irqs[i].srcbusirq) {
			irq = pin_2_irq(i, ioapic_idx, mp_irqs[i].dstirq);
			apic_printk(APIC_DEBUG, "Found our bus %d, src IRQ %d -> dst IRQ %d\n",
				    lbus, mp_irqs[i].srcbusirq, irq);
			return (irq);
		}
	}
	apic_printk(APIC_DEBUG, "IO_APIC_get_fix_irq_vector() could not "
		"find IRQ\n");
	return (-1);
}
EXPORT_SYMBOL(IO_APIC_get_fix_irq_vector);

void lock_vector_lock(void)
{
	/* Used to the online set of cpus does not change
	 * during assign_irq_vector.
	 */
	raw_spin_lock(&vector_lock);
}

void unlock_vector_lock(void)
{
	raw_spin_unlock(&vector_lock);
}

static int
__assign_irq_vector(int irq, struct irq_cfg *cfg, const struct cpumask *mask)
{
	/*
	 * NOTE! The local APIC isn't very good at handling
	 * multiple interrupts at the same interrupt level.
	 * As the interrupt level is determined by taking the
	 * vector number and shifting that right by 4, we
	 * want to spread these out a bit so that they don't
	 * all fall in the same interrupt level.
	 *
	 * Also, we've got to be careful not to trash gate
	 * 0x80, because int 0x80 is hm, kind of importantish. ;)
	 */
	static int current_vector = FIRST_EXTERNAL_VECTOR + VECTOR_OFFSET_START;
	static int current_offset = VECTOR_OFFSET_START % 16;
	int cpu, err;
	cpumask_var_t tmp_mask;

	if (cfg->move_in_progress)
		return -EBUSY;

	if (!alloc_cpumask_var(&tmp_mask, GFP_ATOMIC))
		return -ENOMEM;

	/* Only try and allocate irqs on cpus that are present */
	err = -ENOSPC;
	cpumask_clear(cfg->old_domain);
	cpu = cpumask_first_and(mask, cpu_online_mask);
	while (cpu < nr_cpu_ids) {
		int new_cpu, vector, offset;

		apic->vector_allocation_domain(cpu, tmp_mask, mask);

		if (cpumask_subset(tmp_mask, cfg->domain)) {
			err = 0;
			if (cpumask_equal(tmp_mask, cfg->domain))
				break;
			/*
			 * New cpumask using the vector is a proper subset of
			 * the current in use mask. So cleanup the vector
			 * allocation for the members that are not used anymore.
			 */
			cpumask_andnot(cfg->old_domain, cfg->domain, tmp_mask);
			cfg->move_in_progress =
			   cpumask_intersects(cfg->old_domain, cpu_online_mask);
			cpumask_and(cfg->domain, cfg->domain, tmp_mask);
			if (cfg->move_in_progress) {
				apic_printk(APIC_DEBUG, KERN_DEBUG "Moving vector %d: reduced CPU set\n",
						cfg->vector);
			}

			break;
		}

		vector = current_vector;
		offset = current_offset;
next:
		vector += 16;
		if (vector >= first_system_vector ||
				vector >= NR_VECTORS_APIC) {
			offset = (offset + 1) % 16;
			vector = FIRST_EXTERNAL_VECTOR + offset;
		}

		if (unlikely(current_vector == vector)) {
			cpumask_or(cfg->old_domain, cfg->old_domain, tmp_mask);
			cpumask_andnot(tmp_mask, mask, cfg->old_domain);
			cpu = cpumask_first_and(tmp_mask, cpu_online_mask);
			continue;
		}

		/*
		 * Bug in IOH and IOH2. Can't use (vector & 4) == 1.
		 * Bug fixed in IOH2 rev5.
		 */
#ifdef CONFIG_E90S
		/* FIXME: it's too early to check iohub generation. */
		if (e90s_get_cpu_type() == E90S_CPU_R1000)
#endif
		if (vector & 4) {
			goto next;
		}
		if (test_bit(vector, used_vectors))
			goto next;

		for_each_cpu_and(new_cpu, tmp_mask, cpu_online_mask) {
			if (per_cpu(vector_irq, new_cpu)[vector] > VECTOR_UNDEFINED)
				goto next;
		}
		/* Found one! */
		current_vector = vector;
		current_offset = offset;
		if (cfg->vector) {
			cpumask_copy(cfg->old_domain, cfg->domain);
			cfg->move_in_progress =
			   cpumask_intersects(cfg->old_domain, cpu_online_mask);
			if (cfg->move_in_progress) {
				apic_printk(APIC_DEBUG, KERN_DEBUG "Started moving vector %d to vector %d\n",
						cfg->vector, vector);
			}
		}
		for_each_cpu_and(new_cpu, tmp_mask, cpu_online_mask)
			per_cpu(vector_irq, new_cpu)[vector] = irq;
		cfg->vector = vector;
		cpumask_copy(cfg->domain, tmp_mask);
		err = 0;
		break;
	}
	free_cpumask_var(tmp_mask);
	return err;
}

int assign_irq_vector(int irq, struct irq_cfg *cfg, const struct cpumask *mask)
{
	int err;
	unsigned long flags;

	raw_spin_lock_irqsave(&vector_lock, flags);
	err = __assign_irq_vector(irq, cfg, mask);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	return err;
}

static void __clear_irq_vector(int irq, struct irq_cfg *cfg)
{
	int cpu, vector;

	BUG_ON(!cfg->vector);

	vector = cfg->vector;
	for_each_cpu_and(cpu, cfg->domain, cpu_online_mask)
		per_cpu(vector_irq, cpu)[vector] = VECTOR_UNDEFINED;

	cfg->vector = 0;
	cpumask_clear(cfg->domain);

	if (likely(!cfg->move_in_progress))
		return;
	for_each_cpu_and(cpu, cfg->old_domain, cpu_online_mask) {
		for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
			if (per_cpu(vector_irq, cpu)[vector] != irq)
				continue;
			per_cpu(vector_irq, cpu)[vector] = VECTOR_UNDEFINED;
			break;
		}
	}
	cfg->move_in_progress = 0;
}

static bool irqchip_is_ioapic(struct irq_chip *chip);

void __apic_setup_vector_irq(int cpu)
{
	/* Initialize vector_irq on a new cpu */
	int irq, vector;
	struct irq_cfg *cfg;

	/*
	 * vector_lock will make sure that we don't run into irq vector
	 * assignments that might be happening on another cpu in parallel,
	 * while we setup our initial vector to irq mappings.
	 */
	raw_spin_lock(&vector_lock);
	/* Mark the inuse vectors */
	for_each_active_irq(irq) {
		if (!irqchip_is_ioapic(irq_get_chip(irq)))
			continue;

		cfg = irq_get_chip_data(irq);
		if (!cfg)
			continue;

		if (!cpumask_test_cpu(cpu, cfg->domain))
			continue;
		vector = cfg->vector;
		per_cpu(vector_irq, cpu)[vector] = irq;
	}
	/* Mark the free vectors */
	for (vector = 0; vector < NR_VECTORS; ++vector) {
		irq = per_cpu(vector_irq, cpu)[vector];
		if (irq <= VECTOR_UNDEFINED)
			continue;

		if (!irqchip_is_ioapic(irq_get_chip(irq)))
			continue;

		cfg = irq_cfg(irq);
		if (!cpumask_test_cpu(cpu, cfg->domain))
			per_cpu(vector_irq, cpu)[vector] = VECTOR_UNDEFINED;
	}
	raw_spin_unlock(&vector_lock);
}

static struct irq_chip ioapic_chip;

static void ioapic_register_intr(unsigned int irq, struct irq_cfg *cfg,
				 unsigned long trigger)
{
	struct irq_chip *chip = &ioapic_chip;
	irq_flow_handler_t hdl;
	bool fasteoi;

	if (trigger == IOAPIC_AUTO || trigger == IOAPIC_LEVEL) {
		irq_set_status_flags(irq, IRQ_LEVEL);
		fasteoi = true;
	} else {
		irq_clear_status_flags(irq, IRQ_LEVEL);
		fasteoi = false;
	}

	hdl = fasteoi ? handle_fasteoi_irq : handle_edge_irq;
	irq_set_chip_and_handler_name(irq, chip, hdl,
				      fasteoi ? "fasteoi" : "edge");
}

int native_setup_ioapic_entry(int irq, struct IO_APIC_route_entry *entry,
			      unsigned int destination, int vector,
			      struct io_apic_irq_attr *attr)
{
	memset(entry, 0, sizeof(*entry));

	entry->delivery_mode = apic->irq_delivery_mode;
	entry->dest_mode     = apic->irq_dest_mode;
	entry->dest	     = destination;
	entry->vector	     = vector;
	entry->mask	     = 0;			/* enable IRQ */
	entry->trigger	     = attr->trigger;
	entry->polarity	     = attr->polarity;

	/*
	 * Mask level triggered irqs.
	 * Use IRQ_DELAYED_DISABLE for edge triggered irqs.
	 */
	if (attr->trigger)
		entry->mask = 1;

	return 0;
}

static int setup_ioapic_irq(unsigned int irq, struct irq_cfg *cfg,
				struct io_apic_irq_attr *attr)
{
	struct IO_APIC_route_entry entry;
	unsigned int dest;
	int ret;

	if ((ret = assign_irq_vector(irq, cfg, apic->target_cpus())))
		return ret;

	if (apic->cpu_mask_to_apicid_and(cfg->domain, apic->target_cpus(),
					 &dest)) {
		pr_warn("Failed to obtain apicid for ioapic %d, pin %d\n",
			mpc_ioapic_id(attr->ioapic), attr->ioapic_pin);
		__clear_irq_vector(irq, cfg);

		return -EINVAL;
	}

	apic_printk(APIC_VERBOSE,KERN_DEBUG
		    "IOAPIC[%d]: Set routing entry (%d-%d -> 0x%x -> "
		    "IRQ %d Mode:%i Active:%i Dest:%d)\n",
		    attr->ioapic, mpc_ioapic_id(attr->ioapic), attr->ioapic_pin,
		    cfg->vector, irq, attr->trigger, attr->polarity, dest);

	if (native_setup_ioapic_entry(irq, &entry, dest, cfg->vector, attr)) {
		pr_warn("Failed to setup ioapic entry for ioapic  %d, pin %d\n",
			mpc_ioapic_id(attr->ioapic), attr->ioapic_pin);
		__clear_irq_vector(irq, cfg);

		return -EINVAL;
	}

	ioapic_register_intr(irq, cfg, attr->trigger);

	ioapic_write_entry(attr->ioapic, attr->ioapic_pin, entry);

	return ret;
}

static bool __init_recv io_apic_pin_not_connected(int idx, int ioapic_idx,
									int pin)
{
	if (idx != -1)
		return false;

	apic_printk(APIC_VERBOSE, KERN_DEBUG " apic %d pin %d not connected\n",
		    mpc_ioapic_id(ioapic_idx), pin);
	return true;
}

static int
io_apic_setup_irq_pin(unsigned int irq, int node, struct io_apic_irq_attr *attr)
{
	struct irq_cfg *cfg = alloc_irq_and_cfg_at(irq, node);
	int ret;

	if (!cfg)
		return -EINVAL;
	ret = __add_pin_to_irq_node(cfg, node, attr->ioapic, attr->ioapic_pin);
	if (!ret)
		return setup_ioapic_irq(irq, cfg, attr);
	return ret;
}

static void __init __io_apic_setup_irqs(unsigned int ioapic_idx)
{
	int idx, node = cpu_to_node(0);
	struct io_apic_irq_attr attr;
	unsigned int pin, irq, ret;

	for (pin = 0; pin < ioapics[ioapic_idx].nr_registers; pin++) {
		idx = find_irq_entry(ioapic_idx, pin, mp_INT);
		if (idx == -1) {
			idx = find_irq_entry(ioapic_idx, pin, mp_FixINT);

#if defined(CONFIG_ACPI_L_SPMC) || defined(CONFIG_ACPI_L_SPMC_MODULE)
			if (idx == -1) {
				/* Boot should provide this data for P8 */
				if ( pin == 1 ) {
					/* Then according to doc:
					 *  irq = 1;
					 *  trigger = 1;
					 *  polarity = 0;
					 */
					irq = 1;

					set_io_apic_irq_attr(
						&attr, ioapic_idx, pin, 1, 0);

					io_apic_setup_irq_pin(irq, node, &attr);

					continue;
				}
			}
#endif /* CONFIG_ACPI_L_SPMC */
		}
		if (io_apic_pin_not_connected(idx, ioapic_idx, pin))
			continue;

		irq = pin_2_irq(idx, ioapic_idx, pin);

		set_io_apic_irq_attr(&attr, ioapic_idx, pin, irq_trigger(idx),
				     irq_polarity(idx));

		if ((ret = io_apic_setup_irq_pin(irq, node, &attr)))
			pr_warn("Failed (%d) to setup irq for"
				" ioapic %d, pin %d\n",
				ret, mpc_ioapic_id(ioapic_idx), pin);
	}
}

static void __init setup_IO_APIC_irqs(void)
{
	unsigned int ioapic_idx;

	apic_printk(APIC_VERBOSE, KERN_DEBUG "init IO_APIC IRQs\n");

	for (ioapic_idx = 0; ioapic_idx < nr_ioapics; ioapic_idx++)
		__io_apic_setup_irqs(ioapic_idx);
}

/*
 * for the gsit that is not in first ioapic
 * but could not use acpi_register_gsi()
 * like some special sci in IBM x3330
 */
void setup_IO_APIC_irq_extra(u32 gsi)
{
	int ioapic_idx = 0, pin, idx, irq, node = cpu_to_node(0);
	struct io_apic_irq_attr attr;

	/*
	 * Convert 'gsi' to 'ioapic.pin'.
	 */
	ioapic_idx = mp_find_ioapic(gsi);
	if (ioapic_idx < 0)
		return;

	pin = mp_find_ioapic_pin(ioapic_idx, gsi);
	idx = find_irq_entry(ioapic_idx, pin, mp_INT);
	if (idx == -1)
		return;

	irq = pin_2_irq(idx, ioapic_idx, pin);

	/* Only handle the non legacy irqs on secondary ioapics */
	if (ioapic_idx == 0 || irq < 0)
		return;

	set_io_apic_irq_attr(&attr, ioapic_idx, pin, irq_trigger(idx),
			     irq_polarity(idx));

	io_apic_setup_irq_pin_once(irq, node, &attr);
}

void native_io_apic_print_entries(unsigned int apic, unsigned int nr_entries)
{
	int i;

	pr_info(" NR Dst Mask Trig IRR Pol Stat Dmod Deli Vect:\n");

	for (i = 0; i <= nr_entries; i++) {
		struct IO_APIC_route_entry entry;

		entry = ioapic_read_entry(apic, i);

		pr_info(" %02x %02X  ", i, entry.dest);
		pr_cont("%1d    %1d    %1d   %1d   %1d    "
			"%1d    %1d    %02X\n",
			entry.mask,
			entry.trigger,
			entry.irr,
			entry.polarity,
			entry.delivery_status,
			entry.dest_mode,
			entry.delivery_mode,
			entry.vector);
	}
}

__apicdebuginit(void) print_IO_APIC(int ioapic_idx)
{
	union IO_APIC_reg_00 reg_00;
	union IO_APIC_reg_01 reg_01;
	union IO_APIC_reg_02 reg_02;
	union IO_APIC_reg_03 reg_03;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	reg_00.raw = io_apic_read(ioapic_idx, 0);
	reg_01.raw = io_apic_read(ioapic_idx, 1);
	if (reg_01.bits.version >= 0x10)
		reg_02.raw = io_apic_read(ioapic_idx, 2);
	if (reg_01.bits.version >= 0x20)
		reg_03.raw = io_apic_read(ioapic_idx, 3);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);

	printk(KERN_DEBUG "IO APIC #%d......\n", mpc_ioapic_id(ioapic_idx));
	printk(KERN_DEBUG ".... register #00: %08X\n", reg_00.raw);
	printk(KERN_DEBUG ".......    : physical APIC id: %02X\n", reg_00.bits.ID);
	printk(KERN_DEBUG ".......    : Delivery Type: %X\n", reg_00.bits.delivery_type);
	printk(KERN_DEBUG ".......    : LTS          : %X\n", reg_00.bits.LTS);

	printk(KERN_DEBUG ".... register #01: %08X\n", *(int *)&reg_01);
	printk(KERN_DEBUG ".......     : max redirection entries: %02X\n",
		reg_01.bits.entries);

	printk(KERN_DEBUG ".......     : PRQ implemented: %X\n", reg_01.bits.PRQ);
	printk(KERN_DEBUG ".......     : IO APIC version: %02X\n",
		reg_01.bits.version);

	/*
	 * Some Intel chipsets with IO APIC VERSION of 0x1? don't have reg_02,
	 * but the value of reg_02 is read as the previous read register
	 * value, so ignore it if reg_02 == reg_01.
	 */
	if (reg_01.bits.version >= 0x10 && reg_02.raw != reg_01.raw) {
		printk(KERN_DEBUG ".... register #02: %08X\n", reg_02.raw);
		printk(KERN_DEBUG ".......     : arbitration: %02X\n", reg_02.bits.arbitration);
	}

	/*
	 * Some Intel chipsets with IO APIC VERSION of 0x2? don't have reg_02
	 * or reg_03, but the value of reg_0[23] is read as the previous read
	 * register value, so ignore it if reg_03 == reg_0[12].
	 */
	if (reg_01.bits.version >= 0x20 && reg_03.raw != reg_02.raw &&
	    reg_03.raw != reg_01.raw) {
		printk(KERN_DEBUG ".... register #03: %08X\n", reg_03.raw);
		printk(KERN_DEBUG ".......     : Boot DT    : %X\n", reg_03.bits.boot_DT);
	}

	printk(KERN_DEBUG ".... IRQ redirection table:\n");

	native_io_apic_print_entries(ioapic_idx, reg_01.bits.entries);
}

#ifdef CONFIG_E90S
static void print_IO_APIC_E90S(void)
{
#define PCI_SCBA_0	0xf0    /* System commutator base address [31:00] */
#define A2_BA0		0x440   /* 32/0xffffffe0 "ioapic"  Mem Base Address
				 * Register 0     m:2:1{0x40-0x43}
				 */
#define A2_BUA0		0x444   /* 32/0xffffffff  "ioapic"  Mem Base Address 0
				 * Upper 32 bits  m:2:1{0x44-0x47}
				 */
#define A2_BA1		0x448   /* 32/0xfffffffc  "ioapic"  Mem Base Address
				 * Register 1     m:2:1{0x48-0x4b}
				 */
#define A2_BUA1		0x44c   /* 32/0xffffffff "ioapic"  Mem Base Address 1
				 * Upper 32 bits  m:2:1{0x4c-0x4f}
				 */
#define A2_BA2		0x450   /* 32/0xfffff000  "ioapic"  Mem Base Address
				 * Register 2     m:2:1{0x50-0x53}
				 */
#define A2_BUA2		0x454   /* 32/0xffffffff  "ioapic"  Mem Base Address 2
				 * Upper 32 bits  m:2:1{0x54-0x57}
				 */

	struct pci_dev *dev = NULL;
	int i;
	printk (KERN_DEBUG "Interrupt Subsystem Configuration\n");
	for_each_online_node(i) {
		u64 nodeid = 0xFE00007000 | (i << 28);
		u64 nodeconfig = 0xFE00007004 | (i << 28);
		u64 ioapic_message_base = 0xFE00001078 | (i << 28);
		u64 lapic_message_base = 0xFE0000107c | (i << 28);

		printk(KERN_DEBUG "node %d: NodeId = 0x%08x;"
			"Nodeconfig = 0x%08x\n",
			i, __raw_readl(&nodeid), __raw_readl((const volatile void *)nodeconfig));
		printk(KERN_DEBUG "node %d: IOAPICMESSAGEBASE = 0x%08x\n",
			i, __raw_readl((const volatile void *)ioapic_message_base));
		printk(KERN_DEBUG "node %d: LAPICMESSAGEBASE = 0x%08x\n",
			i, __raw_readl(
				(const volatile void *)lapic_message_base));
	}

	while ((dev = pci_get_device(PCI_VENDOR_ID_ELBRUS,
			PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE, dev))) {
		u32 addr;
		void __iomem * scrb;
		pci_read_config_dword(dev, PCI_SCBA_0, &addr);
		addr &= ~3;
		scrb = ioremap(addr, 0x1000);
		printk(KERN_DEBUG "%s: SCRB at %08x:\n", pci_name(dev), addr);
		printk(KERN_DEBUG "   A2_BA0 : %08x\n", readl(scrb + A2_BA0));
		printk(KERN_DEBUG "   A2_BUA0: %08x\n", readl(scrb + A2_BUA0));
		printk(KERN_DEBUG "   A2_BA1 : %08x\n", readl(scrb + A2_BA1));
		printk(KERN_DEBUG "   A2_BUA1: %08x\n", readl(scrb + A2_BUA1));
		printk(KERN_DEBUG "   A2_BA2 : %08x\n", readl(scrb + A2_BA2));
		printk(KERN_DEBUG "   A2_BUA2: %08x\n", readl(scrb + A2_BUA2));
		iounmap(scrb);
	}
	dev = NULL;
	while ((dev = pci_get_device(PCI_VENDOR_ID_ELBRUS,
			PCI_DEVICE_ID_MCST_I2CSPI, dev))) {
		u32 v, v2;
		pci_read_config_dword(dev, 0x50, &v);
		pci_read_config_dword(dev, 0x54, &v2);
		printk(KERN_DEBUG "%s:  LAPIC Message Base & Upper Base Address:"
			" %08x, %08x\n", pci_name(dev), v, v2);
		pci_read_config_dword(dev, 0x6c, &v);
		pci_read_config_dword(dev, 0x70, &v2);
		printk(KERN_DEBUG "%s: IOAPIC Message Base & Upper Base Address:"
			" %08x, %08x\n", pci_name(dev), v, v2);
	}
}
#else
static inline void print_IO_APIC_E90S(void) { }
#endif /* CONFIG_E90S */

void print_IO_APICs(void)
{
	int ioapic_idx;
	struct irq_cfg *cfg;
	unsigned int irq;
	struct irq_chip *chip;

	print_IO_APIC_E90S();

	printk(KERN_DEBUG "number of MP IRQ sources: %d.\n", mp_irq_entries);
	for (ioapic_idx = 0; ioapic_idx < nr_ioapics; ioapic_idx++)
		printk(KERN_DEBUG "number of IO-APIC #%d registers: %d.\n",
		       mpc_ioapic_id(ioapic_idx),
		       ioapics[ioapic_idx].nr_registers);

	/*
	 * We are a bit conservative about what we expect.  We have to
	 * know about every hardware change ASAP.
	 */
	printk(KERN_INFO "testing the IO APIC.......................\n");

	for (ioapic_idx = 0; ioapic_idx < nr_ioapics; ioapic_idx++)
		print_IO_APIC(ioapic_idx);

	printk(KERN_DEBUG "IRQ to pin mappings:\n");
	for_each_active_irq(irq) {
		struct irq_pin_list *entry;

		chip = irq_get_chip(irq);
		if (chip != &ioapic_chip)
			continue;

		cfg = irq_get_chip_data(irq);
		if (!cfg)
			continue;
		entry = cfg->irq_2_pin;
		if (!entry)
			continue;
		printk(KERN_DEBUG "IRQ%d ", irq);
		for_each_irq_pin(entry, cfg->irq_2_pin)
			pr_cont("-> %d:%d", entry->apic, entry->pin);
		pr_cont("\n");
	}

	printk(KERN_INFO ".................................... done.\n");
}

__apicdebuginit(void) save_APIC_field(int base, u32 saved_reg[])
{
	int i;

	for (i = 0; i < 8; i++)
		saved_reg[i] = apic_read(base + i*0x10);
}

__apicdebuginit(void) print_saved_APIC_field(const u32 saved_reg[])
{
	int i, j, bit = 0;
	u32 reg;

	for (i = 0; i < 8; i++) {
		reg = saved_reg[i];
		for (j = 0; j < 32; j++) {
			if (reg & 1)
				pr_cont("0x%x ", bit);
			reg = reg >> 1;
			bit++;
		}
	}
	pr_cont("\n");
}

__apicdebuginit(void) print_APIC_field(int base)
{
	int i, j, bit = 0;
	u32 reg;

	for (i = 0; i < 8; i++) {
		reg = apic_read(base + i*0x10);
		for (j = 0; j < 32; j++) {
			if (reg & 1)
				pr_cont("0x%x ", bit);
			reg = reg >> 1;
			bit++;
		}
	}
	pr_cont("\n");
}

struct saved_apic_regs {
	bool valid;
	int hard_cpu;
	int maxlvt;
	u64 icr;
	u32 ver;
	u32 apic_id;
	u32 apic_lvr;
	u32 apic_taskpri;
	u32 apic_arbpri;
	u32 apic_procpri;
	u32 apic_ldr;
	u32 apic_dfr;
	u32 apic_spiv;
	u32 apic_esr;
	u32 apic_lvtt;
	u32 apic_lvtpc;
	u32 apic_lvt0;
	u32 apic_lvt1;
	u32 apic_lvterr;
	u32 apic_tmict;
	u32 apic_tmcct;
	u32 apic_tdcr;
	u32 apic_isr[8];
	u32 apic_tmr[8];
	u32 apic_irr[8];
};

__apicdebuginit(void) print_saved_local_APIC(int cpu,
		const struct saved_apic_regs *regs)
{
	pr_info("printing local APIC contents on CPU#%d/%d:\n",
			cpu, regs->hard_cpu);
	pr_info("... APIC ID:      %08x (%01x)\n", regs->apic_id,
			apic->get_apic_id(regs->apic_id));
	pr_info("... APIC VERSION: %08x\n", regs->apic_lvr);
	pr_info("... APIC TASKPRI: %08x (%02x)\n", regs->apic_taskpri,
			regs->apic_taskpri & APIC_TPRI_MASK);

	if (!APIC_XAPIC(regs->ver)) {
		pr_info("... APIC ARBPRI: %08x (%02x)\n",
				regs->apic_arbpri,
				regs->apic_arbpri & APIC_ARBPRI_MASK);
	}
	pr_info("... APIC PROCPRI: %08x\n", regs->apic_procpri);

	pr_info("... APIC LDR: %08x\n", regs->apic_ldr);
	pr_info("... APIC DFR: %08x\n", regs->apic_dfr);
	pr_info("... APIC SPIV: %08x\n", regs->apic_spiv);

	pr_info("... APIC ISR field: ");
	print_saved_APIC_field(regs->apic_isr);
	pr_info("... APIC TMR field: ");
	print_saved_APIC_field(regs->apic_tmr);
	pr_info("... APIC IRR field: ");
	print_saved_APIC_field(regs->apic_irr);

	pr_info("... APIC ESR: %08x\n", regs->apic_esr);

	pr_info("... APIC ICR: %08x\n", (u32) regs->icr);
	pr_info("... APIC ICR2: %08x\n", (u32) (regs->icr >> 32));

	pr_info("... APIC LVTT: %08x\n", regs->apic_lvtt);

	if (regs->maxlvt > 3)                       /* PC is LVT#4. */
		pr_info("... APIC LVTPC: %08x\n", regs->apic_lvtpc);
	pr_info("... APIC LVT0: %08x\n", regs->apic_lvt0);
	pr_info("... APIC LVT1: %08x\n", regs->apic_lvt1);

	if (regs->maxlvt > 2)			/* ERR is LVT#3. */
		pr_info("... APIC LVTERR: %08x\n", regs->apic_lvterr);

	pr_info("... APIC TMICT: %08x\n", regs->apic_tmict);
	pr_info("... APIC TMCCT: %08x\n", regs->apic_tmcct);
	pr_info("... APIC TDCR: %08x\n", regs->apic_tdcr);
}

__apicdebuginit(void) save_local_APIC(void *apic_regs)
{
	struct saved_apic_regs *regs = apic_regs;

	regs->hard_cpu = hard_smp_processor_id();
	regs->apic_id = apic_read(APIC_ID);
	regs->apic_lvr = apic_read(APIC_LVR);
	regs->ver = GET_APIC_VERSION(regs->apic_lvr);
	/* Note that we don't have APIC_RRR even though maxlvt is 3 */
	regs->maxlvt = lapic_get_maxlvt();

	regs->apic_taskpri = apic_read(APIC_TASKPRI);

	if (!APIC_XAPIC(regs->ver))
		regs->apic_arbpri = apic_read(APIC_ARBPRI);
	regs->apic_procpri = apic_read(APIC_PROCPRI);

	regs->apic_ldr = apic_read(APIC_LDR);
	regs->apic_dfr = apic_read(APIC_DFR);
	regs->apic_spiv = apic_read(APIC_SPIV);

	save_APIC_field(APIC_ISR, regs->apic_isr);
	save_APIC_field(APIC_TMR, regs->apic_tmr);
	save_APIC_field(APIC_IRR, regs->apic_irr);

	if (regs->maxlvt > 3)     /* Due to the Pentium erratum 3AP. */
		apic_write(APIC_ESR, 0);

	regs->apic_esr = apic_read(APIC_ESR);

	regs->icr = apic_icr_read();

	regs->apic_lvtt = apic_read(APIC_LVTT);

	if (regs->maxlvt > 3)                       /* PC is LVT#4. */
		regs->apic_lvtpc = apic_read(APIC_LVTPC);
	regs->apic_lvt0 = apic_read(APIC_LVT0);
	regs->apic_lvt1 = apic_read(APIC_LVT1);

	if (regs->maxlvt > 2)			/* ERR is LVT#3. */
		regs->apic_lvterr = apic_read(APIC_LVTERR);

	regs->apic_tmict = apic_read(APIC_TMICT);
	regs->apic_tmcct = apic_read(APIC_TMCCT);
	regs->apic_tdcr = apic_read(APIC_TDCR);

	regs->valid = true;
}

__apicdebuginit(void) print_local_APIC(void *dummy)
{
	unsigned int v, ver, maxlvt;
	u64 icr;

	pr_info("printing local APIC contents on CPU#%d/%d:\n",
			smp_processor_id(), hard_smp_processor_id());
	v = apic_read(APIC_ID);
	pr_info("... APIC ID:      %08x (%01x)\n", v, read_apic_id());
	v = apic_read(APIC_LVR);
	pr_info("... APIC VERSION: %08x\n", v);
	ver = GET_APIC_VERSION(v);
	/* Note that we don't have RRR even though maxlvt is 3 */
	maxlvt = lapic_get_maxlvt();

	v = apic_read(APIC_TASKPRI);
	pr_info("... APIC TASKPRI: %08x (%02x)\n", v, v & APIC_TPRI_MASK);

	if (!APIC_XAPIC(ver)) {
		v = apic_read(APIC_ARBPRI);
		pr_info("... APIC ARBPRI: %08x (%02x)\n", v,
				v & APIC_ARBPRI_MASK);
	}
	v = apic_read(APIC_PROCPRI);
	pr_info("... APIC PROCPRI: %08x\n", v);

	v = apic_read(APIC_LDR);
	pr_info("... APIC LDR: %08x\n", v);
	v = apic_read(APIC_DFR);
	pr_info("... APIC DFR: %08x\n", v);
	v = apic_read(APIC_SPIV);
	pr_info("... APIC SPIV: %08x\n", v);

	pr_info("... APIC ISR field: ");
	print_APIC_field(APIC_ISR);
	pr_info("... APIC TMR field: ");
	print_APIC_field(APIC_TMR);
	pr_info("... APIC IRR field: ");
	print_APIC_field(APIC_IRR);

	if (maxlvt > 3)         /* Due to the Pentium erratum 3AP. */
		apic_write(APIC_ESR, 0);

	v = apic_read(APIC_ESR);
	pr_info("... APIC ESR: %08x\n", v);

	icr = apic_icr_read();
	pr_info("... APIC ICR: %08x\n", (u32)icr);
	pr_info("... APIC ICR2: %08x\n", (u32)(icr >> 32));

	v = apic_read(APIC_LVTT);
	pr_info("... APIC LVTT: %08x\n", v);

	if (maxlvt > 3) {                       /* PC is LVT#4. */
		v = apic_read(APIC_LVTPC);
		pr_info("... APIC LVTPC: %08x\n", v);
	}
	v = apic_read(APIC_LVT0);
	pr_info("... APIC LVT0: %08x\n", v);
	v = apic_read(APIC_LVT1);
	pr_info("... APIC LVT1: %08x\n", v);

	if (maxlvt > 2) {			/* ERR is LVT#3. */
		v = apic_read(APIC_LVTERR);
		pr_info("... APIC LVTERR: %08x\n", v);
	}

	v = apic_read(APIC_TMICT);
	pr_info("... APIC TMICT: %08x\n", v);
	v = apic_read(APIC_TMCCT);
	pr_info("... APIC TMCCT: %08x\n", v);
	v = apic_read(APIC_TDCR);
	pr_info("... APIC TDCR: %08x\n", v);
}

int print_local_APICs(bool force)
{
	int cpu;

	if (!force && apic_verbosity == APIC_QUIET)
		return 1;

	preempt_disable();
	for_each_online_cpu(cpu) {
		struct saved_apic_regs regs;

		if (cpu == smp_processor_id()) {
			print_local_APIC(NULL);
			continue;
		}

		regs.valid = false;
#ifdef CONFIG_E2K
		/* This function can be called through SysRq under
		 * disabled interrupts, so we have to be careful
		 * and use nmi_call_function() with a timeout
		 * instead of smp_call_function(). */
		nmi_call_function_single(cpu, save_local_APIC, &regs, 1, 30000);
#else
		smp_call_function_single(cpu, save_local_APIC, &regs, 1);
#endif
		if (regs.valid)
			print_saved_local_APIC(cpu, &regs);
	}
	preempt_enable();

	return 0;
}


static void native_disable_io_apic(void)
{
	if (!cpu_has_epic() && smp_found_config)
		disconnect_bsp_APIC(0);
}

/*
 * Not an __init, needed by the reboot code
 */
void disable_IO_APIC(void)
{
	/*
	 * Clear the IO-APIC before rebooting:
	 */
	clear_IO_APIC();

	native_disable_io_apic();
}

int get_physical_broadcast(void)
{
	return 0xff;
}

/*
 * function to set the IO-APIC physical IDs based on the
 * values stored in the MPC table.
 *
 * by Matt Domsch <Matt_Domsch@dell.com>  Tue Dec 21 12:25:05 CST 1999
 */
void __init_recv setup_ioapic_ids_from_mpc_nocheck(void)
{
	union IO_APIC_reg_00 reg_00;
	physid_mask_t phys_id_present_map;
	int ioapic_idx;
	int i;
	unsigned char old_id;
	unsigned long flags;

	/*
	 * This is broken; anything with a real cpu count has to
	 * circumvent this idiocy regardless.
	 */
	apic->ioapic_phys_id_map(&phys_cpu_present_map, &phys_id_present_map);

	/*
	 * Set the IOAPIC ID to the value stored in the MPC table.
	 */
	for (ioapic_idx = 0; ioapic_idx < nr_ioapics; ioapic_idx++) {
		/* Read the register 0 value */
		raw_spin_lock_irqsave(&ioapic_lock, flags);
		reg_00.raw = io_apic_read(ioapic_idx, 0);
		raw_spin_unlock_irqrestore(&ioapic_lock, flags);

		old_id = mpc_ioapic_id(ioapic_idx);

		if (mpc_ioapic_id(ioapic_idx) >= get_physical_broadcast()) {
			printk(KERN_ERR "BIOS bug, IO-APIC#%d ID is %d in the MPC table!...\n",
				ioapic_idx, mpc_ioapic_id(ioapic_idx));
			printk(KERN_ERR "... fixing up to %d. (tell your hw vendor)\n",
				reg_00.bits.ID);
			ioapics[ioapic_idx].mp_config.apicid = reg_00.bits.ID;
		}

		/*
		 * Sanity check, is the ID really free? Every APIC in a
		 * system must have a unique ID or we get lots of nice
		 * 'stuck on smp_invalidate_needed IPI wait' messages.
		 */
		if (apic->check_apicid_used(&phys_id_present_map,
					    mpc_ioapic_id(ioapic_idx))) {
			printk(KERN_ERR "BIOS bug, IO-APIC#%d ID %d is already used!...\n",
				ioapic_idx, mpc_ioapic_id(ioapic_idx));
			for (i = 0; i < get_physical_broadcast(); i++)
				if (!physid_isset(i, phys_id_present_map))
					break;
			if (i >= get_physical_broadcast())
				panic("Max APIC ID exceeded!\n");
			printk(KERN_ERR "... fixing up to %d. (tell your hw vendor)\n",
				i);
			physid_set(i, phys_id_present_map);
			ioapics[ioapic_idx].mp_config.apicid = i;
		} else {
			physid_mask_t tmp;
			apic->apicid_to_cpu_present(mpc_ioapic_id(ioapic_idx),
						    &tmp);
			apic_printk(APIC_VERBOSE, "Setting %d in the "
					"phys_id_present_map\n",
					mpc_ioapic_id(ioapic_idx));
			physids_or(phys_id_present_map, phys_id_present_map, tmp);
		}

		/*
		 * Adjust the IOLINK table if the ID changed.
		 */
		if (old_id != mpc_ioapic_id(ioapic_idx))
			mp_fix_io_apicid(old_id, mpc_ioapic_id(ioapic_idx));

		/*
		 * We need to adjust the IRQ routing table
		 * if the ID changed.
		 */
		if (old_id != mpc_ioapic_id(ioapic_idx))
			for (i = 0; i < mp_irq_entries; i++)
				if (mp_irqs[i].dstapic == old_id)
					mp_irqs[i].dstapic
						= mpc_ioapic_id(ioapic_idx);

		/*
		 * Update the ID register according to the right value
		 * from the MPC table if they are different.
		 */
		if (mpc_ioapic_id(ioapic_idx) == reg_00.bits.ID)
			continue;

		apic_printk(APIC_VERBOSE, KERN_INFO
			"...changing IO-APIC physical APIC ID to %d ...",
			mpc_ioapic_id(ioapic_idx));

		reg_00.bits.ID = mpc_ioapic_id(ioapic_idx);
		raw_spin_lock_irqsave(&ioapic_lock, flags);
		io_apic_write(ioapic_idx, 0, reg_00.raw);
		raw_spin_unlock_irqrestore(&ioapic_lock, flags);

		/*
		 * Sanity check
		 */
		raw_spin_lock_irqsave(&ioapic_lock, flags);
		reg_00.raw = io_apic_read(ioapic_idx, 0);
		raw_spin_unlock_irqrestore(&ioapic_lock, flags);
		if (reg_00.bits.ID != mpc_ioapic_id(ioapic_idx))
			pr_cont("could not set ID!\n");
		else
			apic_printk(APIC_VERBOSE, " ok.\n");
	}
}

/*
 * In the SMP+IOAPIC case it might happen that there are an unspecified
 * number of pending IRQ events unhandled. These cases are very rare,
 * so we 'resend' these IRQs via IPIs, to the same CPU. It's much
 * better to do it this way as thus we do not have to be aware of
 * 'pending' interrupts in the IRQ path, except at this point.
 */
/*
 * Edge triggered needs to resend any interrupt
 * that was delayed but this is now handled in the device
 * independent code.
 */

/*
 * Starting up a edge-triggered IO-APIC interrupt is
 * nasty - we need to make sure that we get the edge.
 * If it is already asserted for some reason, we need
 * return 1 to indicate that is was pending.
 *
 * This is not complete - we should be able to fake
 * an edge even if it isn't on the 8259A...
 */

static unsigned int startup_ioapic_irq(struct irq_data *data)
{
	int was_pending = 0;
	unsigned long flags;

	apic_printk(APIC_DEBUG, KERN_DEBUG "Starting up IO-APIC irq %u\n",
		data->irq);
	raw_spin_lock_irqsave(&ioapic_lock, flags);
	__unmask_ioapic(data->chip_data);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);

	return was_pending;
}

int ioapic_retrigger_irq(struct irq_data *data)
{
	struct irq_cfg *cfg = data->chip_data;
	unsigned long flags;
	int cpu;

	raw_spin_lock_irqsave(&vector_lock, flags);
	cpu = cpumask_first_and(cfg->domain, cpu_online_mask);
	apic->send_IPI_mask(cpumask_of(cpu), cfg->vector);
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	return 1;
}

/*
 * Level and edge triggered IO-APIC interrupts need different handling,
 * so we use two separate IRQ descriptors. Edge triggered IRQs can be
 * handled with the level-triggered descriptor, but that one has slightly
 * more overhead. Level-triggered interrupts cannot be handled with the
 * edge-triggered handler, without risking IRQ storms and other ugly
 * races.
 */

#ifdef CONFIG_SMP
static void send_cleanup_vector(struct irq_cfg *cfg)
{
	cpumask_var_t cleanup_mask;

	if (unlikely(!alloc_cpumask_var(&cleanup_mask, GFP_ATOMIC))) {
		unsigned int i;
		for_each_cpu_and(i, cfg->old_domain, cpu_online_mask)
			apic->send_IPI_mask(cpumask_of(i), IRQ_MOVE_CLEANUP_VECTOR);
	} else {
		cpumask_and(cleanup_mask, cfg->old_domain, cpu_online_mask);
		apic->send_IPI_mask(cleanup_mask, IRQ_MOVE_CLEANUP_VECTOR);
		free_cpumask_var(cleanup_mask);
	}
	apic_printk(APIC_DEBUG, KERN_DEBUG "Finished moving vector %d\n",
			cfg->vector);
	cfg->move_in_progress = 0;
}

asmlinkage void smp_irq_move_cleanup_interrupt(struct pt_regs *regs)
{
	unsigned vector, me;

	ack_APIC_irq();
	l_irq_enter();
	exit_idle();

	me = smp_processor_id();
	for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
		int irq;
		unsigned int irr;
		struct irq_desc *desc;
		struct irq_cfg *cfg;
		irq = __this_cpu_read(vector_irq[vector]);

		if (irq <= VECTOR_UNDEFINED)
			continue;

		desc = irq_to_desc(irq);
		if (!desc)
			continue;

		cfg = irq_cfg(irq);
		if (!cfg)
			continue;

		raw_spin_lock(&desc->lock);

		/*
		 * Check if the irq migration is in progress. If so, we
		 * haven't received the cleanup request yet for this irq.
		 */
		if (cfg->move_in_progress)
			goto unlock;

		if (vector == cfg->vector && cpumask_test_cpu(me, cfg->domain))
			goto unlock;

		irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
		/*
		 * Check if the vector that needs to be cleanedup is
		 * registered at the cpu's IRR. If so, then this is not
		 * the best time to clean it up. Lets clean it up in the
		 * next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
		 * to myself.
		 */
		if (irr  & (1 << (vector % 32))) {
			apic->send_IPI_self(IRQ_MOVE_CLEANUP_VECTOR);
			goto unlock;
		}
		__this_cpu_write(vector_irq[vector], -1);
unlock:
		raw_spin_unlock(&desc->lock);
	}

	l_irq_exit();
}

static void irq_complete_move_vector(struct irq_cfg *cfg, int vec_eq)
{
	unsigned int vector;

	if (cpumask_test_cpu(smp_processor_id(), cfg->domain)) {
		if (!vec_eq) {
			vector =
#if defined CONFIG_E2K
			(unsigned int) get_irq_regs()->interrupt_vector;
#elif defined CONFIG_E90S
			(unsigned int)
				e90s_irq_pending[smp_processor_id()].vector;
#else
			~get_irq_regs()->orig_ax;
#endif
			vec_eq = vector == cfg->vector;
		}
		if (vec_eq)
			send_cleanup_vector(cfg);
	}
}

static void irq_complete_move(struct irq_cfg *cfg)
{
	if (likely(!cfg->move_in_progress))
		return;

	irq_complete_move_vector(cfg, 0);
}

void apic_irq_force_complete_move(struct irq_desc *desc)
{
	struct irq_data *data = irq_desc_get_irq_data(desc);
	struct irq_cfg *cfg;
	unsigned int irq;

	if (!data)
		return;

	irq = data->irq;
	cfg = irq_data_get_irq_chip_data(data);
	if (unlikely(cfg && cfg->move_in_progress))
		irq_complete_move_vector(cfg, 1);
}
#else
static inline void irq_complete_move(struct irq_cfg *cfg) { }
#endif

static void __target_IO_APIC_irq(unsigned int irq, unsigned int dest, struct irq_cfg *cfg)
{
	int apic, pin;
	struct irq_pin_list *entry;
	u8 vector = cfg->vector;

	for_each_irq_pin(entry, cfg->irq_2_pin) {
		unsigned int reg;

		apic = entry->apic;
		pin = entry->pin;

		/* We cannot write the whole entry as once, only 32 bits
		 * at a time. So mask the IRQ while changing entry to
		 * avoid races in half-changed entries. */
		reg = io_apic_read(apic, 0x10 + pin*2);
		reg &= ~IO_APIC_REDIR_VECTOR_MASK;
		reg |= vector;
		io_apic_modify(apic, 0x10 + pin*2, reg | IO_APIC_REDIR_MASKED);
		io_apic_write(apic, 0x11 + pin*2, dest);
		if (!(reg & IO_APIC_REDIR_MASKED))
			io_apic_write(apic, 0x10 + pin*2, reg);
	}
}

/*
 * Either sets data->affinity to a valid value, and returns
 * ->cpu_mask_to_apicid of that in dest_id, or returns -1 and
 * leaves data->affinity untouched.
 */
int __ioapic_set_affinity(struct irq_data *data, const struct cpumask *mask,
			  unsigned int *dest_id)
{
	struct irq_cfg *cfg = data->chip_data;
	unsigned int irq = data->irq;
	int err;

	if (!IS_ENABLED(CONFIG_SMP))
		return -1;

	if (!cpumask_intersects(mask, cpu_online_mask))
		return -EINVAL;

	err = assign_irq_vector(irq, cfg, mask);
	if (err)
		return err;

	err = apic->cpu_mask_to_apicid_and(mask, cfg->domain, dest_id);
	if (err) {
		if (assign_irq_vector(irq, cfg,
				irq_data_get_affinity_mask(data)))
			pr_err("Failed to recover vector for irq %d\n", irq);
		return err;
	}

	cpumask_copy(irq_data_get_affinity_mask(data), mask);

	return 0;
}


int native_ioapic_set_affinity(struct irq_data *data,
			       const struct cpumask *mask,
			       bool force)
{
	unsigned int dest, irq = data->irq;
	unsigned long flags;
	int ret;

	if (!IS_ENABLED(CONFIG_SMP))
		return -1;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	ret = __ioapic_set_affinity(data, mask, &dest);
	if (!ret) {
		/* Only the high 8 bits are valid. */
		dest = SET_APIC_LOGICAL_ID(dest);
		__target_IO_APIC_irq(irq, dest, data->chip_data);
		ret = IRQ_SET_MASK_OK_NOCOPY;
	}
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
	return ret;
}

void ack_apic_edge(struct irq_data *data)
{
	irq_complete_move(data->chip_data);
	irq_move_irq(data);
	ack_APIC_irq();
}

atomic_t irq_mis_count;

#ifdef CONFIG_GENERIC_PENDING_IRQ
static bool io_apic_level_ack_pending(struct irq_cfg *cfg)
{
	struct irq_pin_list *entry;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	for_each_irq_pin(entry, cfg->irq_2_pin) {
		unsigned int reg;
		int pin;

		pin = entry->pin;
		reg = io_apic_read(entry->apic, 0x10 + pin*2);
		/* Is the remote IRR bit set? */
		if (reg & IO_APIC_REDIR_REMOTE_IRR) {
			raw_spin_unlock_irqrestore(&ioapic_lock, flags);
			return true;
		}
	}
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);

	return false;
}

static inline bool ioapic_irqd_mask(struct irq_data *data, struct irq_cfg *cfg)
{
	/* If we are moving the irq we need to mask it */
	if (unlikely(irqd_is_setaffinity_pending(data))) {
		if (!irqd_irq_masked(data))
			mask_ioapic(cfg);
		return true;
	}
	return false;
}

static inline void ioapic_irqd_unmask(struct irq_data *data,
				      struct irq_cfg *cfg, bool masked)
{
	if (unlikely(masked)) {
		/* Only migrate the irq if the ack has been received.
		 *
		 * On rare occasions the broadcast level triggered ack gets
		 * delayed going to ioapics, and if we reprogram the
		 * vector while Remote IRR is still set the irq will never
		 * fire again.
		 *
		 * To prevent this scenario we read the Remote IRR bit
		 * of the ioapic.  This has two effects.
		 * - On any sane system the read of the ioapic will
		 *   flush writes (and acks) going to the ioapic from
		 *   this cpu.
		 * - We get to see if the ACK has actually been delivered.
		 *
		 * Based on failed experiments of reprogramming the
		 * ioapic entry from outside of irq context starting
		 * with masking the ioapic entry and then polling until
		 * Remote IRR was clear before reprogramming the
		 * ioapic I don't trust the Remote IRR bit to be
		 * completey accurate.
		 *
		 * However there appears to be no other way to plug
		 * this race, so if the Remote IRR bit is not
		 * accurate and is causing problems then it is a hardware bug
		 * and you can go talk to the chipset vendor about it.
		 */
		if (!io_apic_level_ack_pending(cfg))
			irq_move_masked_irq(data);

		/* If the IRQ is masked in the core, leave it: */
		if (!irqd_irq_masked(data))
			unmask_ioapic(cfg);
	}
}
#else
static inline bool ioapic_irqd_mask(struct irq_data *data, struct irq_cfg *cfg)
{
	return false;
}
static inline void ioapic_irqd_unmask(struct irq_data *data,
				      struct irq_cfg *cfg, bool masked)
{
}
#endif

void ack_apic_level(struct irq_data *data)
{
	struct irq_cfg *cfg = data->chip_data;
	int i, irq = data->irq, eoi_bug = false;
	unsigned long v, flags = 0;
	bool masked;

#ifdef CONFIG_E2K
	eoi_bug = cpu_has(CPU_HWBUG_LEVEL_EOI);
#elif CONFIG_E90S
	eoi_bug = get_cpu_revision() <= 0x11;
#endif

	irq_complete_move(cfg);
	masked = ioapic_irqd_mask(data, cfg);

	/*
	 * It appears there is an erratum which affects at least version 0x11
	 * of I/O APIC (that's the 82093AA and cores integrated into various
	 * chipsets).  Under certain conditions a level-triggered interrupt is
	 * erroneously delivered as edge-triggered one but the respective IRR
	 * bit gets set nevertheless.  As a result the I/O unit expects an EOI
	 * message but it will never arrive and further interrupts are blocked
	 * from the source.  The exact reason is so far unknown, but the
	 * phenomenon was observed when two consecutive interrupt requests
	 * from a given source get delivered to the same CPU and the source is
	 * temporarily disabled in between.
	 *
	 * A workaround is to simulate an EOI message manually.  We achieve it
	 * by setting the trigger mode to edge and then to level when the edge
	 * trigger mode gets detected in the TMR of a local APIC for a
	 * level-triggered interrupt.  We mask the source for the time of the
	 * operation to prevent an edge-triggered interrupt escaping meanwhile.
	 * The idea is from Manfred Spraul.  --macro
	 *
	 * Also in the case when cpu goes offline, fixup_irqs() will forward
	 * any unhandled interrupt on the offlined cpu to the new cpu
	 * destination that is handling the corresponding interrupt. This
	 * interrupt forwarding is done via IPI's. Hence, in this case also
	 * level-triggered io-apic interrupt will be seen as an edge
	 * interrupt in the IRR. And we can't rely on the cpu's EOI
	 * to be broadcasted to the IO-APIC's which will clear the remoteIRR
	 * corresponding to the level-triggered interrupt. Hence on IO-APIC's
	 * supporting EOI register, we do an explicit EOI to clear the
	 * remote IRR and on IO-APIC's which don't have an EOI register,
	 * we use the above logic (mask+edge followed by unmask+level) from
	 * Manfred Spraul to clear the remote IRR.
	 */
	i = cfg->vector;
	v = apic_read(APIC_TMR + ((i & ~0x1f) >> 1));

	if (eoi_bug)
		raw_local_irq_save(flags);

	/*
	 * We must acknowledge the irq before we move it or the acknowledge will
	 * not propagate properly.
	 */
	ack_APIC_irq();

	/*
	 * Tail end of clearing remote IRR bit (either by delivering the EOI
	 * message via io-apic EOI register write or simulating it using
	 * mask+edge followed by unnask+level logic) manually when the
	 * level triggered interrupt is seen as the edge triggered interrupt
	 * at the cpu.
	 */
	if (!(v & (1 << (i & 0x1f)))) {
		atomic_inc(&irq_mis_count);

		eoi_ioapic_irq(irq, cfg);
	}

	if (eoi_bug) {
		do {
			v = apic_read(APIC_ISR + ((i & ~0x1f) >> 1));
		} while (v & (1 << (i & 0x1f)));
		raw_local_irq_restore(flags);
	}

	ioapic_irqd_unmask(data, cfg, masked);
}

#ifdef CONFIG_EPIC
void ioapic_ack_epic_edge(struct irq_data *data)
{
	irq_complete_move(data->chip_data);
	irq_move_irq(data);
	ack_epic_irq();
}

void ioapic_ack_epic_level(struct irq_data *data)
{
	struct irq_cfg *cfg = data->chip_data;
	bool masked;

	irq_complete_move(cfg);
	masked = ioapic_irqd_mask(data, cfg);

	ack_epic_irq();

	/*
	 * To send a message from CEPIC to IOAPIC we need to write HC_IOAPIC_EOI
	 * SIC register
	 */
	epic_ioapic_eoi(cfg->vector);

	ioapic_irqd_unmask(data, cfg, masked);
}
#endif

static struct irq_chip ioapic_chip __read_mostly = {
	.name			= "IO-APIC",
	.irq_startup		= startup_ioapic_irq,
	.irq_mask		= mask_ioapic_irq,
	.irq_unmask		= unmask_ioapic_irq,
	.irq_ack		= ioapic_ack_pic_edge,
	.irq_eoi		= ioapic_ack_pic_level,
	.irq_set_affinity	= native_ioapic_set_affinity,
	.irq_retrigger		= ioapic_retrigger_irq,
};

static inline void init_IO_APIC_traps(void)
{
	struct irq_cfg *cfg;
	unsigned int irq;

	/*
	 * NOTE! The local APIC isn't very good at handling
	 * multiple interrupts at the same interrupt level.
	 * As the interrupt level is determined by taking the
	 * vector number and shifting that right by 4, we
	 * want to spread these out a bit so that they don't
	 * all fall in the same interrupt level.
	 *
	 * Also, we've got to be careful not to trash gate
	 * 0x80, because int 0x80 is hm, kind of importantish. ;)
	 */
	for_each_active_irq(irq) {
		if (!irqchip_is_ioapic(irq_get_chip(irq)))
			continue;

		cfg = irq_get_chip_data(irq);
		if (cfg && !cfg->vector) {
			/* Strange. Oh, well.. */
			irq_set_chip(irq, &no_irq_chip);
		}
	}
}

void __init setup_IO_APIC(void)
{
	apic_printk(APIC_VERBOSE, "ENABLING IO-APIC IRQs\n");
	/*
         * Set up IO-APIC IRQ routing.
         */
	setup_ioapic_ids_from_mpc_nocheck();
	setup_IO_APIC_irqs();
	init_IO_APIC_traps();
}

static void resume_ioapic_id(int ioapic_idx)
{
	unsigned long flags;
	union IO_APIC_reg_00 reg_00;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	reg_00.raw = io_apic_read(ioapic_idx, 0);
	if (reg_00.bits.ID != mpc_ioapic_id(ioapic_idx)) {
		reg_00.bits.ID = mpc_ioapic_id(ioapic_idx);
		io_apic_write(ioapic_idx, 0, reg_00.raw);
	}
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);
}

static void ioapic_resume(void)
{
	int ioapic_idx;

	for (ioapic_idx = nr_ioapics - 1; ioapic_idx >= 0; ioapic_idx--)
		resume_ioapic_id(ioapic_idx);

	restore_ioapic_entries();
}

static struct syscore_ops ioapic_syscore_ops = {
	.suspend = save_ioapic_entries,
	.resume = ioapic_resume,
};

static int __init ioapic_init_ops(void)
{
	register_syscore_ops(&ioapic_syscore_ops);

	return 0;
}
device_initcall(ioapic_init_ops);

/*
 * Dynamic irq allocate and deallocation
 */
unsigned int __create_irqs(unsigned int from, unsigned int count, int node)
{
	struct irq_cfg **cfg;
	unsigned long flags;
	int irq, i;

	if (from < nr_irqs_gsi)
		from = nr_irqs_gsi;

	cfg = kzalloc_node(count * sizeof(cfg[0]), GFP_KERNEL, node);
	if (!cfg)
		return 0;

	irq = alloc_irqs_from(from, count, node);
	if (irq < 0)
		goto out_cfgs;

	for (i = 0; i < count; i++) {
		cfg[i] = alloc_irq_cfg(irq + i, node);
		if (!cfg[i])
			goto out_irqs;
	}

	raw_spin_lock_irqsave(&vector_lock, flags);
	for (i = 0; i < count; i++)
		if (__assign_irq_vector(irq + i, cfg[i], apic->target_cpus()))
			goto out_vecs;
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	for (i = 0; i < count; i++) {
		irq_set_chip_data(irq + i, cfg[i]);
		irq_clear_status_flags(irq + i, IRQ_NOREQUEST);
	}

	kfree(cfg);
	return irq;

out_vecs:
	for (i--; i >= 0; i--)
		__clear_irq_vector(irq + i, cfg[i]);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
out_irqs:
	for (i = 0; i < count; i++)
		free_irq_at(irq + i, cfg[i]);
out_cfgs:
	kfree(cfg);
	return 0;
}

unsigned int create_irq_nr(unsigned int from, int node)
{
	return __create_irqs(from, 1, node);
}

int create_irq(void)
{
	int node = cpu_to_node(0);
	unsigned int irq_want;
	int irq;

	irq_want = nr_irqs_gsi;
	irq = create_irq_nr(irq_want, node);

	if (irq == 0)
		irq = -1;

	return irq;
}

void destroy_irq(unsigned int irq)
{
	struct irq_cfg *cfg = irq_get_chip_data(irq);
	unsigned long flags;

	irq_set_status_flags(irq, IRQ_NOREQUEST|IRQ_NOPROBE);

	raw_spin_lock_irqsave(&vector_lock, flags);
	__clear_irq_vector(irq, cfg);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
	free_irq_at(irq, cfg);
}

void destroy_irqs(unsigned int irq, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		destroy_irq(irq + i);
}

/*
 * MSI message composition
 */
void native_compose_msi_msg(struct pci_dev *pdev,
			    unsigned int irq, unsigned int dest,
			    struct msi_msg *msg, u8 hpet_id)
{
	struct irq_cfg *cfg = irq_cfg(irq);
	struct iohub_sysdata *sd = pdev->bus->sysdata;
	msg->address_hi = sd->pci_msi_addr_hi;

	msg->address_lo =
		sd->pci_msi_addr_lo |
		((apic->irq_dest_mode == 0) ?
			MSI_ADDR_DEST_MODE_PHYSICAL:
			MSI_ADDR_DEST_MODE_LOGICAL) |
		((apic->irq_delivery_mode != dest_LowestPrio) ?
			MSI_ADDR_REDIRECTION_CPU:
			MSI_ADDR_REDIRECTION_LOWPRI) |
		MSI_ADDR_DEST_ID(dest);

	/* IOH and IOH2 have a bug. We must duplicate
	 * destination into data. Fortunately it's possible
	 */
	msg->data =
		MSI_ADDR_DEST_ID(dest) |
		MSI_DATA_VECTOR(cfg->vector);
	apic_printk(APIC_DEBUG, "MSI interrupt for %s: irq %d : address_lo = 0x%08x,"
		"data = 0x%08x\n", pdev->bus->name, irq,
		msg->address_lo, msg->data);
}

#ifdef CONFIG_PCI_MSI
int msi_compose_msg(struct pci_dev *pdev, unsigned int irq,
			   struct msi_msg *msg, u8 hpet_id)
{
	struct irq_cfg *cfg;
	int err;
	unsigned dest;

#ifdef CONFIG_E2K
	if (e2k_msi_disabled) {
		return -ENXIO;
	}
#endif

	cfg = irq_cfg(irq);
	err = assign_irq_vector(irq, cfg, apic->target_cpus());
	if (err)
		return err;

	err = apic->cpu_mask_to_apicid_and(cfg->domain,
					   apic->target_cpus(), &dest);
	if (err)
		return err;

	native_compose_msi_msg(pdev, irq, dest, msg, hpet_id);
	return 0;
}

static int
msi_set_affinity(struct irq_data *data, const struct cpumask *mask, bool force)
{
	struct irq_cfg *cfg = data->chip_data;
	struct msi_msg msg;
	unsigned int dest;

	if (__ioapic_set_affinity(data, mask, &dest))
		return -1;

	__get_cached_msi_msg(data->common->msi_desc, &msg);

	/* IOH and IOH2 have a bug. We must duplicate
	 * destination into data. Fortunately it's possible
	 */
	msg.data = MSI_DATA_VECTOR(cfg->vector) | MSI_ADDR_DEST_ID(dest);
	msg.address_lo &= ~MSI_ADDR_DEST_ID_MASK;
	msg.address_lo |= MSI_ADDR_DEST_ID(dest);

	pci_write_msi_msg(data->irq, &msg);

	return IRQ_SET_MASK_OK_NOCOPY;
}

static void l_msi_irq_ack(struct irq_data *data)
{
	struct msi_desc *desc = irq_data_get_msi_desc(data);
	struct pci_dev *dev = msi_desc_to_pci_dev(desc);

	if (iohub_generation(dev) < 2) {
		u32 mask;
		/* interrupt can come ahead of DMA,
				so flush DMA with register read */
		if (desc->msi_attrib.is_msix)
			readl(desc->mask_base);
		else
			pci_read_config_dword(dev, desc->mask_pos, &mask);
	}

	ioapic_ack_pic_edge(data);
}

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
static struct irq_chip msi_chip = {
	.name			= "PCI-MSI",
	.irq_unmask		= pci_msi_unmask_irq,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= l_msi_irq_ack,
	.irq_set_affinity	= msi_set_affinity,
	.irq_retrigger		= ioapic_retrigger_irq,
};

int setup_msi_irq(struct pci_dev *dev, struct msi_desc *msidesc,
		  unsigned int irq_base, unsigned int irq_offset)
{
	struct irq_chip *chip = &msi_chip;
	struct msi_msg msg;
	unsigned int irq = irq_base + irq_offset;
	int ret;
	ret = msi_compose_msg(dev, irq, &msg, -1);
	if (ret < 0)
		return ret;

	irq_set_msi_desc_off(irq_base, irq_offset, msidesc);

	/*
	 * MSI-X message is written per-IRQ, the offset is always 0.
	 * MSI message denotes a contiguous group of IRQs, written for 0th IRQ.
	 */
	if (!irq_offset)
		pci_write_msi_msg(irq, &msg);

	irq_set_chip_and_handler_name(irq, chip, handle_edge_irq, "edge");

	dev_printk(KERN_DEBUG, &dev->dev, "irq %d for MSI/MSI-X\n", irq);

	return 0;
}

int native_setup_msi_irqs_apic(struct pci_dev *dev, int nvec, int type)
{
	unsigned int irq, irq_want;
	struct msi_desc *msidesc;
	int node, ret;

	/* Multiple MSI vectors only supported with interrupt remapping */
	if (type == PCI_CAP_ID_MSI && nvec > 1)
		return 1;

	node = dev_to_node(&dev->dev);
	irq_want = nr_irqs_gsi;
	list_for_each_entry(msidesc, dev_to_msi_list(&dev->dev), list) {
		irq = create_irq_nr(irq_want, node);
		if (irq == 0)
			return -ENOSPC;

		irq_want = irq + 1;

		ret = setup_msi_irq(dev, msidesc, irq, 0);
		if (ret < 0)
			goto error;
	}
	return 0;

error:
	destroy_irq(irq);
	return ret;
}

void native_teardown_msi_irq_apic(unsigned int irq)
{
	destroy_irq(irq);
}

static bool irqchip_is_ioapic(struct irq_chip *chip)
{
	return chip == &ioapic_chip || chip == &msi_chip ||
		irqchip_is_ioepic_to_apic(chip);
}

#endif /* CONFIG_PCI_MSI */

int io_apic_setup_irq_pin_once(unsigned int irq, int node,
			       struct io_apic_irq_attr *attr)
{
	unsigned int ioapic_idx = attr->ioapic, pin = attr->ioapic_pin;
	int ret;
	struct IO_APIC_route_entry orig_entry;

	/* Avoid redundant programming */
	if (test_bit(pin, ioapics[ioapic_idx].pin_programmed)) {
		pr_debug("Pin %d-%d already programmed\n", mpc_ioapic_id(ioapic_idx), pin);
		orig_entry = ioapic_read_entry(attr->ioapic, pin);
		if (attr->trigger == orig_entry.trigger && attr->polarity == orig_entry.polarity)
			return 0;
		return -EBUSY;
	}
	ret = io_apic_setup_irq_pin(irq, node, attr);
	if (!ret)
		set_bit(pin, ioapics[ioapic_idx].pin_programmed);
	return ret;
}

static int __init io_apic_get_redir_entries(int ioapic)
{
	union IO_APIC_reg_01	reg_01;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	reg_01.raw = io_apic_read(ioapic, 1);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);

	/* The register returns the maximum index redir index
	 * supported, which is one less than the total number of redir
	 * entries.
	 */
	return reg_01.bits.entries + 1;
}

void __init probe_nr_irqs_gsi(void)
{
	int nr = gsi_top;
	if (nr > nr_irqs_gsi)
		nr_irqs_gsi = nr;

	printk(KERN_DEBUG "nr_irqs_gsi: %d\n", nr_irqs_gsi);
}

int get_nr_irqs_gsi(void)
{
	return nr_irqs_gsi;
}
EXPORT_SYMBOL(get_nr_irqs_gsi);

int __init arch_probe_nr_irqs(void)
{
	int nr;

	if (nr_irqs > (NR_VECTORS * nr_cpu_ids))
		nr_irqs = NR_VECTORS * nr_cpu_ids;

	/*
	 * We have nr_irqs_gsi pins, I2C_SPI_IRQS_NUM chained
	 * interrupts in I2C-SPI controller and 
	 * ARCH_NR_OWN_GPIOS*MAX_NUMIOLINKS chained interrupts 
	 * in GPIO controller (if CONFIG_IOHUB_DOMAINS - it can be 
	 * MAX_NUMIOLINKS controllers on board).
	 *
	 * GPIO irqs will belong 
	 *   [nr_irqs_gsi, nr_irqs_gsi + ARCH_MAX_NR_OWN_GPIOS)
	 *
	 * And I2C_SPI irqs:
	 *   [nr_irqs_gsi + ARCH_MAX_NR_OWN_GPIOS,
	 *    nr_irqs_gsi + ARCH_MAX_NR_OWN_GPIOS + I2C_SPI_IRQS_NUM)
	 */
#ifdef CONFIG_IOHUB_DOMAINS
	nr = nr_irqs_gsi + ARCH_MAX_NR_OWN_GPIOS * num_online_iohubs() +
			I2C_SPI_IRQS_NUM;
#else
	nr = nr_irqs_gsi + ARCH_MAX_NR_OWN_GPIOS + I2C_SPI_IRQS_NUM;
#endif

#if defined(CONFIG_PCI_MSI) || defined(CONFIG_HT_IRQ)
	/*
	 * for MSI and HT dyn irq
	 */
	nr += nr_irqs_gsi * 16;
#endif
	if (nr < nr_irqs)
		nr_irqs = nr;

	return 0;
}

/* TODO just a reminder: pin numbers here and in current arch/l/pci
 * implementation are different, see commit 878f2e50.
 */
int io_apic_set_pci_routing(struct device *dev, int irq,
			    struct io_apic_irq_attr *irq_attr)
{
	int node = dev ? dev_to_node(dev) : cpu_to_node(0);

	return io_apic_setup_irq_pin_once(irq, node, irq_attr);
}

static u8 __init io_apic_unique_id(u8 id)
{
	int i;
	DECLARE_BITMAP(used, 256);

	bitmap_zero(used, 256);
	for (i = 0; i < nr_ioapics; i++) {
		__set_bit(mpc_ioapic_id(i), used);
	}
	if (!test_bit(id, used))
		return id;
	return find_first_zero_bit(used, 256);
}

static int __init io_apic_get_version(int ioapic)
{
	union IO_APIC_reg_01	reg_01;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioapic_lock, flags);
	reg_01.raw = io_apic_read(ioapic, 1);
	raw_spin_unlock_irqrestore(&ioapic_lock, flags);

	return reg_01.bits.version;
}

/*
 * This function currently is only a helper for the i386 smp boot process where
 * we need to reprogram the ioredtbls to cater for the cpus which have come online
 * so mask in all cases should simply be apic->target_cpus()
 */
#ifdef CONFIG_SMP
void __init_recv setup_ioapic_dest(void)
{
	int pin, ioapic, irq, irq_entry;
	const struct cpumask *mask;
	struct irq_data *idata;

	for (ioapic = 0; ioapic < nr_ioapics; ioapic++)
	for (pin = 0; pin < ioapics[ioapic].nr_registers; pin++) {
		irq_entry = find_irq_entry(ioapic, pin, mp_INT);
		if (irq_entry == -1)
			continue;
		irq = pin_2_irq(irq_entry, ioapic, pin);

		if ((ioapic > 0) && (irq > 16))
			continue;

		idata = irq_get_irq_data(irq);

		/*
		 * Honour affinities which have been set in early boot
		 */
		if (!irqd_can_balance(idata) || irqd_affinity_was_set(idata))
			mask = irq_data_get_affinity_mask(idata);
		else
			mask = apic->target_cpus();

		native_ioapic_set_affinity(idata, mask, false);
	}

}
#endif

int mp_find_ioapic(u32 gsi)
{
	int i = 0;

	if (nr_ioapics == 0)
		return -1;

	/* Find the IOAPIC that manages this GSI. */
	for (i = 0; i < nr_ioapics; i++) {
		struct mp_ioapic_gsi *gsi_cfg = mp_ioapic_gsi_routing(i);
		if ((gsi >= gsi_cfg->gsi_base)
		    && (gsi <= gsi_cfg->gsi_end))
			return i;
	}

	printk(KERN_ERR "ERROR: Unable to locate IOAPIC for GSI %d\n", gsi);
	return -1;
}

int mp_find_ioapic_pin(int ioapic, u32 gsi)
{
	struct mp_ioapic_gsi *gsi_cfg;

	if (WARN_ON(ioapic == -1))
		return -1;

	gsi_cfg = mp_ioapic_gsi_routing(ioapic);
	if (WARN_ON(gsi > gsi_cfg->gsi_end))
		return -1;

	return gsi - gsi_cfg->gsi_base;
}

static __init int bad_ioapic(unsigned long address)
{
	if (nr_ioapics >= MAX_IO_APICS) {
		pr_warn("WARNING: Max # of I/O APICs (%d) exceeded (found %d), skipping\n",
			MAX_IO_APICS, nr_ioapics);
		return 1;
	}
	if (!address) {
		pr_warn("WARNING: Bogus (zero) I/O APIC address found in table, skipping!\n");
		return 1;
	}
	return 0;
}

static __init int bad_ioapic_register(int idx)
{
	union IO_APIC_reg_00 reg_00;
	union IO_APIC_reg_01 reg_01;
	union IO_APIC_reg_02 reg_02;

	reg_00.raw = io_apic_read(idx, 0);
	reg_01.raw = io_apic_read(idx, 1);
	reg_02.raw = io_apic_read(idx, 2);

	if (reg_00.raw == -1 && reg_01.raw == -1 && reg_02.raw == -1) {
		pr_warn("I/O APIC 0x%lx registers return all ones, skipping!\n",
			mpc_ioapic_addr(idx));
		return 1;
	}

	return 0;
}

void __init mp_register_ioapic(int id, unsigned long address, u32 gsi_base)
{
	int idx = 0;
	int entries;
	struct mp_ioapic_gsi *gsi_cfg;

	if (bad_ioapic(address))
		return;

	idx = nr_ioapics;

	ioapics[idx].mp_config.type = MP_IOAPIC;
	ioapics[idx].mp_config.flags = MPC_APIC_USABLE;
	ioapics[idx].mp_config.apicaddr = address;

	if (bad_ioapic_register(idx)) {
		return;
	}

	ioapics[idx].mp_config.apicid = io_apic_unique_id(id);
	ioapics[idx].mp_config.apicver = io_apic_get_version(idx);

	/*
	 * Build basic GSI lookup table to facilitate gsi->io_apic lookups
	 * and to prevent reprogramming of IOAPIC pins (PCI GSIs).
	 */
	entries = io_apic_get_redir_entries(idx);
	gsi_cfg = mp_ioapic_gsi_routing(idx);
	gsi_cfg->gsi_base = gsi_base;
	gsi_cfg->gsi_end = gsi_base + entries - 1;

	/*
	 * The number of IO-APIC IRQ registers (== #pins):
	 */
	ioapics[idx].nr_registers = entries;

	if (gsi_cfg->gsi_end >= gsi_top)
		gsi_top = gsi_cfg->gsi_end + 1;

	pr_info("IOAPIC[%d]: apic_id %d, version %d, address 0x%lx, GSI %d-%d\n",
		idx, mpc_ioapic_id(idx),
		mpc_ioapic_ver(idx), mpc_ioapic_addr(idx),
		gsi_cfg->gsi_base, gsi_cfg->gsi_end);

	nr_ioapics++;
}

#if defined CONFIG_PCI_MSI && defined CONFIG_PCI_QUIRKS
#define MSI_LO_ADDRESS			0x48
#define MSI_HI_ADDRESS			0x4c


void  l_request_msi_addresses_window(struct pci_dev *pdev)
{
	u32 lo;
	u32 hi;
	u64 a;
	if (pdev->device != PCI_DEVICE_ID_MCST_I2C_SPI) {
		return;
	}
	if ((pdev->vendor != PCI_VENDOR_ID_ELBRUS) &&
		(pdev->vendor != PCI_VENDOR_ID_MCST_TMP)) {
		return;
	}
	/* this is the place where it's possible to insert resource for APIC
	 * MSI window address
	*/
	pci_read_config_dword(pdev, MSI_LO_ADDRESS, &lo);
	pci_read_config_dword(pdev, MSI_HI_ADDRESS, &hi);
	a = ((u64)hi << 32) | lo;
	if (__request_region(&iomem_resource, a, 0x100000, "MSI",
		IORESOURCE_MEM)) {
		pr_info("MSI window 0x%llx + 0x100000. Reserved\n", a);
	} else {
		pr_info("MSI window 0x%llx + 0x100000. Could not reserve\n", a);
	}
}

static void quirk_pci_msi(struct pci_dev *pdev)
{
	struct iohub_sysdata *sd = pdev->bus->sysdata;
	int gen, rev = pdev->revision;
	u64 address;

	if (pdev->device == PCI_DEVICE_ID_MCST_I2CSPI) {
		gen = 0;
		sd->iohub_generation = gen;
		sd->has_iohub = true;
		sd->iohub_revision = rev;
	} else if (pdev->device == PCI_DEVICE_ID_MCST_I2C_SPI) {
		gen = 1;
		sd->iohub_generation = gen;
		sd->has_iohub = true;
		sd->iohub_revision = rev;
	} else  {
		gen = 2;
		sd->eioh_generation = gen;
		sd->has_eioh = true;
		sd->eioh_revision = rev;
	}
	/*
	 * Use RT_MSI address instead of the address from IOAPIC BARs if:
	 * - IOHub2 is plugged into an EPIC machine
	 * - EIOHub is plugged into an APIC machine (paravirt. guest)
	 */
	if (cpu_has_epic() || paravirt_enabled()) {
		get_io_epic_msi(dev_to_node(&pdev->dev),
			 &sd->pci_msi_addr_lo, &sd->pci_msi_addr_hi);
	} else if (gen < 2) {
		pci_read_config_dword(pdev, MSI_LO_ADDRESS,
			&sd->pci_msi_addr_lo);
		pci_read_config_dword(pdev, MSI_HI_ADDRESS,
			&sd->pci_msi_addr_hi);
	}

	address = (u64) sd->pci_msi_addr_hi << 32 | sd->pci_msi_addr_lo;
	dev_info(&pdev->dev, "MSI address at: %llx; IOHUB generation: %d, "
		"revision: %x\n", address, gen, rev);
}
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_ELBRUS,
			  PCI_DEVICE_ID_MCST_I2CSPI, quirk_pci_msi);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MCST_TMP,
			  PCI_DEVICE_ID_MCST_I2C_SPI, quirk_pci_msi);
DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MCST_TMP,
			  PCI_DEVICE_ID_MCST_I2C_SPI_EPIC, quirk_pci_msi);

#elif defined CONFIG_PCI_MSI
#error		fixme
#endif	/*CONFIG_PCI_QUIRKS*/

unsigned int ioapic_cfg_get_pin(struct irq_cfg *cfg)
{
	return cfg->irq_2_pin->pin;
}

unsigned int ioapic_cfg_get_idx(struct irq_cfg *cfg)
{
	return cfg->irq_2_pin->apic;
}

void fixup_irqs_apic(void)
{
	unsigned int vector;

	/*
	 * We can remove mdelay() and then send spuriuous interrupts to
	 * new cpu targets for all the irqs that were handled previously by
	 * this cpu. While it works, I have seen spurious interrupt messages
	 * (nothing wrong but still...).
	 *
	 * So for now, retain mdelay(1) and check the IRR and then send those
	 * interrupts to new targets as this cpu is already offlined...
	 */
	mdelay(1);

	for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
		unsigned int irr;

		if (__this_cpu_read(vector_irq[vector]) < 0)
			continue;

		irr = apic_read(APIC_IRR + (vector / 32 * 0x10));
		if (irr  & (1 << (vector % 32))) {
			unsigned int irq = __this_cpu_read(vector_irq[vector]);
			struct irq_desc *desc = irq_to_desc(irq);
			struct irq_data *data = irq_desc_get_irq_data(desc);
			struct irq_chip *chip = irq_data_get_irq_chip(data);
			raw_spin_lock(&desc->lock);
			if (chip->irq_retrigger)
				chip->irq_retrigger(data);
			raw_spin_unlock(&desc->lock);
		}
		__this_cpu_write(vector_irq[vector], -1);
	}
}
