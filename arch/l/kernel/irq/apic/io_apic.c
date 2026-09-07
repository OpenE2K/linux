/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/mm.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irq.h>
#include <linux/init.h>
#include <linux/delay.h>
#include <linux/sched.h>
#include <linux/compiler.h>
#include <linux/acpi.h>
#include <linux/export.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>	/* time_after() */
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/msi.h>
#include <asm/pic.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>

#include "apic.h"
#include "io_apic.h"
#include "apic-msidef.h"
#include "../io_pic.h"
#include "../epic/io_epic_regs.h"

static void ioapic_configure_entry(struct irq_data *irqd);

struct ioapic_chip_data {
	struct iopic_chip_data d;
	struct IO_APIC_route_entry entry;
};

struct io_apic {
	unsigned int index;
	unsigned int unused[3];
	unsigned int data;
	unsigned int unused2[11];
	unsigned int eoi;
};

static struct io_apic __iomem *io_apic_base(struct iopic *apic)
{
	return apic->regs;
}

static inline void io_apic_eoi(struct iopic *apic, unsigned int vector)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);
	writel(vector, &io_apic->eoi);
}

static unsigned int io_apic_read(struct iopic *apic, unsigned int reg)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);
	lockdep_assert_held(&apic->lock);
	writel(reg, &io_apic->index);
	return readl(&io_apic->data);
}

static void io_apic_write(struct iopic *apic, unsigned int reg,
			  unsigned int value)
{
	struct io_apic __iomem *io_apic = io_apic_base(apic);
	lockdep_assert_held(&apic->lock);

	writel(reg, &io_apic->index);
	writel(value, &io_apic->data);
}

static struct IO_APIC_route_entry __ioapic_read_entry(struct iopic *apic, int pin)
{
	return (struct IO_APIC_route_entry) {
		.w1 = io_apic_read(apic, 0x10 + 2 * pin),
		.w2 = io_apic_read(apic, 0x11 + 2 * pin),
	};
}

static struct IO_APIC_route_entry ioapic_read_entry(struct iopic *apic, int pin)
{
	struct IO_APIC_route_entry entry;
	unsigned long flags;

	raw_spin_lock_irqsave(&apic->lock, flags);
	entry = __ioapic_read_entry(apic, pin);
	raw_spin_unlock_irqrestore(&apic->lock, flags);

	return entry;
}

/*
 * When we write a new IO APIC routing entry, we need to write the high
 * word first! If the mask bit in the low word is clear, we will enable
 * the interrupt, and we need to make sure the entry is fully populated
 * before that happens.
 */
static void __ioapic_write_entry(struct iopic *apic, int pin, struct IO_APIC_route_entry e)
{
	io_apic_write(apic, 0x11 + 2 * pin, e.w2);
	io_apic_write(apic, 0x10 + 2 * pin, e.w1);
}

static void ioapic_write_entry(struct iopic *apic, int pin, struct IO_APIC_route_entry e)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&apic->lock, flags);
	__ioapic_write_entry(apic, pin, e);
	raw_spin_unlock_irqrestore(&apic->lock, flags);
}

static void io_apic_modify_irq(struct ioapic_chip_data *data, bool masked,
			       void (*final)(struct ioapic_chip_data *data))
{
	data->entry.masked = masked;

	io_apic_write(data->d.pic, 0x10 + 2 * data->d.pin, data->entry.w1);
	if (final)
		final(data);
}

static void io_apic_sync(struct ioapic_chip_data *data)
{
	/*
	 * Synchronize the IO-APIC and the CPU by doing
	 * a dummy read from the IO-APIC
	 */
	struct io_apic __iomem *io_apic;

	io_apic = io_apic_base(data->d.pic);
	readl(&io_apic->data);
}

static void mask_ioapic_irq(struct irq_data *irqd)
{
	unsigned long flags;
	struct ioapic_chip_data *data = irqd->chip_data;
	struct iopic *apic = data->d.pic;

	raw_spin_lock_irqsave(&apic->lock, flags);
	io_apic_modify_irq(data, true, &io_apic_sync);
	raw_spin_unlock_irqrestore(&apic->lock, flags);
}

static void __unmask_ioapic(struct ioapic_chip_data *data)
{
	io_apic_modify_irq(data, false, NULL);
}

static void unmask_ioapic_irq(struct irq_data *irqd)
{
	unsigned long flags;
	struct ioapic_chip_data *data = irqd->chip_data;
	struct iopic *apic = data->d.pic;

	raw_spin_lock_irqsave(&apic->lock, flags);
	__unmask_ioapic(data);
	raw_spin_unlock_irqrestore(&apic->lock, flags);
}

static void io_apic_print_entries(struct iopic *pic)
{
	int pin;

	pr_info(" NR Dst Mask Level IRR Pol Stat Dmod Deli Vect:\n");

	for_each_iopic_pin(pic, pin) {
		struct IO_APIC_route_entry entry = ioapic_read_entry(pic, pin);
		pr_info(" %02x %02X  %1d    %1d     %1d   %1d   %1d    %1d    %1d    %02X\n",
			pin, entry.destid_0_7, entry.masked, entry.is_level,
			entry.irr, entry.active_low, entry.delivery_status,
			entry.dest_mode_logical, entry.delivery_mode, entry.vector);
	}
}

void print_IO_APIC(struct iopic *pic)
{
	union IO_APIC_reg_00 reg_00;
	union IO_APIC_reg_01 reg_01;
	union IO_APIC_reg_02 reg_02;
	union IO_APIC_reg_03 reg_03;
	unsigned long flags;

	raw_spin_lock_irqsave(&pic->lock, flags);
	reg_00.raw = io_apic_read(pic, 0);
	reg_01.raw = io_apic_read(pic, 1);
	if (reg_01.bits.version >= 0x10)
		reg_02.raw = io_apic_read(pic, 2);
	if (reg_01.bits.version >= 0x20)
		reg_03.raw = io_apic_read(pic, 3);
	raw_spin_unlock_irqrestore(&pic->lock, flags);

	pr_info("IO-APIC #%d......\n", pic->id);
	pr_info(".... register #00: %08X\n", reg_00.raw);
	pr_info(".......    : physical APIC id: %02X\n", reg_00.bits.ID);
	pr_info(".......    : Delivery Type: %X\n", reg_00.bits.delivery_type);
	pr_info(".......    : LTS          : %X\n", reg_00.bits.LTS);
	pr_info(".... register #01: %08X\n", *(int *)&reg_01);
	pr_info(".......     : max redirection entries: %02X\n", reg_01.bits.entries);
	pr_info(".......     : PRQ implemented: %X\n", reg_01.bits.PRQ);
	pr_info(".......     : IO APIC version: %02X\n", reg_01.bits.version);

	if (reg_01.bits.version >= 0x10) {
		pr_info(".... register #02: %08X\n", reg_02.raw);
		pr_info(".......     : arbitration: %02X\n", reg_02.bits.arbitration);
	}

	if (reg_01.bits.version >= 0x20) {
		pr_info(".... register #03: %08X\n", reg_03.raw);
		pr_info(".......     : Boot DT    : %X\n", reg_03.bits.boot_DT);
	}

	pr_info(".... IRQ redirection table:\n");

	io_apic_print_entries(pic);
}

#ifdef CONFIG_PM
static int save_ioapic_entries(struct iopic *pic)
{
	int pin;
	struct IO_APIC_route_entry *saved_registers = pic->saved_registers;

	if (!saved_registers)
		return -ENOMEM;

	for_each_iopic_pin(pic, pin)
		saved_registers[pin] = ioapic_read_entry(pic, pin);

	return 0;
}

/*
 * Restore IO APIC entries which was saved in the ioapic structure.
 */
static int restore_ioapic_entries(struct iopic *pic)
{
	int pin;
	struct IO_APIC_route_entry *saved_registers = pic->saved_registers;

	if (!saved_registers)
		return 0;

	for_each_iopic_pin(pic, pin)
		ioapic_write_entry(pic, pin, saved_registers[pin]);

	return 0;
}
#endif

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
static unsigned int startup_ioapic_irq(struct irq_data *irqd)
{
	ioapic_configure_entry(irqd);
	return 0;
}

atomic_t irq_mis_count;

#ifdef CONFIG_GENERIC_PENDING_IRQ
static bool io_apic_level_ack_pending(struct ioapic_chip_data *data)
{
	unsigned long flags;
	struct IO_APIC_route_entry e;
	int pin;
	struct iopic *apic = data->d.pic;

	raw_spin_lock_irqsave(&apic->lock, flags);
	pin = data->d.pin;
	e.w1 = io_apic_read(data->d.pic, 0x10 + pin*2);
	/* Is the remote IRR bit set? */
	if (e.irr) {
		raw_spin_unlock_irqrestore(&apic->lock, flags);
		return true;
	}
	raw_spin_unlock_irqrestore(&apic->lock, flags);

	return false;
}

static inline bool ioapic_prepare_move(struct irq_data *irqd)
{
	/* If we are moving the IRQ we need to mask it */
	if (unlikely(irqd_is_setaffinity_pending(irqd))) {
		if (!irqd_irq_masked(irqd))
			mask_ioapic_irq(irqd);
		return true;
	}
	return false;
}

static inline void ioapic_finish_move(struct irq_data *irqd, bool moveit)
{
	if (unlikely(moveit)) {
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
		 * completely accurate.
		 *
		 * However there appears to be no other way to plug
		 * this race, so if the Remote IRR bit is not
		 * accurate and is causing problems then it is a hardware bug
		 * and you can go talk to the chipset vendor about it.
		 */
		if (!io_apic_level_ack_pending(irqd->chip_data))
			irq_move_masked_irq(irqd);
		/* If the IRQ is masked in the core, leave it: */
		if (!irqd_irq_masked(irqd))
			unmask_ioapic_irq(irqd);
	}
}
#else
static inline bool ioapic_prepare_move(struct irq_data *irqd)
{
	return false;
}
static inline void ioapic_finish_move(struct irq_data *irqd, bool moveit)
{
}
#endif

static void epic_ioapic_eoi(int node, u8 vector)
{
	unsigned v = (vector << 8) | 0x5;
	/*
	 * To send a message from CEPIC to IOAPIC we need to write HC_IOAPIC_EOI
	 * SIC register
	 */
	sic_write_node_nbsr_reg(node, SIC_hc_ioapic_eoi, v);
}

static void ioapic_ack_level(struct irq_data *irqd)
{
	struct irq_cfg *cfg = irqd_cfg(irqd);
	struct irq_data *pd = irqd->parent_data;
	bool moveit;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);

	irq_complete_move(cfg);
	moveit = ioapic_prepare_move(irqd);

	/*
	 * We must acknowledge the irq before we move it or the acknowledge will
	 * not propagate properly.
	 */
	pd->chip->irq_eoi(pd);

	if (cpu_has_epic()) {
		struct ioapic_chip_data *data = irqd->chip_data;
		struct iopic *pic = data->d.pic;
		epic_ioapic_eoi(pic->node, cfg->vector);
	}
	ioapic_finish_move(irqd, moveit);
}

/*
 * The I/OAPIC is just a device for generating MSI messages from legacy
 * interrupt pins. Various fields of the RTE translate into bits of the
 * resulting MSI which had a historical meaning.
 *
 * With interrupt remapping, many of those bits have different meanings
 * in the underlying MSI, but the way that the I/OAPIC transforms them
 * from its RTE to the MSI message is the same. This function allows
 * the parent IRQ dmn to compose the MSI message, then takes the
 * relevant bits to put them in the appropriate places in the RTE in
 * order to generate that message when the IRQ happens.
 *
 * The setup here relies on a preconfigured route entry (is_level,
 * active_low, masked) because the parent dmn is merely composing the
 * generic message routing information which is used for the MSI.
 */
static void ioapic_setup_msg_from_msi(struct irq_data *irqd,
				      struct IO_APIC_route_entry *e)
{
	struct msi_msg msg;

	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);
	irq_chip_compose_msi_msg(irqd, &msg);

	if (cpu_has_epic()) {
		union IO_EPIC_MSG_ADDR_LOW *lo = (void *)&msg.address_lo;
		union IO_EPIC_MSG_DATA *d = (void *)&msg.data;
		WARN_ONCE(lo->dst > 0xff, "hw bug 170189:ioapic: iohub2 interrupts can be handled only by processor 0");
		WARN_ONCE(d->vector > 0xff, "ioapic: vector number to big: %d", d->vector);

		e->vector		= d->vector;
		e->delivery_mode	= d->dlvm;
		e->dest_mode_logical	= 0;
		e->destid_0_7		= lo->dst;
	} else {
		ioapic_msi_msg_addr_lo_t *lo = (void *)&msg.address_lo;
		ioapic_msi_msg_data_t *d = (void *)&msg.data;

		e->vector		= d->vector;
		e->delivery_mode	= d->delivery_mode;
		e->dest_mode_logical	= lo->dest_mode_logical;
		e->destid_0_7		= lo->destid_0_7;
	}
}

static void __ioapic_configure_entry(struct irq_data *irqd)
{
	unsigned long flags;
	struct ioapic_chip_data *data = irqd->chip_data;
	struct iopic *pic = data->d.pic;
	ioapic_setup_msg_from_msi(irqd, &data->entry);

	raw_spin_lock_irqsave(&pic->lock, flags);
	__ioapic_write_entry(pic, data->d.pin, data->entry);
	raw_spin_unlock_irqrestore(&pic->lock, flags);
}

static void ioapic_configure_entry(struct irq_data *irqd)
{
	struct ioapic_chip_data *data = irqd->chip_data;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);
	data->entry.masked = false;
	__ioapic_configure_entry(irqd);
}

static int ioapic_set_affinity(struct irq_data *irqd,
			       const struct cpumask *mask, bool force)
{
	int ret;
	struct irq_data *parent = irqd->parent_data;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret >= 0 && ret != IRQ_SET_MASK_OK_DONE)
		__ioapic_configure_entry(irqd);

	return ret;
}

static int ioapic_irq_set_type(struct irq_data *d, unsigned int flow_type)
{
	irq_flow_handler_t hdl;
	bool fasteoi;
	struct ioapic_chip_data *data = d->chip_data;
	struct IO_APIC_route_entry *entry = &data->entry;

	switch (flow_type) {
	case IRQF_TRIGGER_LOW:
		entry->is_level = true;
		entry->active_low = true;
		break;
	case IRQF_TRIGGER_HIGH:
		entry->is_level = true;
		entry->active_low = false;
		break;
	case IRQF_TRIGGER_FALLING:
		entry->is_level = false;
		entry->active_low = false;
		break;
	case IRQF_TRIGGER_RISING:
		entry->is_level = false;
		entry->active_low = true;
		break;
	}
	if (entry->is_level)
		fasteoi = true;
	else
		fasteoi = false;

	hdl = fasteoi ? handle_fasteoi_irq : handle_edge_irq;
	irq_set_handler_locked(d, hdl);
	return 0;
}
/*
 * Interrupt shutdown masks the ioapic pin, but the interrupt might already
 * be in flight, but not yet serviced by the target CPU. That means
 * __synchronize_hardirq() would return and claim that everything is calmed
 * down. So free_irq() would proceed and deactivate the interrupt and free
 * resources.
 *
 * Once the target CPU comes around to service it it will find a cleared
 * vector and complain. While the spurious interrupt is harmless, the full
 * release of resources might prevent the interrupt from being acknowledged
 * which keeps the hardware in a weird state.
 *
 * Verify that the corresponding Remote-IRR bits are clear.
 */
static int ioapic_irq_get_chip_state(struct irq_data *irqd,
				   enum irqchip_irq_state which,
				   bool *state)
{
	struct ioapic_chip_data *p = irqd->chip_data;
	struct iopic *apic = p->d.pic;
	struct IO_APIC_route_entry rentry;

	if (which != IRQCHIP_STATE_ACTIVE)
		return -EINVAL;

	*state = false;
	raw_spin_lock(&apic->lock);
	rentry = __ioapic_read_entry(apic, p->d.pin);
	/*
	* The remote IRR is only valid in level trigger mode. It's
	* meaning is undefined for edge triggered interrupts and
	* irrelevant because the IO-APIC treats them as fire and
	* forget.
	*/
	if (rentry.irr && rentry.is_level)
		*state = true;
	raw_spin_unlock(&apic->lock);
	return 0;
}

static void ioapic_compose_msi_msg(struct irq_data *irqd,
				       struct msi_msg *msg)
{
	u32 lo = 0;
	ioapic_msi_msg_addr_lo_t *l = (void *)&msg->address_lo;
	int node = of_node_to_nid(to_of_node(irqd->domain->fwnode));

	WARN_ON_ONCE(!is_of_node(irqd->domain->fwnode));
	WARN_ON_ONCE(node >= 0 && !iohub_online(node));

	/* Let the parent dmn compose the MSI message */
	irq_chip_compose_msi_msg(irqd->parent_data, msg);

	get_io_pic_msi(node, &lo, &msg->address_hi);
	l->base_address = lo >> 20;
}

static struct irq_chip ioapic_chip __read_mostly = {
	.name			= "IO-APIC",
	.irq_startup		= startup_ioapic_irq,
	.irq_mask		= mask_ioapic_irq,
	.irq_unmask		= unmask_ioapic_irq,
	.irq_compose_msi_msg	= ioapic_compose_msi_msg,
	.irq_set_type		= ioapic_irq_set_type,
	.irq_ack		= irq_chip_ack_parent,
	.irq_eoi		= ioapic_ack_level,
	.irq_set_affinity	= ioapic_set_affinity,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_get_irqchip_state	= ioapic_irq_get_chip_state,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_AFFINITY_PRE_STARTUP,
};

#ifdef CONFIG_PM
static void resume_ioapic_id(struct iopic *apic)
{
	unsigned long flags;
	union IO_APIC_reg_00 reg_00;

	raw_spin_lock_irqsave(&apic->lock, flags);
	reg_00.raw = io_apic_read(apic, 0);
	if (reg_00.bits.ID != apic->id) {
		reg_00.bits.ID = apic->id;
		io_apic_write(apic, 0, reg_00.raw);
	}
	raw_spin_unlock_irqrestore(&apic->lock, flags);
}

static int ioapic_suspend(struct iopic *pic)
{
	return save_ioapic_entries(pic);
}

static void ioapic_resume(struct iopic *pic)
{
	resume_ioapic_id(pic);
	restore_ioapic_entries(pic);
}
#endif /* CONFIG_PM */

static int ioapic_get_redir_entries(struct iopic *apic)
{
	union IO_APIC_reg_01	reg_01;
	unsigned long flags;

	raw_spin_lock_irqsave(&apic->lock, flags);
	reg_01.raw = io_apic_read(apic, 1);
	raw_spin_unlock_irqrestore(&apic->lock, flags);

	/* The register returns the maximum index redir index
	 * supported, which is one less than the total number of redir
	 * entries.
	 */
	return reg_01.bits.entries + 1;
}

static int ioapic_get_id(struct iopic *apic)
{
	unsigned long flags;
	union IO_APIC_reg_00 reg_00;

	raw_spin_lock_irqsave(&apic->lock, flags);
	reg_00.raw = io_apic_read(apic, 0);
	raw_spin_unlock_irqrestore(&apic->lock, flags);
	return reg_00.bits.ID;
}

static int ioapic_get_version(struct iopic *apic)
{
	union IO_APIC_reg_01	reg_01;
	unsigned long flags;

	raw_spin_lock_irqsave(&apic->lock, flags);
	reg_01.raw = io_apic_read(apic, 1);
	raw_spin_unlock_irqrestore(&apic->lock, flags);

	return reg_01.bits.version;
}

static void ioapic_get_id_ver_pins(struct iopic *apic,
			int *id, int *version, int *pins)
{
	*id      = ioapic_get_id(apic);
	*version = ioapic_get_version(apic);
	*pins    = ioapic_get_redir_entries(apic);
}

static void ioapic_set_id(struct iopic *apic, int id)
{
	unsigned long flags;
	union IO_APIC_reg_00 reg_00;

	raw_spin_lock_irqsave(&apic->lock, flags);
	reg_00.raw = io_apic_read(apic, 0);

	reg_00.bits.ID = id;
	io_apic_write(apic, 0, reg_00.raw);

	raw_spin_unlock_irqrestore(&apic->lock, flags);
}

static void eoi_ioapic_pin(struct iopic *apic, int pin)
{
	struct IO_APIC_route_entry entry, entry1;

	entry = __ioapic_read_entry(apic, pin);
	entry1 = entry;

	/* Mask the entry and change the trigger mode to edge. */
	entry1.masked = true;
	entry1.is_level = false;

	__ioapic_write_entry(apic, pin, entry1);

	/* Restore the previous level triggered entry. */
	__ioapic_write_entry(apic, pin, entry);
}

static void ioapic_reset_pin(struct iopic *apic, unsigned int pin)
{
	struct IO_APIC_route_entry entry;

	/* Check delivery_mode to be sure we're not clearing an SMI pin */
	entry = ioapic_read_entry(apic, pin);
	if (entry.delivery_mode == APIC_DELIVERY_MODE_SMI)
		return;

	/*
	 * Make sure the entry is masked and re-read the contents to check
	 * if it is a level triggered pin and if the remote-IRR is set.
	 */
	if (!entry.masked) {
		entry.masked = true;
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
		if (!entry.is_level) {
			entry.is_level = true;
			ioapic_write_entry(apic, pin, entry);
		}
		raw_spin_lock_irqsave(&apic->lock, flags);
		eoi_ioapic_pin(apic, pin);
		raw_spin_unlock_irqrestore(&apic->lock, flags);
	}

	/*
	 * Clear the rest of the bits in the IO-APIC RTE except for the mask
	 * bit.
	 */
	struct IO_APIC_route_entry e = { .masked = true };
	ioapic_write_entry(apic, pin, e);
	entry = ioapic_read_entry(apic, pin);
	if (entry.irr)
		pr_err("Unable to reset IRR for apic: %d, pin :%d\n",
		       apic->id, pin);
}

static void ioapic_reset(struct iopic *apic)
{
	unsigned int pin;

	for_each_iopic_pin(apic, pin) {
		ioapic_reset_pin(apic, pin);
	}
}

struct iopic_chip iopic_ioapic_chip = {
#ifdef CONFIG_PM
	.iopic_suspend		= ioapic_suspend,
	.iopic_resume		= ioapic_resume,
#endif
	.iopic_get_id_ver_pins	= ioapic_get_id_ver_pins,
	.iopic_set_id		= ioapic_set_id,
	.iopic_reset		= ioapic_reset,
	.iopic_chip		= &ioapic_chip,
	.iopic_sizeof_entry	= sizeof(struct IO_APIC_route_entry),
};

