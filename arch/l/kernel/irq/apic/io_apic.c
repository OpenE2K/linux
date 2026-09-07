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
#include <linux/syscore_ops.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>	/* time_after() */
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/msi.h>

#include "apic.h"
#include "io_apic.h"
#include "apic-msidef.h"
#include "../io_pic.h"

static void ioapic_configure_entry(struct irq_data *irqd);

#define	for_each_pin(apic, pin)		\
	for ((pin) = 0; (pin) < apic->nr_pins; (pin)++)

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
	struct IO_APIC_route_entry entry;

	entry.w1 = io_apic_read(apic, 0x10 + 2 * pin);
	entry.w2 = io_apic_read(apic, 0x11 + 2 * pin);

	return entry;
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
	io_apic_write(apic, 0x11 + 2*pin, e.w2);
	io_apic_write(apic, 0x10 + 2*pin, e.w1);
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

static void __eoi_ioapic_pin(struct iopic *apic, int pin, int vector)
{
	io_apic_eoi(apic, vector);

}

static void eoi_ioapic_pin(int vector, struct ioapic_chip_data *data)
{
	unsigned long flags;
	struct iopic *apic = data->d.pic;
	raw_spin_lock_irqsave(&apic->lock, flags);
	__eoi_ioapic_pin(data->d.pic, data->d.pin, vector);
	raw_spin_unlock_irqrestore(&apic->lock, flags);
}
static int save_ioapic_entries(struct device *dev)
{
	int pin;
	int err = 0;
	struct iopic *apic = dev_get_drvdata(dev);
	struct IO_APIC_route_entry *saved_registers = apic->saved_registers;

	if (!saved_registers) {
		err = -ENOMEM;
		goto err;
	}

	for_each_pin(apic, pin)
		saved_registers[pin] =
			ioapic_read_entry(apic, pin);
err:
	return err;
}

/*
 * Restore IO APIC entries which was saved in the ioapic structure.
 */
static int restore_ioapic_entries(struct iopic *apic)
{
	int pin;
	struct IO_APIC_route_entry *saved_registers = apic->saved_registers;

	if (!saved_registers)
		return 0;

	for_each_pin(apic, pin)
		ioapic_write_entry(apic, pin,
					saved_registers[pin]);

	return 0;
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

static void ioapic_ack_level(struct irq_data *irqd)
{
	struct irq_cfg *cfg = irqd_cfg(irqd);
	unsigned long v;
	bool moveit;
	int i;

	irq_complete_move(cfg);
	moveit = ioapic_prepare_move(irqd);

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

	/*
	 * We must acknowledge the irq before we move it or the acknowledge will
	 * not propagate properly.
	 */
	ack_APIC_irq();

	/*
	 * Tail end of clearing remote IRR bit (either by delivering the EOI
	 * message via io-apic EOI register write or simulating it using
	 * mask+edge followed by unmask+level logic) manually when the
	 * level triggered interrupt is seen as the edge triggered interrupt
	 * at the cpu.
	 */
	if (!(v & (1 << (i & 0x1f)))) {
		atomic_inc(&irq_mis_count);
		eoi_ioapic_pin(cfg->vector, irqd->chip_data);
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
				      struct IO_APIC_route_entry *entry)
{
	struct msi_msg msg;
	ioapic_msi_msg_addr_lo_t *lo = (ioapic_msi_msg_addr_lo_t *)&msg.address_lo;
	ioapic_msi_msg_data_t *d = (ioapic_msi_msg_data_t *)&msg.data;

	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);

	/* Let the parent dmn compose the MSI message */
	irq_chip_compose_msi_msg(irqd, &msg);

	entry->vector			= d->vector;
	entry->delivery_mode		= d->delivery_mode;
	entry->dest_mode_logical	= lo->dest_mode_logical;
	entry->destid_0_7		= lo->destid_0_7;
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

struct irq_chip ioapic_chip __read_mostly = {
	.name			= "IO-APIC",
	.irq_startup		= startup_ioapic_irq,
	.irq_mask		= mask_ioapic_irq,
	.irq_unmask		= unmask_ioapic_irq,
	.irq_set_type		= ioapic_irq_set_type,
	.irq_ack		= irq_chip_ack_parent,
	.irq_eoi		= ioapic_ack_level,
	.irq_set_affinity	= ioapic_set_affinity,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_get_irqchip_state	= ioapic_irq_get_chip_state,
	.flags			= IRQCHIP_SKIP_SET_WAKE |
				  IRQCHIP_AFFINITY_PRE_STARTUP,
};

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

static int ioapic_resume(struct device *dev)
{
	struct iopic *apic = dev_get_drvdata(dev);
	resume_ioapic_id(apic);
	restore_ioapic_entries(apic);
	return 0;
}


static const struct dev_pm_ops ioapic_pm_ops = {
	SET_RUNTIME_PM_OPS(save_ioapic_entries,
			   ioapic_resume, NULL)
};

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

struct iopic_chip iopic_ioapic_chip = {
	.iopic_get_id_ver_pins = ioapic_get_id_ver_pins,
	.iopic_chip = &ioapic_chip,
	.iopic_sizeof_entry = sizeof(struct IO_APIC_route_entry),
};

