/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * IO-EPIC support
 */

#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irq.h>
#include <linux/pci.h>

#include "../io_pic.h"
#include "../pic.h"
#include "epic.h"
#include "io_epic.h"
#include "io_epic_regs.h"

struct ioepic_chip_data {
	struct iopic_chip_data d; /*must be the first*/
	struct IO_EPIC_route_entry entry;
};

static void   mask_ioepic_irq(struct irq_data *irqd);
static void unmask_ioepic_irq(struct irq_data *irqd);

static void __iomem *io_epic_base(struct iopic *pic)
{
	return pic->regs;
}

static unsigned int io_epic_read(struct iopic *pic, unsigned int reg)
{
	void __iomem *io_epic = io_epic_base(pic);
	return readl(io_epic + reg);
}

static void io_epic_write(struct iopic *pic, unsigned int reg,
			  unsigned int value)
{
	void __iomem *io_epic = io_epic_base(pic);
	writel(value, io_epic + reg);
}

static void io_epic_modify_irq(struct ioepic_chip_data *d, bool masked,
			       void (*final)(struct ioepic_chip_data *data))
{
	d->entry.int_ctrl.mask = masked;

	io_epic_write(d->d.pic, IOEPIC_TABLE_INT_CTRL(d->d.pin),
		      d->entry.int_ctrl.raw);
	if (final)
		final(d);
}

static void io_epic_sync(struct ioepic_chip_data *data)
{
	/*
	 * Synchronize the IO-APIC and the CPU by doing
	 * a dummy read from the IO-APIC
	 */
	void __iomem *io_epic;

	io_epic = io_epic_base(data->d.pic);
	readl(io_epic);
}

static void __unmask_ioepic(struct ioepic_chip_data *data)
{
	io_epic_modify_irq(data, false, NULL);
}

union io_epic_entry_union {
	struct { u32 w1, w2, w3, w4, w5; };
	struct IO_EPIC_route_entry entry;
};

static void __ioepic_write_entry(struct iopic *pic,
			int pin, struct IO_EPIC_route_entry e)
{

	union io_epic_entry_union eu;
	union IO_EPIC_INT_CTRL reg;

	reg.raw = 0;
	reg.mask = 1;
	io_epic_write(pic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	eu.entry = e;
	io_epic_write(pic, IOEPIC_TABLE_MSG_DATA(pin), eu.w2);
	io_epic_write(pic, IOEPIC_TABLE_ADDR_HIGH(pin), eu.w3);
	io_epic_write(pic, IOEPIC_TABLE_ADDR_LOW(pin), eu.w4);
	io_epic_write(pic, IOEPIC_INT_RID(pin), eu.w5);

	reg.raw = eu.w1;
	/* do not reset RWC1 bits */
	reg.delivery_status = 0;
	reg.software_int = 0;

	io_epic_write(pic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);
}

struct pci_dev *__of_find_pci_device_by_node(struct device_node *np)
{
	struct pci_dev *pdev = NULL;

	for_each_pci_dev(pdev) {
		if (pdev->dev.of_node == np)
			break;
	}
	return pdev;
}

struct pci_dev *of_find_pci_device_by_node(struct device_node *np)
{
	struct pci_dev *pdev = NULL;
	while (np) {
		pdev = __of_find_pci_device_by_node(np);
		if (pdev)
			break;
		np = np->parent;
	}
	return pdev;
}

static int ioepic_setup_msg_from_msi(struct irq_data *irqd,
				      struct IO_EPIC_route_entry *e)
{
	struct msi_msg msg;
	struct irq_desc *desc = irq_data_to_desc(irqd);
	lockdep_assert_held(&desc->lock);

	/* Let the parent dmn compose the MSI message */
	irq_chip_compose_msi_msg(irqd, &msg);

	e->addr_high	= msg.address_hi;
	e->addr_low.raw	= msg.address_lo;
	e->msg_data.raw	= msg.data;
	return 0;
}

static void __ioepic_configure_entry(struct irq_data *irqd)
{
	struct ioepic_chip_data *data = irqd->chip_data;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);

	ioepic_setup_msg_from_msi(irqd, &data->entry);
	__ioepic_write_entry(data->d.pic, data->d.pin, data->entry);
}

static void ioepic_configure_entry(struct irq_data *irqd)
{
	struct ioepic_chip_data *data = irqd->chip_data;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);
	data->entry.int_ctrl.mask = false;
	__ioepic_configure_entry(irqd);
}

static bool ioepic_has_fast_eoi(struct iopic *pic)
{
	return pic->version >= IOEPIC_VERSION_2;
}

static void ioepic_level_eoi_slow(struct iopic *pic, int pin)
{
	union IO_EPIC_INT_CTRL reg;

	reg.raw = io_epic_read(pic, IOEPIC_TABLE_INT_CTRL(pin));
	reg.delivery_status = 1;
	io_epic_write(pic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);
}

/* Writing W1C bits of int_ctrl does not change the RW bits (IOEPIC version 2) */
static void ioepic_level_eoi_fast(struct iopic *pic, int pin)
{
	union IO_EPIC_INT_CTRL reg;

	reg.raw = 0;
	reg.delivery_status = 1;
	io_epic_write(pic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);
}


static void ioepic_level_eoi(struct iopic *pic, int pin)
{
	if (ioepic_has_fast_eoi(pic))
		ioepic_level_eoi_fast(pic, pin);
	else
		ioepic_level_eoi_slow(pic, pin);
}

#ifdef CONFIG_GENERIC_PENDING_IRQ
static bool io_epic_level_ack_pending(struct ioepic_chip_data *data)
{
	bool ret = false;
	union IO_EPIC_INT_CTRL reg;
	struct iopic *pic = data->d.pic;

	reg.raw = io_epic_read(pic, IOEPIC_TABLE_INT_CTRL(data->d.pin));
	/* Is the remote IRR bit set? */
	if (reg.delivery_status)
		ret = true;
	return ret;
}

static inline bool ioepic_prepare_move(struct irq_data *irqd)
{
	/* If we are moving the IRQ we need to mask it */
	if (unlikely(irqd_is_setaffinity_pending(irqd))) {
		if (!irqd_irq_masked(irqd))
			mask_ioepic_irq(irqd);
		return true;
	}
	return false;
}

static inline void ioepic_finish_move(struct irq_data *irqd, bool moveit)
{
	if (unlikely(moveit)) {
		/* Only migrate the irq if the ack has been received.
		 *
		 * On rare occasions the broadcast level triggered ack gets
		 * delayed going to ioepics, and if we reprogram the
		 * vector while Remote IRR is still set the irq will never
		 * fire again.
		 *
		 * To prevent this scenario we read the Remote IRR bit
		 * of the ioepic.  This has two effects.
		 * - On any sane system the read of the ioepic will
		 *   flush writes (and acks) going to the ioepic from
		 *   this cpu.
		 * - We get to see if the ACK has actually been delivered.
		 *
		 * Based on failed experiments of reprogramming the
		 * ioepic entry from outside of irq context starting
		 * with masking the ioepic entry and then polling until
		 * Remote IRR was clear before reprogramming the
		 * ioepic I don't trust the Remote IRR bit to be
		 * completely accurate.
		 *
		 * However there appears to be no other way to plug
		 * this race, so if the Remote IRR bit is not
		 * accurate and is causing problems then it is a hardware bug
		 * and you can go talk to the chipset vendor about it.
		 */
		if (!io_epic_level_ack_pending(irqd->chip_data))
			irq_move_masked_irq(irqd);
		/* If the IRQ is masked in the core, leave it: */
		if (!irqd_irq_masked(irqd))
			unmask_ioepic_irq(irqd);
	}
}
#else
static inline bool ioepic_prepare_move(struct irq_data *irqd)
{
	return false;
}
static inline void ioepic_finish_move(struct irq_data *irqd, bool moveit)
{
}
#endif

/*struct irq_chip callbacks */


static void ioepic_ack_level(struct irq_data *irqd)
{
	struct irq_cfg *cfg = irqd_cfg(irqd);
	struct ioepic_chip_data *data = irqd->chip_data;
	struct iopic *pic = data->d.pic;
	bool moveit;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);
	irq_complete_move(cfg);
	moveit = ioepic_prepare_move(irqd);

	ack_epic_irq();
	ioepic_level_eoi(pic, data->d.pin);

	ioepic_finish_move(irqd, moveit);
}

static void mask_ioepic_irq(struct irq_data *irqd)
{
	struct ioepic_chip_data *data = irqd->chip_data;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);
	io_epic_modify_irq(data, true, &io_epic_sync);
}

static void unmask_ioepic_irq(struct irq_data *irqd)
{
	struct ioepic_chip_data *data = irqd->chip_data;
	lockdep_assert_held(&irq_data_to_desc(irqd)->lock);
	__unmask_ioepic(data);
}

static int ioepic_irq_set_type(struct irq_data *d, unsigned int flow_type)
{
	irq_flow_handler_t hdl;
	bool fasteoi;
	struct ioepic_chip_data *data = d->chip_data;
	struct IO_EPIC_route_entry *entry = &data->entry;

	switch (flow_type) {
	case IRQF_TRIGGER_HIGH:
		entry->int_ctrl.trigger = true;
		break;
	case IRQF_TRIGGER_RISING:
		entry->int_ctrl.trigger = false;
		break;
	default:
		pr_err("invalid type %d for irq %ld\n",
			flow_type, d->hwirq);
		return -EINVAL;
	}
	if (entry->int_ctrl.trigger)
		fasteoi = true;
	else
		fasteoi = false;

	hdl = fasteoi ? handle_fasteoi_irq : handle_edge_irq;
	irq_set_handler_locked(d, hdl);
	return 0;
}

static int ioepic_set_affinity(struct irq_data *irqd,
			       const struct cpumask *mask, bool force)
{
	int ret;
	struct irq_data *parent = irqd->parent_data;

	ret = parent->chip->irq_set_affinity(parent, mask, force);
	if (ret >= 0 && ret != IRQ_SET_MASK_OK_DONE)
		__ioepic_configure_entry(irqd);

	return ret;
}

static int ioepic_irq_request_resources(struct irq_data *irqd)
{
	int ret;
	unsigned long flags;
	struct irq_desc *desc = irq_data_to_desc(irqd);
	struct ioepic_chip_data *d = irqd->chip_data;
	struct IO_EPIC_route_entry *e = &d->entry;
	struct device_node *np = d->d.pic->of_nodes[d->d.pin];
	struct pci_dev *pdev = of_find_pci_device_by_node(np);
	u32 req_id;
	lockdep_assert_not_held(&desc->lock);

	/* We can not do this in startup_ioepic_irq()
	 * because of invalid wait contex (spinlock
	 * inside rawspinlock) */
	if (!pdev && (ret = of_property_read_u32(np, "requester-id", &req_id)) < 0) {
		WARN(1, "No pci device (%pOF %d) for irq %d (pic pin %d)\n",
					np, ret, irqd->irq, d->d.pin);
		return -ENODEV;
	}
	raw_spin_lock_irqsave(&desc->lock, flags);
	if (!pdev) {
		e->rid.raw = req_id;
		raw_spin_unlock_irqrestore(&desc->lock, flags);
		return 0;
	}
	e->rid.raw = 0;
	e->rid.bus = pdev->bus->number;
	e->rid.dev = PCI_SLOT(pdev->devfn);
	e->rid.fn = PCI_FUNC(pdev->devfn);

	raw_spin_unlock_irqrestore(&desc->lock, flags);
	pci_dev_put(pdev);
	return 0;
}

static unsigned int startup_ioepic_irq(struct irq_data *irqd)
{
	ioepic_configure_entry(irqd);
	return 0;
}

static int ioepic_irq_get_chip_state(struct irq_data *irqd,
				   enum irqchip_irq_state which,
				   bool *state)
{
	int level;
	struct ioepic_chip_data *p = irqd->chip_data;
	struct iopic *pic = p->d.pic;
	union IO_EPIC_INT_CTRL reg;

	if (which != IRQCHIP_STATE_ACTIVE)
		return -EINVAL;

	*state = false;
	reg.raw = io_epic_read(pic, IOEPIC_TABLE_INT_CTRL(p->d.pin));
	level = reg.trigger;
	/*
	* The remote IRR is only valid in level trigger mode. It's
	* meaning is undefined for edge triggered interrupts and
	* irrelevant because the IO-APIC treats them as fire and
	* forget.
	*/
	if (level && reg.delivery_status)
		*state = true;
	return 0;
}

#ifdef CONFIG_E2K
static void ioepic_initialize_pin(struct irq_data *irqd)
{
	ioepic_configure_entry(irqd);

}

/* Support both IOEPIC v1 and v2 by writing INT_CTRL twice (for RW and RW1C bits) */
static void io_epic_reset_pin(struct iopic *epic, unsigned pin)
{
	union IO_EPIC_INT_CTRL reg;

	reg.raw = 0;
	reg.mask = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	reg.delivery_status = 1;
	reg.software_int = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	io_epic_write(epic, IOEPIC_TABLE_MSG_DATA(pin), 0);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_HIGH(pin), 0);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_LOW(pin), 0);
}

static int ioepic_setup_pin_passthrough(struct irq_data *irqd,
		struct ioepic_vcpu_info *info, struct iopic_chip_data *cfg)
{
	int ret = 0;
	struct ioepic_pt_pin *pt_pin, *tmp;

	if (info->valid) {
		/*
		 * Host and guest pin numbers always match.
		 * Passthrough of the same pin from several host IOEPICs to one VM isn't supported
		 */
		list_for_each_entry_safe(pt_pin, tmp, info->ioepic_pt_pin, list) {
			if (pt_pin->pin == cfg->pin) {
				WARN(true, "failed to pass ioepic node %d pin %d (already passing ioepic node %d pin %d\n)",
					cfg->pic->node, cfg->pin, pt_pin->node, pt_pin->pin);
				return -ENOENT;
			}
		}

		pt_pin = kmalloc(sizeof(struct ioepic_pt_pin), GFP_KERNEL);
		pt_pin->pic_id = cfg->pic->id;
		pt_pin->pic_version = cfg->pic->version;
		pt_pin->pin = cfg->pin;
		pt_pin->node = cfg->pic->node;
		INIT_LIST_HEAD(&pt_pin->list);
		list_add_tail(&pt_pin->list, info->ioepic_pt_pin);

		io_epic_reset_pin(cfg->pic, cfg->pin);
	} else {
		list_for_each_entry_safe(pt_pin, tmp, info->ioepic_pt_pin, list) {
			if (pt_pin->pin == cfg->pin &&
					pt_pin->pic_id == cfg->pic->id) {
				list_del(&pt_pin->list);
				kfree(pt_pin);
				break;
			}
		}
		ioepic_initialize_pin(irqd);
	}

	cfg->passthrough = info->valid;

	pr_info("%s(): %s IOEPIC passthrough (id %d pin %d)\n", __func__,
		info->valid ? "set" : "reset", cfg->pic->id, cfg->pin);
	return ret;
}

static int ioepic_set_vcpu_affinity(struct irq_data *irqd, void *vcpu_info)
{
	int i, irq = irqd->irq, ret;
	struct ioepic_vcpu_info *info = vcpu_info;
	struct ioepic_chip_data *d = irq_data_get_irq_chip_data(irqd);
	struct iopic_chip_data *cfg = &d->d;
	struct iopic *pic = cfg->pic;
	struct device_node *np = pic->of_nodes[cfg->pin];

	if (np == NULL) {
		pr_info("%s(): no device node (id %d pin %d)\n", __func__,
			pic->id, cfg->pin);
		return -EACCES;
	}
	/* setup all pins of device node */
	for (i = 0, ret = -ENOENT; i < pic->nr_pins; i++) {
		if (np == pic->of_nodes[i]) {
			irqd = irq_get_irq_data(irq + (i - cfg->pin));
			if (irqd) {
				d = irq_data_get_irq_chip_data(irqd);
				ret = ioepic_setup_pin_passthrough(irqd, info, &d->d);
				if (ret)
					break;
			}
		}
	}
	return ret;
}
#else
# define ioepic_set_vcpu_affinity NULL
#endif

struct irq_chip ioepic_chip __read_mostly = {
	.name			= "IO-EPIC",
	.irq_request_resources	= ioepic_irq_request_resources,
	.irq_startup		= startup_ioepic_irq,
	.irq_mask		= mask_ioepic_irq,
	.irq_unmask		= unmask_ioepic_irq,
	.irq_set_type		= ioepic_irq_set_type,
	.irq_ack		= irq_chip_ack_parent,
	.irq_eoi		= ioepic_ack_level,
	.irq_set_affinity	= ioepic_set_affinity,
	.irq_retrigger		= irq_chip_retrigger_hierarchy,
	.irq_get_irqchip_state	= ioepic_irq_get_chip_state,
	.irq_set_vcpu_affinity	= ioepic_set_vcpu_affinity,
};

static void ioepic_get_id_ver_pins(struct iopic *pic,
			int *id, int *version, int *pins)
{

	union IO_EPIC_ID reg_id;
	union IO_EPIC_VERSION reg_version;
	reg_id.raw = io_epic_read(pic, IOEPIC_ID);
	reg_version.raw = io_epic_read(pic, IOEPIC_VERSION);

	*id      = reg_id.id;
	*version = reg_version.version;
	*pins    = reg_version.entries;
}

struct iopic_chip iopic_ioepic_chip = {
	.iopic_get_id_ver_pins = ioepic_get_id_ver_pins,
	.iopic_chip = &ioepic_chip,
	.iopic_sizeof_entry = sizeof(struct IO_EPIC_route_entry),
};
