/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irq.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/idr.h>

#include "io_pic.h"

static DEFINE_IDR(iopic_dev_ids);

unsigned io_pic_read_by_id(unsigned id, unsigned reg)
{
	struct iopic *ip = idr_find(&iopic_dev_ids, id);
	if (WARN_ON(!ip))
		return ~0;
	return readl(ip->regs + reg);
}

void io_pic_write_by_id(unsigned id, unsigned reg, unsigned value)
{
	struct iopic *ip = idr_find(&iopic_dev_ids, id);
	if (WARN_ON(!ip))
		return;
	writel(value, ip->regs + reg);
}

unsigned long io_pic_base_by_id(int id)
{
	struct iopic *ip = idr_find(&iopic_dev_ids, id);
	if (WARN_ON(!ip))
		return ~0UL;
	return ip->iomem_res->start;
}

static void alloc_iopic_saved_registers(struct iopic *iopic)
{
	size_t size;

	if (iopic->saved_registers)
		return;

	size = iopic->iopic_chip->iopic_sizeof_entry * iopic->nr_pins;
	iopic->saved_registers = kzalloc(size, GFP_KERNEL);
	if (!iopic->saved_registers)
		pr_err("IOAPIC %d: suspend/resume impossible!\n", iopic->id);
}

static struct iopic *l_irqdomain_iopic(struct irq_domain *dmn)
{
	return dmn->host_data;
}

static int iopic_parse_devtree(struct iopic *pic, struct device_node *pic_np)
{
	int irq, i;
	struct of_phandle_args oirq;
	struct device_node *np;

	for_each_of_allnodes_from(of_root, np) {
		for (i = 0; of_irq_parse_one(np, i, &oirq) == 0; i++) {
			if (pic_np != oirq.np)
				break;
			if (WARN_ON(oirq.args_count != 2))
				break;

			irq = oirq.args[0];
			if (WARN(irq >= pic->nr_pins,
				"%pOF: irq %d >= %d pins\n", np, irq, pic->nr_pins)) {
				break;
			}
			pic->of_nodes[irq] = np;
		}
	}
	return 0;
}

static int __l_irqdomain_alloc(struct irq_domain *dmn, unsigned int virq,
		       unsigned int nr_irqs, void *arg)
{
	struct irq_fwspec *fwspec = arg;
	struct fwnode_handle *fwnode = fwspec->fwnode;
	struct iopic_chip_data *d;
	struct irq_data *irqd;
	struct iopic *iopic;
	int ret;
	irq_hw_number_t pin;
	unsigned int type;

	if (!is_of_node(fwnode))
		return -EINVAL;

	irqd = irq_domain_get_irq_data(dmn, virq);
	if (!irqd)
		return -ENODEV;

	if (WARN_ON(IS_ENABLED(CONFIG_NUMA) && irq_data_get_node(irqd) < 0))
		return -EINVAL;

	iopic = l_irqdomain_iopic(dmn);

	d = kzalloc(sizeof(*d) +
		iopic->iopic_chip->iopic_sizeof_entry, GFP_KERNEL);
	if (!d)
		return -ENOMEM;

	ret = irq_domain_translate_twocell(dmn, fwspec, &pin, &type);
	if (ret)
		return ret;

	d->pic = iopic;
	d->pin = pin;

	ret = irq_domain_set_hwirq_and_chip(dmn, virq, pin,
			iopic->iopic_chip->iopic_chip, d);
	if (ret)
		return ret;

	ret = irq_domain_alloc_irqs_parent(dmn, virq, nr_irqs, arg);
	if (ret < 0) {
		kfree(d);
		return ret;
	}

	printk(KERN_DEBUG
		    "IOPIC[%d]: Preconfigured routing entry (%ld -> IRQ %d)\n",
		    iopic->id, pin, virq);
	return 0;
}

static int l_irqdomain_alloc(struct irq_domain *dmn, unsigned int virq,
			      unsigned int nr_irqs, void *arg)
{
	return __l_irqdomain_alloc(dmn, virq, nr_irqs, arg);
}

static void l_irqdomain_free(struct irq_domain *dmn, unsigned int virq,
		       unsigned int nr_irqs)
{
	struct irq_data *irqd;

	BUG_ON(nr_irqs != 1);
	irqd = irq_domain_get_irq_data(dmn, virq);
	if (irqd)
		kfree(irqd->chip_data);

	irq_domain_free_irqs_top(dmn, virq, nr_irqs);
}

static int l_irqdomain_activate(struct irq_domain *dmn,
			  struct irq_data *irqd, bool reserve)
{
	unsigned long flags;
	struct iopic *apic = l_irqdomain_iopic(dmn);

	raw_spin_lock_irqsave(&apic->lock, flags);
	apic->iopic_chip->iopic_configure_entry(irqd);
	raw_spin_unlock_irqrestore(&apic->lock, flags);
	return 0;
}

static void l_irqdomain_deactivate(struct irq_domain *dmn,
			     struct irq_data *irqd)
{

	struct iopic *apic = l_irqdomain_iopic(dmn);
	/* It won't be called for IRQ with multiple IOAPIC pins associated */
	apic->iopic_chip->iopic_mask_entry(l_irqdomain_iopic(dmn),
			  (int)irqd->hwirq);
}

const struct irq_domain_ops iopic_irqdomain_ops = {
	.alloc		= l_irqdomain_alloc,
	.free		= l_irqdomain_free,
	.activate	= l_irqdomain_activate,
	.deactivate	= l_irqdomain_deactivate,
	.translate	= irq_domain_translate_twocell,
};

static void __init iopic_exit(struct iopic *ip)
{
	if (!ip)
		return;

	if (ip->irqdomain)
		irq_domain_remove(ip->irqdomain);

	if (ip->regs)
		iounmap(ip->regs);
	kfree(ip->saved_registers);
	kfree(ip->of_nodes);
	kfree(ip);
}

static int __init iopic_init(struct device_node *np,
			struct device_node *parent, struct iopic_chip *ic)
{
	u64 b[2], v;
	int bus = -1;
	int ret;
	struct fwnode_handle *fn = of_node_to_fwnode(np);
	struct iopic *ip = kzalloc(sizeof(*ip), GFP_KERNEL);

	if (!ip)
		return -ENOMEM;

	if (!of_property_read_u64_array(np, "bus-reg64", b, ARRAY_SIZE(b))) {
		v = boot_readl((void *)b[0]);
		bus = (v >> 8) & 0xFF;
	}

	if (((ret = of_property_read_u64_array(np, "regbar-and-size64",
			b, ARRAY_SIZE(b))) < 0)) {
		goto err;
	}
	if (bus >= 0) {
		b[0] &= ~(PCIE_ECAM_BUS_MASK << PCIE_ECAM_BUS_SHIFT);
		b[0] |= bus << PCIE_ECAM_BUS_SHIFT;
	}
	v = boot_readl((void *)b[0]);
	if (WARN(v == 0 || v == 0xffffFFFF,
			"%pOF: bad io_pic base address: %llx\n", np, v)) {
		ret = -ENODEV;
		goto err;
	}
	raw_spin_lock_init(&ip->lock);
	ip->iopic_chip = ic;

	v &= PCI_BASE_ADDRESS_MEM_MASK;
	ip->regs = ioremap(v, b[1]);

	if (WARN(!ip->regs, "%pOF: Failed to map: [%llx-%llx]\n", np, v, b[1])) {
		ret = -ENXIO;
		goto err;
	}

	ip->iopic_chip->iopic_get_id_ver_pins(ip, &ip->id, &ip->version,
					&ip->nr_pins);
	ip->of_nodes = kzalloc(sizeof(*ip->of_nodes) * ip->nr_pins, GFP_KERNEL);
	if (WARN(!ip->of_nodes, "%pOF: Failed to allocate memory\n", np)) {
		ret = -ENOMEM;
		goto err;
	}
	if ((ret = iopic_parse_devtree(ip, np)))
		goto err;
	ret = of_node_to_nid(np);
	ip->node = ret == NUMA_NO_NODE ? 0 : ret;

	alloc_iopic_saved_registers(ip);
	ip->irqdomain = irq_domain_create_linear(fn, ip->nr_pins,
				&iopic_irqdomain_ops,
				ip);
	if (WARN_ON(!ip->irqdomain)) {
		ret = -ENOMEM;
		goto err;
	}

	ip->irqdomain->parent = irq_find_host(parent);
	BUG_ON(!ip->irqdomain->parent);

	ret = idr_alloc(&iopic_dev_ids, ip, ip->id, ip->id + 1, GFP_KERNEL);

	if (WARN(ret < 0, "%pOF: failed to map id: %d: %llx #%d version %d with %d pins\n",
		np, ret,
		v, ip->id, ip->version, ip->nr_pins)) {
		goto err;
	}
	pr_info("%pOF: @%llx #%d version %d with %d pins\n", np,
		v, ip->id, ip->version, ip->nr_pins);

	return 0;
err:
	iopic_exit(ip);
	return ret;
}

#ifdef CONFIG_L_IO_APIC
static int __init ioapic_init(struct device_node *np,
			struct device_node *parent)
{
	return iopic_init(np, parent, &iopic_ioapic_chip);
}
IRQCHIP_DECLARE(apic, "mcst,ioapic", ioapic_init);
#endif
#ifdef CONFIG_EPIC
static int __init ioepic_init(struct device_node *np,
			struct device_node *parent)
{
	return iopic_init(np, parent, &iopic_ioepic_chip);
}
IRQCHIP_DECLARE(epic, "mcst,ioepic", ioepic_init);
#endif
#if 0
IRQCHIP_PLATFORM_DRIVER_BEGIN(iopic)
IRQCHIP_MATCH("mcst,ioapic", iopic_init)
IRQCHIP_PLATFORM_DRIVER_END(iopic, .pm = &iopic_pm_ops)
#endif
