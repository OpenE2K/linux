/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/idr.h>
#include <linux/interrupt.h>
#include <linux/irqchip.h>
#include <linux/irq.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/syscore_ops.h>
#include <asm/sic_regs_access.h>
#include <asm/iolinkmask.h>
#include <asm/pic.h>

#include "io_pic.h"

static DEFINE_IDR(iopic_dev_ids);

#define for_each_iopic(pic, i) idr_for_each_entry(&iopic_dev_ids, pic, i)

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

static const struct irq_domain_ops iopic_irqdomain_ops = {
	.alloc		= l_irqdomain_alloc,
	.free		= l_irqdomain_free,
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
	int ret;
	int bus = -1;
	u64 b[2], v, regs_pa;
	void __iomem *a;
	struct fwnode_handle *fn = of_node_to_fwnode(np);
	struct iopic *ip = kzalloc(sizeof(*ip), GFP_KERNEL);

	if (!ip)
		return -ENOMEM;

	if (!of_property_read_u64_array(np, "bus-reg64", b, ARRAY_SIZE(b))) {
		v = boot_readl((void __iomem __force *)b[0]);
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
	a = (void __iomem __force *)b[0];
	v = boot_readl(a);
	if (WARN(v == 0 || v == 0xffffFFFF,
			"%pOF: bad io_pic base address: %llx\n", np, v)) {
		ret = -ENODEV;
		goto err;
	}

	raw_spin_lock_init(&ip->lock);
	ip->iopic_chip = ic;

	v &= PCI_BASE_ADDRESS_MEM_MASK;
	regs_pa = v;
	ip->regs = ioremap(regs_pa, b[1]);

	if (WARN(!ip->regs, "%pOF: Failed to map: [%llx-%llx]\n", np, v, b[1])) {
		ret = -ENXIO;
		goto err;
	}

	v = PCIE_ECAM_REG_MASK;
	b[0] &= ~v;
	a = (void __iomem __force *)b[0];
	v = boot_readw(a + PCI_COMMAND);
	/* Enable access to pic. Boot does not do it for us
		 in eioh + iohub2 configurations*/
	boot_writew(v | PCI_COMMAND_MEMORY | PCI_COMMAND_MASTER,
				a + PCI_COMMAND);

	ip->iopic_chip->iopic_get_id_ver_pins(ip, &ip->id, &ip->version,
					&ip->nr_pins);

	/* iopic pins may contain garbage, for example, after
	 * kexec previous kernel can't properly end some interrupts,
	 * so we need reset here */
	if (ip->iopic_chip->iopic_reset)
		ip->iopic_chip->iopic_reset(ip);

	ip->of_nodes = kzalloc(sizeof(*ip->of_nodes) * ip->nr_pins, GFP_KERNEL);
	if (WARN(!ip->of_nodes, "%pOF: Failed to allocate memory\n", np)) {
		ret = -ENOMEM;
		goto err;
	}
	if ((ret = iopic_parse_devtree(ip, np)))
		goto err;
	/* hw bug 170189: iohub2 interrupts can
	* be handled only by processor 0, but
	* end of interrupt should be sent from
	* processor to which iohub2 is connected,
	* so check real-numa-node-id property */
	if (of_property_read_u32(np, "real-numa-node-id", &ip->node))
		ip->node = of_node_to_nid(np);

	if (ip->node == NUMA_NO_NODE)
		ip->node = 0;

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

	if (ret == -ENOSPC && ip->iopic_chip->iopic_set_id) {
		ret = idr_alloc(&iopic_dev_ids, ip, 1, 0, GFP_KERNEL);
		if (WARN_ON(ret < 0))
			goto err;
		pr_warn("%pOF: boot bug: changing pic physical id from %d to %d\n",
				np, ip->id, ret);
		ip->id = ret;
		ip->iopic_chip->iopic_set_id(ip, ip->id);
	} else if (WARN(ret < 0, "%pOF: failed to map id: %d: %llx #%d version %d with %d pins\n",
		np, ret,
		regs_pa, ip->id, ip->version, ip->nr_pins)) {
		goto err;
	}
	pr_info("%pOF: @%llx #%d version %d with %d pins\n", np,
		regs_pa, ip->id, ip->version, ip->nr_pins);

	return 0;
err:
	iopic_exit(ip);
	return ret;
}


#define MSI_LO_ADDRESS			0x48
#define MSI_HI_ADDRESS			0x4c

static void get_io_apic_msi(int node, u32 *lo, u32 *hi)
{
	u32 bus, devfn = PCI_DEVFN(0, 0); /* it is iohub2 */

	if (node < 0 || !iohub_online(node))
		node = 0;

	if (IS_MACHINE_E2S) /* it is iohub */
		devfn = PCI_DEVFN(1, 0);
	conf_inl(node, 0,  CONFIG_CMD(0, devfn, PCI_PRIMARY_BUS), &bus);

	bus = (bus >> 8) & 0xFF;
	/* Read from i2c-spi controller */
	conf_inl(node, bus,  CONFIG_CMD(bus, PCI_DEVFN(2, 1), MSI_LO_ADDRESS), lo);
	conf_inl(node, bus,  CONFIG_CMD(bus, PCI_DEVFN(2, 1), MSI_HI_ADDRESS), hi);
}

static void get_io_epic_msi(int node, u32 *lo, u32 *hi)
{
	if (node < 0)
		node = 0;
	/* FIXME SIC reads with mas 0x13 aren't supported by hypervisor */
	if (paravirt_enabled()) {
		*lo = early_sic_read_node_nbsr_reg(node, SIC_rt_msi);
		*hi = early_sic_read_node_nbsr_reg(node, SIC_rt_msi_h);
	} else {
		*lo = sic_read_node_nbsr_reg(node, SIC_rt_msi);
		*hi = sic_read_node_nbsr_reg(node, SIC_rt_msi_h);
	}
}

void get_io_pic_msi(int node, u32 *lo, u32 *hi)
{
	/*
	 * QEMU always creates EIOHUB for all CPU models, so we can
	 * safely use the address from NBSR in guest.
	 */
	if (cpu_has_epic() || IS_HV_GM())
		return get_io_epic_msi(node, lo, hi);

	get_io_apic_msi(node, lo, hi);
}

void __cold print_IO_PICs(void)
{
	int iopic_idx;
	struct iopic *pic;

	for_each_iopic(pic, iopic_idx) {
		print_IO_PIC(pic, iopic_idx);
	}
}

#ifdef CONFIG_PM
static int iopic_suspend(void)
{
	struct iopic *pic;
	int i;

	for_each_iopic(pic, i) {
		int ret = pic->iopic_chip->iopic_suspend(pic);
		if (ret)
			return ret;
	}

	return 0;
}

static void iopic_resume(void)
{
	struct iopic *pic;
	int i;

	for_each_iopic(pic, i) {
		pic->iopic_chip->iopic_resume(pic);
	}
}

static struct syscore_ops iopic_syscore_ops = {
	.suspend = iopic_suspend,
	.resume = iopic_resume,
};

static int __init iopic_init_ops(void)
{
	register_syscore_ops(&iopic_syscore_ops);
	return 0;
}
device_initcall(iopic_init_ops);
#endif /* CONFIG_PM */

#ifdef CONFIG_L_IO_APIC
static int __init ioapic_init(struct device_node *np, struct device_node *parent)
{
	return iopic_init(np, parent, &iopic_ioapic_chip);
}
IRQCHIP_DECLARE(apic, "mcst,ioapic", ioapic_init);
#endif
#ifdef CONFIG_EPIC
static int __init ioepic_init(struct device_node *np, struct device_node *parent)
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
