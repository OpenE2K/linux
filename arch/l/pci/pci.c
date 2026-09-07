/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define DEBUG
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/console.h>
#include <linux/irq.h>
#include <linux/of_pci.h>
#include <linux/of_irq.h>
#include <asm/mpspec.h>

static struct device_node *l_get_pci_bus_np_and_pin(struct pci_dev *dev,
				u8 *pin)
{
	struct device_node *np;
	struct pci_bus *b = dev->bus;
	if (pci_is_root_bus(b))
		return NULL;
	*pin = pci_swizzle_interrupt_pin(dev, *pin);

	np = pci_device_to_OF_node(b->self);

	if (np && of_irq_count(np) >= 4)
		return np;
	return l_get_pci_bus_np_and_pin(b->self, pin);
}

int pcibios_alloc_irq(struct pci_dev *dev)
{
	u8 pin;
	u8 line;
	struct of_phandle_args oirq;
	int ret = 0, irq = 0, i;
	struct device_node *np = pci_device_to_OF_node(dev);
	int nr = of_irq_count(np);
	/* map all the device irqs from device tree */
	for (i = 0; i < nr && ret >= 0; i++)
		ret = of_irq_get(np, i);
	if (WARN_ON(ret < 0))
		return ret;
	if (nr)
		dev->irq = of_irq_get(np, 0);
	if (np)
		return 0;

	pci_read_config_byte(dev, PCI_INTERRUPT_PIN, &pin);
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &line);

	/* No pin, exit with no error message. */
	if (pin == 0)
		return 0;

	if (IS_HV_GM()) /* Let virtio drivers handle irqs */
		return 0;

	if (WARN_ON(pin > 4))
		pin = 1; /* Cope with illegal. */

	oirq.np = l_get_pci_bus_np_and_pin(dev, &pin);

	if (WARN(!oirq.np, "%s (pin %d): no IRQ in device tree\n",
			pci_name(dev), pin)) {
		return -ENODEV;
	}

	ret = of_irq_parse_one(oirq.np, pin - 1, &oirq);
	if (WARN_ON(ret))
		return ret;

	if (WARN_ON(oirq.args_count != 2))
		return -EINVAL;

	pci_dbg(dev, "line:%d, pin:%d; pic pin: got %d (%d) node: %pOF\n",
		line, pin, dev->irq, oirq.args[0], oirq.np);
	if (line == 0) /* bootloader asigned nothing */
		line = oirq.args[0];

	oirq.args[0] = line;

	irq = irq_create_of_mapping(&oirq);
	dev->irq = irq;
	if (WARN_ON(irq == 0))
		return -ENXIO;
	return 0;
}
EXPORT_SYMBOL(pcibios_alloc_irq); /*for e8v7 galcore */

void pcibios_free_irq(struct pci_dev *dev)
{
}

void pcibios_add_bus(struct pci_bus *bus)
{
	/* lock consoles to prevent output to pci consoles while scanning */
	console_lock();
}
/*
 *  Called after each bus is probed, but before its children
 *  are examined.
 */

void pcibios_fixup_bus(struct pci_bus *b)
{
	console_unlock();
}

