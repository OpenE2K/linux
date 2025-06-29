#define DEBUG
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/console.h>
#include <linux/irq.h>
#include <linux/of_pci.h>
#include <linux/of_irq.h>
#include <asm/mpspec.h>

#ifdef CONFIG_KVM
/* MP IRQ source entries */
struct mpc_intsrc mp_irqs[MAX_IRQ_SOURCES];

/* # of MP IRQ source entries */
int mp_irq_entries;

/*
 * Only used for mp_INT intsrc MP-table entries. Currently only passed by qemu
 * for virtio
 */
int mp_get_pic_pin(int bus, int slot, int pin)
{
	int i;

	for (i = 0; i < mp_irq_entries; i++) {
		int lbus = mp_irqs[i].srcbus;

		if (!mp_irqs[i].irqtype &&
		    (bus == lbus) &&
		    (slot == ((mp_irqs[i].srcbusirq >> 2) & 0x1f))) {
			if (pin == (mp_irqs[i].srcbusirq & 3))
				return mp_irqs[i].dstirq;
		}
	}
	return -1;
}
#else
int mp_get_pic_pin(int bus, int slot, int pin)
{
	return -1;
}
#endif /*CONFIG_KVM*/

static struct device_node *l_get_pci_bus_np_and_pin(struct pci_dev *dev,
				u8 *pin)
{
	struct device_node *np;
	struct pci_bus *b = dev->bus;
	if (pci_is_root_bus(b))
		return NULL;
	*pin = pci_swizzle_interrupt_pin(dev, *pin);

	np = pci_device_to_OF_node(b->self);
	if (np)
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
	/* No pin, exit with no error message. */
	if (pin == 0)
		return 0;

	if (WARN_ON(pin > 4))
		pin = 1; /* Cope with illegal. */

	if (IS_HV_GM()) { /* try to get irq from mptable */
		struct device *d = &dev->dev;
		np = d->of_node;
		for (; d && !np; d = d->parent, np = d->of_node)
			;

		if (WARN(!np, "%s: no parent\n", pci_name(dev)))
			return -ENODEV;
		irq = mp_get_pic_pin(dev->bus->number,
					PCI_SLOT(dev->devfn),
					pin);
		if (irq < 0) {
			pci_dbg(dev, "no irq found\n");
			goto out;
		}
		oirq.np = np;
		oirq.args[0] = irq;
		oirq.args[1] = IRQ_TYPE_LEVEL_HIGH;
		oirq.args_count = 2;
		pin = 1;

		dev->irq = irq;

		goto map_irq;
	}

	oirq.np = l_get_pci_bus_np_and_pin(dev, &pin);

	if (WARN(!oirq.np, "%s (pin %d, line %d): no IRQ in device tree\n",
			pci_name(dev), pin, line)) {
		return -ENODEV;
	}

map_irq:
	ret = of_irq_parse_one(oirq.np, pin - 1, &oirq);
	if (ret)
		return ret;

	if (WARN_ON(oirq.args_count != 2))
		return -EINVAL;
	pci_read_config_byte(dev, PCI_INTERRUPT_LINE, &line);

	pci_dbg(dev, "line:%d, pin:%d; pic pin: got %d (%d) node: %pOF\n",
		line, pin, dev->irq, oirq.args[0], oirq.np);
	if (dev->irq == 0) /* bootloader asigned nothing */
		dev->irq = oirq.args[0];

	oirq.args[0] = dev->irq;

	irq = irq_create_of_mapping(&oirq);
	dev->irq = irq;
	if (WARN_ON(irq == 0))
		return -ENXIO;
out:
	return 0;
}

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

static const struct pci_device_id l_iohub_root_devices[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_ELBRUS,
			   PCI_DEVICE_ID_MCST_VIRT_PCI_BRIDGE),
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_PCIE_BRIDGE,
		      PCI_DEVICE_ID_MCST_PCIE_BRIDGE)
	},
	{}
};

static const struct pci_device_id l_eioh_proto_root_devices[] = {
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_EIOH_PROTO_PCIE_SWITCH_PORT),
	},
	{
		PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
			   PCI_DEVICE_ID_MCST_EIOH_PROTO_PCIE_SWITCH_PORT_R2000P),
	},
	{}
};

static bool __l_eioh_device(struct pci_dev *pdev)
{
	struct pci_bus *b = pdev->bus;
	if (pdev->vendor == PCI_VENDOR_ID_MCST_TMP &&
			pdev->device == PCI_DEVICE_ID_MCST_VPPB) {
		return pdev->revision >= 0x10 ? true : false;
	} else if (pci_match_id(l_iohub_root_devices, pdev)) {
		return false;
	} else if (pci_match_id(l_eioh_proto_root_devices, pdev)) {
		return true;
	}
	if (pci_is_root_bus(b)) {
		u16 vid = 0, did = 0;
		u8 rev;
		pci_bus_read_config_word(b, 0, PCI_VENDOR_ID, &vid);
		pci_bus_read_config_word(b, 0, PCI_DEVICE_ID, &did);
		pci_bus_read_config_byte(b, 0, PCI_REVISION_ID, &rev);
		if (vid == PCI_VENDOR_ID_MCST_TMP &&
			did == PCI_DEVICE_ID_MCST_VPPB) {
			return rev >= 0x10 ? true : false;
		}
		return false;
	}
	return __l_eioh_device(b->self);
}

bool l_eioh_device(struct pci_dev *pdev)
{
	struct pci_config_window *cfg = pdev->bus->sysdata;
	struct iohub_sysdata *sd = cfg->priv;
	if (!sd->has_eioh)
		return false;
	if (!sd->has_iohub)
		return true;
	return __l_eioh_device(pdev);
}
EXPORT_SYMBOL(l_eioh_device);
