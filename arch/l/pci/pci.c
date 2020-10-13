/*
 *	Low-Level PCI Access for i386 machines
 *
 * Copyright 1993, 1994 Drew Eckhardt
 *      Visionary Computing
 *      (Unix and Linux consulting and custom programming)
 *      Drew@Colorado.EDU
 *      +1 (303) 786-7975
 *
 * Drew's work was sponsored by:
 *	iX Multiuser Multitasking Magazine
 *	Hannover, Germany
 *	hm@ix.de
 *
 * Copyright 1997--2000 Martin Mares <mj@ucw.cz>
 *
 * For more information, please consult the following manuals (look at
 * http://www.pcisig.com/ for how to get them):
 *
 * PCI BIOS Specification
 * PCI Local Bus Specification
 * PCI to PCI Bridge Specification
 * PCI System Design Guide
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/errno.h>
#include <linux/delay.h>

#include "pci.h"

#undef	DEBUG_PCI_MODE
#undef	DebugPCI
#define	DEBUG_PCI_MODE		0	/* PCI init */
#define	DebugPCI		if (DEBUG_PCI_MODE) printk
#define	DebugBUSINFO		if (DEBUG_PCI_MODE) Debug_BUS_INFO
#define	DebugRESINFO		if (DEBUG_PCI_MODE) Debug_RES_INFO
#define	DebugALLRESINFO		if (DEBUG_PCI_MODE) Debug_ALL_RES_INFO
#define	DebugDEVINFO		if (DEBUG_PCI_MODE) Debug_DEV_INFO

void
Debug_RES_INFO(struct resource *resource, int num)
{
	printk("RESOURCE 0x%p #%d %s\n", resource, num,
		(resource->name) ? resource->name : "???");
	printk("         from 0x%llx to 0x%llx flags 0x%lx\n",
		resource->start, resource->end, resource->flags);
}

void
Debug_ALL_RES_INFO(struct resource *resource, int num)
{
	int i;

	printk("ALL RESOURCES 0x%p number of resources %d\n",
		resource, num);
	for (i = 0; i < num; i ++) {
		DebugRESINFO(&resource[i], i);
	}
}

void
Debug_DEV_INFO(struct pci_dev *dev, int res)
{
	printk("DEV 0x%p BUS 0x%p bus this device bridges to 0x%p\n",
		dev, dev->bus, dev->subordinate);
	printk("    %s devfn %x vendor %x device %x class (base,sub,prog-if) "
		"%06x\n", pci_name(dev),
		dev->devfn, dev->vendor, dev->device, dev->class);
	printk("    config space size 0x%x IRQ %d\n",
		dev->cfg_size, dev->irq);
	if (res) {
		printk("I/O and memory regions + expansion ROMs :\n");
		DebugALLRESINFO(dev->resource, PCI_NUM_RESOURCES);
	}
}

void
Debug_BUS_INFO(struct pci_bus *bus, int self, int res)
{
	int i;

	printk("BUS 0x%p parent 0x%p self 0x%p\n",
		bus, bus->parent, bus->self);
	printk("    %s # %02x primary %02x\n",
		bus->name, bus->number, bus->primary);
	if (self && bus->self) {
		printk("Bridge device as seen by parent:\n");
		DebugDEVINFO(bus->self, res);
	}
	if (res && bus->resource) {
		printk("Address space routed to this bus:\n");
		for (i = 0; i < PCI_BRIDGE_RESOURCE_NUM; i ++) {
			if (bus->resource[i]) {
				printk("   SPACE #%d\n", i);
				DebugRESINFO(bus->resource[i], i);
			}
		}
	}
}


/*
 *  Handle resources of PCI devices.  If the world were perfect, we could
 *  just allocate all the resource regions and do nothing more.  It isn't.
 *  On the other hand, we cannot just re-allocate all devices, as it would
 *  require us to know lots of host bridge internals.  So we attempt to
 *  keep as much of the original configuration as possible, but tweak it
 *  when it's found to be wrong.
 *
 *  Known BIOS problems we have to work around:
 *	- I/O or memory regions not configured
 *	- regions configured, but not enabled in the command register
 *	- bogus I/O addresses above 64K used
 *	- expansion ROMs left enabled (this may sound harmless, but given
 *	  the fact the PCI specs explicitly allow address decoders to be
 *	  shared between expansion ROMs and other resource regions, it's
 *	  at least dangerous)
 *
 *  Our solution:
 *	(1) Allocate resources for all buses behind PCI-to-PCI bridges.
 *	    This gives us fixed barriers on where we can allocate.
 *	(2) Allocate resources for all enabled devices.  If there is
 *	    a collision, just mark the resource as unallocated. Also
 *	    disable expansion ROMs during this step.
 *	(3) Try to allocate resources for disabled devices.  If the
 *	    resources were assigned correctly, everything goes well,
 *	    if they weren't, they won't disturb allocation of other
 *	    resources.
 *	(4) Assign new addresses to resources which were either
 *	    not configured at all or misconfigured.  If explicitly
 *	    requested by the user, configure expansion ROM address
 *	    as well.
 */

static void __init pcibios_allocate_bus_resources(struct list_head *bus_list)
{
	struct list_head *ln;
	struct pci_bus *bus;
	struct pci_dev *dev;
	int idx;
	struct resource *r, *pr;

	/* Depth-First Search on bus tree */
	DebugPCI("pcibios_allocate_bus_resources() started for bus list\n");
	for (ln=bus_list->next; ln != bus_list; ln=ln->next) {
		bus = pci_bus_b(ln);
		DebugBUSINFO(bus, 0, 0);
		if ((dev = bus->self)) {
			DebugDEVINFO(dev, 0);
			for (idx = PCI_BRIDGE_RESOURCES; idx < PCI_NUM_RESOURCES; idx++) {
				r = &dev->resource[idx];
				DebugRESINFO(r, idx);
				if (!r->flags)
					continue;
				pr = pci_find_parent_resource(dev, r);
				DebugPCI("pcibios_allocate_bus_resources() "
					"parent resource is 0x%p : \n", pr);
				if (pr) {
					DebugPCI("PARENT ");
					DebugRESINFO(pr, 0);
				}
				if ((!r->start && !r->end) || !pr || request_resource(pr, r) < 0) {
					printk(KERN_ERR "PCI: Cannot allocate resource region %d of bridge %s\n", idx, pci_name(dev));
					/* Something is wrong with the region.
					   Invalidate the resource to prevent child
					   resource allocations in this range. */
					r->flags = 0;
				}
			}
		}
		pcibios_allocate_bus_resources(&bus->children);
	}
}

static void __init pcibios_allocate_resources(int pass)
{
	struct pci_dev *dev = NULL;
	int idx, disabled;
	u16 command;
	struct resource *r;

	DebugPCI("pcibios_allocate_resources() started for pass %d\n", pass);
	for_each_pci_dev(dev) {
		DebugDEVINFO(dev, 0);
		pci_read_config_word(dev, PCI_COMMAND, &command);
		for(idx = 0; idx < 6; idx++) {
			r = &dev->resource[idx];
			DebugRESINFO(r, idx);
			if (r->parent) {	/* Already allocated */
				DebugPCI("pcibios_allocate_resources() "
					"Already allocated\n");
				continue;
			}
			if (!r->start && !r->end) {	/* Address not assigned at all */
				DebugPCI("pcibios_allocate_resources() "
					"Address not assigned at all\n");
				continue;
			}
			if (r->flags & IORESOURCE_IO)
				disabled = !(command & PCI_COMMAND_IO);
			else
				disabled = !(command & PCI_COMMAND_MEMORY);
			if (pass == disabled) {
				DebugPCI("PCI: Resource %08llx-%08llx (f=%lx, "
					"disabled=%d, pass=%d)\n",
					r->start, r->end, r->flags,
					disabled, pass);
				if (pci_claim_resource(dev, idx) < 0) {
					printk(KERN_ERR "PCI: Cannot allocate "
						"resource region %d of device "
						"%s\n", idx, pci_name(dev));
					/* We'll assign a new address later */
					r->end -= r->start;
					r->start = 0;
				}
			}
		}
		if (!pass) {
			r = &dev->resource[PCI_ROM_RESOURCE];
			if (r->flags & PCI_ROM_ADDRESS_ENABLE) {
				/* Turn the ROM off, leave the resource region, but keep it unregistered. */
				u32 reg;
				DebugPCI("PCI: Switching off ROM of %s\n", pci_name(dev));
				r->flags &= ~PCI_ROM_ADDRESS_ENABLE;
				pci_read_config_dword(dev, dev->rom_base_reg, &reg);
				pci_write_config_dword(dev, dev->rom_base_reg, reg & ~PCI_ROM_ADDRESS_ENABLE);
			}
		}
	}
}

static int __init pcibios_assign_resources(void)
{
	struct pci_dev *dev = NULL;
	int idx;
	struct resource *r;
	int res = 0;

	for_each_pci_dev(dev) {
		int class = dev->class >> 8;

		/* Don't touch classless devices and host bridges */
		if (!class || class == PCI_CLASS_BRIDGE_HOST)
			continue;

		for(idx=0; idx<6; idx++) {
			r = &dev->resource[idx];

			/*
			 *  Don't touch IDE controllers and I/O ports of video cards!
			 */
			if ((class == PCI_CLASS_STORAGE_IDE && idx < 4) ||
			    (class == PCI_CLASS_DISPLAY_VGA && (r->flags & IORESOURCE_IO)))
				continue;

			/*
			 *  We shall assign a new address to this resource, either because
			 *  the BIOS forgot to do so or because we have decided the old
			 *  address was unusable for some reason.
			 */
			if (!r->start && r->end && !(r->flags & IORESOURCE_IO))
				res = pci_assign_resource(dev, idx);
		}

		if (pci_probe & PCI_ASSIGN_ROMS) {
			r = &dev->resource[PCI_ROM_RESOURCE];
			r->end -= r->start;
			r->start = 0;
			if (r->end)
				res = pci_assign_resource(dev, PCI_ROM_RESOURCE);
		}
	}
	return res;
}

void __init pcibios_resource_survey(void)
{
	DBG("PCI: Allocating resources\n");
	pcibios_allocate_bus_resources(&pci_root_buses);
	pcibios_allocate_resources(0);
	pcibios_allocate_resources(1);
}

/**
 * called in fs_initcall (one below subsys_initcall),
 * give a chance for motherboard reserve resources
 */
fs_initcall(pcibios_assign_resources);

int pcibios_enable_resources(struct pci_dev *dev, int mask)
{
	u16 cmd, old_cmd;
	int idx;
	struct resource *r;

	pci_read_config_word(dev, PCI_COMMAND, &cmd);
	old_cmd = cmd;
	for(idx = 0; idx < PCI_NUM_RESOURCES; idx++) {
		/* Only set up the requested stuff */
		if (!(mask & (1<<idx)))
			continue;

		r = &dev->resource[idx];
		if (!r->start && r->end && !(r->flags & IORESOURCE_IO)) {		
			printk(KERN_ERR "PCI: Device %s not available because of resource collisions\n", pci_name(dev));
			return -EINVAL;
		}
		if (r->flags & IORESOURCE_IO)
			cmd |= PCI_COMMAND_IO;
		if (r->flags & IORESOURCE_MEM)
			cmd |= PCI_COMMAND_MEMORY;
	}
	if (dev->resource[PCI_ROM_RESOURCE].start)
		cmd |= PCI_COMMAND_MEMORY;
	if (cmd != old_cmd) {
		printk("PCI: Enabling device %s (%04x -> %04x)\n", pci_name(dev), old_cmd, cmd);
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	return 0;
}

#ifdef CONFIG_E2K
#ifdef CONFIG_PCI_QUIRKS

static unsigned long __initdata l_slink_freq;

static int __init l_slink_freq_setup(char *str)
{
	l_slink_freq = memparse(str, &str);
	return 1;
}

__setup("slink=", l_slink_freq_setup);

#define SLINK_PLL_MULTIPLIER			0x6c
#define SLINK_PLL_STROB				0x6e
# define SLPLLM_STB_UP				0xa5
#define SLINK_PLLSTS				0x6f
# define SLINK_PLLSTS_0_LOCKED			0x3

struct l_slink_freqs {
	unsigned long dflt, min, max, mult, div;
} l_slink_freqs[] __initdata = {
	{
	.dflt = 14, .min = 7, .max = 25, .mult = 50 * 1000 * 1000, .div = 3}, {
	.dflt = 19, .min = 9, .max = 25, .mult = 25 * 1000 * 1000, .div = 1}
};

#define SLINK_TIMEOUT_10USEC	(1 * 1000 * 100)
static void __init l_quirk_slink_freq(struct pci_dev *pdev)
{
	struct l_slink_freqs *f;
	int i;
	unsigned short v, curr;
	if (l_slink_freq == 0)
		return;
	pci_write_config_byte(pdev, SLINK_PLL_STROB, 0);
	pci_read_config_word(pdev, SLINK_PLL_MULTIPLIER, &curr);
	for (i = 0; i < ARRAY_SIZE(l_slink_freqs); i++) {
		f = &l_slink_freqs[i];
		if (f->dflt == curr)
			break;
	}
	if (i == ARRAY_SIZE(l_slink_freqs)) {
		pr_err("slink: unknown default multiplier: %d\n", curr);
		return;
	}
	if (l_slink_freq > (f->max + 1) * f->mult / f->div ||
	    l_slink_freq < (f->min +1) * f->mult / f->div) {
		pr_err("slink: requested frequency out of bounds: %ld\n",
		       l_slink_freq);
		return;
	}
	v = ((l_slink_freq + (f->mult / f->div / 2)) * f->div) / f->mult - 1;
	do {
		unsigned short last;
		if (v == curr) {
			pr_info("slink: frequency set to: %ld (SLPLLM=%d)\n",
			       (v + 1) * f->mult / f->div, v);
			break;
		}
		if (v < f->dflt)
			curr--;
		else
			curr++;
		pci_write_config_byte(pdev, SLINK_PLL_STROB, 0);
		pci_write_config_word(pdev, SLINK_PLL_MULTIPLIER, curr);
		pci_write_config_byte(pdev, SLINK_PLL_STROB, SLPLLM_STB_UP);
		for (i = 0; i < SLINK_TIMEOUT_10USEC; i++) {
			unsigned char sts;
			pci_read_config_byte(pdev, SLINK_PLLSTS, &sts);
			if ((sts & SLINK_PLLSTS_0_LOCKED) ==
			    SLINK_PLLSTS_0_LOCKED)
				break;
			udelay(10);
		}
		if (i == SLINK_TIMEOUT_10USEC) {
			panic("slink: timeout\n");
		}
		pci_write_config_byte(pdev, SLINK_PLL_STROB, 0);
		pci_read_config_word(pdev, SLINK_PLL_MULTIPLIER, &last);
		if (last != curr) {
			panic("slink: failed to set frequency to: %ld (SLPLLM=%d)\n",
			       (curr + 1)  * f->mult / f->div, curr);
			break;
		}
	} while (1);

}

DECLARE_PCI_FIXUP_HEADER(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MSCT_VPPB,
			 l_quirk_slink_freq);

#else
#error		fixme
#endif /*CONFIG_PCI_QUIRKS */
#endif /*CONFIG_E2K*/
