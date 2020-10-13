/*
 *	Low-Level PCI Support for Elbrus/Intel chipset
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 */

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/console.h>
#include <linux/slab.h>
#include <asm/io.h>
#include <asm/smp.h>

#include "pci.h"

#undef	DEBUG_PCI_MODE
#undef	DebugPCI
#define	DEBUG_PCI_MODE	0	/* PCI init */
#define	DebugPCI	if (DEBUG_PCI_MODE) printk

int noioapicquirk;
#ifdef CONFIG_X86_REROUTE_FOR_BROKEN_BOOT_IRQS
int noioapicreroute = 0;
#else
int noioapicreroute = 1;
#endif

unsigned int pci_probe = 0;

int pcibios_last_bus = -1;
unsigned long pirq_table_addr;
struct pci_bus *pci_root_bus = NULL;
struct pci_raw_ops *raw_pci_ops = NULL;

int raw_pci_read(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 *val)
{
	return raw_pci_ops->read(domain, bus, devfn, reg, len, val);
}

int raw_pci_write(unsigned int domain, unsigned int bus, unsigned int devfn,
						int reg, int len, u32 val)
{
	return raw_pci_ops->write(domain, bus, devfn, reg, len, val);
}

static int pci_read(struct pci_bus *bus, unsigned int devfn, int where,
			int size, u32 *value)
{
	return raw_pci_read(pci_domain_nr(bus), bus->number,
				devfn, where, size, value);
}

static int pci_write(struct pci_bus *bus, unsigned int devfn, int where,
			int size, u32 value)
{
	return raw_pci_write(pci_domain_nr(bus), bus->number,
				devfn, where, size, value);
}

struct pci_ops pci_root_ops = {
	.read = pci_read,
	.write = pci_write,
};

/*
 * legacy, numa, and acpi all want to call pcibios_scan_root
 * from their initcalls. This flag prevents that.
 */
int pcibios_scanned;

/*
 * This interrupt-safe spinlock protects all accesses to PCI
 * configuration space.
 */
DEFINE_RAW_SPINLOCK(pci_config_lock);

struct pci_bus *pcibios_scan_root(int busnum)
{
	struct pci_bus *bus = NULL;
	struct iohub_sysdata *sd;

	DebugPCI("pcibios_scan_root() started for bus # %d\n", busnum);
	while ((bus = pci_find_next_bus(bus)) != NULL) {
		DebugPCI("pcibios_scan_root() find next bus # %d\n",
			bus->number);
		if (bus->number == busnum) {
			/* Already scanned */
			DebugPCI("pcibios_scan_root() bus # %d already "
				"scanned\n", busnum);
			return bus;
		}
	}

	/* Allocate per-root-bus (not per bus) arch-specific data.
	 * TODO: leak; this memory is never freed.
	 * It's arguable whether it's worth the trouble to care.
	 */
	sd = kzalloc(sizeof(*sd), GFP_KERNEL);
	if (!sd) {
		printk(KERN_ERR "PCI: OOM, not probing PCI bus %02x\n", busnum);
		return NULL;
	}
	printk("PCI: Probing PCI hardware (bus %02x)\n", busnum);

	return pci_scan_bus_parented(NULL, busnum, &pci_root_ops, sd);
}

extern u8 pci_cache_line_size;

static int __init pcibios_init(void)
{
	if (!raw_pci_ops) {
		printk("PCI: System does not support PCI\n");
		return 0;
	}
	/* lock consoles to prevent output to pci consoles while scanning */
	console_lock();
	if (pci_root_bus == NULL) {
		pci_root_bus = pcibios_scan_root(0);
		if (pci_root_bus)
			pci_bus_add_devices(pci_root_bus);
	}
	pcibios_fixup_resources(pci_root_bus);
	pcibios_irq_init();

	/*
	 * Assume PCI cacheline size of 32 bytes for all x86s except K7/K8
	 * and P4. It's also good for 386/486s (which actually have 16)
	 * as quite a few PCI devices do not support smaller values.
	 */
	pci_cache_line_size = PCI_ARCH_CACHE_LINE_SIZE >> 2;

	pcibios_resource_survey();

	pci_assign_unassigned_resources();
	console_unlock();

	return 0;
}

subsys_initcall(pcibios_init);
