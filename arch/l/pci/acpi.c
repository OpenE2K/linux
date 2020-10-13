#include <linux/pci.h>
#include <linux/acpi.h>
#include <linux/init.h>
#include "pci.h"

struct pci_bus *pci_acpi_scan_root(struct acpi_device *device, int domain, int busnum)
{
	if (domain != 0) {
		printk(KERN_WARNING "PCI: Multiple domains not supported\n");
		return NULL;
	}

	return pcibios_scan_root(busnum);
}

static int __init pci_acpi_init(void)
{
	return 0;
}
subsys_initcall(pci_acpi_init);
