/*
 * direct.c - Low-level direct PCI config space access
 */

#include <linux/pci.h>
#include <linux/init.h>
#include "pci.h"

int __init l_pci_direct_init(void)
{
	if ((pci_probe & PCI_PROBE_L) == 0)
		return (-1);
	if (pci_check_type_l()) {
		printk(KERN_INFO "PCI: Using Elbrus configuration type\n");
		return (0);
	}
	return (-1);
}
