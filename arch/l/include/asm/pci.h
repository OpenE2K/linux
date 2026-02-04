/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _L_PCI_H
#define _L_PCI_H

#if !defined ___ASM_SPARC_PCI_H && !defined _E2K_PCI_H
# error Do not include "asm-l/pci.h" directly, use "linux/pci.h" instead
#endif

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/pci-ecam.h>

#ifdef __KERNEL__

#define CONFIG_CMD(bus, devfn, where)  	\
		((bus&0xFF)<<20)|((devfn&0xFF)<<12)|(where&0xFFF)

extern int IOHUB_revision;
static inline int is_prototype(void)
{
	return IOHUB_revision >= 0xf0;
}

struct pci_dev;
struct pci_bus;
enum pci_mmap_state;
struct pci_ops;

bool l_eioh_device(struct pci_dev *pdev);
int iohub_revision(struct pci_dev *pdev);
int iohub_generation(struct pci_dev *pdev);
bool is_iohub_asic(struct pci_dev *pdev);

#ifdef CONFIG_NUMA
#define pcibus_to_node(__bus)	dev_to_node(&__bus->dev)
#endif
#define pcibios_assign_all_busses()	pci_has_flag(PCI_REASSIGN_ALL_BUS)

int pci_legacy_read(struct pci_bus *bus, loff_t port, u32 *val,
				size_t count);
int pci_legacy_write(struct pci_bus *bus, loff_t port, u32 val,
				size_t count);
int pci_mmap_legacy_page_range(struct pci_bus *bus,
					struct vm_area_struct *vma,
					enum pci_mmap_state mmap_state);

#ifndef	L_IOPORT_RESOURCE_OFFSET
#define	L_IOPORT_RESOURCE_OFFSET	0UL
#endif
#ifndef	L_IOMEM_RESOURCE_OFFSET
#define	L_IOMEM_RESOURCE_OFFSET		0UL
#endif

#endif /* __KERNEL__ */

#endif /* _L_PCI_H */
