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

struct e2k_iommu;
struct pci_dev;
struct pci_bus;
enum pci_mmap_state;
struct pci_ops;

typedef struct iohub_sysdata {
	int	domain;		/* IOHUB (PCI) domain */
	int	node;		/* NUMA node */
	int	link;		/* local number of IO link on the node */
	/* IOHUB can be connected to EIOHUB and vice versa */
	bool	has_iohub;
	u8	iohub_revision;		/* IOHUB revision */
	u8	iohub_generation;	/* IOHUB generation */
	bool	has_eioh;
	u8	eioh_generation;	/* EIOHUB generation */
	u8	eioh_revision;		/* EIOHUB revision */

	struct resource		mem_space; /* pci registers memory */
	void *l_iommu;
} iohub_sysdata_t;

extern bool l_eioh_device(struct pci_dev *pdev);

#define iohub_revision(pdev)	({			\
	struct pci_config_window *_cfg = pdev->bus->sysdata; \
	struct iohub_sysdata *_sd = _cfg->priv;		\
	u8 _rev = l_eioh_device(pdev) ?		\
			_sd->eioh_revision & 0xf :	\
			_sd->iohub_revision >> 1;	\
	_rev;						\
})

#define iohub_generation(pdev)	({			\
	struct pci_config_window *_cfg = pdev->bus->sysdata; \
	struct iohub_sysdata *_sd = _cfg->priv;		\
	(l_eioh_device(pdev) ? _sd->eioh_generation :	\
				_sd->iohub_generation);	\
})

#define is_iohub_asic(pdev)	({			\
	struct pci_config_window *_cfg = pdev->bus->sysdata; \
	struct iohub_sysdata *_sd = _cfg->priv;		\
	u8 _rev = l_eioh_device(pdev) ?			\
			!(_sd->eioh_revision & 0xf0) :	\
			_sd->iohub_revision & 1;	\
	_rev;						\
})

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


extern struct blocking_notifier_head l_pci_register_done_chain;

#endif /* __KERNEL__ */

#endif /* _L_PCI_H */
