// SPDX-License-Identifier: GPL-2.0
/*
 * Hantro driver on pcie fpga.
 *
 * Copyright (c) 2020, VeriSilicon Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You may obtain a copy of the GNU General Public License
 * Version 2 at the following locations:
 * https://opensource.org/licenses/gpl-2.0.php
 */
#include <linux/pci.h>
#include "hantro_pcie.h"

#ifdef VSI_FPGA_PCIE
#ifdef PLATFORM_GEN7
#define PCI_VENDOR_ID_HANTRO		0x10ee // 0x16c3
#define PCI_DEVICE_ID_HANTRO_PCI	0x9014 // 0x7011
/* Base address got control register */
#define PCI_H2_BAR					2
/* Base address DDR register */
#define PCI_DDR_BAR					0
#else
#define PCI_VENDOR_ID_HANTRO		0x10ee // 0x16c3
#define PCI_DEVICE_ID_HANTRO_PCI	0x8014 // 0x7011
/* Base address got control register */
#define PCI_H2_BAR					4
/* Base address DDR register */
#define PCI_DDR_BAR					0
#endif //PLATFORM_GEN7

#else //customer set own PCIE number
#define PCI_VENDOR_ID_HANTRO	 PCI_VENDOR_ID_MCST_TMP
#define PCI_DEVICE_ID_HANTRO_PCI PCI_DEVICE_ID_MCST_VC9000D
/* Base address got control register */
#define PCI_H2_BAR				 (0)
/* Base address DDR register */
#undef PCI_DDR_BAR
#endif

#if defined(CONFIG_MCST)
int pcie_init(struct hantro_pci_t *pci_par, struct pci_dev *dev)
#else
int pcie_init(struct hantro_pci_t *pci_par)
#endif
{
#if !defined(CONFIG_MCST)
	struct pci_dev *dev = NULL; /* PCI device structure. */
#endif
	unsigned long
		base_hdwr; /* PCI base register address (Hardware address) */
#ifdef PCI_DDR_BAR
	unsigned long base_ddr_hw; /* PCI base register address (memalloc) */
#endif
	u32 base_len; /* Base register address Length */
#ifdef PCI_DDR_BAR
	u32 ddr_len; /* Base register address Length */
#endif

#if !defined(CONFIG_MCST)
	dev = pci_get_device(PCI_VENDOR_ID_HANTRO, PCI_DEVICE_ID_HANTRO_PCI,
			     dev);
#endif
	if (!dev) {
		pr_err("Init: Hardware not found.\n");
		goto out;
	}

	if (pci_enable_device(dev) < 0) {
		pr_err("Init: Device not enabled.\n");
		goto out;
	}
	pci_set_master(dev);

	base_hdwr = pci_resource_start(dev, PCI_H2_BAR);
	if (base_hdwr < 0) {
		pr_info("Init: Base Address not set.\n");
		goto out_pci_disable_device;
	}
	pr_info("Base hw val 0x%llx\n", (unsigned long long)base_hdwr);

	base_len = pci_resource_len(dev, PCI_H2_BAR);
	pr_info("Base hw len 0x%x\n", (unsigned int)base_len);

#ifdef PCI_DDR_BAR
	base_ddr_hw = pci_resource_start(dev, PCI_DDR_BAR);
	if (base_ddr_hw == 0) {
		pr_info("PcieInit: Base Address not set.\n");
		goto out_pci_disable_device;
	}
	pr_info("Base memory val 0x%08x\n", (unsigned int)base_ddr_hw);

	ddr_len = pci_resource_len(dev, PCI_DDR_BAR);
	pr_info("Base memory len 0x%x\n", (unsigned int)ddr_len);
#endif

	if (pci_enable_msi(dev)) {
		pr_debug("Init: pci_enable_msi() failed.\n");
	}
	pci_par->dev = dev;
	pci_par->irq = dev->irq;
	pr_info("Init: PCI IRQ = %d\n", dev->irq);

	pci_par->pci_base_reg_hw = base_hdwr;
	pci_par->pci_base_reg_len = base_len;
#ifdef PCI_DDR_BAR
	pci_par->pci_base_ddr_hw = base_ddr_hw;
	pci_par->pci_base_ddr_len = ddr_len;
#endif
	return 0;

out_pci_disable_device:
	pci_disable_device(dev);
out:
	return -1;
}

int pcie_exit(struct pci_dev *dev)
{
//	pci_disable_device(dev);
	return 1;
}
