/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_pci.c - MXGBE module device driver
 *
 * PCI Device Driver Part
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "kcompat.h"


/* extern */
int mxgbe_init_board(struct pci_dev *pdev, void __iomem *bar_addr[],
		     phys_addr_t bar_addr_bus[]);
void mxgbe_release_board(struct pci_dev *pdev);

/* eldwcxpcs.ko */
int eldwcxpcs_get_mpll_mode(struct pci_dev *pdev);
/* PCS MPLL MODE */
#define MPLL_MODE_10G		0
#define MPLL_MODE_1G		1
#define MPLL_MODE_2G5		2
#define MPLL_MODE_1G_BIF	3


/**
 * Device Initialization Routine
 *
 * @pdev: PCI device information struct
 * @pid: entry in ids
 *
 * Returns 0 on success, negative on failure
 *
 * probe initializes an adapter identified by a pci_dev structure.
 * The OS initialization, configuring of the adapter private structure,
 * and a hardware reset occur.
 */
static int probe(struct pci_dev *pdev, const struct pci_device_id *pid)
{
	int err;
	int i;
	size_t size;
	void __iomem *bar_addr[MXGBE_PCI_BAR_NUMS] = {NULL};
	phys_addr_t bar_addr_bus[MXGBE_PCI_BAR_NUMS] = {0};
	struct device_node *np = dev_of_node(&pdev->dev);
	const char *of_status_prop = NULL;
	int mpllm;
	u32 val;
	unsigned long timestart;

	/* check cmdline param */
	if (mxgbe_status == 0) {
		dev_warn(&pdev->dev, "device disabled in cmdline\n");
		return -ENODEV;
	} else if (mxgbe_status > 1) {
		/* check devtree config */
		if (np) {
			of_status_prop = of_get_property(np, "status", NULL);
			if (!strcmp(of_status_prop, "disabled")) {
				dev_warn(&pdev->dev,
					"device disabled in devicetree\n");
				return -ENODEV;
			}
		} else {
			dev_warn(&pdev->dev,
				 "devicetree for node not found!\n");
		}
	}

	/* PCS MPLL mode: 0-10G, 1-1G, 2-2.5G, 3-bifurcation */
	mpllm = eldwcxpcs_get_mpll_mode(pdev);
	if (mpllm < 0) {
		dev_err(&pdev->dev,
			 "wrong PCS MPLL mode (%d)\n", mpllm);
		return -ENODEV;
	} else {
		dev_dbg(&pdev->dev,
			 "PCS MPLL mode (%d)\n", mpllm);
	}
	if (mpllm != MPLL_MODE_10G) {
		dev_warn(&pdev->dev,
			 "10G device disabled, use 1G device\n");
		return -ENODEV;
	}

	dev_info(&pdev->dev, "initializing PCI device %04x:%04x\n",
		 pdev->vendor, pdev->device);

	/* PCI */
	if ((err = pci_enable_device(pdev))) {
		dev_err(&pdev->dev,
			"Cannot enable PCI device, aborting\n");
		goto failure;
	}

	if ((err = pci_request_regions(pdev, KBUILD_MODNAME))) {
		dev_err(&pdev->dev,
			"Cannot obtain PCI resources, aborting\n");
		goto failure_release_pci;
	}

	for (i = 0; i < MXGBE_PCI_BAR_NUMS; i++) {
		size = pci_resource_end(pdev, i) -
		       pci_resource_start(pdev, i) + 1;
		if ((bar_addr[i] = pci_iomap(pdev, i, size)) == NULL) {
			err = -ENODEV;
			dev_err(&pdev->dev,
				"Cannot map BAR%d, aborting\n", i);
			goto failure_iounmap;
		}
		bar_addr_bus[i] = pci_resource_start(pdev, i);
	}

	/*
	pci_enable_pcie_error_reporting(pdev);
	*/

	/* RESET */
#define CFGSPACE_RST_REG 0x40 /* +40h */
#define CFGSPACE_RST 0x40 /* bit 6 */
	pci_write_config_dword(pdev, CFGSPACE_RST_REG, CFGSPACE_RST);
	timestart = jiffies;
	do {
		err = pci_read_config_dword(pdev, CFGSPACE_RST_REG, &val);
		if (err) {
			dev_warn(&pdev->dev,
				"HW Reset (CFGSPACE_RST) not done\n");
			break;
		}
		if (time_after(jiffies, timestart + HZ)) {
			dev_warn(&pdev->dev,
				"HW Reset (CFGSPACE_RST) not done - timeout\n");
			break;
		}
	} while (val & CFGSPACE_RST);

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		dev_warn(&pdev->dev,
			"No usable 64bit DMA configuration\n");
	} else {
		pci_set_master(pdev);
		/*pci_set_cacheline_size(pdev);*/
	}

	if ((err = mxgbe_init_board(pdev, bar_addr, bar_addr_bus)))
		goto failure_iounmap;

	dev_dbg(&pdev->dev, "PCI probe: done\n");

	return 0;


failure_iounmap:
	for (i = 0; i < MXGBE_PCI_BAR_NUMS; i++) {
		if (bar_addr[i] != NULL)
			pci_iounmap(pdev, bar_addr[i]);
	}
	pci_release_regions(pdev);
failure_release_pci:
	pci_disable_device(pdev);
failure:
	return err;
} /* probe */


/**
 * Device Removal Routine
 * @pdev: PCI device information struct
 *
 * remove is called by the PCI subsystem to alert the driver
 * that it should release a PCI device.  The could be caused by a
 * Hot-Plug event, or because the driver is going to be removed from
 * memory.
 */
static void remove(struct pci_dev *pdev)
{
	int i;
	mxgbe_priv_t *priv;
	void __iomem *bar_addr[MXGBE_PCI_BAR_NUMS] = {NULL};

	assert(pdev);
	if (!pdev)
		return;

	dev_dbg(&pdev->dev, "PCI remove device\n");

	priv = pci_get_drvdata(pdev);
	assert(priv);
	if (!priv)
		return;

	bar_addr[0] = priv->bar0_base;

	mxgbe_release_board(pdev);
	pci_set_drvdata(pdev, NULL);

	for (i = 0; i < MXGBE_PCI_BAR_NUMS; i++) {
		if (bar_addr[i] != NULL)
			pci_iounmap(pdev, bar_addr[i]);
	}
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	dev_dbg(&pdev->dev, "PCI remove: done\n");
} /* remove */


static void shutdown(struct pci_dev *pdev)
{
	if (!pdev)
		return;

	dev_dbg(&pdev->dev, "PCI shutdown\n");

	mxgbe_release_board(pdev);

	pci_save_state(pdev);
	pci_clear_master(pdev);
} /* shutdown */


static DEFINE_PCI_DEVICE_TABLE(ids) = {
	{
		PCI_DEVICE(MXGBE_VENDOR_ID, MXGBE_DEVICE_ID)
	},
	{ 0, },
};

MODULE_DEVICE_TABLE(pci, ids);


/* PCI Device API Driver */
struct pci_driver mxgbe_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= ids,
	.probe		= probe,
	.remove		= remove,
	.shutdown	= shutdown,
};
