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

	FDEBUG;

	assert(pdev);
	if (!pdev)
		return -ENODEV;

	DEV_DBG(MXGBE_DBG_MSK_PCI, &pdev->dev, "PCI Probe: device %s\n",
		pci_name(pdev));

	dev_info(&pdev->dev, "initializing PCI device %04x:%04x\n",
		 pdev->vendor, pdev->device);

	/* PCI */
	if ((err = pci_enable_device(pdev))) {
		dev_err(&pdev->dev,
			"ERROR: Cannot enable PCI device, aborting\n");
		goto failure;
	}

	if ((err = pci_request_regions(pdev, DRIVER_NAME))) {
		dev_err(&pdev->dev,
			"ERROR: Cannot obtain PCI resources, aborting\n");
		goto failure_release_pci;
	}

	for (i = 0; i < MXGBE_PCI_BAR_NUMS; i++) {
		size = pci_resource_end(pdev, i) -
		       pci_resource_start(pdev, i) + 1;
		if ((bar_addr[i] = pci_iomap(pdev, i, size)) == NULL) {
			err = -ENODEV;
			dev_err(&pdev->dev,
				"ERROR: Cannot map BAR%d, aborting\n", i);
			goto failure_iounmap;
		}
		bar_addr_bus[i] = pci_resource_start(pdev, i);
	}

	/*
	pci_enable_pcie_error_reporting(pdev);
	*/

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		dev_warn(&pdev->dev,
			"WARNING: No usable 64bit DMA configuration\n");
	} else {
		pci_set_master(pdev);
		/*pci_set_cacheline_size(pdev);*/
	}

	if ((err = mxgbe_init_board(pdev, bar_addr, bar_addr_bus)))
		goto failure_iounmap;

	DEV_DBG(MXGBE_DBG_MSK_PCI, &pdev->dev, "PCI Probe: done\n");
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


	FDEBUG;

	assert(pdev);
	if (!pdev)
		return;

	DEV_DBG(MXGBE_DBG_MSK_PCI, &pdev->dev, "PCI Remove device\n");

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

	DEV_DBG(MXGBE_DBG_MSK_PCI, &pdev->dev, "PCI Remove: done\n");
} /* remove */


static void shutdown(struct pci_dev *pdev)
{
	FDEBUG;

	if (!pdev)
		return;

	DEV_DBG(MXGBE_DBG_MSK_PCI, &pdev->dev, "PCI Shutdown\n");

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
	.name		= DRIVER_NAME,
	.id_table	= ids,
	.probe		= probe,
	.remove		= remove,
	.shutdown	= shutdown,
};
