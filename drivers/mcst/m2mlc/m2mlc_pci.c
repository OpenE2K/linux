/**
 * m2mlc_pci.c - M2MLC module device driver
 *
 * PCI Device Driver Part
 */

#include "m2mlc.h"

#define PCI_BAR_NUMS 4


/* extern */
int m2mlc_init_board(struct pci_dev *pdev, void __iomem *bar_addr[],
		     phys_addr_t bar_addr_bus[]);
void m2mlc_release_board(struct pci_dev *pdev);


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
	void __iomem *bar_addr[PCI_BAR_NUMS] = {NULL};
	phys_addr_t bar_addr_bus[PCI_BAR_NUMS] = {0};
	/*char irq;*/


	assert(pdev);
	if (!pdev)
		return -ENODEV;

	DEV_DBG(M2MLC_DBG_MSK_PCI, &pdev->dev, "PCI Probe: device %s\n",
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

	for (i = 0; i < PCI_BAR_NUMS; i++) {
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

	/*pci_read_config_byte(pdev, PCI_INTERRUPT_LINE, &irq);*/

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(64))) {
		dev_warn(&pdev->dev,
			"WARNING: No usable 64bit DMA configuration\n");
	} else {
		pci_set_master(pdev);
		/*pci_set_cacheline_size(pdev);*/
	}

	if ((err = m2mlc_init_board(pdev, bar_addr, bar_addr_bus)))
		goto failure_iounmap;

	DEV_DBG(M2MLC_DBG_MSK_PCI, &pdev->dev, "PCI Probe: done\n");
	return 0;


failure_iounmap:
	for (i = 0; i < PCI_BAR_NUMS; i++) {
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
	m2mlc_priv_t *priv;
	void __iomem *bar_addr[PCI_BAR_NUMS] = {NULL};


	assert(pdev);
	if (!pdev)
		return;

	DEV_DBG(M2MLC_DBG_MSK_PCI, &pdev->dev, "PCI Remove device\n");

	priv = pci_get_drvdata(pdev);
	assert(priv);
	if (!priv)
		return;

	bar_addr[0] = priv->ecs_base;
	bar_addr[1] = priv->reg_base;
	bar_addr[2] = priv->buf_base;
	bar_addr[3] = priv->iom_base;

	m2mlc_release_board(pdev);
	pci_set_drvdata(pdev, NULL);

	for (i = 0; i < PCI_BAR_NUMS; i++) {
		if (bar_addr[i] != NULL)
			pci_iounmap(pdev, bar_addr[i]);
	}
	pci_release_regions(pdev);
	pci_disable_device(pdev);

	DEV_DBG(M2MLC_DBG_MSK_PCI, &pdev->dev, "PCI Remove: done\n");
} /* remove */


static DEFINE_PCI_DEVICE_TABLE(ids) = {
	{
		PCI_DEVICE(VENDOR_ID, DEVICE_ID)
	},
	{ 0, },
};

MODULE_DEVICE_TABLE(pci, ids);


/* PCI Device API Driver */
struct pci_driver m2mlc_pci_driver = {
	.name		= DRIVER_NAME,
	.id_table	= ids,
	.probe		= probe,
	.remove		= remove,
};
