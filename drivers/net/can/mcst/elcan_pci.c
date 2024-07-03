/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * PCI bus driver for MCST ELCAN/CAN2 controller
 *
 */

#include "elcan.h"
#include "elcan_debugfs.h"

struct elcan_pci_data {
	unsigned int freq;	/* Set the frequency */
	int bar;		/* PCI bar number */
	/* Callback for reset */
	void (*init)(const struct elcan_priv *priv, bool enable);
};


static u32 elcan_pci_read_reg_32(const struct elcan_priv *priv,
				 enum reg index)
{
	return ioread32(priv->base + priv->regs[index]);
}

static void elcan_pci_write_reg_32(const struct elcan_priv *priv,
				   enum reg index, u32 val)
{
	iowrite32(val, priv->base + priv->regs[index]);
}


static void elcan_pci_reset_pch(const struct elcan_priv *priv, bool enable)
{
	unsigned long time_out;

	if (enable) {
		elcan_pci_write_reg_32(priv, ELCAN_CTLSTA_REG,
				       BIT(CAN2_REGS__RESET));

		/* wait for reset complete */
		time_out = jiffies + msecs_to_jiffies(INIT_WAIT_RST);
		while ((elcan_pci_read_reg_32(priv, ELCAN_CTLSTA_REG) &
		       BIT(CAN2_REGS__RESET)) &&
			time_after(time_out, jiffies)) {
				cpu_relax();
		}
		if (time_after(jiffies, time_out))
			dev_warn(&priv->pdev->dev,
				"initialization is not completed\n");
	}
} /* elcan_pci_reset_pch */


/**
 ******************************************************************************
 * PCI Part
 ******************************************************************************
 **/

static int elcan_pci_probe(struct pci_dev *pdev,
			   const struct pci_device_id *ent)
{
	struct elcan_pci_data *elcan_pci_data = (void *)ent->driver_data;
	struct elcan_priv *priv;
	struct net_device *dev;
	void __iomem *addr;
	int ret;

	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "pci_enable_device FAILED\n");
		goto out;
	}

	ret = pci_request_regions(pdev, KBUILD_MODNAME);
	if (ret) {
		dev_err(&pdev->dev, "pci_request_regions FAILED\n");
		goto out_disable_device;
	}

#if 0 /* no msi */
	ret = pci_enable_msi(pdev);
	if (!ret) {
		dev_info(&pdev->dev, "MSI enabled\n");
		pci_set_master(pdev);
	}
#endif /* no msi */

	addr = pci_iomap(pdev, elcan_pci_data->bar,
			 pci_resource_len(pdev, elcan_pci_data->bar));
	if (!addr) {
		dev_err(&pdev->dev,
			"device has no PCI memory resources, "
			"failing adapter\n");
		ret = -ENOMEM;
		goto out_release_regions;
	}

	/* allocate the elcan device */
	dev = elcan_alloc_dev();
	if (!dev) {
		ret = -ENOMEM;
		goto out_iounmap;
	}

	priv = netdev_priv(dev);
	pci_set_drvdata(pdev, dev);
	SET_NETDEV_DEV(dev, &pdev->dev);

	dev->irq = pdev->irq;
	priv->base = addr;
	priv->pdev = pdev;
	priv->device = &pdev->dev;

	if (!elcan_pci_data->freq) {
		dev_err(&pdev->dev, "no clock frequency defined\n");
		ret = -ENODEV;
		goto out_free_elcan;
	} else {
		priv->can.clock.freq = elcan_pci_data->freq;
	}

	priv->regs = reg_map_elcan;
	/* Configure access to registers */
	priv->read_reg = elcan_pci_read_reg_32;
	priv->write_reg = elcan_pci_write_reg_32;

	priv->caninit = elcan_pci_data->init;

	ret = elcan_register_dev(dev);
	if (ret) {
		dev_err(&pdev->dev, "registering %s failed (err=%d)\n",
			KBUILD_MODNAME, ret);
		goto out_free_elcan;
	}

	elcan_dbg_board_init(priv);

	dev_info(&pdev->dev,
		 "%s device registered (rev=%d, irq=%d)\n", KBUILD_MODNAME,
		 elcan_pci_read_reg_32(priv, ELCAN_REV_ID_REG), dev->irq);

	return 0;

out_free_elcan:
	elcan_free_dev(dev);
out_iounmap:
	pci_iounmap(pdev, addr);
out_release_regions:
#if 0 /* no msi */
	pci_disable_msi(pdev);
	pci_clear_master(pdev);
#endif /* no msi */
	pci_release_regions(pdev);
out_disable_device:
	pci_disable_device(pdev);
out:
	return ret;
} /* elcan_pci_probe */

static void elcan_pci_remove(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct elcan_priv *priv = netdev_priv(dev);

	elcan_dbg_board_exit(priv);

	elcan_unregister_dev(dev);
	elcan_free_dev(dev);
	pci_iounmap(pdev, priv->base);
#if 0 /* no msi */
	pci_disable_msi(pdev);
	pci_clear_master(pdev);
#endif /* no msi */
	pci_release_regions(pdev);
	pci_disable_device(pdev);
} /* elcan_pci_remove */


static struct elcan_pci_data elcan_pch = {
	.freq = ELCAN_PCH_FREQ,
	.init = elcan_pci_reset_pch,
	.bar = 0,
};

#define ELCAN_ID(_vend, _dev, _driverdata) {		\
	PCI_DEVICE(_vend, _dev),			\
	.driver_data = (unsigned long)&_driverdata,	\
}

static const struct pci_device_id elcan_pci_tbl[] = {
	ELCAN_ID(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_ELCAN, elcan_pch),
	{},
};
static struct pci_driver elcan_pci_driver = {
	.name = KBUILD_MODNAME,
	.id_table = elcan_pci_tbl,
	.probe = elcan_pci_probe,
	.remove = elcan_pci_remove,
};


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

static int __init elcan_init(void)
{
	int status;

	pr_info(KBUILD_MODNAME ": v.%s", ELCAN_DRIVER_VERSION);

	elcan_dbg_init();

	status = pci_register_driver(&elcan_pci_driver);
	if (status != 0) {
		pr_err(KBUILD_MODNAME ": Could not register driver\n");
		goto devexit;
	}

	return 0;

devexit:
	elcan_dbg_exit();
	return status;
} /* elcan_init */


static void __exit elcan_exit(void)
{
	pci_unregister_driver(&elcan_pci_driver);

	elcan_dbg_exit();
} /* elcan_exit */


module_init(elcan_init);
module_exit(elcan_exit);


MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("PCI CAN bus driver for MCST ELCAN controller");
MODULE_SUPPORTED_DEVICE("ELCAN, DeviceID:" PCI_DEVICE_ID_MCST_ELCAN
			", VendorID:" PCI_DEVICE_ID_MCST_ELCAN);
MODULE_VERSION(ELCAN_DRIVER_VERSION);
