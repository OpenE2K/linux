/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Elbrus I2C_SPI controller support
 */

#include <linux/irq.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/of.h>
#include <linux/pci.h>
#include <linux/spi/spi.h>
#include <asm/io.h>
#include <asm/pic.h>
#include <asm-l/i2c-spi.h>
#include "i2c-spi.h"

static struct i2c_spi_data iohub_iohub2_driver_data = {
	.num_chipselect = 4,
	.i2c_device_exist = true,
	.mode1_unsupported = true,
	.ext_freq_unsupported = true,
};

static struct i2c_spi_data eioh_driver_data = {
	.num_chipselect = 4,
	.i2c_device_exist = true,
};

static struct i2c_spi_data eioh2_driver_data = {
	.num_chipselect = 6,
};

/*
 * Elbrus I2C-SPI and Reset Controller that is part of Elbrus IOHUB
 * and is implemented as a pci device in iohub.
 */
static const struct pci_device_id i2c_spi_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ELBRUS, PCI_DEVICE_ID_MCST_I2CSPI),
		.driver_data = (unsigned long)&iohub_iohub2_driver_data },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_SM),
		.driver_data = (unsigned long)&iohub_iohub2_driver_data },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_I2C_SPI),
		.driver_data = (unsigned long)&iohub_iohub2_driver_data },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
		PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI),
		.driver_data = (unsigned long)&eioh_driver_data },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_SPI),
		.driver_data = (unsigned long)&eioh2_driver_data },
	{ 0, }
};

struct i2c_spi_priv {
	struct platform_device *i2c;
	struct platform_device *spi;
};

static void i2c_spi_cleanup(struct pci_dev *pdev)
{
	struct i2c_spi_priv *priv = pci_get_drvdata(pdev);
	platform_device_unregister(priv->i2c);
	platform_device_unregister(priv->spi);
	/* don't do this. ioapic also will be disabled.*/
	/* pci_disable_device(pdev); */
}

static int i2c_spi_probe(struct pci_dev *pdev,
		const struct pci_device_id *id)
{
	int ret = 0;
	struct i2c_spi_data *pdata = (struct i2c_spi_data *)id->driver_data;
	struct resource res[] = {
		{
			.flags	= IORESOURCE_MEM,
			.start	= pci_resource_start(pdev, 0),
			.end	= pci_resource_end(pdev, 0),
		}, {
			.flags	= IORESOURCE_MEM,
			.start	= pci_resource_start(pdev, 1),
			.end	= pci_resource_end(pdev, 1),
		}, {
			.flags	= IORESOURCE_IRQ,
			.start	= pdev->irq,
			.end	= pdev->irq,
		},
	};
	struct i2c_spi_priv *priv = devm_kzalloc(&pdev->dev, sizeof(*priv), GFP_KERNEL);
	int pdev_id = dev_to_node(&pdev->dev);
	if (pdev_id < 0)
		pdev_id = 0;
#ifdef CONFIG_EPIC
	/* Handle eioh + iohub2 hardware configuration: */
	if ((cpu_has_epic() &&
			pdev->device != PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI &&
			pdev->device != PCI_DEVICE_ID_MCST_SPI) ||
		(!cpu_has_epic() &&
			(pdev->device == PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI ||
			pdev->device == PCI_DEVICE_ID_MCST_SPI))) {
		pdev_id += MAX_NUMNODES;
	}
#endif
	if (!priv)
		return -ENOMEM;

	pci_set_drvdata(pdev, priv);
	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to setup  Elbrus reset control "
			"in i2c-iohub: Unable to make enable device\n");
		goto out;
	}
	priv->spi = platform_device_register_resndata(&pdev->dev, "l_spi",
			pdev_id, res, ARRAY_SIZE(res), pdata, sizeof(*pdata));
	if (IS_ERR(priv->spi)) {
		ret = PTR_ERR(priv->spi);
		goto out;
	}
	if (pdata->i2c_device_exist) {
		priv->i2c = platform_device_register_resndata(&pdev->dev,
				"l_i2c", pdev_id, res,
				ARRAY_SIZE(res), NULL, 0);
		if (IS_ERR(priv->i2c)) {
			ret = PTR_ERR(priv->i2c);
			goto out;
		}
	}
out:
	if (ret)
		i2c_spi_cleanup(pdev);
	return ret;
}

static void i2c_spi_remove(struct pci_dev *pdev)
{
	i2c_spi_cleanup(pdev);
	pci_set_drvdata(pdev, NULL);
}

static int i2c_spi_suspend(struct pci_dev *dev, pm_message_t state)
{
	/* Do not disable DMA: ioapic will not be able to send interrupts */
	return 0;
}

static int i2c_spi_resume(struct pci_dev *dev)
{
	return 0;
}

static struct pci_driver i2c_spi_driver = {
	.name		= "i2c_spi",
	.id_table	= i2c_spi_ids,
	.probe		= i2c_spi_probe,
	.remove		= i2c_spi_remove,
	.suspend	= i2c_spi_suspend,
	.resume		= i2c_spi_resume,
};

__init
static int i2c_spi_init(void)
{
	return pci_register_driver(&i2c_spi_driver);
}
module_init(i2c_spi_init);

__exit
static void i2c_spi_exit(void)
{
	pci_unregister_driver(&i2c_spi_driver);
}
module_exit(i2c_spi_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Elbrus I2C-SPI SMBus driver");
MODULE_LICENSE("GPL v2");
