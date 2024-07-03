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
#include <asm/io_apic.h>
#include <asm/epic.h>

#include <asm-l/i2c-spi.h>

/*
 * Elbrus I2C-SPI and Reset Controller that is part of Elbrus IOHUB
 * and is implemented as a pci device in iohub.
 */

static struct pci_device_id i2c_spi_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_ELBRUS, PCI_DEVICE_ID_MCST_I2CSPI) },
 	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_SM) },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_I2C_SPI) },
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
		PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI) },
	{ 0, }
};

struct i2c_spi_priv {
	struct platform_device *i2c;
	struct platform_device *spi;
};

static void i2c_spi_clenup(struct pci_dev *pdev, int stage)
{
	struct i2c_spi_priv *priv = pci_get_drvdata(pdev);
	switch (stage) {
	case 4:
		platform_device_unregister(priv->i2c);
		fallthrough;
	case 3:
		platform_device_unregister(priv->spi);
		fallthrough;
	case 2:
		/* don't do this. ioapic also will be disabled.*/
		/*pci_disable_device(pdev);*/
		fallthrough;
	case 1:
		kfree(priv);
	}
}

static int i2c_spi_probe(struct pci_dev *pdev,
		const struct pci_device_id *id)
{
	int ret = 0, stage = 0;
	/* HACK: boot sets irq for watchdog, so we have to fix it */
	int irq = pdev->device == PCI_DEVICE_ID_MCST_I2CSPI ? 15 :
		  pdev->device == PCI_DEVICE_ID_MCST_I2C_SPI ? 7 : 0;
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
			.start	= pdev->irq + irq,
			.end	= pdev->irq + irq,
		},
	};
	struct i2c_spi_priv *priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	int pdev_id = dev_to_node(&pdev->dev);
	if (pdev_id < 0)
		pdev_id = 0;
#ifdef CONFIG_EPIC
	if ((cpu_has_epic() && pdev->device !=
				PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI) ||
		(!cpu_has_epic() && pdev->device ==
				PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI)) {
		 pdev_id += MAX_NUMNODES;
	}
#endif
	if (!priv)
		return -ENOMEM;
	stage++;
	ret = pci_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev,
			"Failed to setup  Elbrus reset control "
			"in i2c-iohub: Unable to make enable device\n");
		goto out;
	}
	stage++;

	priv->i2c = platform_device_register_resndata(&pdev->dev,
			"l_i2c", pdev_id, res, ARRAY_SIZE(res), NULL, 0);
	if (IS_ERR(priv->i2c)) {
		ret = PTR_ERR(priv->i2c);
		goto out;
	}

	stage++;
	priv->spi = platform_device_register_resndata(&pdev->dev, "l_spi",
			pdev_id, res, ARRAY_SIZE(res), NULL, 0);
	if (IS_ERR(priv->spi)) {
		ret = PTR_ERR(priv->spi);
		goto out;
	}
	stage++;
	pci_set_drvdata(pdev, priv);
out:
	if (ret)
		i2c_spi_clenup(pdev, stage);
	return ret;
}

static void i2c_spi_remove(struct pci_dev *pdev)
{
	i2c_spi_clenup(pdev, 4);
	pci_set_drvdata(pdev, NULL);
}

static int i2c_spi_suspend(struct pci_dev *dev, pm_message_t state)
{
	/*Do not disable DMA: ioapic will not be able to send interrupts*/
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
