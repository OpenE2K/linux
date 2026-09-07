/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/uio_driver.h>

static int ddrmem_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *r;
	void __iomem *base;
	int ret;
	static const char * const regs[] = {"MC regs", "DDR phys regs"};
	struct uio_info *ddrmem_uio_info = devm_kzalloc(dev, sizeof(struct uio_info), GFP_KERNEL);

	if (!ddrmem_uio_info) {
		dev_err(dev, "ddrmem: devm_kzalloc() failed for uio_info struct\n");
		return -ENOMEM;
	}
	dev_set_drvdata(dev, ddrmem_uio_info);
	ddrmem_uio_info->name = "ddrmem";
	ddrmem_uio_info->version = "1.0.0";
	ddrmem_uio_info->irq = UIO_IRQ_NONE;

	for (int i = 0; i < 2; ++i) {
		r = platform_get_resource(pdev, IORESOURCE_MEM, i);
		if (!r) {
			dev_err(dev, "No MEM resource available!");
			return -ENOMEM;
		}
		base = devm_ioremap(dev, r->start, resource_size(r));
		if (IS_ERR(base)) {
			dev_err(dev, "Unable to ioremap base!");
			return PTR_ERR(base);
		}
		ddrmem_uio_info->mem[i].addr = r->start;
		ddrmem_uio_info->mem[i].size = resource_size(r);
		ddrmem_uio_info->mem[i].memtype = UIO_MEM_PHYS;
		ddrmem_uio_info->mem[i].name = regs[i];
	}
	ret = uio_register_device(&pdev->dev, ddrmem_uio_info);
	if (ret) {
		dev_err(dev, "ddrmem: uio_register_device() failed (%d)\n", ret);
		return ret;
	}
	return ret;
}

static int ddrmem_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct uio_info *ddrmem_uio_info = dev_get_drvdata(dev);

	uio_unregister_device(ddrmem_uio_info);
	dev_set_drvdata(dev, NULL);
	devm_kfree(dev, ddrmem_uio_info);
	return 0;
}

static const struct of_device_id ddrmem_of_match[] = {
	{ .compatible = "mcst,uncore_mc", },
	{}
};

/* MODULE_DEVICE_TABLE(of, ddrmem_of_match);
 * Disable autoloading */

static struct platform_driver ddrmem_pldr = {
	.driver = {
		.name = "ddrmem",
		.of_match_table = ddrmem_of_match,
	},
	.probe = ddrmem_probe,
	.remove = ddrmem_remove,
};
module_platform_driver(ddrmem_pldr);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("DDR MEM DRIVER");
