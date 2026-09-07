/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */
#include <linux/platform_device.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/uio_driver.h>

#if defined(CONFIG_E2K)
#define IPLINKS_SUPPORTED() \
		(IS_MACHINE_E2S || IS_MACHINE_E8C || IS_MACHINE_E8C2 || \
		IS_MACHINE_E12C || IS_MACHINE_E16C)
#elif defined(CONFIG_E90S)
#define IPLINKS_SUPPORTED() \
		(e90s_get_cpu_type() == E90S_CPU_R2000)
#endif

static int iplinks_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct resource *res;
	void __iomem *base;
	int ret;
	static const char * const regs_name = {"IPCC regs"};
	struct uio_info *iplinks_uio_info;

#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
	if (!IPLINKS_SUPPORTED())
		return -ENODEV;
#endif

	iplinks_uio_info = devm_kzalloc(dev, sizeof(*iplinks_uio_info), GFP_KERNEL);

	if (!iplinks_uio_info)
		return -ENOMEM;

	dev_set_drvdata(dev, iplinks_uio_info);
	iplinks_uio_info->name = "iplinks";
	iplinks_uio_info->version = "1.0.0";
	iplinks_uio_info->irq = UIO_IRQ_NONE;

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	if (!res) {
		dev_err(dev, "failed to get mem resource");
		return -ENOMEM;
	}

	base = devm_ioremap(dev, res->start, resource_size(res));
	if (IS_ERR(base)) {
		dev_err(dev, "failed to map resource");
		return PTR_ERR(base);
	}

	iplinks_uio_info->mem[0].addr = res->start;
	iplinks_uio_info->mem[0].size = resource_size(res);
	iplinks_uio_info->mem[0].memtype = UIO_MEM_PHYS;
	iplinks_uio_info->mem[0].name = regs_name;

	ret = uio_register_device(&pdev->dev, iplinks_uio_info);
	if (ret) {
		dev_err(dev, "failed to register iplinks driver\n");
		return ret;
	}
	return ret;
}

static int iplinks_remove(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct uio_info *iplinks_uio_info = dev_get_drvdata(dev);

	uio_unregister_device(iplinks_uio_info);
	dev_set_drvdata(dev, NULL);
	devm_kfree(dev, iplinks_uio_info);
	return 0;
}

static const struct of_device_id iplinks_of_match[] = {
	{ .compatible = "mcst,iplinks", },
	{}
};

/* MODULE_DEVICE_TABLE(of, iplinks_of_match);
 * Disable autoloading */

static struct platform_driver iplinks_platdrv = {
	.driver = {
		.name = "iplinks",
		.of_match_table = iplinks_of_match,
	},
	.probe = iplinks_probe,
	.remove = iplinks_remove,
};
module_platform_driver(iplinks_platdrv);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("IPLINKS DRIVER");
