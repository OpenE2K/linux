/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/cpu.h>
#include <linux/cpufreq.h>
#include <asm/io.h>
#include <linux/pci.h>
#include <linux/platform_data/i2c-l-i2c2.h>
#include <linux/pm_opp.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/regulator/consumer.h>
#include <asm/l_pmc.h>

#include "pmc.h"

static int get_pmc_cbase(struct l_pmc *l_pmc)
{
	int result = -ENODEV;

	struct resource r[] = {
		{
			.flags	= IORESOURCE_MEM,
			.start	= PMC_I2C_REGS_BASE,
			.end	= PMC_I2C_REGS_BASE + 0x20 - 1
		},
	};

	struct l_i2c2_platform_data pmc_i2c = {
		.bus_nr	         = -1,
		.base_freq_hz    = 100 * 1000 * 1000,
		.desired_freq_hz = 100 * 1000,
	};

	result = pci_enable_device_mem(l_pmc->pdev);

	if (result) {
		pci_dev_put(l_pmc->pdev);
		pr_err("pmc_init:"
				" failed to enable pci mem device\n");
		return result;
	}

	/* Initialize I2C master */
	r[0].start += pci_resource_start(l_pmc->pdev, E1CP_PMC_BAR);
	r[0].end   += pci_resource_start(l_pmc->pdev, E1CP_PMC_BAR);

	l_pmc->i2c_chan  =
		platform_device_register_resndata(&l_pmc->pdev->dev,
				"pmc-i2c", PLATFORM_DEVID_AUTO, r,
				ARRAY_SIZE(r),
				&pmc_i2c, sizeof(pmc_i2c));
	if (l_pmc->i2c_chan == NULL) {
		pr_err("pmc_init:"
				" failed to initialize pmc_i2c master\n");
	}

	return result;
}

static int pmc_pci_probe(struct l_pmc *l_pmc)
{
	int pdev_id = dev_to_node(&l_pmc->pdev->dev);
	struct platform_device *vdev;

	if (pdev_id < 0)
		pdev_id = 0;

/*
 *  R2000 has 3 temperature sensors (Core 0-3, Core 4-7, NB)
 *  embedded in chips's die, access to sensors (and other
 *  PMC functions) provided by NB registers;
 *
 *  E1C+ has PMC device embedded in root hub of
 *  SoC, access to two temp. sensors (Core & GPU)
 *  performed through PCI.
 *
 */

	struct resource r[] = {
		{
			.flags = IORESOURCE_MEM,
			.start = pci_resource_start(l_pmc->pdev, E1CP_PMC_BAR),
			.end   = pci_resource_start(l_pmc->pdev, E1CP_PMC_BAR)
					+ PMC_L_REGS_AREA_SIZE - 1,
		},
		{
			.flags = IORESOURCE_IRQ,
			.start = l_pmc->pdev->irq,
			.end   = l_pmc->pdev->irq,
		},
	};

	vdev = platform_device_register_resndata(&l_pmc->pdev->dev,
			"pmc_hwmon", pdev_id, r, ARRAY_SIZE(r), NULL, 0);

	if (IS_ERR(vdev)) {
		dev_err(&l_pmc->pdev->dev, "failed to create PMC platform device");
		return PTR_ERR(vdev);
	}

	l_pmc->vdev = vdev;

	return 0;
}

static void pmc_pci_remove(struct l_pmc *l_pmc)
{
	platform_device_unregister(l_pmc->vdev);
}


static int pmc_drv_probe(struct pci_dev *pdev, const struct pci_device_id *no_name)
{
	int res = 0;
	struct l_pmc *l_pmc = (struct l_pmc *)devm_kzalloc(&pdev->dev,
							sizeof(struct l_pmc), GFP_KERNEL);

	if (!l_pmc)
		return -ENOMEM;

	l_pmc->pdev = pdev;

	res = get_pmc_cbase(l_pmc);
	if (res) {
		pr_err("PMC: failed to get pmc_cbase err = %d\n", res);
		return res;
	}

#ifdef CONFIG_CPU_FREQ
	res = pmc_cpufreq_init();
#endif
	res = pmc_pci_probe(l_pmc);

	if (res) {
		pr_err("PMC: failed to hwmon err = %d\n", res);
		return res;
	}

	pci_set_drvdata(pdev, l_pmc);

	return res;
}

static void pmc_drv_remove(struct pci_dev *pdev)
{
	struct l_pmc *l_pmc = pci_get_drvdata(pdev);

	pmc_pci_remove(l_pmc);

#ifdef CONFIG_CPU_FREQ
	pmc_cpufreq_exit();
#endif

	if (l_pmc->i2c_chan)
		platform_device_unregister(l_pmc->i2c_chan);

}

static const struct pci_device_id pmc_drv_devices[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_HB) },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, pmc_drv_devices);


static struct pci_driver pmc_drv_driver = {
	.name     = "pmc_drv",
	.id_table = pmc_drv_devices,
	.probe    = pmc_drv_probe,
	.remove   = pmc_drv_remove,
};


static int pmc_drv_init(void)
{
	int result = pci_register_driver(&pmc_drv_driver);
	result = pmc_hwmon_init();

	return result;
}

static void pmc_drv_exit(void)
{
	pmc_hwmon_exit();
	pci_unregister_driver(&pmc_drv_driver);
}

module_init(pmc_drv_init);
module_exit(pmc_drv_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("PMC driver. For E1C+ and R2000");
MODULE_LICENSE("GPL v2");
MODULE_SOFTDEP("pre: max20730");

