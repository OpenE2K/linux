/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/i2c/pca953x.h>
#include <asm/gpio.h>
#include <asm-l/devtree.h>
#include <asm-l/i2c-spi.h>

#define BUTTERFLY_PCA953X_LINES_NR	8
#ifdef CONFIG_E2K
#if IS_ENABLED(CONFIG_IPE2ST_POWER)
static struct pca953x_platform_data e2k_i2c_board_pdata[] = {
	[0] = { .gpio_base	= ARCH_NR_IOHUB_GPIOS * MAX_NUMIOHUBS, },
};

static struct pca953x_platform_data e8c_i2c_board_pdata[] = {
	[0] = { .gpio_base	= ARCH_MAX_NR_OWN_GPIOS * MAX_NUMIOHUBS, },
};

static struct i2c_board_info __initdata e2k_i2c_board_info1[] = {
#if IS_ENABLED(CONFIG_LTC4306)
	{
		I2C_BOARD_INFO("ltc4306", 0x44),
	},
#endif
#if IS_ENABLED(CONFIG_GPIO_PCA953X)
	{
		I2C_BOARD_INFO("pca9536", 0x41),
		.platform_data  = &e2k_i2c_board_pdata[0],
	},
#endif
#if IS_ENABLED(CONFIG_ISL22317)
	{
		I2C_BOARD_INFO("isl22317", 0x2a),
	},
#endif
#if IS_ENABLED(CONFIG_SENSORS_LTC4151)
	{
		I2C_BOARD_INFO("ltc4151", 0x6a),
	},
#endif

#if IS_ENABLED(CONFIG_SENSORS_LTC2978)
	{
		I2C_BOARD_INFO("ltm4676", 0x40),
	},
	{
		I2C_BOARD_INFO("ltm4676", 0x4f),
	},
#endif

};

static struct i2c_board_info __initdata e2k_i2c_board_info_e8c[] = {
#if IS_ENABLED(CONFIG_LTC4306)
	{
		I2C_BOARD_INFO("ltc4306", 0x4e),
	},
#endif
#if IS_ENABLED(CONFIG_GPIO_PCA953X)
	{
		I2C_BOARD_INFO("pca9534", 0x24),
		.platform_data  = &e8c_i2c_board_pdata[0],
	},
#endif
#if IS_ENABLED(CONFIG_ISL22317)
	{
		I2C_BOARD_INFO("isl22317", 0x2a),
	},
#endif
#if IS_ENABLED(CONFIG_SENSORS_LTC4151)
	{
		I2C_BOARD_INFO("ltc4151", 0x6a),
	},
#endif

#if IS_ENABLED(CONFIG_SENSORS_LTC2978)
	{
		I2C_BOARD_INFO("ltm4676", 0x40),
	},
	{
		I2C_BOARD_INFO("ltm4676", 0x4f),
	},
#endif

};
#endif /* CONFIG_IPE2ST_POWER */
static const char * const iohub2_spmc[] = {
	"spmc.0", "spmc.1", "spmc.2", "spmc.3",
	"spmc.4", "spmc.5", "spmc.6", "spmc.7",
};
static const char * const iohub2_pci_req[] = {
	"pci-req.0", "pci-req.1", "pci-req.2", "pci-req.3",
	"pci-req.4", "pci-req.5", "pci-req.6", "pci-req.7",
};
static const char * const iohub2_pe0[] = {
	"pe0-ctrl.0", "pe0-ctrl.1", "pe0-ctrl.2", "pe0-ctrl.3",
	"pe0-ctrl.4", "pe0-ctrl.5", "pe0-ctrl.6", "pe0-ctrl.7",
};
static const char * const iohub2_pe1[] = {
	"pe1-ctrl.0", "pe1-ctrl.1", "pe1-ctrl.2", "pe1-ctrl.3",
	"pe1-ctrl.4", "pe1-ctrl.5", "pe1-ctrl.6", "pe1-ctrl.7",
};

static struct pca953x_platform_data iohub2_i2c_board_pdata[] = {
	[0] = { .gpio_base	= ARCH_NR_IOHUB2_GPIOS,
		.names = iohub2_spmc,
	},
	[1] = { .gpio_base	= 1 * BUTTERFLY_PCA953X_LINES_NR +
					ARCH_NR_IOHUB2_GPIOS,
		.names = iohub2_pci_req,
	},
	[2] = { .gpio_base	= 2 * BUTTERFLY_PCA953X_LINES_NR +
					ARCH_NR_IOHUB2_GPIOS,
		.names = iohub2_pe0,
	},
	[3] = { .gpio_base	= 3 * BUTTERFLY_PCA953X_LINES_NR +
					ARCH_NR_IOHUB2_GPIOS,
		.names = iohub2_pe1,
	},
};

static struct i2c_board_info __initdata iohub2_i2c_devices_bus1[] = {
	{
		I2C_BOARD_INFO("pca9534", 0x20),
		.platform_data  = &iohub2_i2c_board_pdata[0],
	},
};

static struct i2c_board_info __initdata iohub2_i2c_devices_bus2[] = {
	{
		I2C_BOARD_INFO("pca9534", 0x20),
		.platform_data  = &iohub2_i2c_board_pdata[1],
	},
	{
		I2C_BOARD_INFO("pca9534", 0x21),
		.platform_data  = &iohub2_i2c_board_pdata[2],
	},
	{
		I2C_BOARD_INFO("pca9534", 0x22),
		.platform_data  = &iohub2_i2c_board_pdata[3],
	},
};

static struct i2c_board_info __initdata iohub2_i2c_devices_bus3[] = {
	{
		I2C_BOARD_INFO("pdt012", 0x10),
	},
	{
		I2C_BOARD_INFO("pdt012", 0x14),
	},
};


static struct i2c_board_info __initdata pmc_i2c_devices_bus[] = {
	{
		I2C_BOARD_INFO("udt020", 0x10),
	},
	{
		I2C_BOARD_INFO("udt020", 0x13),
	},
	{
		I2C_BOARD_INFO("pdt012", 0x14),
	},
};

#endif /* CONFIG_E2K */

/* Occupy gpios after iohub's ones */
static struct pca953x_platform_data butterfly_pca953x_pdata[] = {
	[0] = { .gpio_base	= ARCH_NR_IOHUB_GPIOS * MAX_NUMIOHUBS + 0 * 8, },
	[1] = { .gpio_base	= ARCH_NR_IOHUB_GPIOS * MAX_NUMIOHUBS + 1 * 8, },
	[2] = { .gpio_base	= ARCH_NR_IOHUB_GPIOS * MAX_NUMIOHUBS + 2 * 8, },
	[3] = { .gpio_base	= ARCH_NR_IOHUB_GPIOS * MAX_NUMIOHUBS + 3 * 8, },
};

static struct i2c_board_info __initdata butterfly_i2c_devices_bus0[] = {
	{
		I2C_BOARD_INFO("pca9534",	0x20),
		.platform_data	= &butterfly_pca953x_pdata[0],
	},
	{
		I2C_BOARD_INFO("ucd9080",	0x60),
	},
};
static struct i2c_board_info __initdata butterfly_i2c_devices_bus1[] = {
	{
		I2C_BOARD_INFO("pca9534",	0x20),
		.platform_data	= &butterfly_pca953x_pdata[1],
	},
};
static struct i2c_board_info __initdata butterfly_i2c_devices_bus2[] = {
	{
		I2C_BOARD_INFO("pca9534",	0x20),
		.platform_data	= &butterfly_pca953x_pdata[2],
	},
};
static struct i2c_board_info __initdata butterfly_i2c_devices_bus3[] = {
	{
		I2C_BOARD_INFO("pca9534",	0x20),
		.platform_data	= &butterfly_pca953x_pdata[3],
	},
};

static int __init i2c_board_info_init(void)
{
#ifdef CONFIG_OF
	if (devtree_detected)
		return 0;
#endif

#ifdef	CONFIG_E2K
	if (0) {
#else
	if (1) {
#endif
		int i;
		for (i = 0; i < ARRAY_SIZE(butterfly_pca953x_pdata); i++)
			butterfly_pca953x_pdata[i].gpio_base =
				i * BUTTERFLY_PCA953X_LINES_NR +
					ARCH_NR_IOHUB_GPIOS * num_online_iohubs();

		i2c_register_board_info(0, butterfly_i2c_devices_bus0,
				ARRAY_SIZE(butterfly_i2c_devices_bus0));
		i2c_register_board_info(1, butterfly_i2c_devices_bus1,
				ARRAY_SIZE(butterfly_i2c_devices_bus1));
		i2c_register_board_info(2, butterfly_i2c_devices_bus2,
				ARRAY_SIZE(butterfly_i2c_devices_bus2));
		i2c_register_board_info(3, butterfly_i2c_devices_bus3,
				ARRAY_SIZE(butterfly_i2c_devices_bus3));
	} else {
#ifdef	CONFIG_E2K
	if (bootblock_virt->info.bios.mb_type ==
		    MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK
	   ) {
		i2c_register_board_info(1, iohub2_i2c_devices_bus1,
				ARRAY_SIZE(iohub2_i2c_devices_bus1));
		i2c_register_board_info(2, iohub2_i2c_devices_bus2,
				ARRAY_SIZE(iohub2_i2c_devices_bus2));
		i2c_register_board_info(3, iohub2_i2c_devices_bus3,
				ARRAY_SIZE(iohub2_i2c_devices_bus3));
	} else if (bootblock_virt->info.bios.mb_type == MB_TYPE_E1CP_PMC  ||
			bootblock_virt->info.bios.mb_type ==
							MB_TYPE_MBE1C_PC) {
		i2c_register_board_info(3, iohub2_i2c_devices_bus3,
				ARRAY_SIZE(iohub2_i2c_devices_bus3));
		i2c_register_board_info(4, pmc_i2c_devices_bus,
				ARRAY_SIZE(pmc_i2c_devices_bus));
	} else if (bootblock_virt->info.bios.mb_type ==
			MB_TYPE_E8C) {
			int j;
			for (j = 0; j < I2C_MAX_BUSSES; j++)
				i2c_register_board_info(j,
					e2k_i2c_board_info_e8c,
					ARRAY_SIZE(e2k_i2c_board_info_e8c));
	} else {
#if IS_ENABLED(CONFIG_IPE2ST_POWER)
		if (iohub_i2c_line_id) {
			i2c_register_board_info(iohub_i2c_line_id,
					e2k_i2c_board_info1,
					ARRAY_SIZE(e2k_i2c_board_info1));
		} else {
			/* if adapter number is not given through kernel
			 * command line - create ipe2st devices on all
			 * adapters.
			 */
			int ii;
			for (ii = 0; ii < I2C_MAX_BUSSES; ii++) {
				i2c_register_board_info(ii,
					e2k_i2c_board_info1,
					ARRAY_SIZE(e2k_i2c_board_info1));
			}
		}
#endif /* CONFIG_IPE2ST_POWER */
	}
#endif
	}
	return 0;
}

module_init(i2c_board_info_init);
