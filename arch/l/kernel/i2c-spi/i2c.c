/*
 * Elbrus I2C controller support
 *
 * Note: we assume there can only be one I2C_SPI device in domain 0, with one
 * SMBus interface on i2c bus 0.
 *
 * Copyright (C) 2011-2012 Evgeny Kravstunov <kravtsunov_e@mcst.ru>,
 *                         Pavel Panteleev <panteleev_p@mcst.ru>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/i2c.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/stddef.h>
#include <asm/io.h>
#include <asm/iolinkmask.h>
#include <asm/gpio.h>
#include <linux/i2c/pca953x.h>

#include <asm-l/i2c-spi.h>
#include <asm-l/nmi.h>

/* I2C definitions for Elbrus I2C-SPI Controller (part of IOHUB) */

/* offset from i2c_spi[domain].cntrl_base */
#define I2C_IOHUB_BAR0_OFFSET	0x14
/* offset from i2c_cbase = i2c_spi[domain].cntrl_base + I2C_IOHUB_BAR0_OFFSET */
#define I2C_CONTROL		0x00
#define I2C_STATUS		0x04 /* offset from i2c_cbase */
#define I2C_MODE		0x08 /* offset from i2c_cbase */
#define I2C_TIMEOUTVAL		0x0c /* offset from i2c_cbase */

/* I2C_CONTROL field */

#define I2C_TRANSACTION_TYPE_WRITE	0x1
#define I2C_MAX_TRANS_BYTES		64
#define I2C_TRANS_SIZE_SHIFT		1
#define I2C_TRANS_SIZE(size)				\
({							\
	unsigned int res = 0, __size = size;				\
	if (__size > 0 && __size < I2C_MAX_TRANS_BYTES)	\
		res = (__size << I2C_TRANS_SIZE_SHIFT);	\
	res;						\
})
#define I2C_TRANS_SIZE_MASK		0x7E /* bits 6:1 */
#define I2C_10BIT_ADDR_SHIFT            7
#define I2C_10BIT_ADDR_MASK		0x1FFF80 /* bits 21:7 */
#define I2C_7BIT_ADDR_SHIFT		15
#define I2C_7BIT_ADDR_MASK		0x3f8000 /* bits 21:15 */
#define I2C_10BIT_ADDR_MODE_SHIFT	22
#define I2C_10BIT_ADDR_MODE		(1 << I2C_10BIT_ADDR_MODE_SHIFT)
#define I2C_DATA_PHASE_PRESENT_SHIFT	23
#define I2C_DATA_PHASE_PRESENT		(1 << I2C_DATA_PHASE_PRESENT_SHIFT)
#define I2C_DST_BUS_NUMBER_SHIFT	24
/* Bus 0 is null in bits 25:24 */
#define I2C_MAX_BUSSES			4
#define I2C_DST_BUS(bus_id)					\
({								\
	unsigned int res = 0;					\
	if (bus_id > 0 && bus_id < I2C_MAX_BUSSES)		\
		res = (bus_id << I2C_DST_BUS_NUMBER_SHIFT);	\
	res;							\
})
#define I2C_START_BYTE_ON_SHIFT	26
#define I2C_START_BYTE_ON	(1 << I2C_START_BYTE_ON_SHIFT)
#define I2C_KILL_SHIFT		27
#define I2C_KILL		(1 << I2C_KILL_SHIFT)
#define I2C_START_EXEC_SHIFT	28
#define I2C_START_EXEC		(1 << I2C_START_EXEC_SHIFT)
#define I2C_CONTROL_MASK	0x1fffffff	/* bits 31:29 not used
						   (const zeros) */

/* I2C_STATUS field */

#define I2C_CONTROLLER_BUSY	0x1
#define I2C_INTERRUPT		0x2
#define I2C_FAILED		0x4
#define I2C_BUS_COLLISION	0x8
#define I2C_TRANS_TIMEOUT	0x10
#define I2C_STATUS_MASK		0x1f /* bits 31:5 not used (const zeros) */

/* I2C_MODE field */

#define I2C_BUS_0_MODE_MASK	0x3 /* bits 1:0 */
#define I2C_BUS_0_FAST		0x1
#define I2C_BUS_0_FASTPLUS	0x2
#define I2C_BUS_1_MODE_SHIFT	2
#define I2C_BUS_1_MODE_MASK	(I2C_BUS_0_MODE_MASK << I2C_BUS_1_MODE_SHIFT)
#define I2C_BUS_2_MODE_SHIFT	4
#define I2C_BUS_2_MODE_MASK	(I2C_BUS_0_MODE_MASK << I2C_BUS_2_MODE_SHIFT)
#define I2C_BUS_3_MODE_SHIFT	6
#define I2C_BUS_3_MODE_MASK	(I2C_BUS_0_MODE_MASK << I2C_BUS_3_MODE_SHIFT)
#define I2C_INTERRUPT_ENABLE_SHIFT	8
#define I2C_INTERRUPT_ENABLE	(1 << I2C_INTERRUPT_ENABLE_SHIFT)
#define I2C_MODE_MASK		0x1ff /* bits 31:9 not used (const zeros) */

/* I2C_TIMEOUTVAL field */

#define I2C_TIMEOUTVAL_ASIC		0x0ee6b280
#define I2C_TIMEOUTVAL_ALTERA		0x05f5e100
#define I2C_TIMEOUTVAL_MASK		0xffffffff


/* IOHUB SMBus address offsets */
#define SMBCONTROL	(I2C_CONTROL + i2c_cbase)
#define SMBSTATUS	(I2C_STATUS + i2c_cbase)
#define SMBMODE		(I2C_MODE + i2c_cbase)
#define SMBTIMEOUT	(I2C_TIMEOUTVAL + i2c_cbase)
#define SMBDATA		(i2c_dbase)

/* IOHUB constants */
#define IOHUB_QUICK		0x00
#define IOHUB_BYTE		0x04
#define IOHUB_BYTE_DATA		0x08
#define IOHUB_WORD_DATA		0x0C
#define IOHUB_BLOCK_DATA	0x14
#define IOHUB_I2C_BLOCK_DATA	0x1C

/* Address of manufacturer id register for
 * majority of lm sensors. Use it to emulate
 * SMBUS_QUICK that is absent in IOHUB. */
#define HWMON_MAN_ID		0xfe

/* Timeout is 1 sec (Altera: 1 sec ~= 0x05f5e100 / 100 MHz,
 * Asic: 1 sec ~= 0x0ee6b280 / 250 MHz.) */
#define MAX_TIMEOUT     10000

/* Multimaster i2c configuration can require i2c_access retry in case of 
 * bus collision. Limit number of retries. */
#define MAX_RETRIES	100

/* I2C adapter */
struct i2c_adapter i2c_adap[MAX_NUMIOLINKS * I2C_ADAPTERS_PER_CONTROLLER];

static void __iomem * i2c_cbase;
static void __iomem * i2c_dbase;


static int i2c_transaction(struct i2c_adapter *idev)
{
	unsigned int status = 0;
	int result = 0;
	int timeout = 0;

	/* Make sure the SMBus host is ready to start transmitting */
	status = readl(SMBSTATUS);
	if (status & I2C_CONTROLLER_BUSY) {
		dev_err(&idev->dev, "Controller is busy! (%02x)\n", status);
		return -EBUSY;
	}

	/* start the transaction by setting bit 28 */
	writel(readl(SMBCONTROL) | I2C_START_EXEC, SMBCONTROL);

	while ((++timeout < MAX_TIMEOUT) &&
			((status = readl(SMBSTATUS)) & I2C_CONTROLLER_BUSY))
		udelay(1000);

	/* If the SMBus is still busy, we give up */
	if (timeout == MAX_TIMEOUT) {
		dev_err(&idev->dev, "SMBus Timeout!\n");
		result = -ETIMEDOUT;
	}

	if (status & I2C_FAILED) {
		result = -EIO;
		dev_err(&idev->dev, "Error: Failed bus transaction\n");
	}

	if (status & I2C_BUS_COLLISION) {
		result = -EAGAIN;
		/* well, try to fixup it later in i2c_access */
	}

	if (status & I2C_TRANS_TIMEOUT) {
		result = -ENXIO;
		/* I2C_TRANS_TIMEOUT is legitimate for multimaster. */
		/* dev_err(&idev->dev, "Error: no response!\n"); */
	}

	/* Reset status register */
	if (readl(SMBSTATUS) != 0)
		writel(readl(SMBSTATUS), SMBSTATUS);

	if ((status = readl(SMBSTATUS)) != 0) {
		dev_err(&idev->dev, "Failed reset at end of "
				"transaction (%02x)\n", status);
	}

	return result;
}

static s32 i2c_access(struct i2c_adapter *adap, u16 addr,
		 unsigned short i2c_flags, char read_write,
		 u8 command, int size, union i2c_smbus_data * data)
{
	unsigned long flags;
	int ret = 0;
	int i, len = 0;
	int domain;
	int bus_id = ((adap->nr) % I2C_ADAPTERS_PER_CONTROLLER);
	unsigned int value;
	unsigned char quick = 0;
	void __iomem *daddr;
	int retries = 0;
	int sz = size;

retry:
	value = (unsigned int) addr;

	if (i2c_flags & I2C_CLIENT_TEN) {
		value <<= I2C_10BIT_ADDR_SHIFT;
		value &= I2C_10BIT_ADDR_MASK;
		value |= I2C_10BIT_ADDR_MODE;
	} else {
		value <<= I2C_7BIT_ADDR_SHIFT;
		value &= I2C_7BIT_ADDR_MASK;
	}

	if ((read_write == I2C_SMBUS_WRITE) && (size != I2C_SMBUS_QUICK))
		value |= I2C_TRANSACTION_TYPE_WRITE;

	value |= I2C_DST_BUS(bus_id);
	value &= ~I2C_START_BYTE_ON;

	/* Lock i2c_spi if we are going to use the common buffer
	 * which may be in use by other I2C adapters or by SPI controller. */
	spin_lock_irqsave(&i2c_spi_lock, flags);

	/* Four i2c lines per IOHUB */
	domain = (adap->nr) / I2C_ADAPTERS_PER_CONTROLLER;

	i2c_cbase = i2c_spi[domain].cntrl_base + I2C_IOHUB_BAR0_OFFSET;
	i2c_dbase = i2c_spi[domain].data_base;

	daddr = SMBDATA;

	switch (size) {
	case I2C_SMBUS_QUICK:
		/* iohub i2c-spi controller does not support QUICK.
		 * We emulate QUICK by BYTE_DATA, assuming QUICK
		 * will be used ONLY for detecting hwmon sensors
		 * on motherboard. Hwmon sensors (lm95231 etc.)
		 * fortunaly have MANUFACTURER_ID and REVISION_ID
		 * registers. Other possible chips (isl22317, pca953x etc.)
		 * are to be instantiated explicitly in
		 * instantiate_i2c_bus(busid). */
		value |= I2C_TRANS_SIZE(1);
		value |= I2C_TRANSACTION_TYPE_WRITE;
		value |= I2C_DATA_PHASE_PRESENT;
		writel(value, SMBCONTROL);
		writeb(HWMON_MAN_ID, daddr);
		ret = i2c_transaction(adap);
		if (ret)
			goto out_unlock;

		value &= ~(I2C_TRANSACTION_TYPE_WRITE);
		writel(value, SMBCONTROL);
		size = IOHUB_QUICK;
		break;
	case I2C_SMBUS_BYTE:
		if (read_write == I2C_SMBUS_WRITE) {
			/* Write */
			value |= I2C_TRANS_SIZE(1);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
			writeb(command, daddr);
		} else {
			/* Read */
			value |= I2C_TRANSACTION_TYPE_WRITE;
			value &= ~(I2C_DATA_PHASE_PRESENT);
			ret = i2c_transaction(adap);
			if (ret)
				goto out_unlock;

			value &= ~(I2C_TRANSACTION_TYPE_WRITE);
			writel(value, SMBCONTROL);
		}
		size = IOHUB_BYTE;
		break;
	case I2C_SMBUS_BYTE_DATA:
		if (read_write == I2C_SMBUS_WRITE) {
			/* Write */
			value |= I2C_TRANS_SIZE(2);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
			writeb(command, daddr);
			writeb(data->byte, (daddr + 1));
		} else {
			/* Read */
			/* Use 10bit address mode to send command
				in the low byte of address */
			value |= ((unsigned int)command)
					<< I2C_10BIT_ADDR_SHIFT;
			value |= I2C_10BIT_ADDR_MODE;
			value |= I2C_TRANS_SIZE(1);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
		}
		size = IOHUB_BYTE_DATA;
		break;
	case I2C_SMBUS_WORD_DATA:
		if (read_write == I2C_SMBUS_WRITE) {
			/* Write */
			value |= I2C_TRANS_SIZE(3);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
			writeb(command, daddr);
			writew((data->word), (daddr + 1));

		} else {
			/* Read */
			/* Use 10bit address mode to send command
				in the low byte of address */
			value |= ((unsigned int)command)
					<< I2C_10BIT_ADDR_SHIFT;
			value |= I2C_10BIT_ADDR_MODE;
			value |= I2C_TRANS_SIZE(2);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
		}
		size = IOHUB_WORD_DATA;
		break;
	case I2C_SMBUS_BLOCK_DATA:
		if (read_write == I2C_SMBUS_WRITE) {
			/* Write */
			len = data->block[0];
			if (len == 0 || len > (I2C_SMBUS_BLOCK_MAX - 1)) {
				ret = -EINVAL;
				goto out_unlock;
			}
			value |= I2C_TRANS_SIZE(len+1);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
			writeb(command, daddr);
			for (i = 1; i <= len; i++) {
				writeb(data->block[i], (daddr + i));
			}
		} else {
			/* Read */
			/* Use 10bit address mode to send command
				in the low byte of address */
			len = data->block[0];
			if (len == 0 || len > (I2C_SMBUS_BLOCK_MAX - 1)) {
				ret = -EINVAL;
				goto out_unlock;
			}
			value |= ((unsigned int)command)
					<< I2C_10BIT_ADDR_SHIFT;
			value |= I2C_10BIT_ADDR_MODE;
			value |= I2C_TRANS_SIZE(len + 1);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
		}
		size = IOHUB_BLOCK_DATA;
		break;
	case I2C_SMBUS_I2C_BLOCK_DATA:
		if (read_write == I2C_SMBUS_WRITE) {
			/* Write */
			len = data->block[0];
			if (len == 0 || len > (I2C_SMBUS_BLOCK_MAX - 1)) {
				ret = -EINVAL;
				goto out_unlock;
			}
			value |= I2C_TRANS_SIZE(len+1);
			value |= I2C_DATA_PHASE_PRESENT;
			writel(value, SMBCONTROL);
			writeb(command, daddr);
			for (i = 1; i <= len; i++) {
				writeb(data->block[i], (daddr + 1 + i));
			}
		} else {
			/* Read */
			len = data->block[0];
			if (len == 0 || len > I2C_SMBUS_BLOCK_MAX) {
				ret = -EINVAL;
				goto out_unlock;
			}

			value |= I2C_TRANS_SIZE(len);
			value &= ~(I2C_TRANSACTION_TYPE_WRITE);
			value |= I2C_DATA_PHASE_PRESENT;

			writel(value, SMBCONTROL);
		}
		size = IOHUB_I2C_BLOCK_DATA;
		break;

	default:
		dev_warn(&adap->dev, "Unsupported transaction %d\n", size);
		ret = -EOPNOTSUPP;
		goto out_unlock;
	}

	ret = i2c_transaction(adap);
	if (ret)
		goto out_unlock;

	if ((read_write == I2C_SMBUS_WRITE) && (size != IOHUB_QUICK)) {
		ret = 0;
		goto out_unlock;
	}

	switch (size) {
	case IOHUB_QUICK:
		quick = readb(daddr);
		break;
	case IOHUB_BYTE:
	case IOHUB_BYTE_DATA:
		data->byte = readb(daddr);
		break;
	case IOHUB_WORD_DATA:
		data->word = readw(daddr);
		break;
	case IOHUB_BLOCK_DATA:
		len = readb(daddr);
		data->block[0] = (unsigned char) len;
		if (len == 0 || len > I2C_SMBUS_BLOCK_MAX) {
			ret = -EPROTO;
			goto out_unlock;
		}

		for (i = 1; i <= len; i++) {
			data->block[i] = readb(daddr + i);
		}
		break;
	case IOHUB_I2C_BLOCK_DATA:
		data->block[0] = (unsigned char) len;
		for (i = 0; i < len; i++) {
			data->block[i + 1] = readb(daddr + i);
		}
		break;
	}

out_unlock:
	spin_unlock_irqrestore(&i2c_spi_lock, flags);

	if (ret == -EAGAIN) {
		/* This is case of bus collision for multimaster 
		 * configuration. Retry is enough here for both reads 
		 * and writes. 
		 */
		retries++;
		if (retries < MAX_RETRIES) {
			size = sz;
			goto retry;
		} else {
			printk(KERN_ERR "i2c_access: Failed to fix i2c bus"
					"collision. Retries %d\n", retries);
		}
	}

	return ret;
}

static u32 i2c_func(struct i2c_adapter *adapter)
{
	return I2C_FUNC_SMBUS_QUICK | I2C_FUNC_SMBUS_BYTE |
			I2C_FUNC_SMBUS_BYTE_DATA | I2C_FUNC_SMBUS_WORD_DATA |
			I2C_FUNC_SMBUS_BLOCK_DATA | I2C_FUNC_10BIT_ADDR;
}

static const struct i2c_algorithm smbus_algorithm = {
	.smbus_xfer	= i2c_access,
	.functionality	= i2c_func,
};

#define BUTTERFLY_PCA953X_LINES_NR	8
#ifdef CONFIG_E2K
#if IS_ENABLED(CONFIG_IPE2ST_POWER)
static struct pca953x_platform_data e2k_i2c_board_pdata[] = {
	[0] = { .gpio_base	= ARCH_NR_IOHUB_GPIOS * MAX_NUMIOHUBS, },
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
#ifdef	CONFIG_E2K
	if (bootblock_virt->info.bios.mb_type == MB_TYPE_ES2_BUTTERFLY) {
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
		    MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK) {
		i2c_register_board_info(1, iohub2_i2c_devices_bus1,
				ARRAY_SIZE(iohub2_i2c_devices_bus1));
		i2c_register_board_info(2, iohub2_i2c_devices_bus2,
				ARRAY_SIZE(iohub2_i2c_devices_bus2));
		i2c_register_board_info(3, iohub2_i2c_devices_bus3,
				ARRAY_SIZE(iohub2_i2c_devices_bus3));
	} else {

#if IS_ENABLED(CONFIG_IPE2ST_POWER)
		i2c_register_board_info(iohub_i2c_line_id, e2k_i2c_board_info1,
				ARRAY_SIZE(e2k_i2c_board_info1));
#endif /* CONFIG_IPE2ST_POWER */
	}
#endif
	}
	return 0;
}

arch_initcall(i2c_board_info_init);

static int l_i2c_probe(struct platform_device *pdev)
{
	unsigned int mvalue = 0;
	unsigned int status;
	int retval = -ENODEV;
	int domain;
	int i;
	int id;

	domain = pdev->id;
	if (domain < 0)
		return retval;

	/* Determine the address of the SMBus areas:
	 *
	 * For domain == 0:
	 *  - boot has already initialized A1_SE, A1_BA0, A1_BA1 IOHUB regs;
	 *  - kernel has already read i2c/spi base addresses from mptable
	 * (start_kernel()->setup_arch()->get_smp_config());
	 *  - l_spi_init() has already ioremapped these addresses.
	 *
	 *  For domain > 0:
	 *  - i2c_spi_probe ioremapped and initailized base addresses
	 */
	i2c_cbase = i2c_spi[domain].cntrl_base + I2C_IOHUB_BAR0_OFFSET;
	i2c_dbase = i2c_spi[domain].data_base;
	dev_info(&pdev->dev, "i2c_cbase = %p, i2c_dbase = %p\n",
			i2c_cbase, i2c_dbase);

	/* Set all I2C buses to standart mode (100 kHz). Other values should
	  * be set only for specific motherboard type.
	 */
	writel(mvalue, SMBMODE);
	dev_dbg(&pdev->dev, "write 0x%x to reg SMBMODE (addr %p)\n",
		mvalue, SMBMODE);

	/* Reset status bits: write ones to RW1C bits of I2C Status. */
	status = readl(SMBSTATUS);
	dev_dbg(&pdev->dev, "read 0x%x from reg SMBSTATUS (addr %p)\n",
		status, SMBSTATUS);
	if (status != 0) {
		writel(readl(SMBSTATUS), SMBSTATUS);
		dev_dbg(&pdev->dev, "write 0x%x to reg SMBSTATUS (addr %p)\n",
			status, SMBSTATUS);
	}

	for (i = 0; i < I2C_ADAPTERS_PER_CONTROLLER; i++) {
		id = (domain * I2C_ADAPTERS_PER_CONTROLLER) + i;
		/* set up the sysfs linkage to our parent device */
		i2c_adap[id].dev.parent = &pdev->dev;

		/* init adapter himself */
		i2c_adap[id].owner = THIS_MODULE;
		i2c_adap[id].class = (I2C_CLASS_HWMON | I2C_CLASS_SPD);
		i2c_adap[id].algo = &smbus_algorithm;
		i2c_adap[id].nr = id;
		strlcpy(i2c_adap[id].name, "l_i2c", sizeof(i2c_adap[id].name));

		if ((retval = i2c_add_numbered_adapter(&i2c_adap[id]))) {
			dev_err(&pdev->dev,
					"failed to register I2C adapter %d!\n",
					id);
			goto cleanup;
		} else {
			dev_info(&pdev->dev, "I2C adapter %d registered\n", id);
		}
	}

	return retval;

cleanup:
	for (i = id - 1; i >= (domain * I2C_ADAPTERS_PER_CONTROLLER); i--) {
		i2c_del_adapter(&i2c_adap[i]);
	}

	return retval;
}

static int l_i2c_remove(struct platform_device *pdev)
{
	int id;
	int i;

	id = pdev->id;

	for (i = 0; i < I2C_ADAPTERS_PER_CONTROLLER; i++) {
		i2c_del_adapter(&i2c_adap[id + i]);
	}
	return 0;
}


static struct platform_driver l_i2c_driver = {
	.driver = {
		.name	= "l_i2c",
		.owner	= THIS_MODULE,
	},
	.probe	= l_i2c_probe,
	.remove	= l_i2c_remove
};

__init
int l_i2c_init(void)
{

	return platform_driver_register(&l_i2c_driver);
}
module_init(l_i2c_init);

__exit
void l_i2c_exit(void)
{
	platform_driver_unregister(&l_i2c_driver);
}
module_exit(l_i2c_exit);

MODULE_AUTHOR("Evgeny Kravtsunov <kravtsunov_e@mcst.ru>");
MODULE_DESCRIPTION("Elbrus I2C controller driver");
MODULE_LICENSE("GPL");
