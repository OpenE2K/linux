/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * linux/arch/l/kernel/l_i2c2.c
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Implementation of Elbrus I2C master.
 */
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/i2c.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/export.h>
#include <linux/stddef.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/platform_data/i2c-l-i2c2.h>
#include <linux/platform_device.h>
#include <asm/io.h>

#include <asm-l/i2c-spi.h>
#include <asm-l/l_pmc.h>


/*******************************************************************************
 * I2C Registers
 *******************************************************************************
 */
#define I2C_REG_PRER_LO (0x00)	/* Clock Prescale register lo-byte (RW) */
#define I2C_REG_PRER_HI (0x04)	/* Clock Prescale register hi-byte (RW) */
#define I2C_REG_CTR	(0x08)	/* Control Register (RW) */
#define I2C_REG_TXR	(0x0c)	/* Transmit Register (W) */
#define I2C_REG_RXR	(0x0c)	/* Receive Register (R)  */
#define I2C_REG_CR	(0x10)	/* Command Register (W)  */
#define I2C_REG_SR	(0x18)	/* Status Register (R)   */
#define I2C_REG_AUX	(0x1c)	/* Reset Register        */

/* Prescaler divider evaluates as (PCICLK/(5*SCLK))-1 */
#define NORMAL_SCL 0x3F

/* Control Register bits */
#define I2C_CTR_EN	(1 << 7)	/* I2C core enable bit           */
#define I2C_CTR_IEN	(1 << 6)	/* I2C core interrupt enable bit */

/* Command Register bits */
#define I2C_CR_STA	(1 << 7)	/* generate (repeated) start condition */
#define I2C_CR_STO	(1 << 6)	/* generate stop condition             */
#define I2C_CR_RD	(1 << 5)	/* read from slave                     */
#define I2C_CR_WR	(1 << 4)	/* write to slave                      */
#define I2C_CR_NACK	(1 << 3)	/* when a receiver, sent I2C_CR_NACK   */
	       /* Interrupt acknowledge. When set, clears pending interrrupt */
#define I2C_CR_IACK	(1 << 0)

/* Status Register bits */
/* Receive acknowledge from slave. '1' - no acknowledge received */
#define I2C_SR_RxACK	(1 << 7)
/* I2C bus busy. '1' after START, '0' after STOP */
#define I2C_SR_BUSY	(1 << 6)
#define I2C_SR_AL	(1 << 5)	/* Arbitration lost */
/* Transfer in progress. '1' when transferring data */
#define I2C_SR_TIP	(1 << 1)
#define I2C_SR_IF	(1 << 0)	/* Interrupt flag */

/* Transmit Register operations */
#define I2C_READ_OP	0x01	/* Reading from slave (x << 1 | I2C_READ_OP) */
#define I2C_WRITE_OP	0xFE	/* Writing to slave (x << 1 & I2C_WRITE_OP) */

struct l_i2c2 {
	struct i2c_adapter adap;
	struct platform_device *pdev;
	void __iomem *regs;
	unsigned reg_offset;
};

# define EXTPLLI2C_RD            (0 << 31)
# define EXTPLLI2C_WR            (1 << 31)

static void st2_i2c_write(struct l_i2c2 *i2c, unsigned reg, u8 val)
{
	unsigned v = EXTPLLI2C_WR | (reg / 4 << 8) | val;
	writel(v, i2c->regs);
}

static u8 st2_i2c_read(struct l_i2c2 *i2c, unsigned reg)
{
	unsigned v = EXTPLLI2C_RD | (reg / 4 << 8);
	writel(v, i2c->regs);
	v = readl(i2c->regs);
	return v;
}

static void raw_i2c_write(struct l_i2c2 *i2c, unsigned reg, u8 val)
{
	__raw_writel(val, i2c->regs + reg);
}

static inline u8 raw_i2c_read(struct l_i2c2 *i2c, unsigned reg)
{
	unsigned r = 0;
	r = __raw_readl(i2c->regs + reg);
	return r;
}

static void i2c_write(struct l_i2c2 *i2c, unsigned reg, u8 val)
{
	struct l_i2c2_platform_data *pdata = dev_get_platdata(&i2c->pdev->dev);
	if (pdata->two_stage_register_access)
		st2_i2c_write(i2c, reg, val);
	else
		raw_i2c_write(i2c, reg, val);
}

static u8 i2c_read(struct l_i2c2 *i2c, unsigned reg)
{
	struct l_i2c2_platform_data *pdata = dev_get_platdata(&i2c->pdev->dev);
	unsigned int r = 0;
	if (pdata->two_stage_register_access)
		r = st2_i2c_read(i2c, reg);
	else
		r = raw_i2c_read(i2c, reg);
	return r;
}

static void set_prescaler(struct l_i2c2 *i2c, int value)
{
	i2c_write(i2c, I2C_REG_PRER_LO, value & 0xFF);
	i2c_write(i2c, I2C_REG_PRER_HI, (value >> 8) & 0xFF);
}


#define	PMC_I2C_TIMEOUT_USEC	(1000 * 1000)

static int i2c_send(struct l_i2c2 *i2c, int cmd, int data)
{
	int i;

	if (cmd & I2C_CR_WR)
		i2c_write(i2c, I2C_REG_TXR, data);

	i2c_write(i2c, I2C_REG_CR, cmd);

	for (i = 0; i < PMC_I2C_TIMEOUT_USEC; i++) {
		unsigned status = i2c_read(i2c, I2C_REG_SR);
		if (status & I2C_SR_AL) {
			dev_dbg(&i2c->adap.dev, "i2c_send: busy: arbitration lost\n");
			return -EAGAIN;
		}
		if (!(status & I2C_SR_TIP))
			return 0;
		udelay(1);
	}
	dev_err(&i2c->adap.dev, "i2c_send: timeout: transfer in progress.\n");
	return -ETIME;
}

static int l_i2c2_read(struct i2c_adapter *adap, unsigned char *buf,
					int length, int flags, int stop_bit)
{
	int ret = 0;
	struct l_i2c2 *i2c = i2c_get_adapdata(adap);
	if (flags & I2C_M_RECV_LEN) {
		dev_err(&adap->dev, "%s: FIXME: I2C_M_RECV_LEN not "
					"supported.\n", adap->name);
		return -ENOTSUPP;
	}
	while (length--) {
		int ret;
		int v = I2C_CR_RD;

		if (length == 0) {
			if (!(flags & I2C_M_NO_RD_ACK))
				v |= I2C_CR_NACK;
			if (stop_bit)
				v |= I2C_CR_STO;
		}
		ret = i2c_send(i2c, v, 0);
		if (ret)
			break;
		*buf++ = i2c_read(i2c, I2C_REG_RXR);
	}
	return ret;
}

static int l_i2c2_write(struct i2c_adapter *adap, unsigned char *buf,
					int length, int flags, int stop_bit)
{
	int ret = 0;
	struct l_i2c2 *i2c = i2c_get_adapdata(adap);
	while (length--) {
		int v = I2C_CR_WR;

		if (length == 0) {
			if (!(flags & I2C_M_NO_RD_ACK))
				v |= I2C_CR_NACK;
			if (stop_bit)
				v |= I2C_CR_STO;
		}
		ret = i2c_send(i2c, v, *buf++);
		if (ret)
			break;
		if (!(flags & I2C_M_IGNORE_NAK)) {
			if (i2c_read(i2c, I2C_REG_SR) & I2C_SR_RxACK) {
				dev_dbg(&adap->dev,
					"no acknowledge from slave.\n");
				ret = -EIO;
				break;
			}
		}
	}

	return ret;
}

static int
l_i2c2_xfer(struct i2c_adapter *adap, struct i2c_msg *pmsg, int num)
{
	int i, ret = 0;
	struct l_i2c2 *i2c = i2c_get_adapdata(adap);
	int last_msg = num - 1;

	if (0)
		dev_dbg(&adap->dev, "%s: processing %d messages:\n",
			adap->name, num);

	for (i = 0; i < num; i++, pmsg++) {
		int addr;
		int flags = pmsg->flags;
		int start = !(flags & I2C_M_NOSTART);
		int nak = !(flags & I2C_M_IGNORE_NAK);
		int stop_bit = i == last_msg ? 1 : 0;
		if (0)
			dev_dbg(&adap->dev,
				" #%d: %sing %d byte%s %s 0x%02x\n", i,
				pmsg->flags & I2C_M_RD ? "read" : "writ",
				pmsg->len, pmsg->len > 1 ? "s" : "",
				pmsg->flags & I2C_M_RD ? "from" : "to",
				pmsg->addr);

		if (flags & I2C_M_TEN) { /* a ten bit address */
			dev_err(&adap->dev, "FIXME: a ten bit address not "
				"supported.\n");
			ret = -ENOTSUPP;
			break;
		} else { /* normal 7bit address	*/
			addr = pmsg->addr << 1;
			if (flags & I2C_M_RD)
				addr |= 1;
			if (flags & I2C_M_REV_DIR_ADDR)
				addr ^= 1;
		}

		if (start) { /* Sending device address */
			ret = i2c_send(i2c, I2C_CR_STA | I2C_CR_WR, addr);
			if (ret)
				break;
		}

		if (nak && i2c_read(i2c, I2C_REG_SR) & I2C_SR_RxACK) {
			dev_dbg(&adap->dev, "no acknowledge from slave.\n");
			ret = -ENXIO;
			break;
		}
		/* check for bus probe */
		if ((num == 1) && (pmsg->len == 0)) {
			i = 1;
			break;
		}

		ret = flags & I2C_M_RD ?
			l_i2c2_read(adap, pmsg->buf,
						pmsg->len, flags, stop_bit) :
			l_i2c2_write(adap, pmsg->buf,
						pmsg->len, flags, stop_bit);

		if (ret)
			break;
	}
	if (ret)
		return ret;
	else
		return i;
}

static u32 l_i2c2_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm l_i2c2_algo = {
	.master_xfer = l_i2c2_xfer,
	.functionality = l_i2c2_func,
};

static void l_i2c2_init_hw(struct l_i2c2 *i2c)
{
	struct l_i2c2_platform_data *pdata = dev_get_platdata(&i2c->pdev->dev);

	/* Prescaler divider evaluates as (BASE_FREQ/(4*SCLK))-1 */
	set_prescaler(i2c, pdata->base_freq_hz / 4 /
				pdata->desired_freq_hz - 1);

	/* Enable I2C core */
	i2c_write(i2c, I2C_REG_CTR, I2C_CTR_EN);
}

static int l_i2c2_probe(struct platform_device *pdev)
{
	int ret;
	void __iomem *regs = NULL;
	struct device *dev = &pdev->dev;
	struct l_i2c2_platform_data *pdata = dev_get_platdata(dev);
	struct resource *res = platform_get_resource(pdev, IORESOURCE_MEM, 0);

	struct l_i2c2 *i2c = devm_kzalloc(dev, sizeof(struct l_i2c2), GFP_KERNEL);
	if (!i2c)
		return -ENOMEM;
	if (!pdata) {
		u32 tmp;
		const void *p = of_device_get_match_data(dev);
		if (WARN_ON(!p))
			return -ENODEV;
		ret = platform_device_add_data(pdev, p, sizeof(*pdata));
		if (WARN_ON(ret))
			goto out;
		pdata = dev_get_platdata(dev);
		if (!of_property_read_u32(dev->of_node->parent,
				 "clock-frequency", &tmp)) {
			pdata->base_freq_hz = tmp;
		}
	}
	regs = devm_ioremap_resource(dev, res);
	if (IS_ERR(regs))
		return PTR_ERR(regs);

	platform_set_drvdata(pdev, i2c);
	i2c->pdev = pdev;
	i2c->regs = regs;

	i2c->adap.owner = THIS_MODULE;
	i2c->adap.class = I2C_CLASS_DDC;
	i2c_set_adapdata(&i2c->adap, i2c);
	snprintf(i2c->adap.name, sizeof(i2c->adap.name),
			"Elbrus %s i2c bus", pdev->name);

	i2c->adap.dev.parent	= dev;
	i2c->adap.dev.of_node	= dev->of_node;
	i2c->adap.nr = pdata->bus_nr; /* Fix pmc i2c master number */
	i2c->adap.algo = &l_i2c2_algo;

	l_i2c2_init_hw(i2c);

	ret = i2c_add_numbered_adapter(&i2c->adap);
	if (ret) {
		dev_err(dev, "Failed to register i2c\n");
		goto out;
	}
out:
	return ret;
}

static int l_i2c2_remove(struct platform_device *pdev)
{
	struct l_i2c2 *i2c = platform_get_drvdata(pdev);
	/* Disable I2C core */
	i2c_write(i2c, I2C_REG_CTR, 0);
	i2c_del_adapter(&i2c->adap);

	return 0;
}


#ifdef CONFIG_PM_SLEEP
static int l_i2c2_suspend(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct l_i2c2 *i2c = platform_get_drvdata(pdev);
	/* Disable I2C core */
	i2c_write(i2c, I2C_REG_CTR, 0);
	return 0;
}

static int l_i2c2_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct l_i2c2 *i2c = platform_get_drvdata(pdev);
	l_i2c2_init_hw(i2c);
	return 0;
}

static const struct dev_pm_ops l_i2c2_pm_ops = {
	.suspend	= l_i2c2_suspend,
	.resume		= l_i2c2_resume,
};
#endif

static const struct l_i2c2_platform_data mga2x_i2c_data = {
	.bus_nr	         = -1, /* -1 means dynamically assign bus id */
	.base_freq_hz    = 1000 * 1000 * 1000, /* mga2.5 */
	.desired_freq_hz = 100 * 1000,
	.two_stage_register_access = true,
};

static const struct of_device_id l_i2c2_dt_ids[] = {
	{ .compatible = "mcst,mga2x-i2c", .data = &mga2x_i2c_data},
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, l_i2c2_dt_ids);

/* driver device registration */
static const struct platform_device_id l_i2c2_driver_ids[] = {
	{
		.name		= "pmc-i2c",
	}, {
		.name		= "mga2-i2c",
	},
	{ /* sentinel */ }
};

MODULE_DEVICE_TABLE(platform, l_i2c2_driver_ids);

static struct platform_driver l_i2c2_driver = {
	.probe		= l_i2c2_probe,
	.remove		= l_i2c2_remove,
	.id_table	= l_i2c2_driver_ids,
	.driver		= {
		.name	= "l-i2c2",
		.of_match_table = l_i2c2_dt_ids,
#ifdef CONFIG_PM_SLEEP
		.pm	= &l_i2c2_pm_ops,
#endif
	},
};

module_platform_driver(l_i2c2_driver);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("i2c driver for Elbrus processors");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");
