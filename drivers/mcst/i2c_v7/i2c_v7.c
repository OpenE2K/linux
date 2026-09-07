/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * linux/drivers/mcst/i2c_v7/i2c_v7.c
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Implementation of Elbrus I2C master for V7 architecture.
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
#include <asm/io.h>
#include <linux/wait.h>
#include <linux/delay.h>
#include <asm-l/i2c-spi.h>
#include <linux/platform_device.h>
#include <linux/irq.h>


/*******************************************************************************
 * I2C V7 Registers
 *******************************************************************************
 */

#define I2C_V7_REG_MEM_0	 (0x000)        /* 0-byte MEM (0x000 - 0x3FF)*/
#define I2C_V7_REG_I2HC_CONTROL  (0x400)	/* Control register */
#define I2C_V7_REG_PRER		 (0x404)	/* Frequency divider register */
#define I2C_V7_REG_BUF_PNT	 (0x408)	/* Value of read/write pointer in MEM register */
#define I2C_V7_REG_BUF_SIZE	 (0x40c)	/* Size of MEM register */
#define I2C_V7_INTR		 (0x410)	/* Source of interrupts register */
#define I2C_V7_INTR_ENA		 (0x414)	/* Interrupts enable register */

/* Control Register bits */
#define I2C_V7_CTRL_EN		(1 << 0)	/* I2C control enable bit */
#define I2C_V7_CTRL_SOFT_RST	(1 << 1)	/* I2C control soft reset bit */
#define I2C_V7_IGNORE_NACK	(1 << 2)	/* I2C control ignore nack bit - on */
#define I2C_V7_IGNORE_NACK_OFF  (0 << 2)        /* I2C control ignore nack bit - off*/

/* Fscl = 100MHz / 4 / (PRER[15:0] - 1) */
/* Values of PRER[15:0] for supported frequencies: */
/* ASIC freqs with base 100MHz */
#define I2C_100KHz 0xC7 /*  100kHz -- used for init */
#define I2C_400KHz 0x31 /* ~400kHz */
#define I2C_3500KHz 0x6 /* ~3500kHz */

/* PLD freqs with base Fscl = 25Mhz */
#define I2C_PLD_100KHz 0x31 /*  100kHz -- used for init */
#define I2C_PLD_400KHz 0x11 /* ~400kHz */
#define I2C_PLD_3500KHz 0x1 /* ~3500kHz */

#define WRITE_ADDR_CMD 0x5
#define WRITE_ADDR_CMD_STOP 0x3D
#define READ_DATA_CMD  0x2
#define WRITE_DATA_CMD 0x1
#define READ_DATA_CMD_STOP  0x3A
#define WRITE_DATA_CMD_STOP 0x39
#define ADDR_SIZE 0x1

#define MAX_MEM_SIZE 1024

#define IRQ_MASK 0XF
#define LAST_IRQ 0x1
#define STOP_IRQ 0x2
#define ARBIT_IRQ 0x4
#define NACK_IRQ 0x8
#define INTERRUPTS_EN 0xF

#define BUF_ADDR_MASK 0x7FFFFFFF
#define BUS_STATUS_MASK 0x80000000
#define SIZE_BITS07_MASK 0xFF

/*****************************************************************************/

static const struct pci_device_id i2c_v7_ids[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_I2C)},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, i2c_v7_ids);

struct i2c_data {
	u32 size_89bits;
	u32 cmd;
	u32 size_07bits;
	u32 dev_addr;
};

struct i2c_cmd_count {
	/* Used to save info about memory for read data */
	int read_offset;
	int read_length;
	/* Used to check if BUF_PNT is correct */
	int cmd_offset;
	int cmd_length;
};

struct i2c_v7 {
	struct i2c_adapter adap;
	struct pci_dev *pdev;
	void __iomem *regs;
	unsigned reg_offset;
	int irq;
	bool arbit_lost;
	bool nack;
	bool none;
	bool stop;
	bool last;
	struct i2c_cmd_count i2c_cmd_array[1024];
	int i2c_cmd_counter;
	/* Used to wait until last command finishes executing  */
	struct completion last_cmd_completion;
};

struct i2c_v7_pci_data {
	int bus_nr;
};

static const struct i2c_v7_pci_data i2c_v7_data = {
	.bus_nr		= -1,	      /* -1 means dynamically assign bus id */
};

static void i2c_write8(struct i2c_v7 *i2c, unsigned reg, u8 val)
{
	writeb(val, i2c->regs + reg);
}

static void i2c_write32(struct i2c_v7 *i2c, unsigned reg, u32 val)
{
	writel(val, i2c->regs + reg);
}

static u8 i2c_read8(struct i2c_v7 *i2c, unsigned reg)
{
	unsigned r = 0;
	r = readb(i2c->regs + reg);
	return r;
}

static u32 i2c_read32(struct i2c_v7 *i2c, unsigned reg)
{
	unsigned r = 0;
	r = readl(i2c->regs + reg);
	return r;
}

/* Write needed value to PRER to set frequency */
static void set_freq(struct i2c_v7 *i2c, unsigned value)
{
	i2c_write32(i2c, I2C_V7_REG_PRER, value);
}

static void i2c_restart(struct i2c_v7 *i2c)
{
	int i;
	i2c->i2c_cmd_counter = 0;
	i2c->nack = false;
	i2c->arbit_lost = false;
	i2c->none = false;
	i2c->stop = false;
	i2c->last = false;
	for (i = 0; i < 1024; i++) {
		i2c->i2c_cmd_array[i].read_length = 0;
		i2c->i2c_cmd_array[i].read_offset = 0;
		i2c->i2c_cmd_array[i].cmd_length = 0;
		i2c->i2c_cmd_array[i].cmd_offset = I2C_V7_REG_MEM_0;
	}
	i2c_write32(i2c, I2C_V7_REG_I2HC_CONTROL, I2C_V7_IGNORE_NACK_OFF);
	i2c_write32(i2c, I2C_V7_REG_BUF_PNT, 0x00000000);
}

static int init_hw_i2c_v7(struct i2c_v7 *i2c)
{
	int i;
	int i2hc_rst_bit;
	unsigned bus_speed;
	int asic_flag = is_iohub_asic(i2c->pdev);
	u8 revision = 0;
	pci_read_config_byte(i2c->pdev, 0x8, &revision);
	int is_100mhz = revision == 0x1 ? 1 : revision == 0x3 ? 0 : -1;

	/* First let's reset i2c controller  */
	i2c_write32(i2c, I2C_V7_REG_I2HC_CONTROL, I2C_V7_CTRL_SOFT_RST);

	/* Waiting for 1 sec for reset to be done */
	for (i = 0; i < 10000; i++) {
		i2hc_rst_bit = (i2c_read32(i2c, I2C_V7_REG_I2HC_CONTROL) >> 1) & 0x1;
		if (!i2hc_rst_bit)
			break;
		udelay(100);
	}

	if (i2hc_rst_bit)
		return -ETIMEDOUT;

	/* Enabling all interrupts  */
	i2c_write32(i2c, I2C_V7_INTR_ENA, INTERRUPTS_EN);

	/* Set frequency */
	of_property_read_u32(i2c->adap.dev.of_node, "clock-frequency", &bus_speed);

	switch (bus_speed) {
	case 100000:
		set_freq(i2c, is_100mhz ? I2C_100KHz : I2C_PLD_100KHz);
		break;
	case 400000:
		set_freq(i2c, is_100mhz ? I2C_400KHz : I2C_PLD_400KHz);
		break;
	case 3500000:
		set_freq(i2c, is_100mhz ? I2C_3500KHz : I2C_PLD_3500KHz);
		break;
	default:
		set_freq(i2c, is_100mhz ? I2C_100KHz : I2C_PLD_100KHz);
	}
	if (is_100mhz < 0)
		set_freq(i2c, asic_flag ? I2C_100KHz : I2C_PLD_100KHz);

	/* Initialize all structures to 0 */
	i2c_restart(i2c);

	return 0;
}

static int i2c_send(struct i2c_v7 *i2c, int cmd, int data, int bus_probe)
{
	struct i2c_data send_addr;
	int cmd_offset = i2c->i2c_cmd_array[i2c->i2c_cmd_counter].cmd_offset;
	if (bus_probe) {
		send_addr.cmd = WRITE_ADDR_CMD_STOP << 2;
	} else {
		send_addr.cmd = WRITE_ADDR_CMD << 2;
	}
	send_addr.size_07bits = ADDR_SIZE;
	send_addr.dev_addr = data;
	i2c_write8(i2c, cmd_offset, send_addr.cmd);
	i2c_write8(i2c, cmd_offset + 0x001, send_addr.size_07bits);
	i2c_write8(i2c, cmd_offset + 0x002, send_addr.dev_addr);

	cmd_offset += 0x003;

	i2c->i2c_cmd_array[i2c->i2c_cmd_counter+1].cmd_offset = cmd_offset;
	i2c->i2c_cmd_array[i2c->i2c_cmd_counter+1].cmd_length = ADDR_SIZE;
	i2c->i2c_cmd_counter += 1;

	return 0;
}

static int i2c_v7_read(struct i2c_adapter *adap, unsigned char *buf,
					int length, int flags, int stop_bit, int read_num)
{
	struct i2c_data read_data;
	struct i2c_v7 *i2c = i2c_get_adapdata(adap);
	int cmd_offset = i2c->i2c_cmd_array[i2c->i2c_cmd_counter].cmd_offset;
	if (flags & I2C_M_RECV_LEN) {
		dev_err(&adap->dev, "%s: FIXME: I2C_M_RECV_LEN not supported.\n", adap->name);
		return -ENOTSUPP;
	}
	/* In order to read data from slave
	 * we gotta send Read command and size to read.
	 * After that get the pointer from BUF_PNT
	 * Finally copy data to buf
	 */
	if (stop_bit)
		read_data.cmd = READ_DATA_CMD_STOP;
	else
		read_data.cmd = READ_DATA_CMD;
	read_data.size_89bits = length >> 8;
	read_data.size_07bits = length & SIZE_BITS07_MASK;
	i2c_write8(i2c, cmd_offset, (read_data.cmd << 2 | read_data.size_89bits));
	i2c_write8(i2c, cmd_offset + 0x001, read_data.size_07bits);

	i2c->i2c_cmd_array[read_num].read_offset = cmd_offset + 0x002;
	i2c->i2c_cmd_array[read_num].read_length = length;
	cmd_offset += length + 0x003; /* Shift to address after place for read data */

	i2c->i2c_cmd_array[i2c->i2c_cmd_counter+1].cmd_offset = cmd_offset;
	i2c->i2c_cmd_array[i2c->i2c_cmd_counter+1].cmd_length = length;
	i2c->i2c_cmd_counter += 1;
	return 0;
}

static void i2c_v7_write(struct i2c_adapter *adap, unsigned char *buf,
					int length, int flags, int stop_bit)
{
	struct i2c_v7 *i2c = i2c_get_adapdata(adap);
	struct i2c_data write_data;
	int cmd_offset = i2c->i2c_cmd_array[i2c->i2c_cmd_counter].cmd_offset;
	/* In order to write data to slave
	 * we gotta send Write commad and then data */
	if (stop_bit)
		write_data.cmd = WRITE_DATA_CMD_STOP;
	else
		write_data.cmd = WRITE_DATA_CMD;
	write_data.size_89bits = length >> 8;
	write_data.size_07bits = length & SIZE_BITS07_MASK;
	i2c_write8(i2c, cmd_offset, ((write_data.cmd << 2) | write_data.size_89bits));
	i2c_write8(i2c, cmd_offset + 0x001, write_data.size_07bits);

	cmd_offset += 0x002;

	while (length--) {
		i2c_write8(i2c, cmd_offset, *buf++);
		cmd_offset += 0x001;
	}
	i2c->i2c_cmd_array[i2c->i2c_cmd_counter+1].cmd_offset = cmd_offset;
	i2c->i2c_cmd_array[i2c->i2c_cmd_counter+1].cmd_length = length;
	i2c->i2c_cmd_counter += 1;
}

static irqreturn_t i2c_v7_irq_handler(int irq, void *dev_id)
{
	struct i2c_v7 *i2c = (struct i2c_v7 *)dev_id;

	u32 irq_check = i2c_read32(i2c, I2C_V7_INTR) & IRQ_MASK;
	u32 last = irq_check & 0x1;
	u32 stop = (irq_check >> 1) & 0x1;
	u32 arbit = (irq_check >> 2) & 0x1;
	u32 nack = (irq_check >> 3) & 0x1;

	if (last) {
		i2c->last = true;
	}
	if (stop) {
		i2c->stop = true;
	}
	if (arbit) {
		i2c->arbit_lost = true;
	}
	if (nack) {
		i2c->nack = true;
	}

	if (!nack && !stop && !arbit && !last) {
		complete(&i2c->last_cmd_completion);
		return IRQ_NONE;
	}

	complete(&i2c->last_cmd_completion);
	return IRQ_HANDLED;
}


static int i2c_v7_xfer(struct i2c_adapter *adap, struct i2c_msg *pmsg, int num)
{
	int i, shift_bytes, ret, j = 0;
	int flag, starts = 0;
	int ignore_nack = 0;
	unsigned long timeout = msecs_to_jiffies(5000);
	int read_num = 0;
	int sum_len = 0;
	int count_starts = 0;
	struct i2c_v7 *i2c = i2c_get_adapdata(adap);
	int last_msg = num - 1;
	unsigned char *buffer[100];
	if (0)
		dev_dbg(&adap->dev, "%s: processing %d messages:\n",
			adap->name, num);
	/* Need to reset cmd counter, irq counter and array */
	i2c_restart(i2c);
	/* Check if we can send such message
	 * We have only 1 kbyte of memory for commands and data
	 */

	for (i = 0; i < num; i++, pmsg++) {
		flag = pmsg->flags;
		starts = !(flag & I2C_M_NOSTART);
		sum_len += pmsg->len;
		if (starts)
			count_starts++;
	}
	if (sum_len >= MAX_MEM_SIZE - 5*count_starts) {
		return -ENOSPC;
	}
	pmsg -= num;
	for (i = 0; i < num; i++, pmsg++) {
		int addr;
		int bus_probe = (num == 1) && (pmsg->len == 0);
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
			dev_err(&adap->dev, "FIXME: a ten bit address not supported.\n");
			return -ENOTSUPP;
		} else { /* normal 7bit address	*/
			addr = pmsg->addr << 1;
			if (flags & I2C_M_RD)
				addr |= 1;
			if (flags & I2C_M_REV_DIR_ADDR)
				addr ^= 1;
		}

		if (start) { /* Sending device address */
			ret = i2c_send(i2c, pmsg->flags & I2C_M_RD, addr, bus_probe);
			if (ret)
				return ret;
		}

		/* In case of ignorable NACK --> set I2HC_CONTROL[2] */
		if (!nak) {
			ignore_nack = 1;
		}

		/* check for bus probe */
		if ((num == 1) && (pmsg->len == 0)) {
			i = 1;
			break;
		}

		if (flags & I2C_M_RD) {
			ret = i2c_v7_read(adap, pmsg->buf,
						pmsg->len, flags, stop_bit, read_num);
			buffer[read_num] = pmsg->buf;
			if (ret)
				return ret;
			read_num++;
		} else {
			i2c_v7_write(adap, pmsg->buf,
						pmsg->len, flags, stop_bit);
		}
	}
	/* Finished with filling up MEM -> Enable i2c controller executing */
	reinit_completion(&i2c->last_cmd_completion);
	i2c_write32(i2c, I2C_V7_REG_I2HC_CONTROL, (ignore_nack << 2 | I2C_V7_CTRL_EN));

	/* Once enabled it will start exec commands one by one until stop interrupt */
	/* But while exec arbit_lost/nack may happen */

	if (!wait_for_completion_timeout(&i2c->last_cmd_completion, timeout)) {
		return -ETIMEDOUT;
	}

	if (i2c->arbit_lost || i2c->nack || i2c->none) {
		/* arbit_lost or nack happened or no irq happened -- ERROR */
		return -EIO;
	} else if (i2c->last) {
		/* This should never happen, but we reached the last byte in i2c MEM */
		for (j = 0; j < 0x400; j += 4) {
			i2c_write32(i2c, I2C_V7_REG_MEM_0 + i, 0x0);
		}
		return -EIO;
	} else if (i2c->stop) {
		/* Now we need to read data after controller's operations done in case of READ */
		for (j = 0; j < read_num; j++) {
			shift_bytes = 0;
			while (i2c->i2c_cmd_array[j].read_length--) {
				*(buffer[j])++ = i2c_read8(i2c,
						i2c->i2c_cmd_array[j].read_offset + shift_bytes);
				shift_bytes += 0x1;
			}
		}
		/* Read finished --> Transfer finished */
	}
	return i;
}

static u32 i2c_v7_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm i2c_v7_algo = {
	.master_xfer	= i2c_v7_xfer,
	.functionality	= i2c_v7_func,
};

static int i2c_v7_probe(struct pci_dev *pdev,
			const struct pci_device_id *id)
{
	int ret = 0;
	void __iomem *regs = NULL;
	struct device *dev = &pdev->dev;
	struct i2c_v7 *i2c = devm_kzalloc(dev, sizeof(*i2c), GFP_KERNEL);
	int irq_num;
	int msi_vectors;

	if (!i2c)
		return -ENOMEM;
	ret = pcim_enable_device(pdev);
	if (ret) {
		dev_err(&pdev->dev, "Failed to enable i2c master device\n");
		return ret;
	}
	ret = pcim_iomap_regions(pdev, BIT(0), KBUILD_MODNAME);
	if (ret < 0) {
		dev_err(&pdev->dev, "BAR0 is busy, can't access\n");
		return ret;
	}
	regs = pcim_iomap_table(pdev)[0];
	if (IS_ERR(regs)) {
		return IS_ERR(regs);
	}
	init_completion(&i2c->last_cmd_completion);

	msi_vectors = pci_alloc_irq_vectors(pdev, 1, 1, PCI_IRQ_MSI);
	if (msi_vectors < 0) {
		dev_err(&pdev->dev, "Cannot allocate MSI vectors for i2c\n");
		return -ENODEV;
	}

	irq_num = pci_irq_vector(pdev, 0);
	if (request_irq(irq_num, i2c_v7_irq_handler, IRQF_SHARED, "i2c_v7 irq", i2c) < 0) {
		dev_err(&pdev->dev, "Failed to register  MSI vectors\n");
		return -ENODEV;
	}

	pci_set_master(pdev);

	i2c->irq = irq_num;
	i2c->regs = regs;
	i2c->pdev = pdev;
	i2c->adap.owner = THIS_MODULE;
	i2c->adap.class = I2C_CLASS_DDC;
	i2c_set_adapdata(&i2c->adap, i2c);

	int ioh = dev_to_node(&pdev->dev);
	if (ioh < 0)
		ioh = 0;
	int chan = PCI_FUNC(pdev->devfn);

	snprintf(i2c->adap.name, sizeof(i2c->adap.name),
			"i2c i2c_v7 (ioh %d chan %d)", ioh, chan);

	i2c->adap.dev.parent	= dev;
	i2c->adap.dev.of_node	= dev->of_node;
	i2c->adap.nr		= i2c_v7_data.bus_nr;
	i2c->adap.algo		= &i2c_v7_algo;
	pci_set_drvdata(pdev, i2c);
	ret = init_hw_i2c_v7(i2c);
	if (ret < 0) {
		dev_err(dev, "init for i2c failed\n");
		return ret;
	}
	ret = i2c_add_numbered_adapter(&i2c->adap);
	if (ret) {
		dev_err(dev, "Failed to register i2c\n");
		return ret;
	}

	return ret;
}

static void i2c_v7_remove(struct pci_dev *pdev)
{
	struct i2c_v7 *i2c = pci_get_drvdata(pdev);
	i2c_write32(i2c, I2C_V7_REG_I2HC_CONTROL, 0);
	i2c_del_adapter(&i2c->adap);
	free_irq(i2c->irq, i2c);
	pci_free_irq_vectors(pdev);
}

static int i2c_v7_suspend(struct pci_dev *pdev, pm_message_t state)
{
	struct i2c_v7 *i2c = pci_get_drvdata(pdev);
	/* DISABLE I2C CORE */
	i2c_write32(i2c, I2C_V7_REG_I2HC_CONTROL, 0);

	return 0;
}

static int i2c_v7_resume(struct pci_dev *pdev)
{
	struct i2c_v7 *i2c = pci_get_drvdata(pdev);
	int ret = init_hw_i2c_v7(i2c);
	if (ret < 0)
		return ret;

	return 0;
}

static struct pci_driver i2c_v7_driver = {
	.name		= "i2c_v7",
	.id_table	= i2c_v7_ids,
	.probe		= i2c_v7_probe,
	.remove		= i2c_v7_remove,
	.suspend	= i2c_v7_suspend,
	.resume		= i2c_v7_resume,
};

static int i2c_v7_init(void)
{
	return pci_register_driver(&i2c_v7_driver);
}
module_init(i2c_v7_init);

static void i2c_v7_exit(void)
{
	pci_unregister_driver(&i2c_v7_driver);
}
module_exit(i2c_v7_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("i2c driver for V7 Elbrus processors");
MODULE_LICENSE("GPL v2");
MODULE_VERSION("1.0");
