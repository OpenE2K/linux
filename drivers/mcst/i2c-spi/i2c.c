/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Elbrus I2C controller support
 *
 */

#include <linux/kernel.h>
#include <linux/delay.h>
#include <linux/ioport.h>
#include <linux/i2c.h>
#include <linux/pci.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/stddef.h>
#include <linux/slab.h>
#include <linux/io.h>
#include <linux/pci_ids.h>
#include <asm/iolinkmask.h>
#include <asm/gpio.h>

#include <asm-l/i2c-spi.h>


/* I2C definitions for Elbrus I2C-SPI Controller (part of IOHUB) */

#define I2C_IOHUB_BAR0_OFFSET	0x14
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
	unsigned __ret = 0, __size = size;		\
	if (__size > 0 && __size < I2C_MAX_TRANS_BYTES)	\
		__ret = (__size << I2C_TRANS_SIZE_SHIFT);\
	__ret;						\
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

#define I2C_DST_BUS(bus_id)					\
({								\
	unsigned __ret = 0, __bus_id = bus_id;			\
	if (__bus_id > 0 && __bus_id < I2C_DST_BUSSES)		\
		__ret = (__bus_id << I2C_DST_BUS_NUMBER_SHIFT);	\
	else if (__bus_id == 4)					\
		__ret = (1 << I2C_BUS_4_SHIFT);			\
	__ret;							\
})
#define I2C_START_BYTE_ON_SHIFT	26
#define I2C_START_BYTE_ON	(1 << I2C_START_BYTE_ON_SHIFT)
#define I2C_KILL_SHIFT		27
#define I2C_KILL		(1 << I2C_KILL_SHIFT)
#define I2C_START_EXEC_SHIFT	28
#define I2C_START_EXEC		(1 << I2C_START_EXEC_SHIFT)
#define I2C_BUS_4_SHIFT		30
#define I2C_CONTROL_MASK	0x1fffffff	/* bits 31 not used
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
#define I2C_BUS_4_MODE_SHIFT	9
#define I2C_BUS_4_MODE_MASK	(I2C_BUS_0_MODE_MASK << I2C_BUS_4_MODE_SHIFT)
#define I2C_MODE_MASK		0x1ff /* bits 31:11 not used (const zeros) */

/* I2C_TIMEOUTVAL field */

#define I2C_TIMEOUTVAL_ASIC		0x0ee6b280
#define I2C_TIMEOUTVAL_ALTERA		0x05f5e100
#define I2C_TIMEOUTVAL_MASK		0xffffffff


/* IOHUB SMBus address offsets */
#define SMBCONTROL	(I2C_CONTROL	+ l_i2c->cbase + I2C_IOHUB_BAR0_OFFSET)
#define SMBSTATUS	(I2C_STATUS	+ l_i2c->cbase + I2C_IOHUB_BAR0_OFFSET)
#define SMBMODE		(I2C_MODE	+ l_i2c->cbase + I2C_IOHUB_BAR0_OFFSET)
#define SMBTIMEOUT	(I2C_TIMEOUTVAL + l_i2c->cbase + I2C_IOHUB_BAR0_OFFSET)
#define SMBDATA		(l_i2c->dbase)

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

/* Multimaster i2c configuration can require l_xfer retry in case of
 * bus collision. Limit number of retries. */
#define MAX_RETRIES	100

struct l_i2c {
	struct i2c_adapter adapter[I2C_MAX_BUSSES];
	int adapters_nr;
	unsigned bus_speed[I2C_MAX_BUSSES];
	struct platform_device *pdev;
	void __iomem *cbase;
	void __iomem *dbase;
	struct completion xfer_complete;
	bool no_irq;
};
#define	__r_i2c(__addr) readl(__addr)
#define	__w_i2c(__v, __addr) writel(__v, __addr)

#define r_i2c(__offset)				\
({								\
	unsigned __val = __r_i2c(__offset);			\
	dev_dbg(&l_i2c->pdev->dev, "r: %8x: %s\t\t%s:%d\n",	\
			__val, # __offset, __func__, __LINE__);	\
	__val;							\
})

#define w_i2c(__val, __offset)	do {				\
	unsigned __val2 = __val;				\
	dev_dbg(&l_i2c->pdev->dev, "w: %8x: %s\t\t%s:%d\n",	\
			__val2, # __offset, __func__, __LINE__);\
	__w_i2c(__val2, __offset);				\
} while (0)

static irqreturn_t l_i2c_irq_handler(int irq, void *devid)
{
	struct l_i2c *l_i2c = devid;
	u32 s = r_i2c(SMBSTATUS);
	if (!(s & I2C_INTERRUPT))
		return IRQ_NONE;

	complete(&l_i2c->xfer_complete);
	w_i2c(I2C_INTERRUPT, SMBSTATUS);
	return IRQ_HANDLED;
}

static int l_i2c_transaction(struct i2c_adapter *adap)
{
	unsigned s = 0;
	int ret = 0;
	struct l_i2c *l_i2c = i2c_get_adapdata(adap);

	/* Make sure the SMBus host is ready to start transmitting */
	s = r_i2c(SMBSTATUS);
	if (s & I2C_CONTROLLER_BUSY) {
		dev_err(&adap->dev, "Controller is busy! (%02x)\n", s);
		return -EBUSY;
	}

	reinit_completion(&l_i2c->xfer_complete);
	/* start the transaction by setting bit 28 */
	w_i2c(r_i2c(SMBCONTROL) | I2C_START_EXEC, SMBCONTROL);

	if (l_i2c->no_irq) {
		unsigned long timeout = jiffies + adap->timeout;
		while (time_before(jiffies, timeout) &&
				r_i2c(SMBSTATUS) & I2C_CONTROLLER_BUSY)
			mdelay(1);
	} else if (!wait_for_completion_timeout(&l_i2c->xfer_complete,
						adap->timeout)) {
		dev_warn(&adap->dev, "SMBus Timeout! status: %x\n",
			  r_i2c(SMBSTATUS));
	}
	s = r_i2c(SMBSTATUS);
	/* If the SMBus is still busy, we give up */
	if (s & I2C_CONTROLLER_BUSY) {
		dev_err(&adap->dev, "l_i2c is still busy (status: %x)!\n", s);
		ret = -ETIMEDOUT;
		goto out;
	}
	if (s & I2C_FAILED) {
		ret = -EIO;
		dev_err(&adap->dev, "Error: Failed bus transaction\n");
		goto out;
	}

	if (s & I2C_BUS_COLLISION) {
		ret = -EAGAIN;
		/* well, try to fixup it later in l_xfer */
		goto out;
	}

	if (s & I2C_TRANS_TIMEOUT) {
		ret = -ENXIO;
		/* I2C_TRANS_TIMEOUT is legitimate for multimaster. */
		/* dev_err(&adap->dev, "Error: no response!\n"); */
		goto out;
	}
out:
	/* Reset status register */
	w_i2c(r_i2c(SMBSTATUS), SMBSTATUS);

	if ((s = r_i2c(SMBSTATUS)) != 0) {
		dev_err(&adap->dev, "Failed reset at end of "
				"transaction (%02x)\n", s);
	}

	return ret;
}

static s32 l_i2c_xfer_one_msg(struct i2c_adapter *adap, struct i2c_msg *m)
{
	struct l_i2c *l_i2c = i2c_get_adapdata(adap);
	int bus_id = adap->nr % l_i2c->adapters_nr;
	int ret = 0;
	int f = m->flags, len = m->len;
	u32 v = m->addr;
	u8 *buf = m->buf;
	if (f & I2C_M_RECV_LEN)
		return -EOPNOTSUPP;

	v = (m->addr & 0xff) << I2C_7BIT_ADDR_SHIFT;
	if (f & I2C_M_TEN) {
		v |= ((m->addr >> 8) & 0xff)
				<< I2C_10BIT_ADDR_SHIFT;
		v |= I2C_10BIT_ADDR_MODE;
	}

	v |= I2C_DST_BUS(bus_id);
	v &= ~I2C_START_BYTE_ON;
	v |= I2C_TRANS_SIZE(len);

	if (len)
		v |= I2C_DATA_PHASE_PRESENT;
	if (!(f & I2C_M_RD))
		v |= I2C_TRANSACTION_TYPE_WRITE;

	if (!(f & I2C_M_RD))
		__memcpy_toio(SMBDATA, buf, len);

	w_i2c(v, SMBCONTROL);

	ret = l_i2c_transaction(adap);
	if (ret)
		goto out;

	if (!(f & I2C_M_RD))
		goto out;

	__memcpy_fromio(buf, SMBDATA, len);
out:
	return ret;
}

static int __l_i2c_xfer(struct i2c_adapter *adap,
			   struct i2c_msg *p, int num)
{
	int i, ret = 0, num_ret = num;
	int f = p[0].flags;
	struct i2c_msg m;

	if (num == 2 && p[0].len == 1 &&
			!(f & I2C_M_RD) && !(f & I2C_M_TEN)) {
		/* rm 33502: emulation of smbus-read:
		 use 10bit address mode to send one byte
		in the low byte of address */
		int a = p[0].buf[0];
		memcpy(&m, &p[1], sizeof(m));
		p = &m;
		p->flags |= I2C_M_TEN;
		p->addr |= (a << 8);
		num = 1;
	}
	/* Bug 114565, rm34303:
	* Controller can't send pmsg in a single transaction,
	* so split it into num transactions in hope (it works with eeprom at24)
	* that slave will handle them.*/
	for (i = 0; i < num && ret == 0; i++, p++) {
		ret = l_i2c_xfer_one_msg(adap, p);
		dev_dbg(&adap->dev,
			"master_xfer[%d] %c, addr=0x%02x, len=%d%s:%d\n",
			i, (p->flags & I2C_M_RD) ? 'R' : 'W',
			p->addr, p->len,
			(p->flags & I2C_M_RECV_LEN) ? "+" : "", ret);
	}

	if (ret)
		return ret;
	else
		return num_ret;
}

static int l_i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *pmsg, int num)
{
	struct l_i2c *l_i2c = i2c_get_adapdata(adap);
	int retries = 0, ret = 0;
	do {
		/* Lock parent device if we are going to use the common buffer
		 * which may be in use by other I2C adapters or
		 * by SPI controller. */
		device_lock(l_i2c->pdev->dev.parent);
		ret = __l_i2c_xfer(adap, pmsg, num);
		device_unlock(l_i2c->pdev->dev.parent);
		retries++;
	} while (ret == -EAGAIN && retries < MAX_RETRIES);

	if (ret == -EAGAIN)
		dev_err(&adap->dev, "l_i2c_xfer: Failed to fix i2c bus"
					"collision. Retries %d\n", retries);
	return ret;
}

static u32 l_i2c_func(struct i2c_adapter *adap)
{
	return I2C_FUNC_I2C | I2C_FUNC_10BIT_ADDR | I2C_FUNC_SMBUS_EMUL;
}

static const struct i2c_algorithm l_i2c_algorithm = {
	.master_xfer	= l_i2c_xfer,
	.functionality	= l_i2c_func,
};

static const struct i2c_adapter_quirks l_i2c_quirks = {
	.max_write_len = I2C_MAX_TRANS_BYTES,
	.max_read_len = I2C_MAX_TRANS_BYTES,
};

static void l_i2c_init_hw(struct l_i2c *l_i2c)
{
	int i;
	unsigned mode = I2C_INTERRUPT_ENABLE;
	/* Reset status bits: write ones to RW1C bits of I2C Status. */
	w_i2c(r_i2c(SMBSTATUS), SMBSTATUS);

	for (i = 0; i < l_i2c->adapters_nr; i++) {
		unsigned speed = l_i2c->bus_speed[i], m = 0;
		int k = i == 4 ? 1 : 0;
		if (speed >= 1000 * 1000)
			m = I2C_BUS_0_FASTPLUS;
		else if (speed >= 400 * 1000)
			m = I2C_BUS_0_FAST;
		mode |= m << (k + i * I2C_BUS_1_MODE_SHIFT);
	}

	w_i2c(mode, SMBMODE);
}

/* Max. transaction takes:
 * (I2C_MAX_TRANS_BYTES + 2) * 10 bit / 100kHz = 6600 us.
 * Let 8 msec is hw timeout.
 */
#define TICKS_100MHZ (0x000C3500)
#define TICKS_250MHZ (0x001E8480)
#define TICKS_500MHZ (0x003D0900)
#define TICKS_1GHZ   (0x007A1200)

static void set_hw_timeout(struct l_i2c *l_i2c)
{
	u32 ticks = 0; /* 0 - use default hw timeout */

	switch (to_pci_dev(l_i2c->pdev->dev.parent)->device) {
	case PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI:
		{
			u32 pdata;

			pci_read_config_dword(to_pci_dev(l_i2c->pdev->dev.parent), 0x40, &pdata);
			/* I2C, IPMB, SPI_CS Port Control(offset 40h) 24:23 bits:
			 * 00 100 MHz
			 * 01 250 MHz
			 * 10 500 MHz
			 * 11 1 GHz
			 */
			switch ((pdata >> 23) & 0x03) {
			/* We set the number of ticks (=8ms) according to the received bits.
			 * But the frequencies can be in the ranges of 1GHz-500MHz,
			 * 500-250MHz, 250-100MHz.
			 * Thus, in reality, hw timeout can be up to 16-20 mc.
			 * So, 20 mc is a reasonable value for i2c->timeout.
			 */
			case 3:
				ticks = TICKS_1GHZ;
				break;
			case 2:
				ticks = TICKS_500MHZ;
				break;
			case 1:
				ticks = TICKS_250MHZ;
				break;
			case 0:
				ticks = TICKS_100MHZ;
			}
		}
		break;
	case PCI_DEVICE_ID_MCST_I2CSPI:
	case PCI_DEVICE_ID_MCST_I2C_SPI:
		if (iohub_revision(to_pci_dev(l_i2c->pdev->dev.parent)) & 0x01) {
			/* 250MHz - ASIC */
			ticks = TICKS_250MHZ;
		} else {
			/* 100MHz - ALTERA */
			ticks = TICKS_100MHZ;
		}
	}

	if (ticks)
		w_i2c(ticks, SMBTIMEOUT);

	dev_info(&l_i2c->pdev->dev, "I2C HW timeout: 0x%X\n", r_i2c(SMBTIMEOUT));
}

static int l_i2c_probe(struct platform_device *pdev)
{
	int ret = 0;
	int i;
	struct resource *r;
	struct l_i2c *l_i2c = kzalloc(sizeof(*l_i2c), GFP_KERNEL);
	if (!l_i2c)
		return -ENOMEM;

	l_i2c->adapters_nr = 4;
	if (to_pci_dev(pdev->dev.parent)->device ==
			PCI_DEVICE_ID_MCST_IOEPIC_I2C_SPI) {
		l_i2c->adapters_nr = 5;
	}

	r = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	l_i2c->cbase = devm_ioremap(&pdev->dev, r->start, resource_size(r));
	if (IS_ERR(l_i2c->cbase))
		return PTR_ERR(l_i2c->cbase);

	r = platform_get_resource(pdev, IORESOURCE_MEM, 1);
	l_i2c->dbase = devm_ioremap(&pdev->dev, r->start, resource_size(r));
	if (IS_ERR(l_i2c->dbase))
		return PTR_ERR(l_i2c->dbase);

	r = platform_get_resource(pdev, IORESOURCE_IRQ, 0);
	if (!r || (ret = devm_request_irq(&pdev->dev, r->start,
				l_i2c_irq_handler, 0, "l_i2c", l_i2c))) {
		l_i2c->no_irq = true;
	}

	l_i2c->pdev = pdev;
	init_completion(&l_i2c->xfer_complete);

	platform_set_drvdata(pdev, l_i2c);
	l_i2c_init_hw(l_i2c);
	set_hw_timeout(l_i2c);

	for (i = 0; i < l_i2c->adapters_nr; i++) {
		int id;
		char s[64];
		struct i2c_adapter *i2c = &l_i2c->adapter[i];

		sprintf(s, "/l_i2c@%d/i2c@%d", pdev->id, i);
		i2c->dev.of_node = of_find_node_by_path(s);
		/* check if a device is available for use in devtree */
		if (i2c->dev.of_node &&
			!of_device_is_available(i2c->dev.of_node))
			continue;

		id = pdev->id * I2C_MAX_BUSSES + i;

		/* set up the sysfs linkage to our parent device */
		i2c->dev.parent = &pdev->dev;
		/* init adapter himself */
		i2c->owner = THIS_MODULE;
		i2c->class = (I2C_CLASS_HWMON | I2C_CLASS_SPD);
		i2c->algo = &l_i2c_algorithm;
		i2c->quirks = &l_i2c_quirks;
		i2c->nr = id;
		/* See details in set_hw_timeout() */
		i2c->timeout = msecs_to_jiffies(20);
		of_property_read_u32(i2c->dev.of_node,
				"clock-frequency", &l_i2c->bus_speed[i]);
		sprintf(s, "i2c l_i2c (ioh %d chan %d)", pdev->id, i);
		strlcpy(i2c->name, s, sizeof(i2c->name));

		i2c_set_adapdata(i2c, l_i2c);

		if ((ret = i2c_add_numbered_adapter(i2c))) {
			dev_err(&pdev->dev, "failed to register "
					"I2C adapter %d!\n", id);
			goto cleanup;
		}
		dev_info(&pdev->dev, "I2C adapter %d registered\n", id);
	}

	return ret;

cleanup:
	for (i = 0; i < l_i2c->adapters_nr; i++)
		i2c_del_adapter(&l_i2c->adapter[i]);
	return ret;
}

static int l_i2c_remove(struct platform_device *pdev)
{
	struct l_i2c *l_i2c = platform_get_drvdata(pdev);
	int i;
	for (i = 0; i < l_i2c->adapters_nr; i++)
		i2c_del_adapter(&l_i2c->adapter[i]);
	kfree(l_i2c);
	return 0;
}

#ifdef CONFIG_PM_SLEEP
static int l_i2c_suspend(struct device *dev)
{
	return 0;
}

static int l_i2c_resume(struct device *dev)
{
	struct platform_device *pdev = to_platform_device(dev);
	struct l_i2c *l_i2c = platform_get_drvdata(pdev);
	l_i2c_init_hw(l_i2c);
	return 0;
}

static const struct dev_pm_ops l_i2c_pm_ops = {
	.suspend	= l_i2c_suspend,
	.resume		= l_i2c_resume,
};
#endif

static struct platform_driver l_i2c_driver = {
	.driver = {
		.name	= "l_i2c",
		.owner	= THIS_MODULE,
		/* To avoid recursive locking during probe()
		   in l_i2c_xfer() & l_smbus_xfer() */
		.probe_type	= PROBE_PREFER_ASYNCHRONOUS,
#ifdef CONFIG_PM_SLEEP
		.pm	= &l_i2c_pm_ops,
#endif
	},
	.probe	= l_i2c_probe,
	.remove	= l_i2c_remove,
};

__init
static int l_i2c_init(void)
{
	return platform_driver_register(&l_i2c_driver);
}
module_init(l_i2c_init);

__exit
static void l_i2c_exit(void)
{
	platform_driver_unregister(&l_i2c_driver);
}
module_exit(l_i2c_exit);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Elbrus I2C controller driver");
MODULE_LICENSE("GPL v2");
