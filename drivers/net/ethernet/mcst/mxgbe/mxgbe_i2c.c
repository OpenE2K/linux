/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_i2c.c - MXGBE module device driver
 *
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "kcompat.h"

#include "mxgbe_i2c.h"


#undef MXGBE_BUG_90353
#undef MXGBE_I2C_FULL_DEBUG


/**
 * ch2.5 - I2C
 */

#define	MXGBE_I2C_TIMEOUT_MSEC	1000
/* I2C_REG_READY regiter bits */
#define I2C2_RMAC_START		SET_BIT(4)
#define I2C2_RMAC_DONE		SET_BIT(3)
#define I2C2_READY		SET_BIT(2)
#define I2C1_READY		SET_BIT(1)
#define I2C0_READY		SET_BIT(0)


/**
 ******************************************************************************
 * I2C Registers
 ******************************************************************************
 */

/* Clock Prescale register lo (RW) */
#define I2C_X_PRER_LO	((I2C_0_PRERLO) - (I2C_0_PRERLO))
/* Clock Prescale register hi (RW) */
#define I2C_X_PRER_HI	((I2C_0_PRERHI) - (I2C_0_PRERLO))
/* Control Register (RW) */
#define I2C_X_CTR	((I2C_0_CTR) - (I2C_0_PRERLO))
/* Transmit Register (W) */
#define I2C_X_TXR	((I2C_0_RX_TXR) - (I2C_0_PRERLO))
/* Receive Register (R) */
#define I2C_X_RXR	((I2C_0_RX_TXR) - (I2C_0_PRERLO))
/* Command Register (W) */
#define I2C_X_CR	((I2C_0_CR) - (I2C_0_PRERLO))
/* Status Register (R) */
#define I2C_X_SR	((I2C_0_SR) - (I2C_0_PRERLO))


/* Control Register bits */
#define I2C_CTR_EN	(1 << 7)  /* I2C core enable bit           */
#define I2C_CTR_IEN	(1 << 6)  /* I2C core interrupt enable bit */

/* Transmit Register operations */
#define I2C_READ_OP	0x01  /* Reading from slave (x << 1 | I2C_READ_OP) */
#define I2C_WRITE_OP	0xFE  /* Writing to slave (x << 1 & I2C_WRITE_OP) */

/* Command Register bits */
#define I2C_CR_STA	(1 << 7)  /* generate (repeated) start condition */
#define I2C_CR_STO	(1 << 6)  /* generate stop condition             */
#define I2C_CR_RD	(1 << 5)  /* read from slave                     */
#define I2C_CR_WR	(1 << 4)  /* write to slave                      */
#define I2C_CR_NACK	(1 << 3)  /* when a receiver, sent I2C_CR_NACK   */
#define I2C_CR_IACK	(1 << 0)  /* interrupt acknowledge               */

/* Status Register bits */
#define I2C_SR_RxACK	(1 << 7)  /* Receive acknowledge from slave. */
				  /* '1' - no acknowledge received   */
#define I2C_SR_BUSY	(1 << 6)  /* I2C bus busy. '1' after START, */
				  /* '0' after STOP                 */
#define I2C_SR_AL	(1 << 5)  /* Arbitration lost */
#define I2C_SR_TIP	(1 << 1)  /* Transfer in progress.      */
				  /* '1' when transferring data */
#define I2C_SR_IF	(1 << 0)  /* Interrupt flag */


#define I2C_WAIT_FOR_READY \
do { \
	u32 val; \
	unsigned long timestart; \
	int cnum = ((u64)regs >> 5) & 0x03; \
	void __iomem *base = (void *)((u64)regs & (~0x0FFFF)); \
	/* wait for ready */ \
	timestart = jiffies; \
	do { \
		val = mxgbe_rreg32(base, I2C_REG_READY); \
		if (time_after(jiffies, timestart + HZ)) { \
			pr_err(KBUILD_MODNAME ": I2C controller busy\n"); \
			return; \
		} \
	} while (!(val & (1 << cnum))); \
} while (0)


struct mxgbe_i2c_chan {
	struct i2c_adapter adapter;
	void __iomem *regs;
};


/**
 ******************************************************************************
 * I2C Internal
 ******************************************************************************
 */

static void i2c_write(void __iomem *regs, int reg_num, int val_in)
{
	nFDEBUG;

#ifdef MXGBE_BUG_90353
	I2C_WAIT_FOR_READY;
#endif /* MXGBE_BUG_90353 */

#ifdef MXGBE_I2C_FULL_DEBUG
	PDEBUG(MXGBE_DBG_MSK_I2C,
		"i2c_write: reg 0x%04llX := 0x%02X\n",
		(u64)(regs + reg_num) & 0xFFFF, val_in);
#endif /* MXGBE_I2C_FULL_DEBUG */

	mxgbe_wreg32(regs, reg_num, val_in);
} /* i2c_write */


static u8 i2c_read(void __iomem *regs, int reg_num)
{
	u32 val_out;

	nFDEBUG;

#ifdef MXGBE_BUG_90353
	I2C_WAIT_FOR_READY;
#endif /* MXGBE_BUG_90353 */

	val_out = mxgbe_rreg32(regs, reg_num);

#ifdef MXGBE_I2C_FULL_DEBUG
	PDEBUG(MXGBE_DBG_MSK_I2C,
		"i2c_read: reg 0x%04llX == 0x%02X\n",
		(u64)(regs + reg_num) & 0xFFFF, val_out);
#endif /* MXGBE_I2C_FULL_DEBUG */

	return (u8)(val_out);
} /* i2c_read */


#if 0
/* set in RTL */
static void set_prescaler(void __iomem *regs, int value)
{
	i2c_write(regs, I2C_X_PRER_LO, value & 0xFF);
	i2c_write(regs, I2C_X_PRER_HI, (value >> 8) & 0xFF);
} /* set_prescaler */
#endif /* set in RTL */


static int i2c_send(struct i2c_adapter *adap, int cmd, int data)
{
	struct mxgbe_i2c_chan *i2c = i2c_get_adapdata(adap);
	void __iomem *regs = i2c->regs;
	u8 status;
	int i;


	nFDEBUG;

	if (cmd & I2C_CR_WR) {
		i2c_write(regs, I2C_X_TXR, data);
	}
	i2c_write(regs, I2C_X_CR, cmd);

	for (i = 0; i < MXGBE_I2C_TIMEOUT_MSEC; i++) {
#ifndef MXGBE_BUG_90353
		/* mdelay(1); */
#else /* MXGBE_BUG_90353 */
		status = i2c_read(regs, I2C_X_SR);
		status = i2c_read(regs, I2C_X_SR);
#endif /* MXGBE_BUG_90353 */
		status = i2c_read(regs, I2C_X_SR);
		if (status & I2C_SR_AL) {
			dev_err(&adap->dev,
				"%s ERROR: i2c_send busy: arbitration lost\n",
				adap->name);
			return -EAGAIN;
		}
		if (!(status & I2C_SR_TIP)) {
			if (cmd & I2C_CR_WR) {
				if (status & I2C_SR_RxACK) {
					dev_err(&adap->dev,
						"%s ERROR: no acknowledge " \
						"from slave\n",
						adap->name);
					return -ENODEV;
				}
			}
			return 0;
		}
	}
	dev_err(&adap->dev,
		"%s ERROR: i2c_send timeout: transfer in progress\n",
		adap->name);
	return -ETIME;
} /* i2c_send */


static int i2c_read_buf(struct i2c_adapter *adap, unsigned char *buf, int len)
{
	int ret = 0;
	struct mxgbe_i2c_chan *i2c = i2c_get_adapdata(adap);
	void __iomem *regs = i2c->regs;

	nFDEBUG;

	while (len--) {
		int ret;
		int v = I2C_CR_RD;

		if (!len)
			v |= I2C_CR_STO | I2C_CR_NACK;
		ret = i2c_send(adap, v, 0);
		if (ret)
			break;

#ifdef MXGBE_BUG_90353
		*buf = i2c_read(regs, I2C_X_RXR);
#endif /* MXGBE_BUG_90353 */
		*buf++ = i2c_read(regs, I2C_X_RXR);
	}
	return ret;
} /* i2c_read_buf */


static int i2c_write_buf(struct i2c_adapter *adap, unsigned char *buf, int len)
{
	nFDEBUG;

	while (len--) {
		int v = I2C_CR_WR;

		if (!len)
			v |= I2C_CR_STO;
		if (i2c_send(adap, v, *buf++)) {
			return -1;
		}
	}

	return 0;
} /* i2c_write_buf */


static int i2c_xfer(struct i2c_adapter *adap, struct i2c_msg *pmsg, int num)
{
	int i, ret;

	nFDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_I2C, &adap->dev,
		"/ %s: processing %d messages:\n",
		adap->name, num);

	for (i = 0; i < num; i++, pmsg++) {
		int addr = pmsg->addr << 1;
		if (pmsg->flags & I2C_M_RD)
			addr |= I2C_READ_OP;
		else
			addr &= I2C_WRITE_OP;

		DEV_DBG(MXGBE_DBG_MSK_I2C, &adap->dev,
			"| #%d: %sing %d byte%s %s 0x%02x\n", i,
			pmsg->flags & I2C_M_RD ? "read" : "writ",
			pmsg->len, pmsg->len > 1 ? "s" : "",
			pmsg->flags & I2C_M_RD ? "from" : "to",
			pmsg->addr);

		/* Sending device address */
		if (i2c_send(adap, I2C_CR_STA | I2C_CR_WR, addr)) {
			return -1;
		}

		/* check for bus probe */
		if ((num == 1) && (pmsg->len == 0)) {
			i = 1;
			break;
		}

		/* Read/Write data */
		if (pmsg->flags & I2C_M_RD)
			ret = i2c_read_buf(adap, pmsg->buf, pmsg->len);
		else
			ret = i2c_write_buf(adap, pmsg->buf, pmsg->len);

		if (ret)
			return ret;
	}
	return i;
} /* i2c_xfer */


static u32 i2c_func(struct i2c_adapter *adap)
{
	FDEBUG;

	return I2C_FUNC_I2C | I2C_FUNC_SMBUS_EMUL;
} /* i2c_func */


static const struct i2c_algorithm i2c_algo = {
	.master_xfer = i2c_xfer,
	.functionality = i2c_func,
};


/**
 ******************************************************************************
 * I2C Init
 ******************************************************************************
 */

void mxgbe_i2c_reset(mxgbe_priv_t *priv)
{
	u32 val;
	void __iomem *base = priv->bar0_base;
	unsigned long timestart;

	FDEBUG;

	/* wait for bit 3 == 1 */
	timestart = jiffies;
	do {
		val = mxgbe_rreg32(base, I2C_REG_READY);
		if (time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: I2C controller busy\n");
			return;
		}
	} while (!(val & I2C2_RMAC_DONE));

	/* Reset */
	mxgbe_wreg32(base, I2C_REG_READY, I2C2_RMAC_START);

	/* wait for bit 3 == 1 */
	timestart = jiffies;
	do {
		val = mxgbe_rreg32(base, I2C_REG_READY);
		if (time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: I2C controller busy\n");
			return;
		}
	} while (!(val & I2C2_RMAC_DONE));

} /* mxgbe_i2c_reset */


struct i2c_adapter *mxgbe_i2c_create(struct device *parent,
				     void __iomem *regs, char *name)
{
	struct mxgbe_i2c_chan *i2c;
	int ret;
#if 0
	/* set in RTL */
	unsigned base_freq_hz = 156250 * 1000; /* 156,25MHz */
	unsigned desired_freq_hz = 100 * 1000;  /* 50kHz */
#endif /* set in RTL */


	FDEBUG;

	i2c = kzalloc(sizeof(struct mxgbe_i2c_chan), GFP_KERNEL);
	if (!i2c)
		return NULL;

	i2c->adapter.owner = THIS_MODULE;
	i2c->adapter.class = MXGBE_I2C_CLASS;
	i2c->adapter.dev.parent = parent;
	i2c->regs = regs;
	i2c_set_adapdata(&i2c->adapter, i2c);
	snprintf(i2c->adapter.name, sizeof(i2c->adapter.name),
		 KBUILD_MODNAME " i2c bus%s", name);

	i2c->adapter.algo = &i2c_algo;
	ret = i2c_add_adapter(&i2c->adapter);
	if (ret) {
		pr_err(KBUILD_MODNAME ": Failed to register i2c adapter\n");
		goto out_free;
	}

#if 0
	/* set in RTL */
	/* Prescaler divider evaluates as (BASE_FREQ/(5*SCLK))-1 */
	set_prescaler(regs, base_freq_hz / 5 / desired_freq_hz - 1);
#endif /* set in RTL */

	/* Enable I2C core */
	i2c_write(regs, I2C_X_CTR, I2C_CTR_EN);

	return &i2c->adapter;
out_free:
	kfree(i2c);
	return NULL;
} /* mxgbe_i2c_create */


void mxgbe_i2c_destroy(struct i2c_adapter *adapter)
{
	struct mxgbe_i2c_chan *i2c;

	FDEBUG;

	if (!adapter)
		return;

	i2c = i2c_get_adapdata(adapter);
	i2c_del_adapter(adapter);
	kfree(i2c);
} /* mxgbe_i2c_destroy */


/**
 ******************************************************************************
 * I2C Interface
 ******************************************************************************
 */

u8 mxgbe_i2c_rd(struct i2c_adapter *adapter, u8 slave_addr, u8 addr)
{
	u8 val = 0;
	u8 out_buf[2];
	u8 in_buf[2];
	struct i2c_msg msgs[] = {
		{
		 .addr = slave_addr,
		 .flags = 0,
		 .len = 1,
		 .buf = out_buf,
		 },
		{
		 .addr = slave_addr,
		 .flags = I2C_M_RD,
		 .len = 1,
		 .buf = in_buf,
		 }
	};

	FDEBUG;

	out_buf[0] = addr;
	out_buf[1] = 0;

	if (i2c_transfer(adapter, msgs, 2) == 2) {
		val = in_buf[0];
		DEV_DBG(MXGBE_DBG_MSK_I2C, &adapter->dev,
			"\\ %s: read 0x%02x = 0x%02x\n",
			adapter->name, addr, val);
	} else {
		DEV_DBG(MXGBE_DBG_MSK_I2C, &adapter->dev,
			"\\ %s: read 0x%02x failed\n",
			adapter->name, addr);
	}
	return val;
} /* mxgbe_i2c_rd */


void mxgbe_i2c_wr(struct i2c_adapter *adapter, u8 slave_addr, u8 addr, u8 val)
{
	uint8_t out_buf[2];
	struct i2c_msg msg = {
		.addr = slave_addr,
		.flags = 0,
		.len = 2,
		.buf = out_buf,
	};

	FDEBUG;

	out_buf[0] = addr;
	out_buf[1] = val;

	DEV_DBG(MXGBE_DBG_MSK_I2C, &adapter->dev,
		"\\ %s: write 0x%02x := 0x%02x\n", adapter->name, addr, val);
	if (i2c_transfer(adapter, &msg, 1) != 1)
		DEV_DBG(MXGBE_DBG_MSK_I2C, &adapter->dev,
			"\\ %s: write 0x%02x failed\n", adapter->name, addr);
} /* mxgbe_i2c_wr */


u64 mxgbe_i2c_read_mac(mxgbe_priv_t *priv)
{
	int i;
	u8 v8;
	u64 mac = 0;

	FDEBUG;

	if (priv->i2c_2) {
		for (i = 0; i < 6; i++) {
			mac <<= 8;
			v8 = mxgbe_i2c_rd(priv->i2c_2, I2C_EEPROM_ADDR,
					i + I2C_EEPROM_MAC_BASE);
			mac |= v8;
		}
	}

	return mac;
} /* mxgbe_i2c_read_mac */
