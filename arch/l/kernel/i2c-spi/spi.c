/*
 * Elbrus SPI controller driver
 *
 * Copyright (C) 2012 MCST
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or (at
 * your option) any later version.
 *
 * 2012-05-29	Created
 */

#include <asm/io.h>
#include <linux/delay.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>

#include <asm-l/i2c-spi.h>

/* SPI definitions for Elbrus I2C-SPI Controller (part of IOHUB) */

#define L_SPI_CONTROL		0x00
#define		L_SPI_DEVICE_SHIFT		0
/* Maximum number of connected devices */
#define		L_SPI_MAX_DEVICES		4
#define		L_SPI_DEVICE_0			0
#define		L_SPI_DEVICE_1			1
#define		L_SPI_DEVICE_2			2
#define		L_SPI_DEVICE_3			3
#define		L_SPI_ADDRESS_SIZE_SHIFT	2
#define		L_SPI_ADDRESS_SIZE_8		(0 << L_SPI_ADDRESS_SIZE_SHIFT)
#define		L_SPI_ADDRESS_SIZE_16		(1 << L_SPI_ADDRESS_SIZE_SHIFT)
#define		L_SPI_ADDRESS_SIZE_24		(2 << L_SPI_ADDRESS_SIZE_SHIFT)
#define		L_SPI_ADDRESS_SIZE_32		(3 << L_SPI_ADDRESS_SIZE_SHIFT)
#define		L_SPI_DATA_SIZE_SHIFT		4
/* Maximum size of transaction */
#define		L_SPI_MAX_BYTES			64
#define		L_SPI_ADDRESS_PHASE_SHIFT	11
#define		L_SPI_ADDRESS_PHASE_ENABLE	(1 << L_SPI_ADDRESS_PHASE_SHIFT)
#define		L_SPI_ADDRESS_PHASE_DISABLE	(0 << L_SPI_ADDRESS_PHASE_SHIFT)
#define		L_SPI_DATA_PHASE_SHIFT		12
#define		L_SPI_DATA_PHASE_ENABLE		(1 << L_SPI_DATA_PHASE_SHIFT)
#define		L_SPI_DATA_PHASE_DISABLE	(0 << L_SPI_DATA_PHASE_SHIFT)
#define		L_SPI_TRANS_TYPE_SHIFT		13
#define		L_SPI_TRANS_READ		(0 << L_SPI_TRANS_TYPE_SHIFT)
#define		L_SPI_TRANS_WRITE		(1 << L_SPI_TRANS_TYPE_SHIFT)
#define		L_SPI_START_SHIFT		14
#define		L_SPI_START			(1 << L_SPI_START_SHIFT)
#define		L_SPI_KILL_SHIFT		15
#define		L_SPI_KILL			(1 << L_SPI_KILL_SHIFT)
#define L_SPI_STATUS		0x04
#define		L_SPI_STATUS_BUSY_SHIFT		0
#define		L_SPI_STATUS_BUSY		(1 << L_SPI_STATUS_BUSY_SHIFT)
#define		L_SPI_STATUS_INTR_SHIFT		1
#define		L_SPI_STATUS_INTR		(1 << L_SPI_STATUS_INTR_SHIFT)
#define		L_SPI_STATUS_FAIL_SHIFT		2
#define		L_SPI_STATUS_FAIL		(1 << L_SPI_STATUS_FAIL_SHIFT)
#define L_SPI_OPCODE		0x08
#define L_SPI_ADDRESS		0x0c
#define L_SPI_MODE		0x10
#define		L_SPI_MODE_MASK			1
#define		L_SPI_MODE_0			0
#define		L_SPI_MODE_3			1
#define		L_SPI_FREQ_CHANGED_SHIFT	1
#define		L_SPI_FREQ_CHANGED		(1 << L_SPI_FREQ_CHANGED_SHIFT)
#define		L_SPI_DIVIDER_SHIFT		2
#define		L_SPI_DIVIDER_2			(0 << L_SPI_DIVIDER_SHIFT)
#define		L_SPI_DIVIDER_4			(1 << L_SPI_DIVIDER_SHIFT)
#define		L_SPI_DIVIDER_8			(2 << L_SPI_DIVIDER_SHIFT)
#define		L_SPI_DIVIDER_16		(3 << L_SPI_DIVIDER_SHIFT)
#define		L_SPI_DIVIDER_MASK		0xc
#define		L_SPI_MODE_INTR_SHIFT		4
#define		L_SPI_MODE_INTR			(1 << L_SPI_MODE_INTR_SHIFT)


struct l_spi {
	spinlock_t lock;
	int mode;
	void __iomem *cntrl;
	void __iomem *data;
	struct device *dev;
	struct spi_master *master;
	u32 speed_hz_min;
	u32 speed_hz_max;
	u32 baseclk;
};


/* Reading/writing SPI controller registers */

static u32 l_spi_read(struct l_spi *l_spi, int reg)
{
	u32 res;

	res = readl(l_spi->cntrl + reg);

	dev_dbg(l_spi->dev, "reading register %s addr 0x%lx + reg 0x%x, got %x\n",
			(reg == L_SPI_CONTROL) ? "CONTROL" :
			(reg == L_SPI_STATUS) ? "STATUS" :
			(reg == L_SPI_ADDRESS) ? "ADDRESS" :
			(reg == L_SPI_MODE) ? "MODE" :
			(reg == L_SPI_OPCODE) ? "OPCODE" :
			"UNKNOWN",
			l_spi->cntrl, reg,
			res);

	return res;
}

static void l_spi_write(struct l_spi *l_spi, u32 val, int reg)
{
	dev_dbg(l_spi->dev, "writing register %s, value %x\n",
			(reg == L_SPI_CONTROL) ? "CONTROL" :
			(reg == L_SPI_STATUS) ? "STATUS" :
			(reg == L_SPI_ADDRESS) ? "ADDRESS" :
			(reg == L_SPI_MODE) ? "MODE" :
			(reg == L_SPI_OPCODE) ? "OPCODE" :
			"UNKNOWN",
			val);

	writel(val, l_spi->cntrl + reg);
}


#define MAX_BUSY_WAIT_LOOPS 10000000

static void l_spi_wait_busy(struct l_spi *l_spi)
{
	int status;
	u32 loops = 0;

	do {
		status = l_spi_read(l_spi, L_SPI_STATUS);
		if (loops++ == MAX_BUSY_WAIT_LOOPS) {
			dev_err(l_spi->dev, "Timed out waiting for the SPI controller!\n");
			break;
		}
	} while (status & L_SPI_STATUS_BUSY);

	/* Reset interrupt & fail bits */
	l_spi_write(l_spi, status, L_SPI_STATUS);
}

static void l_spi_wait_freq(struct l_spi *l_spi)
{
	u32 mode;
	u32 loops = 0;

	do {
		mode = l_spi_read(l_spi, L_SPI_MODE);
		if (loops++ == MAX_BUSY_WAIT_LOOPS) {
			dev_err(l_spi->dev, "Timed out waiting for the SPI controller to change frequency!\n");
			break;
		}
	} while (!(mode & L_SPI_FREQ_CHANGED));

	/* Reset 'freq' field */
	l_spi_write(l_spi, mode, L_SPI_MODE);
}

static u32 l_spi_wait_completion(struct l_spi *l_spi)
{
	u32 status;
	u32 loops = 0;

	do {
		status = l_spi_read(l_spi, L_SPI_STATUS);
		if (loops++ == MAX_BUSY_WAIT_LOOPS) {
			dev_err(l_spi->dev, "Timed out waiting for the SPI controller to finish transaction!\n");
			break;
		}
	} while ((status & (L_SPI_STATUS_INTR | L_SPI_STATUS_FAIL)) == 0);

	/* Reset interrupt & fail bits */
	l_spi_write(l_spi, status, L_SPI_STATUS);

	return status;
}


/* Change bus speed or mode as requested. */
static int l_spi_set_mode_and_freq(struct spi_device *spi,
		int spi_mode, int spi_freq)
{
	struct l_spi *l_spi = spi_master_get_devdata(spi->master);
	struct device *dev = l_spi->dev;
	int n, prev_n;
	u32 mode;

	dev_dbg(dev, "Setting mode %x and freq %d Hz, current mode %x and current speeds: %u - %u\n",
			spi_mode, spi_freq, l_spi->mode,
			l_spi->speed_hz_min, l_spi->speed_hz_max);

	if (spi_mode == l_spi->mode
			&& (!spi_freq || (spi_freq < l_spi->speed_hz_max &&
					spi_freq >= l_spi->speed_hz_min)))
		return 0;

	mode = l_spi_read(l_spi, L_SPI_MODE);
	prev_n = mode & L_SPI_DIVIDER_MASK;

	if (spi_freq) {
		n = DIV_ROUND_UP(l_spi->baseclk, spi_freq);
		if (n <= 2) {
			n = L_SPI_DIVIDER_2;
			l_spi->speed_hz_min = l_spi->baseclk / 2;
			l_spi->speed_hz_max = UINT_MAX;
		} else if (n <= 4) {
			n = L_SPI_DIVIDER_4;
			l_spi->speed_hz_min = l_spi->baseclk / 4;
			l_spi->speed_hz_max = l_spi->baseclk / 2;
		} else if (n <= 8) {
			n = L_SPI_DIVIDER_8;
			l_spi->speed_hz_min = l_spi->baseclk / 8;
			l_spi->speed_hz_max = l_spi->baseclk / 4;
		} else if (n <= 16) {
			n = L_SPI_DIVIDER_16;
			l_spi->speed_hz_min = 0;
			l_spi->speed_hz_max = l_spi->baseclk / 8;
		} else {
			dev_dbg(dev, "requested speed %d is not supported\n",
					spi_freq);
			return -EINVAL;
		}
	} else {
		/* No speed was specified so do not change it */
		n = prev_n;
	}

	dev_dbg(dev, "previous divider %d, new divider %d\n", prev_n, n);

	if (n != prev_n || spi_mode != l_spi->mode) {
		l_spi->mode = spi_mode;

		/* Frequency divider or SPI mode has changed */
		mode &= ~L_SPI_DIVIDER_MASK;
		mode |= n;
		mode &= ~L_SPI_MODE_MASK;
		if (spi_mode == SPI_MODE_0)
			mode |= L_SPI_MODE_0;
		else
			mode |= L_SPI_MODE_3;

		dev_dbg(dev, "set divider to %d and mode to %d\n",
				(n == L_SPI_DIVIDER_2) ? 2 :
				(n == L_SPI_DIVIDER_4) ? 4 :
				(n == L_SPI_DIVIDER_8) ? 8 :
				(n == L_SPI_DIVIDER_16) ? 16 : 0,
				(spi_mode == SPI_MODE_0) ? 0 : 3);

		l_spi_write(l_spi, mode, L_SPI_MODE);

		/* Wait until the new frequency
		 * divider is set */
		if (n != prev_n)
			l_spi_wait_freq(l_spi);
	}

	return 0;
}

static int l_spi_transfer(struct spi_device *spi, struct spi_message *m)
{
	struct l_spi *l_spi = spi_master_get_devdata(spi->master);
	struct device *dev = l_spi->dev;
	struct spi_transfer *t;
	unsigned long flags;
	int last = 1, ret = 0;
#define REG_BYTES 5
#define BUF_BYTES L_SPI_MAX_BYTES
	u8 reg[REG_BYTES], buf[BUF_BYTES], *rbuf;
	unsigned long reg_i, buf_i, buf_write;
	u32 speed_hz;
	u16 delay_usecs;
	u32 status, cmd;

	m->actual_length = 0;

	if (unlikely(spi->chip_select >= L_SPI_MAX_DEVICES)) {
		dev_err(dev, "spi transfer: bad spi device number %d\n",
				spi->chip_select);
		return -EINVAL;
	}

	/* check each transfer's parameters */
	list_for_each_entry(t, &m->transfers, transfer_list) {
		speed_hz = t->speed_hz ? : spi->max_speed_hz;
		u8 bits_per_word = t->bits_per_word ? : spi->bits_per_word;

		bits_per_word = bits_per_word ? : 8;

		if (unlikely(bits_per_word != 8)) {
			dev_err(dev, "spi transfer: requested bits_per_word %d "
				"is not supported\n", bits_per_word);
			return -EINVAL;
		}

		if (unlikely(speed_hz < l_spi->baseclk / 16)) {
			dev_err(dev, "spi transfer: requested speed %d "
					"is lower than %d\n", speed_hz,
					l_spi->baseclk / 16);
			return -EINVAL;
		}

		if (unlikely(!t->tx_buf && !t->rx_buf && t->len)) {
			dev_err(dev, "spi transfer: message is not empty but "
					"no buffers were provided\n");
			return -EINVAL;
		}

		if (unlikely(!t->len)) {
			dev_err(dev, "spi transfer: chip selecting is not "
					"supported\n");
			return -EIO;
		}
	}

	/* do all transfers atomically */
	spin_lock_irqsave(&l_spi->lock, flags);
	/* l_spi controller can do only one type of transactions:
	 *
	 * Write 1, 2, 3, 4 or 5 bytes followed by either write
	 * or read of up to 64 bytes.
	 *
	 * Chipselect is automatically asserted at the beginning
	 * of the transaction and de-asserted at its end.
	 *
	 * So we have to merge transfers in the message into
	 * this transaction and fail if thansfers do not follow
	 * the pattern. */

	t = list_entry(&m->transfers, struct spi_transfer, transfer_list);
next_transaction:
	rbuf = NULL;
	speed_hz = 0;
	reg_i = 0;
	buf_i = 0;
	buf_write = 0;
	delay_usecs = 0;
	cmd = 0;
	list_for_each_entry_continue(t, &m->transfers, transfer_list) {
		unsigned int len = t->len;

		last = (t->transfer_list.next == &m->transfers);
		if (t->speed_hz && (speed_hz == 0 || t->speed_hz < speed_hz))
			speed_hz = t->speed_hz;

		if (t->tx_buf) {
			unsigned long tx_i = 0;
			const char *tbuf = t->tx_buf;

			if (unlikely(buf_i && !buf_write)) {
				dev_err(dev, "write-read-write sequence\n");
				ret = -EIO;
				goto out_unlock;
			}
			if (unlikely(len > BUF_BYTES - buf_i +
						REG_BYTES - reg_i)) {
				dev_err(dev, "write size is too big: "
					"%ld bytes\n", len + reg_i + buf_i);
				ret = -EIO;
				goto out_unlock;
			}
			if (len > REG_BYTES - reg_i) {
				buf_write = 1;
				rbuf = NULL;
			}
			while (tx_i < len && reg_i < REG_BYTES)
				reg[reg_i++] = tbuf[tx_i++];
			while (tx_i < len && buf_i < BUF_BYTES)
				buf[buf_i++] = tbuf[tx_i++];
		}

		if (t->rx_buf) {
			if (unlikely(!reg_i)) {
				dev_err(dev, "sequence starts with a read\n");
				ret = -EIO;
				goto out_unlock;
			}
			if (unlikely(buf_i && buf_write)) {
				dev_err(dev, "write more than 5 bytes - read "
						"sequence\n");
				ret = -EIO;
				goto out_unlock;
			}
			if (unlikely(buf_i)) {
				dev_err(dev, "read-read sequence\n");
				ret = -EIO;
				goto out_unlock;
			}
			if (unlikely(len > BUF_BYTES - buf_i)) {
				dev_err(dev, "read size is too big: "
						"%ld bytes\n", len + buf_i);
				ret = -EIO;
				goto out_unlock;
			}
			buf_write = 0;
			rbuf = t->rx_buf;
			buf_i += len;
		}

		if (last || t->cs_change) {
			/* If this is the last trnasfer we'll ignore the flag.
			 * And if this is not the last transfer, we must
			 * deselect chip after it is done. Either way,
			 * the transaction has been formed. */
			delay_usecs = t->delay_usecs;
			break;
		} else if (unlikely(t->delay_usecs)) {
			dev_err(dev, "delay in the middle of transaction "
					"will be ignored\n");
		}
	}

	/* Change bus speed or mode if requested. */
	ret = l_spi_set_mode_and_freq(spi, spi->mode, speed_hz);
	if (ret)
		goto out_unlock;

	/* Now prepare control register and start the transaction */
	BUG_ON(!reg_i);

	dev_dbg(dev, "writing first %ld byte(s) from "
			"\"0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx 0x%02hhx\", "
			"%s %ld byte(s) %s buffer, device %d\n",
			reg_i, reg[0], reg[1], reg[2], reg[3], reg[4],
			buf_write ? "writing" : "reading", buf_i,
			buf_write ? "to" : "from", spi->chip_select);

	l_spi_write(l_spi, reg[0], L_SPI_OPCODE);

	if (reg_i > 1) {
		u32 addr = 0;
		cmd |= L_SPI_ADDRESS_PHASE_ENABLE;
		switch (reg_i - 1) {
		case 1:
			addr = reg[1];
			cmd |= L_SPI_ADDRESS_SIZE_8;
			break;
		case 2:
			addr = (reg[1] << 8) | reg[2];
			cmd |= L_SPI_ADDRESS_SIZE_16;
			break;
		case 3:
			addr = (reg[1] << 16) | (reg[2] << 8) | reg[3];
			cmd |= L_SPI_ADDRESS_SIZE_24;
			break;
		case 4:
			/* This is the correct order for 32 bit address. */
			addr = (reg[1] << 16) | (reg[2] << 8) |
					reg[3] | (reg[4] << 24);
			cmd |= L_SPI_ADDRESS_SIZE_32;
			break;
		}
		l_spi_write(l_spi, addr, L_SPI_ADDRESS);
	} else {
		cmd |= L_SPI_ADDRESS_PHASE_DISABLE;
	}

	if (buf_i) {
		u32 data_size = (buf_i == 64) ? 0 : buf_i;
		cmd |= L_SPI_DATA_PHASE_ENABLE |
				(data_size << L_SPI_DATA_SIZE_SHIFT);
	} else {
		cmd |= L_SPI_DATA_PHASE_DISABLE;
	}

	cmd |= buf_write ? L_SPI_TRANS_WRITE : L_SPI_TRANS_READ;
	cmd |= spi->chip_select << L_SPI_DEVICE_SHIFT;
	cmd |= L_SPI_START;

	if (buf_i) {
		/* Lock i2c_spi if we are going to use the common buffer
		 * which may be in use by I2C devices (other SPI devices
		 * are synchronized with by using l_spi->lock). */
		spin_lock(&i2c_spi_lock);

		if (buf_write)
			/* Prepare data to be sent */
			memcpy_toio(l_spi->data, buf, buf_i);
	}

	l_spi_write(l_spi, cmd, L_SPI_CONTROL);

	status = l_spi_wait_completion(l_spi);

	if (buf_i) {
		/* Receive data */
		if (!buf_write) {
#ifdef DEBUG
			int i;
#endif
			memcpy_fromio(rbuf, l_spi->data, buf_i);
#ifdef DEBUG
			dev_dbg(dev, "read data:");
			for (i = 0; i < buf_i; i++)
				pr_debug(" %02hhx", rbuf[i]);
			pr_debug("\n");
#endif
		}

		spin_unlock(&i2c_spi_lock);
	}

	if (status & L_SPI_STATUS_FAIL) {
		dev_err(dev, "write operation failed\n");
		ret = -EIO;
		goto out_unlock;
	}

	m->actual_length += reg_i + buf_i;
	if (delay_usecs)
		udelay(delay_usecs);

	if (!last)
		/* More transactions to do */
		goto next_transaction;

out_unlock:
	spin_unlock_irqrestore(&l_spi->lock, flags);

	dev_dbg(dev, "spi_transfer: status %d\n", ret);

	m->status = ret;
	m->complete(m->context);

	return ret;
}

static int l_spi_setup(struct spi_device *spi)
{
	struct l_spi *l_spi = spi_master_get_devdata(spi->master);
	struct device *dev = l_spi->dev;

	/* Sanity checks */

	dev_dbg(dev, "%s setup\n", spi->modalias);

	if (spi->mode != SPI_MODE_0 && spi->mode != SPI_MODE_3) {
		dev_err(dev, "mode %d is not supported\n", spi->mode);
		return -EINVAL;
	}

	if (spi->bits_per_word != 8) {
		dev_err(dev, "bits_per_word %d is not supported\n",
				spi->bits_per_word);
		return -EINVAL;
	}

	if (spi->max_speed_hz < l_spi->baseclk / 16) {
		dev_err(dev, "requested bus speed %d is not supported\n",
				spi->max_speed_hz);
		return -EINVAL;
	}

	/* Set SPI speed and mode */

	return l_spi_set_mode_and_freq(spi, spi->mode, spi->max_speed_hz);
}

static void l_spi_cleanup(struct spi_device *spi)
{
	struct l_spi *l_spi = spi_master_get_devdata(spi->master);
	struct device *dev = l_spi->dev;

	dev_dbg(dev, "%s cleanup\n", spi->modalias);
}

static int l_spi_probe(struct platform_device *pdev)
{
	int ret;
	struct spi_master *master;
	struct l_spi *l_spi;
	u32 mode;
	int freq_changed;

	master = spi_alloc_master(&pdev->dev, sizeof(struct l_spi));
	if (!master)
		return -ENOMEM;

	l_spi = spi_master_get_devdata(master);
	platform_set_drvdata(pdev, l_spi);

	/* init l_spi */
	spin_lock_init(&l_spi->lock);
	l_spi->baseclk = 100 * 1024 * 1024; /* 100 MHz */
	l_spi->master = master;
	l_spi->dev = &pdev->dev;
	l_spi->cntrl = i2c_spi[0].cntrl_base;
	l_spi->data = i2c_spi[0].data_base;

	/* Bus number will be the same as id of the spi controller device */
	master->bus_num = pdev->id;

	master->num_chipselect = L_SPI_MAX_DEVICES;

	/* the spi->mode bits understood by this driver: */
	master->mode_bits = SPI_CPOL | SPI_CPHA;

	master->setup = l_spi_setup;
	master->transfer = l_spi_transfer;
	master->cleanup = l_spi_cleanup;

	/* Full duplex is not supported */
	master->flags = SPI_MASTER_HALF_DUPLEX;

	/* Wait for controller */
	l_spi_wait_busy(l_spi);

	/* Initialize SPI speed and mode */
	/* NOTE: we are not working around hardware bug when SPI bus
	 * has 50 MHz speed after reset althouth SPI_MODE register
	 * is set to 12.5 MHz since it's being worked around by boot. */
	mode = l_spi_read(l_spi, L_SPI_MODE);
	if (mode & L_SPI_FREQ_CHANGED)
		/* Reset 'freq' field if it was set */
		l_spi_write(l_spi, mode, L_SPI_MODE);
	mode &= ~L_SPI_FREQ_CHANGED;
	mode = (mode & ~L_SPI_MODE_MASK) | L_SPI_MODE_0;
	l_spi->mode = SPI_MODE_0;
	freq_changed = ((mode & L_SPI_DIVIDER_MASK) != L_SPI_DIVIDER_8);
	mode = (mode & ~L_SPI_DIVIDER_MASK) | L_SPI_DIVIDER_8;
	l_spi->speed_hz_min = l_spi->baseclk / 8;
	l_spi->speed_hz_max = l_spi->baseclk / 4;
	l_spi_write(l_spi, mode, L_SPI_MODE);

	if (freq_changed)
		l_spi_wait_freq(l_spi);

	ret = spi_register_master(master);
	if (ret < 0) {
		dev_err(&pdev->dev, "spi_register_master error.\n");
		goto error;
	}

	dev_info(&pdev->dev, "probed\n");

	return 0;

error:
	spi_master_put(master);

	dev_info(&pdev->dev, "probed with errors (%d)\n", ret);

	return ret;
}

static int l_spi_remove(struct platform_device *pdev)
{
	struct l_spi *l_spi = dev_get_drvdata(&pdev->dev);

	spi_unregister_master(l_spi->master);

	return 0;
}

static struct platform_driver l_spi_driver = {
	.driver = {
		.name	= "l_spi",
		.owner	= THIS_MODULE,
	},
	.probe	= l_spi_probe,
	.remove	= l_spi_remove
};

__init
int l_spi_init(void)
{
	return platform_driver_register(&l_spi_driver);
}
module_init(l_spi_init);

__exit
void l_spi_exit(void)
{
	platform_driver_unregister(&l_spi_driver);
}
module_exit(l_spi_exit);

MODULE_AUTHOR("Alexander Fyodorov");
MODULE_DESCRIPTION("Elbrus SPI controller driver");
MODULE_LICENSE("GPL");
