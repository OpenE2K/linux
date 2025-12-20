/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_hw.c - MXGBE module device driver
 *
 * Hardware part
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_txq.h"
#include "mxgbe_rxq.h"
#include "mxgbe_mac.h"
#include "mxgbe_i2c.h"
#include "mxgbe_phy.h"
#include "mxgbe_gpio.h"

#include "mxgbe_hw.h"


/**
 * ch1.5 - Reset (HW)
 */

/* PRST_CST regiter bits */
#define PRST_CST_SETRST		SET_BIT(31)	/* [31] - set rst */
#define PRST_CST_STATRST	SET_BIT(30)	/* [30] - rst state */
#define PRST_DIS_STB_CLK	SET_BIT(29)	/* [29] - standby clk disable */
#define PRST_DMAERR		0X00700000	/* [22:20] - DMA err */
#define PRST_SIGNS		0X000FFC00	/* [19:10] - wr/rd_signs */
#define PRST_ZEROS		0X000003FF	/* [09:00] - wr/rd_zeros */
#define PRST_ZEROS_SIGNS_ERR	(PRST_ZEROS | PRST_SIGNS | PRST_DMAERR)


/**
 ******************************************************************************
 * COMMON
 ******************************************************************************
 **/

inline u32 mxgbe_rreg32(void __iomem *base, u32 port)
{
	return readl(base + port);
}

inline void mxgbe_wreg32(void __iomem *base, u32 port, u32 val)
{
	writel(val, base + port);
}

/* Read counter register */
u64 mxgbe_rreg64c(void __iomem *base, u32 port)
{
	u32 h1, l2, h3;

	do {
		h1 = readl(base + port + 4);
		l2 = readl(base + port);
		h3 = readl(base + port + 4);
	} while (h1 != h3);

	return ((u64)h3 << 32) | l2;
} /* mxgbe_rreg64c */

#ifndef writeq
#define writeq writeq
static inline void writeq(u64 val, void __iomem *addr)
{
	writel((u32)val, addr);
	writel((u32)(val >> 32), addr + 4);
}
#endif

inline void mxgbe_wreg64(void __iomem *base, u32 port, u64 val)
{
#ifdef __e2k__
	__raw_writeq(val, base + port);
#else
	writeq(val, base + port);
#endif
} /* mxgbe_wreg64 */


/**
 ******************************************************************************
 * Init
 ******************************************************************************
 */

/**
 * Full hardware restart (~60ms) & start autoread MAC
 */
int mxgbe_hw_reset(mxgbe_priv_t *priv)
{
	int err = 0;
	u32 val;
	void __iomem *base = priv->bar0_base;
	unsigned long timestart;

	val = mxgbe_rreg32(base, PRST_CST);
	if ((val & PRST_CST_SETRST) || !(val & PRST_CST_STATRST)) {
		dev_err(&priv->pdev->dev,
			"ERROR: HW Reset not started\n");
		err = -EAGAIN;
		goto err_reset;
	}
	if ((val & (PRST_DMAERR | PRST_SIGNS)) || (~val & PRST_ZEROS)) {
		dev_info(&priv->pdev->dev,
			"HW Reset start, PRST_CST=0x%08X\n", val);
	}

	/* Start reset */
	mxgbe_wreg32(base, PRST_CST, PRST_CST_SETRST);

	/* wait for bit 31 */
	timestart = jiffies;
	do {
		val = mxgbe_rreg32(base, PRST_CST);
		if (time_after(jiffies, timestart + HZ)) {
			err = -EAGAIN;
			goto err_reset;
		}
	} while (val & PRST_CST_SETRST);

	/* wait for bit 30 */
	timestart = jiffies;
	do {
		val = mxgbe_rreg32(base, PRST_CST);
		if (time_after(jiffies, timestart + HZ)) {
			err = -EAGAIN;
			goto err_reset;
		}
	} while (!(val & PRST_CST_STATRST));

	/* R2000+ proto */
	mxgbe_wreg32(base, PRST_CST, PRST_DIS_STB_CLK);

	val = mxgbe_rreg32(base, PRST_CST);
	dev_info(&priv->pdev->dev,
		 "HW Reset done, PRST_CST=0x%08X\n", val);

	return 0;

err_reset:
	dev_err(&priv->pdev->dev,
		"ERROR: HW Reset not done, PRST_CST=0x%08X\n", val);
	return err;
} /* mxgbe_hw_reset */


/**
 * Read info from hardware
 */
int mxgbe_hw_getinfo(mxgbe_priv_t *priv)
{
	u32 val;
	u8 byte;
	void __iomem *base = priv->bar0_base;
	struct pci_dev *pdev = priv->pdev;

	assert(base);
	assert(pdev);

	/* PCI Config Space */
	pci_read_config_byte(pdev, PCI_REVISION_ID, &byte);
	if (MXGBE_REVISION_ID_BOARD == byte) {
		priv->revision = MXGBE_REVISION_ID_BOARD;
		priv->pcsaddr = 0;
		dev_info(&priv->pdev->dev,
			 "revision id = %d: PCIe board\n", byte);
	} else if (MXGBE_REVISION_ID_E16C_R2000P == byte) {
		priv->revision = MXGBE_REVISION_ID_E16C_R2000P;
		priv->pcsaddr = 1;
		dev_info(&priv->pdev->dev,
#ifdef __e2k__
			 "revision id = %d: E16C\n", byte);
#else /* sparc */
			 "revision id = %d: R2000+\n", byte);
#endif
	} else {
		dev_info(&priv->pdev->dev,
			 "revision id = %d: unknown\n", byte);
		return -ENODEV;
	}

	val = mxgbe_rreg32(base, TX_BUFSIZE);
	priv->hw_tx_bufsize = (unsigned int)val;
	val = mxgbe_rreg32(base, RX_BUFSIZE);
	priv->hw_rx_bufsize = (unsigned int)val;

	return 0;
} /* mxgbe_hw_getinfo */


/**
 * First Init at start of probe
 */
int mxgbe_hw_init(mxgbe_priv_t *priv)
{
	int err = 0;

	/* Init GPIO */
	mxgbe_gpio_init(priv);

	/* PHY */
	mxgbe_mdio_reset(priv);

	/* Init MAC (ch2.pdf) */
	mxgbe_mac_init(priv);

	/* Init TX (ch3.pdf) */
	mxgbe_tx_init(priv);
	/* Init TXQ (ch3.pdf) */
	err = mxgbe_txq_init_all(priv);
	if (0 != err) {
		dev_err(&priv->pdev->dev, "ERROR: TX Q_CTRL_RESET == 1\n");
		goto out_err;
	}

	/* Init RX (ch4.pdf) */
	mxgbe_rx_init(priv);
	/* Init RXQ (ch4.pdf) */
	err = mxgbe_rxq_init_all(priv);
	if (0 != err) {
		dev_err(&priv->pdev->dev, "ERROR: RX Q_CTRL_RESET == 1\n");
		goto out_err;
	}

	return 0;
out_err:
	return err;
} /* mxgbe_hw_init */


/**
 * Last Init at end of probe
 */
void mxgbe_hw_start(mxgbe_priv_t *priv)
{
	unsigned int qn;

	/* Start MAC */
	mxgbe_mac_start(priv);

	/* Start all TX Queue */
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_txq_start(priv, qn);
	}
	/* Start all RX Queue -- move to Net */
} /* mxgbe_hw_start */
