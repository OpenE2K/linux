/**
 * mxgbe_phy.c - MXGBE module device driver
 *
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "mxgbe_gpio.h"

#include "mxgbe_phy.h"


/**
 * ch2.4 - MDIO (PHY)
 */

/* MDIO_CSR regiter bits */
#define MDIO_CSR_RRDY		SET_BIT(13)	/* RC RESULT READY */
#define MDIO_CSR_PHY_RSTHI	SET_BIT(6)	/* Reset act Hi */
#define MDIO_CSR_PHY_RESET	SET_BIT(2)	/* Soft Reset */
/* MDIO_DATA registers bits */
#define	MDIO_DATA_OFF		0	/* [15:00] = data */
#define	MDIO_CS_OFF		16	/* [17:16] = 2 */
#define	MDIO_REG_AD_OFF		18	/* [22:18] = phy reg num  */
#define	MDIO_PHY_AD_OFF		23	/* [27:23] = phy id */
#define	MDIO_OP_CODE_OFF	28	/* [29:28] = 1-W, 2-R */
#define	MDIO_ST_OF_F_OFF	30	/* [31:30] = 1 */
#define MDIO_DATA_OPCODE_ADDR	0x0
#define MDIO_DATA_OPCODE_WR	0x1
#define MDIO_DATA_OPCODE_RD	0x3
#define MDIO_DATA_OPCODE_RDINC	0x2


/* VSC8488 */
#define TMON_AN_DIS	(1 << 14)
#define TMON_ENABLE	(1 << 12)
#define TMON_RUN	(1 << 11)
#define TMON_DONE	(1 << 10)
#define TMON_MASK	(0xFF)


/**
 ******************************************************************************
 * MDIO
 ******************************************************************************
 */

static int mdio_io(mxgbe_priv_t *priv, u32 dat)
{
	u32 val;
	unsigned long timestart;
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	mxgbe_wreg32(base, MDIO_DATA, dat);

	timestart = jiffies;
	/* wait for Read done */
	do {
		if (time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: Unable to read/write MDIO reg\n");
			return -EAGAIN;
		}
		val = mxgbe_rreg32(base, MDIO_CSR);
		DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
			"mdio_io: reg MDIO_CSR = 0x%08X\n", val);
	} while (!(val & MDIO_CSR_RRDY));

	return 0;
} /* mdio_io */


/**
 ******************************************************************************
 * MDIO Interface
 ******************************************************************************
 */

void mxgbe_mdio_reset(mxgbe_priv_t *priv)
{
#ifndef GPIO_RESET_PHY
	void __iomem *base = priv->bar0_base;
#endif /* GPIO_RESET_PHY */

	FDEBUG;

#ifdef GPIO_RESET_PHY
	/* Use GPIO.0 to reset Phy */
	mxgbe_gpio_phy_reset(priv);
#else /* !GPIO_RESET_PHY */
	/* Use MDIO_CSR to reset Phy */
	mxgbe_wreg32(base, MDIO_CSR, MDIO_CSR_PHY_RSTHI | MDIO_CSR_PHY_RESET);
	mdelay(1);
	mxgbe_wreg32(base, MDIO_CSR, MDIO_CSR_PHY_RSTHI | 0);
	mdelay(1);
#endif /* GPIO_RESET_PHY */

	/* Enable Digitel temp monitor */
	mxgbe_mdio_write(priv, 0 /*phy_id*/, MXGBE_PHY_DEV_GLOBAL,
			 MXGBE_PHY_DEVGLB_TEMPMON,
			 TMON_AN_DIS | TMON_ENABLE);
} /* mxgbe_mdio_reset */


int mxgbe_mdio_read(mxgbe_priv_t *priv, int phy_id, int dev, int reg_num)
{
	u32 val;
	u16 val_out;
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	if (!base)
		return -ENODEV;

	/* Write Address */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_ADDR << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= (dev & 0x1F) << MDIO_REG_AD_OFF;
	val |= reg_num & 0xFFFF;
	if (mdio_io(priv, val) != 0)
		return -EAGAIN;

	/* Read Data */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_RD << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= (dev & 0x1F) << MDIO_REG_AD_OFF;
	if (mdio_io(priv, val) != 0)
		return -EAGAIN;

	val_out = (u16)(mxgbe_rreg32(base, MDIO_DATA) & 0xFFFF);
	DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
		"mdio_read: dev 0x%02X - reg 0x%04X = 0x%04X\n",
		dev, reg_num, val_out);

	return (int)val_out;
} /* mxgbe_mdio_read */


int mxgbe_mdio_write(mxgbe_priv_t *priv, int phy_id, int dev, int reg_num,
		     int val_in)
{
	u32 val;
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	if (!base)
		return -ENODEV;

	/* Write Address */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_ADDR << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= (dev & 0x1F) << MDIO_REG_AD_OFF;
	val |= reg_num & 0xFFFF;
	if (mdio_io(priv, val) != 0)
		return -EAGAIN;

	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_WR << MDIO_OP_CODE_OFF;
	val |= (phy_id  & 0x1F) << MDIO_PHY_AD_OFF;
	val |= (dev & 0x1F) << MDIO_REG_AD_OFF;
	val |= val_in & 0xFFFF;
	if (mdio_io(priv, val) != 0)
		return -EAGAIN;

	DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
		"mdio_write: dev 0x%02X - reg 0x%04X := 0x%04X\n",
		dev, reg_num, val_in);

	return 0;
} /* mxgbe_mdio_write */


/**
 ******************************************************************************
 * VSC8488
 ******************************************************************************
 */

int mxgbe_mdio_read_temp(mxgbe_priv_t *priv)
{
	int val;
	unsigned long timestart;

	FDEBUG;

	mxgbe_mdio_write(priv, 0 /*phy_id*/, MXGBE_PHY_DEV_GLOBAL,
			 MXGBE_PHY_DEVGLB_TEMPMON,
			 TMON_AN_DIS | TMON_ENABLE | TMON_RUN);

	timestart = jiffies;
	/* wait for TMON_DONE set (autoclean) */
	do {
		val = mxgbe_mdio_read(priv, 0 /*phy_id*/,
				      MXGBE_PHY_DEV_GLOBAL,
				      MXGBE_PHY_DEVGLB_TEMPMON);
		if (val < -1)
			return val;
		if (time_after(jiffies, timestart + HZ)) {
			return -EAGAIN;
		}
	} while (!(val & TMON_DONE));

	return val & TMON_MASK;
} /* mxgbe_mdio_read_temp */


u32 mxgbe_mdio_get_pma_stat(mxgbe_priv_t *priv)
{
	int val;
	u32 ret;

	FDEBUG;

	val = mxgbe_mdio_read(priv, 0 /*phy_id*/,
			      MXGBE_PHY_DEV_PMD_PMA,
			      MXGBE_PHY_DEVPMA_STATUS1);
	if (val < -1)
		return (u32)-1;
	ret = (u32)(val & 0xFFFF);

	val = mxgbe_mdio_read(priv, 0 /*phy_id*/,
			      MXGBE_PHY_DEV_PMD_PMA,
			      MXGBE_PHY_DEVPMA_STATUS2);
	if (val < -1)
		return (u32)-1;
	ret |= (u32)(val << 16);

	return ret;
} /* mxgbe_mdio_get_pma_stat */
