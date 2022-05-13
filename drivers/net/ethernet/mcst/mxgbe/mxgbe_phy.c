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
#define	MDIO_REG_AD_OFF		18	/* [22:18] = phy reg num */
#define	MDIO_PHY_AD_OFF		23	/* [27:23] = phy id */
#define	MDIO_OP_CODE_OFF	28	/* [29:28] = 1-W, 2-R */
#define	MDIO_ST_OF_F_OFF	30	/* [31:30] = 1 */
#define MDIO_DATA_OPCODE_ADDR	0x0
#define MDIO_DATA_OPCODE_WR	0x1
#define MDIO_DATA_OPCODE_RD	0x3
#define MDIO_DATA_OPCODE_RDINC	0x2


/* VSC8488 - external phy on PCIe board */


#define PCS_DEV_ID_1G_2G5	0x7996CED0
#define PCS_DEV_ID_1G_2G5_10G	0x7996CED1

/** Internal PCS */
#define PMA_and_PMD_MMD	(0x1 << 18)
#define PCS_MMD		(0x3 << 18)
#define AN_MMD		(0x7 << 18)
#define VS_MMD1		(0x1e << 18)
#define VS_MII_MMD	(0x1f << 18)

#define SR_XS_PCS_CTRL1		(0x0000 | PCS_MMD)
#define SR_XS_PCS_DEV_ID1	(0x0002 | PCS_MMD)
#define SR_XS_PCS_DEV_ID2	(0x0003 | PCS_MMD)
#define SR_XS_PCS_CTRL2		(0x0007 | PCS_MMD)
#define VR_XS_PCS_DIG_CTRL1	(0x8000 | PCS_MMD)
#define VR_XS_PCS_DIG_CTRL2	(0x8001 | PCS_MMD)

#define SR_MII_CTRL		(0x0000 | VS_MII_MMD)
#define VR_MII_AN_CTRL		(0x8001 | VS_MII_MMD)
#define SR_MII_AN_ADV		(0x0004 | VS_MII_MMD)
#define VR_MII_DIG_CTRL1	(0x8000 | VS_MII_MMD)
#define VR_MII_AN_INTR_STS	(0x8002 | VS_MII_MMD)
#define VR_MII_LINK_TIMER_CTRL	(0x800a | VS_MII_MMD)

#define SR_VSMMD_CTRL		(0x0009 | VS_MMD1)

#define VR_AN_INTR		(0x8002 | AN_MMD)
#define SR_AN_CTRL		(0x0000 | AN_MMD)
#define SR_AN_LP_ABL1		(0x0013 | AN_MMD)
#define SR_AN_LP_ABL2		(0x0014 | AN_MMD)
#define SR_AN_LP_ABL3		(0x0015 | AN_MMD)
#define SR_AN_XNP_TX1		(0x0016 | AN_MMD)
#define SR_AN_XNP_TX2		(0x0017 | AN_MMD)
#define SR_AN_XNP_TX3		(0x0018 | AN_MMD)

#define SR_PMA_KR_PMD_CTRL	(0x0096 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL	(0x8070 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0	(0x8071 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLA_CTRL1		(0x8072 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2	(0x8073 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0	(0x8074 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLB_CTRL1		(0x8075 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2	(0x8076 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLA_CTRL3		(0x8077 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLB_CTRL3		(0x8078 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1	(0x8031 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2	(0x8032 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL	(0x8033 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL	(0x8034 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0	(0x8036 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1	(0x8037 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2	(0x8052 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3	(0x8053 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL	(0x8054 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL	(0x8056 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL	(0x8057 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0		(0x8058 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4	(0x805C | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL	(0x805D | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0	(0x8090 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL	(0x8091 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0	(0x8092 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_VCO_CAL_REF0		(0x8096 | PMA_and_PMD_MMD)

#define SR_XS_PCS_KR_STS2	 (0x0021 | PCS_MMD)
#define VR_XS_PCS_DIG_STS	 (0x8010 | PCS_MMD)


/**
 ******************************************************************************
 * MDIO
 ******************************************************************************
 */

static int mdio_io(void __iomem *base, u32 dat)
{
	u32 val;
	unsigned long timestart;

	mxgbe_wreg32(base, MDIO_DATA, dat);

	/* wait for Read done */
	timestart = jiffies;
	do {
		if (time_after(jiffies, timestart + HZ))
			return -EAGAIN;

		val = mxgbe_rreg32(base, MDIO_CSR);
	} while (!(val & MDIO_CSR_RRDY));

	return 0;
} /* mdio_io */

/* mii_bus->read wrapper for read PHYs */
static int mdio_read(struct mii_bus *bus, int phy_id, int reg_num)
{
	u32 val;
	u16 val_out;
	mxgbe_priv_t *priv = bus->priv;
	void __iomem *base = priv->bar0_base;
	unsigned long flags;

	if (!base)
		return -ENODEV;

	raw_spin_lock_irqsave(&priv->mgio_lock, flags);

	/* Write Address */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_ADDR << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= reg_num & (0x1F << MDIO_REG_AD_OFF);
	val |= reg_num & 0xFFFF;
	if (mdio_io(base, val) != 0) {
		raw_spin_unlock_irqrestore(&priv->mgio_lock, flags);
		dev_err(&priv->pdev->dev, "Unable to write MDIO addr\n");
		return -EAGAIN;
	}

	/* Read Data */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_RD << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= reg_num & (0x1F << MDIO_REG_AD_OFF);
	if (mdio_io(base, val) != 0) {
		raw_spin_unlock_irqrestore(&priv->mgio_lock, flags);
		dev_err(&priv->pdev->dev, "Unable to read MDIO data\n");
		return -EAGAIN;
	}

	val_out = (u16)(mxgbe_rreg32(base, MDIO_DATA) & 0xFFFF);

	raw_spin_unlock_irqrestore(&priv->mgio_lock, flags);

	DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
		"mdio_read: dev 0x%02X - reg 0x%04X = 0x%04X\n",
		(reg_num >> MDIO_REG_AD_OFF) & 0x1F, reg_num & 0xFFFF, val_out);

	return (int)val_out;
} /* mdio_read */

/* mii_bus->write wrapper for write PHYs */
static int mdio_write(struct mii_bus *bus, int phy_id, int reg_num, u16 val_in)
{
	u32 val;
	mxgbe_priv_t *priv = bus->priv;
	void __iomem *base = priv->bar0_base;
	unsigned long flags;

	if (!base)
		return -ENODEV;

	raw_spin_lock_irqsave(&priv->mgio_lock, flags);

	/* Write Address */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_ADDR << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= reg_num & (0x1F << MDIO_REG_AD_OFF);
	val |= reg_num & 0xFFFF;
	if (mdio_io(base, val) != 0) {
		raw_spin_unlock_irqrestore(&priv->mgio_lock, flags);
		dev_err(&priv->pdev->dev, "Unable to write MDIO addr\n");
		return -EAGAIN;
	}

	/* Write Data */
	val = 0;
	val |= 0x2 << MDIO_CS_OFF; /* const */
	val |= 0x0 << MDIO_ST_OF_F_OFF; /* const */
	val |= MDIO_DATA_OPCODE_WR << MDIO_OP_CODE_OFF;
	val |= (phy_id & 0x1F) << MDIO_PHY_AD_OFF;
	val |= reg_num & (0x1F << MDIO_REG_AD_OFF);
	val |= val_in & 0xFFFF;
	if (mdio_io(base, val) != 0) {
		raw_spin_unlock_irqrestore(&priv->mgio_lock, flags);
		dev_err(&priv->pdev->dev, "Unable to write MDIO data\n");
		return -EAGAIN;
	}

	raw_spin_unlock_irqrestore(&priv->mgio_lock, flags);

	DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
		"mdio_write: dev 0x%02X - reg 0x%04X := 0x%04X\n",
		(reg_num >> MDIO_REG_AD_OFF) & 0x1F, reg_num & 0xFFFF, val_in);

	return 0;
} /* mdio_write */

/* PCS Register read/write functions */
static u16 mxgbe_pcs_read(mxgbe_priv_t *priv, int regnum)
{
	return (u16)mdio_read(priv->mii_bus, priv->pcsaddr, regnum);
}

static void mxgbe_pcs_write(mxgbe_priv_t *priv, int regnum, u16 value)
{
	mdio_write(priv->mii_bus, priv->pcsaddr, regnum, value);
}


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
} /* mxgbe_mdio_reset */

/* called from init_board() */
int mxgbe_mdio_register(mxgbe_priv_t *priv)
{
	struct pci_dev *pdev = priv->pdev;
	struct mii_bus *new_bus;
	struct device_node *np = dev_of_node(&pdev->dev);
	int ret;

	new_bus = devm_mdiobus_alloc(&pdev->dev);
	if (!new_bus) {
		dev_err(&pdev->dev,
			"Error on devm_mdiobus_alloc\n");
		return -ENOMEM;
	}

	new_bus->name = KBUILD_MODNAME" mdio";
	new_bus->priv = priv;
	new_bus->parent = &pdev->dev;
	new_bus->irq[0] = PHY_IGNORE_INTERRUPT;
	snprintf(new_bus->id, MII_BUS_ID_SIZE, KBUILD_MODNAME"-%x",
		 PCI_DEVID(pdev->bus->number, pdev->devfn));

	new_bus->read = mdio_read;
	new_bus->write = mdio_write;

	if (np) {
		struct device_node *mdio_node;

		mdio_node = of_get_child_by_name(np, "mdio");
		ret = of_mdiobus_register(new_bus, mdio_node);
		of_node_put(mdio_node);
	} else {
		ret = mdiobus_register(new_bus);
	}
	if (ret) {
		dev_err(&pdev->dev,
			"Error on mdiobus_register\n");
		return ret;
	}
	priv->mii_bus = new_bus;
	dev_info(&pdev->dev, "register mdiobus %s\n", new_bus->id);

	return 0;
} /* mxgbe_mdio_register */


/**
 ******************************************************************************
 * Internal PCS
 ******************************************************************************
 */

static void mxgbe_pcs_first_init(mxgbe_priv_t *priv)
{
	int i;
	u16 val;

	/* PCS Reset */
	val = mxgbe_pcs_read(priv, SR_XS_PCS_CTRL1);
	mxgbe_pcs_write(priv, SR_XS_PCS_CTRL1, val | (1 << 15)); /* RST */
	val = mxgbe_pcs_read(priv, SR_XS_PCS_CTRL1);
	/* Wait RST (SR_XS_PCS_CTRL1) to 1'h0 */
	for (i = 0; i <= 500; i++) {
		if ((mxgbe_pcs_read(priv, SR_XS_PCS_CTRL1) & 0x8000) == 0)
			break;
		udelay(1);
	}
	if (i >= 500)
		dev_warn(&priv->pdev->dev,
			 "could not reset pcs at first init\n");

	/* Disable Clause 73 Auto-Negotiation */
	/* RSTRT_AN to 1'h0 / LPM to 1'h0 / AN_EN to 1'h0
	 * EXT_NP_CTL to 1'h1 / AN_RST to 1'h0 */
	/*
	mxgbe_pcs_write(priv, SR_AN_CTRL, 0x2000);
	*/

	/* Disable Clause 72 Auto-Negotiation */
	/* RS_TR to 1'h0 / TR_EN to 1'h1 */
	/*
	mxgbe_pcs_write(priv, SR_PMA_KR_PMD_CTRL, 0x0002);
	*/

	mxgbe_pcs_write(priv, VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0, 0x77CA);
	mxgbe_pcs_write(priv, VR_XS_PMA_Gen5_12G_MPLLA_CTRL3, 0x0004);

#if 1
	/* Soft Reset */
	val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1);
	mxgbe_pcs_write(priv, VR_XS_PCS_DIG_CTRL1, val | (1 << 15)); /* VR_RST */
	val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1);
	i = 0;
	while ((val & (1 << 15)) && (i < 10)) {
		DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
			"wait for PCSDIG reset: dev.reg 0x%02X.%04X = 0x%04X\n",
			VR_XS_PCS_DIG_CTRL1 >> 16,
			VR_XS_PCS_DIG_CTRL1 & 0xFFFF, val);
		val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1);
		i++;
	};

	/* SAPFIR1:
	 * Proto: Error on PCB (Bug 115092 #8)
	 * Reg: 0x038001 - VR_XS_PCS_DIG_CTRL2
	 * set bit [04:04] TX_POL_INV_0 --> 1
	 */
#if 0
	val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL2);
	mxgbe_pcs_write(priv, VR_XS_PCS_DIG_CTRL2, val | (1 << 4)); /* TX_POL_INV_0 */
#endif

	/* INIT */
	val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1);
	mxgbe_pcs_write(priv, VR_XS_PCS_DIG_CTRL1, val | (1 << 8)); /* INIT */
	val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1);
	i = 0;
	while ((val & (1 << 8)) && (i < 10)) {
		DEV_DBG(MXGBE_DBG_MSK_PHY, &priv->pdev->dev,
			"wait for INIT done: dev.reg 0x%02X.%04X = 0x%04X\n",
			VR_XS_PCS_DIG_CTRL1 >> 16,
			VR_XS_PCS_DIG_CTRL1 & 0xFFFF, val);
		val = mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1);
		i++;
	};
#endif
} /* mxgbe_pcs_first_init */

/* Initiate the Vendor specific software reset */
/* reset for both controllers are configured via func 0 */
#if 0
static int mxgbe_pcs_vs_reset(mxgbe_priv_t *priv)
{
	int i;

	/* EN_VSMMD1, VR_RST */
	mxgbe_pcs_write(priv, VR_XS_PCS_DIG_CTRL1, 0xa000);
	for (i = 0; i < 500; i++) {
		if ((mxgbe_pcs_read(priv, VR_XS_PCS_DIG_CTRL1) &
			0x8000) == 0) {
			break;
		}
		udelay(1);
	}
	if (i ==  500) {
		dev_warn(&priv->pdev->dev, "Could not reset phy\n");
		return 1;
	}
	dev_dbg(&priv->pdev->dev, "phy reset done\n");

	return 0;
} /* mxgbe_pcs_vs_reset */
#endif

/* Programming Guidelines for Clause 73 Auto-Negotiation */
static int mxgbe_set_pcs_an_clause_73(mxgbe_priv_t *priv)
{
	int i;
	int r;

	if (netif_msg_hw(priv))
		dev_info(&priv->ndev->dev, "%s\n", __func__);

	for (i = 0; i < 500; i++) {
		r = mxgbe_pcs_read(priv, VR_AN_INTR);
		if (r & 0x7) { /* AN_INT_CMPLT | AN_INC_LINK | AN_PG_RCV */
			break;
		}
	}
	if (i == 500) {
		dev_warn(&priv->ndev->dev,
			 "could not set autonegotiation mode\n");
		return 1;
	}

	if (r & 0x1) { /* AN_INT_CMPLT */
	/* Ready */
		return 0;
	}

	if ((r & 0x4) == 0) { /* AN_PG_RCV == 0 */
		goto wait_an_int_cmplt;
	}
	r &= ~0x4; /* AN_PG_RCV = 0 */
	mxgbe_pcs_write(priv, VR_AN_INTR, r);
	(void)mxgbe_pcs_read(priv, SR_AN_LP_ABL1);
	(void)mxgbe_pcs_read(priv, SR_AN_LP_ABL2);
	(void)mxgbe_pcs_read(priv, SR_AN_LP_ABL3);

	r = mxgbe_pcs_read(priv, SR_AN_LP_ABL1);
	if ((r & 0x800) == 0) { /* AN_LP_ADV_NP == 0 */
		goto wait_an_int_cmplt;
	}

	for (i = 0; i < 500; i++) {
		int j;
		mxgbe_pcs_write(priv, SR_AN_XNP_TX3, 0);
		mxgbe_pcs_write(priv, SR_AN_XNP_TX2, 0);
		mxgbe_pcs_write(priv, SR_AN_XNP_TX1, 0);
		for (j = 0; j < 500; j++) {
			if (mxgbe_pcs_read(priv, VR_AN_INTR) & 0x4) {
				break;
			}
		}
		if (j == 500) {
			return 1;
		}
		r = mxgbe_pcs_read(priv, VR_AN_INTR);
		mxgbe_pcs_write(priv, VR_AN_INTR, r & ~0x4);/*AN_PG_RCV=0*/
		(void)mxgbe_pcs_read(priv, SR_AN_LP_ABL1);
		(void)mxgbe_pcs_read(priv, SR_AN_LP_ABL2);
		(void)mxgbe_pcs_read(priv, SR_AN_LP_ABL3);
		r = mxgbe_pcs_read(priv, SR_AN_LP_ABL1);
		if ((r & 0x800) == 0) { /* AN_LP_ADV_NP == 0 */
			break;
		}
	}
	if (i == 500) {
		return 1;
	}
wait_an_int_cmplt:
	for (i = 0; i < 500; i++) {
		r = mxgbe_pcs_read(priv, VR_AN_INTR);
		if (r & 0x1) { /* AN_INT_CMPLT */
			break;
		}
	}
	if (i == 500) {
		return 1;
	}
	return 0;
} /* mxgbe_set_pcs_an_clause_73 */

/* init internal PCS/PMA phy */
int mxgbe_set_pcsphy_mode(struct net_device *ndev)
{
	u32 val;
	mxgbe_priv_t *priv = netdev_priv(ndev);

	val = mdio_read(priv->mii_bus, priv->pcsaddr, SR_XS_PCS_DEV_ID1);
	val <<= 16;
	val |= mdio_read(priv->mii_bus, priv->pcsaddr, SR_XS_PCS_DEV_ID2);
	priv->pcs_dev_id = val;
	dev_info(&priv->pdev->dev,
		 "pcs[%d] phy id: 0x%08X - %s\n",
		 priv->pcsaddr, priv->pcs_dev_id,
		 (priv->pcs_dev_id == PCS_DEV_ID_1G_2G5_10G) ? "10G" :
		 (priv->pcs_dev_id == PCS_DEV_ID_1G_2G5) ? "1G/2.5G" :
			"unknown");

	/*if (mxgbe_pcs_vs_reset(priv))
		return 1;*/

	mxgbe_pcs_first_init(priv);

	mxgbe_set_pcs_an_clause_73(priv);

	return 0;
} /* mxgbe_set_pcsphy_mode */
