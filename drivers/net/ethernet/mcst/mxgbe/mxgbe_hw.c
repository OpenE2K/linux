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
	return ioread32(base + port);
}


inline void mxgbe_wreg32(void __iomem *base, u32 port, u32 val)
{
	iowrite32(val, base + port);
} /* mxgbe_wreg32 */


/* Read counter register */
u64 mxgbe_rreg64c(void __iomem *base, u32 port)
{
	u32 h1, l2, h3;

	do {
		h1 = ioread32(base + port + 4);
		l2 = ioread32(base + port);
		h3 = ioread32(base + port + 4);
	} while (h1 != h3);

	return ((u64)h3 << 32) | l2;
} /* mxgbe_rreg64c */


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

	FDEBUG;

	val = mxgbe_rreg32(base, PRST_CST);
	if (val & ~(PRST_CST_STATRST | PRST_ZEROS_SIGNS_ERR)) {
		err = -EAGAIN;
		goto err_reset;
	}

	mxgbe_wreg32(base, PRST_CST, PRST_CST_SETRST);

	timestart = jiffies;
	do {
		val = mxgbe_rreg32(base, PRST_CST);
		if (time_after(jiffies, timestart + HZ)) {
			err = -EAGAIN;
			goto err_reset;
		}
	} while (val & PRST_CST_SETRST);

	timestart = jiffies;
	do {
		val = mxgbe_rreg32(base, PRST_CST);
		if (time_after(jiffies, timestart + HZ)) {
			err = -EAGAIN;
			goto err_reset;
		}
	} while (!(val & PRST_CST_STATRST));

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
	int cpus;
	void __iomem *base = priv->bar0_base;
	struct pci_dev *pdev = priv->pdev;

	FDEBUG;

	assert(base);
	assert(pdev);


	/* PCI Config Space */
	pci_read_config_byte(pdev, PCI_REVISION_ID, &byte);
	if (MXGBE_REVISION_ID != byte)
		return -ENODEV;

	/* read Tx */
	val = mxgbe_rreg32(base, TX_QNUM);
	priv->num_tx_queues = (unsigned int)val;
	val = mxgbe_rreg32(base, TX_BUFSIZE);
	priv->hw_tx_bufsize = (unsigned int)val;

	/* read Rx */
	val = mxgbe_rreg32(base, RX_QNUM);
	priv->num_rx_queues = (unsigned int)val;
	val = mxgbe_rreg32(base, RX_BUFSIZE);
	priv->hw_rx_bufsize = (unsigned int)val;

	cpus = num_online_cpus();

	/* chk Tx */
	if ((priv->num_tx_queues < TXQ_MINNUM) ||
	    (priv->num_tx_queues > TXQ_MAXNUM))
		return -ENODEV;

	priv->num_tx_queues = min_t(int, priv->num_tx_queues, cpus);
	priv->num_tx_queues = min_t(int, priv->num_tx_queues, TX_QNUM_MAX_USE);

	/* chk Rx */
	if ((priv->num_rx_queues < RXQ_MINNUM) ||
	    (priv->num_rx_queues > RXQ_MAXNUM))
		return -ENODEV;

	priv->num_rx_queues = min_t(int, priv->num_rx_queues, cpus);
	priv->num_rx_queues = min_t(int, priv->num_rx_queues, RX_QNUM_MAX_USE);

	return 0;
} /* mxgbe_hw_getinfo */


/**
 * First Init at start of probe
 */
int mxgbe_hw_init(mxgbe_priv_t *priv)
{
	int err = 0;

	FDEBUG;

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

	FDEBUG;

	/* Start MAC */
	mxgbe_mac_start(priv);

	/* Start all TX Queue */
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_txq_start(priv, qn);
	}
	/* Start all RX Queue -- move to Net */
} /* mxgbe_hw_start */
