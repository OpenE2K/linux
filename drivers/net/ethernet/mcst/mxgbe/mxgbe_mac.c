/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_mac.c - MXGBE module device driver
 *
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"

#include "mxgbe_mac.h"


static int mac_kthread(void *arg);


/**
 ******************************************************************************
 * MAC
 ******************************************************************************
 */

/**
 * First Init MAC at start of probe
 */
void mxgbe_mac_init(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;

	/* Init MAC */
	if (mxgbe_loopback_mode) {
		mxgbe_wreg32(base, MAC_LOOPBACK, MAC_LOOPBACK_ON);
	} else {
		mxgbe_wreg32(base, MAC_LOOPBACK, 0);
	}

	mxgbe_wreg32(base, MAC_LINK_CHG, MAC_LINK_EN_ALL | MAC_LINK_REQ_ALL);

	mxgbe_wreg32(base, MAC_RAW, 0);
	mxgbe_wreg32(base, MAC_PAUSE_CTRL, 0);
	mxgbe_wreg32(base, MAC_PAUSE_RXCTRL, 0);
	mxgbe_wreg32(base, MAC_PAUSE_CHG, 0);
	mxgbe_wreg64(base, MAC_PAUSE_MAC, 0);
	mxgbe_wreg32(base, MAC_MAX_RATE, MAC_MAX_RATE_DEF);
	mxgbe_wreg32(base, MAC_MIN_IPG, 0);
	mxgbe_wreg32(base, MAC_MAX_PPS, 0);

	priv->mac_task = NULL;
} /* mxgbe_mac_init */


/**
 * Last Init at end of probe
 */
void mxgbe_mac_start(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;

	mxgbe_wreg64(base, MAC_PAUSE_MAC, (u64 __force)priv->MAC);

	/* Default - Disable pause frame - Bug 98328 */
	mxgbe_wreg32(base, MAC_PAUSE_CTRL, 0);
	/* Enable pause frame - `ethtool -A eth* rx|tx on` */
} /* mxgbe_mac_start */

void mxgbe_mac_event_en(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;

	/* Enable interrupt */
	mxgbe_wreg32(base, MAC_LINK_CHG, MAC_LINK_ENSETBITS | MAC_LINK_EN_ALL);

	/* Start MAC kthread */
	priv->mac_task = kthread_run(mac_kthread, (void *)priv,
			       "%s_mac_thread", priv->ndev->name);
} /* mxgbe_mac_event_en */

void mxgbe_mac_event_dis(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;

	/* Disable interrupt */
	mxgbe_wreg32(base, MAC_LINK_CHG, MAC_LINK_EN_ALL | MAC_LINK_REQ_ALL);

	/* Stop MAC kthread */
	if (priv->mac_task) {
		kthread_stop(priv->mac_task);
		priv->mac_task = NULL;
	}
} /* mxgbe_mac_event_dis */


/**
 ******************************************************************************
 * IRQ
 ******************************************************************************
 */

/**
 * Interrupt handler
 *
 * @irq:	not used (== msix_entries[i].vector == priv->vector[i].irq)
 * @dev_id:	PCI device information struct
 */
irqreturn_t mxgbe_mac_irq_handler(int irq, void *dev_id)
{
	mxgbe_vector_t *vector;
	mxgbe_priv_t *priv;
	void __iomem *base;
	u32 irqst;
	u32 val, stat;

	if (!dev_id)
		return IRQ_NONE;

	vector = (mxgbe_vector_t *)dev_id;
	priv = vector->priv;
	base = priv->bar0_base;

	/* MSIX_IRQST_* value */
	irqst = mxgbe_rreg32(base, MSIX_IRQST_MACBASE);

	if (0 == irqst)
		return IRQ_NONE;

	stat = mxgbe_rreg32(base, MAC_LINK_STAT);

	/* clean request flags */
	val = mxgbe_rreg32(base, MAC_LINK_CHG);
	val &= MAC_LINK_REQ_ALL;
	mxgbe_wreg32(base, MAC_LINK_CHG, val);
	mxgbe_net_mac_irq_handler(priv, stat & (MAC_LINK_REQ_LINKINT |
						MAC_LINK_REQ_REMFAULT |
						MAC_LINK_REQ_LOCFAULT));

	return IRQ_HANDLED;
} /* mxgbe_mac_irq */

/*
 * MAC kthread loop
 */
static int mac_kthread(void *arg)
{
	u32 val, stat;
	mxgbe_priv_t *priv = (mxgbe_priv_t *)arg;
	void __iomem *base = priv->bar0_base;

	while (!kthread_should_stop()) {
		set_current_state(TASK_RUNNING);
		stat = mxgbe_rreg32(base, MAC_LINK_STAT);
		if (stat != priv->carrier) {
			/* clean request flags */
			val = mxgbe_rreg32(base, MAC_LINK_CHG);
			val &= MAC_LINK_REQ_ALL;
			mxgbe_wreg32(base, MAC_LINK_CHG, val);
			mxgbe_net_mac_irq_handler(priv, stat &
						  (MAC_LINK_REQ_LINKINT |
						   MAC_LINK_REQ_REMFAULT |
						   MAC_LINK_REQ_LOCFAULT));
		}

		set_current_state(TASK_INTERRUPTIBLE);
		msleep(1000); /* millisecond sleep */
	}

	return 0;
} /* mac_kthread */
