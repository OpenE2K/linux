/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_MAC_H__
#define MXGBE_MAC_H__


/**
 * ch2.3 - MAC
 */

/* MAC_LOOPBACK regiter bits */
#define MAC_LOOPBACK_ON		SET_BIT(0)
/* MAC_LINK_STAT|CHG regiter bits */
#define MAC_LINK_ENSETBITS	SET_BIT(31)	/* WO */
#define MAC_LINK_EN_RX_READY	SET_BIT(20)	/* R/W */
#define MAC_LINK_EN_TX_READY	SET_BIT(19)	/* R/W */
#define MAC_LINK_EN_LINKINT	SET_BIT(18)	/* R/W */
#define MAC_LINK_EN_REMFAULT	SET_BIT(17)	/* R/W */
#define MAC_LINK_EN_LOCFAULT	SET_BIT(16)	/* R/W */
#define MAC_LINK_EN_ALL		(MAC_LINK_EN_RX_READY | \
				 MAC_LINK_EN_TX_READY | \
				 MAC_LINK_EN_LINKINT  | \
				 MAC_LINK_EN_REMFAULT | \
				 MAC_LINK_EN_LOCFAULT)
#define MAC_LINK_REQSETBITS	SET_BIT(15)	/* WO */
#define MAC_LINK_REQ_RX_READY	SET_BIT(4)	/* R/W */
#define MAC_LINK_REQ_TX_READY	SET_BIT(3)	/* R/W */
#define MAC_LINK_REQ_LINKINT	SET_BIT(2)	/* R/W */
#define MAC_LINK_REQ_REMFAULT	SET_BIT(1)	/* R/W */
#define MAC_LINK_REQ_LOCFAULT	SET_BIT(0)	/* R/W - 0==LINK-OK*/
#define MAC_LINK_REQ_ALL	(MAC_LINK_REQ_RX_READY | \
				 MAC_LINK_REQ_TX_READY | \
				 MAC_LINK_REQ_LINKINT  | \
				 MAC_LINK_REQ_REMFAULT | \
				 MAC_LINK_REQ_LOCFAULT)
/* MAC_RAW regiter bits */
#define MAC_RAW_RX_BAD_FCS	SET_BIT(17)
#define MAC_RAW_RX_SHORT64	SET_BIT(16)
#define MAC_RAW_TX_DIS_FCS	SET_BIT(1)
#define MAC_RAW_TX_RESIZE64	SET_BIT(0)
/* MAC_MAX_RATE regiter bits */
#define MAC_MAX_RATE_DEF	0x01000000	/* default */
/* MAC_PAUSE_CTRL */
#define MAC_PAUSE_CTRL_TXEN	0x02
#define MAC_PAUSE_CTRL_RXEN	0x01


void mxgbe_mac_init(mxgbe_priv_t *priv);
void mxgbe_mac_start(mxgbe_priv_t *priv);
void mxgbe_mac_event_en(mxgbe_priv_t *priv);
void mxgbe_mac_event_dis(mxgbe_priv_t *priv);

irqreturn_t mxgbe_mac_irq_handler(int irq, void *dev_id);


#endif /* MXGBE_MAC_H__ */
