/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_net.c - MXGBE module device driver
 *
 * Network part
 */

#include "mxgbe.h"
#include "mxgbe_hw.h"
#include "mxgbe_txq.h"
#include "mxgbe_rxq.h"
#include "mxgbe_phy.h"
#include "mxgbe_mac.h"
#include "mxgbe_dbg.h"
#include "kcompat.h"


/**
 *  Network interface Consts
 */
#define MXGBE_WATCHDOG_PERIOD	(5 * HZ)
#define MXGBE_NAPI_WEIGHT	64

#define MXGBE_TX_QUE_LEN	(priv->rxq[0].descr_cnt)

/** frame size */
#define MXGBE_ETH_HEAD_LEN	(14)
#define MXGBE_MTU	(MXGBE_MAXFRAMESIZE - MXGBE_ETH_HEAD_LEN)


void mxgbe_set_ethtool_ops(struct net_device *ndev);
#ifdef DEBUG
static void print_skb(struct sk_buff *skb, mxgbe_priv_t *priv, int dir);
#endif /* DEBUG */


/**
 ******************************************************************************
 * Buffer/skb alloc/free/init
 ******************************************************************************
 */

static int net_rxq_alloc_buff(mxgbe_priv_t *priv, mxgbe_rx_buff_t *rxq_buff)
{
	dma_addr_t dmaaddr;
	struct sk_buff *skb;
	struct net_device *ndev = priv->ndev;

	assert(ndev);

	rxq_buff->size = MXGBE_MAXFRAMESIZE;

	/* allocate new skb */
	skb = netdev_alloc_skb(ndev, rxq_buff->size + NET_IP_ALIGN);
	if (!skb) {
		dev_err(&ndev->dev,
			"ERROR: Cannot allocate skb for rx\n");
		return -ENOMEM;
	}
	skb_reserve(skb, NET_IP_ALIGN);
	skb->dev = ndev;

	dmaaddr = pci_map_single(priv->pdev, skb->data, rxq_buff->size,
				 PCI_DMA_FROMDEVICE);
	assert((dmaaddr & 0x01) == 0);

	rxq_buff->skb = skb;
	rxq_buff->addr = NULL;
	rxq_buff->dma = dmaaddr;

	return 0;
} /* net_rxq_alloc_buff */

static void net_rxq_clean_buff(mxgbe_priv_t *priv, mxgbe_rx_buff_t *rxq_buff)
{
	if (!rxq_buff)
		return;

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &priv->ndev->dev,
		"net_rxq_clean_buff: dma=%llX, size=%u, skb=%p\n",
		rxq_buff->dma, (unsigned)rxq_buff->size, rxq_buff->skb);

	if (0 == rxq_buff->dma || 0 == rxq_buff->size)
		return;

	pci_unmap_single(priv->pdev, rxq_buff->dma, rxq_buff->size,
			 PCI_DMA_FROMDEVICE);
	dev_kfree_skb_any(rxq_buff->skb);
} /* net_rxq_clean_buff */

static int net_rxq_init_buff(mxgbe_priv_t *priv, int qn,
			     mxgbe_rx_buff_t *rxq_buff, u16 head)
{
	mxgbe_descr_t descr;

	descr.ctrl.r = 0;
	descr.ctrl.RC.BUFSIZE = (rxq_buff->size >> 3) - 1;
	descr.addr.r = 0;
	descr.addr.RC.BUFPTR = rxq_buff->dma;
	descr.addr.RC.OWNER = XX_OWNER_HW;

	/* Prepare descriptor for Rx */
	return mxgbe_rxq_request(priv, qn, &descr, head);  /* used lock */
} /* net_rxq_init_buff */


/**
 * First Init RXQ# at start of probe
 * called from mxgbe_net_register
 */
static int net_rxq_init_q(mxgbe_priv_t *priv, int qn)
{
	int err;
	int i;
	mxgbe_rx_buff_t *rxq_buff;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &priv->ndev->dev,
		"net_rxq_init_q(qn=%d): alloc %d buffers for Rx\n",
		qn, priv->rxq[qn].descr_cnt);

	/* Init Rx ring */
	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt - 1; i++) {
		priv->rxq[qn].last_alloc = i;
		/* Alloc RAM for RX Data */
		err = net_rxq_alloc_buff(priv, rxq_buff);
		if (err) {
			/* dev_err() in net_rxq_alloc_buff() */
			goto err_free_ring;
		}
		err = net_rxq_init_buff(priv, qn, rxq_buff, i);
		if (err) {
			/* dev_err() in mxgbe_rxq_request() */
			goto err_free_ring;
		}
		rxq_buff++;
	}

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &priv->ndev->dev,
		"net_rxq_init_q(qn=%d): last alloc_buff N=%d\n",
		qn, priv->rxq[qn].last_alloc);

	return 0;

err_free_ring:
	return err;
} /* net_rxq_init_q */

static void net_rxq_clean_q(mxgbe_priv_t *priv, int qn)
{
	int i;
	mxgbe_rx_buff_t *rxq_buff;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &priv->ndev->dev,
		"net_rxq_clean_q(qn=%d): free %d buffers for Rx\n",
		qn, priv->rxq[qn].descr_cnt);

	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt; i++) {
		net_rxq_clean_buff(priv, rxq_buff);
		rxq_buff++;
	}
} /* net_rxq_clean_q */


/**
 ******************************************************************************
 * Rx Part
 ******************************************************************************
 **/

static void reinit_rxbuf_descr(mxgbe_priv_t *priv, int qn, u16 tail_cur)
{
	void __iomem *base = priv->bar0_base;
	mxgbe_rx_buff_t *rxq_buff;
	u16 head;
	int err;
	int j;

	while (priv->rxq[qn].last_alloc != tail_cur) {
		INC_RXQ_INDEX(j, priv->rxq[qn].last_alloc, qn);
		if (j == tail_cur)
			break; /* head == tail - 1 */
		rxq_buff = priv->rxq[qn].rx_buff + j;

		head = Q_HEAD_GET_PTR(mxgbe_rreg32(base,
						   RXQ_REG_ADDR(qn, Q_HEAD)));
		assert(head != tail_cur);

		DEV_DBG(MXGBE_DBG_MSK_NET_RX, &priv->ndev->dev,
			"net_hw_rx(qn=%d): last_alloc=%d, alloc_buff N=%d, " \
			"head=%d, tail_cur=%d\n",
			qn, priv->rxq[qn].last_alloc, j, head, tail_cur);

		err = net_rxq_alloc_buff(priv, rxq_buff);
		if (err) {
			dev_err(&priv->ndev->dev,
				"ERROR: Rx queue %d stopped !!!\n", qn);
			break;
		} else {
			/* err = */
			net_rxq_init_buff(priv, qn, rxq_buff, j);
			priv->rxq[qn].last_alloc = j;
		}
	}
} /* reinit_rxbuf_descr */

/**
 * The Rx function
 * Get one descriptor
 * return 0 for some work done
 */
int mxgbe_net_hw_rx(mxgbe_priv_t *priv, int qn)
{
	struct net_device *ndev;
	u16 tail_new, tail_hw, tail_cur;
	mxgbe_rx_buff_t *rxq_buff;
	mxgbe_descr_t *descr;
	struct sk_buff *skb;
	/* unsigned long flags; */ /* spin_lock */
	unsigned timestart;
	mxgbe_addr_t descr_addr;
	mxgbe_ctrl_t descr_ctrl;
	s64 t1, t2;
	void __iomem *base = priv->bar0_base;


	FDEBUG;

	assert(priv);
	ndev = priv->ndev;
	assert(ndev);
	if (!ndev)
		return 1;


	/* raw_spin_lock_irqsave(&priv->rxq[qn].lock, flags); */

	tail_cur = priv->rxq[qn].tail; /* new rx descr */

	/* Get HW TAIL */
	tail_hw = Q_TAIL_GET_PTR(mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_TAIL)));
	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"net_hw_rx(qn=%d): tail_ram=%d\n",
		qn, tail_hw);
	if (tail_cur == tail_hw) {
		/* no new data - exit */
		/* raw_spin_unlock_irqrestore(&priv->rxq[qn].lock, flags); */
		DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
			"net_hw_rx(qn=%d): tail_cur(%d) == tail_hw(%d), exit\n",
			qn, tail_cur, tail_hw);
		DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
			"========== net_hw_rx ========== EXIT ==========\n");
		return 0;  /* done */
	}

	rxq_buff = priv->rxq[qn].rx_buff + tail_cur;
	assert(rxq_buff);
	descr = ((mxgbe_descr_t *)(priv->rxq[qn].que_addr)) + tail_cur;

	/* tail ++ */
	INC_RXQ_INDEX(tail_new, tail_cur, qn);

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"net_hw_rx(qn=%d): tail_cur=%d, tail_new=%d, tail_hw=%d\n",
		qn, tail_cur, tail_new, tail_hw);

	/* tail ++ */
	priv->rxq[qn].tail = tail_new;


	/* Wait for OWNER */
	t1 = ktime_to_ns(ktime_get());

	descr_addr.r = le64_to_cpu(READ_ONCE(descr->addr.r));
	if (!descr_addr.RD.OWNER) {
#ifdef DEBUG
		dev_err(&ndev->dev, "RX ERROR: old OWNER\n");
#endif /* DEBUG */
		timestart = 0;
		do {
			descr_addr.r = le64_to_cpu(READ_ONCE(descr->addr.r));
			if (timestart >= 0xFFFF) {
				/* realloc this */
				pci_unmap_single(priv->pdev,
						 rxq_buff->dma,
						 rxq_buff->size,
						 PCI_DMA_FROMDEVICE);
				rxq_buff->dma = 0;
#ifdef DEBUG
				mxgbe_rx_dbg_prn_descr_s(priv, qn, descr,
							 tail_cur);
#endif /* DEBUG */
				t2 = ktime_to_ns(ktime_get());
				dev_err(&ndev->dev,
					"RX ERROR: OWNER not changed " \
					"- %lld ns\n",
					t2 - t1);
				DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
					"########## OWNER ##########\n");
				return 1; /* continue */
			}
			if (timestart == 1) {
#ifdef DEBUG
				dev_err(&ndev->dev, "Wait for OWNER !!!\n");
#endif /* DEBUG */
			}
			timestart += 1;
		} while (!descr_addr.RD.OWNER);
		t2 = ktime_to_ns(ktime_get());
		DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
			"RX: OWNER Ok (readcnt=%u) - %lld ns\n",
			timestart, t2 - t1);
	}

	descr_ctrl.r = le64_to_cpu(READ_ONCE(descr->ctrl.r));

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"net_hw_rx(qn=%d): descr=%p, rxq_buff=%p\n",
		qn, descr, rxq_buff);
	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"net_hw_rx(qn=%d): descr: %016llX %016llX\n",
		qn, descr_ctrl.r, descr_addr.r);

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"net_hw_rx(qn=%d): dma=%llX, size=%u, skb=%p\n",
		qn, rxq_buff->dma, (unsigned)rxq_buff->size, rxq_buff->skb);

/*#ifdef DEBUG*/
	if (0 == rxq_buff->dma || 0 == rxq_buff->size) {
		DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
			"net_hw_rx(qn=%d): dma==0 or size==0\n", qn);
		return 1; /* continue */
	}
/*#endif*/ /* DEBUG */

	/* Init SKB */
	pci_unmap_single(priv->pdev, rxq_buff->dma, rxq_buff->size,
			 PCI_DMA_FROMDEVICE);
	skb = rxq_buff->skb;
	skb_put(skb, descr_ctrl.RD.FRMSIZE + 1);
	rxq_buff->dma = 0;
	/* -= process descr =- */

#ifdef DEBUG
	if ((mxgbe_debug_mask & MXGBE_DBG_MSK_NET_RX) &
	    (mxgbe_debug_mask & MXGBE_DBG_MSK_NET_SKB)) {
		mxgbe_rx_dbg_prn_descr_s(priv, qn, descr, tail_cur);
		print_skb(skb, priv, 0);
	}
#endif /* DEBUG */


	/* Reinit Rx buf & descr */
	reinit_rxbuf_descr(priv, qn, tail_cur);

	/* raw_spin_unlock_irqrestore(&priv->rxq[qn].lock, flags); */

	/* Process SKB */
	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"net_hw_rx(qn=%d): len=%d\n", qn, (int)skb->len);

	/* nothing receive */
	if (skb->len < (MXGBE_ETH_HEAD_LEN)) {
		dev_err(&ndev->dev,
			"ERROR: Very small Rx packet's size\n");
		dev_kfree_skb_any(skb);
		DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
			"========== net_hw_rx ========== WRONG ==========\n");
		return 1; /* continue */
	}

#ifdef USE_HW_CSUM
	/* IPv4 CS */
	if (((descr_ctrl.RD.TYPE == 4) || (descr_ctrl.RD.TYPE == 5)) &&
	    (descr_ctrl.RD.IPCSUMOK == 0)) {
		dev_err(&ndev->dev,
			"ERROR: Wrong IPv4 CSUM\n");
		dev_kfree_skb_any(skb);
		priv->stats.rx_dropped++;
		return 1; /* continue */
	}
#endif /* USE_HW_CSUM */

	priv->stats.rx_packets++;
	priv->stats.rx_bytes += skb->len;

	skb->protocol = eth_type_trans(skb, ndev);
	netif_receive_skb(skb);

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &ndev->dev,
		"========== net_hw_rx ========== DONE ==========\n");
	return 1; /* continue */
} /* mxgbe_net_hw_rx */


/**
 * called from hw irq handler
 */
void mxgbe_net_rx_irq_handler(mxgbe_vector_t *vector)
{
	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &vector->priv->ndev->dev,
		"net_rx_irq_handler(qn=%d)\n", vector->qn);

	if (napi_schedule_prep(&(vector->napi)))
		__napi_schedule(&(vector->napi));
} /* mxgbe_net_rx_irq_handler */


/**
 * The rx poll function
 */
static int mxgbe_poll_rx(struct napi_struct *napi, int budget)
{
	mxgbe_vector_t *vector;
	mxgbe_priv_t *priv;
	void __iomem *base;
	int work_done = 0;
	int qn;

	FDEBUG;

	vector = container_of(napi, mxgbe_vector_t, napi);
	qn = vector->qn;
	priv = vector->priv;

	assert(priv);
	if (!priv)
		return -1;

	base = priv->bar0_base;

	DEV_DBG(MXGBE_DBG_MSK_NET_RX, &priv->ndev->dev,
		"*** mxgbe_poll_rx ***\n");

	/* Rx */
	while (mxgbe_net_hw_rx(priv, qn)) {
		work_done++;
		if (work_done >= budget) {
			DEV_DBG(MXGBE_DBG_MSK_NET_RX,
				&priv->ndev->dev,
				"*** mxgbe_poll_rx: rx budget %d overloaded\n",
				budget);
			return work_done;
		}
	}

	napi_complete(&(vector->napi));
	/* NAPI: Enable IRQ */
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ),
		     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);

	DEV_DBG(MXGBE_DBG_MSK_NET_RX,
		&priv->ndev->dev,
		"*** mxgbe_poll_rx: napi_complete %d (budget %d)\n",
		work_done, budget);

	return work_done;
} /* mxgbe_poll_rx */


/**
 ******************************************************************************
 * Tx Part
 ******************************************************************************
 **/

/**
 * Clean sended resource
 * called from irq handler or poll
 */
static void mxgbe_net_tx_confirm(mxgbe_priv_t *priv, int qn,
				 mxgbe_tx_buff_t *tx_buff)
{
	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_NET_TX, &priv->ndev->dev,
		"net_tx_confirm(qn=%d): skb=%p\n", qn, tx_buff->skb);

	priv->stats.tx_packets++;
	priv->stats.tx_bytes += tx_buff->skb->len;

	pci_unmap_single(priv->pdev, tx_buff->dma, tx_buff->skb->len,
			 PCI_DMA_TODEVICE);
	dev_kfree_skb_irq(tx_buff->skb);
} /* mxgbe_net_tx_confirm */

/*
 * Clean sended resource
 * called from irq handler or poll
 */
int mxgbe_txq_confirm(mxgbe_priv_t *priv, int qn)
{
	u16 cur_tail;
	u16 tail;
	mxgbe_tx_buff_t *tx_buff;
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	spin_lock(&priv->txq[qn].tlock);
	tail = Q_TAIL_GET_PTR(mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_TAIL)));

	cur_tail = READ_ONCE(priv->txq[qn].tail);
	if (cur_tail == tail) {
		spin_unlock(&priv->txq[qn].tlock);
		return 0; /* DONE */
	}

	priv->txq[qn].tail = tail;

	DEV_DBG(MXGBE_DBG_MSK_TX, &priv->ndev->dev,
		"txq_confirm: old tail=%d, new tail=%d\n", cur_tail, tail);

	while (cur_tail != tail) {
		tx_buff = &priv->txq[qn].tx_buff[cur_tail];
		if (tx_buff) {
			DEV_DBG(MXGBE_DBG_MSK_TX, &priv->ndev->dev,
				"txq_confirm: dma=%llX, skb=%p\n",
				tx_buff->dma, tx_buff->skb);
			if (tx_buff->skb)
				mxgbe_net_tx_confirm(priv, qn, tx_buff);
		}

		INC_TXQ_INDEX(cur_tail, cur_tail, qn);
	}
	spin_unlock(&priv->txq[qn].tlock);

	return 1;
} /* mxgbe_txq_confirm */

/**
 * called from hw irq handler
 */
void mxgbe_net_tx_irq_handler(mxgbe_vector_t *vector)
{
	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_NET_TX, &vector->priv->ndev->dev,
		"net_tx_irq_handler(qn=%d)\n", vector->qn);

	if (napi_schedule_prep(&(vector->napi)))
		__napi_schedule(&(vector->napi));
} /* mxgbe_net_tx_irq_handler */

/**
 * The tx poll function
 */
static int mxgbe_poll_tx(struct napi_struct *napi, int budget)
{
	mxgbe_vector_t *vector;
	mxgbe_priv_t *priv;
	void __iomem *base;
	int work_done = 0;
	int qn;

	FDEBUG;

	vector = container_of(napi, mxgbe_vector_t, napi);
	qn = vector->qn;
	priv = vector->priv;

	assert(priv);
	if (!priv)
		return -1;

	base = priv->bar0_base;

	DEV_DBG(MXGBE_DBG_MSK_NET_TX, &priv->ndev->dev,
		"*** mxgbe_poll_tx ***\n");

	/* Tx */
	while (mxgbe_txq_confirm(priv, qn)) {
		work_done++;
		if (work_done >= budget) {
			DEV_DBG(MXGBE_DBG_MSK_NET_TX,
				&priv->ndev->dev,
				"*** mxgbe_poll_tx: tx budget %d overloaded\n",
				budget);
			return work_done;
		}
	}

	napi_complete(&(vector->napi));
	/* NAPI: Enable IRQ */
	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ),
		     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);

	DEV_DBG(MXGBE_DBG_MSK_NET_TX,
		&priv->ndev->dev,
		"*** mxgbe_poll_tx: napi_complete %d (budget %d)\n",
		work_done, budget);

	return work_done;
} /* mxgbe_poll_tx */


/**
 ******************************************************************************
 * MAC Part
 ******************************************************************************
 **/

/**
 * called from mac irq handler
 */
void mxgbe_net_mac_irq_handler(mxgbe_priv_t *priv, u32 state)
{
	struct net_device *ndev;

	FDEBUG;

	ndev = priv->ndev;
	assert(ndev);
	if (!ndev)
		return;

	if (state == priv->carrier)
		return;

	DEV_DBG(MXGBE_DBG_MSK_NET, &ndev->dev,
		"net_mac_irq_handler: state=0x%X\n", state);

	priv->carrier = state;
	if (state) {
		netif_carrier_off(ndev);
		dev_dbg(&ndev->dev, "carrier off\n");
	} else {
		netif_carrier_on(ndev);
		dev_dbg(&ndev->dev, "carrier on\n");
	}
} /* mxgbe_net_mac_irq_handler */


/**
 ******************************************************************************
 * Network Driver Part
 ******************************************************************************
 **/

static inline int mxgbe_tx_q_mapping(mxgbe_priv_t *priv, struct sk_buff *skb)
{
	unsigned int r_idx = skb->queue_mapping;

	if (r_idx >= priv->num_tx_queues)
		r_idx = r_idx % priv->num_tx_queues;

	return r_idx;
} /* mxgbe_tx_q_mapping */

/**
 * The network interface transmission function
 * @skb: socket buffer for tx
 * @ndev: network interface device structure
 *
 * mxgbe_start_xmit is called by socket send function
 */
static netdev_tx_t mxgbe_start_xmit(struct sk_buff *skb,
				    struct net_device *ndev)
{
	int ret = -1;
	mxgbe_priv_t *priv;
	mxgbe_descr_t descr;
	dma_addr_t dmaaddr;
	mxgbe_tx_buff_t tx_buff;
	ssize_t size;
	int nq;

	FDEBUG;

	priv = netdev_priv(ndev);
	assert(priv);
	if (!priv)
		return -1;

	if (netif_queue_stopped(ndev))
		return 1;

	nq = mxgbe_tx_q_mapping(priv, skb);

	/* Check packet's size */
#if 0
	if (skb->len < ETH_ZLEN) {
		if (skb_padto(skb, ETH_ZLEN)) {
			dev_err(&ndev->dev,
				"ERROR: Very small Tx packet's size\n");
			goto tx_free_skb;
		}
		skb->len = ETH_ZLEN;
	}
#endif
	if (skb->len > MXGBE_MTU) {
		dev_err(&ndev->dev,
			"ERROR: Very large Tx packet's size\n");
		goto tx_free_skb;
	}

	if (skb_put_padto(skb, ETH_ZLEN)) {
		/*if (netif_msg_tx_queued(ep))*/
			dev_err(&ndev->dev,
				 "%s: Could not skb_put_padto\n", __func__);

		return NETDEV_TX_OK;
	}
	if (__netif_subqueue_stopped(ndev, nq)) {
		/*if (netif_msg_tx_queued(ep))*/
			dev_info(&ndev->dev,
				 "%s: xmit to queue %d stopped\n",
				 __func__, nq);

		return NETDEV_TX_BUSY;
	}

	/* start_xmit_to_q */

	size = skb->len;

	dmaaddr = pci_map_single(priv->pdev, skb->data, size,
				 PCI_DMA_TODEVICE);
	assert((dmaaddr & 0x01) == 0);

	DEV_DBG(MXGBE_DBG_MSK_NET_TX, &ndev->dev,
		"start_xmit: adr=%p, dma=%llX, len=%ld\n",
		skb->data, dmaaddr, size);

	netif_trans_update(ndev); /* qn ? */

	/* Create descriptor */
	descr.ctrl.r = 0;
	descr.ctrl.TC.BUFSIZE = (size >> 3); /* QWORDs - 1 */
	descr.ctrl.TC.MSS = TC_MSS_NOSPLIT;
	descr.ctrl.TC.FRMSIZE = size - 1;

	descr.addr.r = 0;
	descr.addr.TC.BUFPTR = (u64)dmaaddr;
	descr.addr.TC.SPLIT = TC_SPLIT_NO;
	descr.addr.TC.OWNER = XX_OWNER_HW;

#ifdef USE_LONG_DESCR
	descr.vlan.r = 0;
	descr.time.r = 0;
#endif /* USE_LONG_DESCR */

	/* Save for unmap and free */
	tx_buff.skb = skb;
	tx_buff.dma = dmaaddr;

#ifdef DEBUG
	if ((mxgbe_debug_mask & MXGBE_DBG_MSK_NET_TX) &
	    (mxgbe_debug_mask & MXGBE_DBG_MSK_NET_SKB)) {
		mxgbe_tx_dbg_prn_descr_s(priv, &descr);
		print_skb(skb, priv, 1);
	}
#endif /* DEBUG */

	ret = mxgbe_txq_send(priv, nq, &descr, &tx_buff);
	if (ret < 0)
		goto tx_free_skb;

	DEV_DBG(MXGBE_DBG_MSK_NET_TX, &ndev->dev,
		"start_xmit: OK\n");

	return NETDEV_TX_OK;

tx_free_skb:
	priv->stats.tx_dropped++;
	dev_kfree_skb(skb);

	DEV_DBG(MXGBE_DBG_MSK_NET_TX, &ndev->dev,
		"start_xmit: ERROR\n");

	return -1;
} /* mxgbe_start_xmit */


/**
 * The network interface open function
 * @ndev: network interface device structure
 *
 * mxgbe_open is called by register_netdev
 */
static int mxgbe_open(struct net_device *ndev)
{
	mxgbe_priv_t *priv;
	int qn;
	int node;

	FDEBUG;

	assert(ndev);
	if (!ndev)
		return -1;

	priv = netdev_priv(ndev);
	assert(priv);
	if (!priv)
		return -1;

	mxgbe_mac_event_dis(priv);
	netif_carrier_off(ndev);

	/* Enable interrupt */

	/* Start all RX Queue */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_rxq_start(priv, qn);
	}

#if 0
	mxgbe_ptp_init(priv);
#endif

	/* start tx/rx */
	netif_start_queue(ndev);
	for (qn = 0; qn < (priv->num_rx_queues +
			   priv->num_tx_queues); qn++) {
		napi_enable(&(priv->vector[qn].napi));
	}

	mxgbe_mac_event_en(priv);
	/* bug#158116: software bypass */
	mxgbe_rx_multicast_enable(priv);

	if (!priv->carrier)
		netif_carrier_on(ndev);

	node = dev_to_node(&priv->pdev->dev);
	dev_info(&ndev->dev, KBUILD_MODNAME " node%d interface OPEN\n", node);

	return 0;
} /* mxgbe_open */


/**
 * The network interface close function
 * @ndev: network interface device structure
 *
 * mxgbe_stop is called by free_netdev
 */
static int mxgbe_stop(struct net_device *ndev)
{
	mxgbe_priv_t *priv;
	int qn;
	int node;

	FDEBUG;

	assert(ndev);
	if (!ndev)
		return -1;

	priv = netdev_priv(ndev);
	assert(priv);
	if (!priv)
		return -1;

	/*if (netif_msg_ifup(priv))*/
	node = dev_to_node(&priv->pdev->dev);
	dev_info(&ndev->dev, KBUILD_MODNAME " node%d interface STOP\n", node);

	/* Disable interrupt */

	mxgbe_mac_event_dis(priv);
	netif_carrier_off(ndev);	/* link off */

	/* stop tx/rx */
	for (qn = 0; qn < (priv->num_rx_queues +
			   priv->num_tx_queues); qn++) {
		napi_disable(&(priv->vector[qn].napi));
	}

	netif_stop_queue(ndev);

	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_rxq_stop(priv, qn);
	}

	/* bug#158116: software bypass */
	mxgbe_rx_multicast_disable(priv);

	return 0;
} /* mxgbe_stop */


static int mxgbe_ioctl(struct net_device *ndev, struct ifreq *rq, int cmd)
{
	int rc = 0;
	mxgbe_priv_t *priv = netdev_priv(ndev);

	switch (cmd) {
	default:
		/* SIOC[GS]MIIxxx ioctls */
		rc = -EOPNOTSUPP;
	}
	return rc;
}


/**
 * The network interface status function
 * @ndev: network interface device structure
 */
static struct net_device_stats *mxgbe_get_stats(struct net_device *ndev)
{
	mxgbe_priv_t *priv;

	FDEBUG;

	assert(ndev);
	if (!ndev)
		return NULL;

	priv = netdev_priv(ndev);
	assert(priv);
	if (!priv)
		return NULL;

	return &priv->stats;
} /* mxgbe_get_stats */


static int mxgbe_change_mtu(struct net_device *ndev, int new_mtu)
{
	int old_mtu = ndev->mtu;

	FDEBUG;

	if (new_mtu == old_mtu) {
		return 0;
	}
	if (new_mtu > MXGBE_MTU) {
		dev_warn(&ndev->dev,
			 "current MTU %u, requested %d (valid: %d..%d)\n",
			 old_mtu, new_mtu, ndev->min_mtu, ndev->max_mtu);
		return -EINVAL;
	}

	ndev->mtu = new_mtu;
	netdev_update_features(ndev);

	dev_info(&ndev->dev, "change MTU: old=%u, new=%d (valid: %d..%d)\n",
		 old_mtu, new_mtu, ndev->min_mtu, ndev->max_mtu);

	return 0;
} /* mxgbe_change_mtu */


static int mxgbe_set_mac_addr(struct net_device *ndev, void *p)
{
	struct sockaddr *addr = p;

	FDEBUG;

	if (netif_running(ndev))
		return -EBUSY;
	memcpy(ndev->dev_addr, addr->sa_data, ndev->addr_len);

	return 0;
} /* mxgbe_set_mac_addr */


#if 0
/**
 * The network interface transmission timeout function
 * @ndev: network interface device structure
 */
static void mxgbe_tx_timeout(struct net_device *ndev)
{
	FDEBUG;

	assert(ndev);
	if (!ndev)
		return;

	/* Save the timestamp */
	ndev->trans_start = jiffies;

	dev_err(&ndev->dev,
		"ERROR: Tx Timeout\n");
} /* mxgbe_tx_timeout */
#endif /* 0 */


/**
 * net_device_ops
 */
const struct net_device_ops mxgbe_netdev_ops = {
	.ndo_open		= mxgbe_open,
	.ndo_stop		= mxgbe_stop,
	.ndo_start_xmit		= mxgbe_start_xmit,
	/*.ndo_select_queue	= mxgbe_select_queue,*/
	/*.ndo_set_rx_mode	= mxgbe_set_rx_mode,*/	/* TODO */
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= mxgbe_set_mac_addr,
	.ndo_change_mtu		= mxgbe_change_mtu,
	/*.ndo_tx_timeout	= mxgbe_tx_timeout,*/	/* TODO */
	.ndo_do_ioctl		= mxgbe_ioctl,
	/*.ndo_get_stats64	= mxgbe_get_stats64,*/ /* TODO: */
	.ndo_get_stats		= mxgbe_get_stats,
};


/**
 ******************************************************************************
 * Init Network Driver Part
 ******************************************************************************
 **/

mxgbe_priv_t *mxgbe_net_alloc(struct pci_dev *pdev, void __iomem *base)
{
	mxgbe_priv_t *priv;
	struct net_device *ndev;
	unsigned int txqs;
	unsigned int rxqs;
	int cpus;


	txqs = mxgbe_rreg32(base, TX_QNUM);
	rxqs = mxgbe_rreg32(base, RX_QNUM);
	cpus = num_online_cpus();

	/* chk Tx */
	if ((txqs < TXQ_MINNUM) || (txqs > TXQ_MAXNUM)) {
		dev_err(&pdev->dev, "wrong txq numbers\n");
		return NULL;
	}
	txqs = min_t(int, txqs, cpus);
	txqs = min_t(int, txqs, TXQ_MAXNUM);
	if ((mxgbe_maxqueue >= TXQ_MINNUM) && (mxgbe_maxqueue <= TXQ_MAXNUM)) {
		txqs = min_t(int, txqs, mxgbe_maxqueue);
	}

	/* chk Rx */
	if ((rxqs < RXQ_MINNUM) || (rxqs > RXQ_MAXNUM)) {
		dev_err(&pdev->dev, "wrong rxq numbers\n");
		return NULL;
	}
	rxqs = min_t(int, rxqs, cpus);
	rxqs = min_t(int, rxqs, RXQ_MAXNUM);
	if ((mxgbe_maxqueue >= RXQ_MINNUM) && (mxgbe_maxqueue <= RXQ_MAXNUM)) {
		rxqs = min_t(int, rxqs, mxgbe_maxqueue);
	}

	ndev = alloc_etherdev_mqs(sizeof(struct mxgbe_priv), txqs, rxqs);
	if (!ndev) {
		dev_err(&pdev->dev,
			"ERROR: Cannot allocate memory" \
			" for net_dev, aborting\n");
		return NULL;
	}
	SET_NETDEV_DEV(ndev, &pdev->dev); /* parent := pci */
	priv = netdev_priv(ndev);
	priv->ndev = ndev;
	priv->pdev = pdev;
	priv->num_tx_queues = txqs;
	priv->num_rx_queues = rxqs;

	dev_info(&pdev->dev,
		 "cpus:%d, tx_queues:%d, rx_queues:%d\n", cpus, txqs, rxqs);

	return priv;
}

int mxgbe_net_register(mxgbe_priv_t *priv)
{
	int ret = 0;
	struct net_device *ndev = priv->ndev;
	int qn;

	FDEBUG;

	assert(ndev);

	ndev->netdev_ops = &mxgbe_netdev_ops;
	ndev->tx_queue_len = MXGBE_TX_QUE_LEN;
	ndev->watchdog_timeo = MXGBE_WATCHDOG_PERIOD;
	mxgbe_set_ethtool_ops(ndev);

#ifdef USE_HW_CSUM
	ndev->features |= 0
		| NETIF_F_IP_CSUM		/* IPv4 CS */
		/* | NETIF_F_HW_CSUM */		/* CS all */
		/* | NETIF_F_IPV6_CSUM */	/* IPV6 XS */
		;
#else
	ndev->hw_features = 0;
#endif /* USE_HW_CSUM */

	/* MTU range: 68 - 16366 */
	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = MXGBE_MAXFRAMESIZE - (ETH_HLEN + ETH_FCS_LEN);

	/* create napi for all queue */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		netif_napi_add(ndev, &(priv->vector[qn].napi),
			       mxgbe_poll_rx, MXGBE_NAPI_WEIGHT);
	}
	for (qn = priv->num_rx_queues; qn < (priv->num_rx_queues +
					     priv->num_tx_queues); qn++) {
		netif_napi_add(ndev, &(priv->vector[qn].napi),
			       mxgbe_poll_tx, MXGBE_NAPI_WEIGHT);
	}

	/* link off */
	netif_carrier_off(ndev);

	if (ret = mxgbe_mdio_register(priv)) {
		dev_err(&priv->pdev->dev,
			"Cannot register mdio bus, aborting\n");
		goto err_out_free_rxq;
	}

	/* set MAC from EEPROM */
	memcpy(ndev->dev_addr, &priv->MAC, 6);

	priv->carrier = (u32)-1;

	ndev->features = 0;

	if (ret = register_netdev(ndev)) {
		dev_err(&priv->pdev->dev,
			"Cannot register net device, aborting\n");
		goto err_out_mdiobus;
	}

	if (priv->num_tx_queues != priv->ndev->num_tx_queues) {
		dev_warn(&ndev->dev,
			 "num_tx_queues wrong: %d != %d\n",
			 priv->num_tx_queues, priv->ndev->num_tx_queues);
	}
	if (priv->num_rx_queues != priv->ndev->num_rx_queues) {
		dev_warn(&ndev->dev,
			 "num_rx_queues wrong: %d != %d\n",
			 priv->num_rx_queues, priv->ndev->num_rx_queues);
	}

	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		if (net_rxq_init_q(priv, qn)) {
			dev_err(&priv->pdev->dev,
				"ERROR: DMA_ALLOC_RAM qn=%d\n", qn);
			ret = -ENOMEM;
			goto err_out_mdiobus;
		}
	}

	if (priv->revision != MXGBE_REVISION_ID_BOARD) {
		if (mxgbe_set_pcsphy_mode(ndev)) {
			dev_err(&priv->pdev->dev,
				"could not set PCS PHY mode\n");
			ret = -EIO;
			goto err_out_mdiobus;
		}
	}

	dev_info(&priv->pdev->dev, "network interface %s init\n",
		 dev_name(&ndev->dev));

	DEV_DBG(MXGBE_DBG_MSK_NET, &ndev->dev,
		"network interface:\n" \
		"\tname=%s\n" \
		"\tstate=%lu\n" \
		"\thard_header_len=%u\n" \
		"\tmtu=%u\n" \
		"\ttx_queue_len=%u\n" \
		"\ttype=%u\n" \
		"\taddr_len=%u\n" \
		"\tflags=0x%X\n" \
		"\tfeatures=0x%llX\n",
		ndev->name,
		ndev->state,
		ndev->hard_header_len,
		ndev->mtu,
		ndev->tx_queue_len,
		ndev->type,
		ndev->addr_len,
		ndev->flags, /* IFF_BROADCAST | IFF_MULTICAST */
		ndev->features); /* features */

	if (ndev->features & NETIF_F_GRO)
		DEV_DBG(MXGBE_DBG_MSK_NET, &ndev->dev,
			"network features: NETIF_F_GRO\n");

	return 0;

err_out_mdiobus:
	if (priv->mii_bus)
		mdiobus_unregister(priv->mii_bus);
err_out_free_rxq:
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		net_rxq_clean_q(priv, qn);
	}

	return ret;
} /* mxgbe_net_register */


void mxgbe_net_remove(mxgbe_priv_t *priv)
{
	int qn;
	struct net_device *ndev;

	FDEBUG;

	assert(priv);
	if (!priv)
		return;

	ndev = priv->ndev;
	assert(ndev);
	if (!ndev)
		return;

	netif_stop_queue(ndev);

	/* link off */
	mxgbe_mac_event_dis(priv);
	netif_carrier_off(ndev);

	/* Free RAM for RX Data */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		net_rxq_clean_q(priv, qn);
	}

	if (ndev)
		unregister_netdev(ndev);

	if (priv->mii_bus)
		mdiobus_unregister(priv->mii_bus);
} /* mxgbe_net_remove */

void mxgbe_net_free(mxgbe_priv_t *priv)
{
	free_netdev(priv->ndev);
} /* mxgbe_net_free */


/**
 ******************************************************************************
 * Event Part
 ******************************************************************************
 **/

#ifdef CONFIG_DEBUG_FS
void mxgbe_dbg_rename(mxgbe_priv_t *priv, const char *name);
#endif /* CONFIG_DEBUG_FS */

/* Use network device events to rename some file entries. */
int mxgbe_device_event(struct notifier_block *unused, unsigned long event,
		       void *ptr)
{
	struct net_device *ndev = netdev_notifier_info_to_dev(ptr);
	mxgbe_priv_t *priv;

	if (!ndev)
		goto done;

	priv = netdev_priv(ndev);
	if (!priv)
		goto done;

	if (ndev->netdev_ops != &mxgbe_netdev_ops)
		goto done;

	switch (event) {
	case NETDEV_CHANGENAME:
		dev_info(&priv->pdev->dev,
			": node%d 10G network interface name - %s\n",
			dev_to_node(&priv->pdev->dev), ndev->name);

#ifdef CONFIG_DEBUG_FS
		snprintf(priv->dbg_name, sizeof(priv->dbg_name) - 1,
			 "%s@%s", ndev->name, dev_name(&priv->pdev->dev));
		mxgbe_dbg_rename(priv, priv->dbg_name);
#endif /* CONFIG_DEBUG_FS */
		break;
	}
done:
	return NOTIFY_DONE;
} /* mxgbe_device_event */


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

#ifdef DEBUG
static void print_skb(struct sk_buff *skb, mxgbe_priv_t *priv, int dir)
{
	pr_debug(">>>>> %s >>>>> (skb: %p)\n", (dir) ? "TX" : "RX", skb);

	dev_dbg(&skb->dev->dev, "\tlen=%u, data_len=%u" \
				", mac_len=%u, hdr_len=%u",
		skb->len, skb->data_len,
		skb->mac_len, skb->hdr_len);
	dev_dbg(&skb->dev->dev, "\tcsum=%u, csum_start=%u, csum_offset=%u",
		skb->csum, skb->csum_start, skb->csum_offset);
	dev_dbg(&skb->dev->dev, "\tpriority=%u, pkt_type=%u, protocol=%u" \
				", napi_id=%u",
		skb->priority, skb->pkt_type, skb->protocol,
		skb->napi_id);
	dev_dbg(&skb->dev->dev, "\ttransport_header=%u, network_header=%u," \
				" mac_header=%u",
		skb->transport_header, skb->network_header, skb->mac_header);
	dev_dbg(&skb->dev->dev, "\thead=%p, data=%p, truesize=%u",
		skb->head, skb->data, skb->truesize);

#if 0
	if (1/*netif_msg_pktdata(priv)*/) {
		void *packet;
		struct ethhdr *eth;
		int i;

		packet = (void *)skb->data;
		eth = (struct ethhdr *) packet;
		for (i = 0; i != 6; i++) {
			pr_debug("%s eth: src %02X, dst %02X\n",
			       (dir) ? "TX" : "RX",
			       eth->h_source[i], eth->h_dest[i]);
		}
		for (i = 0; i != ((skb->len) / 4); i++) {
			pr_debug("%s packet: int # %d  0x%08X\n",
			       (dir) ? "TX" : "RX",
			       i, *(u32 *)packet);
			packet += 4;
		}
		for (i = 0; i != ((skb->len) % 4); i++) {
			pr_debug("%s packet: byte # %d  0x%02X\n",
			       (dir) ? "TX" : "RX",
			       i, *(u8 *)packet);
			packet += 1;
		}
	}
#endif
	pr_debug("<<<<< %s <<<<<\n", (dir) ? "TX" : "RX");
} /* print_skb */
#endif /* DEBUG */
