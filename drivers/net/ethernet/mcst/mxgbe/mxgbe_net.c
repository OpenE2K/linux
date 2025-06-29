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
#include "mxgbe_xdp.h"
#include "kcompat.h"


/**
 *  Network interface Consts
 */
#define MXGBE_WATCHDOG_PERIOD	(5 * HZ)

/** frame size */
#define MXGBE_SKB_HEADROOM	ALIGN(max(NET_SKB_PAD, XDP_PACKET_HEADROOM), 8)
#define MXGBE_SKB_PAD		(SKB_DATA_ALIGN(sizeof(struct skb_shared_info) + \
							MXGBE_SKB_HEADROOM))
#define MXGBE_ETH_LEN		(ETH_HLEN + ETH_FCS_LEN + (VLAN_HLEN * 2))
#define MXGBE_MTU			(MXGBE_MAXFRAMESIZE - MXGBE_ETH_LEN - MXGBE_SKB_HEADROOM)


void mxgbe_set_ethtool_ops(struct net_device *ndev);

/**
 ******************************************************************************
 * Buffer/skb alloc/free/init
 ******************************************************************************
 */

static int net_rxq_alloc_buff(mxgbe_priv_t *priv, mxgbe_rx_buff_t *rxq_buff, int qn)
{
	dma_addr_t dma;
	struct page *page;
	unsigned int len = MXGBE_MAXFRAMESIZE;
	struct mxgbe_queue *q = &priv->rxq[qn];

	/* Clear rx buffer first */
	if (rxq_buff->page) {
		page_pool_recycle_direct(q->page_pool, rxq_buff->page);
		rxq_buff->page = NULL;
		if (dma_unmap_len(rxq_buff, len)) {
			dma_unmap_page(&priv->pdev->dev,
				       dma_unmap_addr(rxq_buff, dma),
				       dma_unmap_len(rxq_buff, len),
				       q->rx_dir);
		}
	}
	dma_unmap_len_set(rxq_buff, len, 0);
	rxq_buff->bytes = 0;

	page = page_pool_dev_alloc_pages(q->page_pool);
	if (!page)
		return -ENOMEM;
	rxq_buff->page = page;

	dma = dma_map_page(&priv->pdev->dev, page, 0, len, q->rx_dir);
	if (dma_mapping_error(&priv->pdev->dev, dma)) {
		page_pool_recycle_direct(q->page_pool, page);
		rxq_buff->page = NULL;
		dma_unmap_len_set(rxq_buff, len, 0);

		return -ENOMEM;
	}

	dma_unmap_addr_set(rxq_buff, dma, dma);
	dma_unmap_len_set(rxq_buff, len, len);

	return 0;
} /* net_rxq_alloc_buff */

static void net_rxq_clean_buff(mxgbe_priv_t *priv, mxgbe_rx_buff_t *rxq_buff, int qn)
{
	struct mxgbe_queue *q = &priv->rxq[qn];

	if (!rxq_buff)
		return;

	if (rxq_buff->page) {
		page_pool_put_full_page(q->page_pool, rxq_buff->page, false);
		rxq_buff->page = NULL;
		if (dma_unmap_len(rxq_buff, len)) {
			dma_unmap_page(&priv->pdev->dev,
				       dma_unmap_addr(rxq_buff, dma),
				       dma_unmap_len(rxq_buff, len),
				       q->rx_dir);
		}
	}
	dma_unmap_len_set(rxq_buff, len, 0);
	rxq_buff->bytes = 0;
} /* net_rxq_clean_buff */

static int net_rxq_init_buff(mxgbe_priv_t *priv, int qn,
			     mxgbe_rx_buff_t *rxq_buff, u16 head)
{
	mxgbe_descr_t descr;
	struct mxgbe_queue *q = &priv->rxq[qn];

	descr.ctrl.r = 0;
	descr.ctrl.RC.BUFSIZE = ((dma_unmap_len(rxq_buff, len) - q->rx_dma_offset) >> 3) - 1;
	descr.addr.r = 0;
	descr.addr.RC.BUFPTR = dma_unmap_addr(rxq_buff, dma) + q->rx_dma_offset;
	descr.addr.RC.OWNER = XX_OWNER_HW;
	descr.vlan.r = 0;
	descr.time.r = 0;

	/* Prepare descriptor for Rx */
	return mxgbe_rxq_request(priv, qn, &descr, head);  /* used lock */
} /* net_rxq_init_buff */


static int mxgbe_rx_page_pool_create(mxgbe_priv_t *priv, int qn)
{
	struct page_pool_params pp = { 0 };
	struct mxgbe_queue *q = &priv->rxq[qn];

	pp.order = (MXGBE_MAXFRAMESIZE / PAGE_SIZE) / 2;
	pp.pool_size = q->descr_cnt;
	pp.dev = &priv->pdev->dev;
	pp.nid = dev_to_node(&priv->pdev->dev);
	pp.dma_dir = DMA_BIDIRECTIONAL;

	q->page_pool = page_pool_create(&pp);
	if (IS_ERR(q->page_pool)) {
		int err = PTR_ERR(q->page_pool);

		q->page_pool = NULL;
		return err;
	}

	return 0;
}

/**
 * First Init RXQ# at start of probe
 * called from mxgbe_net_register
 */
int net_rxq_init_q(mxgbe_priv_t *priv, int qn)
{
	int err;
	int i;
	mxgbe_rx_buff_t *rxq_buff;
	struct mxgbe_queue *q = &priv->rxq[qn];
	bool xdp_enabled = !!READ_ONCE(priv->xdp_prog);

	/* Create page pool first */
	err =  mxgbe_rx_page_pool_create(priv, qn);
	if (err) {
		dev_err(&priv->ndev->dev,
			"ERROR: Failed to create page pool(%u)\n", qn);
		goto err_free_ring;
	}

	/* XDP RX-queue info */
	if (xdp_rxq_info_is_reg(&q->xdp_rxq))
		xdp_rxq_info_unreg(&q->xdp_rxq);

	err = xdp_rxq_info_reg(&q->xdp_rxq, priv->ndev, qn, 0);
	if (err < 0) {
		dev_err(&priv->ndev->dev,
			"Failed to register xdp_rxq(%u)\n", qn);
		goto err_free_ring;
	}

	xdp_rxq_info_unreg_mem_model(&q->xdp_rxq);
	err = xdp_rxq_info_reg_mem_model(&q->xdp_rxq,
					 MEM_TYPE_PAGE_POOL, q->page_pool);
	if (err < 0) {
		dev_err(&priv->ndev->dev,
			"Failed to register memory model(%u)\n", qn);
		xdp_rxq_info_unreg(&q->xdp_rxq);
		goto err_free_ring;
	}

	q->rx_dir = DMA_BIDIRECTIONAL;
	q->rx_dma_offset = XDP_PACKET_HEADROOM;

	/* Init Rx ring */
	rxq_buff = priv->rxq[qn].rx_buff;
	for (i = 0; i < priv->rxq[qn].descr_cnt - 1; i++) {
		priv->rxq[qn].last_alloc = i;
		/* Alloc RAM for RX Data */
		err = net_rxq_alloc_buff(priv, rxq_buff, qn);
		if (err)
			goto err_free_ring;

		err = net_rxq_init_buff(priv, qn, rxq_buff, i);
		if (err)
			goto err_free_ring;

		rxq_buff++;
	}

	return 0;

err_free_ring:
	return err;
} /* net_rxq_init_q */

void net_rxq_clean_q(mxgbe_priv_t *priv, int qn)
{
	int i;
	mxgbe_rx_buff_t *rxq_buff;
	struct mxgbe_queue *q = &priv->rxq[qn];

	rxq_buff = q->rx_buff;
	for (i = 0; i < q->descr_cnt; i++) {
		net_rxq_clean_buff(priv, rxq_buff, qn);
		rxq_buff++;
	}

	if (xdp_rxq_info_is_reg(&q->xdp_rxq))
		xdp_rxq_info_unreg(&q->xdp_rxq);

	if (q->page_pool) {
		page_pool_destroy(q->page_pool);
		q->page_pool = NULL;
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

		err = net_rxq_alloc_buff(priv, rxq_buff, qn);
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

static int mxgbe_rx_csum(mxgbe_ctrl_t *descr_ctrl)
{
	if (((descr_ctrl->RD.TYPE == 4) || (descr_ctrl->RD.TYPE == 5)) &&
	    (descr_ctrl->RD.IPCSUMOK && (descr_ctrl->RD.L4CSUM &&
	    descr_ctrl->RD.L4CSUMOK)))
		return CHECKSUM_UNNECESSARY;

	return CHECKSUM_NONE;
}

/**
 * The Rx function
 * Get one descriptor
 * return 0 for some work done
 */
int mxgbe_net_hw_rx(mxgbe_priv_t *priv, int qn)
{
	struct net_device *ndev = priv->ndev;
	u16 tail_new, tail_hw, tail_cur;
	mxgbe_rx_buff_t *rxq_buff;
	mxgbe_descr_t *descr;
	struct sk_buff *skb;
	mxgbe_addr_t descr_addr;
	mxgbe_ctrl_t descr_ctrl;
	mxgbe_vlan_t descr_vlan;
	void __iomem *base = priv->bar0_base;
	struct bpf_prog *xdp_prog = READ_ONCE(priv->xdp_prog);
	struct mxgbe_queue *q = &priv->rxq[qn];

	tail_cur = q->tail;
	tail_hw = Q_TAIL_GET_PTR(mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_TAIL)));
	if (tail_cur == tail_hw)
		return 0;

	descr = ((mxgbe_descr_t *)(q->que_addr)) + tail_cur;
	descr_addr.r = le64_to_cpu(READ_ONCE(descr->addr.r));
	if (!descr_addr.RD.OWNER)
		return 0;

	/* tail ++ */
	INC_RXQ_INDEX(tail_new, tail_cur, qn);
	priv->rxq[qn].tail = tail_new;

	descr_ctrl.r = le64_to_cpu(READ_ONCE(descr->ctrl.r));

	rxq_buff = q->rx_buff + tail_cur;
	rxq_buff->bytes = descr_ctrl.RD.FRMSIZE + 1;

	dma_sync_single_for_cpu(&priv->pdev->dev,
				dma_unmap_addr(rxq_buff, dma) + q->rx_dma_offset,
				dma_unmap_len(rxq_buff, len) - q->rx_dma_offset,
				q->rx_dir);

	if (xdp_prog) {
		struct xdp_buff xdp;
		unsigned char *data;

		xdp_init_buff(&xdp, (MXGBE_MTU + MXGBE_ETH_LEN), &q->xdp_rxq);

		xdp.data_hard_start = page_address(rxq_buff->page);
		data = (u8 *)xdp.data_hard_start + q->rx_dma_offset;
		xdp.data = (void *)data;
		xdp.data_end = (void *)(data + rxq_buff->bytes);
		xdp.data_meta = (void *)(data + 1);

		if (mxgbe_run_xdp(xdp_prog, &xdp, priv, rxq_buff, qn)) {
			rxq_buff->bytes = 0;
			reinit_rxbuf_descr(priv, qn, tail_cur);
			return 1;
		}
	}

	dma_unmap_page(&priv->pdev->dev,
		       dma_unmap_addr(rxq_buff, dma),
		       dma_unmap_len(rxq_buff, len),
		       q->rx_dir);
	skb = build_skb(page_address(rxq_buff->page), dma_unmap_len(rxq_buff, len));
	dma_unmap_len_set(rxq_buff, len, 0);

	if (!skb) {
		page_pool_recycle_direct(q->page_pool, rxq_buff->page);
		rxq_buff->bytes = 0;
		rxq_buff->page = NULL;
		reinit_rxbuf_descr(priv, qn, tail_cur);

		return 1;
	}
	rxq_buff->page = NULL;
	skb_mark_for_recycle(skb);
	skb_reserve(skb, q->rx_dma_offset);
	skb_put(skb, rxq_buff->bytes);
	skb->dev = ndev;

	reinit_rxbuf_descr(priv, qn, tail_cur);

	if (skb->len < (MXGBE_ETH_LEN)) {
		dev_kfree_skb_any(skb);

		return 1;
	}

	if (((descr_ctrl.RD.TYPE == 4) || (descr_ctrl.RD.TYPE == 5)) &&
	    (!descr_ctrl.RD.IPCSUMOK || (descr_ctrl.RD.L4CSUM &&
	    !descr_ctrl.RD.L4CSUMOK))) {
		dev_kfree_skb_any(skb);
		u64_stats_update_begin(&priv->stats.syncp);
		priv->stats.rx_crc_errors++;
		u64_stats_update_end(&priv->stats.syncp);

		return 1;
	}
	skb->ip_summed = mxgbe_rx_csum(&descr_ctrl);

	descr_vlan.r = le64_to_cpu(READ_ONCE(descr->vlan.r));

	if ((descr_vlan.RD.OVLAN) &&
	    (ndev->features & NETIF_F_HW_VLAN_CTAG_FILTER)) {
		/* Drop 802.1AD if there is the VLAN(802.1Q) filtering table only */
		dev_kfree_skb_any(skb);

		return 1;
	}

	skb->protocol = eth_type_trans(skb, ndev);
	napi_gro_receive(&(priv->vector[qn].napi), skb);

	return 1;
} /* mxgbe_net_hw_rx */


/**
 * called from hw irq handler
 */
void mxgbe_net_rx_irq_handler(mxgbe_vector_t *vector)
{
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
	struct mxgbe_queue *q;

	vector = container_of(napi, mxgbe_vector_t, napi);
	qn = vector->qn;
	priv = vector->priv;
	q = &priv->rxq[qn];
	base = priv->bar0_base;

	while (mxgbe_net_hw_rx(priv, qn)) {
		work_done++;
		if (work_done >= budget) {
			if (q->xdp_xmit & MXGBE_XDP_REDIR)
				xdp_do_flush();

			return work_done;
		}
	}

	if (likely(napi_complete_done(&vector->napi, work_done))) {
		/* NAPI: Enable IRQ */
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ),
			     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);
	}

	if (q->xdp_xmit & MXGBE_XDP_REDIR)
		xdp_do_flush();

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
	struct sk_buff *skb = NULL;
	struct xdp_frame *xdpf = NULL;
	dma_addr_t dma = 0;
	int len = 0;
	enum mxgbe_buff_type type = tx_buff->type;

	if (type == MXGBE_TYPE_SKB) {
		if (tx_buff->skb == NULL)
			return;
		skb = tx_buff->skb;
	} else {
		if (tx_buff->xdpf == NULL)
			return;
		xdpf = tx_buff->xdpf;
	}
	tx_buff->skb = NULL;

	len = dma_unmap_len(tx_buff, len);
	if (len) {
		dma = dma_unmap_addr(tx_buff, dma);
		dma_unmap_len_set(tx_buff, len, 0);
	}

	if (skb)
		dev_kfree_skb_any(skb);

	if (xdpf) {
		if (type == MXGBE_TYPE_XDP_TX)
			xdp_return_frame_rx_napi(xdpf);
		else
			xdp_return_frame(xdpf);
	}

	if (dma && len) {
		if (type == MXGBE_TYPE_XDP_TX)
			dma_unmap_page(&priv->pdev->dev,
				       dma, len, DMA_BIDIRECTIONAL);
		else
			dma_unmap_single(&priv->pdev->dev,
					 dma, len, DMA_TO_DEVICE);
	}

	tx_buff->bytes = 0;
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

	spin_lock(&priv->txq[qn].tlock);
	tail = Q_TAIL_GET_PTR(mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_TAIL)));

	cur_tail = READ_ONCE(priv->txq[qn].tail);
	if (cur_tail == tail) {
		spin_unlock(&priv->txq[qn].tlock);
		return 0; /* DONE */
	}

	priv->txq[qn].tail = tail;

	while (cur_tail != tail) {
		tx_buff = &priv->txq[qn].tx_buff[cur_tail];
		if (tx_buff)
			mxgbe_net_tx_confirm(priv, qn, tx_buff);

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

	vector = container_of(napi, mxgbe_vector_t, napi);
	qn = vector->qn;
	priv = vector->priv;
	base = priv->bar0_base;

	while (mxgbe_txq_confirm(priv, qn)) {
		work_done++;
		if (work_done >= budget) {
			return work_done;
		}
	}

	if (likely(napi_complete_done(&vector->napi, work_done))) {
		/* NAPI: Enable IRQ */
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ),
			     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);
	}

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
	struct net_device *ndev = priv->ndev;

	if (mxgbe_loopback_mode) {
		if (netif_carrier_ok(ndev))
			return;
		netif_carrier_on(ndev);
		return;
	}

	if (state == priv->carrier)
		return;

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

int mxgbe_tx_q_mapping(mxgbe_priv_t *priv, struct sk_buff *skb)
{
	unsigned int r_idx;

	r_idx = (skb == NULL) ? 0 : skb->queue_mapping;

	if (r_idx >= priv->num_tx_queues)
		r_idx = r_idx % priv->num_tx_queues;

	return r_idx;
} /* mxgbe_tx_q_mapping */

static int mxgbe_get_tx_ip_csum_flag(struct sk_buff *skb)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL)
		return 0;
	if (!((skb->protocol == htons(ETH_P_IP)) ||
	      (skb->protocol == htons(ETH_P_8021Q))))
		goto calc_sum;
	if (ip_is_fragment(ip_hdr(skb)))
		goto calc_sum;

	ip_hdr(skb)->check = 0;
	return 1;

calc_sum:
	skb_checksum_help(skb);

	return 0;
}

static int mxgbe_get_tx_l4_csum_flag(struct sk_buff *skb)
{
	if (!mxgbe_get_tx_ip_csum_flag(skb))
		return 0;

	if (skb->csum_offset == offsetof(struct tcphdr, check)) {
		tcp_hdr(skb)->check = 0;
		return 1;
	}
	if (skb->csum_offset == offsetof(struct udphdr, check)) {
		udp_hdr(skb)->check = 0;
		return 1;
	}

	skb_checksum_help(skb);
	ip_hdr(skb)->check = 0;

	return 0;
}

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
	ssize_t size = skb->len;
	int nq;
	int ipv6 = 0;
	int ipcsum = 0;
	int l4csum = 0;
	int ntcp_udp = 0;
	int iphdr = 0;
	int tcphdr = 0;
	int l4hdr = 0;

	if (size > MXGBE_MTU)
		goto tx_free_skb;

	if (skb_put_padto(skb, ETH_ZLEN))
		goto tx_free_skb;

	if (netif_queue_stopped(ndev))
		goto tx_free_skb;

	priv = netdev_priv(ndev);

	nq = mxgbe_tx_q_mapping(priv, skb);

	if (__netif_subqueue_stopped(ndev, nq))
		goto tx_free_skb;

	dmaaddr = dma_map_single(&priv->pdev->dev, skb->data, size, DMA_TO_DEVICE);
	if (dma_mapping_error(&priv->pdev->dev, dmaaddr))
		goto tx_free_skb;

	txq_trans_cond_update(netdev_get_tx_queue(ndev, nq));

	if ((skb->protocol == htons(ETH_P_IP)) ||
	    (skb->protocol == htons(ETH_P_8021Q))) {
		if (skb->protocol == htons(ETH_P_8021Q)) {
			struct vlan_ethhdr *ethhdr = vlan_eth_hdr(skb);

			if (ethhdr->h_vlan_encapsulated_proto != htons(ETH_P_IP))
				goto no_hwcs;
		}
		ipv6 = 0; /* ipv4 */
		iphdr = skb_network_header(skb) - skb->data - 1;
		l4hdr = ip_hdr(skb)->ihl - 1;
		switch (ip_hdr(skb)->protocol) {
		case IPPROTO_UDP:
			ntcp_udp = 1;
			break;
		case IPPROTO_TCP:
			ntcp_udp = 0;
			break;
		default:
			l4hdr = 0;
			iphdr = 0; /* as a 'raw' packet */
		}
	}

	if (iphdr) {
		ipcsum = mxgbe_get_tx_ip_csum_flag(skb);
		l4csum = mxgbe_get_tx_l4_csum_flag(skb);
	}

no_hwcs:

	/* Create descriptor */
	descr.ctrl.r = 0;
	descr.ctrl.TC.IPV6 = ipv6;
	descr.ctrl.TC.IPCSUM = ipcsum;
	descr.ctrl.TC.L4CSUM = l4csum;
	descr.ctrl.TC.NTCP_UDP = ntcp_udp;
	descr.ctrl.TC.TCPHDR = tcphdr;
	descr.ctrl.TC.IPHDR = iphdr;
	descr.ctrl.TC.L4HDR = l4hdr;
	descr.ctrl.TC.BUFSIZE = (size >> 3); /* QWORDs - 1 */
	descr.ctrl.TC.MSS = TC_MSS_NOSPLIT;
	descr.ctrl.TC.FRMSIZE = size - 1;

	descr.addr.r = 0;
	descr.addr.TC.BUFPTR = (u64)dmaaddr;
	descr.addr.TC.SPLIT = TC_SPLIT_NO;
	descr.addr.TC.OWNER = XX_OWNER_HW;

	descr.vlan.r = 0;
	descr.time.r = 0;

	if (iphdr && (ndev->vlan_features & NETIF_F_IP_CSUM) &&
	    (skb->protocol == htons(ETH_P_8021Q))) {
		u16 vid;
		struct vlan_hdr *vhdr, _vhdr;
		struct vlan_ethhdr *ethhdr;

		vhdr = skb_header_pointer(skb, ETH_HLEN, sizeof(_vhdr), &_vhdr);
		if (!vhdr)
			goto dma_unmap_skb;

		vid = ntohs(vhdr->h_vlan_TCI);
		ethhdr = vlan_eth_hdr(skb);
		ethhdr->h_vlan_proto = 0;
		ethhdr->h_vlan_TCI = 0;
		descr.vlan.TC.IVLAN = vid;
		descr.vlan.TC.SIVLAN = 1;
	}

	dma_unmap_len_set(&tx_buff, len, size);
	dma_unmap_addr_set(&tx_buff, dma, dmaaddr);
	tx_buff.type = MXGBE_TYPE_SKB;
	tx_buff.skb = skb;
	tx_buff.bytes = size;

	ret = mxgbe_txq_send(priv, nq, &descr, &tx_buff);
	if (ret < 0)
		goto dma_unmap_skb;

	return NETDEV_TX_OK;

dma_unmap_skb:
	dma_unmap_single(&priv->pdev->dev,
			 dmaaddr, size, DMA_TO_DEVICE);
tx_free_skb:
	u64_stats_update_begin(&priv->stats.syncp);
	priv->stats.tx_dropped++;
	u64_stats_update_end(&priv->stats.syncp);
	dev_kfree_skb_any(skb);

	return NETDEV_TX_OK;
} /* mxgbe_start_xmit */


/**
 * The network interface open function
 * @ndev: network interface device structure
 *
 * mxgbe_open is called by register_netdev
 */
int mxgbe_open(struct net_device *ndev)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	int qn;
	int node;

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
int mxgbe_stop(struct net_device *ndev)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	int qn;
	int node;

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


static void mxgbe_dump_rx_queue(struct net_device *ndev, unsigned int qn)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	int i;
	mxgbe_descr_t *descr;
	mxgbe_addr_t descr_addr;
	mxgbe_ctrl_t descr_ctrl;
	struct mxgbe_queue *q = &priv->rxq[qn];
	u16	head = Q_HEAD_GET_PTR(mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_HEAD)));
	u16 tail = Q_TAIL_GET_PTR(mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_TAIL)));

	dev_warn(&priv->pdev->dev, "RX %d: head=%d tail=%d\n", qn, head, tail);
	for (i = 0; i < q->descr_cnt - 1; i++) {
		descr = ((mxgbe_descr_t *)(q->que_addr)) + i;
		descr_ctrl.r = le64_to_cpu(READ_ONCE(descr->ctrl.r));
		descr_addr.r = le64_to_cpu(READ_ONCE(descr->addr.r));
		dev_warn(&priv->pdev->dev, "\t%d 0x%llx 0x%llx\n", i, descr_ctrl.r, descr_addr.r);
	}
}

static void mxgbe_dump_rx_queues(struct net_device *ndev)
{
	int qn;
	mxgbe_priv_t *priv = netdev_priv(ndev);

	for (qn = 0; qn < priv->num_rx_queues; qn++)
		mxgbe_dump_rx_queue(ndev, qn);
}

static void mxgbe_dump_tx_queue(struct net_device *ndev, unsigned int qn)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	int i;
	mxgbe_descr_t *descr;
	mxgbe_addr_t descr_addr;
	mxgbe_ctrl_t descr_ctrl;
	struct mxgbe_queue *q = &priv->txq[qn];
	u16 head = Q_HEAD_GET_PTR(mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_HEAD)));
	u16 tail = Q_TAIL_GET_PTR(mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_TAIL)));

	dev_warn(&priv->pdev->dev, "TX %d: head=%d tail=%d\n", qn, head, tail);
	for (i = 0; i < q->descr_cnt - 1; i++) {
		descr = ((mxgbe_descr_t *)(q->que_addr)) + i;
		descr_ctrl.r = le64_to_cpu(READ_ONCE(descr->ctrl.r));
		descr_addr.r = le64_to_cpu(READ_ONCE(descr->addr.r));
		dev_warn(&priv->pdev->dev, "\t%d 0x%llx 0x%llx\n", i, descr_ctrl.r, descr_addr.r);
	}
}

static void mxgbe_dump_tx_queues(struct net_device *ndev)
{
	int qn;
	mxgbe_priv_t *priv = netdev_priv(ndev);

	for (qn = 0; qn < priv->num_tx_queues; qn++)
		mxgbe_dump_tx_queue(ndev, qn);
}

static int mxgbe_ioctl_private(struct net_device *ndev, struct ifreq *rq,
			       void __user *data, int cmd)
{
	int rc = -EOPNOTSUPP;

	switch (cmd) {
	case SIOCDEVPRIVATE + 10:
		mxgbe_dump_tx_queues(ndev);
		mxgbe_dump_rx_queues(ndev);
		return 0;
	default:
		break;
	}

	return rc;
}

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

static void mxgbe_get_stats64(struct net_device *ndev,
			      struct rtnl_link_stats64 *stats)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	unsigned int start;

	stats->tx_packets = mxgbe_rreg64c(base, TX_PACK_CNT);
	stats->tx_bytes = mxgbe_rreg64c(base, TX_BYTE_CNT);
	stats->rx_packets = mxgbe_rreg64c(base, RX_PACK_CNT);
	stats->rx_bytes = mxgbe_rreg64c(base, RX_BYTE_CNT);
	stats->rx_errors = mxgbe_rreg64c(base, RX_ERR_CNT);
	stats->rx_dropped = mxgbe_rreg64c(base, RX_FILT_CNT);
	stats->rx_over_errors = mxgbe_rreg64c(base, RX_DROP_CNT);

	do {
		start = u64_stats_fetch_begin(&priv->stats.syncp);
		stats->tx_dropped = priv->stats.tx_dropped;
		stats->rx_crc_errors = priv->stats.rx_crc_errors;
	} while (u64_stats_fetch_retry(&priv->stats.syncp, start));
}

static int mxgbe_change_mtu(struct net_device *ndev, int new_mtu)
{
	int old_mtu = ndev->mtu;

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

	if (netif_running(ndev))
		return -EBUSY;

	eth_hw_addr_set(ndev, addr->sa_data);

	return 0;
} /* mxgbe_set_mac_addr */


static int mxgbe_xdp_xmit(struct net_device *dev, int n,
			  struct xdp_frame **xdpfs, u32 xdp_flags)
{
	mxgbe_priv_t *priv = netdev_priv(dev);
	struct bpf_prog *xdp_prog = READ_ONCE(priv->xdp_prog);
	int qn = mxgbe_tx_q_mapping(priv, NULL);
	int nxmit = 0;
	int i;

	if (__netif_subqueue_stopped(dev, qn))
		return -ENETDOWN;

	if (!xdp_prog)
		return -EINVAL;

	txq_trans_cond_update(netdev_get_tx_queue(dev, qn));

	for (i = 0; i < n; i++) {
		struct xdp_frame *xdpf = xdpfs[i];

		if (mxgbe_xdp_xmit_to_q(xdpf, priv, qn, true))
			break;
		nxmit++;
	}

	priv->ethtool_stats.xdp_xmit += nxmit;
	priv->ethtool_stats.xdp_xmit_err += n - nxmit;

	return nxmit;
} /* mxgbe_xdp_xmit */

static int mxgbe_xdp_setup(struct net_device *dev, struct netdev_bpf *bpf)
{
	mxgbe_priv_t *priv = netdev_priv(dev);
	struct bpf_prog *prog = bpf->prog, *old_prog;
	bool running = netif_running(dev);
	bool need_update;
	int frame_size = dev->mtu + MXGBE_ETH_LEN;
	int max_xdp_bufsz = MXGBE_MTU + MXGBE_ETH_LEN;

	if (frame_size > max_xdp_bufsz) {
		netdev_warn(dev, "XDP RX buffer size %d is too small for the frame size %d\n",
			    max_xdp_bufsz, frame_size);
		return -EOPNOTSUPP;
	}

	need_update = (!!prog != !!priv->xdp_prog);

	if (running && need_update)
		mxgbe_stop(dev);

	old_prog = xchg(&priv->xdp_prog, prog);
	if (old_prog)
		bpf_prog_put(old_prog);

	if (running && need_update)
		mxgbe_open(dev);

	return 0;
} /* mxgbe_xdp_setup */

static int mxgbe_bpf(struct net_device *dev, struct netdev_bpf *bpf)
{
	switch (bpf->command) {
	case XDP_SETUP_PROG:
		return mxgbe_xdp_setup(dev, bpf);
	default:
		return -EINVAL;
	}
} /* mxgbe_bpf */

static void mxgbe_rxall_mode(mxgbe_priv_t *priv,
			     netdev_features_t features)
{
	void __iomem *base = priv->bar0_base;
	u32 val;

	if (features & NETIF_F_RXALL) {
		mxgbe_wreg32(base, MAC_RAW, (MAC_RAW_RX_BAD_FCS | MAC_RAW_RX_SHORT64));
		val = mxgbe_rreg32(base, RX_CTRL);
		val |= RX_CTRL_RAWMODE;
		mxgbe_wreg32(base, RX_CTRL, val);
	} else {
		mxgbe_wreg32(base, MAC_RAW, 0);
		val = mxgbe_rreg32(base, RX_CTRL);
		val &= ~RX_CTRL_RAWMODE;
		mxgbe_wreg32(base, RX_CTRL, val);
	}
}

static int mxgbe_set_features(struct net_device *dev,
			      netdev_features_t features)
{
	mxgbe_priv_t *priv = netdev_priv(dev);
	netdev_features_t changed = dev->features ^ features;

	if (changed & NETIF_F_RXALL)
		mxgbe_rxall_mode(priv, features);

	return 0;
}

static netdev_features_t mxgbe_fix_features(struct net_device *dev,
					    netdev_features_t features)
{
	return features;
}

static int mxgbe_vlan_rx_add_vid(struct net_device *dev,
				 __be16 proto, u16 vid)
{
	mxgbe_priv_t *priv = netdev_priv(dev);
	int gidx;
	int bidx;
	union mxgbe_vf_group *vfg;

	if (!(dev->features & NETIF_F_HW_VLAN_CTAG_FILTER))
		return -EOPNOTSUPP;

	netdev_info(dev, "Adding VLAN %d\n", vid);

	gidx = vid / 4;

	if (gidx > RX_VLANFILT_TBLSIZE - 1)
		return -EINVAL;

	bidx = vid % 4;
	vfg = &priv->vft[gidx];

	switch (bidx) {
	case 0:
		vfg->qblock.block0 = RX_VF_4B_ACCEPT;
		break;
	case 1:
		vfg->qblock.block1 = RX_VF_4B_ACCEPT;
		break;
	case 2:
		vfg->qblock.block2 = RX_VF_4B_ACCEPT;
		break;
	case 3:
		vfg->qblock.block3 = RX_VF_4B_ACCEPT;
		break;
	default:
		return -EINVAL;
	}

	mxgbe_rx_update_vlanfilt(priv, gidx, vfg->group);

	return 0;
}

static int mxgbe_vlan_rx_kill_vid(struct net_device *dev,
				  __be16 proto, u16 vid)
{
	mxgbe_priv_t *priv = netdev_priv(dev);
	int gidx;
	int bidx;
	union mxgbe_vf_group *vfg;

	if (!(dev->features & NETIF_F_HW_VLAN_CTAG_FILTER))
		return -EOPNOTSUPP;

	netdev_info(dev, "Removing VLAN %d\n", vid);

	gidx = vid / 4;

	if (gidx > RX_VLANFILT_TBLSIZE - 1)
		return -EINVAL;

	bidx = vid % 4;
	vfg = &priv->vft[gidx];

	switch (bidx) {
	case 0:
		vfg->qblock.block0 = RX_VF_4B_DROP;
		break;
	case 1:
		vfg->qblock.block1 = RX_VF_4B_DROP;
		break;
	case 2:
		vfg->qblock.block2 = RX_VF_4B_DROP;
		break;
	case 3:
		vfg->qblock.block3 = RX_VF_4B_DROP;
		break;
	default:
		return -EINVAL;
	}

	mxgbe_rx_update_vlanfilt(priv, gidx, vfg->group);

	return 0;
}

static void mxgbe_vlan_promisc_enable(mxgbe_priv_t *priv)
{
	int i;

	for (i = 0; i < RX_VLANFILT_TBLSIZE; i++) {
		/* Accept frames */
		mxgbe_rx_update_vlanfilt(priv, i, RX_VF_16B_ACCEPT);
	}
}

static void mxgbe_vlan_promisc_disable(mxgbe_priv_t *priv)
{
	int i;

	for (i = 0; i < RX_VLANFILT_TBLSIZE; i++) {
		/* Restore the vlan filter table */
		mxgbe_rx_update_vlanfilt(priv, i, priv->vft[i].group);
	}
}

static void mxgbe_set_rx_mode(struct net_device *ndev)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	netdev_features_t features = ndev->features;

	if (ndev->flags & IFF_PROMISC)
		features &= ~NETIF_F_HW_VLAN_CTAG_FILTER;

	if (features & NETIF_F_HW_VLAN_CTAG_FILTER)
		mxgbe_vlan_promisc_disable(priv);
	else
		mxgbe_vlan_promisc_enable(priv);
}

/**
 * net_device_ops
 */
const struct net_device_ops mxgbe_netdev_ops = {
	.ndo_open		= mxgbe_open,
	.ndo_stop		= mxgbe_stop,
	.ndo_start_xmit		= mxgbe_start_xmit,
	.ndo_set_rx_mode	= mxgbe_set_rx_mode,
	.ndo_set_features	= mxgbe_set_features,
	.ndo_fix_features	= mxgbe_fix_features,
	.ndo_vlan_rx_add_vid	= mxgbe_vlan_rx_add_vid,
	.ndo_vlan_rx_kill_vid	= mxgbe_vlan_rx_kill_vid,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= mxgbe_set_mac_addr,
	.ndo_change_mtu		= mxgbe_change_mtu,
	.ndo_do_ioctl		= mxgbe_ioctl,
	.ndo_siocdevprivate	= mxgbe_ioctl_private,
	.ndo_get_stats64	= mxgbe_get_stats64,
	.ndo_bpf		= mxgbe_bpf,
	.ndo_xdp_xmit		= mxgbe_xdp_xmit,
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

static void mxgbe_vft_init(mxgbe_priv_t *priv)
{
	struct net_device *ndev = priv->ndev;
	int i;

	/* Populate a VLAN filtering table */
	for (i = 0; i < RX_VLANFILT_TBLSIZE; i++) {
		if (ndev->features & NETIF_F_HW_VLAN_CTAG_FILTER) {
			/* Drop frames */
			priv->vft[i].group = RX_VF_16B_DROP;
		} else {
			/* Accept frames */
			priv->vft[i].group = RX_VF_16B_ACCEPT;
		}
		mxgbe_rx_update_vlanfilt(priv, i, priv->vft[i].group);
	}
}

int mxgbe_net_register(mxgbe_priv_t *priv)
{
	int ret = 0;
	struct net_device *ndev = priv->ndev;
	int qn;

	ndev->netdev_ops = &mxgbe_netdev_ops;
	ndev->watchdog_timeo = MXGBE_WATCHDOG_PERIOD;
	mxgbe_set_ethtool_ops(ndev);

	ndev->min_mtu = ETH_MIN_MTU;
	ndev->max_mtu = MXGBE_MTU;

	/* create napi for all queue */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		netif_napi_add(ndev, &(priv->vector[qn].napi),
			       mxgbe_poll_rx);
	}
	for (qn = priv->num_rx_queues; qn < (priv->num_rx_queues +
					     priv->num_tx_queues); qn++) {
		netif_napi_add(ndev, &(priv->vector[qn].napi),
			       mxgbe_poll_tx);
	}

	/* link off */
	netif_carrier_off(ndev);

	if (ret = mxgbe_mdio_register(priv)) {
		dev_err(&priv->pdev->dev,
			"Cannot register mdio bus, aborting\n");
		goto err_out_free_rxq;
	}

	/* set MAC from EEPROM */
	eth_hw_addr_set(ndev, (char *)(&priv->MAC));

	priv->carrier = (u32)-1;

	if (ret = register_netdev(ndev)) {
		dev_err(&priv->pdev->dev,
			"Cannot register net device, aborting\n");
		goto err_out_mdiobus;
	}

	priv->hw_features = NETIF_F_IP_CSUM |
				NETIF_F_HW_VLAN_CTAG_FILTER;
	ndev->features = priv->hw_features;
	/* list of user selectable features */
	ndev->hw_features = NETIF_F_RXALL;
	ndev->vlan_features = NETIF_F_IP_CSUM;

	mxgbe_vft_init(priv);

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

int mxgbe_net_reinit(mxgbe_priv_t *priv)
{
	int ret = 0;
	struct net_device *ndev = priv->ndev;
	int qn;

	mxgbe_vft_init(priv);

	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		if (net_rxq_init_q(priv, qn)) {
			dev_err(&priv->pdev->dev,
				"ERROR: DMA_ALLOC_RAM qn=%d\n", qn);
			ret = -ENOMEM;
			goto err_out;
		}
	}

	dev_info(&priv->pdev->dev, "network interface %s reinit\n",
		 dev_name(&ndev->dev));

	return 0;

err_out:

	return ret;
} /* mxgbe_net_reinit */

void mxgbe_net_remove(mxgbe_priv_t *priv)
{
	int qn;
	struct net_device *ndev = priv->ndev;

	netif_stop_queue(ndev);

	/* link off */
	mxgbe_mac_event_dis(priv);
	netif_carrier_off(ndev);

	/* Free RAM for RX Data */
	for (qn = 0; qn < priv->num_rx_queues; qn++)
		net_rxq_clean_q(priv, qn);

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

