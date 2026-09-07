/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_xdp.c - MXGBE module device driver
 *
 * XDP part
 */

#include "mxgbe.h"
#include "mxgbe_hw.h"
#include "mxgbe_txq.h"
#include "mxgbe_rxq.h"
#include "mxgbe_phy.h"
#include "mxgbe_mac.h"
#include "mxgbe_dbg.h"
#include "mxgbe_xdp.h"

static int mxgbe_xdp_xmit_back(mxgbe_priv_t *priv, int qn, struct xdp_buff *xdp)
{
	struct xdp_frame *xdpf;
	int rc = 1;

	xdpf = xdp_convert_buff_to_frame(xdp);
	if (unlikely(!xdpf))
		return rc;

	txq_trans_cond_update(netdev_get_tx_queue(priv->ndev, qn));
	rc = mxgbe_xdp_xmit_to_q(xdpf, priv, qn, false);

	return rc;
}

static void mxgbe_put_rx_buff(mxgbe_priv_t *priv,
			      mxgbe_buff_t *rxq_buff, int qn)
{
	struct mxgbe_queue *q;

	if (!rxq_buff->page)
		return;

	q = &priv->rxq[qn];
	page_pool_recycle_direct(q->page_pool, rxq_buff->page);
	rxq_buff->page = NULL;
	if (dma_unmap_len(rxq_buff, len)) {
		dma_unmap_page(&priv->pdev->dev,
			       dma_unmap_addr(rxq_buff, dma),
			       dma_unmap_len(rxq_buff, len),
			       q->rx_dir);
	}
	dma_unmap_len_set(rxq_buff, len, 0);
}

int mxgbe_run_xdp(struct bpf_prog *prog,
		  struct xdp_buff *xdp, mxgbe_priv_t *priv,
		  mxgbe_buff_t *rxq_buff, int qn)
{
	int act = bpf_prog_run_xdp(prog, xdp);
	struct mxgbe_queue *q = &priv->rxq[qn];
	int rc;

	switch (act) {
	case XDP_PASS:
		priv->ethtool_stats.xdp_pass++;
		return 0;
	case XDP_TX:
		page_pool_set_dma_addr(rxq_buff->page,
				       dma_unmap_addr(rxq_buff, dma));
		rc = mxgbe_xdp_xmit_back(priv, qn, xdp);
		if (unlikely(rc)) {
			priv->ethtool_stats.xdp_tx_err++;
			page_pool_set_dma_addr(rxq_buff->page, 0);
			mxgbe_put_rx_buff(priv, rxq_buff, qn);
		} else {
			priv->ethtool_stats.xdp_tx++;
			rxq_buff->page = NULL;
			dma_unmap_len_set(rxq_buff, len, 0);
		}
		return 1;
	case XDP_REDIRECT:
		if (dma_unmap_len(rxq_buff, len)) {
			dma_unmap_page(&priv->pdev->dev,
				       dma_unmap_addr(rxq_buff, dma),
				       dma_unmap_len(rxq_buff, len),
				       q->rx_dir);
		}
		dma_unmap_len_set(rxq_buff, len, 0);
		rc = xdp_do_redirect(priv->ndev, xdp, prog);
		if (unlikely(rc)) {
			priv->ethtool_stats.xdp_redirect_err++;
			mxgbe_put_rx_buff(priv, rxq_buff, qn);
		} else {
			priv->ethtool_stats.xdp_redirect++;
			rxq_buff->page = NULL;
			q->xdp_xmit |= MXGBE_XDP_REDIR;
		}
		return 1;
	default:
		bpf_warn_invalid_xdp_action(priv->ndev, prog, act);
		fallthrough;
	case XDP_ABORTED:
		trace_xdp_exception(priv->ndev, prog, act);
		fallthrough;
	case XDP_DROP:
		mxgbe_put_rx_buff(priv, rxq_buff, qn);
		priv->ethtool_stats.xdp_drop++;
		break;
	}
	return 1;
}

static int mxgbe_xdp_get_tx_ip_csum_flag(struct ethhdr *eth)
{
	struct iphdr *iph = NULL;

	if (!eth)
		return 0;

	if (unlikely(!eth_proto_is_802_3(eth->h_proto)))
		return 0;

	if (eth->h_proto == htons(ETH_P_IP)) {
		iph = (struct iphdr *)(eth + 1);
		iph->check = 0;

		return 1;
	}

	return 0;
}

static int mxgbe_xdp_get_tx_l4_csum_flag(struct ethhdr *eth)
{
	struct iphdr *iph;
	u8 ip_proto;

	if (!mxgbe_xdp_get_tx_ip_csum_flag(eth))
		return 0;

	iph = (struct iphdr *)(eth + 1);
	ip_proto = iph->protocol;

	if (ip_proto == IPPROTO_TCP) {
		struct tcphdr *tcph;

		tcph = (struct tcphdr *)(iph + 1);
		tcph->check = 0;

		return 1;
	} else if (ip_proto == IPPROTO_UDP) {
		struct udphdr *udph;

		udph = (struct udphdr *)(iph + 1);
		udph->check = 0;

		return 1;
	}

	return 0;
}

int mxgbe_xdp_xmit_to_q(struct xdp_frame *xdpf,
			mxgbe_priv_t *priv, int qn, bool ndo)
{
	int		ret;
	int		nq;
	mxgbe_buff_t	tx_buff;
	mxgbe_descr_t	descr;
	u32		len = xdpf->len;
	void	*data;
	dma_addr_t	dma;
	u32		offset = 0;
	int		ipv6 = 0;
	int		ipcsum = 0;
	int		l4csum = 0;
	int		ntcp_udp = 0;
	int		iphdr = 0;
	int		tcphdr = 0;
	int		l4hdr = 0;
	struct ethhdr *eth;
	struct iphdr *iph;

	if (ndo) {
		nq = mxgbe_tx_q_mapping(priv, NULL);
		data = xdpf->data;
		dma = dma_map_single(&priv->pdev->dev, data,
				     len, DMA_TO_DEVICE);
		if (dma_mapping_error(&priv->pdev->dev, dma))
			return 1;

		dma_unmap_len_set(&tx_buff, len, len);
		dma_unmap_addr_set(&tx_buff, dma, dma);
		tx_buff.type = MXGBE_TYPE_XDP;
	} else {
		struct page *page = virt_to_page(xdpf->data);

		nq = qn;
		dma = page_pool_get_dma_addr(page);
		if (unlikely(!dma))
			return 1;

		page_pool_set_dma_addr(page, 0);
		dma_unmap_len_set(&tx_buff, len, MXGBE_MAXFRAMESIZE);
		dma_unmap_addr_set(&tx_buff, dma, dma);
		offset = sizeof(*xdpf) + xdpf->headroom;
		dma += offset;
		dma_sync_single_for_device(&priv->pdev->dev, dma, len,
					   DMA_BIDIRECTIONAL);
		tx_buff.type = MXGBE_TYPE_XDP_TX;
	}
	tx_buff.bytes = len;
	tx_buff.xdpf = xdpf;

	eth = (struct ethhdr *)xdpf->data;

	if (eth_proto_is_802_3(eth->h_proto) &&
	    (eth->h_proto == htons(ETH_P_IP))) {
		ipv6 = 0; /* ipv4 */
		iph = (struct iphdr *)(eth + 1);
		iphdr = (char *)(eth + 1) - (char *)xdpf->data - 1;
		l4hdr = iph->ihl - 1;
		switch (iph->protocol) {
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
		ipcsum = mxgbe_xdp_get_tx_ip_csum_flag(eth);
		l4csum = mxgbe_xdp_get_tx_l4_csum_flag(eth);
	}

	/* Create descriptor */
	descr.ctrl.r = 0;
	descr.ctrl.TC.IPV6 = ipv6;
	descr.ctrl.TC.IPCSUM = ipcsum;
	descr.ctrl.TC.L4CSUM = l4csum;
	descr.ctrl.TC.NTCP_UDP = ntcp_udp;
	descr.ctrl.TC.TCPHDR = tcphdr;
	descr.ctrl.TC.IPHDR = iphdr;
	descr.ctrl.TC.L4HDR = l4hdr;
	descr.ctrl.TC.BUFSIZE = (len >> 3); /* QWORDs - 1 */
	descr.ctrl.TC.MSS = TC_MSS_NOSPLIT;
	descr.ctrl.TC.FRMSIZE = len - 1;

	descr.addr.r = 0;
	descr.addr.TC.BUFPTR = (u64)dma;
	descr.addr.TC.SPLIT = TC_SPLIT_NO;
	descr.addr.TC.OWNER = XX_OWNER_HW;

	descr.vlan.r = 0;
	descr.time.r = 0;

	ret = mxgbe_txq_send(priv, nq, &descr, &tx_buff);

	if (ret < 0) {
		if (tx_buff.type == MXGBE_TYPE_XDP_TX) {
			dma_unmap_page(&priv->pdev->dev,
				       dma_unmap_addr(&tx_buff, dma),
				       dma_unmap_len(&tx_buff, len),
				       DMA_BIDIRECTIONAL);
			xdp_return_frame_rx_napi(tx_buff.xdpf);
		} else {
			dma_unmap_single(&priv->pdev->dev,
					 dma_unmap_addr(&tx_buff, dma),
					 dma_unmap_len(&tx_buff, len),
					 DMA_TO_DEVICE);
			xdp_return_frame(tx_buff.xdpf);
		}
		return 1;
	}
	return 0;
}
