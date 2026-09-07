/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_ethtool.c - MXGBE module device driver
 *
 * Network part - ethtool support
 */

#include "mxgbe.h"
#include "mxgbe_mac.h"
#include "mxgbe_hw.h"
#include "mxgbe_dbg.h"
#include "mxgbe_rxq.h"
#include "mxgbe_txq.h"


static int mxgbe_get_link_ksettings(struct net_device *ndev,
			struct ethtool_link_ksettings *ecmd)
{
	u32 supported;

	ecmd->base.speed = 10000;
	ecmd->base.duplex = DUPLEX_FULL;
	ecmd->base.port = PORT_AUI; /* ? */
	ecmd->base.autoneg = AUTONEG_ENABLE;

	supported = SUPPORTED_10000baseT_Full | SUPPORTED_Pause;
	ethtool_convert_legacy_u32_to_link_mode(ecmd->link_modes.supported,
						supported);

	return 0;
}

static int mxgbe_set_link_ksettings(struct net_device *ndev,
			const struct ethtool_link_ksettings *ecmd)
{
	return 0;
}

static void mxgbe_get_pauseparam(struct net_device *ndev,
				 struct ethtool_pauseparam *pause)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;

	/* disable autonegotiation of pause frame use */
	pause->autoneg = 0;

	if (mxgbe_rreg32(base, MAC_PAUSE_CTRL) & MAC_PAUSE_CTRL_RXEN) {
		pause->rx_pause = 1;
	} else {
		pause->rx_pause = 0;
	}

	if (mxgbe_rreg32(base, MAC_PAUSE_CTRL) & MAC_PAUSE_CTRL_TXEN) {
		pause->tx_pause = 1;
	} else {
		pause->tx_pause = 0;
	}
}

static int mxgbe_set_pauseparam(struct net_device *ndev,
				struct ethtool_pauseparam *pause)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	u32 val = 0;

	if (pause->rx_pause)
		val |= MAC_PAUSE_CTRL_RXEN;

	if (pause->tx_pause)
		val |= MAC_PAUSE_CTRL_TXEN;

	mxgbe_wreg32(base, MAC_PAUSE_CTRL, val);

	return 0;
}

#define MXGBE_MAX_COAL_FRAMES	(255)
#define MXGBE_MAX_COAL_TIME		(65535)
#define MXGBE_COAL_TICK		(16384)

static int mxgbe_get_coalesce(struct net_device *ndev,
			      struct ethtool_coalesce *ec,
			      struct kernel_ethtool_coalesce *kernel_coal,
			      struct netlink_ext_ack *extack)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);

	ec->rx_max_coalesced_frames = priv->rx_coalesced_frames;
	ec->tx_max_coalesced_frames = priv->tx_coalesced_frames;
	ec->rx_coalesce_usecs = ((u32)MXGBE_COAL_TICK * priv->rx_coalesce_usecs) / 10000;
	ec->tx_coalesce_usecs = ((u32)MXGBE_COAL_TICK * priv->tx_coalesce_usecs) / 10000;

	return 0;
}

static int mxgbe_set_coalesce(struct net_device *ndev,
			      struct ethtool_coalesce *ec,
			      struct kernel_ethtool_coalesce *kernel_coal,
			      struct netlink_ext_ack *extack)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	int qn;
	u32 rx_tos, tx_tos;

	if (ec->tx_max_coalesced_frames > (u32)MXGBE_MAX_COAL_FRAMES ||
	    ec->rx_max_coalesced_frames > (u32)MXGBE_MAX_COAL_FRAMES) {
		netdev_info(priv->ndev, "%s: maximum coalesced frames supported is %u\n",
			    __func__, (u32)MXGBE_MAX_COAL_FRAMES);
		return -ERANGE;
	}
	tx_tos = DIV_ROUND_UP((ec->tx_coalesce_usecs * 10000), MXGBE_COAL_TICK);
	rx_tos = DIV_ROUND_UP((ec->rx_coalesce_usecs * 10000), MXGBE_COAL_TICK);
	if (tx_tos > MXGBE_MAX_COAL_TIME ||
	    rx_tos > MXGBE_MAX_COAL_TIME) {
		netdev_info(priv->ndev, "%s: maximum coalesce time supported is %u usecs\n",
			    __func__, ((u32)MXGBE_COAL_TICK * (u32)(MXGBE_MAX_COAL_TIME)) / 10000);
		return -ERANGE;
	}

	priv->rx_coalesced_frames = ec->rx_max_coalesced_frames;
	priv->rx_coalesce_usecs = rx_tos;
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_RDYTHR), 0 |
			     Q_RDYTHR_SET_N(priv->rx_coalesced_frames) |
			     Q_RDYTHR_SET_TO(priv->rx_coalesce_usecs));
	}

	priv->tx_coalesced_frames = ec->tx_max_coalesced_frames;
	priv->tx_coalesce_usecs = tx_tos;
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_RDYTHR), 0 |
			     Q_RDYTHR_SET_N(priv->tx_coalesced_frames) |
			     Q_RDYTHR_SET_TO(priv->tx_coalesce_usecs));
	}

	return 0;
}

static void mxgbe_get_ringparam(struct net_device *ndev,
				struct ethtool_ringparam *ring,
				struct kernel_ethtool_ringparam *kernel_ering,
				struct netlink_ext_ack *extack)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);

	ring->rx_max_pending = Q_SIZE_MAX;
	ring->tx_max_pending = Q_SIZE_MAX;
	ring->rx_pending = priv->rx_ring_count;
	ring->tx_pending = priv->tx_ring_count;
}

static inline u32 mxgbe_cnt_align(u32 cnt)
{
	u8 log_cnt = 0;

	while (true) {
		if (cnt == 1)
			break;
		cnt >>= 1;
		log_cnt++;
	}

	return (u32)(1UL << log_cnt);
}

static int mxgbe_set_ringparam(struct net_device *ndev,
			       struct ethtool_ringparam *ring,
			       struct kernel_ethtool_ringparam *kernel_ering,
			       struct netlink_ext_ack *extack)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	u32 new_rx_cnt, new_tx_cnt;
	int err = 0;
	bool running = netif_running(ndev);

	if ((ring->rx_mini_pending) || (ring->rx_jumbo_pending))
		return -EINVAL;

	new_tx_cnt = clamp_t(u32, ring->tx_pending, Q_SIZE_MIN, Q_SIZE_MAX);
	new_tx_cnt = mxgbe_cnt_align(new_tx_cnt);

	new_rx_cnt = clamp_t(u32, ring->rx_pending, Q_SIZE_MIN, Q_SIZE_MAX);
	new_rx_cnt = mxgbe_cnt_align(new_rx_cnt);

	if ((new_tx_cnt == priv->tx_ring_count) &&
	    (new_rx_cnt == priv->rx_ring_count))
		return 0;

	if (running)
		dev_close(ndev);

	mxgbe_board_down(priv);

	priv->rx_ring_count = new_rx_cnt;
	priv->tx_ring_count = new_tx_cnt;

	err = mxgbe_board_up(priv);
	if (err)
		goto err_out;

	if (running)
		err = dev_open(ndev, NULL);

err_out:

	return err;
}

static void mxgbe_get_drvinfo(struct net_device *ndev,
			      struct ethtool_drvinfo *drvinfo)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);

	strlcpy(drvinfo->driver, KBUILD_MODNAME,
		sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, DRIVER_VERSION,
		sizeof(drvinfo->version));
	strlcpy(drvinfo->bus_info, pci_name(priv->pdev),
		sizeof(drvinfo->bus_info));
}

static void mxgbe_get_channels(struct net_device *ndev,
			       struct ethtool_channels *ch)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;

	ch->max_rx = mxgbe_rreg32(base, RX_QNUM);
	ch->rx_count = priv->num_rx_queues;

	ch->max_tx = mxgbe_rreg32(base, TX_QNUM);
	ch->tx_count = priv->num_tx_queues;

	ch->max_other = 0;
	ch->other_count = 0;

	ch->max_combined = 0;
	ch->combined_count = 0;
}

static int mxgbe_set_channels(struct net_device *ndev,
			      struct ethtool_channels *ch)
{
	return -EINVAL;
}

static int mxgbe_ethtool_get_sset_count(struct net_device *dev, int sset)
{
	if (sset == ETH_SS_STATS) {
		int count = ARRAY_SIZE(mxgbe_eth_gstrings);

#ifdef CONFIG_PAGE_POOL_STATS
		count += page_pool_ethtool_stats_get_count();
#endif

		return count;
	}

	return -EOPNOTSUPP;
}

static void mxgbe_ethtool_get_strings(struct net_device *netdev, u32 sset,
				      u8 *data)
{
	if (sset == ETH_SS_STATS) {
		int i;

		for (i = 0; i < ARRAY_SIZE(mxgbe_eth_gstrings); i++)
			memcpy(data + i * ETH_GSTRING_LEN,
			       mxgbe_eth_gstrings[i].name, ETH_GSTRING_LEN);

#ifdef CONFIG_PAGE_POOL_STATS
		data += ETH_GSTRING_LEN * ARRAY_SIZE(mxgbe_eth_gstrings);
		page_pool_ethtool_stats_get_strings(data);
#endif
	}
}

#ifdef CONFIG_PAGE_POOL_STATS
static void mxgbe_ethtool_pp_stats(mxgbe_priv_t *priv, u64 *data)
{
	struct page_pool_stats stats = { 0 };
	int i;

	for (i = 0; i < priv->num_rx_queues; i++) {
		struct mxgbe_queue *q = &priv->rxq[i];

		if (q->page_pool)
			page_pool_get_stats(q->page_pool, &stats);
	}

	page_pool_ethtool_stats_get(data, &stats);
}
#endif

static void mxgbe_ethtool_get_stats(struct net_device *dev,
				    struct ethtool_stats *stats, u64 *data)
{
	mxgbe_priv_t *priv = netdev_priv(dev);
	int i;

	for (i = 0; i < ARRAY_SIZE(mxgbe_eth_gstrings); i++)
		*data++ = *(((u64 *)&priv->ethtool_stats) + i);

#ifdef CONFIG_PAGE_POOL_STATS
	mxgbe_ethtool_pp_stats(priv, data);
#endif
}

static const struct ethtool_ops mxgbe_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				ETHTOOL_COALESCE_MAX_FRAMES,
	.get_link_ksettings = mxgbe_get_link_ksettings,
	.set_link_ksettings = mxgbe_set_link_ksettings,
	.get_pauseparam = mxgbe_get_pauseparam,
	.set_pauseparam = mxgbe_set_pauseparam,
	.get_coalesce = mxgbe_get_coalesce,
	.set_coalesce = mxgbe_set_coalesce,
	.get_ringparam = mxgbe_get_ringparam,
	.set_ringparam = mxgbe_set_ringparam,
	.get_drvinfo = mxgbe_get_drvinfo,
	.get_channels = mxgbe_get_channels,
	.set_channels = mxgbe_set_channels,
	.get_link = ethtool_op_get_link,
	.get_strings = mxgbe_ethtool_get_strings,
	.get_ethtool_stats = mxgbe_ethtool_get_stats,
	.get_sset_count = mxgbe_ethtool_get_sset_count,
};

void mxgbe_set_ethtool_ops(struct net_device *ndev)
{
	ndev->ethtool_ops = &mxgbe_ethtool_ops;
} /* mxgbe_set_ethtool_ops */
