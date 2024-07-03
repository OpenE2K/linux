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


/*
 * Display standard information about device
 * ethtool DEVNAME
 */
static int mxgbe_get_link_ksettings(struct net_device *ndev,
			struct ethtool_link_ksettings *ecmd)
{
	u32 supported;
	FDEBUG;

	ecmd->base.speed = 10000;
	ecmd->base.duplex = DUPLEX_FULL;
	ecmd->base.port = PORT_AUI; /* ? */
	ecmd->base.autoneg = AUTONEG_ENABLE;

	supported = SUPPORTED_10000baseT_Full | SUPPORTED_Pause;
	ethtool_convert_legacy_u32_to_link_mode(ecmd->link_modes.supported,
						supported);

	return 0;
}

/*
 * Change generic options
 * ethtool -s|--change DEVNAME
 *   [ speed %d ]
 *   [ duplex half|full ]
 *   [ port tp|aui|bnc|mii|fibre ]
 *   [ mdix auto|on|off ]
 *   [ autoneg on|off ]
 *   [ advertise %x ]
 *   [ phyad %d ]
 *   [ xcvr internal|external ]
 *   [ wol p|u|m|b|a|g|s|d... ]
 *   [ sopass %x:%x:%x:%x:%x:%x ]
 *   [ msglvl %d | msglvl type on|off ... ]
 */
static int mxgbe_set_link_ksettings(struct net_device *ndev,
			const struct ethtool_link_ksettings *ecmd)
{
	s32 err = 0;

	FDEBUG;

	return err;
}


/*
 * Show pause options
 * ethtool -a|--show-pause DEVNAME
 */
static void mxgbe_get_pauseparam(struct net_device *ndev,
				 struct ethtool_pauseparam *pause)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;

	FDEBUG;

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

/*
 * Set pause options
 * ethtool -A|--pause DEVNAME
 *   [ autoneg on|off ]
 * + [ rx on|off ]
 * + [ tx on|off ]
 */
static int mxgbe_set_pauseparam(struct net_device *ndev,
				struct ethtool_pauseparam *pause)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	u32 val = 0;

	FDEBUG;

	if (pause->rx_pause)
		val |= MAC_PAUSE_CTRL_RXEN;

	if (pause->tx_pause)
		val |= MAC_PAUSE_CTRL_TXEN;

	mxgbe_wreg32(base, MAC_PAUSE_CTRL, val);

	return 0;
}


/*
 * Show coalesce options
 * ethtool -c|--show-coalesce DEVNAME
 */
static int mxgbe_get_coalesce(struct net_device *ndev,
			      struct ethtool_coalesce *ec)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	ec->rx_max_coalesced_frames =
		Q_RDYTHR_GET_N(mxgbe_rreg32(base, RXQ_REG_ADDR(0, Q_RDYTHR)));
	ec->tx_max_coalesced_frames =
		Q_RDYTHR_GET_N(mxgbe_rreg32(base, TXQ_REG_ADDR(0, Q_RDYTHR)));

	return 0;
}

/*
 * Set coalesce options
 * ethtool -C|--coalesce DEVNAME
 *   [adaptive-rx on|off]
 *   [adaptive-tx on|off]
 *   [rx-usecs N]
 * + [rx-frames N]
 *   [rx-usecs-irq N]
 *   [rx-frames-irq N]
 *   [tx-usecs N]
 * + [tx-frames N]
 *   [tx-usecs-irq N]
 *   [tx-frames-irq N]
 *   [stats-block-usecs N]
 *   [pkt-rate-low N]
 *   [rx-usecs-low N]
 *   [rx-frames-low N]
 *   [tx-usecs-low N]
 *   [tx-frames-low N]
 *   [pkt-rate-high N]
 *   [rx-usecs-high N]
 *   [rx-frames-high N]
 *   [tx-usecs-high N]
 *   [tx-frames-high N]
 *   [sample-interval N]
 */
static int mxgbe_set_coalesce(struct net_device *ndev,
			      struct ethtool_coalesce *ec)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;
	int qn;

	FDEBUG;

	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_RDYTHR),
			     Q_RDYTHR_SET_N(ec->rx_max_coalesced_frames));
	}
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_RDYTHR),
			     Q_RDYTHR_SET_N(ec->tx_max_coalesced_frames));
	}

	return 0;
}


/*
 * Query RX/TX ring parameters
 * ethtool -g|--show-ring DEVNAME
 */
static void mxgbe_get_ringparam(struct net_device *ndev,
				struct ethtool_ringparam *ring)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);

	FDEBUG;

	ring->rx_max_pending = priv->rxq[0].descr_cnt;
	ring->tx_max_pending = priv->txq[0].descr_cnt;
	ring->rx_pending = priv->rxq[0].descr_cnt;
	ring->tx_pending = priv->txq[0].descr_cnt;
}

/*
 * Set RX/TX ring parameters
 * ethtool -G|--set-ring DEVNAME
 *   [ rx N ]
 *   [ rx-mini N ]
 *   [ rx-jumbo N ]
 *   [ tx N ]
 */
static int mxgbe_set_ringparam(struct net_device *ndev,
			       struct ethtool_ringparam *ring)
{
	FDEBUG;

	return -EINVAL;
}


/*
 * Get state of protocol offload and other features
 * ethtool -k|--show-features|--show-offload DEVNAME
 * (no func)
 */

/*
 * Set protocol offload and other features
 * ethtool -K|--features|--offload DEVNAME
 *   FEATURE on|off ...
 */


/*
 * Show driver information
 * ethtool -i|--driver DEVNAME
 */
static void mxgbe_get_drvinfo(struct net_device *ndev,
			      struct ethtool_drvinfo *drvinfo)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);

	FDEBUG;

	strlcpy(drvinfo->driver, KBUILD_MODNAME,
		sizeof(drvinfo->driver));
	strlcpy(drvinfo->version, DRIVER_VERSION,
		sizeof(drvinfo->version));
	strlcpy(drvinfo->bus_info, pci_name(priv->pdev),
		sizeof(drvinfo->bus_info));
}


#if 0
ethtool -d|--register-dump DEVNAME
ethtool -e|--eeprom-dump DEVNAME
ethtool -E|--change-eeprom DEVNAME
ethtool -r|--negotiate DEVNAME
ethtool -p|--identify DEVNAME
ethtool -t|--test DEVNAME
ethtool -S|--statistics DEVNAME
ethtool -n|-u|--show-nfc|--show-ntuple DEVNAME
ethtool -N|-U|--config-nfc|--config-ntuple DEVNAME
ethtool -T|--show-time-stamping DEVNAME
ethtool -x|--show-rxfh-indir DEVNAME
ethtool -X|--set-rxfh-indir DEVNAME
ethtool -f|--flash DEVNAME
ethtool -P|--show-permaddr DEVNAME
ethtool -w|--get-dump DEVNAME
ethtool -W|--set-dump DEVNAME
#endif


/*
 * Query Channels
 * ethtool -l|--show-channels DEVNAME
 */
static void mxgbe_get_channels(struct net_device *ndev,
			       struct ethtool_channels *ch)
{
	mxgbe_priv_t *priv = netdev_priv(ndev);
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	ch->max_rx = mxgbe_rreg32(base, RX_QNUM);
	ch->rx_count = priv->num_rx_queues;

	ch->max_tx = mxgbe_rreg32(base, TX_QNUM);
	ch->tx_count = priv->num_tx_queues;

	ch->max_other = 0;
	ch->other_count = 0;

	ch->max_combined = 0;
	ch->combined_count = 0;
}

/*
 * Set Channels
 * ethtool -L|--set-channels DEVNAME
 *   [ rx N ]
 *   [ tx N ]
 *   [ other N ]
 *   [ combined N ]
 */
static int mxgbe_set_channels(struct net_device *ndev,
			      struct ethtool_channels *ch)
{
	FDEBUG;

	return -EINVAL;
}


#if 0
ethtool --show-priv-flags DEVNAME
ethtool --set-priv-flags DEVNAME
ethtool -m|--dump-module-eeprom|--module-info DEVNAME
ethtool --show-eee DEVNAME
ethtool --set-eee DEVNAME
#endif


static const struct ethtool_ops mxgbe_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_MAX_FRAMES,
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
};

void mxgbe_set_ethtool_ops(struct net_device *ndev)
{
	ndev->ethtool_ops = &mxgbe_ethtool_ops;
} /* mxgbe_set_ethtool_ops */
