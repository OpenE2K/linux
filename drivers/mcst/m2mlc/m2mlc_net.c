/**
 * m2mlc_net.c - M2MLC module device driver
 *
 * Network part
 */

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/crc32.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_arp.h>

#include "m2mlc.h"


#ifdef ENABLE_NET_DEV

#undef ENABLE_NAPI

/**
 *  Network interface Consts
 */
#define M2MLC_WATCHDOG_PERIOD		(1 * HZ)
#define M2MLC_NAPI_WEIGHT		(16)
#define M2MLC_TX_QUE_LEN		(100)

/** get device_id from MAC */
#define M2MLC_GET_DESTID(x)	(*((u8 *)x + 5))


u32 m2mlc_read_reg32(void __iomem *base_addr, u32 port);
void m2mlc_hw_int_setmask(m2mlc_priv_t *priv, int ep,
			  m2mlc_interrupt_t intmask);
int ksvv_open_endpoint(m2mlc_npriv_t *npriv);
int ksvv_close_endpoint(m2mlc_npriv_t *npriv);
uint32_t ksvv_send(m2mlc_npriv_t *npriv, int rem_node_id, int rem_endp_id,
		   void *data, uint32_t send_size);
int ksvv_poll(m2mlc_npriv_t *npriv);


/**
 ******************************************************************************
 * Rx Part
 ******************************************************************************
 **/

/**
 * The rx poll function
 */
void m2mlc_hw_rx(struct net_device *ndev, char *data, ssize_t size)
{
	m2mlc_npriv_t *npriv;
	struct sk_buff *rx_skb;
	u8 *prdbuf;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev, "m2mlc_hw_rx(%d)\n", (int)size);

	assert(ndev);
	if (!ndev)
		return;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return;

	/* nothing receive */
	if (size < (M2MLC_ETH_HEAD_LEN)) {
		dev_err(&ndev->dev,
			"ERROR: Very small packet's size (< header's size)\n");
		return;
	}

	/* allocate new skb */
	rx_skb = netdev_alloc_skb(ndev, size);
	if (!rx_skb) {
		dev_err(&ndev->dev,
			"ERROR: Cannot allocate rx buffer (skb)\n");
		npriv->stats.rx_dropped++;
		return;
	}

	/* receive err packet */
	/*if () {
		rx_skb->len = 0;
		npriv->stats.rx_errors++;
		dev_kfree_skb(rx_skb);
		return;
	}*/

	/* getting all data */
	prdbuf = skb_put(rx_skb, size);
	memcpy(prdbuf, data, size);

	/* Pass to upper layer */
	rx_skb->protocol = eth_type_trans(rx_skb, ndev);
	npriv->stats.rx_packets++;
	npriv->stats.rx_bytes += size;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev, "netif_rx(%d)\n", rx_skb->len);
#ifdef ENABLE_NAPI
	netif_receive_skb(rx_skb);
#else /* ENABLE_NAPI */
	netif_rx(rx_skb);
#endif /* ENABLE_NAPI */
	/* rx_skb = NULL; */

	return;
} /* m2mlc_hw_rx */

/**
 * m2mlc_irq_handler
 */
void m2mlc_net_irq_handler(m2mlc_priv_t *m2mlc_priv, uint32_t irq_stat)
{
	struct net_device *ndev;
	m2mlc_npriv_t *npriv;
#ifdef ENABLE_NAPI
	m2mlc_interrupt_t intmask;
#endif /* ENABLE_NAPI */

	ndev = m2mlc_priv->ndev;
	assert(ndev);
	if (!ndev)
		return;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"net_irq_handler(0x%X)\n", irq_stat);

#ifdef ENABLE_NAPI
	intmask.r = 0;
	m2mlc_hw_int_setmask(npriv->p_priv, CDEV_ENDPOINT_NET, intmask);
	napi_schedule(&(npriv->napi));
#else /* ENABLE_NAPI */
	while (ksvv_poll(npriv))
		;
#endif /* ENABLE_NAPI */

#if 0
	if (link) {
		/* Link Up if transmit enable */
		if (1)
			netif_carrier_on(ndev);
		else
			netif_carrier_off(ndev);
	}
#endif /* 0 */
} /* m2mlc_net_irq_handler */

/**
 * The main poll function
 */
#ifdef ENABLE_NAPI
static int m2mlc_poll(struct napi_struct *napi, int budget)
{
	m2mlc_npriv_t *npriv;
	struct net_device *ndev;
	int work_done;
	int work_done_;
	m2mlc_interrupt_t intmask;

	assert(napi);
	if (!napi)
		return -1;

	npriv = container_of(napi, m2mlc_npriv_t, napi);
	assert(npriv);
	if (!npriv)
		return -1;

	ndev = npriv->p_priv->ndev;
	assert(ndev);
	if (!ndev)
		return -1;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev, "m2mlc_poll\n");

	work_done = 0;
	do {
		/* Reset interrupt controller */
		/*
		intmask.r = 0;
		m2mlc_hw_int_setmask(npriv->p_priv, CDEV_ENDPOINT_NET, intmask);
		*/

		work_done_ = work_done;
		if (ksvv_poll(npriv))
			work_done++;
	} while ((work_done != budget) && (work_done != work_done_));

	if (work_done < budget) {
		/* Restore irq mask */
		intmask.r = 0;
		intmask.p.mb = M2MLC_INT_MB_RXMSG;
		m2mlc_hw_int_setmask(npriv->p_priv, CDEV_ENDPOINT_NET, intmask);

		napi_complete(napi);
	}

	return work_done;
} /* m2mlc_poll */
#endif /* ENABLE_NAPI */


/**
 ******************************************************************************
 * Network Driver Part
 ******************************************************************************
 **/

/**
 * The network interface transmission function
 * @skb: socket buffer for tx
 * @ndev: network interface device structure
 *
 * m2mlc_start_xmit is called by socket send function
 */
static netdev_tx_t m2mlc_start_xmit(struct sk_buff *skb,
				    struct net_device *ndev)
{
	int tx_ret = -1;
	uint32_t DestId;
	m2mlc_npriv_t *npriv;
	struct ethhdr *eth;

	assert(skb);
	if (!skb)
		return -1;
	assert(ndev);
	if (!ndev)
		return -1;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return -1;

	/* Check packet's size */
	if (skb->len < (M2MLC_ETH_HEAD_LEN)) {
		dev_err(&ndev->dev,
			"ERROR: Very small packet's size (< header's size)\n");
		goto tx_free_skb;
	}

	/* Save the timestamp */
	netif_trans_update(ndev);

	/* HW transmit data */
	eth = (struct ethhdr *)skb->data;
	DestId = M2MLC_GET_DESTID(eth->h_dest);
	if (DestId == 0) {
		dev_dbg(&ndev->dev,
			"net_tx: DROP: skblen=%d DestId=%u\n",
			skb->len, DestId);
		goto tx_free_skb;
	}
	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"TX: [%ld] skblen=%d DestId=%u\n",
		ndev->trans_start, skb->len, DestId);
	tx_ret = ksvv_send(npriv, DestId, CDEV_ENDPOINT_NET,
			   (void *)(skb->data), skb->len);

tx_free_skb:
	/* Free skb */
	dev_kfree_skb(skb);

	/* Stats */
	if (tx_ret < 0) {
		npriv->stats.tx_dropped++;
	} else {
		npriv->stats.tx_packets++;
		npriv->stats.tx_bytes += skb->len;
	}

	if (tx_ret)
		return NETDEV_TX_OK;
	else
		return -1;
} /* m2mlc_start_xmit */


/**
 * The network interface open function
 * @ndev: network interface device structure
 *
 * m2mlc_open is called by register_netdev
 */
static int m2mlc_open(struct net_device *ndev)
{
	m2mlc_npriv_t *npriv;
	m2mlc_interrupt_t intmask;

	assert(ndev);
	if (!ndev)
		return -1;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return -1;

	if (!ndev->dev_addr[5]) {
		dev_err(&ndev->dev, "please assign DeviceID before open\n");
		return -1;
	}

	dev_info(&ndev->dev, "interface OPEN\n");

	if (ksvv_open_endpoint(npriv))
		return -1;

	/* Enable interrupt */
	intmask.r = 0;
	intmask.p.mb = M2MLC_INT_MB_RXMSG; /* Mailbox Rx irq */
	m2mlc_hw_int_setmask(npriv->p_priv, CDEV_ENDPOINT_NET, intmask);

	/* start tx/rx */
	netif_start_queue(ndev);
#ifdef ENABLE_NAPI
	napi_enable(&(npriv->napi));
#endif /* ENABLE_NAPI */

	return 0;
} /* m2mlc_open */

/**
 * The network interface close function
 * @ndev: network interface device structure
 *
 * m2mlc_stop is called by free_netdev
 */
static int m2mlc_stop(struct net_device *ndev)
{
	m2mlc_npriv_t *npriv;
	m2mlc_interrupt_t intmask;

	assert(ndev);
	if (!ndev)
		return -1;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return -1;

	/*if (netif_msg_ifup(npriv))*/
	dev_info(&ndev->dev, "interface STOP\n");

	/* Disable interrupt */
	intmask.r = 0;
	m2mlc_hw_int_setmask(npriv->p_priv, CDEV_ENDPOINT_NET, intmask);

	/* stop tx/rx */
#ifdef ENABLE_NAPI
	napi_disable(&(npriv->napi));
#endif /* ENABLE_NAPI */
	netif_stop_queue(ndev);

	/* link off */
	netif_carrier_off(ndev);

	ksvv_close_endpoint(npriv);

	return 0;
} /* m2mlc_stop */


/**
 * The network interface status function
 * @ndev: network interface device structure
 */
static struct net_device_stats *m2mlc_get_stats(struct net_device *ndev)
{
	m2mlc_npriv_t *npriv;

	assert(ndev);
	if (!ndev)
		return NULL;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return NULL;

	return &npriv->stats;
} /* m2mlc_get_stats */

#if 0
static int m2mlc_change_mtu(struct net_device *ndev, int new_mtu)
{
	dev_info(&ndev->dev, "change MTU: old=%u, new=%d\n",
		 ndev->mtu, new_mtu);

	if (new_mtu == ndev->mtu) {
		return 0;
	}
	if (new_mtu > M2MLC_MTU) {
		return 0;
	}

	ndev->mtu = new_mtu;
	return 0;
} /* m2mlc_change_mtu */
#endif /* 0 */

static int m2mlc_set_mac_addr(struct net_device *ndev, void *p)
{
	m2mlc_npriv_t *npriv;
	ecs_basedevid_csr_reg_t basedevid;
	struct sockaddr *addr = p;

	npriv = netdev_priv(ndev);
	assert(npriv);
	if (!npriv)
		return -EBUSY;

	if (netif_running(ndev))
		return -EBUSY;
	memcpy(ndev->dev_addr, addr->sa_data, ndev->addr_len);

	basedevid.r = m2mlc_read_reg32(npriv->p_priv->ecs_base,
				       ECS_BASEDEVID_CSR);
	if (basedevid.r) {
		ndev->dev_addr[5] = basedevid.p.Base_DeviceID;
	}

	dev_info(&ndev->dev, "set new mac address (%d)\n", ndev->dev_addr[5]);

	return 0;
} /* m2mlc_set_mac_addr */

#if 0
/**
 * The network interface transmission timeout function
 * @ndev: network interface device structure
 */
static void m2mlc_tx_timeout(struct net_device *ndev)
{
	assert(ndev);
	if (!ndev)
		return;

	/* Save the timestamp */
	ndev->trans_start = jiffies;

	dev_err(&ndev->dev,
		"ERROR: Tx Timeout\n");
} /* m2mlc_tx_timeout */
#endif /* 0 */


/**
 * net_device_ops
 */
static const struct net_device_ops m2mlc_netdev_ops = {
	.ndo_open		= m2mlc_open,
	.ndo_stop		= m2mlc_stop,
	.ndo_start_xmit		= m2mlc_start_xmit,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_set_mac_address	= m2mlc_set_mac_addr,
	.ndo_get_stats		= m2mlc_get_stats,
#if 0
	.ndo_tx_timeout		= m2mlc_tx_timeout,
#endif /* 0 */
};


/**
 ******************************************************************************
 * Init Network Driver Part
 ******************************************************************************
 **/

/**
 * The network interface init function
 * @ndev: network interface device structure
 *
 * m2mlc_net_init is called by alloc_netdev
 */
static void m2mlc_net_init(struct net_device *ndev)
{
	m2mlc_npriv_t *npriv;

	assert(ndev);

	/* net device ops */
#if 0 /*def CONFIG_E2K*/
	ndev->dev_addr[0]	= l_base_mac_addr[0];
	ndev->dev_addr[1]	= l_base_mac_addr[1];
	ndev->dev_addr[2]	= l_base_mac_addr[2];
	ndev->dev_addr[3]	= l_base_mac_addr[3];
	ndev->dev_addr[4]	= 0xF0;
	ndev->dev_addr[5]	= 0; /* << device_id */
#else
	ndev->dev_addr[0]	= 0x00;
	ndev->dev_addr[1]	= 0x01;
	ndev->dev_addr[2]	= 0x00;
	ndev->dev_addr[3]	= 0x01;
	ndev->dev_addr[4]	= 0xF0;
	ndev->dev_addr[5]	= 0; /* << device_id */
	/* ifconfig m2m0 hw ether 00:01:00:01:f0:<device_id> */
#endif
	ether_setup(ndev);
	ndev->mtu		= M2MLC_MTU;
	ndev->netdev_ops	= &m2mlc_netdev_ops;
	ndev->flags		= IFF_NOARP;
	ndev->tx_queue_len	= M2MLC_TX_QUE_LEN;
	/* FIXME: disable ipv6 */
#if 0
	ndev->features		= NETIF_F_LLTX;
	ndev->type		= ARPHRD_NONE; ARPHRD_ETHER
	ndev->flags		= IFF_NOARP | IFF_POINTOPOINT | IFF_PROMISC;
	ndev->watchdog_timeo	= M2MLC_WATCHDOG_PERIOD;
	ndev->hard_header_len	= M2MLC_ETH_HEAD_LEN;
#endif /* 0 */
	memset(ndev->broadcast, 0, sizeof(ndev->broadcast));

	/* initialize the npriv field. */
	npriv = netdev_priv(ndev);
	memset(npriv, 0, sizeof(m2mlc_npriv_t));
} /* m2mlc_net_init */

int m2mlc_net_register(m2mlc_priv_t *priv)
{
	int ret = 0;
	struct pci_dev *pdev;
	m2mlc_npriv_t *npriv;

	assert(priv);
	if (!priv)
		return -ENODEV;

	pdev = priv->pdev;
	assert(pdev);
	if (!pdev)
		return -ENODEV;

	priv->ndev = alloc_netdev(sizeof(m2mlc_npriv_t), M2MLC_DEVNAME "%d",
				  NET_NAME_UNKNOWN, m2mlc_net_init);
	if (!priv->ndev) {
		dev_err(&pdev->dev,
			"ERROR: Cannot allocate memory" \
			" for net_dev, aborting\n");
		ret = -ENOMEM;
		goto err_out;
	}
	SET_NETDEV_DEV(priv->ndev, &pdev->dev); /* parent := pci */
	npriv = netdev_priv(priv->ndev);
	npriv->p_priv = priv;

#ifdef ENABLE_NAPI
	netif_napi_add(priv->ndev, &(npriv->napi),
		       m2mlc_poll, M2MLC_NAPI_WEIGHT);
#endif /* ENABLE_NAPI */

	/* link off */
	netif_carrier_off(priv->ndev);

	if ((ret = register_netdev(priv->ndev))) {
		dev_err(&pdev->dev,
			"ERROR: Cannot register net device, aborting\n");
		goto err_out_free_netdev;
	}

	dev_info(&pdev->dev, "network interface %s init\n",
		 dev_name(&priv->ndev->dev));

	DEV_DBG(M2MLC_DBG_MSK_NET, &priv->ndev->dev,
		"network interface hard_header_len=%d\n",
		priv->ndev->hard_header_len);

	netif_carrier_on(priv->ndev);
	return 0;


err_out_free_netdev:
	free_netdev(priv->ndev);
err_out:
	return ret;
} /* m2mlc_net_register */

void m2mlc_net_remove(m2mlc_priv_t *priv)
{
	assert(priv);
	if (!priv)
		return;

	/* link off */
	netif_carrier_off(priv->ndev);

	if (priv->ndev) {
		unregister_netdev(priv->ndev);
		free_netdev(priv->ndev);
	}
} /* m2mlc_net_remove */

#endif /* ENABLE_NET_DEV */
