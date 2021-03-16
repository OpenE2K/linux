

#define SUNLANCE_CHECK_TMD
#include <linux/interrupt.h>
#if defined(__sparc__) && !defined(__sparc64__)

#define lance_request_threaded_irq request_threaded_irq
#define lance_free_irq free_irq

#else // e2k, e90s - using pci2sbus interface

extern int sbus_request_threaded_irq(unsigned int irq, irqreturn_t (*handler)(int, void *),
                              irqreturn_t (*threadfn)(int, void *), unsigned long irqflags,
                              const char * devname, void *dev_id);
extern void sbus_free_irq(unsigned int irq, void *dev_id);
#define lance_request_threaded_irq      sbus_request_threaded_irq
#define lance_free_irq                  sbus_free_irq

#endif


#define LANCE_TYPE_NAME	"sbus-sunlance"
#define SUNLANCE_BODY_FOR_SBUS
#include "sunlance_body.h"
#undef SUNLANCE_BODY_FOR_SBUS



static void lance_free_hwresources(struct lance_private *lp)
{
	if (lp->op == NULL) {
		return;
	}
	if (lp->lregs.vbase)
		of_iounmap(&lp->op->resource[0], lp->lregs.vbase, LANCE_REG_SIZE);
        if (lp->ioctl_lregs)
                of_iounmap(&lp->op->resource[SBUS_IOCTL_BAR], lp->ioctl_lregs,
				resource_size(&lp->op->resource[SBUS_IOCTL_BAR]));
	if (lp->init_block_iomem) {
		of_iounmap(&lp->lebuffer->resource[0], lp->init_block_iomem,
			   sizeof(struct lance_init_block));
	} else if (lp->init_block_mem) {
		dma_free_coherent(&lp->op->dev,
				  sizeof(struct lance_init_block),
				  lp->init_block_mem,
				  lp->init_block_dvma);
	}
}


static const struct net_device_ops sparc_lance_ops = {
	.ndo_open		= lance_open,
	.ndo_stop		= lance_close,
	.ndo_start_xmit		= lance_start_xmit,
	.ndo_set_multicast_list	= lance_set_multicast,
	.ndo_tx_timeout		= lance_tx_timeout,
	.ndo_change_mtu		= eth_change_mtu,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_get_stats          = lance_get_stats,
	.ndo_do_ioctl           = our_ioctl,
};

static int sbus_mii = 0; /* turn on mii tool for sbus card */
module_param(sbus_mii , int , 1 );
MODULE_PARM_DESC(sbus_mii,"support mii-tool for sunlance sbus card ");

static int sparc_lance_probe_one(struct of_device *op,
					   struct of_device *ledma,
					   struct of_device *lebuffer)
{
	struct device_node *dp = op->node;
	static unsigned version_printed;
	struct lance_private *lp;
	struct net_device *dev;


	dev = alloc_etherdev(sizeof(struct lance_private) + 8);
	if (!dev)
		return -ENOMEM;

	lp = netdev_priv(dev);

	if (sparc_lance_debug && version_printed++ == 0)
		printk (KERN_INFO "%s", version);
#ifdef CONFIG_MCST_RT
        raw_spin_lock_init(&lp->rt_stuff_lock);
#endif
        raw_spin_lock_init(&lp->init_lock);
	raw_spin_lock_init(&lp->lock);
	lance_setup_mac(dev);

	lp->lregs.vbase = of_ioremap(&op->resource[0], 0,
			       LANCE_REG_SIZE, lancestr);
	if (!lp->lregs.vbase) {
		printk(KERN_ERR "SunLance: Cannot map registers.\n");
		goto fail;
	}
        lp->lregs.rdp = lp->lregs.vbase + RDP;
        lp->lregs.rap = lp->lregs.vbase + RAP;

#ifdef CONFIG_E90
        op->resource[SBUS_IOCTL_BAR].start = 0xf0400000;
	op->resource[SBUS_IOCTL_BAR].end = 0xf0400000 + LANCE_REG_SIZE_BAGET -1;
	op->resource[SBUS_IOCTL_BAR].flags = op->resource[0].flags;
        lp->ioctl_lregs = of_ioremap(&op->resource[SBUS_IOCTL_BAR], 0,
                                 resource_size(&op->resource[SBUS_IOCTL_BAR]), dev->name);
        if (lp->ioctl_lregs == 0UL) {
                printk(KERN_ERR "%s: Cannot map SunLance ioctl registers.\n",
                       dev->name);
                goto fail;
        }
#endif

	lp->ledma = ledma;
	if (lp->ledma) {
		lp->dregs = of_ioremap(&ledma->resource[0], 0,
				       resource_size(&ledma->resource[0]),
				       "ledma");
		if (!lp->dregs) {
			printk(KERN_ERR "SunLance: Cannot map "
			       "ledma registers.\n");
			goto fail;
		}
	}
	lp->op = op;
	lp->init_block_mem =
			dma_alloc_coherent(&op->dev,
					   sizeof(struct lance_init_block),
					   &lp->init_block_dvma, GFP_ATOMIC);
	if (!lp->init_block_mem) {
		printk(KERN_ERR "SunLance: Cannot allocate consistent DMA memory.\n");
		goto fail;
	}
	lp->pio_buffer = 0;
	lp->init_ring = lance_init_ring_dvma;
	lp->rx = lance_rx_dvma;
//	lp->tx = lance_tx_dvma;
	lp->busmaster_regval = of_getintprop_default(dp,  "busmaster-regval",
						     (LE_C3_BSWP |
						      LE_C3_ACON |
						      LE_C3_BCON));

	lp->name = lancestr;
	lp->burst_sizes = 0;
	if (lp->ledma) {
		struct device_node *ledma_dp = ledma->node;
		struct device_node *dp;
		unsigned int sbmask;
		u32 csr;

		/* Find burst-size property for ledma */
		lp->burst_sizes = of_getintprop_default(ledma_dp,
							"burst-sizes", 0);

		/* ledma may be capable of fast bursts, but sbus may not. */
		dp = ledma_dp->parent;
		sbmask = of_getintprop_default(dp, "burst-sizes",
					       DMA_BURSTBITS);
		lp->burst_sizes &= sbmask;

		/* Reset ledma */
		csr = lance_readl(lp->dregs + DMA_CSR);
		lance_writel(csr | DMA_RST_ENET, lp->dregs + DMA_CSR);
		udelay(400);
		lance_writel(csr & ~DMA_RST_ENET, lp->dregs + DMA_CSR);
	} else {
		lp->dregs = NULL;
	}
	lp->dev = dev;
	SET_NETDEV_DEV(dev, &op->dev);
        dev_set_drvdata(&op->dev, lp);
#if IS_ENABLED(CONFIG_PCI2SBUS)
	dev->irq = op->irqs[0] & 0xff0f;
#else
	dev->irq = op->irqs[0];
#endif
	if (lance_common_init(dev, lp)) {
		goto fail;
	}
	/*FIXME: mii doesn't work on sbus for unknown reason */
	lp->mii = sbus_mii;

#if 0
        if (sunlance_uses_poll) {
                dev->poll = &lance_poll;
                dev->weight = (1 << LANCE_LOG_RX_BUFFERS);
                dev->quota = dev->weight;
        }
#endif
	return 0;

fail:
	lance_free_hwresources(lp);
	free_netdev(dev);
	return -ENODEV;
}

static int sunlance_sbus_probe(struct of_device *op, const struct of_device_id *match)
{
	struct of_device *parent = to_of_device(op->dev.parent);
	struct device_node *parent_dp = parent->node;
	int err;

	if (!strcmp(parent_dp->name, "ledma")) {
		err = sparc_lance_probe_one(op, parent, NULL);
	} else
		err = sparc_lance_probe_one(op, NULL, NULL);

	return err;
}

static int sunlance_sbus_remove(struct of_device *op)
{
	struct lance_private *lp = dev_get_drvdata(&op->dev);
	struct net_device *net_dev = lp->dev;

	unregister_netdev(net_dev);

	lance_free_hwresources(lp);

	free_netdev(net_dev);

	dev_set_drvdata(&op->dev, NULL);

	return 0;
}

static const struct of_device_id sunlance_sbus_match[] = {
	{
		.name = "le",
	},
	{},
};

MODULE_DEVICE_TABLE(of, sunlance_sbus_match);

static struct of_platform_driver sunlance_sbus_driver = {
	.name		= "sbus-sunlance",
	.match_table	= sunlance_sbus_match,
	.probe		= sunlance_sbus_probe,
	.remove		= sunlance_sbus_remove,
};


/* Find all the lance cards on the system and initialize them */
static int __init sparc_lance_init(void)
{
	return of_register_driver(&sunlance_sbus_driver, &of_platform_bus_type);
}

static void __exit sparc_lance_exit(void)
{
	of_unregister_driver(&sunlance_sbus_driver);
}

module_init(sparc_lance_init);
module_exit(sparc_lance_exit);
