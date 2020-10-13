

#define SUNLANCE_CHECK_TMD

#define lance_request_threaded_irq request_threaded_irq
#define lance_free_irq free_irq

#define LANCE_TYPE_NAME  "pci-sunlance"


#define SUNLANCE_BODY_FOR_PCI
#include "sunlance_body.h"
#undef SUNLANCE_BODY_FOR_PCI


static void lance_free_hwresources(struct lance_private *lp)
{
        if (lp->pdev) {
                iounmap( lp->dregs );
                pci_release_region( lp->pdev, PCI_DREGS_BAR );
                pci_free_consistent(lp->pdev,
                             sizeof(struct lance_init_block),
                             (void *)lp->init_block_mem,
                             lp->init_block_dvma);
                iounmap( lp->lregs.vbase );
                pci_release_region( lp->pdev, PCI_LREGS_BAR );
        }
}

#if 0
static const struct net_device_ops pci_lance_ops = {
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

#endif

static int sunlance_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
        struct net_device *dev;
        struct lance_private *lp;
        unsigned long   lregs_base;
        unsigned int    lregs_len;
        unsigned long   dregs_base;
        unsigned int    dregs_len;
        u32 csr;
        int err;
        static unsigned version_printed;

        err = pci_enable_device(pdev);
        if (err < 0) {
                if (sparc_lance_debug & NETIF_MSG_PROBE)
                        printk(KERN_ERR DRV_NAME "failed to enable device -- err=%d\n", err);
                return err;
        }

        pci_set_master(pdev);

        dev = alloc_etherdev(sizeof(struct lance_private) + 8);
        if (!dev)
                return -ENOMEM;

        lp = netdev_priv(dev);
        memset(lp, 0, sizeof(*lp));

        if (sparc_lance_debug && version_printed++ == 0)
                printk (KERN_INFO "%s", version);

#ifdef CONFIG_MCST_RT
        raw_spin_lock_init(&lp->rt_stuff_lock);
#endif
        raw_spin_lock_init(&lp->lock);
        raw_spin_lock_init(&lp->init_lock);

	lance_setup_mac(dev);
        lp->pdev = pdev;
        dev_set_drvdata(&pdev->dev, lp);

        /* Copy the IDPROM ethernet address to the device structure, later we
         * will copy the address in the device structure to the lance
         * initialization block.
         */

        lregs_base = pci_resource_start( pdev, PCI_LREGS_BAR );
        lregs_len = pci_resource_len( pdev, PCI_LREGS_BAR );

        if ( pci_request_region(pdev, PCI_LREGS_BAR, "sunlance_lregs") ) {
                printk(KERN_ERR "SunLance: Unable to request memory region for lregs (0x%08lx:0x%x)\n",
                        lregs_base, lregs_len );
                goto fail_lregs;
        }

       /* Get the IO region */
        lp->lregs.vbase = ioremap( lregs_base, lregs_len );
        if ( !lp->lregs.vbase ) {
                printk(KERN_ERR "SunLance: Cannot map lregs.\n");
                goto fail_lregs_ioremap;
        }
        lp->lregs.rdp = lp->lregs.vbase + RDP;
        lp->lregs.rap = lp->lregs.vbase + RAP;
        printk("sunlance init: rdp reg = 0x%lx, rap reg = 0x%lx\n",
                (unsigned long)lp->lregs.rdp, (unsigned long)lp->lregs.rap);
        lp->init_block_mem =
                pci_alloc_consistent(pdev, sizeof(struct lance_init_block),
                                &lp->init_block_dvma);
        printk("init_block_mem = 0x%lx, init_block_dvma = 0x%x\n",
                        (unsigned long)lp->init_block_mem, (unsigned int)lp->init_block_dvma);
        if (!lp->init_block_mem || lp->init_block_dvma == 0) {
                printk(KERN_ERR "SunLance: Cannot allocate consistent DMA memory.\n");
                goto fail_dma;
        }
        lp->pio_buffer = 0;
        lp->init_ring = lance_init_ring_dvma;
   //     lp->rx = lance_rx_dvma;
   //     lp->tx = lance_tx_dvma;

        lp->busmaster_regval = LE_C3_BSWP | LE_C3_ACON | LE_C3_BCON;

        lp->name = lancestr;

        // FIXME this values may be invalid. Test!!!
        lp->burst_sizes = DMA_BURST32;

        dregs_base = pci_resource_start( pdev, PCI_DREGS_BAR );
        dregs_len = pci_resource_len( pdev, PCI_DREGS_BAR );

        if ( pci_request_region(pdev, PCI_DREGS_BAR, "sunlance_dregs") ) {
                printk(KERN_ERR "SunLance: Unable to request memory region for lregs (0x%08lx:0x%x)\n",
                        dregs_base, dregs_len );
                goto fail_dregs;
        }
printk("io_remapping dregs: base = 0x%lx, len = 0x%x\n", dregs_base, dregs_len);
       /* Get the IO region */
        lp->dregs = ioremap( dregs_base, dregs_len );
        if ( !lp->dregs ) {
                printk(KERN_ERR "SunLance: Cannot map dregs.\n");
                goto fail_dregs_ioremap;
        }
        printk("sunlance init: dregs addr = 0x%lx\n", (unsigned long)lp->dregs);
        /* Reset ledma */
        csr = readl(lp->dregs + DMA_CSR);
	lance_writel(csr | DMA_RST_ENET, lp->dregs + DMA_CSR);
        udelay(200);
	lance_writel(csr & ~DMA_RST_ENET, lp->dregs + DMA_CSR);

        lp->dev = dev;
        SET_NETDEV_DEV(dev, &pdev->dev);
        dev->irq = pdev->irq;
        dev->dma = 0;
	if (lance_common_init(dev, lp)) {
		goto fail_register_netdev;
	}
#if 0
        if (sunlance_uses_poll) {
                dev->poll = &lance_poll;
                dev->weight = (1 << LANCE_LOG_RX_BUFFERS);
                dev->quota = dev->weight;
        }
#endif
        // FIXME
	lance_writew(LE_CSR0, lp->lregs.rap);
	lance_writew(0, lp->lregs.rdp);


        return 0;

fail_register_netdev:
        iounmap( lp->dregs );
fail_dregs_ioremap:
        pci_release_region( lp->pdev, PCI_DREGS_BAR );
fail_dregs:
        pci_free_consistent(lp->pdev,
                             sizeof(struct lance_init_block),
                             (void *)lp->init_block_mem,
                             lp->init_block_dvma);
fail_dma:
        iounmap( lp->lregs.vbase );
fail_lregs_ioremap:
        pci_release_region( lp->pdev, PCI_LREGS_BAR );
fail_lregs:
        free_netdev(dev);
        return -ENODEV;
}

static void sunlance_remove(struct pci_dev *pdev) 
{
	struct lance_private *lp = dev_get_drvdata(&pdev->dev);

	dev_set_drvdata(&pdev->dev, NULL);
	unregister_netdev(lp->dev);
        lance_free_hwresources(lp);
        free_netdev(lp->dev);
}

static  struct pci_device_id sunlance_match[] = {
	{SUNLANCE_PCI_VENDOR_ID, SUNLANCE_PCI_DEVICE_ID,
	 PCI_ANY_ID, PCI_ANY_ID
	},
	{},
};
MODULE_DEVICE_TABLE(pci, sunlance_match);

static struct pci_driver sunlance_driver = {
	.name		= "PCI-LANCE",
	.id_table	= sunlance_match,
	.probe		= sunlance_probe,
	.remove		= sunlance_remove,
};


/* Find all the lance cards on the system and initialize them */
extern int e1000;
static int __init pci_lance_init(void)
{
	if (e1000) {
		sunlance_match[0].subvendor = 1;
	}	
	return pci_register_driver(&sunlance_driver);
}

static void __exit pci_lance_exit(void)
{
	pci_unregister_driver(&sunlance_driver);
}

module_init(pci_lance_init);
module_exit(pci_lance_exit);
