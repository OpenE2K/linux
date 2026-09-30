/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe.c - MXGBE module device driver
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "mxgbe_txq.h"
#include "mxgbe_rxq.h"
#include "mxgbe_msix.h"
#include "mxgbe_i2c.h"
#include "mxgbe_gpio.h"
#include "mxgbe_debugfs.h"
#ifdef CONFIG_MXGBE_DCA
#include <asm/sic_regs.h>
#include <asm/sic_regs_access.h>
#endif /* CONFIG_MXGBE_DCA */




/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

#ifdef DEBUG
u32 mxgbe_debug_mask = 0
	/* | MXGBE_DBG_MSK_NAME */	/* FDEBUG - func call */
	/* | MXGBE_DBG_MSK_MAC */	/* MAC */
	/* | MXGBE_DBG_MSK_MEM */	/* Mem Alloc */
	/* | MXGBE_DBG_MSK_NET */	/* Network device - init */
	/* | MXGBE_DBG_MSK_NET_TX */	/* Network device - Transmit */
	/* | MXGBE_DBG_MSK_NET_RX */	/* Network device - Receive */
	/* | MXGBE_DBG_MSK_NET_SKB */	/* Network device - print skb */
	/* | MXGBE_DBG_MSK_TX */
	/* | MXGBE_DBG_MSK_RX */
	/* | MXGBE_DBG_MSK_GPIO */	/* GPIO */
	/* | MXGBE_DBG_MSK_I2C */	/* I2C */
	/* | MXGBE_DBG_MSK_IRQ */	/* MSIX & MAC IRQ */
	/* | MXGBE_DBG_MSK_TX_IRQ */	/* TX IRQ */
	/* | MXGBE_DBG_MSK_RX_IRQ */	/* RX IRQ */
	/* | MXGBE_DBG_MSK_PHY */	/* PHY */
	/* | MXGBE_DBG_MSK_REGS */	/* HW */
	;
#else
u32 mxgbe_debug_mask = 0;
#endif

module_param_named(debug_mask, mxgbe_debug_mask, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(debug_mask, "Mask for debug level (default: 0)");

u32 mxgbe_loopback_mode = 0;
module_param_named(loopback_mode, mxgbe_loopback_mode, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(loopback_mode, "Enable internal loopback (default: 0)");

u32 mxgbe_led_gpio = 0;
module_param_named(led_gpio, mxgbe_led_gpio, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(led_gpio, "Enable led as gpio (default: 0)");

int mxgbe_status = 2;
module_param_named(status, mxgbe_status, int, 0444);
MODULE_PARM_DESC(status, "0 - disable, 1 - enable, other - use devtree");

int mxgbe_maxqueue = -1;
module_param_named(maxqueue, mxgbe_maxqueue, int, 0444);
MODULE_PARM_DESC(maxqueue, "Set tx/rx queue num");

#ifdef CONFIG_MXGBE_DCA
int mxgbe_rx_desc_dca_enable = 1;
module_param_named(rx_desc_dca, mxgbe_rx_desc_dca_enable, int, 0444);
MODULE_PARM_DESC(rx_desc_dca, "0 - disabled; 1 - enabled");

int mxgbe_rx_hdr_dca_enable = 1;
module_param_named(rx_hdr_dca, mxgbe_rx_hdr_dca_enable, int, 0444);
MODULE_PARM_DESC(rx_hdr_dca, "0 - disabled; 1 - enabled");

int mxgbe_rx_hdr_size_dca;
module_param_named(rx_hdr_size_dca, mxgbe_rx_hdr_size_dca, int, 0444);
MODULE_PARM_DESC(rx_hdr_size_dca, "0 - 64 bytes; 1 - 128 bytes");

int mxgbe_ro_rx_data = 1;
module_param_named(ro_rx_data, mxgbe_ro_rx_data, int, 0444);
MODULE_PARM_DESC(ro_rx_data, "0 - disabled; 1 - enabled");

int mxgbe_ro_rx_descr;
module_param_named(ro_rx_descr, mxgbe_ro_rx_descr, int, 0444);
MODULE_PARM_DESC(ro_rx_descr, "0 - disabled; 1 - enabled");

int mxgbe_tx_dca_enable = 1;
module_param_named(tx_dca, mxgbe_tx_dca_enable, int, 0444);
MODULE_PARM_DESC(tx_dca, "0 - disabled; 1 - enabled");

int mxgbe_ro_tx_descr;
module_param_named(ro_tx_descr, mxgbe_ro_tx_descr, int, 0444);
MODULE_PARM_DESC(ro_tx_descr, "0 - disabled; 1 - enabled");

int mxgbe_ro_tx_data = 1;
module_param_named(ro_tx_data, mxgbe_ro_tx_data, int, 0444);
MODULE_PARM_DESC(ro_tx_data, "0 - disabled; 1 - enabled");

#endif /* CONFIG_MXGBE_DCA */

/**
 * Module parameters checker
 *
 * Returns 0 on success, negative on failure
 **/
static int check_parameters(void)
{
	if (mxgbe_debug_mask != 0)
		pr_info(KBUILD_MODNAME ": MODULE_PARM debug_mask = 0x%X\n",
			mxgbe_debug_mask);
	if (mxgbe_loopback_mode != 0)
		pr_info(KBUILD_MODNAME ": MODULE_PARM loopback_mode : %s\n",
			(mxgbe_loopback_mode) ? "On" : "Off");
	if (mxgbe_led_gpio != 0)
		pr_info(KBUILD_MODNAME ": MODULE_PARM led_gpio : %s\n",
			(mxgbe_led_gpio) ? "Enable" : "Disable");
#ifdef CONFIG_MXGBE_DCA
	pr_info(KBUILD_MODNAME ": MODULE_PARM TX dca : %s\n",
		(mxgbe_tx_dca_enable) ? "enabled" : "disabled");
	pr_info(KBUILD_MODNAME ": MODULE_PARM TX decs ro : %s\n",
		(mxgbe_ro_tx_descr) ? "enabled" : "disabled");
	pr_info(KBUILD_MODNAME ": MODULE_PARM TX data ro : %s\n",
		(mxgbe_ro_tx_data) ? "enabled" : "disabled");
	pr_info(KBUILD_MODNAME ": MODULE_PARM RX decs dca : %s\n",
		(mxgbe_rx_desc_dca_enable) ? "enabled" : "disabled");
	pr_info(KBUILD_MODNAME ": MODULE_PARM RX decs ro : %s\n",
		(mxgbe_ro_rx_descr) ? "enabled" : "disabled");
	pr_info(KBUILD_MODNAME ": MODULE_PARM RX hdr dca : %s\n",
		(mxgbe_rx_hdr_dca_enable) ? "enabled" : "disabled");
	if (mxgbe_rx_hdr_dca_enable)
		pr_info(KBUILD_MODNAME ": MODULE_PARM RX header size : %s\n",
			(mxgbe_rx_hdr_size_dca) ? "128" : "64");
	pr_info(KBUILD_MODNAME ": MODULE_PARM RX data ro : %s\n",
		(mxgbe_ro_rx_data) ? "enabled" : "disabled");
#endif /* CONFIG_MXGBE_DCA */

	return 0;
} /* check_parameters */


/**
 ******************************************************************************
 * Board Init Part
 ******************************************************************************
 **/

/**
 * Driver Initialization Routine
 */
int mxgbe_init_board(struct pci_dev *pdev, void __iomem *bar_addr[],
		     phys_addr_t bar_addr_bus[])
{
	int err;
	mxgbe_priv_t *priv;

	/* allocate memory for priv* and ndev */
	priv = mxgbe_net_alloc(pdev, bar_addr[0]);
	if (!priv) {
		dev_err(&pdev->dev,
			"Cannot allocate memory for priv*, aborting\n");
		err = -ENOMEM;
		goto err_out;
	}
	pci_set_drvdata(pdev, priv);

	/* init priv-> */
	priv->pdev = pdev;
	priv->bar0_base = bar_addr[0];
	priv->bar0_base_bus = bar_addr_bus[0];

	priv->tx_ring_count = Q_SIZE_MIN;
	priv->rx_ring_count = Q_SIZE_MIN;

	priv->tx_coalesced_frames = 10;
	priv->tx_coalesce_usecs   = 610; /* 1 msec */
	priv->rx_coalesced_frames = 10;
	priv->rx_coalesce_usecs   = 30;  /* 50 usecs */

#ifdef CONFIG_MXGBE_DCA
	/* PCI EXPRESS BASE SPECIFICATION, REV. 3.0
	 *
	 * Table 2-16: Processing Hint Encoding
	 *
	 * PH[1:0] : 00b
	 * Processing Hint : Bi-directional data structure
	 * Description : Indicates frequent read and/or
	 *               write access to data by Host and device
	 */
	priv->proc_hint = 0;
#endif

	priv->node = dev_to_node(&pdev->dev);
	if (priv->node == NUMA_NO_NODE)
		priv->node = 0;

	if (priv->node >= MAX_NUMNODES) {
		dev_err(&pdev->dev, "node = %d >= MAX_NUMNODES (%d)\n",
			priv->node, MAX_NUMNODES);
		err =  -ENODEV;
		goto err_out;
	}

	err = mxgbe_board_up(priv);
	if (err)
		goto err_out;

	dev_info(&pdev->dev,
#ifdef __sparc__
		 "MAC = %012llX\n", be64_to_cpu(priv->MAC) >> 16);
#else
		 "MAC = %012llX\n", be64_to_cpu(priv->MAC) << 16);
#endif

err_out:
	return err;
} /* mxgbe_init_board */

int mxgbe_board_up(mxgbe_priv_t *priv)
{
	int err;
	int i;

	err = mxgbe_hw_reset(priv);
	if (err)
		goto err_free_priv;

	msleep(20); /* millisecond sleep */

	if (priv->revision == MXGBE_REVISION_ID_BOARD)
		mxgbe_i2c_reset(priv);

	/* Read HW Info */
	err = mxgbe_hw_getinfo(priv);
	if (err) {
		dev_err(&priv->pdev->dev,
			"Wrong hardware, aborting\n");
		goto err_free_priv;
	}

	/* init msix_entries */
	err = mxgbe_msix_prepare(priv);
	if (err)
		goto err_free_priv;

	/* tx/rx queue prio */
	for (i = 0; i < priv->num_tx_queues; i++)
		priv->txq[i].prio = 0;
	for (i = 0; i < priv->num_rx_queues; i++)
		priv->rxq[i].prio = 0;

	/* Alloc pages for tx queue */
	err = mxgbe_txq_alloc_all(priv);
	if (err)
		goto err_free_txq;

	/* Alloc pages for rx queue */
	err = mxgbe_rxq_alloc_all(priv);
	if (err)
		goto err_free_rxq;

	err = mxgbe_hw_init(priv);
	if (err) {
		dev_err(&priv->pdev->dev,
			"hardware busy, aborting\n");
		goto err_free_rxq;
	}

	/* Init I2C for board only */
	if (priv->revision == MXGBE_REVISION_ID_BOARD) {
		priv->i2c_0 = mxgbe_i2c_create(&priv->pdev->dev,
					priv->bar0_base + I2C_0_PRERLO,
					"0 - SFP");
		if (!priv->i2c_0) {
			err = -ENODEV;
			goto err_free_rxq;
		}

		priv->i2c_1 = mxgbe_i2c_create(&priv->pdev->dev,
					priv->bar0_base + I2C_1_PRERLO,
					"1 - VSC");
		if (!priv->i2c_1) {
			err = -ENODEV;
			goto err_free_i2c;
		}

		priv->i2c_2 = mxgbe_i2c_create(&priv->pdev->dev,
					priv->bar0_base + I2C_2_PRERLO,
					"2 - EEPROM");
		if (!priv->i2c_2) {
			err = -ENODEV;
			goto err_free_i2c;
		}
	}

	/* MAC */
	if (priv->ndev->reg_state != NETREG_REGISTERED) {
		if (priv->i2c_2) {
			priv->MAC = mxgbe_i2c_read_mac(priv);
		} else {
			l_set_ethernet_macaddr(priv->pdev, (char *)&priv->MAC);
		}
	}

	/* GPIO */
	err = mxgbe_gpio_probe(priv);
	if (err) {
		dev_err(&priv->pdev->dev,
			"init GPIO failed\n");
		goto err_free_i2c;
	}

	if (priv->ndev->reg_state != NETREG_REGISTERED)
		err = mxgbe_net_register(priv);
	else
		err = mxgbe_net_reinit(priv);
	if (err) {
		if (priv->ndev->reg_state != NETREG_REGISTERED) {
			dev_err(&priv->pdev->dev,
				"Cannot create ndev, aborting\n");
			goto err_free_gpio;
		}
		dev_err(&priv->pdev->dev,
			"Cannot reinit a net device stuff, aborting\n");
		goto err_net_remove;
	}

	/* request_irq */
	err = mxgbe_msix_init(priv);
	if (err) {
		dev_err(&priv->pdev->dev,
			"Cannot request irq, aborting\n");
		goto err_net_remove;
	}

	mxgbe_hw_start(priv);

	if (!priv->mxgbe_dbg_board)
		mxgbe_dbg_board_init(priv);

	return 0;

err_net_remove:
	mxgbe_net_remove(priv);
err_free_gpio:
	mxgbe_gpio_remove();
err_free_i2c:
	if (priv->i2c_2)
		mxgbe_i2c_destroy(priv->i2c_2);
	if (priv->i2c_1)
		mxgbe_i2c_destroy(priv->i2c_1);
	if (priv->i2c_0)
		mxgbe_i2c_destroy(priv->i2c_0);
err_free_rxq:
	mxgbe_rxq_free_all(priv);
err_free_txq:
	mxgbe_txq_free_all(priv);
	mxgbe_msix_free(priv);
err_free_priv:
	mxgbe_net_free(priv);
	return err;
} /* mxgbe_board_up */

/**
 * Cleanup Routine
 */
void mxgbe_release_board(struct pci_dev *pdev)
{
	mxgbe_priv_t *priv = pci_get_drvdata(pdev);
	int qn;

	if (!priv)
		return;

	mxgbe_dbg_board_exit(priv);

	pdev = priv->pdev;

	mxgbe_hw_reset(priv);

	/* free_irq */
	mxgbe_msix_release(priv);

	mxgbe_net_remove(priv);

	mxgbe_gpio_remove();

	if (priv->i2c_2)
		mxgbe_i2c_destroy(priv->i2c_2);
	if (priv->i2c_1)
		mxgbe_i2c_destroy(priv->i2c_1);
	if (priv->i2c_0)
		mxgbe_i2c_destroy(priv->i2c_0);

	for (qn = 0; qn < priv->num_rx_queues; qn++)
		net_rxq_clean_q(priv, qn);

	for (qn = 0; qn < priv->num_tx_queues; qn++)
		net_txq_clean_q(priv, qn);

	mxgbe_rxq_free_all(priv);
	mxgbe_txq_free_all(priv);

	mxgbe_msix_free(priv);

	mxgbe_net_free(priv);
} /* mxgbe_release_board */

void mxgbe_board_down(mxgbe_priv_t *priv)
{
	int qn;

	mxgbe_msix_release(priv);

	mxgbe_gpio_remove();

	if (priv->i2c_2)
		mxgbe_i2c_destroy(priv->i2c_2);
	if (priv->i2c_1)
		mxgbe_i2c_destroy(priv->i2c_1);
	if (priv->i2c_0)
		mxgbe_i2c_destroy(priv->i2c_0);

	for (qn = 0; qn < priv->num_rx_queues; qn++)
		net_rxq_clean_q(priv, qn);

	for (qn = 0; qn < priv->num_tx_queues; qn++)
		net_txq_clean_q(priv, qn);

	mxgbe_rxq_free_all(priv);
	mxgbe_txq_free_all(priv);

	mxgbe_msix_free(priv);
} /* mxgbe_board_down */

#ifdef CONFIG_MXGBE_DCA
#define HC_CTRL_DCAE	BIT(7) /* Direct Cache Access Enable (default: 0) */
/* HC_CTRL_WL3STE : WL3 Steering Tag Enable (default: 1) */

static inline void mxgbe_enable_dca(void)
{
	int node;

	for_each_online_node(node) {
		u32 reg = sic_read_node_nbsr_reg(node, HC_CTRL);

		reg |= (HC_CTRL_DCAE);
		sic_write_node_nbsr_reg(node, HC_CTRL, reg);
	}
}
#endif /* CONFIG_MXGBE_DCA */

/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/


static struct notifier_block mxgbe_notifier = {
	.notifier_call = mxgbe_device_event,
};

/**
 * Driver Registration Routine
 */
static int __init mxgbe_init(void)
{
	int status;

	pr_info(KBUILD_MODNAME ": Init MXGBE module device driver\n");

	if (0 != check_parameters()) {
		pr_err(KBUILD_MODNAME ": Invalid module param, aborting\n");
		return -EINVAL;
	}

#ifdef CONFIG_DEBUG_FS
	mxgbe_dbg_init();
#endif /* CONFIG_DEBUG_FS */

	register_netdevice_notifier(&mxgbe_notifier);

	status = pci_register_driver(&mxgbe_pci_driver);
	if (status != 0) {
		pr_err(KBUILD_MODNAME ": Could not register driver\n");
		goto devexit;
	}

#ifdef CONFIG_MXGBE_DCA
	if (mxgbe_tx_dca_enable ||
	    mxgbe_rx_desc_dca_enable ||
	    mxgbe_rx_hdr_dca_enable)
		mxgbe_enable_dca();
#endif /* CONFIG_MXGBE_DCA */
	pr_debug(KBUILD_MODNAME ": Init done\n");

	return 0;

devexit:
#ifdef CONFIG_DEBUG_FS
	mxgbe_dbg_exit();
#endif /* CONFIG_DEBUG_FS */

	return status;
} /* mxgbe_init */


/**
 * Driver Exit Cleanup Routine
 */
static void __exit mxgbe_exit(void)
{
	unregister_netdevice_notifier(&mxgbe_notifier);

	pci_unregister_driver(&mxgbe_pci_driver);

#ifdef CONFIG_DEBUG_FS
	mxgbe_dbg_exit();
#endif /* CONFIG_DEBUG_FS */

	pr_debug(KBUILD_MODNAME ": Exit\n");
} /* mxgbe_exit */


module_init(mxgbe_init);
module_exit(mxgbe_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("MXGBE module device driver");
MODULE_VERSION(DRIVER_VERSION);
