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


mxgbe_priv_t *mxgbe_net_alloc(struct pci_dev *pdev, void __iomem *base);
int mxgbe_net_register(mxgbe_priv_t *priv);
void mxgbe_net_remove(mxgbe_priv_t *priv);
void mxgbe_net_free(mxgbe_priv_t *priv);


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
	int i;

	assert(pdev);
	if (!pdev)
		return -ENODEV;

	assert(bar_addr[0]);


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

	raw_spin_lock_init(&priv->mgio_lock);

	/* HW reset */
	err = mxgbe_hw_reset(priv);
	if (err) {
		goto err_free_priv;
	}
	msleep(20); /* millisecond sleep */

	/* Reset I2C - start autoread MAC */
#ifndef __sparc__
	mxgbe_i2c_reset(priv);
#endif

	/* Read HW Info */
	err = mxgbe_hw_getinfo(priv);
	dev_dbg(&pdev->dev,
		"Tx queue num = %u,  Tx bufsize = %u(0x%X)\n",
		priv->num_tx_queues, priv->hw_tx_bufsize, priv->hw_tx_bufsize);
	dev_dbg(&pdev->dev,
		"Rx queue num = %u,  Rx bufsize = %u(0x%X)\n",
		priv->num_rx_queues, priv->hw_rx_bufsize, priv->hw_rx_bufsize);
	if (err) {
		dev_err(&pdev->dev,
			"Wrong hardware, aborting\n");
		goto err_free_priv;
	}

	/* init msix_entries */
	err = mxgbe_msix_prepare(priv);
	if (err) {
		goto err_free_priv;
	}

	/* = Tx/Rx queue prio = */
	for (i = 0; i < priv->num_tx_queues; i++) {
		priv->txq[i].prio = 7;	/* TODO: */
	}
	for (i = 0; i < priv->num_rx_queues; i++) {
		priv->rxq[i].prio = 7;	/* TODO: */
	}

	/* = Alloc pages for Tx queue = */
	err = mxgbe_txq_alloc_all(priv);
	if (err)
		goto err_free_txq;

	/* = Alloc pages for Rx queue = */
	err = mxgbe_rxq_alloc_all(priv);
	if (err)
		goto err_free_rxq;

	err = mxgbe_hw_init(priv);
	if (err) {
		dev_err(&pdev->dev,
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
	if (priv->i2c_2) {
		priv->MAC = cpu_to_be64(mxgbe_i2c_read_mac(priv)) >> 16;
	} else {
		l_set_ethernet_macaddr(pdev, (char *)&priv->MAC);
	}
	dev_info(&pdev->dev,
#ifdef __sparc__
		 "MAC = %012llX\n", be64_to_cpu(priv->MAC >> 16));
#else
		 "MAC = %012llX\n", be64_to_cpu(priv->MAC << 16));
#endif

	/* GPIO */
	err = mxgbe_gpio_probe(priv);
	if (err) {
		dev_err(&pdev->dev,
			"init GPIO failed\n");
		goto err_free_i2c;
	}

	/* Create ndev */
	err = mxgbe_net_register(priv);
	if (err) {
		dev_err(&pdev->dev,
			"Cannot create ndev, aborting\n");
		goto err_free_gpio;
	}

	/* request_irq */
	err = mxgbe_msix_init(priv);
	if (err) {
		dev_err(&pdev->dev,
			"Cannot request irq, aborting\n");
		goto err_net_remove;
	}

	mxgbe_hw_start(priv);

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
/*err_disable_msix:*/
	mxgbe_msix_free(priv);
err_free_priv:
	mxgbe_net_free(priv);
err_out:
	return err;
} /* mxgbe_init_board */


/**
 * Cleanup Routine
 */
void mxgbe_release_board(struct pci_dev *pdev)
{
	mxgbe_priv_t *priv;

	assert(pdev);
	if (!pdev)
		return;

	priv = pci_get_drvdata(pdev);
	assert(priv);
	if (!priv)
		return;

	mxgbe_dbg_board_exit(priv);

	pdev = priv->pdev;

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

	mxgbe_rxq_free_all(priv);
	mxgbe_txq_free_all(priv);

	mxgbe_msix_free(priv);

	mxgbe_net_free(priv);
} /* mxgbe_release_board */


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

int mxgbe_device_event(struct notifier_block *unused, unsigned long event,
		       void *ptr);

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
MODULE_SUPPORTED_DEVICE("MXGBE, DeviceID:" MXGBE_DEVICE_ID
			", VendorID:" MXGBE_VENDOR_ID);
MODULE_VERSION(DRIVER_VERSION);
