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


mxgbe_priv_t *mxgbe_net_alloc(struct pci_dev *pdev);
int mxgbe_net_register(mxgbe_priv_t *priv);
void mxgbe_net_remove(mxgbe_priv_t *priv);
void mxgbe_net_free(mxgbe_priv_t *priv);


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

#ifdef DEBUG
u32 mxgbe_debug_mask =
	  MXGBE_DBG_MSK_UNK		/* mxgbe_print_all_regs() */
	/* | MXGBE_DBG_MSK_NAME */	/* FDEBUG - func call */
	| MXGBE_DBG_MSK_MODULE		/* Main: module init */
	| MXGBE_DBG_MSK_PCI		/* PCI */
	/* | MXGBE_DBG_MSK_MAC */	/* MAC */
	/* | MXGBE_DBG_MSK_MEM */	/* Mem Alloc */
	| MXGBE_DBG_MSK_NET		/* Network device - init */
	/* | MXGBE_DBG_MSK_NET_TX */	/* Network device - Transmit */
	/* | MXGBE_DBG_MSK_NET_RX */	/* Network device - Receive */
	/* | MXGBE_DBG_MSK_NET_SKB */	/* Network device - print skb */
	/* | MXGBE_DBG_MSK_TX */
	/* | MXGBE_DBG_MSK_RX */
	/* | MXGBE_DBG_MSK_GPIO */	/* GPIO */
	/* | MXGBE_DBG_MSK_I2C */	/* I2C */
	| MXGBE_DBG_MSK_IRQ	/* MSIX & MAC IRQ */
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

u32 mxgbe_renameeth = 0;
module_param_named(renameeth, mxgbe_renameeth, uint, S_IRUGO | S_IWUSR);
MODULE_PARM_DESC(renameeth, "Rename eth* to " MXGBE_DEVNAME "* (default: 0)");


/**
 * Module parameters checker
 *
 * Returns 0 on success, negative on failure
 **/
static int check_parameters(void)
{
	FDEBUG;

	if (mxgbe_debug_mask != 0)
		LOG_MSG("MODULE_PARM debug_mask = 0x%X\n", mxgbe_debug_mask);
	if (mxgbe_loopback_mode != 0)
		LOG_MSG("MODULE_PARM loopback_mode : %s\n",
			(mxgbe_loopback_mode) ? "On" : "Off");
	if (mxgbe_led_gpio != 0)
		LOG_MSG("MODULE_PARM led_gpio : %s\n",
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

	FDEBUG;

	assert(pdev);
	if (!pdev)
		return -ENODEV;

	assert(bar_addr[0]);


	/* allocate memory for priv* and ndev */
/*
	priv = kzalloc_node(sizeof(mxgbe_priv_t),
			    GFP_KERNEL, dev_to_node(&pdev->dev));
	if (!priv) {
		dev_err(&pdev->dev,
			"ERROR: Cannot allocate memory for priv*, aborting\n");
		err = -ENOMEM;
		goto err_out;
	}
*/
	priv = mxgbe_net_alloc(pdev);
	if (!priv) {
		dev_err(&pdev->dev,
			"ERROR: Cannot allocate memory for priv*, aborting\n");
		err = -ENOMEM;
		goto err_out;
	}
	pci_set_drvdata(pdev, priv);

	/* init priv-> */
	priv->pdev = pdev;
	priv->bar0_base = bar_addr[0];
	priv->bar0_base_bus = bar_addr_bus[0];

	/* HW reset */
	err = mxgbe_hw_reset(priv);
	if (err) {
		goto err_free_priv;
	}
	msleep(20); /* millisecond sleep */

	/* Reset I2C - start autoread MAC */
	mxgbe_i2c_reset(priv);

	/* Read HW Info */
	err = mxgbe_hw_getinfo(priv);
	DEV_DBG(MXGBE_DBG_MSK_MODULE, &pdev->dev,
		"Tx queue num = %u,  Tx bufsize = %u(0x%X)\n",
		priv->num_tx_queues, priv->hw_tx_bufsize, priv->hw_tx_bufsize);
	DEV_DBG(MXGBE_DBG_MSK_MODULE, &pdev->dev,
		"Rx queue num = %u,  Rx bufsize = %u(0x%X)\n",
		priv->num_rx_queues, priv->hw_rx_bufsize, priv->hw_rx_bufsize);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Wrong hardware, aborting\n");
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


#if 0
	/* DEBUG: */
	if (mxgbe_debug_mask & MXGBE_DBG_MSK_UNK)
		mxgbe_print_all_regs(priv, 0
				     | MXGBE_PRINTREG_MAC
				     | MXGBE_PRINTREG_TX
				     | MXGBE_PRINTREG_TXQ
				     | MXGBE_PRINTREG_RX
				     | MXGBE_PRINTREG_RXQ
				    );
#endif

	err = mxgbe_hw_init(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: hardware busy, aborting\n");
		goto err_free_rxq;
	}

	/* Init I2C */
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

	/* MAC */
	priv->MAC = cpu_to_be64(mxgbe_i2c_read_mac(priv)) >> 16;
	DEV_DBG(MXGBE_DBG_MSK_MODULE, &pdev->dev,
		"MAC = %012llX\n", priv->MAC);

	/* GPIO */
	err = mxgbe_gpio_probe(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: init GPIO failed\n");
		goto err_free_i2c;
	}

	/* Create ndev */
	err = mxgbe_net_register(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot create ndev, aborting\n");
		goto err_free_gpio;
	}

	/* request_irq */
	err = mxgbe_msix_init(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot request irq, aborting\n");
		goto err_net_remove;
	}

	mxgbe_hw_start(priv);

	mxgbe_dbg_board_init(priv);

#if 0
	/* DEBUG: */
	if (mxgbe_debug_mask & MXGBE_DBG_MSK_UNK)
		mxgbe_print_all_regs(priv, 0
				     | MXGBE_PRINTREG_MAC
				     | MXGBE_PRINTREG_TX
				     | MXGBE_PRINTREG_TXQ
				     | MXGBE_PRINTREG_RX
				     | MXGBE_PRINTREG_RXQ
				     | MXGBE_PRINTREG_IRQ
				    );
#endif

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

	FDEBUG;

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

	mxgbe_i2c_destroy(priv->i2c_2);
	mxgbe_i2c_destroy(priv->i2c_1);
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

/**
 * Driver Registration Routine
 */
static int __init mxgbe_init(void)
{
	int status;

	FDEBUG;

	PDEBUG(MXGBE_DBG_MSK_MODULE,
	       "------------------------------------------\n");
	LOG_MSG("Init MXGBE module device driver\n");

	if (0 != check_parameters()) {
		ERR_MSG("ERROR: Invalid module parameters, aborting\n");
		return -EINVAL;
	}

	mxgbe_dbg_init();


	status = pci_register_driver(&mxgbe_pci_driver);
	if (status != 0) {
		ERR_MSG("ERROR: Could not register driver\n");
		goto devexit;
	}

	PDEBUG(MXGBE_DBG_MSK_MODULE, "Init done\n");
	return 0;

devexit:
	mxgbe_dbg_exit();
	return status;
} /* mxgbe_init */


/**
 * Driver Exit Cleanup Routine
 */
static void __exit mxgbe_exit(void)
{
	FDEBUG;

	pci_unregister_driver(&mxgbe_pci_driver);

	mxgbe_dbg_exit();

	PDEBUG(MXGBE_DBG_MSK_MODULE, "Exit\n");
} /* mxgbe_exit */


module_init(mxgbe_init);
module_exit(mxgbe_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Andrey Kalita <Andrey.V.Kalita@mcst.ru>");
MODULE_DESCRIPTION("MXGBE module device driver");
MODULE_SUPPORTED_DEVICE("MXGBE, DeviceID:" MXGBE_DEVICE_ID
			", VendorID:" MXGBE_VENDOR_ID);
MODULE_VERSION(DRIVER_VERSION);
