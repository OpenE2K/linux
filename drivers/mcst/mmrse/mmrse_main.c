/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mmrse.c - MMR/M-SE module device driver
 */

#include "mmrse_main.h"
#include "mmrse_regs.h"
#include "mmrse_dbg.h"


#define DRIVER_VERSION		"1.0.1"


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

static uint16_t rtl_version = 0;
module_param(rtl_version, ushort, S_IRUGO);
MODULE_PARM_DESC(rtl_version,
		 "RTL Version (valid: 0..255, default: 0, don't check: 256)");

#ifdef DEBUG
uint32_t debug_mask = (uint32_t)0
	/*| DBG_MSK_CDEV*/
	/*| DBG_MSK_CDEV_BC*/
	/*| DBG_MSK_CDEV_RT*/
	/*| DBG_MSK_CDEV_BM*/
	/*| DBG_MSK_IRQ*/
	/*| DBG_MSK_IRQ_BC*/
	/*| DBG_MSK_IRQ_RT*/
	/*| DBG_MSK_IRQ_BM*/
	;
#else
uint32_t debug_mask = 0;
#endif
module_param(debug_mask, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(debug_mask, "Mask for debug level (default: 0)");

static uint16_t log_pages = 8;	/* default 32K */
module_param(log_pages, ushort, S_IRUGO);
MODULE_PARM_DESC(log_pages,
		 "Number of 4K pages for Bus Monitor log "
		 "(valid: 8, 16, 32, 64; default: 8)");


/**
 * Module parameters checker
 *
 * Returns 0 on success, negative on failure
 **/
static int check_parameters(void)
{
	if (rtl_version > 256) {
		pr_err(KBUILD_MODNAME ": invalid parameter rtl_version: %u\n",
		       rtl_version);
		return -1;
	}

	if ((8 != log_pages) && (16 != log_pages) &&
	    (32 != log_pages) && (64 != log_pages)) {
		pr_err(KBUILD_MODNAME ": invalid parameter log_pages: %u\n",
		       log_pages);
		return -1;
	}

	return 0;
} /* check_parameters */


/**
 ******************************************************************************
 * Hardware part - common
 ******************************************************************************
 **/

/**
 * Set ENDIANES
 *
 * @base_addr:	registers base address
 */
static inline void hw_set_endianes(void __iomem *base_addr)
{
	reg32wr(COMMON_STATUS_SET_ACCESSMODE, P_COMMON_STATUS_REG(base_addr));
}

/**
 * Get RTL Version
 *
 * @base_addr:	registers base address
 *
 * Returns RTL Version/Revision
 */
static inline uint8_t hw_get_rtlversion(void __iomem *base_addr)
{
	return COMMON_STATUS_GET_VERSION(
		reg32rd(P_COMMON_STATUS_REG(base_addr)));
}

/**
 * Get Interrupt Souce
 *
 * @base_addr:	registers base address
 *
 * Returns Interrupt Souce: BM, RT, BC
 */
static inline uint8_t hw_get_intsrc(void __iomem *base_addr)
{
	return COMMON_STATUS_GET_INTSRC(
		reg32rd(P_COMMON_STATUS_REG(base_addr)));
}


void mmrse_bc_irq_handler(mmrse_priv_t *priv);
void mmrse_bm_irq_handler(mmrse_priv_t *priv);
void mmrse_rt_irq_handler(mmrse_priv_t *priv);

/**
 * Interrupt handler
 *
 * @irq:	not used
 * @dev_id:	PCI device information struct
 */
static irqreturn_t irq_handler(int irq, void *dev_id)
{
	mmrse_priv_t *priv;
	uint8_t irq_stat;


	if (!dev_id)
		return IRQ_NONE;

	priv = pci_get_drvdata(dev_id);
	if (!priv)
		return IRQ_NONE;

	if (!priv->reg_base)
		return IRQ_NONE;

	/* Read IRQ status */
	irq_stat = hw_get_intsrc(priv->reg_base);
	if (!irq_stat)
		return IRQ_NONE;

	nDEV_DBG(DBG_MSK_IRQ, &priv->pdev->dev, "IRQ: stat = 0x%X\n", irq_stat);

	if (irq_stat & COMMON_STATUS_INTSRC_BC)
		mmrse_bc_irq_handler(priv);

	if (irq_stat & COMMON_STATUS_INTSRC_RT)
		mmrse_rt_irq_handler(priv);

	if (irq_stat & COMMON_STATUS_INTSRC_BM)
		mmrse_bm_irq_handler(priv);

	return IRQ_HANDLED;
} /* irq_handler */


/**
 ******************************************************************************
 * Driver Part
 ******************************************************************************
 **/

void mmrse_hw_bc_reset(mmrse_priv_t *priv, int rst);
void mmrse_hw_bc_init(mmrse_priv_t *priv, dma_addr_t mem_addr);
void mmrse_hw_rt_reset(mmrse_priv_t *priv, int rst);
void mmrse_hw_bm_reset(mmrse_priv_t *priv);

int mmrse_cdev_register(mmrse_priv_t *priv, int devtype);
void mmrse_cdev_remove(mmrse_priv_t *priv, int devtype);


/**
 * Driver Initialization Routine
 */
static int init_board(struct pci_dev *pdev, mmrse_priv_t **dev_priv,
		      int dma_dis, void __iomem *base_addr,
		      void __iomem *buff_addr)
{
	int err;
	mmrse_priv_t *priv;
	uint8_t rtl_ver;
	int i;


	hw_set_endianes(base_addr);

	/* Check RTL Version */
	rtl_ver = hw_get_rtlversion(base_addr);
	if (rtl_version != 256) {
		if (rtl_ver != (uint8_t)rtl_version) {
			dev_err(&pdev->dev,
				"wrong RTL version (%d), aborting\n", rtl_ver);
			err = -EFAULT;
			goto err_out;
		}
	}
	dev_info(&pdev->dev, "rtl version %d\n", rtl_ver);

	/* allocate memory for priv* */
	priv = kzalloc(sizeof(mmrse_priv_t), GFP_KERNEL);
	if (!priv) {
		dev_err(&pdev->dev,
			"cannot allocate memory for priv*, aborting\n");
		err = -ENOMEM;
		goto err_out;
	}

	*dev_priv = priv;

	/* init priv-> */
	priv->pdev = pdev;
	priv->reg_base = base_addr;
	priv->buf_base = buff_addr;
	priv->dma_dis = dma_dis;

	spin_lock_init(&priv->cdev_open_lock);
	spin_lock_init(&priv->bc_lock);
	spin_lock_init(&priv->rt_lock);
	spin_lock_init(&priv->bm_lock);

	/* Full Reset */
	mmrse_hw_bc_reset(priv, 1);
	mmrse_hw_rt_reset(priv, 1 /*hw reset*/);
	mmrse_hw_bm_reset(priv);

	/* Create cdev */
	err = mmrse_cdev_register(priv, MMRSE_CDEV_MAIN);
	if (err) {
		dev_err(&pdev->dev,
			"cannot create main cdev, aborting\n");
		goto err_free_mem;
	}
	err = mmrse_cdev_register(priv, MMRSE_CDEV_BC);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot Create BC cdev, aborting\n");
		goto err_dev_remove;
	}
	err = mmrse_cdev_register(priv, MMRSE_CDEV_RT);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot Create RT cdev, aborting\n");
		goto err_dev_bc_remove;
	}
	err = mmrse_cdev_register(priv, MMRSE_CDEV_BM);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot Create BM cdev, aborting\n");
		goto err_dev_rt_remove;
	}


	/* Alloc pages for DMA buffers - BC & BM */
	priv->bm_log_size = BM_LOG_PAGE_SIZE * log_pages;
	priv->bc_buff_size = (BC_BUFF_SIZE < PAGE_SIZE) ? PAGE_SIZE
							: BC_BUFF_SIZE;
	priv->dma_buff_size = priv->bc_buff_size + priv->bm_log_size;
	priv->dma_buff = dma_alloc_coherent(&pdev->dev, priv->dma_buff_size,
				&(priv->dma_buff_handle), GFP_KERNEL);
	if (!priv->dma_buff) {
		dev_err(&pdev->dev,
			"ERROR: Cannot allocate memory for dma, aborting\n");
		err = -ENOMEM;
		goto err_dev_bm_remove;
	}
	dev_dbg(&pdev->dev,
		"Alloc %zd(0x%zX) mem for BC bufs "
		"and BM log at 0x%p (hw:0x%p)\n",
		priv->dma_buff_size, priv->dma_buff_size,
		priv->dma_buff, (void *)(priv->dma_buff_handle));
	/* dma_alloc_coherent use PAGE_ALIGN() */
	assert((((uint64_t)priv->dma_buff) & 0x0FFF) == 0);

	/* Clean buffers */
	/* BCSND */
	for (i = 0; i < (32 * 32); i++) {
		u16 *dma_buff;
		dma_buff = (u16 *)priv->dma_buff + i;
		*dma_buff = 0;
	}
	/* BCREC */
	for (i = 0; i < (32 * 32); i++) {
		u16 *dma_buff;
		dma_buff = (u16 *)priv->dma_buff + i + (32 * 32);
		*dma_buff = 0;
	}
	/* RTOUT */
	for (i = 0; i < (16 * 32); i++) {
		u32 *ram_buff;
		ram_buff = (u32 *)priv->buf_base + i;
		buf32wr(0, ram_buff);
	}
	/* RTIN */
	for (i = 0; i < (16 * 32); i++) {
		u32 *ram_buff;
		ram_buff = (u32 *)priv->buf_base + i + (16 * 32);
		buf32wr(0, ram_buff);
	}

	/** Init BC */
	init_waitqueue_head(&priv->wq_bc_event);
	mmrse_hw_bc_init(priv, priv->dma_buff_handle);

	/** Init RT */
	init_waitqueue_head(&priv->wq_rt_event);
	/* init in dev-open/ioctl */

	/** Init BM */
	init_waitqueue_head(&priv->wq_bm_event);
	dev_dbg(&pdev->dev,
		"Monitor log base address: 0x%p (hw:0x%p)\n",
		priv->dma_buff + priv->bc_buff_size,
		(void *)(priv->dma_buff_handle + priv->bc_buff_size));

	return 0;

err_dev_bm_remove:
	mmrse_cdev_remove(priv, MMRSE_CDEV_BM);
err_dev_rt_remove:
	mmrse_cdev_remove(priv, MMRSE_CDEV_RT);
err_dev_bc_remove:
	mmrse_cdev_remove(priv, MMRSE_CDEV_BC);
err_dev_remove:
	mmrse_cdev_remove(priv, MMRSE_CDEV_MAIN);
err_free_mem:
	kfree(priv);
err_out:
	return err;
} /* init_board */

/**
 * Cleanup Routine
 */
static void release_board(mmrse_priv_t *priv)
{
	struct pci_dev *pdev;

	if (priv) {
		/* Full Reset */
		mmrse_hw_bc_reset(priv, 1);
		mmrse_hw_rt_reset(priv, 0 /* deactivate */);
		mmrse_hw_bm_reset(priv);

		/* free pages for DMA buffers - BC & BM */
		pdev = priv->pdev;
		if (priv->dma_buff)
			dma_free_coherent(&pdev->dev, priv->dma_buff_size,
				priv->dma_buff, priv->dma_buff_handle);

		/* remove cdev */
		mmrse_cdev_remove(priv, MMRSE_CDEV_BM);
		mmrse_cdev_remove(priv, MMRSE_CDEV_RT);
		mmrse_cdev_remove(priv, MMRSE_CDEV_BC);
		mmrse_cdev_remove(priv, MMRSE_CDEV_MAIN);

		/* release priv */
		kfree(priv);
	}
} /* release_board */


/**
 ******************************************************************************
 * PCI Part
 ******************************************************************************
 **/

#ifdef CONFIG_DEBUG_FS
void mmrse_dbg_board_init(mmrse_priv_t *priv);
void mmrse_dbg_board_exit(mmrse_priv_t *priv);
#endif /*CONFIG_DEBUG_FS*/


/**
 * Device Initialization Routine
 *
 * @pdev: PCI device information struct
 * @pid: entry in ids
 *
 * Returns 0 on success, negative on failure
 */
static int probe(struct pci_dev *pdev, const struct pci_device_id *pid)
{
	int err = 0;
	int dma_dis = 0;
	void __iomem *base_addr = NULL;
	void __iomem *buff_addr = NULL;
	mmrse_priv_t *priv;


	if (!pdev)
		return -ENODEV;

	dev_info(&pdev->dev, "initializing device %04x:%04x\n",
		 pdev->vendor, pdev->device);

	err = pci_enable_device(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"failed to enable device - err=%d\n", err);
		goto failure;
	}

	err = pci_request_regions(pdev, KBUILD_MODNAME);
	if (err) {
		dev_err(&pdev->dev,
			"cannot obtain pci resources, aborting\n");
		goto failure_release_pci;
	}

	base_addr = pci_iomap(pdev, 0, PCI_PORT_SIZE);
	if (base_addr == NULL) {
		err = -ENOMEM;
		dev_err(&pdev->dev,
			"cannot map device registers, aborting\n");
		goto failure_release_regions;
	}

	buff_addr = pci_iomap(pdev, 1, PCI_BUFF_SIZE);
	if (buff_addr == NULL) {
		err = -ENOMEM;
		dev_err(&pdev->dev,
			"cannot map device buffers, aborting\n");
		goto failure_release_regions;
	}

	pci_pme_active(pdev, false);

	if (pci_set_dma_mask(pdev, DMA_BIT_MASK(32))) {
		dev_warn(&pdev->dev,
			"no usable DMA configuration, DMA disabled\n");
		dma_dis = 1;
	} else {
		err = pci_set_mwi(pdev);
		if (err) {
			dev_warn(&pdev->dev,
				"cannot enable memory-write-invalidate"
				" pci transaction\n");
		}
		pci_set_master(pdev);
		pci_set_cacheline_size(pdev);
	}

	err = init_board(pdev, &priv, dma_dis, base_addr, buff_addr);
	if (err)
		goto failure_iounmap;

	err = request_irq(pdev->irq, irq_handler, IRQF_SHARED,
			  dev_name(priv->dev), (void *)pdev);
	if (err) {
		dev_err(&pdev->dev,
			"cannot request pci irq %d, aborting\n", pdev->irq);
		goto failure_init_board;
	}

	pci_set_drvdata(pdev, priv);

#ifdef CONFIG_DEBUG_FS
	mmrse_dbg_board_init(priv);
#endif /*CONFIG_DEBUG_FS*/

	dev_dbg(&pdev->dev, "pci probe - done\n");

	return 0;

failure_init_board:
	release_board(priv);
	pci_set_drvdata(pdev, NULL);
	if (!priv->dma_dis)
		pci_clear_mwi(pdev);
failure_iounmap:
	if (base_addr != NULL)
		pci_iounmap(pdev, base_addr);
	if (buff_addr != NULL)
		pci_iounmap(pdev, buff_addr);
failure_release_regions:
	pci_release_regions(pdev);
failure_release_pci:
	pci_disable_device(pdev);
failure:
	return err;
} /* probe */

/**
 * Device Removal Routine
 * @pdev: PCI device information struct
 */
static void remove(struct pci_dev *pdev)
{
	mmrse_priv_t *priv;

	if (!pdev)
		return;

	dev_dbg(&pdev->dev, "remove pci device\n");

	priv = pci_get_drvdata(pdev);
	if (!priv)
		return;

#ifdef CONFIG_DEBUG_FS
	mmrse_dbg_board_exit(priv);
#endif /*CONFIG_DEBUG_FS*/

	irq_set_affinity_hint(pdev->irq, NULL);
	free_irq(pdev->irq, (void *)pdev);

	release_board(priv);
	pci_set_drvdata(pdev, NULL);
	if (!priv->dma_dis)
		pci_clear_mwi(pdev);

	if (!priv->reg_base)
		pci_iounmap(pdev, priv->reg_base);
	if (!priv->buf_base)
		pci_iounmap(pdev, priv->buf_base);

	pci_release_regions(pdev);

	pci_disable_device(pdev);

	pr_debug(KBUILD_MODNAME ": remove pci device - done\n");
} /* remove */


#ifdef CONFIG_PM

static int suspend(struct pci_dev *pdev, pm_message_t state)
{
	mmrse_priv_t *priv = pci_get_drvdata(pdev);

	if (priv->bc_device_open ||
	    priv->bm_device_open ||
	    priv->rt_device_open)
		return -EBUSY;

	pci_save_state(pdev);
	pci_clear_master(pdev);
	pci_disable_device(pdev);

	return 0;
} /* suspend */

static int resume(struct pci_dev *pdev)
{
	int err;

	pci_restore_state(pdev);

	err = pci_enable_device_mem(pdev);
	if (err) {
		dev_err(&pdev->dev,
			"cannot enable pci device from suspend state\n");
		return err;
	}

	pci_set_master(pdev);

	return 0;
} /* resume */

static void shutdown(struct pci_dev *pdev)
{
	mmrse_priv_t *priv = pci_get_drvdata(pdev);

	if (priv->bc_device_open ||
	    priv->bm_device_open ||
	    priv->rt_device_open)
		return;

	pci_save_state(pdev);
	pci_clear_master(pdev);
} /* shutdown */

#endif /* CONFIG_PM */


static const struct pci_device_id ids[] = {
	{
		.vendor		= VENDOR_ID,
		.device		= DEVICE_ID,
		.subvendor	= SUBSYSTEM_VENDOR_ID,
		.subdevice	= SUBSYSTEM_DEVICE_ID,
	},
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, ids);

/* PCI Device API Driver */
static struct pci_driver mmrse_pci_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= ids,
	.probe		= probe,
	.remove		= remove,
#ifdef CONFIG_PM
	.shutdown	= shutdown,
	.resume		= resume,
	.suspend	= suspend,
#endif
};


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

int __init mmrse_dev_init(void);
void __exit mmrse_dev_exit(void);

#ifdef CONFIG_DEBUG_FS
void mmrse_dbg_init(void);
void mmrse_dbg_exit(void);
#endif /*CONFIG_DEBUG_FS*/


/**
 * Driver Registration Routine
 *
 * mmrse_init is the first routine called when the driver is loaded.
 * All it does is register with the PCI subsystem.
 */
static int __init mmrse_init(void)
{
	int status;

	pr_info(KBUILD_MODNAME ": init MMR/M-SE module device driver\n");

	if (0 != check_parameters()) {
		pr_err(KBUILD_MODNAME
		       ": invalid module parameters, aborting\n");
		return -EINVAL;
	}

#ifdef CONFIG_DEBUG_FS
	mmrse_dbg_init();
#endif /* CONFIG_DEBUG_FS */

	mmrse_dev_init(); /* register class for cdev */

	status = pci_register_driver(&mmrse_pci_driver);
	if (status != 0) {
		pr_err(KBUILD_MODNAME ": could not register driver\n");
#ifdef CONFIG_DEBUG_FS
		mmrse_dbg_exit();
#endif /*CONFIG_DEBUG_FS*/
		return status;
	}

	pr_debug(KBUILD_MODNAME ": init done\n");

	return 0;
} /* mmrse_init */

/**
 * Driver Exit Cleanup Routine
 *
 * mmrse_exit is called just before the driver is removed from memory.
 */
static void __exit mmrse_exit(void)
{
	pci_unregister_driver(&mmrse_pci_driver);

#ifdef CONFIG_DEBUG_FS
	mmrse_dbg_exit();
#endif /*CONFIG_DEBUG_FS*/

	mmrse_dev_exit();

	pr_debug(KBUILD_MODNAME ": exit\n");
} /* mmrse_exit */


module_init(mmrse_init);
module_exit(mmrse_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("MMR/M-SE module device driver");
MODULE_SUPPORTED_DEVICE("MMR/M-SE PMC card: " VENDOR_ID ":" DEVICE_ID);
MODULE_VERSION(DRIVER_VERSION);
