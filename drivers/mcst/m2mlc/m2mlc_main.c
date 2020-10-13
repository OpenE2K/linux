/**
 * m2mlc.c - M2MLC module device driver
 */

#include <linux/moduleparam.h>

#include "m2mlc.h"


#ifdef USE_MUL2ALIGN
#define MUL2ALIGN 2
#else
#define MUL2ALIGN 1
#endif /* USE_MUL2ALIGN */


u32 m2mlc_read_reg32(void __iomem *base_addr, u32 port);
void m2mlc_write_reg32(void __iomem *base_addr, u32 port, u32 val);
irqreturn_t m2mlc_irq_handler(int irq, void *dev_id);
u16 m2mlc_hw_get_niccapability(struct pci_dev *pdev);
int m2mlc_hw_reset(void __iomem *base_addr, int first);
void m2mlc_hw_init(m2mlc_priv_t *priv);
void m2mlc_hw_set_endianes(void __iomem *base_addr);

int m2mlc_cdev_register(m2mlc_priv_t *priv);
void m2mlc_cdev_remove(m2mlc_priv_t *priv);

#ifdef ENABLE_NET_DEV
int m2mlc_net_register(m2mlc_priv_t *priv);
void m2mlc_net_remove(m2mlc_priv_t *priv);
#endif /* ENABLE_NET_DEV */

int __init m2mlc_dev_init(void);
void m2mlc_dev_exit(void);


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

u16 rtl_version = NICCPB_PROCVAL;
module_param(rtl_version, ushort, S_IRUGO);
MODULE_PARM_DESC(rtl_version,
		 "RTL Version (default: 20, don't check: 0)");

#ifdef DEBUG
u32 debug_mask =
	  M2MLC_DBG_MSK_UNK
	| M2MLC_DBG_MSK_MODULE
	| M2MLC_DBG_MSK_PCI
	| M2MLC_DBG_MSK_CDEV
	| M2MLC_DBG_MSK_MEM
	| M2MLC_DBG_MSK_HW
	| M2MLC_DBG_MSK_IRQ
	| M2MLC_DBG_MSK_REGS
	;
#else
u32 debug_mask = 0;
#endif

module_param(debug_mask, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(debug_mask, "Mask for debug level (default: 0)");

u32 softreset_enable = 0;

module_param(softreset_enable, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(softreset_enable,
		 "Set to 1 to enable softreset on reload (default: 0)");

u32 timeout_retry = 0;
u32 timeout_counter = 0;

module_param(timeout_retry, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(timeout_retry,
		 "Set retry count for DMA descriptors to 0..3 (default: 0)");

module_param(timeout_counter, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(timeout_counter,
		 "Set timeout to n*5 mks (default: 0; typical: 100000)");

unsigned int dma_max_seg_size = 65536;
unsigned long dma_seg_boundary = 0xFFFFFFFF;

module_param(dma_max_seg_size, uint, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(dma_max_seg_size,
		 "Set max_seg_size for DMA memory (default: 65536)");

module_param(dma_seg_boundary, ulong, S_IRUGO|S_IWUSR);
MODULE_PARM_DESC(dma_seg_boundary,
		 "Set seg_boundary for DMA memory (default: 0xFFFFFFFF)");


/**
 * Module parameters checker
 *
 * Returns 0 on success, negative on failure
 **/
static int check_parameters(void)
{
	if (rtl_version > NICCPB_PROCVAL) {
		ERR_MSG("ERROR: Invalid parameter rtl_version: %u" \
			" (max valid: %u)\n",
			rtl_version, NICCPB_PROCVAL);
		return -1;
	}

	if (softreset_enable > 1) {
		ERR_MSG("ERROR: Invalid parameter softreset_enable: %u" \
			" (max valid: %u)\n",
			softreset_enable, 1);
		return -1;
	}

	if (timeout_retry > 3) {
		ERR_MSG("ERROR: Invalid parameter timeout_retry: %u" \
			" (max valid: %u)\n",
			timeout_retry, 3);
		return -1;
	}

	if ((timeout_counter != 0) && (timeout_counter < 1000)) {
		ERR_MSG("ERROR: Invalid parameter timeout_counter: %u" \
			" (min valid: %u = 5ms)\n",
			timeout_counter, 1000);
		return -1;
	}

	if (timeout_counter > 1024*1024*1024) {
		ERR_MSG("ERROR: Invalid parameter timeout_counter: %u" \
			" (max valid: %u)\n",
			timeout_counter, 1024*1024*1024);
		return -1;
	}

	return 0;
} /* check_parameters */


/**
 ******************************************************************************
 * Fake dev Part
 ******************************************************************************
 **/

static int fakedev_probe(struct platform_device *device)
{
	/* create iommu mapping */
	device->dev.dma_parms = devm_kzalloc(&device->dev,
					     sizeof(*(device->dev.dma_parms)),
					     GFP_KERNEL);
	if (!(device->dev.dma_parms))
		return -ENOMEM;

	dev_info(&device->dev, "fakedev registered\n");
	return 0;
} /* fakedev_probe */

static int fakedev_remove(struct platform_device *device)
{
	return 0;
} /* fakedev_remove */

static struct platform_driver fakedev_driver = {
	.driver = {
		.name	= KBUILD_MODNAME,
		.owner	= THIS_MODULE,
	},
	.probe	= fakedev_probe,
	.remove	= fakedev_remove,
};

static int fakedev_init(m2mlc_priv_t *priv)
{
	int err;

	err = platform_driver_register(&fakedev_driver);
	if (err)
		return err;

	priv->fakedev = platform_device_register_simple(KBUILD_MODNAME,
							-1, NULL, 0);
	if (IS_ERR(priv->fakedev)) {
		err = PTR_ERR(priv->fakedev);
		goto fail;
	}

	return 0;

fail:
	platform_driver_unregister(&fakedev_driver);
	return err;
} /* fakedev_init */

static void fakedev_exit(m2mlc_priv_t *priv)
{
	platform_device_unregister(priv->fakedev);
	platform_driver_unregister(&fakedev_driver);
} /* fakedev_exit */


/**
 ******************************************************************************
 * Board Init Part
 ******************************************************************************
 **/

#define DMA_ALLOC_RAM(NM_size, NM_buff, NM_handle, SIZ, ELB, S) \
do { \
	NM_size = SIZ; \
	NM_buff = dma_alloc_coherent(&pdev->dev, NM_size, \
				     &(NM_handle), GFP_KERNEL); \
	if (!NM_buff) { \
		dev_err(&pdev->dev, \
			"ERROR: Can't allocate %zu(0x%zX) memory, aborting\n", \
			NM_size, NM_size); \
		err = -ENOMEM; \
		goto ELB; \
	} \
	assert(!(NM_size & (PAGE_SIZE-1))); \
	assert(!(NM_handle & (PAGE_SIZE-1))); \
	DEV_DBG(M2MLC_DBG_MSK_MEM, &pdev->dev, \
		"Alloc %zu(0x%zX) bytes at 0x%p (hw:0x%llX) for %s\n", \
		NM_size, NM_size, NM_buff, (unsigned long long)NM_handle, S); \
} while (0)

#define DMA_FREE_RAM(NM_size, NM_buff, NM_handle) \
do { \
	if (NM_buff) \
		dma_free_coherent(&pdev->dev, NM_size, \
				  NM_buff, NM_handle); \
} while (0)

#ifdef USE_ALLOCPOOL

#define DMA_ALLOC_POOL(NM_pool, NM_size, NM_buff, NM_handle, SIZ, ELB, S) \
do { \
	NM_size = SIZ; \
	NM_buff = dma_pool_alloc(NM_pool, GFP_KERNEL, &(NM_handle)); \
	if (!NM_buff) { \
		dev_err(&pdev->dev, \
			"ERROR: Can't allocate %zu(0x%zX) pool, aborting\n", \
			NM_size, NM_size); \
		err = -ENOMEM; \
		goto ELB; \
	} \
	assert(!(NM_size & (NM_size-1))); \
	assert(!(NM_handle & (NM_size-1))); \
	DEV_DBG(M2MLC_DBG_MSK_MEM, &pdev->dev, \
		"Alloc %zu(0x%zX) bytes at 0x%p (hw:0x%llX) for %s\n", \
		NM_size, NM_size, NM_buff, (unsigned long long)NM_handle, S); \
} while (0)

#define DMA_FREE_POOL(NM_pool, NM_buff, NM_handle) \
do { \
	if (NM_buff) \
		dma_pool_free(NM_pool, NM_buff, NM_handle); \
} while (0)

#endif /* USE_ALLOCPOOL */


/**
 * Driver Initialization Routine
 */
int m2mlc_init_board(struct pci_dev *pdev, void __iomem *bar_addr[],
		     phys_addr_t bar_addr_bus[])
{
	int err;
	int i;
	m2mlc_priv_t *priv;
	u16 nic_capab, rtl_ver;


	assert(pdev);
	if (!pdev)
		return -ENODEV;

	assert(bar_addr[0]);
	assert(bar_addr[1]);
	assert(bar_addr[2]);
	assert(bar_addr[3]);

	/* Check RTL Version */
	nic_capab = m2mlc_hw_get_niccapability(pdev);
	rtl_ver = NICCPB_GET_PROCVAL(nic_capab);
	if (rtl_version != 0) {
		if (rtl_ver != rtl_version) {
			dev_err(&pdev->dev,
				"ERROR: wrong RTL version (%d), aborting\n",
				rtl_ver);
			err = -EFAULT;
			goto err_out;
		}
	}
	dev_info(&pdev->dev, "rtl version %d\n", rtl_ver);
	dev_info(&pdev->dev, "Arbiter Config: " \
		 "DMA0->IOLink%d, DMA1->IOLink%d, DMA2->IOLink%d\n",
		 NICCPB_GET_AACFG_DMA0(nic_capab),
		 NICCPB_GET_AACFG_DMA1(nic_capab),
		 NICCPB_GET_AACFG_DMA2(nic_capab));

	/* allocate memory for priv* */
	priv = kzalloc(sizeof(m2mlc_priv_t), GFP_KERNEL);
	if (!priv) {
		dev_err(&pdev->dev,
			"ERROR: Cannot allocate memory for priv*, aborting\n");
		err = -ENOMEM;
		goto err_out;
	}
	pci_set_drvdata(pdev, priv);

	/* init priv-> */
	priv->pdev = pdev;
	priv->ecs_base = bar_addr[0];
	priv->reg_base = bar_addr[1];
	priv->buf_base = bar_addr[2];
	priv->iom_base = bar_addr[3];
	priv->reg_base_bus = bar_addr_bus[1];
	priv->buf_base_bus = bar_addr_bus[2];
	priv->niccpb_procval = NICCPB_GET_PROCVAL(rtl_ver);

	spin_lock_init(&priv->cdev_open_lock);
	priv->device_open = 1;	/* disable open */


	/* create iommu mapping */
	pdev->dev.dma_parms = devm_kzalloc(&pdev->dev,
					    sizeof(*(pdev->dev.dma_parms)),
					    GFP_KERNEL);
	if (!(pdev->dev.dma_parms)) {
		err = -ENOMEM;
		goto err_free_mem;
	}

	/* Set DMA seg_size & boundary */
	if (dma_set_max_seg_size(&pdev->dev, dma_max_seg_size)) {
		dev_warn(&pdev->dev,
			"WARNING: wrong dma_max_seg_size\n");
	}
	if (dma_set_seg_boundary(&pdev->dev, dma_seg_boundary)) {
		dev_warn(&pdev->dev,
			"WARNING: wrong dma_seg_boundary\n");
	}

	DEV_DBG(M2MLC_DBG_MSK_MEM, &pdev->dev,
		"pdev->dma_parms-> max_segment_size: %u(0x%X), "
		"segment_boundary_mask: %lu(0x%lX)",
		dma_get_max_seg_size(&pdev->dev),
		dma_get_max_seg_size(&pdev->dev),
		dma_get_seg_boundary(&pdev->dev),
		dma_get_seg_boundary(&pdev->dev));


	/* Full Reset */
	err = m2mlc_hw_reset(priv, 1);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot reset hw, aborting\n");
		goto err_free_mem;
	}
	m2mlc_hw_set_endianes(priv);


	/* Create cdev */
	err = m2mlc_cdev_register(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot create cdev, aborting\n");
		goto err_free_mem;
	}

    #ifdef ENABLE_NET_DEV
	/* Create ndev */
	err = m2mlc_net_register(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot create ndev, aborting\n");
		goto err_cdev_remove;
	}
    #endif /* ENABLE_NET_DEV */


	/* create fake dev */
	err = fakedev_init(priv);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot create fakedev, aborting\n");
		goto err_dev_remove;
	}
	set_dev_node(&priv->fakedev->dev, /*node*/ 3);
#if defined(__e2k__)
	set_dev_link(&priv->fakedev->dev, /*link*/ 0);
#endif
	/* Set DMA seg_size & boundary */
	if (dma_set_max_seg_size(&priv->fakedev->dev, dma_max_seg_size)) {
		dev_warn(&priv->fakedev->dev,
			"WARNING: wrong dma_max_seg_size\n");
	}
	if (dma_set_seg_boundary(&priv->fakedev->dev, dma_seg_boundary)) {
		dev_warn(&priv->fakedev->dev,
			"WARNING: wrong dma_seg_boundary\n");
	}


	/* = Alloc pages for buffers = */

	/* PIO Done Queue */
	/* FIXME: Align to 32 pages; 1 page per endpoint used; 24 bytes? */
	/* FIXME: compute nearest power of two greater than niccpb_procval */
	DMA_ALLOC_RAM(priv->pio_done_que_size,
		      priv->pio_done_que_buff,
		      priv->pio_done_que_handle,
		      /*priv->niccpb_procval*/32 * PIO_DONE_QUE_RAM * MUL2ALIGN,
		      err_fakedev_remove,
		      "PIO Done Queue");
#ifdef USE_MUL2ALIGN
	priv->pio_done_que_offset = ((priv->pio_done_que_handle +
				    (32 * PIO_DONE_QUE_RAM - 1)) &
				    ~(32 * PIO_DONE_QUE_RAM - 1)) -
				    priv->pio_done_que_handle;
	DEV_DBG(M2MLC_DBG_MSK_MEM, &pdev->dev,
		"offset for PIO Done queue is %u(0x%X) result at buf+off=" \
		" 0x%p (handle+off= hw:0x%llX)\n",
		priv->pio_done_que_offset,
		priv->pio_done_que_offset,
		(void *)(priv->pio_done_que_buff + priv->pio_done_que_offset),
		(dma_addr_t)(priv->pio_done_que_handle +
			     priv->pio_done_que_offset));
#endif /* USE_MUL2ALIGN */

	/* PIO Data Queue */
	/* FIXME: Align to 32 pages; 1 page per endpoint used */
	DMA_ALLOC_RAM(priv->pio_data_que_size,
		      priv->pio_data_que_buff,
		      priv->pio_data_que_handle,
		      /*priv->niccpb_procval*/32 * PIO_DATA_QUE_RAM * MUL2ALIGN,
		      err_free_pio_done_que,
		      "PIO Data Queue");
#ifdef USE_MUL2ALIGN
	priv->pio_data_que_offset = ((priv->pio_data_que_handle +
				    (32 * PIO_DATA_QUE_RAM - 1)) &
				    ~(32 * PIO_DATA_QUE_RAM - 1)) -
				    priv->pio_data_que_handle;
	DEV_DBG(M2MLC_DBG_MSK_MEM, &pdev->dev,
		"offset for PIO Data queue is %u(0x%X) result at buf+off=" \
		" 0x%p (handle+off= hw:0x%llX)\n",
		priv->pio_data_que_offset,
		priv->pio_data_que_offset,
		(void *)(priv->pio_data_que_buff + priv->pio_data_que_offset),
		(dma_addr_t)(priv->pio_data_que_handle +
			     priv->pio_data_que_offset));
#endif /* USE_MUL2ALIGN */


	/* Mailbox/Doorbell/DMA Return */
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_RAM(priv->mdd_ret_size[i],
			      priv->mdd_ret_buff[i],
			      priv->mdd_ret_handle[i],
			      MDD_RET_RAM,
			      err_free_pio_data_que,
			      "Mailbox/Doorbell/DMA Return");
	}

	/* Mailbox Structure */
#ifdef USE_ALLOCPOOL
	priv->mb_struct_dma_pool = dma_pool_create("mb_struct", &pdev->dev,
						   MB_STRUCT_RAM,
						   MB_STRUCT_RAM, 0);
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_POOL(priv->mb_struct_dma_pool,
			       priv->mb_struct_size[i],
			       priv->mb_struct_buff[i],
			       priv->mb_struct_handle[i],
			       MB_STRUCT_RAM,
			       err_free_mdd_ret,
			       "Mailbox Structure");
	}
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_RAM(priv->mb_struct_size[i],
			      priv->mb_struct_buff[i],
			      priv->mb_struct_handle[i],
			      MB_STRUCT_RAM * MUL2ALIGN,
			      err_free_mdd_ret,
			      "Mailbox Structure");
#ifdef USE_MUL2ALIGN
		priv->mb_struct_offset = ((priv->mb_struct_handle[i] +
					 (MB_STRUCT_RAM - 1)) &
					 ~(MB_STRUCT_RAM - 1)) -
					 priv->mb_struct_handle[i];
#endif /* USE_MUL2ALIGN */
	}
#endif /* USE_ALLOCPOOL */

	/* Mailbox Done Queue */
#ifdef USE_ALLOCPOOL
	priv->mb_done_dma_pool = dma_pool_create("mb_done", &pdev->dev,
						 MB_DONE_QUE_RAM,
						 MB_DONE_QUE_RAM, 0);
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_POOL(priv->mb_done_dma_pool,
			       priv->mb_done_que_size[i],
			       priv->mb_done_que_buff[i],
			       priv->mb_done_que_handle[i],
			       MB_DONE_QUE_RAM,
			       err_free_mb_struct,
			       "Mailbox Done Queue");
	}
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_RAM(priv->mb_done_que_size[i],
			      priv->mb_done_que_buff[i],
			      priv->mb_done_que_handle[i],
			      MB_DONE_QUE_RAM * MUL2ALIGN,
			      err_free_mb_struct,
			      "Mailbox Done Queue");
#ifdef USE_MUL2ALIGN
		priv->mb_done_offset = ((priv->mb_done_que_handle[i] +
				       (MB_DONE_QUE_RAM - 1)) &
				       ~(MB_DONE_QUE_RAM - 1)) -
				       priv->mb_done_que_handle[i];
#endif /* USE_MUL2ALIGN */
	}
#endif /* USE_ALLOCPOOL */

	/* Doorbell Start */
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_RAM(priv->db_start_size[i],
			      priv->db_start_buff[i],
			      priv->db_start_handle[i],
			      DB_START_RAM,
			      err_free_mb_done_que,
			      "Doorbell Start");
	}

	/* DMA Start */
#ifdef USE_ALLOCPOOL
	priv->dma_start_dma_pool = dma_pool_create("dma_start", &pdev->dev,
						   DMA_START_RAM,
						   DMA_START_RAM, 0);
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_POOL(priv->dma_start_dma_pool,
			       priv->dma_start_size[i],
			       priv->dma_start_buff[i],
			       priv->dma_start_handle[i],
			       DMA_START_RAM,
			       err_free_db_start,
			       "DMA Start");
	}
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_RAM(priv->dma_start_size[i],
			      priv->dma_start_buff[i],
			      priv->dma_start_handle[i],
			      DMA_START_RAM * MUL2ALIGN,
			      err_free_db_start,
			      "DMA Start");
#ifdef USE_MUL2ALIGN
		priv->dma_start_offset = ((priv->dma_start_handle[i] +
					 (DMA_START_RAM - 1)) &
					 ~(DMA_START_RAM - 1)) -
					 priv->dma_start_handle[i];
#endif /* USE_MUL2ALIGN */
	}
#endif /* USE_ALLOCPOOL */

	/* DMA Done Queue */
#ifdef USE_ALLOCPOOL
	priv->dma_done_dma_pool = dma_pool_create("dma_done", &pdev->dev,
						  DMA_DONE_QUE_RAM,
						  DMA_DONE_QUE_RAM, 0);
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_POOL(priv->dma_done_dma_pool,
			       priv->dma_done_que_size[i],
			       priv->dma_done_que_buff[i],
			       priv->dma_done_que_handle[i],
			       DMA_DONE_QUE_RAM,
			       err_free_dma_start,
			       "DMA Done Queue");
	}
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_ALLOC_RAM(priv->dma_done_que_size[i],
			      priv->dma_done_que_buff[i],
			      priv->dma_done_que_handle[i],
			      DMA_DONE_QUE_RAM * MUL2ALIGN,
			      err_free_dma_start,
			      "DMA Done Queue");
#ifdef USE_MUL2ALIGN
		priv->dma_done_offset = ((priv->dma_done_que_handle[i] +
					(DMA_DONE_QUE_RAM - 1)) &
					~(DMA_DONE_QUE_RAM - 1)) -
					priv->dma_done_que_handle[i];
#endif /* USE_MUL2ALIGN */
	}
#endif /* USE_ALLOCPOOL */


#ifndef TESTWOIRQ
	/* Register IRQ */
	if (-1 == pdev->irq) {
		dev_warn(&pdev->dev, "WARNING: no interrupt (%d) for %s\n",
			 pdev->irq, dev_name(priv->dev));
	} else {
		for (i = 0; i < priv->niccpb_procval; i++) {
			dev_info(&pdev->dev, "request interrupt: %d - %s\n",
				pdev->irq + i, dev_name(priv->dev));
			err = request_irq(pdev->irq + i, m2mlc_irq_handler,
					IRQF_SHARED, dev_name(priv->dev),
					(void *)pdev);
			if (err) {
				dev_err(&pdev->dev,
					"ERROR: Cannot request PCI irq %d," \
					" aborting\n",
					pdev->irq + i);
				goto err_unregister_irq;
			}
		}
	}
#endif /* TESTWOIRQ */

	m2mlc_hw_init(priv);

	/* enable open */
	spin_lock(&priv->cdev_open_lock);
	priv->device_open = 0;
	spin_unlock(&priv->cdev_open_lock);

	return 0;


#ifndef TESTWOIRQ
err_unregister_irq:
	if (pdev->irq != -1) {
		for (i = 0; i < priv->niccpb_procval; i++) {
			free_irq(pdev->irq + i, (void *)pdev);
		}
	}
#endif /* TESTWOIRQ */
/*err_free_dma_done_que:*/
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->dma_done_dma_pool,
			      priv->dma_done_que_buff[i],
			      priv->dma_done_que_handle[i]);
	}
	dma_pool_destroy(priv->dma_done_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->dma_done_que_size[i],
			     priv->dma_done_que_buff[i],
			     priv->dma_done_que_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
err_free_dma_start:
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->dma_start_dma_pool,
			      priv->dma_start_buff[i],
			      priv->dma_start_handle[i]);
	}
	dma_pool_destroy(priv->dma_start_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->dma_start_size[i],
			     priv->dma_start_buff[i],
			     priv->dma_start_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
err_free_db_start:
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->db_start_size[i],
			     priv->db_start_buff[i],
			     priv->db_start_handle[i]);
	}
err_free_mb_done_que:
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->mb_done_dma_pool,
			      priv->mb_done_que_buff[i],
			      priv->mb_done_que_handle[i]);
	}
	dma_pool_destroy(priv->mb_done_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->mb_done_que_size[i],
			     priv->mb_done_que_buff[i],
			     priv->mb_done_que_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
err_free_mb_struct:
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->mb_struct_dma_pool,
			      priv->mb_struct_buff[i],
			      priv->mb_struct_handle[i]);
	}
	dma_pool_destroy(priv->mb_struct_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->mb_struct_size[i],
			     priv->mb_struct_buff[i],
			     priv->mb_struct_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
err_free_mdd_ret:
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->mdd_ret_size[i],
			     priv->mdd_ret_buff[i],
			     priv->mdd_ret_handle[i]);
	}
err_free_pio_data_que:
	DMA_FREE_RAM(priv->pio_data_que_size,
		     priv->pio_data_que_buff,
		     priv->pio_data_que_handle);
err_free_pio_done_que:
	DMA_FREE_RAM(priv->pio_done_que_size,
		     priv->pio_done_que_buff,
		     priv->pio_done_que_handle);
err_fakedev_remove:
	fakedev_exit(priv);
err_dev_remove:
#ifdef ENABLE_NET_DEV
	m2mlc_net_remove(priv);
err_cdev_remove:
#endif /* ENABLE_NET_DEV */
	m2mlc_cdev_remove(priv);
err_free_mem:
	kfree(priv);
err_out:
	return err;
} /* m2mlc_init_board */

/**
 * Cleanup Routine
 */
void m2mlc_release_board(struct pci_dev *pdev)
{
	int i;
	int err;
	m2mlc_priv_t *priv;
#if 0
	/* TODO: move to daemon */
	ecs_gpstat_csr_reg_t ecs_gpstat_csr;
#endif

	assert(pdev);
	if (!pdev)
		return;

	priv = pci_get_drvdata(pdev);
	assert(priv);
	if (!priv)
		return;

	/* disable open */
	spin_lock(&priv->cdev_open_lock);
	priv->device_open = 1;
	spin_unlock(&priv->cdev_open_lock);

#if 0
	/* TODO: move to daemon */
	/* Clean Discovered bit */
	ecs_gpstat_csr.r = m2mlc_read_reg32(priv->ecs_base, ECS_GPSTAT_CSR);
	ecs_gpstat_csr.p.Discovered = 0;
	m2mlc_write_reg32(priv->ecs_base, ECS_GPSTAT_CSR, ecs_gpstat_csr.r);
	mdelay(1);
#endif

	/* Full Reset */
	err = m2mlc_hw_reset(priv, 0);
	if (err) {
		dev_err(&pdev->dev,
			"ERROR: Cannot reset hw, continue\n");
	}

#ifndef TESTWOIRQ
	if (pdev->irq != -1) {
		for (i = 0; i < priv->niccpb_procval; i++) {
			free_irq(pdev->irq + i, (void *)pdev);
		}
	}
#endif /* TESTWOIRQ */

	/* free pages for DMA buffers */
	pdev = priv->pdev;

#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->dma_done_dma_pool,
			      priv->dma_done_que_buff[i],
			      priv->dma_done_que_handle[i]);
	}
	dma_pool_destroy(priv->dma_done_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->dma_done_que_size[i],
			     priv->dma_done_que_buff[i],
			     priv->dma_done_que_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->dma_start_dma_pool,
			      priv->dma_start_buff[i],
			      priv->dma_start_handle[i]);
	}
	dma_pool_destroy(priv->dma_start_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->dma_start_size[i],
			     priv->dma_start_buff[i],
			     priv->dma_start_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->db_start_size[i],
			     priv->db_start_buff[i],
			     priv->db_start_handle[i]);
	}
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->mb_done_dma_pool,
			      priv->mb_done_que_buff[i],
			      priv->mb_done_que_handle[i]);
	}
	dma_pool_destroy(priv->mb_done_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->mb_done_que_size[i],
			     priv->mb_done_que_buff[i],
			     priv->mb_done_que_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
#ifdef USE_ALLOCPOOL
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_POOL(priv->mb_struct_dma_pool,
			      priv->mb_struct_buff[i],
			      priv->mb_struct_handle[i]);
	}
	dma_pool_destroy(priv->mb_struct_dma_pool);
#else
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->mb_struct_size[i],
			     priv->mb_struct_buff[i],
			     priv->mb_struct_handle[i]);
	}
#endif /* USE_ALLOCPOOL */
	for (i = 0; i < priv->niccpb_procval; i++) {
		DMA_FREE_RAM(priv->mdd_ret_size[i],
			     priv->mdd_ret_buff[i],
			     priv->mdd_ret_handle[i]);
	}
	DMA_FREE_RAM(priv->pio_data_que_size,
		     priv->pio_data_que_buff,
		     priv->pio_data_que_handle);
	DMA_FREE_RAM(priv->pio_done_que_size,
		     priv->pio_done_que_buff,
		     priv->pio_done_que_handle);

	fakedev_exit(priv);
    #ifdef ENABLE_NET_DEV
	m2mlc_net_remove(priv);
    #endif /* ENABLE_NET_DEV */
	m2mlc_cdev_remove(priv);

	kfree(priv);
} /* m2mlc_release_board */


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

/**
 * Driver Registration Routine
 *
 * m2mlc_init is the first routine called when the driver is loaded.
 * All it does is register with the PCI subsystem.
 */
static int __init m2mlc_init(void)
{
	int status;

	PDEBUG(M2MLC_DBG_MSK_MODULE,
	       "------------------------------------------\n");
	LOG_MSG("Init M2MLC module device driver, build " FULLBUILD "\n");

	if (0 != check_parameters()) {
		ERR_MSG("ERROR: Invalid module parameters, aborting\n");
		return -EINVAL;
	}

	m2mlc_dev_init();

	status = pci_register_driver(&m2mlc_pci_driver);
	if (status != 0) {
		ERR_MSG("ERROR: Could not register driver\n");
		goto cdevexit;
	}

	PDEBUG(M2MLC_DBG_MSK_MODULE, "Init done\n");
	return 0;

cdevexit:
	m2mlc_dev_exit();
	return status;
} /* m2mlc_init */

/**
 * Driver Exit Cleanup Routine
 *
 * m2mlc_exit is called just before the driver is removed from memory.
 */
static void __exit m2mlc_exit(void)
{
	pci_unregister_driver(&m2mlc_pci_driver);

	m2mlc_dev_exit();

	PDEBUG(M2MLC_DBG_MSK_MODULE, "Exit\n");
} /* m2mlc_exit */


module_init(m2mlc_init);
module_exit(m2mlc_exit);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Andrey Kalita <Andrey.V.Kalita@mcst.ru>");
MODULE_DESCRIPTION("M2MLC module device driver, build " FULLBUILD);
MODULE_SUPPORTED_DEVICE("M2MLC, DeviceID:" DEVICE_ID ", VendorID:" VENDOR_ID);
MODULE_VERSION(DRIVER_VERSION);
