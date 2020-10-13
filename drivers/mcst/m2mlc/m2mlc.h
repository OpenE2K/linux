#ifndef M2MLC_H__
#define M2MLC_H__


/* Global parameters */
#undef ENABLE_NET_DEV	/* define: enable Network device */
#undef USE_ALLOCPOOL	/* define: use dma_pool_create */
#define USE_MUL2ALIGN	/* define: allocate mem * 2 (RTL BUG) */
#undef TESTWOIRQ	/* define: disable interrupt */
#undef USE_DUALIOLINK	/* define: enable second iolink */


#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/audit.h>
#include <linux/platform_device.h>

#include "m2mlc_dbg.h"
#include "m2mlc_regs.h"
#ifdef DEBUG
#include "m2mlc_io.h"
#else
#include <linux/mcst/m2mlc_io.h>
#endif


/**
 ******************************************************************************
 * Driver
 ******************************************************************************
 **/

#define DRIVER_NAME		"m2mlc"
#define DRIVER_VERSION		"1.0.0"

#define FULLBUILD __DATE__ " " __TIME__


/**
 ******************************************************************************
 * Interface & Settings
 ******************************************************************************
 **/

/* PCI */
#define DEVICE_ID		(0x8021)
#define VENDOR_ID		(0x1FFF)

/* Endpoint number:
 *   0 - root: maintenance
 *   1..16 - for user
 *   17 - root: network
 *   18..19 - root
 */
#define CDEV_ENDPOINT_UMIN 1
#define CDEV_ENDPOINT_UMAX 16
#define CDEV_ENDPOINT_NET  17
#define CDEV_ENDPOINT_NONE (-1)


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

extern u16 rtl_version;
extern u32 debug_mask;
extern u32 softreset_enable;
extern u32 timeout_retry;
extern u32 timeout_counter;
extern unsigned int dma_max_seg_size;
extern unsigned long dma_seg_boundary;


/**
 ******************************************************************************
 * Buffers in RAM
 ******************************************************************************
 **/

#define PIO_DONE_QUE_RAM	PAGE_SIZE	/* xN */
#define PIO_DATA_QUE_RAM	(16 * 256)	/* xN */
#define MDD_RET_RAM		PAGE_SIZE	/* for N */
#define MB_STRUCT_RAM		(1024 * 4096)	/* for N */
#define MB_DONE_QUE_RAM		(1024 * 8)	/* for N */
#define DB_START_RAM		PAGE_SIZE	/* for N (256 * 8) */
#define DMA_START_RAM		(4096 * 32)	/* for N */
#define DMA_DONE_QUE_RAM	(4096 * 4)	/* for N */


/**
 ******************************************************************************
 * Private structs
 ******************************************************************************
 **/

extern struct pci_driver m2mlc_pci_driver;


#ifdef ENABLE_NET_DEV
struct m2mlc_priv;

typedef struct m2mlc_npriv {
	struct m2mlc_priv	*p_priv;		/* parent */

	struct net_device_stats	stats;
	struct napi_struct	napi;

	struct sk_buff		*tx_dma_skb;
	struct sk_buff		*rx_skb;
	struct sk_buff		*rx_dma_skb;

	dma_addr_t		tx_dma_map_adr;
	dma_addr_t		rx_dma_map_adr;

	/* Lock long rx packet (>MTU): 0 - unlock, 1 - lock */
	int			rx_lock_long_rx_pack;
} m2mlc_npriv_t;
#endif /* ENABLE_NET_DEV */


typedef struct m2mlc_priv {
	/* PCI */
	struct pci_dev *pdev;		/* PCI device information struct */
	struct platform_device *fakedev;	/* second CPU link */
	void __iomem *ecs_base;		/* ioremap'ed address to BAR0 */
	void __iomem *reg_base;		/* ioremap'ed address to BAR1 */
	void __iomem *buf_base;		/* ioremap'ed address to BAR2 */
	void __iomem *iom_base;		/* ioremap'ed address to BAR3 */
	phys_addr_t reg_base_bus;	/* BAR1 phys address for mmap */
	phys_addr_t buf_base_bus;	/* BAR2 phys address for mmap */
	u8 niccpb_procval;		/* PCI conf space - NIC Capability */

	/* CDEV */
    #ifdef CONFIG_MCST_RT_NO
	raw_spinlock_t cdev_open_lock;
    #else
	spinlock_t cdev_open_lock;
    #endif
	int device_open;
	struct cdev cdev;
	struct device *dev;
	unsigned int minor;
	/* Endpoint */
	int pid[NICCPB_PROCVAL];
	int signal[NICCPB_PROCVAL];	/* signal to user, or 0 */
	struct task_struct *tsk[NICCPB_PROCVAL];
	/* <<< cdev_open_lock */

    #ifdef ENABLE_NET_DEV
	struct net_device *ndev;
    #endif

	/* = buffs in main memory = */
	/* PIO Done Queue */
	size_t		pio_done_que_size;	/* Size */
	void		*pio_done_que_buff;	/* CPU-viewed address */
	dma_addr_t	pio_done_que_handle;	/* device-viewed address */
	/* PIO Data Queue */
	size_t		pio_data_que_size;
	void		*pio_data_que_buff;
	dma_addr_t	pio_data_que_handle;
	/* Mailbox/Doorbell/DMA Return */
	size_t		mdd_ret_size[NICCPB_PROCVAL];
	void		*mdd_ret_buff[NICCPB_PROCVAL];
	dma_addr_t	mdd_ret_handle[NICCPB_PROCVAL];
	/* Mailbox Structure */
	size_t		mb_struct_size[NICCPB_PROCVAL];
	void		*mb_struct_buff[NICCPB_PROCVAL];
	dma_addr_t	mb_struct_handle[NICCPB_PROCVAL];
	/* Mailbox Done Queue */
	size_t		mb_done_que_size[NICCPB_PROCVAL];
	void		*mb_done_que_buff[NICCPB_PROCVAL];
	dma_addr_t	mb_done_que_handle[NICCPB_PROCVAL];
	/* Doorbell Start */
	size_t		db_start_size[NICCPB_PROCVAL];
	void		*db_start_buff[NICCPB_PROCVAL];
	dma_addr_t	db_start_handle[NICCPB_PROCVAL];
	/* DMA Start */
	size_t		dma_start_size[NICCPB_PROCVAL];
	void		*dma_start_buff[NICCPB_PROCVAL];
	dma_addr_t	dma_start_handle[NICCPB_PROCVAL];
	/* DMA Done Queue */
	size_t		dma_done_que_size[NICCPB_PROCVAL];
	void		*dma_done_que_buff[NICCPB_PROCVAL];
	dma_addr_t	dma_done_que_handle[NICCPB_PROCVAL];
#ifdef USE_ALLOCPOOL
	/* Mailbox Structure, Done Queue; DMA Start, Done Queue */
	struct dma_pool *mb_struct_dma_pool;
	struct dma_pool *mb_done_dma_pool;
	struct dma_pool *dma_start_dma_pool;
	struct dma_pool *dma_done_dma_pool;
#endif /* USE_ALLOCPOOL */
#ifdef USE_MUL2ALIGN
	unsigned int	pio_done_que_offset;
	unsigned int	pio_data_que_offset;
	unsigned int	mb_struct_offset;
	unsigned int	mb_done_offset;
	unsigned int	dma_start_offset;
	unsigned int	dma_done_offset;
#endif /* USE_MUL2ALIGN */
} m2mlc_priv_t;


#endif /* M2MLC_H__ */
