/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_H__
#define MXGBE_H__

#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/audit.h>
#include <linux/device.h>
#include <linux/kobject.h>
#include <linux/jiffies.h>
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>

#include <linux/io.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/i2c.h>
#include <linux/kthread.h>
#include <asm/io.h>

#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/crc32.h>
#include <linux/ethtool.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/mii.h>
#include <linux/mdio.h>

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>

#include <asm/setup.h>


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

#define MSIX_MAC_IDX_NUM_USE	1	/* one vector for MAC irqs */

#undef MSIX_COMPACTMODE		/* default undefined */

#undef USE_LONG_DESCR		/* Use long descriptor format */

#undef GPIO_RESET_PHY		/* Don't use GPIO.0 to reset Phy !!! */

#define MXGBE_MAXFRAMESIZE	(16384)  /* (TXQ_TC_MSS_MAX + 1) */


#include "mxgbe_regs.h"


/**
 ******************************************************************************
 * Driver
 ******************************************************************************
 **/

#define DRIVER_VERSION		"1.2.0"


/* Module parameters */
extern u32 mxgbe_debug_mask;
extern u32 mxgbe_loopback_mode;
extern u32 mxgbe_led_gpio;
extern int mxgbe_status;
extern int mxgbe_maxqueue;


/**
 ******************************************************************************
 * MEM alloc
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
	nDEV_DBG(MXGBE_DBG_MSK_MEM, &pdev->dev, \
		"Alloc %zu(0x%zX) bytes at 0x%p (hw:0x%llX) for %s\n", \
		NM_size, NM_size, NM_buff, (unsigned long long)NM_handle, S); \
} while (0)

#define DMA_FREE_RAM(NM_size, NM_buff, NM_handle) \
do { \
	if (NM_buff) \
		dma_free_coherent(&pdev->dev, NM_size, \
				  NM_buff, NM_handle); \
} while (0)


/**
 ******************************************************************************
 * Private structs
 ******************************************************************************
 **/

/* forward declaration */
struct mxgbe_vector;
struct mxgbe_priv;

struct mxgbe_tx_buff {
	struct sk_buff		*skb;
	dma_addr_t		dma;
	/*
	union mxgbe_adv_tx_desc *next_to_watch;
	unsigned long time_stamp;
	unsigned int bytecount;
	unsigned short gso_segs;
	__be16 protocol;
	u32 len;
	u32 tx_flags;
	*/
};
typedef struct mxgbe_tx_buff mxgbe_tx_buff_t; /* net, txq */

struct mxgbe_rx_buff {
	void			*addr;		/* CPU-viewed addr */
	dma_addr_t		dma;		/* DMA-viewed addr */
	size_t			size;
	struct sk_buff		*skb;
	unsigned int		bytecount;
};
typedef struct mxgbe_rx_buff mxgbe_rx_buff_t; /* net, rxq */

struct mxgbe_queue {
	struct mxgbe_vector	*vector;	/* backpointer to host vector */
	int			descr_cnt;	/* <-- ethtool set_ringparam */
	size_t			que_size;
	void			*que_addr;	/* CPU-viewed addr */
	dma_addr_t		que_handle;	/* dev-viewed addr */
	size_t			tail_size;
	void			*tail_addr;	/* CPU-viewed addr */
	dma_addr_t		tail_handle;	/* dev-viewed addr */
	int			prio;
	union {
		mxgbe_rx_buff_t	*rx_buff;	/* [sizeof() * descr_cnt] */
		mxgbe_tx_buff_t	*tx_buff;	/* [sizeof() * descr_cnt] */
	};
	int			last_alloc;

	spinlock_t		tlock;		/* lock .tail */
	spinlock_t		hlock;		/* lock .head */
	u16			tail;
	u16			head;
} ____cacheline_internodealigned_in_smp;

typedef struct mxgbe_vector {
	struct mxgbe_priv	*priv;

	char			name[8 + IFNAMSIZ + 8 + 20];
	int			irq;	/* requested irq / MSIX vector */

	int			bidx;	/* MSIX_LUT table base event/index */
	int			vect;	/* MSIX_LUT table vector/data */
	int			qn;	/* Queue num */

	struct napi_struct	napi;

	int			cpu;
	struct rcu_head		rcu;
	cpumask_t		affinity_mask;
	int			numa_node;
} mxgbe_vector_t;

struct mxgbe_err_flags {
	int			quefull_f;
	u64			quefull_c;
	int			queempty_f;
	u64			queempty_c;
	u64			errirq_c;
};

/* PCI */
typedef struct mxgbe_priv {
	/* PCI */
	struct pci_dev		*pdev;		/* PCI device struct */
	void __iomem		*bar0_base;	/* ioremap'ed address to BAR0 */
	phys_addr_t		bar0_base_bus;	/* BAR0 phys address for mmap */
	int			revision;

	/* Net */
	struct net_device	*ndev;		/* Network device */
	u32			carrier;
	struct net_device_stats	stats;

	/* TX */
	unsigned int		num_tx_queues;	/* TX_QNUM <- hw_getinfo */
	unsigned int		hw_tx_bufsize;	/* TX_BUFSIZE <- hw_getinfo */
	struct mxgbe_queue	txq[TXQ_MAXNUM] ____cacheline_aligned_in_smp;

	/* RX */
	unsigned int		num_rx_queues;	/* RX_QNUM <- hw_getinfo */
	unsigned int		hw_rx_bufsize;	/* RX_BUFSIZE <- hw_getinfo */
	struct mxgbe_queue	rxq[RXQ_MAXNUM] ____cacheline_aligned_in_smp;

	/* MSI-X */
	struct mxgbe_vector	vector[MSIX_V_NUM];
	int			num_msix_entries;
	int			msix_mac_num;
	int			msix_tx_num;
	int			msix_rx_num;
	struct msix_entry	*msix_entries;

	u32			msg_enable;	/* debug message level */

	/* MDIO */
	raw_spinlock_t		mgio_lock;
	struct mii_bus		*mii_bus;
	int			pcsaddr;	/* Address of Internal PHY */
	u32			pcs_dev_id;

	/* I2C */
	struct i2c_adapter	*i2c_0;	/* SFP */
	struct i2c_adapter	*i2c_1;	/* VSC */
	struct i2c_adapter	*i2c_2;	/* EEPROM */
	u64			MAC;

	/* MAC */
	struct task_struct	*mac_task;

#ifdef CONFIG_DEBUG_FS
	struct dentry		*mxgbe_dbg_board;
	u32			reg_last_value;
	char			dbg_name[IFNAMSIZ + 14];
#endif /*CONFIG_DEBUG_FS*/

	struct mxgbe_err_flags	rx_err_flags[RXQ_MAXNUM];
	struct mxgbe_err_flags	tx_err_flags[TXQ_MAXNUM];
} mxgbe_priv_t;


extern struct pci_driver mxgbe_pci_driver;


#endif /* MXGBE_H__ */
