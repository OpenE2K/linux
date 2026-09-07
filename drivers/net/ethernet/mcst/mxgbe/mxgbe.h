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

#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/ip.h>

#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>

#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <net/xdp.h>
#include <net/page_pool.h>

#include <asm/setup.h>


/**
 ******************************************************************************
 * Module parameters
 ******************************************************************************
 **/

#define MSIX_MAC_IDX_NUM_USE	1	/* one vector for MAC irqs */

#undef MSIX_COMPACTMODE		/* default undefined */

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
#ifdef CONFIG_MXGBE_DCA
extern int mxgbe_rx_desc_dca_enable;
extern int mxgbe_rx_hdr_dca_enable;
extern int mxgbe_rx_hdr_size_dca;
extern int mxgbe_ro_rx_data;
extern int mxgbe_ro_rx_descr;
extern int mxgbe_tx_dca_enable;
extern int mxgbe_ro_tx_descr;
extern int mxgbe_ro_tx_data;
#endif /* CONFIG_MXGBE_DCA */


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

struct mxgbe_eth_gstring {
	const char name[ETH_GSTRING_LEN];
};

static const struct mxgbe_eth_gstring mxgbe_eth_gstrings[] = {
	{ "rx_xdp_redirect", },
	{ "rx_xdp_redirect_errors", },
	{ "rx_xdp_pass", },
	{ "rx_xdp_drop", },
	{ "rx_xdp_tx", },
	{ "rx_xdp_tx_errors", },
	{ "tx_xdp_xmit", },
	{ "tx_xdp_xmit_errors", },
};

struct mxgbe_ethtool_stats {
	u64		xdp_redirect;
	u64		xdp_redirect_err;
	u64		xdp_pass;
	u64		xdp_drop;
	u64		xdp_tx;
	u64		xdp_tx_err;
	u64		xdp_xmit;
	u64		xdp_xmit_err;
};

#define MXGBE_XDP_TX		BIT(0)
#define MXGBE_XDP_REDIR		BIT(1)

enum mxgbe_buff_type {
	MXGBE_TYPE_SKB = 0,
	MXGBE_TYPE_XDP,
	MXGBE_TYPE_XDP_TX,
	MXGBE_TYPE_PAGE,
};

struct mxgbe_stats {
	u64		tx_dropped;
	u64		rx_crc_errors;
	struct u64_stats_sync	syncp;
};

/* forward declaration */
struct mxgbe_vector;
struct mxgbe_priv;

struct mxgbe_buff {
	union {
		struct sk_buff *skb;
		struct xdp_frame *xdpf;
		struct page *page;
	};
	DEFINE_DMA_UNMAP_ADDR(dma);
	DEFINE_DMA_UNMAP_LEN(len);
	unsigned int bytes;
	enum mxgbe_buff_type type;
};

typedef struct mxgbe_buff mxgbe_buff_t; /* net, txq, rxq */

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
	mxgbe_buff_t	*buff;	/* [sizeof() * descr_cnt] */
	int			last_alloc;

	spinlock_t		tlock;		/* lock .tail */
	spinlock_t		hlock;		/* lock .head */
	u16			tail;
	u16			head;

	unsigned int	xdp_xmit;
	enum dma_data_direction	rx_dir;
	unsigned long	rx_dma_offset;
	unsigned int	rx_bufsz;
	struct xdp_rxq_info	xdp_rxq;
	struct page_pool	*page_pool;
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

struct mxgbe_vf_qblock {
	u16 block0	:4;
	u16 block1	:4;
	u16 block2	:4;
	u16 block3	:4;
};

union mxgbe_vf_group {
	struct mxgbe_vf_qblock	qblock;
	u16		group;
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
	struct mxgbe_stats	stats;
	struct mxgbe_ethtool_stats ethtool_stats;

	/* TX */
	unsigned int		tx_ring_count;
	u32			tx_coalesced_frames;
	u32			tx_coalesce_usecs;
	unsigned int		num_tx_queues;	/* TX_QNUM <- hw_getinfo */
	unsigned int		hw_tx_bufsize;	/* TX_BUFSIZE <- hw_getinfo */
	struct mxgbe_queue	txq[TXQ_MAXNUM] ____cacheline_aligned_in_smp;

	/* RX */
	unsigned int		rx_ring_count;
	u32			rx_coalesced_frames;
	u32			rx_coalesce_usecs;
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
	struct mii_bus		*mii_bus;
	int			pcsaddr;	/* Address of Internal PHY */
	u32			pcs_dev_id;
	int			node;

	/* I2C */
	struct i2c_adapter	*i2c_0;	/* SFP */
	struct i2c_adapter	*i2c_1;	/* VSC */
	struct i2c_adapter	*i2c_2;	/* EEPROM */
	__be64			MAC;

	/* MAC */
	struct task_struct	*mac_task;

	netdev_features_t hw_features;
#ifdef CONFIG_DEBUG_FS
	struct dentry		*mxgbe_dbg_board;
	u32			reg_last_value;
	char			dbg_name[IFNAMSIZ + 14];
#endif /*CONFIG_DEBUG_FS*/

	struct mxgbe_err_flags	rx_err_flags[RXQ_MAXNUM];
	struct mxgbe_err_flags	tx_err_flags[TXQ_MAXNUM];
#ifdef CONFIG_MXGBE_DCA
	u8			proc_hint; /* 4.1: Processing Hint */
#endif /* CONFIG_MXGBE_DCA */
	struct bpf_prog	*xdp_prog;
	union mxgbe_vf_group vft[RX_VLANFILT_TBLSIZE];	/* VLAN filtering table */
} mxgbe_priv_t;


extern spinlock_t eldwcxpcs_mgio_lock[];
extern struct pci_driver mxgbe_pci_driver;

int mxgbe_tx_q_mapping(mxgbe_priv_t *priv, struct sk_buff *skb);
int mxgbe_open(struct net_device *ndev);
int mxgbe_stop(struct net_device *ndev);
void net_rxq_clean_q(mxgbe_priv_t *priv, int qn);
void net_txq_clean_q(mxgbe_priv_t *priv, int qn);
int net_rxq_init_q(mxgbe_priv_t *priv, int qn);

void mxgbe_set_ethtool_ops(struct net_device *ndev);

void mxgbe_net_rx_irq_handler(mxgbe_vector_t *vector);
void mxgbe_net_tx_irq_handler(mxgbe_vector_t *vector);
void mxgbe_net_mac_irq_handler(mxgbe_priv_t *priv, u32 state);

mxgbe_priv_t *mxgbe_net_alloc(struct pci_dev *pdev, void __iomem *base);
int mxgbe_net_register(mxgbe_priv_t *priv);
int mxgbe_net_reinit(mxgbe_priv_t *priv);
void mxgbe_net_remove(mxgbe_priv_t *priv);
void mxgbe_net_free(mxgbe_priv_t *priv);
int mxgbe_board_up(mxgbe_priv_t *priv);
void mxgbe_board_down(mxgbe_priv_t *priv);

int mxgbe_device_event(struct notifier_block *unused, unsigned long event, void *ptr);

int mxgbe_init_board(struct pci_dev *pdev, void __iomem *bar_addr[], phys_addr_t bar_addr_bus[]);
void mxgbe_release_board(struct pci_dev *pdev);

#endif /* MXGBE_H__ */
