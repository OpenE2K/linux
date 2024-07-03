/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/pci.h>
#include <linux/delay.h>
#include <linux/init.h>
#include <linux/ethtool.h>
#include <linux/mii.h>
#include <linux/crc32.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/moduleparam.h>
#include <linux/bitops.h>
#include <linux/proc_fs.h>
#include <linux/skbuff.h>
#include <linux/pci_ids.h>
#include <linux/timecounter.h>		/* for IEEE 1588 */
#include <linux/net_tstamp.h>		/* for IEEE 1588 */
#include <linux/ptp_clock_kernel.h>	/* for IEEE 1588 */
#include <linux/pps_kernel.h>		/* for IEEE 1588 */
#include <linux/phy.h>
#include <linux/irq.h>

#ifndef MODULE
#undef CONFIG_DEBUG_FS
#endif
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include <asm/dma.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/irqflags.h>
#include <asm/irq.h>
#include <asm/setup.h>
#include "l_e1000.h"

/* only for printk */
#include <linux/micrel_phy.h>
#include <linux/marvell_phy.h>

/* NatSemi DP83865 phy identifier values (not in .h) */
#define DP83865_PHY_ID		0x20005c7a
#define NATSEMI_PHY_ID_MASK	0xfffffff0
/* TI DP83867 phy identifier values (not in .h) */
#define DP83867_PHY_ID		0x2000a231


#define DRV_VERSION	"2.00"
#define DRV_RELDATE	"20.02.2020"

static const char *version = "l_e1000_nort.c: v"
			     DRV_VERSION " " DRV_RELDATE
			     " alexmipt@mcst.ru, kalita_a@mcst.ru\n";

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("Driver for e1000 on e2k/e90 family architecture");
MODULE_LICENSE("GPL v2");


#define LE1000_CHEKS_TX_RING	0

#define E1000_DMA_MASK		0xffffffff
#define E1000_TOTAL_SIZE	0x20

#define e1000_mode		(FULL)

/*
 * Set the number of Tx and Rx buffers, using Log_2(# buffers).
 * Reasonable default values are 16 Tx buffers, and 256 Rx buffers.
 * That translates to 4 (16 == 2^^4) and 8 (256 == 2^^8).
 */
#ifndef E1000_LOG_TX_BUFFERS
#define E1000_LOG_TX_BUFFERS	8 /*4*/
#define E1000_LOG_RX_BUFFERS	9 /*8*/
#endif /* E1000_LOG_TX_BUFFERS */

#define TX_RING_SIZE		(1 << (E1000_LOG_TX_BUFFERS))
#define TX_RING_MOD_MASK	(TX_RING_SIZE - 1)

#define TX_HISTERESIS		4
#define RX_RING_SIZE		(1 << (E1000_LOG_RX_BUFFERS))
#define RX_RING_MOD_MASK	(RX_RING_SIZE - 1)

#define SMALL_PKT_SZ		1536
#define E100_MAX_DATA_LEN	3000
#define PKT_BUF_SZ		(E100_MAX_DATA_LEN + ETH_HLEN)

/* Each packet consists of header 14 bytes + [46min..1500max] data + 4 bytes crc 
 * e1000 makes crc automatically when sending a packet so you havn't to take
 * care about it allocating memory for the packet being sent. As to received
 * packets e1000 doesn't hew crc off so you'll have to alloc an extra 4 bytes
 * of memory in addition to common packet size
 */
#define CRC_SZ			4

#define L_E1000_NAPI_WEIGHT	64

#define MAX_TX_COAL_FRAMES	64
#define MAX_COAL_USEC		(0xFFFF / 125)


/* E1000 Rx and Tx ring descriptors. */

struct e1000_rx_head {
	u32	base;		/* RBADR [31:0] */ 
	s16	buf_length;	/* BCNT only [13:0] */
	s16	status;
	s16	msg_length;	/* MCNT only [13:0] */
	u16	reserved1;
	u32	etmr;	/* timer count for ieee 1588 is set by hardware */
} __attribute__((packed));

struct e1000_tx_head {
	u32	base;		/* TBADR [31:0] */
	s16	buf_length;	/* BCNT only [13:0] */
	s16	status;
	u32	misc;		/* [31:26] + [3:0] */
	u32	etmr;	/* timer count for ieee 1588 is set by hardware */
} __attribute__((packed));

struct e1000_dma_area {
	init_block_t init_block __attribute__((aligned(32)));
	struct e1000_rx_head rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
	struct e1000_tx_head tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
};
typedef struct napi_work {
	struct work_struct	work;
	struct list_head	napi_list;
} napi_work_t;

/*
 * The first three fields of pcnet32_private are read by the ethernet device
 * so we allocate the structure should be allocated by pci_alloc_consistent().
 */
struct e1000_private {
#if 0
	init_block_t		init_block __attribute__((aligned(32)));

	/* The Tx and Rx ring entries must be aligned on 16-byte boundaries
	 * in 32bit mode.
	 */
	struct e1000_rx_head rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
	struct e1000_tx_head tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
#else
	init_block_t		*init_block;
	struct e1000_rx_head	*rx_ring;
	struct e1000_tx_head	*tx_ring;
	void			*dma_area;
#endif /* 0 */
	dma_addr_t		dma_addr;	/* DMA address of beginning of
						 * this object of type
						 * e1000_private, returned by
						 * pci_alloc_consistent
						 */
	struct pci_dev		*pci_dev; 	/* Pointer to the associated
						 * pci device structure
						 */
	void			*smpkts_area;
	dma_addr_t		smpkts_dma;
	struct net_device	*dev;
	struct resource		*resource;
	int			msi_status;
	int			bar;		/* MSIX support */
	struct msix_entry	*msix_entries;	/* MSIX support */
	int			irq;

	/* The saved address of a sent-in-place packet/buffer, for skfree(). */
	struct sk_buff		*tx_skbuff[TX_RING_SIZE];
	struct sk_buff		*rx_skbuff[RX_RING_SIZE];
	dma_addr_t		tx_dma_addr[TX_RING_SIZE];
	dma_addr_t		rx_dma_addr[RX_RING_SIZE];
	unsigned char		*base_ioaddr;

	raw_spinlock_t		lock;		/* Guard lock */
	unsigned int		cur_rx, cur_tx;	/* The next free ring entry */
	unsigned int		dirty_tx; /* The ring entries to be free()ed. */
	unsigned int		last_tx_intr;
#if LE1000_CHEKS_TX_RING
	unsigned int		od_tx, oc_tx;
#endif /* LE1000_CHEKS_TX_RING */

	struct napi_struct	napi;
	int			napi_cpu;
	int			napi_scheduled;
	int			napi_wanted;
	int			xmit_enabled_intr;

	struct net_device_stats	stats;
	char			tx_full;
	char			revision;	/* PCI_REVISION_ID */
	unsigned int		shared_irq:1,	/* shared irq possible */
				dxsuflo:1;	/* disable trans stop on uflo */

	struct mii_bus		*mii_bus;
	int			phyaddr;
	phy_interface_t		phy_mode;	/* PHY_INTERFACE_MODE_* */
	int			fiber_mode;

	struct sk_buff		*skb_to_pause;
	dma_addr_t		skb_to_pause_dma;
	int			skb_to_pause_sent;
	int			tx_coal_frame;	/* Not raise intr until send
						 * this nmbr of pkts
						 */
	u32			txrx_delay;	/* Delay after first rx_ & tx_
						 * pkt to raise interrupt
						 */

	u32			msg_enable;	/* debug message level */

	/* For IEEE 1588 */
	struct hwtstamp_config	hwtstamp_config;
	struct ptp_clock	*ptp_clock;
	struct ptp_clock_info	ptp_clock_info;
	int			csr_1588;
	raw_spinlock_t		systim_lock;
	struct cyclecounter	cc;
	struct timecounter	tc;
#ifdef CONFIG_DEBUG_FS
	struct dentry		*l_e1000_dbg_board;
	u32			reg_last_value;
#endif /*CONFIG_DEBUG_FS*/
};


static void *iohub_eth_base_addr;

static int e1000_debug = 0;

static unsigned int rx_prev_etmr = 0;	/* for debug */
static unsigned int tx_prev_etmr = 0;	/* for debug */

static const char e1000_gstrings_test[][ETH_GSTRING_LEN] = {
	"Loopback test  (offline)"
};

static unsigned char pause_packet[ETH_ZLEN] = {
	0x01, 0x80, 0xC2, 0x00, 0x00, 0x01,	/* dest MAC */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	/* will be my MAC */
	0x88, 0x08,				/* type/lengh */
	0x00, 0x01,				/* the PAUSE opcade */
	0x00, 0xEF				/* pause value */
};

/* For IEEE-1588 testing in IOHUB2 */
static u32 max_min_tstmp[8] = {0, 0, 0xffffffff, 0xffffffff, 0, 0, 0, 0};
#define MAX_TX_TSMP	0
#define MAX_RX_TSMP	1
#define MIN_TX_TSMP	2
#define MIN_RX_TSMP	3
#define LST_TX_TSMP	4
#define LST_RX_TSMP	5
#define PRV_TX_TSMP	6
#define PRV_RX_TSMP	7


static int assigned_speed = SPEED_1000;
module_param_named(speed, assigned_speed, int, 0444);
MODULE_PARM_DESC(speed, "used to restrict speed to 10 or 100");

static int half_duplex = 0;
module_param_named(hd, half_duplex, int, 0444);
MODULE_PARM_DESC(hd, "work in half duplex mode");

static int num_tx_bufs_to_clean = TX_RING_SIZE;
module_param_named(tx_bufs_to_clean, num_tx_bufs_to_clean, int, 0444);
MODULE_PARM_DESC(tx_bufs_to_clean, "num txbufs to clean in xmit");

static int do_pause_sender = 0;
module_param_named(pause_sender, do_pause_sender, int, 0444);
MODULE_PARM_DESC(pause_sender, "pause sender in case of FIFO error");

static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, KBUILD_MODNAME " debug level");

#if 0
static int max_interrupt_work = 2;
module_param(max_interrupt_work, int, 0);
MODULE_PARM_DESC(max_interrupt_work, "maximum events handled per interrupt");
#endif /* 0 */

static int rx_copybreak = 200;
module_param(rx_copybreak, int, 0);
MODULE_PARM_DESC(rx_copybreak, "copy breakpoint for copy-only-tiny-frames");


/** TITLE: PHC stuff */
/**
 * le1000_phc_adjfreq - adjust the frequency of the hardware clock
 * @ptp: ptp clock structure
 * @delta: Desired frequency change in parts per billion
 *
 * Adjust the frequency of the PHC cycle counter by the indicated delta from
 * the base frequency.
 **/
static int le1000_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	/* TODO: write to RTC if SCLKR_RTC */
	return 0;
}

/**
 * le1000_phc_adjtime - Shift the time of the hardware clock
 * @ptp: ptp clock structure
 * @delta: Desired change in nanoseconds
 *
 * Adjust the timer by resetting the timecounter structure.
 **/
static int le1000_phc_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct e1000_private *ep = container_of(ptp, struct e1000_private,
						ptp_clock_info);
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->systim_lock, flags);
	timecounter_adjtime(&ep->tc, delta);
	raw_spin_unlock_irqrestore(&ep->systim_lock, flags);

	return 0;
}

/**
 * le1000_phc_gettime - Reads the current time from the hardware clock
 * @ptp: ptp clock structure
 * @ts: timespec structure to hold the current time value
 *
 * Read the timecounter and return the correct value in ns after converting
 * it into a struct timespec.
 **/
static int le1000_phc_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct e1000_private *ep = container_of(ptp, struct e1000_private,
						ptp_clock_info);
	unsigned long flags;
	u64 ns;

	raw_spin_lock_irqsave(&ep->systim_lock, flags);
	ns = timecounter_read(&ep->tc);
	raw_spin_unlock_irqrestore(&ep->systim_lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

/**
 * le1000_phc_settime - Set the current time on the hardware clock
 * @ptp: ptp clock structure
 * @ts: timespec containing the new time for the cycle counter
 *
 * Reset the timecounter to use a new base value instead of the kernel
 * wall timer value.
 **/
static int le1000_phc_settime(struct ptp_clock_info *ptp,
			      const struct timespec64 *ts)
{
	struct e1000_private *ep = container_of(ptp, struct e1000_private,
						ptp_clock_info);
	unsigned long flags;
	u64 ns;

	ns = timespec64_to_ns(ts);

	/* reset the timecounter */
	raw_spin_lock_irqsave(&ep->systim_lock, flags);
	timecounter_init(&ep->tc, &ep->cc, ns);
	raw_spin_unlock_irqrestore(&ep->systim_lock, flags);

	return 0;
}

/**
 * le1000_phc_enable - enable or disable an ancillary feature
 * @ptp: ptp clock structure
 * @request: Desired resource to enable or disable
 * @on: Caller passes one to enable or zero to disable
 *
 * Enable (or disable) ancillary features of the PHC subsystem.
 * Currently, no ancillary features are supported.
 **/
static int le1000_phc_enable(struct ptp_clock_info *ptp,
			     struct ptp_clock_request *rq, int on)
{
	if (rq->type == PTP_CLK_REQ_PPS) {
		pr_warn("%s: TODO: call to mpv pps init\n", __func__);
		/* mpv_set_pps(on); */
		return 0;
	}

	return -ENOTSUPP;
}

static const struct ptp_clock_info le1000_ptp_clock_info = {
	.owner		= THIS_MODULE,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.pps		= 1,
	.adjfreq	= le1000_phc_adjfreq,
	.adjtime	= le1000_phc_adjtime,
	.gettime64	= le1000_phc_gettime,
	.settime64	= le1000_phc_settime,
	.enable		= le1000_phc_enable,
};


/** TITLE: utility stuff */

static int l_e1000_supports_coalesce(struct e1000_private *ep)
{
	if (ep->pci_dev->vendor != PCI_VENDOR_ID_MCST_TMP)
		return 0;

	if (ep->pci_dev->device == PCI_DEVICE_ID_MCST_MGEX)
		return 1;

	return 0;
}

static int l_e1000_num_chanels(struct pci_dev *pdev)
{
	if ((pdev->vendor == PCI_VENDOR_ID_MCST_TMP) &&
	    (pdev->device == PCI_DEVICE_ID_MCST_MGEX)) {
		if (pdev->revision < 0x20) {
			return 4;
		} else {
			return 2;
		}
	}
	return 1;
}

#ifdef MCST_MSIX
static int l_e1000_supports_msix(struct pci_dev *pdev)
{
	if ((pdev->vendor == PCI_VENDOR_ID_MCST_TMP) &&
	    (pdev->device == PCI_DEVICE_ID_MCST_MGEX)) {
		return l_e1000_num_chanels(pdev);
	}
	return 0;
}
#endif /* MCST_MSIX */

static int l_e1000_supports_msi(struct pci_dev *pdev)
{
	return ((pdev->vendor == PCI_VENDOR_ID_MCST_TMP) &&
		(pdev->device == PCI_DEVICE_ID_MCST_MGEX));
}

/** register read/write */

/* Ethernet Control/Status Register (E_CSR) */
static u32 e1000_read_e_csr(struct e1000_private *ep)
{
	u32 val = 0;

	BUG_ON(!ep->base_ioaddr);
	val = readl(ep->base_ioaddr + E_CSR);
	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s: e_csr == 0x%x\n", __func__, val);

	return val;
}

static void e1000_write_e_csr(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + E_CSR);
	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s: e_csr := 0x%x\n", __func__, val);
}

/* MGIO Control/Status Register (MGIO_CSR) */
static u32 e1000_read_mgio_csr(struct e1000_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + MGIO_CSR);
}

static void e1000_write_mgio_csr(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + MGIO_CSR);
}

/* MGIO Data Register (MGIO_DATA) */
static u32 e1000_read_mgio_data(struct e1000_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + MGIO_DATA);
}

static void e1000_write_mgio_data(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + MGIO_DATA);
}

/* Ethernet Base Address Register (E_BASE_ADDR) */
static u32 e1000_read_e_base_address(struct e1000_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + E_BASE_ADDR);
}

static void e1000_write_e_base_address(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + E_BASE_ADDR);
}

/* DMA Base Address Register  (DMA_BASE_ADDR) */
static u32 e1000_read_dma_base_address(struct e1000_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + DMA_BASE_ADDR);
}

static void e1000_write_dma_base_address(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + DMA_BASE_ADDR);
}

/* Pause Frame Control/Status Register (PSF_CSR) */
static u32 e1000_read_psf_csr(struct e1000_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + PSF_CSR);
}

#if 0
static void e1000_write_psf_csr(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + PSF_CSR);
}
#endif /* 0 */

/* Pause Frame Data Register (PSF_DATA) */
static u32 e1000_read_psf_data(struct e1000_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + PSF_DATA);
}

#if 0
static void e1000_write_psf_data(struct e1000_private *ep, int val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + PSF_DATA);
}
#endif /* 0 */

/** ring dump */
static void dump_rx_ring_state(struct e1000_private *ep)
{
	int i;

	dev_warn(&ep->dev->dev, "RX ring: cur_rx = %u\n", ep->cur_rx);
	for (i = 0 ; i < RX_RING_SIZE; i++) {
		pr_cont("   RX %03d base %08x buf len %04x msg len %04x status"
			" %04x\n", i,
			le32_to_cpu(ep->rx_ring[i].base),
			le16_to_cpu((-ep->rx_ring[i].buf_length& 0xffff) ),
			le16_to_cpu(ep->rx_ring[i].msg_length),
			(u16)le16_to_cpu((ep->rx_ring[i].status)));
	}
	pr_cont("\n");
}

static void dump_tx_ring_state(struct e1000_private *ep)
{
	int i;

	dev_warn(&ep->dev->dev, "TX ring: cur_rx = %u, dirty_tx = %u %s\n",
		 ep->cur_tx, ep->dirty_tx, ep->tx_full ? " (full)" : "");
	for (i = 0 ; i < TX_RING_SIZE; i++) {
		pr_cont("   TX %03d base %08x buf len %04x misc %04x status"
			" %04x\n", i,
			le32_to_cpu(ep->tx_ring[i].base),
			le16_to_cpu((-ep->tx_ring[i].buf_length) & 0xffff),
			le32_to_cpu(ep->tx_ring[i].misc),
			le16_to_cpu((u16)(ep->tx_ring[i].status)));
	}
	pr_cont("\n");
}

static void dump_ring_state(struct e1000_private *ep)
{
	dump_rx_ring_state(ep);
	dump_tx_ring_state(ep);
}

static void dump_init_block(struct e1000_private *ep)
{
	dev_warn(&ep->dev->dev, "Init block (%p)state:\n", ep->init_block);
	pr_cont("   MODE 0x%04x PADDR 0x%02x%02x%02x%02x%02x%02x "
		"LADDRF 0x%016llx\n",
		le16_to_cpu(ep->init_block->mode),
		ep->init_block->paddr[5], ep->init_block->paddr[4],
		ep->init_block->paddr[3], ep->init_block->paddr[2],
		ep->init_block->paddr[1], ep->init_block->paddr[0],
		ep->init_block->laddrf);
	pr_cont("   Receive  Desc Ring Addr: 0x%08x\n",
		ep->init_block->rdra);
	pr_cont("   Transmit Desc Ring Addr: 0x%08x\n",
		ep->init_block->tdra);
	pr_cont("CSR = 0x%x\n", e1000_read_e_csr(ep));
}

#if LE1000_CHEKS_TX_RING
static int check_tx_ring(struct e1000_private *ep, char *str)
{
	static int checked = 10;
	int cur_tx = ep->cur_tx;
	int dirty_tx = ep->dirty_tx;
	int i;
	int base;
	char *reason;

	if (checked <= 0) {
		return 1;
	}

	if (cur_tx == dirty_tx) {
		/* all entries are dirty or all entries are clean */
		base = !!ep->tx_ring[0].base;
		for (i = 0; i < TX_RING_SIZE; i++) {
			if (base != !!ep->tx_ring[i].base) {
				reason = "Bad entry ";
				goto bad_ring;
			}
		}
		return 0;
	}

	if (ep->tx_ring[dirty_tx].base == 0) {
		reason = "Bad dirty_tx";
		i = dirty_tx;
		goto bad_ring;
	}

	base = 1;
	i = (dirty_tx + 1) & TX_RING_MOD_MASK;
	while (i != dirty_tx) {
		if (ep->tx_ring[i].base == 0) {
			if (i != cur_tx) {
				reason = "Bad cur_tx. First clesn ";
				goto bad_ring;
			}
			base = 0;
			break;
		}
		i = (i + 1) & TX_RING_MOD_MASK;
	}
	if (base) {
		reason = "No clean entries";
		i = 0;
		goto bad_ring;
	}
	while (i != dirty_tx) {
		if (ep->tx_ring[i].base != 0) {
			reason = "Dirty_entry ";
			goto bad_ring;
		}
		i = (i + 1) & TX_RING_MOD_MASK;
	}
	ep->oc_tx = ep->cur_tx;
	ep->od_tx = ep->dirty_tx;
	return 0;

bad_ring:
	dev_warn(&ep->dev->dev, "%s: %s: %s %d\n", __func__, str, reason, i);
	dev_warn(&ep->dev->dev, "Pevious values: cur_tx = %u, dirty_tx = %u\n",
		 ep->oc_tx, ep->od_tx);
	dump_tx_ring_state(ep);
	checked--;
	return 1;
}
#else /* !LE1000_CHEKS_TX_RING */
#define check_tx_ring(a,b) {}
#endif /* LE1000_CHEKS_TX_RING */

/** utility function which is used in init timecounter only */
static u64 l_e1000_ptp_read(const struct cyclecounter *cc)
{
	return 0; /* it is need for init only */
}

/**
 * l_e1000_hwtstamp - utility function for IEEE 1588 in IOHUB2
 * @ep: board private structure
 * @skb: particular skb to include time stamp
 * @entry: descriptor entry
 *
 * If the time stamp is valid, convert it into the timecounter ns value
 * and store that result into the hwtstamps structure which is passed
 * up the network stack.
 **/
static void l_e1000_hwtstamp(struct e1000_private *ep, struct sk_buff *skb,
			     u32 etmr)
{
	u64 ns;
	struct skb_shared_hwtstamps *hwtstamps;
	unsigned long flags;

	/* skb->tstamp = ktime_get_real(); */

	raw_spin_lock_irqsave(&ep->systim_lock, flags);
	ns = timecounter_cyc2time(&ep->tc, etmr);
	raw_spin_unlock_irqrestore(&ep->systim_lock, flags);

	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ns);
}

/*
 * This is the only way to put data to boot while reset
 */
#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
#ifndef MODULE
static int set_iohub_eth_for_special_reset(int m)
{
	int i;

	if (!iohub_eth_base_addr)
		return -1;

	/* At first stop the card */
	writel(STOP, iohub_eth_base_addr + E_CSR);

	/* wait for stop */
        for (i = 0; i < 1000; i++) {
		if (readl(iohub_eth_base_addr + E_CSR) & STOP)
			break;
	}
	if (i == 1000) {
		return -1;
	}

	writel(m, iohub_eth_base_addr + E_BASE_ADDR);
	(void)readl(iohub_eth_base_addr + E_BASE_ADDR);

	return 0;
}
#endif /* MODULE */
#endif /* CONFIG_E2K) || CONFIG_E90S */


/** TITLE: PHY/MDIO stuff */

/* This routine assumes that the mii_bus.mdio_lock is held */
static int e1000_mdio_read_reg(struct mii_bus *mii_bus, int addr, int regnum)
{
	struct e1000_private *ep = mii_bus->priv;
	u32 rd; 
	u16 val_out = 0;
	int i = 0;

	rd = 0;
	rd |= 0x2 << MGIO_CS_OFF;
	rd |= 0x1 << MGIO_ST_OF_F_OFF;
	rd |= 0x2 << MGIO_OP_CODE_OFF; /* Read */
	rd |= (addr  & 0x1f) << MGIO_PHY_AD_OFF;
	rd |= (regnum & 0x1f) << MGIO_REG_AD_OFF;
	e1000_write_mgio_data(ep, rd);

	rd = 0;
	for (i = 0; i != 1000; i++){
		if (e1000_read_mgio_csr(ep) & RRDY) {
			rd = e1000_read_mgio_data(ep);
			val_out = (u16)rd;

			if (netif_msg_hw(ep))
				dev_info(&ep->dev->dev, "%s: reg[0x%x]==0x%x\n",
					 __func__, regnum, val_out);

			return val_out;
		}
	}

	if (netif_msg_hw(ep))
		dev_err(&ep->dev->dev,
			"%s: Unable to read from MGIO_DATA reg[0x%x]\n",
			__func__, regnum);

	return -ETIMEDOUT;
}

/* This routine assumes that the mii_bus.mdio_lock is held */
static int e1000_mdio_write_reg(struct mii_bus *mii_bus, int addr,
				int regnum, u16 val)
{
	struct e1000_private *ep = mii_bus->priv;
	u32 wr;
	int i = 0;

	wr = 0;
	wr |= 0x2 << MGIO_CS_OFF;
	wr |= 0x1 << MGIO_ST_OF_F_OFF;
	wr |= 0x1 << MGIO_OP_CODE_OFF; /* Write */
	wr |= (addr  & 0x1f) << MGIO_PHY_AD_OFF;
	wr |= (regnum & 0x1f) << MGIO_REG_AD_OFF;
	wr |= val & 0xffff;

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			 "%s: reg[0x%x]:=0x%x\n", __func__, regnum, val);

	e1000_write_mgio_data(ep, wr);

	for (i = 0; i != 1000; i++) {
		if (e1000_read_mgio_csr(ep) & RRDY)
			return 0;
	}

	if (netif_msg_hw(ep))
		dev_err(&ep->dev->dev,
			"%s: Unable to write MGIO_DATA reg[0x%x], wr = 0x%x\n",
			__func__, regnum, wr);

	return -ETIMEDOUT;
}

/* get mode from phy and set to mac */
static void e1000_set_mac_phymode(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	struct phy_device *phydev = dev->phydev;
	unsigned int val;

	if (!dev->phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	phy_read_status(phydev);

	if (!netif_running(dev)) {
		if (netif_msg_link(ep))
			dev_info(&dev->dev, "netif not running\n");
		return;
	}

	/* disable auto mac control from all phys */
	val = e1000_read_mgio_csr(ep);
	val |= HARD;
	val |= SLSE;
	e1000_write_mgio_csr(ep, val);

	val &= ~(FETH|GETH|FDUP|SLST);

	if (phydev->speed == SPEED_1000) {
		val |= GETH;
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s speed == 1000\n",
				 phydev_name(dev->phydev));
	} else if (phydev->speed == SPEED_100) {
		val |= FETH;
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s speed == 100\n",
				 phydev_name(dev->phydev));
	} else {
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s speed == 10\n",
				 phydev_name(dev->phydev));
	}

	if (phydev->duplex == DUPLEX_FULL) {
		val |= FDUP;
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s duplex == FULL\n",
				 phydev_name(dev->phydev));
	}

	if (phydev->link)
		val |= SLST;

	e1000_write_mgio_csr(ep, val);
}

/* callback - phy change state */
static void e1000_phylink_handler(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);

	if (!dev->phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	e1000_set_mac_phymode(dev);

	if (netif_carrier_ok(dev)) {
		/*pm_request_resume(&ep->pci_dev->dev);*/
	} else {
		/*pm_runtime_idle(&ep->pci_dev->dev);*/
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s no carrier\n",
				 phydev_name(dev->phydev));
	}

	if (net_ratelimit())
		phy_print_status(dev->phydev);
}

/* called at begin of open() */
static int e1000_phy_connect(struct e1000_private *ep)
{
	struct phy_device *phydev = mdiobus_get_phy(ep->mii_bus, ep->phyaddr);
	int ret;

	ret = phy_connect_direct(ep->dev, phydev, e1000_phylink_handler,
				 ep->phy_mode);
	if (ret) {
		dev_err(&ep->dev->dev, "connect to phy %s failed\n",
			phydev_name(phydev));
		return ret;
	}

	phy_read_status(phydev);

	if (half_duplex) {
		phydev->duplex = DUPLEX_HALF;
	}
	if (assigned_speed == SPEED_100) {
		phy_set_max_speed(phydev, SPEED_100);
	} else if (assigned_speed == SPEED_10) {
		phy_set_max_speed(phydev, SPEED_10);
	}

	/* Ensure to advertise everything, incl. pause */
	linkmode_copy(phydev->advertising, phydev->supported);

	if (netif_msg_link(ep))
		phy_attached_info(phydev);

	return 0;
}

/* called at end of open() - start phy */
static void e1000_init_phy(struct e1000_private *ep)
{
	struct net_device *dev = ep->dev;

	if (!dev->phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	/* We may have called phy_speed_down before */
	/*phy_speed_up(dev->phydev);*/

	if (dev->phydev->autoneg == AUTONEG_ENABLE) {
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s restart autoneg\n",
				 phydev_name(dev->phydev));
		phy_restart_aneg(dev->phydev);
	}

	phy_start(dev->phydev);

	if (ep->fiber_mode) {
		u32 r;

#define MII_M1111_PHY_LED_CONTROL	0x18
#define MII_M1111_PHY_EXT_SR		0x1b
#define MII_M1111_HWCFG_MODE_MASK		0xf
#define MII_M1111_HWCFG_FIBER_COPPER_RES	0x2000
#define MII_M1111_HWCFG_FIBER_COPPER_AUTO	0x8000

		r = mdiobus_read(ep->mii_bus, ep->phyaddr,
				 MII_M1111_PHY_EXT_SR);
		r &= ~(MII_M1111_HWCFG_MODE_MASK |
		       MII_M1111_HWCFG_FIBER_COPPER_RES);
		r |= 0x7 | MII_M1111_HWCFG_FIBER_COPPER_AUTO;
		mdiobus_write(ep->mii_bus, ep->phyaddr,
			      MII_M1111_PHY_EXT_SR, r);

		mdiobus_read(ep->mii_bus, ep->phyaddr,
			     MII_M1111_PHY_LED_CONTROL);
		r |= 0x10; /* Led Link Control */
		mdiobus_write(ep->mii_bus, ep->phyaddr,
			      MII_M1111_PHY_LED_CONTROL, r);
	}
}

/* printk only */
static void e1000_print_phy(struct e1000_private *ep, u32 id)
{
	struct pci_dev *pdev = ep->pci_dev;

	if ((id & MARVELL_PHY_ID_MASK) == MARVELL_PHY_ID_88E1111) {
		dev_info(&pdev->dev,
			 "found phy id 0x%08X - Marvell 88E1111\n", id);
	} else if ((id & MICREL_PHY_ID_MASK) == PHY_ID_KSZ9031) {
		dev_info(&pdev->dev,
			 "found phy id 0x%08X - Micrel KSZ9031\n", id);
	} else if ((id & MICREL_PHY_ID_MASK) == PHY_ID_KSZ9021) {
		dev_info(&pdev->dev,
			 "found phy id 0x%08X - Micrel KSZ9021\n", id);
	} else if ((id & NATSEMI_PHY_ID_MASK) == DP83865_PHY_ID) {
		dev_info(&pdev->dev,
			 "found phy id 0x%08X - NatSemi DP83865\n", id);
	} else if (id == DP83867_PHY_ID) {
		dev_info(&pdev->dev,
			 "found phy id 0x%08X - TI DP83867\n", id);
	} else {
		dev_warn(&pdev->dev,
			 "found phy id 0x%08X - unknown phy\n", id);
	}
}

/* called from probe() */
static int e1000_mdio_register(struct e1000_private *ep)
{
	struct pci_dev *pdev = ep->pci_dev;
	struct phy_device *phydev;
	struct mii_bus *new_bus;
	int ret;

	new_bus = devm_mdiobus_alloc(&pdev->dev);
	if (!new_bus) {
		dev_err(&pdev->dev,
			"Error on devm_mdiobus_alloc\n");
		return -ENOMEM;
	}

	new_bus->name = KBUILD_MODNAME" mdio";
	new_bus->priv = ep;
	new_bus->parent = &pdev->dev;
	new_bus->irq[0] = PHY_IGNORE_INTERRUPT;
	if (l_e1000_num_chanels(pdev) == 1) {
		snprintf(new_bus->id, MII_BUS_ID_SIZE, KBUILD_MODNAME"-%x",
			PCI_DEVID(pdev->bus->number, pdev->devfn));
	} else {
		snprintf(new_bus->id, MII_BUS_ID_SIZE, KBUILD_MODNAME"-%x-%x",
			PCI_DEVID(pdev->bus->number, pdev->devfn), ep->bar);
	}

	new_bus->read = e1000_mdio_read_reg;
	new_bus->write = e1000_mdio_write_reg;

	ret = mdiobus_register(new_bus);
	if (ret) {
		dev_err(&pdev->dev,
			"Error on mdiobus_register\n");
		return ret;
	}

	phydev = phy_find_first(new_bus);
	if (!phydev) {
		dev_err(&pdev->dev,
			"Error - no phy found on mdiobus %s\n", new_bus->id);
		mdiobus_unregister(new_bus);
		return -ENODEV;
	}
	ep->phyaddr = phydev->mdio.addr;
	ep->mii_bus = new_bus;

	if ((phydev->phy_id & MARVELL_PHY_ID_MASK) == MARVELL_PHY_ID_88E1111) {
		if (mdiobus_read(ep->mii_bus, ep->phyaddr, 26) & 0x10) {
			dev_info(&pdev->dev, "phy in FIBER mode\n");
			ep->fiber_mode = 1;
		} else {
			dev_info(&pdev->dev, "phy in COPPER mode\n");
			ep->fiber_mode = 0;
		}
	}

	/* reset the PHY via BMCR_RESET bit */
	genphy_soft_reset(phydev);
	mdelay(1);

	/* phy will be woken up in open() */
	phydev->irq = PHY_POLL;
	phy_suspend(phydev);

	if (netif_msg_link(ep))
		e1000_print_phy(ep, phydev->phy_id);

	if (netif_msg_link(ep))
		dev_info(&pdev->dev, "register mdiobus %s with phy %s\n",
			new_bus->id, phydev_name(phydev));

	return 0;
}


/** TITLE: Net Rx/Tx stuff */

static void e1000_load_multicast(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	volatile init_block_t *ib = ep->init_block;
	volatile u16 *mcast_table = (u16 *)&ib->laddrf;
	struct netdev_hw_addr *ha;
	u32 crc;

	/* set all multicast bits */
	if (dev->flags & IFF_ALLMULTI) {
		ib->laddrf = 0xffffffffffffffffLL;
		return;
	}
	/* clear the multicast filter */
	ib->laddrf = 0;

	/* Add addresses */
	netdev_for_each_mc_addr(ha, dev) {
		crc = ether_crc_le(6, ha->addr);
		crc = crc >> 26;
		/* TODO 3.10 cpu_to_le16 is called for store, but is not 
		 * called for load?
		 */
		mcast_table[crc >> 4] = cpu_to_le16((mcast_table[crc >> 4]) |
						    (1 << (crc & 0xf)));
	}
	return;
}

/* Initialize the E1000 Rx and Tx rings. */
static int e1000_init_ring(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	int i;

	ep->tx_full = 0;
	ep->cur_rx = ep->cur_tx = 0;
	ep->last_tx_intr = 0;
	ep->dirty_tx = 0;

	for (i = 0; i < RX_RING_SIZE; i++) {
		struct sk_buff *rx_skbuff = ep->rx_skbuff[i];
		struct e1000_rx_head *rxr = ep->rx_ring + i;

		if (rx_skbuff == NULL) {
			if (!(rx_skbuff = ep->rx_skbuff[i] =
			    dev_alloc_skb(PKT_BUF_SZ + CRC_SZ + 2))) {
				/* there is not much, we can do at this point */
				dev_err(&dev->dev,
					"%s: dev_alloc_skb failed.\n",
					__func__);
				return -1;
			}
			skb_reserve(rx_skbuff, 2);
		}
		rmb();

		if (ep->rx_dma_addr[i] == 0)
			ep->rx_dma_addr[i] = pci_map_single(ep->pci_dev,
							rx_skbuff->data,
							(PKT_BUF_SZ + CRC_SZ) + 2,
							PCI_DMA_FROMDEVICE);

		if (WARN_ON(pci_dma_mapping_error(ep->pci_dev, ep->rx_dma_addr[i])))
			return -1;
		rxr->base = cpu_to_le32((u32)(ep->rx_dma_addr[i]));
		rxr->buf_length = cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
		wmb(); /*Make sure owner changes after all others are visible*/

		rxr->status |= cpu_to_le16(RX_ST_OWN);
		if (netif_msg_pktdata(ep))
			dev_info(&dev->dev,
				 "%s: make recieve buf %d, base = 0x%x,"
				 " buf_len = 0x%x [0x%x]\n",
				 __func__, i,
				 le32_to_cpu(ep->rx_ring[i].base),
				 le16_to_cpu(ep->rx_ring[i].buf_length),
				 (PKT_BUF_SZ + CRC_SZ));
	}

	/* The Tx buffer address is filled in as needed, but we do need to clear
	 * the upper ownership bit.
	 */
	for (i = 0; i < TX_RING_SIZE; i++) {
		struct e1000_tx_head *txr = ep->tx_ring + i;

		txr->status = 0; /* CPU owns buffer */
		wmb(); /* Make sure adapter sees owner change */

		txr->base = 0;
		ep->tx_dma_addr[i] = 0;
	}

	for (i = 0; i < 6; i++)
		ep->init_block->paddr[i] = dev->dev_addr[i];

	ep->init_block->rdra = cpu_to_le32((u32)(ep->dma_addr + 
				offsetof(struct e1000_dma_area, rx_ring)));
	ep->init_block->rdra |= cpu_to_le32(E1000_LOG_RX_BUFFERS);
	ep->init_block->tdra = cpu_to_le32((u32)(ep->dma_addr +
				offsetof(struct e1000_dma_area, tx_ring)));
	ep->init_block->tdra |= cpu_to_le32(E1000_LOG_TX_BUFFERS);
	if (netif_msg_pktdata(ep)) {
		dev_info(&dev->dev,
			 "%s: Receive  Desc Ring DMA Addr | Rlen[3:0]: 0x%x\n",
			 __func__, le32_to_cpu(ep->init_block->rdra));
		dev_info(&dev->dev,
			 "%s: Transmit Desc Ring DMA Addr | Tlen[3:0]: 0x%x\n",
			 __func__, le32_to_cpu(ep->init_block->tdra));
		dev_info(&dev->dev,
			 "%s: init block mode: 0x%x\n",
			 __func__, le16_to_cpu(ep->init_block->mode));
	}

	if (ep->csr_1588) {
		ep->cc.read = l_e1000_ptp_read;
		ep->cc.mask = CYCLECOUNTER_MASK(32);
		ep->cc.shift = 22;
		/* mult = (1 << shift) / freq */
		ep->cc.mult = (1 << ep->cc.shift) / 125000000;
		timecounter_init(&ep->tc, &ep->cc,
				 ktime_to_ns(ktime_get_real()));
	}

	wmb(); /* Make sure all changes are visible */
	return 0;
}

/*
 * The LANCE has been halted for one reason or another (busmaster memory
 * arbitration error, Tx FIFO underflow, driver stopped it to reconfigure,
 * etc.).  Modern LANCE variants always reload their ring-buffer
 * configuration when restarted, so we must reinitialize our ring
 * context before restarting.  As part of this reinitialization,
 * find all packets still on the Tx ring and pretend that they had been
 * sent (in effect, drop the packets on the floor) - the higher-level
 * protocols will time out and retransmit.  It'd be better to shuffle
 * these skbs to a temp list and then actually re-Tx them after
 * restarting the chip, but I'm too lazy to do so right now.  dplatt@3do.com
 */
static void e1000_purge_tx_ring(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	int i;

	for (i = 0; i < TX_RING_SIZE; i++) {
		ep->tx_ring[i].status = 0; /* CPU owns buffer */
		wmb(); /* Make sure adapter sees owner change */

		if (ep->tx_skbuff[i] && (ep->tx_skbuff[i] !=
		    ep->skb_to_pause)) {
#ifdef CAN_UNMAP_SKB_IN_CONSUME
			ep->tx_skbuff[i]->dmaaddr = ep->tx_dma_addr[i];
			ep->tx_skbuff[i]->pci_dev = ep->pci_dev;
#else /* !CAN_UNMAP_SKB_IN_CONSUME */
			if (ep->tx_dma_addr[i]) {
				pci_unmap_single(ep->pci_dev,
						 ep->tx_dma_addr[i],
						 ep->tx_skbuff[i]->len,
						 PCI_DMA_TODEVICE);
			}
#endif /* CAN_UNMAP_SKB_IN_CONSUME */
			if (ep->csr_1588) {
				u32 et = le32_to_cpu(ep->tx_ring[i].etmr);

				l_e1000_hwtstamp(ep, ep->tx_skbuff[i], et);
			}
			dev_kfree_skb_any(ep->tx_skbuff[i]);
		}
		ep->skb_to_pause_sent = 0;
		ep->tx_skbuff[i] = NULL;
		ep->tx_dma_addr[i] = 0;
	}
	netif_trans_update(dev);
}

/*
 * the e1000 has been issued a stop or reset.  Wait for the stop bit
 * then flush the pending transmit operations, re-initialize the ring,
 * and tell the chip to initialize.
 */

static int e1000_restart(struct net_device *dev, unsigned int csr0_bits)
{
	struct e1000_private *ep = netdev_priv(dev);
	int i;

	if (netif_msg_rx_err(ep) || netif_msg_tx_err(ep))
		dev_info(&dev->dev, "reset started\n");

	/* wait for stop */
	for (i = 0; i < 1000; i++)
		if (e1000_read_e_csr(ep) & STOP)
			break;

	if (i >= 1000 && netif_msg_drv(ep))
		dev_warn(&dev->dev,
			 "%s timed out waiting for stop.\n", __func__);

	e1000_purge_tx_ring(dev);
	/* we call e1000_init_ring with ep->lock locked.
	 * we consider it won't call dev_alloc_skb for rx_ring
	 * because all rx bufs already allocated in e1000_open
	 * and successfuly substituted in e1000_rx
	 */
	if (e1000_init_ring(dev))
		return 1;

	ep->napi_scheduled = 0;
	ep->napi_wanted = 0;

	/* ReInit Ring */
	e1000_write_e_csr(ep, INIT | ep->csr_1588);
	i = 0;
	while (i++ < 1000)
		if (e1000_read_e_csr(ep) & IDON)
			break;

	if (i >= 1000 && (netif_msg_rx_err(ep) || netif_msg_tx_err(ep)))
		dev_warn(&dev->dev,
			 "initialization is not completed,"
			 " status register 0x%08x\n",
			 e1000_read_e_csr(ep));

	if (netif_msg_rx_err(ep) || netif_msg_tx_err(ep))
		dev_info(&dev->dev,
			 "%s: e_csr register after "
			 "initialization: 0x%x, must be 0x%x\n",
			 __func__, e1000_read_e_csr(ep), (IDON | INTR | INIT));

	if (l_e1000_supports_coalesce(ep)) {
		/* Set 125 usec. It's time to tx about 250
		 * the smallest packets
		 */
		writel(ep->txrx_delay, ep->base_ioaddr + INT_DELAY);
	}

	e1000_write_e_csr(ep, csr0_bits);
	if (netif_msg_rx_err(ep) || netif_msg_tx_err(ep)) {
		dev_info(&dev->dev, "reset done\n");
		dump_init_block(ep);
	}

	return 0;
}

static void napi_wq_worker(struct work_struct *work)
{
	napi_work_t *napi_work1 = container_of(work, napi_work_t, work);

	set_thread_flag(TIF_NAPI_WORK);
	netif_receive_skb_list(&napi_work1->napi_list);
	clear_thread_flag(TIF_NAPI_WORK);
	kfree((void *)work);
}

static void e1000_pause_sender(struct e1000_private *ep);
/** TITLE: Net Rx stuff */

static int e1000_rx(struct e1000_private *ep, int budget)
{
	int entry = ep->cur_rx & RX_RING_MOD_MASK;
	struct net_device *dev = ep->dev;
	int boguscnt = RX_RING_SIZE;
	int work_done = 0;
	short pkt_len;
	struct sk_buff *skb;
	int rx_in_place;
	struct list_head rx_list;
	u32 csr0;
	napi_work_t *napi_work1;

	INIT_LIST_HEAD(&rx_list);

	/* If we own the next entry, it's a new packet. Send it up. */
	while (((s16)le16_to_cpu(ep->rx_ring[entry].status)) >= 0) {
		int status = (short)le16_to_cpu(ep->rx_ring[entry].status);
		int status_a;

		if (work_done == budget) {
			if (netif_msg_rx_err(ep)) {
				dev_info(&dev->dev,
					 "rx budget %d overloaded.\n", budget);
			}
			break;
		}
		status_a = (short)le16_to_cpu(ep->rx_ring[(entry
			+ RX_RING_SIZE - 8) & RX_RING_MOD_MASK].status);
		if (netif_msg_rx_status(ep))
			dev_info(&dev->dev,
				 "%s: status = 0x%x\n", __func__, status);

		if ((status & 0xff00) != (RD_ENP | RD_STP)) {
			/* There was an error. */
			ep->stats.rx_errors++;
			if (netif_msg_rx_err(ep)) {
				dev_info(&dev->dev,
					 "reciever error: bl=0x%x, ml=0x%x."
					 " error status = 0x%x",
					 (short)le16_to_cpu(
						 ep->rx_ring[entry].buf_length),
					 (short)le16_to_cpu(
						 ep->rx_ring[entry].msg_length),
					 status);
			}
			/*
			* There is a tricky error noted by John Murphy,
			* <murf@perftech.com> to Russ Nelson: Even with
			* full-sized buffers it's possible for a jabber packet
			* to use two buffers, with only the last correctly
			* noting the error.
			*/
			if (status & RD_ENP) {
				if (netif_msg_rx_err(ep)) {
					pr_cont("  ENP");
				}
				/* No detailed rx_errors counter to increment
				 * at the end of a packet.
				 */
			}
			if (status & RD_FRAM) {
				if (netif_msg_rx_err(ep)) {
					pr_cont("  FRAM");
				}
				ep->stats.rx_frame_errors++;
			}
			if (status & RD_OFLO) {
				if (netif_msg_rx_err(ep)) {
					pr_cont("  OFLO");
				}
				ep->stats.rx_over_errors++;
			}
			if (status & RD_CRC) {
				if (netif_msg_rx_err(ep)) {
					pr_cont(" CRC ");
				}
				ep->stats.rx_crc_errors++;
			}
			if (status & RD_BUFF) {
				if (netif_msg_rx_err(ep)) {
					pr_cont(" BUFF");
				}
				ep->stats.rx_fifo_errors++;
			}
			if (netif_msg_rx_err(ep)) {
				pr_cont("\n");
			}
			ep->rx_ring[entry].status &= cpu_to_le16(RD_ENP|RD_STP);
			goto try_next;
		}
		pkt_len = (le16_to_cpu(ep->rx_ring[entry].msg_length) & 0xfff)
			  - CRC_SZ;
		/* Malloc up new buffer, compatible with net-2e. */
		/* Discard oversize frames. */
		if (unlikely(pkt_len > PKT_BUF_SZ)) {
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "Impossible packet size %d!\n",
					 pkt_len);
			ep->stats.rx_errors++;
			goto try_next;
		}
		if (pkt_len < 60) {
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev, "Runt packet!\n");
			ep->stats.rx_errors++;
			goto try_next;
		}
		rx_in_place = 0;

		if (pkt_len > rx_copybreak) {
			struct sk_buff *newskb;

			if ((newskb = netdev_alloc_skb(dev,
			    PKT_BUF_SZ + CRC_SZ + 2))) {
				dma_addr_t a = pci_map_single(ep->pci_dev,
						newskb->data + 2,
						(PKT_BUF_SZ + CRC_SZ + 2),
						PCI_DMA_FROMDEVICE);
				if (pci_dma_mapping_error(ep->pci_dev, a)) {
					skb = newskb;
					goto copy;
				}
				skb_reserve (newskb, 2);
				skb = ep->rx_skbuff[entry];
				pci_unmap_single(ep->pci_dev,
						 ep->rx_dma_addr[entry],
						 (PKT_BUF_SZ + CRC_SZ + 2),
						 PCI_DMA_FROMDEVICE);
				skb_put(skb, pkt_len);
				ep->rx_skbuff[entry] = newskb;
				newskb->dev = dev;
				ep->rx_dma_addr[entry] = a;
				ep->rx_ring[entry].base = 
					cpu_to_le32(ep->rx_dma_addr[entry]);
				rx_in_place = 1;
				if (netif_msg_rx_status(ep))
					dev_info(&dev->dev,
						 "%s: interrupt: new sbk is "
						 "alloced, rx_in_place = 1\n",
						 __func__);
			} else {
				if (netif_msg_rx_status(ep))
					dev_info(&dev->dev,
						 "%s: interrupt: new sbk is "
						 "failed to alloc\n",
						 __func__);
				skb = NULL;
			}
		} else {
			if (netif_msg_rx_status(ep))
				dev_info(&dev->dev,
					 "%s: interrupt: pkt_len 0x%x "
					 "<= rx_copybreak 0x%x\n",
					 __func__, pkt_len,
					 rx_copybreak);
			skb = netdev_alloc_skb(dev, pkt_len + 2);
		}
	copy:
		if (skb == NULL) {
			int i;

			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "Memory squeeze, deferring packet.\n");
			for (i = 0; i < RX_RING_SIZE; i++)
				if ((short)le16_to_cpu(ep->rx_ring[(entry+i)
				    & RX_RING_MOD_MASK].status) < 0)
					break;
			if (i > RX_RING_SIZE - 2) {
				ep->stats.rx_dropped++;
				ep->rx_ring[entry].status = 0;
				ep->rx_ring[entry].status |=
							cpu_to_le16(RD_OWN);
				wmb(); /* Make sure adapter sees owner change */

				ep->cur_rx++;
			}
			break;
		}
		if (ep->csr_1588) {
			u32 et = le32_to_cpu(ep->rx_ring[entry].etmr);

			l_e1000_hwtstamp(ep, skb, et);
			if (max_min_tstmp[MAX_RX_TSMP] < et)
				max_min_tstmp[MAX_RX_TSMP] = et;
			if (max_min_tstmp[MIN_RX_TSMP] >
			    (et - max_min_tstmp[LST_RX_TSMP]) &&
			    et !=  max_min_tstmp[LST_RX_TSMP]) {
				max_min_tstmp[MIN_RX_TSMP] =
						et - max_min_tstmp[LST_RX_TSMP];
			}
			max_min_tstmp[PRV_RX_TSMP] = max_min_tstmp[LST_RX_TSMP];
			max_min_tstmp[LST_RX_TSMP] = et;
		}
		if (netif_msg_1588(ep)) {
			u32 et = le32_to_cpu(ep->rx_ring[entry].etmr);

			if (rx_prev_etmr >= et) {
				dev_warn(&dev->dev,
					 "cs=%7x Rx= 0x%8x prv= 0x%8x "
					 " maxt %8x r %8x c=%16lu\n",
					 ep->csr_1588,
					 et,
					 rx_prev_etmr,
					 max_min_tstmp[MAX_TX_TSMP],
					 max_min_tstmp[MAX_RX_TSMP],
					 get_cycles());
			}
			rx_prev_etmr = et;
		}
		skb->dev = dev;
		if (!rx_in_place) {
			void *packet;
			struct ethhdr *eth;
			int i;

			if (netif_msg_rx_status(ep))
				dev_info(&dev->dev,
					 "%s: interrupt: rx_in_place = 0\n",
					 __func__);
			skb_reserve(skb,2); /* 16 byte align */
			skb_put(skb,pkt_len); /* Make room */
			pci_dma_sync_single_for_cpu(ep->pci_dev,
						    ep->rx_dma_addr[entry],
						    (PKT_BUF_SZ + CRC_SZ),
						    PCI_DMA_FROMDEVICE);
			packet = (void *) ep->rx_skbuff[entry]->data;
			eth = (struct ethhdr *) packet;
			for (i = 0; i != 6; i++) {
				if (netif_msg_pktdata(ep))
					dev_info(&dev->dev,
						 "%s: interrupt: eth: src 0x%x,"
						 " dst 0x%x\n", __func__,
						 eth->h_source[i],
						 eth->h_dest[i]);
			}
			for (i = 0; i != (pkt_len / 4); i++) {
				if (netif_msg_pktdata(ep))
					dev_info(&dev->dev,
						 "%s: RX packet: int # %d"
						 "  0x%x \n", __func__,
						 i, *(u32 *)packet);
				packet += 4;
			}
			for (i = 0; i != (pkt_len % 4); i++) {
				if (netif_msg_pktdata(ep))
					dev_info(&dev->dev,
						 "%s: RX packet: byte # %d"
						 "  0x%x \n", __func__,
						 i, *(u8 *)packet);
				packet += 1;
			}
			skb_copy_to_linear_data(skb,
				(unsigned char *)(ep->rx_skbuff[entry]->data),
				pkt_len);
			pci_dma_sync_single_for_device(ep->pci_dev,
						       ep->rx_dma_addr[entry],
						       (PKT_BUF_SZ + CRC_SZ),
						       PCI_DMA_FROMDEVICE);
		}
		ep->stats.rx_bytes += skb->len;
		skb->protocol=eth_type_trans(skb, dev);
		list_add_tail(&skb->list, &rx_list);
		ep->stats.rx_packets++;
		e1000_write_e_csr(ep, RINT | ep->csr_1588);
		work_done++;

	try_next:
		/*
		 * The docs say that the buffer length isn't touched,
		 * but Andrew Boyd of QNX reports that some revs of the
		 * 79C965 clear it.
		 */
		ep->rx_ring[entry].buf_length =
					cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
		wmb(); /*Make sure owner changes after all others are visible*/

		ep->rx_ring[entry].status = 0;
		ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
		entry = (++ep->cur_rx) & RX_RING_MOD_MASK;

		/* avoid long reading csr0 if there is free status RD_OWN*/
		if (status_a >= 0) {
			csr0 = e1000_read_e_csr(ep);
			if (csr0 & MISS) {
				ep->stats.rx_missed_errors++;
				if (netif_msg_intr(ep)) {
					dev_info(&dev->dev,
					"Rcv packet missed, status %4.4x.\n",
						 csr0);
				}
				e1000_pause_sender(ep);
				e1000_write_e_csr(ep, csr0);
			}
		}
		if (--boguscnt <= 0) { /* don't stay in loop forever */
			if (netif_msg_rx_err(ep)) {
				dev_info(&dev->dev,
					 "%d pkts recieved. Recieve deffered\n",
					 (-boguscnt + RX_RING_SIZE + 1));
			}
			break;
		}
	}
	if (list_empty(&rx_list))
		return work_done;

	/* You may want to set other cpu for napi processing to get high
	 * performance by means of command e.g for cpu 1 anf for eth4
	 * echo 1 > /proc/sys/dev/l_e1000/napi_cpu/eth4 */
	if (!cpu_online(ep->napi_cpu)) { /* it was mistaken set of napi_cpu */
		ep->napi_cpu = -1;
	}
	if (ep->napi_cpu >= 0) {
		napi_work1 = kmalloc(sizeof(napi_work_t), GFP_KERNEL);
		INIT_WORK(&napi_work1->work, napi_wq_worker);
		/* swap list head from rx_list to napi_work1->napi_list */
		rx_list.prev->next = &napi_work1->napi_list;
		rx_list.next->prev = &napi_work1->napi_list;
		napi_work1->napi_list.next = rx_list.next;
		napi_work1->napi_list.prev = rx_list.prev;
		queue_work_on(ep->napi_cpu, system_wq, &napi_work1->work);
	} else {
		netif_receive_skb_list(&rx_list);
	}
	return work_done;
}

static int e1000_start_xmit(struct sk_buff *skb, struct net_device *dev);

static void e1000_pause_sender(struct e1000_private *ep)
{
	if (!ep->dev->phydev->duplex) {
		return;
	}
	if (!do_pause_sender) {
		return;
	}
	if (!ep->skb_to_pause) {
		return;
	}
	if (ep->skb_to_pause_sent) {
		return;
	}
	e1000_start_xmit(ep->skb_to_pause, ep->dev);
}

/** The E1000 interrupt handlers. */
static irqreturn_t e1000_interrupt(int irq, void *dev_id)
{
	struct net_device *dev = dev_id;
	struct e1000_private *ep;
	u16 csr0, csr_ack;

	ep = netdev_priv(dev);
	csr0 = e1000_read_e_csr(ep);
	if (!(csr0 & INTR))
		return IRQ_NONE; /* Not our interrupt */

	csr0 &= (BABL | CERR | MISS | MERR | RINT | TINT);

	if (ep->napi_scheduled) {
		/*
		 * e1000_kick_xmit occasualy enabled interrurpts
		 * Disable it and do nothing
		 */
again_1:
		e1000_write_e_csr(ep, IDON | ep->csr_1588);
		/* Be sure it reached the card */
		if (e1000_read_e_csr(ep) & INEA) {
			goto again_1;
		}
		smp_wmb();

		if (ep->napi_scheduled) {
			/*
			 * Napi still works. It will enable interrupts
			 * when finished. Else we can continue
			 */
			return IRQ_HANDLED;
		}
	}
	/*
	 * I do it here cause I don't see a good way to sync
	 * with xmit. Here and there the work with interrupts
	 * disabled, so I hope we will work long enough
	 */
	ep->xmit_enabled_intr = 0;
	smp_wmb();

	ep->napi_wanted = 1;
	smp_wmb();

	/*  disable interrupts and ack errors*/
	csr_ack = csr0;
	e1000_write_e_csr(ep, (csr0 & ~(TINT | RINT)) | IDON | ep->csr_1588);

	if (netif_msg_intr(ep)) {
		dev_info(&dev->dev,
			 "interrupt  csr0=0x%x new csr=0x%x.\n",
			 csr0, e1000_read_e_csr(ep));
	}

	/* Log misc errors. */
	if (csr0 & BABL) {
		ep->stats.tx_errors++; /* Tx babble. */
		if (netif_msg_intr(ep)) {
			dev_info(&dev->dev,
				 "Babble (transmit timed out), status %4.4x.\n",
				 csr0);
		}
		csr0 &= ~BABL;
	}

	if (csr0 & CERR) {
		ep->stats.collisions++;
		if (netif_msg_intr(ep)) {
			dev_info(&dev->dev,
				 "CERR (collisions), status %4.4x.\n",
				 csr0);
		}
		csr0 &= ~CERR;
	}

	if (csr0 & MISS) {
		ep->stats.rx_missed_errors++; /* Missed a Rx frame. */
		if (netif_msg_intr(ep)) {
			dev_info(&dev->dev,
				 "Receiver packet missed, status %4.4x.\n",
				 csr0);
		}
		e1000_pause_sender(ep);
		csr0 &= ~MISS;

		/* The device did't set RINT in case of buffers are full
		 * and MISS is set. So we do this manually.
		 */
		csr0 |= RINT;
	}
	if (csr0 == 0) {
		ep->napi_wanted = 0;
		/* Set interrupts enabled and ack errors */
		e1000_write_e_csr(ep, csr_ack | INEA | ep->csr_1588);

		return IRQ_HANDLED;
	}

	/* Do this before napi_schedule() to notify e1000_kick_xmit() faster */
	if (ep->xmit_enabled_intr) {
again_2:
		e1000_write_e_csr(ep, ep->csr_1588);
		if (e1000_read_e_csr(ep) & INEA) {
			goto again_2;
		}
	}
	/* if napi scheduled napi_poll will ack (TINT | RINT)
	 * overwise we will get interrupt again when INEA enable
	 */
	if (!napi_reschedule(&ep->napi)) {
		ep->napi_wanted = 0;
	}

	return IRQ_HANDLED;
}

static int e1000_tx(struct net_device *dev);

static int e1000_poll(struct napi_struct *napi, int budget)
{
	struct e1000_private *ep = container_of(napi, struct e1000_private,
						napi);
	struct net_device *dev = ep->dev;
	int work_done, must_restart = 0;
	unsigned long flags;

	ep->napi_scheduled = 1;
	smp_wmb();

	ep->napi_wanted = 0;
	e1000_write_e_csr(ep, TINT | RINT | ep->csr_1588);
	/* Rx interrupt */
	work_done = e1000_rx(ep, budget);

	/* Tx interrupt */
	must_restart = e1000_tx(dev);

	if (must_restart) {
		/* reset the chip to clear the error condition, then restart */
		raw_spin_lock_irqsave(&ep->lock, flags);
		e1000_write_e_csr(ep, STOP);
		e1000_restart(dev, STRT | ep->csr_1588);
		work_done = 0;
		raw_spin_unlock_irqrestore(&ep->lock, flags);
		netif_wake_queue(dev);
	}

	if (netif_msg_intr(ep))
		dev_info(&dev->dev,
			 "exiting interrupt, csr0=%x.\n", e1000_read_e_csr(ep));

	if (work_done < budget || must_restart) {
		/*
		 * We are going to enable interrupts.
		 * Notify e1000_kick_xmit() about this.
		 */
		if (ep->napi_wanted) {
			ep->napi_wanted = 0;
			smp_wmb();
			work_done = budget;
		} else {
			ep->napi_scheduled = 0;
			smp_wmb(); /* Pairs with e1000_kick_xmit */
			napi_complete(&ep->napi);
			/* Set interrupt enable. */
			e1000_write_e_csr(ep, INEA | ep->csr_1588);
		}
	}
	return work_done;
}


/** TITLE: Net Tx stuff */

static int e1000_tx(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	unsigned int dirty_tx = ep->dirty_tx;
	int delta, must_restart = 0;
	int first_loop = 1;
	int n = 0;
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->lock, flags);
	check_tx_ring(ep, "e1000_tx begin");

	while ((dirty_tx != ep->cur_tx) || first_loop) {
		int entry = dirty_tx;
		struct e1000_tx_head *tx_ring = &ep->tx_ring[entry];
		int status = (short)le16_to_cpu(tx_ring->status);

		if (tx_ring->base == 0) {
			break;
		}
		status = (short)le16_to_cpu(tx_ring->status);
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: status = 0x%x\n", __func__, status);
		if (status < 0)
			break; /* It still hasn't been Txed */

		first_loop = 0;

		if (status & TD_ERR) {
			if (netif_msg_tx_queued(ep))
				dev_info(&dev->dev,
					 "%s: base: 0x%x;"
					 " buf_length: 0x%x;"
					 " status: 0x%x; misc: 0x%x\n",
					 __func__,
					 le32_to_cpu(tx_ring->base),
					 le16_to_cpu(tx_ring->buf_length),
					 le16_to_cpu(tx_ring->status),
					 le32_to_cpu(tx_ring->misc));
		}
		tx_ring->base = 0;
		tx_ring->status = 0;

		if (status & TD_ERR) {
			/* There was an major error, log it. */
			int err_status = le32_to_cpu(tx_ring->misc);

			if (netif_msg_tx_queued(ep))
				dev_info(&dev->dev,
					 "%s: misc = 0x%x\n",
					 __func__, err_status);

			ep->stats.tx_errors++;

			if (netif_msg_tx_err(ep))
				dev_info(&dev->dev,
					 "Tx error status=%04x"
					 " err_status=%08x\n",
					 status, err_status);

			if (err_status & TD_RTRY)
				ep->stats.tx_aborted_errors++;

			if (err_status & TD_LCAR)
#if 1
				ep->stats.tx_carrier_errors++;
#else
				ep->stats.tx_errors--;
#endif
			if (err_status & TD_LCOL)
				ep->stats.tx_window_errors++;

#ifndef DO_DXSUFLO
			if (err_status & TD_UFLO) {
				ep->stats.tx_fifo_errors++;
				/*
				 * Ackk!
				 * On FIFO errors the Tx unit is turned off!
				 */
				/* Remove this verbosity later! */
				if (netif_msg_tx_err(ep))
					dev_err(&dev->dev, "Tx UFLO error!\n");
				must_restart = 1;
			}
#else /* DO_DXSUFLO */
			if (err_status & TD_UFLO) {
				ep->stats.tx_fifo_errors++;
				if (!ep->dxsuflo) {
					/* If controller doesn't recover ... */
					/* Ack!
					 * On FIFO errors the Tx unit is
					 * turned off!
					 */
					/* Remove this verbosity later! */
					if (netif_msg_tx_err(ep))
						dev_err(&dev->dev,
							"Tx UFLO error! "
							"CSR0=%4.4x\n", csr0);
					must_restart = 1;
				}
			}
#endif /* DO_DXSUFLO */
		} else {
			if (status & (TD_MORE|TD_ONE))
				ep->stats.collisions++;
		}

		/* We must free the original skb */
		if (ep->tx_skbuff[entry]) {
			dma_addr_t dmaaddr = ep->tx_dma_addr[entry];
			struct sk_buff *skb = ep->tx_skbuff[entry];

			if (ep->csr_1588) {
				u32 et = le32_to_cpu(ep->tx_ring[entry].etmr);
				l_e1000_hwtstamp(ep, skb, et);
				if (max_min_tstmp[MAX_TX_TSMP] < et)
					max_min_tstmp[MAX_TX_TSMP] = et;
				if (max_min_tstmp[MIN_TX_TSMP] >
				    (et - max_min_tstmp[LST_TX_TSMP]) &&
				    et !=  max_min_tstmp[LST_TX_TSMP]) {
					max_min_tstmp[MIN_TX_TSMP] =
						et - max_min_tstmp[LST_TX_TSMP];
				}
				max_min_tstmp[PRV_TX_TSMP] =
						max_min_tstmp[LST_TX_TSMP];
				max_min_tstmp[LST_TX_TSMP] = et;
			}
			if (netif_msg_1588(ep)) {
				u32 et = le32_to_cpu(ep->tx_ring[entry].etmr);

				if (et == 0 || tx_prev_etmr > et) {
					dev_warn(&dev->dev,
						 "cs=%7x Tx= 0x%8x prv= 0x%8x"
						 " maxt %8x r %8x c=%16lu\n",
						 ep->csr_1588,
						 et,
						 tx_prev_etmr,
						 max_min_tstmp[MAX_TX_TSMP],
						 max_min_tstmp[MAX_RX_TSMP],
						 get_cycles());
				}
				tx_prev_etmr = et;
			}
			dirty_tx = (dirty_tx + 1) & TX_RING_MOD_MASK;
			ep->dirty_tx = dirty_tx;
			ep->tx_skbuff[entry] = NULL;
			ep->tx_dma_addr[entry] = 0;
			raw_spin_unlock_irqrestore(&ep->lock, flags);
			
			if (skb == ep->skb_to_pause) {
				ep->skb_to_pause_sent = 0;
			} else {
				if (dmaaddr) { 
					pci_unmap_single(ep->pci_dev, dmaaddr,
							 skb->len,
							 PCI_DMA_TODEVICE);
				}
				dev_kfree_skb_any(skb);
			}
			raw_spin_lock_irqsave(&ep->lock, flags);
			check_tx_ring(ep, "e1000_tx middle");
			dirty_tx = ep->dirty_tx;
		} else {
			dirty_tx = (dirty_tx + 1) & TX_RING_MOD_MASK;
		}
		n++;
	}

	delta = (ep->cur_tx - dirty_tx) & (TX_RING_MOD_MASK);

	if (ep->tx_full && netif_queue_stopped(dev) &&
	    delta < TX_RING_SIZE - TX_HISTERESIS) {
		/* The ring is no longer full, clear tbusy. */
		if (ep->tx_ring[ep->cur_tx].base) {
			goto no_unqueue;
		}
		ep->tx_full = 0;
		netif_wake_queue(dev);
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "transmitter was unqueueed "
				 "cur_tx = %d, dirty_tx = %d\n",
				 ep->cur_tx, ep->dirty_tx);
	}

no_unqueue:
	check_tx_ring(ep, "e1000_tx end");
	raw_spin_unlock_irqrestore(&ep->lock, flags);

	return must_restart;
}

static void try_to_cleanup_tx_bufs(struct e1000_private *ep)
{
	int dirty_tx = ep->dirty_tx;
	int num = 0;
	int first_loop = 1;

	while (dirty_tx != ep->cur_tx || first_loop) {
		int status;
		if (num >= num_tx_bufs_to_clean) {
			break;
		}
		if (ep->tx_ring[dirty_tx].base == 0) {
			if (netif_msg_tx_done(ep))
				dev_info(&ep->dev->dev,
					 "%s: base == 0 on first loop ?"
					 " cur = %d, dirty = %d\n",
					 __func__, ep->cur_tx, ep->dirty_tx);
			break;
		}
		status = (short)le16_to_cpu(ep->tx_ring[dirty_tx].status);
		if (status < 0) {
			break; /* It still hasn't been Txed */
		}
		if (status & TD_ERR) {
			break;
		}
		first_loop = 0;
		ep->tx_ring[dirty_tx].base = 0;
		ep->tx_ring[dirty_tx].status = 0;

		if (status & (TD_MORE|TD_ONE))
			ep->stats.collisions++;

		num++;
		/* We must free the original skb */
		if (ep->tx_skbuff[dirty_tx]) {
			dma_addr_t dmaaddr = ep->tx_dma_addr[dirty_tx];
			struct sk_buff *skb = ep->tx_skbuff[dirty_tx];

			ep->tx_skbuff[dirty_tx] = NULL;
			ep->tx_dma_addr[dirty_tx] = 0;
			if (skb != ep->skb_to_pause) {
#ifdef CAN_UNMAP_SKB_IN_CONSUME
				skb->dmaaddr = dmaaddr;
				skb->pci_dev = ep->pci_dev;
#else /* !CAN_UNMAP_SKB_IN_CONSUME */
				if (dmaaddr) {
					pci_unmap_single(ep->pci_dev,
							 dmaaddr,
							 skb->len,
							 PCI_DMA_TODEVICE);
				}
#endif /* CAN_UNMAP_SKB_IN_CONSUME */
				dev_kfree_skb_irq(skb);
			} else {
				ep->skb_to_pause_sent = 0;
			}
		}
		dirty_tx = (dirty_tx + 1) & (TX_RING_MOD_MASK);
	}
	ep->dirty_tx = dirty_tx;

	if (netif_msg_tx_done(ep))
		dev_info(&ep->dev->dev, "%s: %d bufs cleaned\n", __func__, num);
}

/* The aim of this function is
 * 1)to write TDMD into csr0
 * 2) and not to change INEA state.
 *
 * This is not always possible. Sometimes we may unnecessary
 * enable INEA when it has to be turned off. This gives an
 * excess interrupt.
 */
static void e1000_kick_xmit(struct e1000_private *ep)
{
	if (ep->napi_wanted || ep->napi_scheduled) {
		/* Pairs with smp_wmb() in e1000_poll() and e1000_interrupt() */
		smp_rmb();

		e1000_write_e_csr(ep, TDMD | ep->csr_1588);

		/* Check it again */
		if (!ep->napi_scheduled && !ep->napi_wanted) {
			/* Pairs with smp_wmb() in e1000_poll()
			 * and e1000_interrupt()
			 */
			ep->xmit_enabled_intr = 1;
			smp_rmb();

			e1000_write_e_csr(ep, INEA | ep->csr_1588);
		}
	} else {
		ep->xmit_enabled_intr = 1;
		e1000_write_e_csr(ep, TDMD|INEA | ep->csr_1588);
	}
}


/** TITLE: Netdev stuff */

static int e1000_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	s16 status;
	int entry;
	unsigned long flags;
	void *packet;
	struct ethhdr *eth;
	int i;
	int len;
	dma_addr_t dmaaddr;

	if (netif_queue_stopped(dev))
		return NETDEV_TX_BUSY;

	if (skb->len < ETH_ZLEN) {
		if (skb_padto(skb, ETH_ZLEN)) {
			/* there is not much, we can do at this point */
			if (netif_msg_tx_err(ep))
				dev_err(&dev->dev,
					"%s: skb_padto failed.\n", __func__);
			return NETDEV_TX_BUSY;
		}
		skb->len = ETH_ZLEN;
	}
	len = skb->len;
	/* we map it here out from raw_spinlock because mapping locks mutex */
	if (skb == ep->skb_to_pause) {
		dmaaddr = ep->skb_to_pause_dma;
	} else if (len > SMALL_PKT_SZ) {
		dmaaddr = pci_map_single(ep->pci_dev, skb->data, len,
					 PCI_DMA_TODEVICE);
		if (pci_dma_mapping_error(ep->pci_dev, dmaaddr))
			return NETDEV_TX_BUSY;
	} else {
		dmaaddr = 0;
	}

	raw_spin_lock_irqsave(&ep->lock, flags);

	check_tx_ring(ep, "start_xmit begin");

	/* Mask to ring buffer boundary. */
	entry = ep->cur_tx;

	if (skb == ep->skb_to_pause) {
		if (ep->tx_ring[entry].base != 0 ||
		    ep->tx_ring[(entry + 1) & TX_RING_MOD_MASK].base != 0) {
			try_to_cleanup_tx_bufs(ep);
		}
		if (ep->tx_ring[entry].base != 0 ||
		    ep->tx_ring[(entry + 1) & TX_RING_MOD_MASK].base != 0) {
			/* we need at least 2 free tx descs - one for us
			 * and 1 for possible general pkt
			 */

			raw_spin_unlock_irqrestore(&ep->lock, flags);

			if (netif_msg_tx_err(ep)) {
				dev_err(&dev->dev,
					"Could not send pause packet"
					" to sender\n");
			}
			return -1;
		}
		if (netif_msg_tx_done(ep)) {
			dev_info(&dev->dev, "Send pause packet to sender\n");
		}
	}

	/* Default status -- will not enable Successful-TxDone
	 * interrupt when that option is available to us.
	 */
	status = TX_ST_OWN | TX_ST_ENP | TX_ST_STP;

	/* Fill in a Tx ring entry */

	/* Mask to ring buffer boundary. */

	/* Caution: the write order is important here, set the status
	 * with the "ownership" bits last.
	 */

	if (CAN_DISABLE_TXINT(ep) && ep->tx_coal_frame) {
		unsigned int num_dirties = (ep->cur_tx - ep->last_tx_intr) &
					   TX_RING_MOD_MASK;
		if (((num_dirties == ep->tx_coal_frame) ||
		    skb == ep->skb_to_pause)) {
			ep->last_tx_intr = ep->cur_tx;
		} else {
			status |= TX_ST_NOINTR;
		}
	}

	ep->tx_ring[entry].buf_length = cpu_to_le16(-len);
	ep->tx_ring[entry].misc = 0x00000000;
	ep->tx_skbuff[entry] = skb;

	if (dmaaddr) {
		ep->tx_dma_addr[entry] = dmaaddr;
		ep->tx_ring[entry].base =
				cpu_to_le32((u32)(ep->tx_dma_addr[entry]));
	} else {
		ep->tx_dma_addr[entry] = 0;
		ep->tx_ring[entry].base = cpu_to_le32((u32)(ep->smpkts_dma +
							SMALL_PKT_SZ * entry));
		memcpy(ep->smpkts_area + SMALL_PKT_SZ * entry, skb->data, len);
	}
	wmb(); /* Make sure owner changes after all others are visible */

	ep->tx_ring[entry].status = cpu_to_le16(status);
	ep->cur_tx = (ep->cur_tx + 1) & TX_RING_MOD_MASK;
	ep->stats.tx_bytes += len;
	ep->stats.tx_packets++;

	if (netif_msg_tx_queued(ep))
		dev_info(&dev->dev,
			 "%s: base: 0x%x; buf_length: 0x%x [0x%x]"
			 " status: 0x%x; misc: 0x%x\n", __func__,
			 le32_to_cpu(ep->tx_ring[entry].base),
			 le16_to_cpu(ep->tx_ring[entry].buf_length),
			 len,
			 le16_to_cpu(ep->tx_ring[entry].status),
			 le32_to_cpu(ep->tx_ring[entry].misc));

	packet = (void *) ep->tx_skbuff[entry]->data;
	eth = (struct ethhdr *) packet;
	if (netif_msg_pktdata(ep)) {
		for (i = 0; i != 6; i++){
			dev_info(&dev->dev,"%s: src 0x%x, dst 0x%x\n",
				 __func__, eth->h_source[i], eth->h_dest[i]);
		}
		for (i = 0; i != ((len) / 4); i++){
			dev_info(&dev->dev, "TX packet: int # %d  0x%x \n",
				 i, *(u32 *)packet);
			packet += 4;
		}
		for (i = 0; i != ((len) % 4); i++){
			dev_info(&dev->dev, "TX packet: byte # %d  0x%x \n",
				 i, *(u8 *)packet);
			packet += 1;
		}
	}	

	/* Trigger an immediate send poll. */
	e1000_kick_xmit(ep);

	netif_trans_update(dev);
	if (ep->tx_ring[ep->cur_tx].base != 0) {
		check_tx_ring(ep, "xmit tries to clean");
		try_to_cleanup_tx_bufs(ep);
		check_tx_ring(ep, "xmit  after clean");
	}
	if (ep->tx_ring[ep->cur_tx].base != 0) {
		if (netif_msg_tx_err(ep)) {
			dev_warn(&dev->dev,
				 "transmitter queue is full "
				 "cur_tx = %d, dirty_tx =%d\n",
				 ep->cur_tx, ep->dirty_tx);
		}
		ep->tx_full = 1;
		netif_stop_queue(dev);
	} else if (ep->tx_full && netif_queue_stopped(dev) &&
		   ((ep->cur_tx - ep->dirty_tx) & (TX_RING_MOD_MASK)) <
					(TX_RING_SIZE - TX_HISTERESIS)) {
		/* The ring is no longer full, clear tbusy. */
		ep->tx_full = 0;
		netif_wake_queue (dev);
		if (netif_msg_tx_err(ep)) {
			dev_err(&dev->dev,
				"transmitter was unqueueed from xmit"
				"cur_tx= %d, dirty_tx= %d\n",
				ep->cur_tx, ep->dirty_tx);
		}
	}
	check_tx_ring(ep, "end_xmit begin");

	raw_spin_unlock_irqrestore(&ep->lock, flags);

	return NETDEV_TX_OK;
}

static int e1000_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct e1000_private *ep = netdev_priv(dev);
	int rc = 0;
	struct hwtstamp_config config;

	switch (cmd) {
	case SIOCDEVPRIVATE + 10:
		dev_warn(&dev->dev, "napi_scheduled = %d\n",
			 ep->napi_scheduled);
		dev_warn(&dev->dev, "xmit_enabled_intr = %d\n",
			 ep->xmit_enabled_intr);
		dev_warn(&dev->dev, "napi state = 0x%lx\n", ep->napi.state);
		dump_init_block(ep);
		dump_ring_state(ep);
		break;
	case SIOCDEVPRIVATE + 11:
		return copy_to_user(rq->ifr_data, max_min_tstmp,
				    sizeof(max_min_tstmp)) ? -EFAULT : 0;
	case SIOCDEVPRIVATE + 12:
		{
			int i;

			for (i = 0; i < 8; i++)
				max_min_tstmp[i] = 0;

			max_min_tstmp[MIN_TX_TSMP] = 0xffffffff;
			max_min_tstmp[MIN_RX_TSMP] = 0xffffffff;
			return 0;
		}
	case SIOCGHWTSTAMP:
		return copy_to_user(rq->ifr_data, &config,
				    sizeof(config)) ? -EFAULT : 0;
	case SIOCSHWTSTAMP:
		if (copy_from_user(&config, rq->ifr_data, sizeof(config)))
			return -EFAULT;

		ep->hwtstamp_config = config;
		if (ep->pci_dev->device != PCI_DEVICE_ID_MCST_ETH) {
			dev_err(&dev->dev,
				"SIOCSHWTSTAMP is not supported. Devid=0x%x\n",
				ep->pci_dev->device);
			return -EOPNOTSUPP;
		}
		if (config.rx_filter == HWTSTAMP_FILTER_NONE) {
			ep->csr_1588 = 0;
		} else {
			ep->csr_1588 = ATME | TMCE;
		}
		config = ep->hwtstamp_config;

		switch (config.rx_filter) {
		case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
		case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
		case HWTSTAMP_FILTER_PTP_V2_SYNC:
		case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
		case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
		case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		/* With V2 type filters which specify a Sync or Delay Request,
		 * Path Delay Request/Response messages are also time stamped
		 * by hardware so notify the caller the requested packets plus
		 * some others are time stamped.
		 */
			config.rx_filter = HWTSTAMP_FILTER_SOME;
			break;
		default:
			break;
		}
		return copy_to_user(rq->ifr_data, &config,
				    sizeof(config)) ? -EFAULT : 0;
	default:
		/* SIOC[GS]MIIxxx ioctls */
		if (!dev->phydev) {
			dev_warn_once(&dev->dev, "phydev not init\n");
			rc = -EINVAL;
		} else {
			rc = phy_mii_ioctl(dev->phydev, rq, cmd);
		}
	}
	return rc;
}

/* Set or clear the multicast filter for this adaptor. */
static void e1000_set_multicast_list(struct net_device *dev)
{
	unsigned long flags;
	struct e1000_private *ep = netdev_priv(dev);

	raw_spin_lock_irqsave(&ep->lock, flags);

	if (dev->flags & IFF_PROMISC) {
		/* Log any net taps. */
		if (netif_msg_drv(ep))
			dev_info(&dev->dev, "Promiscuous mode enabled.\n");
		ep->init_block->mode |= cpu_to_le16(PROM);
	} else {
		ep->init_block->mode &= ~cpu_to_le16(PROM);
		e1000_load_multicast(dev);
	}

	e1000_write_e_csr(ep, STOP); /* Temporarily stop the lance. */
	e1000_restart(dev, (INEA|STRT | ep->csr_1588)); /* Resume normal op. */
	netif_wake_queue(dev);

	raw_spin_unlock_irqrestore(&ep->lock, flags);
}

static void e1000_tx_timeout (struct net_device *dev, unsigned int txqueue)
{
	struct e1000_private *ep = netdev_priv(dev);
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->lock, flags);

	/* Transmitter timeout, serious problems. */
	if (netif_msg_tx_err(ep)) {
		dev_warn(&dev->dev,
			 "transmit timed out, status %4.4x, resetting.\n",
			 e1000_read_e_csr(ep));
		dump_init_block(ep);
		dump_ring_state(ep);
	}
	e1000_write_e_csr(ep, STOP);
	ep->stats.tx_errors++;
	if (netif_msg_tx_err(ep)) {
		dump_ring_state(ep);
	}

	e1000_restart(dev, INEA|STRT | ep->csr_1588);

	netif_trans_update(dev);
	netif_wake_queue(dev);

	raw_spin_unlock_irqrestore(&ep->lock, flags);
}

static struct net_device_stats *e1000_get_stats(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);

	return &ep->stats;
}

static int e1000_change_mtu(struct net_device *dev, int new_mtu)
{
	if ((new_mtu < (ETH_ZLEN - ETH_HLEN)) || (new_mtu > E100_MAX_DATA_LEN))
		return -EINVAL;

	dev->mtu = new_mtu;
	return 0;
}

static int e1000_open(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	int rc, i;
	unsigned int init_block_addr_part = 0;
	unsigned long irqflags = IRQF_NO_THREAD |
				 (ep->shared_irq ? IRQF_SHARED : 0);

	netif_carrier_off(dev);
	if (netif_msg_ifup(ep))
		dev_info(&dev->dev, "%s: begin\n", __func__);

	/* Reset the PCNET32 */
	e1000_write_e_csr(ep, STOP);

	/* wait for stop */
	for (i=0; i<1000; i++)
		if (e1000_read_e_csr(ep) & STOP)
			break;
	if (i >= 100 && netif_msg_drv(ep)) {
		dev_err(&dev->dev,
			"%s timed out waiting for stop.\n", __func__);
		return -EAGAIN;
	}

	/* PHY connect */
	rc = e1000_phy_connect(ep);
	if (rc) {
		dev_err(&dev->dev, "phy_connect error.\n");
		return -EAGAIN;
	}

	napi_enable(&ep->napi);

	/* No harm to request irq so early. Card stopped */
	if (ep->msix_entries) {
		/* MSIX supported */
		ep->irq = ep->msix_entries[ep->bar].vector;
		if (netif_msg_intr(ep))
			dev_info(&dev->dev,
				 "%s: uses MSIX irq %d\n", __func__, ep->irq);
	} else {
		ep->irq = ep->pci_dev->irq;
		if (netif_msg_intr(ep))
			dev_info(&dev->dev,
				 "%s: uses PCI irq %d\n", __func__, ep->irq);
	}
	rc = request_irq(ep->irq, &e1000_interrupt, irqflags,
			 dev->name, (void *)dev);
	if (rc) {
		napi_disable(&ep->napi);
		dev_err(&dev->dev, "Could not request irq %d\n", dev->irq);
		goto err_phy_dis;
	}

	/* Check for a valid station address */
	if (!is_valid_ether_addr(dev->dev_addr)) {
		rc = -EINVAL;
		dev_err(&dev->dev, "Invalid ethernet address\n");
		goto err_free_irq;
	}

	ep->init_block->mode = le16_to_cpu(e1000_mode);
	ep->init_block->laddrf = 0UL;

	if (netif_msg_ifup(ep))
		dev_info(&dev->dev,
			 "%s: irq %u tx/rx rings %#llx/%#llx init %#llx.\n",
			 __func__, dev->irq,
			 (u64)(ep->dma_addr +
				offsetof(struct e1000_dma_area, tx_ring)),
			 (u64)(ep->dma_addr +
				offsetof(struct e1000_dma_area, rx_ring)),
			 (u64)(ep->dma_addr +
				offsetof(struct e1000_dma_area, init_block)));

	e1000_load_multicast(dev);
	/* Re-initialize the PCNET32, and start it when done. */
	/* low 32 bits */
	init_block_addr_part = (ep->dma_addr +
			offsetof(struct e1000_dma_area, init_block))
			& 0xffffffff;
	e1000_write_e_base_address(ep, init_block_addr_part);
	/* high 32 bits */
	init_block_addr_part = ((u64)(ep->dma_addr +
			offsetof(struct e1000_dma_area, init_block)) >> 32)
			& 0xffffffff; 
	e1000_write_dma_base_address(ep, init_block_addr_part);

	/** PHY start */
	e1000_init_phy(ep);

	/* start e1000 */
	if (e1000_restart(dev, INEA|STRT)) {
		rc = -ENOMEM;
		goto err_free_ring;
	}

	netif_carrier_on(dev);

	if (netif_msg_ifup(ep))
		dev_info(&dev->dev, "%s: ok\n", __func__);

	return 0;

err_free_ring:
	/** PHY stop */
	phy_stop(dev->phydev);
	/* free any allocated skbuffs */
	for (i = 0; i < RX_RING_SIZE; i++) {
		ep->rx_ring[i].status = 0;
		if (ep->rx_skbuff[i]) {
			pci_unmap_single(ep->pci_dev, ep->rx_dma_addr[i],
					 (PKT_BUF_SZ + CRC_SZ),
					 PCI_DMA_FROMDEVICE);
			dev_kfree_skb(ep->rx_skbuff[i]);
		}
		ep->rx_skbuff[i] = NULL;
		ep->rx_dma_addr[i] = 0;
	}
err_free_irq:
	free_irq(ep->irq, dev);
	napi_disable(&ep->napi);
err_phy_dis:
	/** PHY release */
	phy_disconnect(dev->phydev);
	dev->phydev = NULL;

	if (netif_msg_ifup(ep))
		dev_err(&dev->dev, "%s: end badly, rc = %d\n", __func__, rc);
	return rc;
}

static int e1000_close(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	int i;

	netif_carrier_off(dev);

	if (netif_msg_ifdown(ep))
		dev_info(&dev->dev,
			 "Shutting down ethercard, status was %2.2x.\n",
			 e1000_read_e_csr(ep));

	/** PHY stop */
	if (dev->phydev) {
		phy_stop(dev->phydev);
		phy_disconnect(dev->phydev);
		dev->phydev = NULL;
	}

	napi_disable(&ep->napi);
	netif_stop_queue(dev);

	/* We stop the PCNET32 here - it occasionally polls memory
	 * if we don't.
	 */
	e1000_write_e_csr(ep, STOP);

	irq_set_affinity_hint(ep->irq, NULL);
	free_irq(ep->irq, dev);

	/* free all allocated skbuffs */
	for (i = 0; i < RX_RING_SIZE; i++) {
		ep->rx_ring[i].status = 0;
		ep->rx_ring[i].base = 0;
		wmb(); /* Make sure adapter sees owner change */

		if (ep->rx_skbuff[i]) {
			pci_unmap_single(ep->pci_dev,
					 ep->rx_dma_addr[i],
					 (PKT_BUF_SZ + CRC_SZ),
					 PCI_DMA_FROMDEVICE);
			dev_kfree_skb(ep->rx_skbuff[i]);
		}

		ep->rx_skbuff[i] = NULL;
		ep->rx_dma_addr[i] = 0;
	}

	for (i = 0; i < TX_RING_SIZE; i++) {
		ep->tx_ring[i].status = 0; /* CPU owns buffer */
		ep->tx_ring[i].base = 0;
		wmb(); /* Make sure adapter sees owner change */

		if (ep->tx_skbuff[i]) {
			if (ep->tx_dma_addr[i]) {
				pci_unmap_single(ep->pci_dev,
						 ep->tx_dma_addr[i],
						 ep->tx_skbuff[i]->len,
						 PCI_DMA_TODEVICE);
			}
			dev_kfree_skb(ep->tx_skbuff[i]);
		}

		ep->tx_skbuff[i] = NULL;
		ep->tx_dma_addr[i] = 0;
	}

	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void e1000_poll_controller(struct net_device *netdev)
{
	struct e1000_private *ep = netdev_priv(netdev);

	(void) e1000_interrupt(ep->irq, netdev);
}
#endif /* CONFIG_NET_POLL_CONTROLLER */

static const struct net_device_ops e1000_netdev_ops = {
	.ndo_start_xmit		= e1000_start_xmit,
	.ndo_do_ioctl		= e1000_ioctl,
	.ndo_set_rx_mode	= e1000_set_multicast_list,
	.ndo_tx_timeout		= e1000_tx_timeout,
	.ndo_get_stats		= e1000_get_stats,
	.ndo_change_mtu		= e1000_change_mtu,
	.ndo_set_mac_address	= eth_mac_addr,
	.ndo_open		= e1000_open,
	.ndo_stop		= e1000_close,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= e1000_poll_controller,
#endif /* CONFIG_NET_POLL_CONTROLLER */
};


/** TITLE: Ethtool stuff */

static int e1000_get_link_ksettings(struct net_device *dev,
				    struct ethtool_link_ksettings *cmd)
{
	struct e1000_private *ep = netdev_priv(dev);

	if (!dev->phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return -ENODEV;
	}

	phy_ethtool_ksettings_get(dev->phydev, cmd);
	return 0;
}

static int e1000_set_link_ksettings(struct net_device *dev,
				    const struct ethtool_link_ksettings *cmd)
{
	struct e1000_private *ep = netdev_priv(dev);
	int r = -EOPNOTSUPP;

	if (!dev->phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return -ENODEV;
	}

	r = phy_ethtool_ksettings_set(dev->phydev, cmd);
	if (r == 0)
		e1000_set_mac_phymode(dev);

	return r;
}

static void e1000_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *info)
{
	struct e1000_private *ep = netdev_priv(dev);

	strcpy(info->driver, KBUILD_MODNAME);
	strcpy(info->version, DRV_VERSION);
	if (ep->pci_dev)
		strcpy(info->bus_info, pci_name(ep->pci_dev));
	else
		sprintf(info->bus_info, "VLB 0x%lx", dev->base_addr);
}

static u32 e1000_get_msglevel(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);

	return ep->msg_enable;
}

static void e1000_set_msglevel(struct net_device *dev, u32 value)
{
	struct e1000_private *ep = netdev_priv(dev);

	ep->msg_enable = value;
}

static int e1000_nway_reset(struct net_device *dev)
{
	return phy_ethtool_nway_reset(dev);
}

static u32 e1000_get_link(struct net_device *dev)
{
	if (dev->phydev)
		return dev->phydev->link;
	else
		return 0;
}

static void e1000_get_ringparam(struct net_device *dev,
				struct ethtool_ringparam *ering)
{
	struct e1000_private *ep = netdev_priv(dev);

	ering->tx_max_pending = TX_RING_SIZE - 1;
	ering->tx_pending = (ep->cur_tx - ep->dirty_tx) & TX_RING_MOD_MASK;
	ering->rx_max_pending = RX_RING_SIZE - 1;
	ering->rx_pending = ep->cur_rx & RX_RING_MOD_MASK;
}

static void e1000_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	memcpy(data, e1000_gstrings_test, sizeof(e1000_gstrings_test));
}

#define E1000_NUM_REGS ((8 * sizeof(u32)) + (32 * sizeof(u16)))
static int e1000_get_regs_len(struct net_device *dev)
{
	return E1000_NUM_REGS;
}

static void e1000_get_regs(struct net_device *dev, struct ethtool_regs *regs,
			   void *ptr)
{
	int i;
	u32 *buff = ptr;
	u16 *mii_buff = NULL;
	struct e1000_private *ep = netdev_priv(dev);

	/* read e1000 registers */
	*buff++ = e1000_read_e_csr(ep);
	*buff++ = e1000_read_mgio_csr(ep);
	*buff++ = e1000_read_mgio_data(ep);
	*buff++ = e1000_read_e_base_address(ep);
	*buff++ = e1000_read_dma_base_address(ep);
	*buff++ = e1000_read_psf_csr(ep);
	*buff++ = e1000_read_psf_data(ep);
	*buff++ = 0xAAAAAAAA;

	/* read mii phy registers */
	mii_buff = (u16 *)buff;
	for (i = 0; i < 32; i++) {
		*mii_buff++ = mdiobus_read(ep->mii_bus, ep->phyaddr, i);
	}

	i = mii_buff - (u16 *)ptr;
	for (; i < E1000_NUM_REGS; i++)
		*mii_buff++ = 0x5555;
}

static int e1000_get_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *ec)
{
	struct e1000_private *ep = netdev_priv(dev);

	memset(ec, 0, sizeof(*ec));
	if (CAN_DISABLE_TXINT(ep)) {
		ec->tx_max_coalesced_frames = ep->tx_coal_frame;
	}
	if (l_e1000_supports_coalesce(ep)) {
		__u32 r = readl(ep->base_ioaddr + INT_DELAY); 
		ec->tx_coalesce_usecs = (r & 0xFFFF) / 125;
		ec->rx_coalesce_usecs = (r >> 16) / 125;
	}
	return 0;
}

static int e1000_set_coalesce(struct net_device *dev,
			      struct ethtool_coalesce *ec)
{
	struct e1000_private *ep = netdev_priv(dev);

	if ((ec->tx_max_coalesced_frames > MAX_TX_COAL_FRAMES) ||
	    (ec->tx_coalesce_usecs > MAX_COAL_USEC) ||
	    (ec->rx_coalesce_usecs > MAX_COAL_USEC)) {
		return -EINVAL;
	}
	if (CAN_DISABLE_TXINT(ep)) {
		ep->tx_coal_frame = ec->tx_max_coalesced_frames;
	}
	if (l_e1000_supports_coalesce(ep)) {
		__u32 r = (ec->tx_coalesce_usecs * 125) |
			 ((ec->rx_coalesce_usecs * 125) << 16);
		writel(r, ep->base_ioaddr + INT_DELAY);
		ep->txrx_delay = r;
	}
	return 0;
}

static int e1000_get_ts_info(struct net_device *dev,
			     struct ethtool_ts_info *info)
{
	struct e1000_private *ep = netdev_priv(dev);

	if (ep->pci_dev->device != PCI_DEVICE_ID_MCST_ETH) {
		if (netif_msg_drv(ep)) {
			netdev_err(dev, "so_timestamping is not supported for"
					" devid=0x%x\n", ep->pci_dev->device);
		}
		return -EINVAL;
	}

	ethtool_op_get_ts_info(dev, info);

	info->so_timestamping |= (SOF_TIMESTAMPING_TX_HARDWARE |
				  SOF_TIMESTAMPING_RX_HARDWARE |
				  SOF_TIMESTAMPING_RAW_HARDWARE);

	info->tx_types = (1 << HWTSTAMP_TX_OFF) | (1 << HWTSTAMP_TX_ON);
	info->rx_filters = ((1 << HWTSTAMP_FILTER_NONE) |
			    (1 << HWTSTAMP_FILTER_PTP_V1_L4_SYNC) |
			    (1 << HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_L2_SYNC) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_EVENT) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_SYNC) |
			    (1 << HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
			    (1 << HWTSTAMP_FILTER_ALL));

	if (ep->ptp_clock)
		info->phc_index = ptp_clock_index(ep->ptp_clock);

	return 0;
}

static struct ethtool_ops e1000_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_RX_USECS,
	.get_link_ksettings	= e1000_get_link_ksettings,
	.set_link_ksettings	= e1000_set_link_ksettings,
	.get_drvinfo		= e1000_get_drvinfo,
	.get_msglevel		= e1000_get_msglevel,
	.set_msglevel		= e1000_set_msglevel,
	.nway_reset		= e1000_nway_reset,
	.get_link		= e1000_get_link,
	.get_ringparam		= e1000_get_ringparam,
	.get_strings		= e1000_get_strings,
	.get_regs_len		= e1000_get_regs_len,
	.get_regs		= e1000_get_regs,
	.get_coalesce		= e1000_get_coalesce,
	.set_coalesce		= e1000_set_coalesce,
	.get_ts_info		= e1000_get_ts_info,
};


/** TITLE: DEBUG_FS stuff */

#ifdef CONFIG_DEBUG_FS
/* Usage: mount -t debugfs none /sys/kernel/debug */

/* /sys/kernel/debug/l_e1000/ */
static struct dentry *l_e1000_dbg_root = NULL;

/** /sys/kernel/debug/l_e1000/<pcidev>/REG_GETH */

#define DPREG_GETH(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%02X: %08X - %s\n", \
		(R), readl(ep->base_ioaddr + (R)), (N)); \
} while (0)

static char l_e1000_dbg_reg_geth_buf[PAGE_SIZE] = "";

const u_int32_t l_e1000_dbg_reg_id_geth[8] = {
	E_CSR,
	MGIO_CSR,
	MGIO_DATA,
	E_BASE_ADDR,
	DMA_BASE_ADDR,
	PSF_CSR,
	PSF_DATA,
	INT_DELAY,
};
const char *l_e1000_dbg_reg_name_geth[8] = {
	"E_CSR: Ethernet Control/Status Register",
	"MGIO_CSR: MGIO Control/Status Register",
	"MGIO_DATA: MGIO Data Register",
	"E_BASE_ADDR: Ethernet Base Address Register",
	"DMA_BASE_ADDR: DMA Base Address Register",
	"PSF_CSR: Pause Frame Control/Status Register",
	"PSF_DATA: Pause Frame Data Register",
	"INT_DELAY: Interrupt Delay Register",
};

static ssize_t l_e1000_dbg_reg_geth_read(struct file *filp, char __user *buffer,
					 size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct e1000_private *ep = filp->private_data;
	char *buf = l_e1000_dbg_reg_geth_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - GETH registers dump (hex) =\n",
			  ep->dev->name, pci_name(ep->pci_dev));

	for (i = 0; i < ARRAY_SIZE(l_e1000_dbg_reg_id_geth); i++) {
		DPREG_GETH(l_e1000_dbg_reg_id_geth[i],
			   l_e1000_dbg_reg_name_geth[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* l_e1000_dbg_reg_geth_read */

static const struct file_operations l_e1000_dbg_reg_geth_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = l_e1000_dbg_reg_geth_read,
};

/** /sys/kernel/debug/l_e1000/<pcidev>/REG_PHY_IEEE */

#define DPREG_PHY(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%04X: %04X - %s\n", \
		(R), mdiobus_read(ep->mii_bus, ep->phyaddr, (R)), (N)); \
} while (0)

static char l_e1000_dbg_reg_phy_buf[PAGE_SIZE] = "";

const u_int32_t l_e1000_dbg_reg_id_phy[23] = {
	MII_BMCR,
	MII_BMSR,
	MII_PHYSID1,
	MII_PHYSID2,
	MII_ADVERTISE,
	MII_LPA,
	MII_EXPANSION,
	MII_CTRL1000,
	MII_STAT1000,
	MII_MMD_CTRL,
	MII_MMD_DATA,
	MII_ESTATUS,
	MII_DCOUNTER,
	MII_FCSCOUNTER,
	MII_NWAYTEST,
	MII_RERRCOUNTER,
	MII_SREVISION,
	MII_RESV1,
	MII_LBRERROR,
	MII_PHYADDR,
	MII_RESV2,
	MII_TPISTATUS,
	MII_NCONFIG,
};
const char *l_e1000_dbg_reg_name_phy[23] = {
	"MII_BMCR: Basic mode control register",
	"MII_BMSR: Basic mode status register",
	"MII_PHYSID1: PHYS ID 1",
	"MII_PHYSID2: PHYS ID 2",
	"MII_ADVERTISE: Advertisement control reg",
	"MII_LPA: Link partner ability reg",
	"MII_EXPANSION: Expansion register",
	"MII_CTRL1000: 1000BASE-T control",
	"MII_STAT1000: 1000BASE-T status",
	"MII_MMD_CTRL: MMD Access Control Register",
	"MII_MMD_DATA: MMD Access Data Register",
	"MII_ESTATUS: Extended Status",
	"MII_DCOUNTER: Disconnect counter",
	"MII_FCSCOUNTER: False carrier counter",
	"MII_NWAYTEST: N-way auto-neg test reg",
	"MII_RERRCOUNTER: Receive error counter",
	"MII_SREVISION: Silicon revision",
	"MII_RESV1: Reserved...",
	"MII_LBRERROR: Lpback, rx, bypass error",
	"MII_PHYADDR: PHY address",
	"MII_RESV2: Reserved...",
	"MII_TPISTATUS: TPI status for 10mbps",
	"MII_NCONFIG: Network interface config",
};

static ssize_t l_e1000_dbg_reg_phy_read(struct file *filp, char __user *buffer,
					size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct e1000_private *ep = filp->private_data;
	char *buf = l_e1000_dbg_reg_phy_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - PHY_IEEE registers dump (hex) =\n",
			  ep->dev->name, pci_name(ep->pci_dev));

	for (i = 0; i < ARRAY_SIZE(l_e1000_dbg_reg_id_phy); i++) {
		DPREG_PHY(l_e1000_dbg_reg_id_phy[i],
			  l_e1000_dbg_reg_name_phy[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* l_e1000_dbg_reg_phy_read */

static const struct file_operations l_e1000_dbg_reg_phy_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = l_e1000_dbg_reg_phy_read,
};

/** /sys/kernel/debug/l_e1000/<pcidev>/reg_ops */
static char l_e1000_dbg_reg_ops_buf[256] = "";

static ssize_t l_e1000_dbg_reg_ops_read(struct file *filp, char __user *buffer,
					size_t count, loff_t *ppos)
{
	struct e1000_private *ep = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "0x%08x\n", ep->reg_last_value);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
}

static ssize_t l_e1000_dbg_reg_ops_write(struct file *filp,
					 const char __user *buffer,
					 size_t count, loff_t *ppos)
{
	struct e1000_private *ep = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(l_e1000_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(l_e1000_dbg_reg_ops_buf,
				     sizeof(l_e1000_dbg_reg_ops_buf)-1,
				     ppos,
				     buffer,
				     count);
	if (len < 0)
		return len;

	l_e1000_dbg_reg_ops_buf[len] = '\0';

	if (strncmp(l_e1000_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&l_e1000_dbg_reg_ops_buf[5],
			     "%x %x", &reg, &value);
		if (cnt == 2) {
			ep->reg_last_value = value;
			if (ep->base_ioaddr)
				writel(value, ep->base_ioaddr + (reg << 2));
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_err(&ep->pci_dev->dev,
				"debugfs reg_ops usage: write <reg> <value>\n");
		}
	} else if (strncmp(l_e1000_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&l_e1000_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			value = (u32)-1;
			if (ep->base_ioaddr)
				value = readl(ep->base_ioaddr + (reg << 2));
			ep->reg_last_value = value;
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_err(&ep->pci_dev->dev,
				"debugfs reg_ops usage: read <reg>\n");
		}
	} else if (strncmp(l_e1000_dbg_reg_ops_buf, "writephy ", 9) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&l_e1000_dbg_reg_ops_buf[8],
			     "%x %x", &reg, &value);
		if (cnt == 2) {
			ep->reg_last_value = value;
			mdiobus_write(ep->mii_bus, ep->phyaddr, reg, value);
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_err(&ep->pci_dev->dev,
				"debugfs reg_ops usage:"
				" writephy <reg> <value>\n");
		}
	} else if (strncmp(l_e1000_dbg_reg_ops_buf, "readphy ", 8) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&l_e1000_dbg_reg_ops_buf[7], "%x", &reg);
		if (cnt == 1) {
			value = (u32)mdiobus_read(ep->mii_bus, ep->phyaddr,
						  reg);
			ep->reg_last_value = value;
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_err(&ep->pci_dev->dev,
				"debugfs reg_ops usage: readphy <reg>\n");
		}
	} else {
		ep->reg_last_value = 0xFFFFFFFF;
		dev_err(&ep->pci_dev->dev,
			"debugfs reg_ops: Unknown command %s\n",
			l_e1000_dbg_reg_ops_buf);
		pr_cont("    Available commands:\n");
		pr_cont("      read <reg>\n");
		pr_cont("      write <reg> <value>\n");
		pr_cont("      readphy <reg>\n");
		pr_cont("      writephy <reg> <value>\n");
	}

	return count;
}

static const struct file_operations l_e1000_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = l_e1000_dbg_reg_ops_read,
	.write = l_e1000_dbg_reg_ops_write,
};

static void l_e1000_dbg_board_init(struct e1000_private *ep)
{
	const char *name = pci_name(ep->pci_dev);
	struct dentry *pfile;

	ep->l_e1000_dbg_board = debugfs_create_dir(name, l_e1000_dbg_root);
	if (ep->l_e1000_dbg_board) {
		/* ./reg_ops */
		pfile = debugfs_create_file("reg_ops", 0600,
					    ep->l_e1000_dbg_board, ep,
					    &l_e1000_dbg_reg_ops_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops for %s failed\n", name);
		}
		/* GETH */
		pfile = debugfs_create_file("REG_GETH", 0400,
					    ep->l_e1000_dbg_board, ep,
					    &l_e1000_dbg_reg_geth_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_geth for %s failed\n", name);
		}
		/* PHY */
		pfile = debugfs_create_file("REG_PHY", 0400,
					    ep->l_e1000_dbg_board, ep,
					    &l_e1000_dbg_reg_phy_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_phy_ieee for %s failed\n", name);
		}
	} else {
		dev_warn(&ep->pci_dev->dev,
			 "debugfs entry for %s failed\n", name);
	}
}

static void l_e1000_dbg_board_exit(struct e1000_private *ep)
{
	if (ep->l_e1000_dbg_board)
		debugfs_remove_recursive(ep->l_e1000_dbg_board);
	ep->l_e1000_dbg_board = NULL;
}

#endif /*CONFIG_DEBUG_FS*/


/** TITLE: PROBE stuff */

static int e1000_init_dma_ba(struct e1000_private *ep)
{
	unsigned int init_block_addr_part;
	unsigned int soft_reset;

	/* low 32 bits DMA addr*/
	init_block_addr_part = (ep->dma_addr + offsetof(struct e1000_dma_area,
		    		init_block)) & 0xffffffff;
	e1000_write_e_base_address(ep, init_block_addr_part);
	if (e1000_debug & NETIF_MSG_PROBE)
		dev_dbg(&ep->pci_dev->dev,
			"%s: Init Block Low DMA addr: 0x%x (align=64)\n",
			__func__, init_block_addr_part);

	/* high 32 bits DMA addr*/
	init_block_addr_part = ((u64)(ep->dma_addr +
		offsetof(struct e1000_dma_area,
		init_block)) >> 32) & 0xffffffff; 
	e1000_write_dma_base_address(ep, init_block_addr_part);
	if (e1000_debug & NETIF_MSG_PROBE)
		dev_dbg(&ep->pci_dev->dev,
			"%s: Init Block High DMA addr: 0x%x\n",
			__func__, init_block_addr_part);

	/* PHY Resetting */
	soft_reset = (E1000_RSET_POLARITY | SRST);
	e1000_write_mgio_csr(ep, soft_reset); /* start software reset */
	soft_reset = e1000_read_mgio_csr(ep);
	soft_reset &= ~(SRST);
	usleep_range(10, 20); /* reset delay */
	e1000_write_mgio_csr(ep, soft_reset); /* stop software reset */
	e1000_read_mgio_csr(ep); /* wait for software reset */
	mdelay(1); /* delay */
	if (e1000_debug & NETIF_MSG_LINK)
		dev_dbg(&ep->pci_dev->dev,
			"software reset PHY completed\n");

	return 0;
}

/* probe nort device - create netdev */
static int e1000_probe1(unsigned long ioaddr, unsigned char *base_ioaddr,
			int shared, struct pci_dev *pdev,
			struct resource *res, int bar,
			struct msix_entry *msix_entries, int msi_status)
{
	int i = 0;
	struct e1000_private *ep = NULL;
	struct net_device *dev = NULL;
	int ret = -ENODEV;
	u16 vendor_id, device_id;
	struct e1000_dma_area *m;
	size_t sz;

	shared = (msi_status != L_E1000_MSIX);
	dev = alloc_etherdev(sizeof(struct e1000_private));
	if (!dev) {
		dev_err(&pdev->dev, "Etherdev allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;
	
	}
	ep = netdev_priv(dev);

	sz = ALIGN(sizeof(struct e1000_dma_area), 64);
	ep->dma_area = dma_alloc_coherent(&pdev->dev, sz,
					  &ep->dma_addr, GFP_ATOMIC);
	if (!ep->dma_area) {
		dev_err(&pdev->dev, "Memory allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;
	}
	ep->smpkts_area = dma_alloc_coherent(&pdev->dev,
					     SMALL_PKT_SZ * TX_RING_SIZE,
					     &ep->smpkts_dma, GFP_ATOMIC);
	if (!ep->smpkts_area) {
		dev_err(&pdev->dev, "Memory allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;
	}

	m = (struct e1000_dma_area *)PTR_ALIGN(ep->dma_area, 64);
	ep->init_block = &m->init_block;
	ep->tx_ring = m->tx_ring;
	ep->rx_ring = m->rx_ring;

	SET_NETDEV_DEV(dev, &pdev->dev);
	dev->base_addr = ioaddr;
	ep->dev = dev;

	if (pci_read_config_byte(pdev, PCI_REVISION_ID, &ep->revision)) {
		dev_warn(&pdev->dev, "Can't read REVISION_ID\n");
	}
	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor_id);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	if (vendor_id == PCI_VENDOR_ID_MCST_TMP &&
	    device_id == PCI_DEVICE_ID_MCST_ETH &&
		have_pps_mpv) {
		ep->csr_1588 = ATME | TMCE;
		ep->ptp_clock_info = le1000_ptp_clock_info;
		ep->ptp_clock = ptp_clock_register(&ep->ptp_clock_info,
						   &(pdev->dev));
		ep->ptp_clock_info.max_adj = 1000000000;
		if (IS_ERR(ep->ptp_clock)) {
			ep->ptp_clock = NULL;
			dev_warn(&pdev->dev, "ptp_clock_register failed\n");
		} else {
			if (netif_msg_timer(ep))
				dev_info(&pdev->dev, "registered PHC clock\n");
		}
		if (netif_msg_timer(ep))
			dev_info(&pdev->dev,
				"Ethernet controller supports "
				"IEEE 1588 in IOHUB2\n");
	} else {
		ep->csr_1588 = 0;
	}

	ep->pci_dev = pdev;
	ep->base_ioaddr = base_ioaddr;

	/* Setup STOP bit; Force e1000 resetting  */
	e1000_write_e_csr(ep, STOP);
			/* RINT => 0; TINT => 0; IDON => 0; INTR => 0;
			*  INEA => 0; RXON => 0; TXON => 0; TMDM => 0;
			*  STRT => 0; INIT => 0;
			*  access to E_BASE_ADDR is allowed
			*/

	raw_spin_lock_init(&ep->lock); /* xmit, ... */
	raw_spin_lock_init(&ep->systim_lock); /* adjtime, gettime */

	/* Setup HW (MAC), also known as "Physical" address. */
	if (l_e1000_num_chanels(pdev) != 1) {
		l_set_ethernet_macaddr(NULL, dev->dev_addr);
	} else {
		if (l_set_ethernet_macaddr(pdev, dev->dev_addr)) {
#if defined(CONFIG_E2K) || defined(CONFIG_E90S)
			iohub_eth_base_addr = base_ioaddr;
#ifndef MODULE
			l_set_boot_mode = set_iohub_eth_for_special_reset;
#endif /* MODULE */
#endif /* CONFIG_E2K || CONFIG_E90S */
		}
	}
	/* eth_hw_addr_random(dev); */

	ep->msg_enable = e1000_debug;
	ep->shared_irq = shared;

	/* Default: */
	ep->phy_mode = PHY_INTERFACE_MODE_GMII;

	/* Setup init block */
	ep->init_block->mode = cpu_to_le16(e1000_mode);
	ep->init_block->laddrf = 0UL;
	for (i = 0; i < 6; i++)
		ep->init_block->paddr[i] = dev->dev_addr[i];
	/*ep->init_block.paddr[2] = 0x40;*/
	ep->init_block->laddrf = 0UL;
	ep->init_block->rdra = cpu_to_le32((u32)(ep->dma_addr +
				offsetof(struct e1000_dma_area, rx_ring)));
	ep->init_block->rdra |= cpu_to_le32(E1000_LOG_RX_BUFFERS);
	ep->init_block->tdra = cpu_to_le32((u32)(ep->dma_addr +
				offsetof(struct e1000_dma_area, tx_ring)));
	ep->init_block->tdra |= cpu_to_le32(E1000_LOG_TX_BUFFERS);

	if (e1000_debug & NETIF_MSG_PROBE)
		dev_dbg(&pdev->dev,
			"%s: Receive  Desc Ring DMA Addr | Rlen[3:0]: 0x%x\n",
			__func__, le32_to_cpu(ep->init_block->rdra));
	if (e1000_debug & NETIF_MSG_PROBE)
		dev_dbg(&pdev->dev,
			"%s: Transmit Desc Ring DMA Addr | Tlen[3:0]: 0x%x\n",
			__func__, le32_to_cpu(ep->init_block->tdra));

	dev->irq = pdev->irq;
	if (e1000_debug & NETIF_MSG_INTR)
		dev_dbg(&pdev->dev, "assigned IRQ #%u\n", dev->irq);

	if (e1000_init_dma_ba(ep)) {
		ret = -ENODEV;
		goto err_free_consistent;
	}

	/* The E1000-specific entries in the device structure. */
	dev->ethtool_ops = &e1000_ethtool_ops;
	dev->netdev_ops = &e1000_netdev_ops;
	dev->watchdog_timeo = (5 * HZ);
	netif_napi_add(dev, &ep->napi, e1000_poll, L_E1000_NAPI_WEIGHT);
	ep->napi_scheduled = 0;

	if (l_e1000_supports_coalesce(ep)) {
		/* tx delay = 1usec for a while */
		ep->txrx_delay = 125;
	}
	if (CAN_DISABLE_TXINT(ep)) {
		ep->tx_coal_frame = 64;
	}

	/* Fill in the generic fields of the device structure. */
	pci_set_drvdata(pdev, dev);

	if (register_netdev(dev))
		goto err_free_consistent;

	ep->resource = res;
	ep->bar = bar;
	ep->msix_entries = msix_entries;
	ep->msi_status = msi_status;

	/** PHY register mdio bus */
	ret = e1000_mdio_register(ep);
	if (ret)
		goto err_free_netdev;

	/* Setup STOP bit; Force e1000 resetting  */
	e1000_write_e_csr(ep, STOP);

	if (do_pause_sender) {
		/* We will send special pkt to sender
		 * to pause its activite in case of MISS error
		 */
		struct sk_buff *skb;

		skb = dev_alloc_skb(ETH_ZLEN + CRC_SZ + 2);
		if (skb) {
			skb_reserve(skb,2); /* 16 byte align */
			skb_put(skb, ETH_ZLEN + CRC_SZ); /* Make room */
			skb_copy_to_linear_data(skb, pause_packet, ETH_ZLEN);
			*(skb->data +6) = dev->dev_addr[0];
			*(skb->data +7) = dev->dev_addr[1];
			*(skb->data +8) = dev->dev_addr[2];
			*(skb->data +9) = dev->dev_addr[3];
			*(skb->data +10) = dev->dev_addr[4];
			*(skb->data +11) = dev->dev_addr[5];
			if (do_pause_sender > 128) {
				*(skb->data + 16) =
					(do_pause_sender & 0xFF00) >> 8;
				*(skb->data + 17) =
					do_pause_sender & 0xFF;
			}
			ep->skb_to_pause = skb;
			ep->skb_to_pause_dma = pci_map_single(ep->pci_dev,
					skb->data, ETH_ZLEN, PCI_DMA_TODEVICE);
			ep->skb_to_pause_sent = 0;
		}
	}

#ifdef CONFIG_DEBUG_FS
	l_e1000_dbg_board_init(ep);
#endif /*CONFIG_DEBUG_FS*/
	ep->napi_cpu = -1;
#ifdef CONFIG_SYSCTL
	static ctl_table *napi_cpu_table;
	char buf[IFNAMSIZ];

	napi_cpu_table = kzalloc(sizeof(ctl_table) * 2, GFP_KERNEL);
	strncpy(buf, netdev_name(dev), IFNAMSIZ);
	napi_cpu_table->procname = kstrdup(buf, GFP_KERNEL);
	napi_cpu_table->data = &ep->napi_cpu;
	napi_cpu_table->maxlen = sizeof(ep->napi_cpu);
	napi_cpu_table->mode = 0644;
	napi_cpu_table->proc_handler = proc_dointvec;
	register_sysctl("dev/l_e1000/napi_cpu", napi_cpu_table);
#endif /* CONFIG_SYSCTL */
	dev_info(&pdev->dev,
		 "registered as " KBUILD_MODNAME " (rev. %d)\n", ep->revision);

	return 0;

err_free_netdev:
	unregister_netdev(dev);
err_free_consistent:
err_release_region:
	if (ep->dma_area) {
		dma_free_coherent(&pdev->dev,
				  ALIGN(sizeof (struct e1000_dma_area), 64),
				  ep->dma_area, ep->dma_addr);
	}
	if (ep->smpkts_area) {
		dma_free_coherent(&pdev->dev,
				  SMALL_PKT_SZ * TX_RING_SIZE,
				  ep->smpkts_area, ep->smpkts_dma);
	}
	if (ep->ptp_clock) {
		ptp_clock_unregister(ep->ptp_clock);
		ep->ptp_clock = NULL;
	}
	if (dev) {
		free_netdev(dev);
	}
	return ret;
}


static char *rt = NULL;
#define MAX_NUM_L_E1000_RT	32
static void *l_1000_rts[MAX_NUM_L_E1000_RT];
static int num_l_e1000_rt;

static int is_rt_device(struct pci_dev *pdev, int bar)
{
	char *s = rt;
	int inst;

retry :
	if (s == NULL) {
		return 0;
	}
	s = strstr(s, pci_name(pdev));
	if (s == NULL) {
		return 0;
	}
	s += strlen(pci_name(pdev));
	if (*s != '#') {
		goto yes;
	}
	s++;
	inst = simple_strtol(s, NULL, 10);
	if (inst == bar) {
		goto yes;
	}
	goto retry;
yes:
	return 1;
}

static int was_rt_device(void *ep)
{
	int i;
	for (i = 0; i < num_l_e1000_rt; i++) {
		if (l_1000_rts[i] == ep) {
			return 1;
		}
	}
	return 0;
}

#define IS_RT_DEVICE(pdev) (rt && strstr(rt, pci_name(pdev)))
module_param(rt, charp, 0444);

static int e1000_probe_pci_bar(struct pci_dev *pdev,
			       const struct pci_device_id *ent,
			       int bar, struct msix_entry *msix_entries,
			       int msi_status)
{
	resource_size_t ioaddr;
	unsigned char *base_ioaddr;
	struct resource *res;
	int err;
	u16 subven;

	pci_read_config_word(pdev, PCI_SUBSYSTEM_VENDOR_ID, &subven);
	if (subven == 0xffff) {
		dev_warn(&pdev->dev,
			 "Skip not used interfaces of IOHUB\n");
		return -ENODEV;
	}

	ioaddr = pci_resource_start(pdev, bar);
	if (!ioaddr) {
		dev_err(&pdev->dev, "card has no PCI IO resource, aborting\n");
		return -ENODEV;
	}

	if (!pci_dma_supported(pdev, E1000_DMA_MASK)) {
		dev_err(&pdev->dev,
			"architecture does not support 32bit"
			" PCI busmaster DMA\n");
		return -ENODEV;
	}

	res = request_mem_region(ioaddr, E1000_TOTAL_SIZE, "e1000_probe_pci");
	if (res == NULL) {
		dev_err(&pdev->dev, "memio address range already allocated\n");
		return -EBUSY;
	}

	base_ioaddr = ioremap(ioaddr, E1000_TOTAL_SIZE);
	if (base_ioaddr == NULL){
		release_mem_region(ioaddr, E1000_TOTAL_SIZE);
		dev_err(&pdev->dev,
			"Unable to map base ioaddr = 0x%llx\n", ioaddr);
		return -ENOMEM;
	}

	if (is_rt_device(pdev, bar)) {
		if (num_l_e1000_rt >= (MAX_NUM_L_E1000_RT - 1)) {
			dev_warn(&pdev->dev,
				 "l_e1000: max rt devices reached.\n");
			err = -ENOMEM;
		} else {
			struct net_device *dev = dev_get_drvdata(&pdev->dev);
			err = e1000_rt_probe1(ioaddr, base_ioaddr, 1, pdev, res,
					      bar, msix_entries, msi_status);
			if (err >= 0) {
				dev = dev_get_drvdata(&pdev->dev);
				l_1000_rts[num_l_e1000_rt] = netdev_priv(dev);
				num_l_e1000_rt++;
			}
		}
	} else {
		err = e1000_probe1(ioaddr, base_ioaddr, 1, pdev, res,
				   bar, msix_entries, msi_status);
	}

	if (err < 0) {
		iounmap(base_ioaddr);
		release_mem_region(ioaddr, E1000_TOTAL_SIZE);
	}
	return err;
}

static int e1000_probe_pci(struct pci_dev *pdev,
			   const struct pci_device_id *ent)
{
	int res, err = 0;
	int bar;
	struct msix_entry *msix_entries = NULL;
#ifdef MCST_MSIX
	int num_msix_entries;
	int i;
	int msixcapbar;
#endif /* MCST_MSIX */
	int msi_status = L_E1000_NOMSI;

	dev_info(&pdev->dev,
		 "initializing PCI device %04x:%04x\n",
		 pdev->vendor, pdev->device);

	err = pci_enable_device(pdev);
	if (err < 0) {
		dev_err(&pdev->dev,
			"failed to enable device -- err=%d\n", err);
		return err;
	}
	pci_set_master(pdev);

#ifdef MCST_MSIX
	num_msix_entries = l_e1000_supports_msix(pdev);
	msixcapbar = num_msix_entries;
	if (num_msix_entries > 0) {
		if (e1000_debug & NETIF_MSG_INTR)
			dev_dbg(&pdev->dev,
				"%s: supports %d MSIX interrupts\n",
				__func__, num_msix_entries);

		msix_entries = kzalloc_node(num_msix_entries *
						sizeof(struct msix_entry),
					    GFP_KERNEL,
					    dev_to_node(&pdev->dev));
		if (msix_entries) {
			for (i = 0; i < num_msix_entries; i++) {
				msix_entries[i].entry = i;
			}
		}
		if (ent->device == PCI_DEVICE_ID_MCST_MGEX) {
			unsigned long ioaddr = pci_resource_start(pdev,
								  msixcapbar);
			if (!ioaddr) {
				dev_warn(&pdev->dev, "cant get MSIX bar 4\n");
				goto nomsix;
			}
			if (request_mem_region(ioaddr,
					pci_resource_len(pdev, msixcapbar),
					"e1000_msix_capabilities") == NULL) {
				dev_warn(&pdev->dev,
					 "msix reg address range"
					 " already allocated\n");
				goto nomsix;
			}

			pdev->mcst_msix_cap_base = ioremap(ioaddr,
					pci_resource_len(pdev, msixcapbar));
			if (pdev->mcst_msix_cap_base == NULL) {
				dev_warn(&pdev->dev,
					 "Unable to map msix ioaddr = 0x%lx\n",
					 ioaddr);
				release_mem_region(ioaddr,
					pci_resource_len(pdev, msixcapbar));
				goto nomsix;
			}

			if (e1000_debug & NETIF_MSG_INTR) {
				dev_dbg(&pdev->dev,
					"%s: pdev->mcst_msix_cap_base = %p, "
					"ioaddr = 0x%lx, len = 0x%llx\n",
					__func__, pdev->mcst_msix_cap_base,
					ioaddr, pci_resource_len(pdev, 4));
				dev_dbg(&pdev->dev,
					"capability             = 0x%04x\n",
					readw(pdev->mcst_msix_cap_base));
				dev_dbg(&pdev->dev,
					"PCI_MSIX_FLAGS         = 0x%04x\n",
					readw(pdev->mcst_msix_cap_base +
					      PCI_MSIX_FLAGS));
				dev_dbg(&pdev->dev,
					"PCI_MSIX_TABLE         = 0x%08x\n",
					readl(pdev->mcst_msix_cap_base +
					      PCI_MSIX_TABLE));
				dev_dbg(&pdev->dev,
					"PCI_MSIX_PBA           = 0x%08x\n",
					readl(pdev->mcst_msix_cap_base +
					      PCI_MSIX_PBA));
			}

			res = pci_enable_msix_range(pdev,
						    msix_entries,
						    num_msix_entries,
						    num_msix_entries);
			if (res < 0) {
				iounmap(pdev->mcst_msix_cap_base);
				release_mem_region(ioaddr,
					pci_resource_len(pdev, msixcapbar));
				pdev->mcst_msix_cap_base = NULL;
				dev_warn(&pdev->dev,
					 "cannot use msix interrupts.i"
					 "reason = %d\n", res);
				goto nomsix;
			}
			msi_status = L_E1000_MSIX;
		} else {
	nomsix:
			kfree(msix_entries);
			msix_entries = NULL;
			num_msix_entries = 0;
		}
	}
#endif /* MCST_MSIX */

	if ((msi_status == L_E1000_NOMSI) && l_e1000_supports_msi(pdev)) {
		res = pci_enable_msi(pdev);
		if (res == 0) {
			if (e1000_debug & NETIF_MSG_INTR)
				dev_dbg(&pdev->dev,
					"%s: use msi interrupt\n", __func__);
			msi_status = L_E1000_MSI;
		} else {
			dev_warn(&pdev->dev,
				 "cannot use msi interrupt, reason = %d\n",
				 res);
		}
	}

	for (bar = 0; bar < l_e1000_num_chanels(pdev); bar++) {
		res = e1000_probe_pci_bar(pdev, ent, bar,
					  msix_entries, msi_status);
		if (res && !err) {
			err = res;
		}
	}

	if (err) {
		if (msi_status == L_E1000_MSIX) {
			pci_disable_msix(pdev);
		} else if (msi_status == L_E1000_MSI) {
			pci_disable_msi(pdev);
		}
#ifdef MCST_MSIX
		kfree(msix_entries);
#endif /* MCST_MSIX */
		dev_set_drvdata(&pdev->dev, NULL);
		pci_disable_device(pdev);
	}
	return err;
}

static void e1000_remove(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct e1000_private *ep = netdev_priv(dev);

#ifdef CONFIG_DEBUG_FS
	l_e1000_dbg_board_exit(ep);
#endif /*CONFIG_DEBUG_FS*/

	if (was_rt_device(ep)) {
		e1000_rt_remove(pdev);
		return;
	}

	/* close */
	netif_carrier_off(dev);
	if (dev->phydev) {
		phy_stop(dev->phydev);
		phy_disconnect(dev->phydev);
		dev->phydev = NULL;
	}
	e1000_write_e_csr(ep, STOP);

	/* cleanup e1000_probe1: */
	if (netif_msg_drv(ep))
		dev_info(&pdev->dev,
			 "cleanup - unregister phy and net\n");

	mdiobus_unregister(ep->mii_bus);
	unregister_netdev(dev);

	if (ep->dma_area) {
		dma_free_coherent(&pdev->dev,
				  ALIGN(sizeof (struct e1000_dma_area), 64),
				  ep->dma_area, ep->dma_addr);
	}
	if (ep->smpkts_area) {
		dma_free_coherent(&pdev->dev,
				  SMALL_PKT_SZ * TX_RING_SIZE,
				  ep->smpkts_area, ep->smpkts_dma);
	}
	if (ep->ptp_clock) {
		ptp_clock_unregister(ep->ptp_clock);
		ep->ptp_clock = NULL;
		if (netif_msg_timer(ep))
			dev_info(&pdev->dev, "cleanup - remove PHC\n");
	}

	free_netdev(dev);

	/* cleanup e1000_probe_pci_bar: */

	if (iohub_eth_base_addr != ep->base_ioaddr)
		iounmap(ep->base_ioaddr);

	release_mem_region(pci_resource_start(pdev, ep->bar),
			   E1000_TOTAL_SIZE);

	/* cleanup e1000_probe_pci: */

	if (ep->msi_status == L_E1000_MSIX) {
		pci_disable_msix(pdev);
	} else if (ep->msi_status == L_E1000_MSI) {
		pci_disable_msi(pdev);
	}

#ifdef MCST_MSIX
	if (pdev->mcst_msix_cap_base) {
		iounmap(pdev->mcst_msix_cap_base);
		pdev->mcst_msix_cap_base = NULL;
		release_mem_region(pci_resource_start(pdev, 4),
				   pci_resource_len(pdev, 4));
	}
	/* FIXME: ???  kfree(msix_entries); */
#endif /* MCST_MSIX */

	dev_set_drvdata(&pdev->dev, NULL);
	pci_disable_device(pdev);
}

#ifdef CONFIG_PM

static void e1000_shutdown(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct e1000_private *ep = netdev_priv(dev);
	int i;
	unsigned long flags;

	if (netif_running(dev)) {
		napi_disable(&ep->napi);
		netif_stop_queue(dev);

		raw_spin_lock_irqsave(&ep->lock, flags);
		e1000_write_e_csr(ep, STOP);
		/* wait for stop */
		for (i = 0; i < 1000; i++)
			if (e1000_read_e_csr(ep) & STOP)
				break;
		if (i >= 100 && netif_msg_drv(ep))
			dev_warn(&pdev->dev,
				 "%s timed out waiting for stop.\n", __func__);
		raw_spin_unlock_irqrestore(&ep->lock, flags);

		netif_carrier_off(dev);
	}
}

static int e1000_suspend(struct pci_dev *pdev, pm_message_t state)
{
	e1000_shutdown(pdev);
	return 0;
}

static int e1000_resume(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct e1000_private *ep = netdev_priv(dev);
	unsigned long flags;

	if (!netif_running(dev)) {
		return 0;
	}

	napi_enable(&ep->napi);
	e1000_init_dma_ba(ep);

	raw_spin_lock_irqsave(&ep->lock, flags);
	e1000_restart(dev, INEA | STRT);
	raw_spin_unlock_irqrestore(&ep->lock, flags);

	netif_start_queue(dev);
	netif_carrier_on(dev);
	return 0;
}

#endif /* CONFIG_PM */

#define PCI_SUBVENDOR_ID_E1000	0x0000

const struct pci_device_id e1000_pci_tbl[] = {
	{
		.vendor = PCI_VENDOR_ID_ELBRUS,
		.device = PCI_DEVICE_ID_MCST_E1000,
		.subvendor = PCI_SUBVENDOR_ID_E1000,
		.subdevice = PCI_ANY_ID,
	},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_ETH)},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, PCI_DEVICE_ID_MCST_MGEX)},
	{0, }
};

MODULE_DEVICE_TABLE (pci, e1000_pci_tbl);

static struct pci_driver e1000_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= e1000_pci_tbl,
	.probe		= e1000_probe_pci,
	.remove		= e1000_remove,
#ifdef CONFIG_PM
	.shutdown	= e1000_shutdown,
	.resume		= e1000_resume,
	.suspend	= e1000_suspend,
#endif /* CONFIG_PM */
};

#ifdef CONFIG_SYSCTL

/* Place file num_tx_bufs_to_clean_on_xmit in /proc/sys/dev/l_e1000 */
static ctl_table l_e1000_table[] = {
	{
		.procname	= "num_bufs_to_clean_on_tx",
		.data		= &num_tx_bufs_to_clean,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{}
};

static ctl_table l_e1000_l_e1000_table[] = {
	{
	.procname	= "l_e1000",
	.maxlen		= 0,
	.mode		= 0555,
	.child          = l_e1000_table,
	},
	{ }
};

/* Make sure that /proc/sys/dev is there */
static ctl_table l_e1000_root_table[] = {
{
	.procname	= "dev",
	.maxlen		= 0,
	.mode		= 0555,
	.child		= l_e1000_l_e1000_table,
	},
	{ }
};

static struct ctl_table_header *l_e1000_sysctl_header;

static void l_e1000_sysctl_register(void)
{
	if (l_e1000_sysctl_header) {
	    return;
	}
        l_e1000_sysctl_header = register_sysctl_table(l_e1000_root_table);
}

static void l_e1000_sysctl_unregister(void)
{
	if (l_e1000_sysctl_header) {
		unregister_sysctl_table(l_e1000_sysctl_header);
	}
	l_e1000_sysctl_header = NULL;
}

#else /* !CONFIG_SYSCTL */

static void l_e1000_sysctl_register(void)
{
}

static void l_e1000_sysctl_unregister(void)
{
}

#endif /* CONFIG_SYSCTL */

static void __exit e1000_cleanup_module(void)
{
	l_e1000_sysctl_unregister();
	pci_unregister_driver(&e1000_driver);

#ifdef CONFIG_DEBUG_FS
	if (l_e1000_dbg_root)
		debugfs_remove_recursive(l_e1000_dbg_root);
#endif /*CONFIG_DEBUG_FS*/
}

extern int e1000;

static int __init e1000_init_module(void)
{
	int r;

	pr_info(KBUILD_MODNAME ": %s", version);
	if (!e1000) {
		pr_err(KBUILD_MODNAME ": Ethernet e1000 driver not allowed. "
				      "Use e1000 in command line\n");
		return (-ENODEV);
	}

	e1000_debug = netif_msg_init(debug,
		NETIF_MSG_DRV |			/* netif_msg_drv */
		/*NETIF_MSG_PROBE |*/		/* netif_msg_probe */
		NETIF_MSG_LINK |		/* netif_msg_link */
		/*NETIF_MSG_TIMER |*/		/* netif_msg_timer */
		/*NETIF_MSG_IFDOWN |*/		/* netif_msg_ifdown */
		/*NETIF_MSG_IFUP |*/		/* netif_msg_ifup */
		/*NETIF_MSG_RX_ERR |*/		/* netif_msg_rx_err */
		/*NETIF_MSG_TX_ERR |*/		/* netif_msg_tx_err */
		/*NETIF_MSG_TX_QUEUED |*/	/* netif_msg_tx_queued */
		/*NETIF_MSG_INTR |*/		/* netif_msg_intr */
		/*NETIF_MSG_TX_DONE |*/		/* netif_msg_tx_done */
		/*NETIF_MSG_RX_STATUS |*/	/* netif_msg_rx_status */
		/*NETIF_MSG_PKTDATA |*/		/* netif_msg_pktdata */
		/*NETIF_MSG_HW |*/		/* netif_msg_hw */
		/*NETIF_MSG_WOL |*/		/* netif_msg_wol */
	0);

#ifdef CONFIG_DEBUG_FS
	l_e1000_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (l_e1000_dbg_root == NULL)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
#endif /*CONFIG_DEBUG_FS*/

	r = pci_register_driver(&e1000_driver);
	if (r == 0) {
		l_e1000_sysctl_register();
	} else {
#ifdef CONFIG_DEBUG_FS
		if (l_e1000_dbg_root)
			debugfs_remove_recursive(l_e1000_dbg_root);
#endif /*CONFIG_DEBUG_FS*/
	}
	return r;
}

module_init(e1000_init_module);
module_exit(e1000_cleanup_module);
