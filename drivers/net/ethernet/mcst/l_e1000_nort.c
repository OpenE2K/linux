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
#include <linux/clocksource.h>		/* for IEEE 1588 */
#include <linux/net_tstamp.h>		/* for IEEE 1588 */
#include <linux/ptp_clock_kernel.h>	/* for IEEE 1588 */

#include <asm/dma.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/irqflags.h>
#include <asm/irq.h>

#ifdef	CONFIG_MCST
#include <asm/setup.h>
#endif

#include "l_e1000.h"


#define LE1000_CHEKS_TX_RING 0

#define PCI_DEVICE_ID_E1000	0x4d45
#define	PCI_SUBVENDOR_ID_E1000	0x0000


MODULE_AUTHOR("Alexey V. Sitnikov");
MODULE_DESCRIPTION("Driver for e1000 on e2k/e90 family architecture");
MODULE_LICENSE("GPL");

#define DEBUG_MDIO_RD_ON	0	/* Debug for mdio_read primitive */
#define DEBUG_MDIO_WR_ON	0	/* Debug for mdio_write primitive */
#define DEBUG_RD_E_CSR_ON	0	/* Debug for read_e_csr primitive */
#define DEBUG_WR_E_CSR_ON	0	/* Debug for write_e_csr primitive */
#define DEBUG_INIT_RING_ON	0	/* Debug for init_ring function */
#define	DEBUG_E1000_RX_ON	0	/* Debug for rx function */
#define DEBUG_E1000_RX_HEAD_ON	0	/* Show rx packet header */
#define DEBUG_E1000_RX_BODY_ON	0	/* Show rx packet body  */
#define DEBUG_E1000_RESTART_ON  0
#define DEBUG_LOOPBACK_ON	0	
#define	DEBUG_PROBE_ON		0
#define	DEBUG_SETPHT_ON		0
#define DEBUG_MULT_CAST_ON	0
#define	DEBUG_INIT_BLOCK_ON	0
#define	DEBUG_RESUME_ON		0
#define	DEBUG_IRQ_ON		1



#define DEBUG_MDIO_RD		if (DEBUG_MDIO_RD_ON) printk
#define DEBUG_MDIO_WR		if (DEBUG_MDIO_WR_ON) printk
#define DEBUG_INIT_RING		if (DEBUG_INIT_RING_ON) printk
#define DEBUG_RD_E_CSR		if (DEBUG_RD_E_CSR_ON) printk
#define DEBUG_WR_E_CSR		if (DEBUG_WR_E_CSR_ON) printk	
#define DEBUG_E1000_RX		if (DEBUG_E1000_RX_ON) printk
#define DEBUG_E1000_RX_HEAD	if (DEBUG_E1000_RX_HEAD_ON) printk
#define DEBUG_E1000_RX_BODY	if (DEBUG_E1000_RX_BODY_ON) printk
#define DEBUG_E1000_RESTART	if (DEBUG_E1000_RESTART_ON) printk
#define DEBUG_LOOPBACK		if (DEBUG_LOOPBACK_ON) printk
#define DEBUG_PROBE		if (DEBUG_PROBE_ON) printk
#define DEBUG_SETPHY		if (DEBUG_SETPHT_ON) printk
#define DEBUG_MULT_CAST		if (DEBUG_MULT_CAST_ON)	printk
#define DEBUG_RESUME		if (DEBUG_RESUME_ON) printk
#define DEBUG_IRQ		if (DEBUG_IRQ_ON) printk

static int max_interrupt_work = 2;
static int rx_copybreak = 200;

DEFINE_PCI_DEVICE_TABLE(e1000_pci_tbl) = {
        {
                .vendor = PCI_VENDOR_ID_INTEL,
                .device = PCI_DEVICE_ID_E1000,
                .subvendor = PCI_SUBVENDOR_ID_E1000,
                .subdevice = PCI_ANY_ID,
        },
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, 0x8016)},
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, 0x8022)},
        {0, }
};

MODULE_DEVICE_TABLE (pci, e1000_pci_tbl);

static int l_cards_without_mac_found;

#define DRV_NAME	"l_e1000"
#define DRV_VERSION	"1.00"
#define DRV_RELDATE	"08.07.2008"
#define PFX		DRV_NAME ": "

static const char e1000_gstrings_test[][ETH_GSTRING_LEN] = {
    "Loopback test  (offline)"
};

#define E1000_TEST_LEN (sizeof(e1000_gstrings_test) / ETH_GSTRING_LEN)

#define E1000_NUM_REGS 168

#define E1000_DMA_MASK 		0xffffffff
#define E1000_TOTAL_SIZE	0x20

#define E1000_WATCHDOG_TIMEOUT (jiffies + (2 * HZ))
#define E1000_BLINK_TIMEOUT	(jiffies + (HZ/4))

#define E1000_PORT_MII      0x03
#define E1000_PORT_ASEL     0x04

#define	e1000_mode		(FULL)

/*
 * Set the number of Tx and Rx buffers, using Log_2(# buffers).
 * Reasonable default values are 16 Tx buffers, and 256 Rx buffers.
 * That translates to 4 (16 == 2^^4) and 8 (256 == 2^^8).
 */
#ifndef E1000_LOG_TX_BUFFERS
#define E1000_LOG_TX_BUFFERS 8 //4
#define E1000_LOG_RX_BUFFERS 8 //8
#endif

#define TX_RING_SIZE		(1 << (E1000_LOG_TX_BUFFERS))
#define TX_RING_MOD_MASK	(TX_RING_SIZE - 1)
#define TX_RING_LEN_BITS	((E1000_LOG_TX_BUFFERS) << 12)

#define TX_HISTERESIS		4
#define RX_RING_SIZE		(1 << (E1000_LOG_RX_BUFFERS))
#define RX_RING_MOD_MASK	(RX_RING_SIZE - 1)
#define RX_RING_LEN_BITS	((E1000_LOG_RX_BUFFERS) << 4)

#define PKT_BUF_SZ		1514 /*(1500 data + 14 header) */

/* Each packet consists of header 14 bytes + [46 min - 1500 max] data + 4 bytes crc 
 * e1000 makes crc automatically when sending a packet so you havn't to take care
 * about it allocating memory for the packet being sent. As to received packets e1000
 * doesn't hew crc off so you'll have to alloc an extra 4 bytes of memory in addition to
 * common packet size */

#define CRC_SZ	4
static unsigned int rx_prev_etmr = 0;   /* for debug */
static unsigned int tx_prev_etmr = 0;	/* for debug */

#define L_E1000_NAPI_WEIGHT 64


/* E1000 Rx and Tx ring descriptors. */


struct e1000_rx_head {
    u32 		base;	      /*u32*/ /* RBADR 	   [31:0] */ 
    s16			buf_length;   /*s16*/ /* BCNT only [13:0] */
    s16		 	status;       /*s16*/
    s16			msg_length;   /*s16*/ /* MCNT only [13:0] */	
    u16 reserved1;
    u32	etmr;	/* timer count for ieee 1588 is set by hardware */
} __attribute__((packed));

struct e1000_tx_head {
    u32 		base;	      /*u32*/ /* TBADR	   [31:0] */
    s16 		buf_length;   /*s16*/ /* BCNT only [13:0] */	
    s16		 	status;       /*s16*/
    u32 		misc;	      /*u32*/ /* [31:26] + [3:0]  */	
    u32	etmr;	/* timer count for ieee 1588 is set by hardware */
} __attribute__((packed));

struct e1000_private;
struct e1000_access {
    u32 	(*read_e_csr)(struct e1000_private *);
    void 	(*write_e_csr)(struct e1000_private*, int);
    u32 	(*read_mgio_csr)(struct e1000_private*);
    void 	(*write_mgio_csr)(struct e1000_private *, int);
    u32 	(*read_mgio_data)(struct e1000_private *);
    void 	(*write_mgio_data)(struct e1000_private *, int);
    u32 	(*read_e_base_address)(struct e1000_private *);
    void 	(*write_e_base_address)(struct e1000_private *, int);	
    u32 	(*read_dma_base_address)(struct e1000_private *);
    void 	(*write_dma_base_address)(struct e1000_private *, int);
    u32 	(*read_psf_csr)(struct e1000_private *);
    void 	(*write_psf_csr)(struct e1000_private *, int);
    u32 	(*read_psf_data)(struct e1000_private *);
    void 	(*write_psf_data)(struct e1000_private *, int);
};





struct e1000_dma_area {
	init_block_t              init_block __attribute__((aligned(32)));
	struct e1000_rx_head      rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
	struct e1000_tx_head      tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
};

/*
 * The first three fields of pcnet32_private are read by the ethernet device
 * so we allocate the structure should be allocated by pci_alloc_consistent().
 */
struct e1000_private {
#if 0
    init_block_t 	      init_block __attribute__((aligned(32)));
    /* The Tx and Rx ring entries must be aligned on 16-byte boundaries in 32bit mode. */
	
    struct e1000_rx_head      rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
    struct e1000_tx_head      tx_ring[TX_RING_SIZE] __attribute__((aligned(16)));
#else
    init_block_t	*init_block;
    struct e1000_rx_head      *rx_ring;
    struct e1000_tx_head      *tx_ring;
    void                      *dma_area;
#endif
    dma_addr_t		dma_addr;	/* DMA address of beginning of this
					   object of type e1000_private, returned by
					   pci_alloc_consistent */
    struct pci_dev	*pci_dev;	/* Pointer to the associated pci device
					   structure */
    struct net_device	*dev;
    struct resource *resource;
    const char		*name;
    int			msi_status;
    int bar;		/* MSIX support */
    struct msix_entry *msix_entries;	/* MSIX support */
    int			irq;
    /* The saved address of a sent-in-place packet/buffer, for skfree(). */
    struct sk_buff	*tx_skbuff[TX_RING_SIZE];
    struct sk_buff	*rx_skbuff[RX_RING_SIZE];
    dma_addr_t		tx_dma_addr[TX_RING_SIZE];
    dma_addr_t		rx_dma_addr[RX_RING_SIZE];
    unsigned char	*base_ioaddr;
    struct e1000_access	*a;
    raw_spinlock_t		lock;			/* Guard lock */
    unsigned int	cur_rx, cur_tx;		/* The next free ring entry */
    unsigned int	dirty_tx; 	/* The ring entries to be free()ed. */
    unsigned int	last_tx_intr;
#if LE1000_CHEKS_TX_RING
    unsigned int od_tx, oc_tx;
#endif
	struct napi_struct napi;
	int napi_scheduled;
	int napi_wanted;
	int xmit_enabled_intr;
    struct net_device_stats stats;
    char		tx_full;
    char		revision;
    int			options;
    unsigned int	shared_irq:1,	/* shared irq possible */
			dxsuflo:1,	/* disable transmit stop on uflo */
			mii:1;		/* mii port available */
    struct mii_if_info	mii_if;
    struct timer_list	watchdog_timer;
    struct timer_list	blink_timer;
    struct sk_buff      *skb_to_pause;
    dma_addr_t          skb_to_pause_dma;
    int                 skb_to_pause_sent;
    int			rx_coal_usec;   /* Delay after first rx_pkt to raise interrupt */
    int			tx_coal_frame;	/* Not raise intr until send this nmbr of pkts */ 

    u32			msg_enable;	/* debug message level */
	/* For IEEE 1588 */
	struct hwtstamp_config hwtstamp_config;
	struct ptp_clock *ptp_clock;
	struct ptp_clock_info ptp_clock_info;
	int			csr_1588;
	spinlock_t		systim_lock;
	struct cyclecounter	cc;
	struct timecounter	tc;
};

static irqreturn_t e1000_interrupt(int , void *);
static int mdio_read(struct net_device* , int , int);
static void e1000_set_phy_mode(struct net_device *dev);
static void dump_init_block(struct net_device *dev);
static int e1000_restart(struct net_device *dev, unsigned int csr0_bits);
static void e1000_kick_xmit(struct e1000_private *ep);

static int assigned_speed = SPEED_1000;
module_param_named(speed, assigned_speed, int, 0444);
MODULE_PARM_DESC(speed, "used to restrict speed to 10 or 100");
static int half_duplex;
module_param_named(hd, half_duplex, int, 0444);
MODULE_PARM_DESC(hd, "work in half duplex mode");
static int num_tx_bufs_to_clean = TX_RING_SIZE;
module_param_named(tx_bufs_to_clean, num_tx_bufs_to_clean, int, 0444);
MODULE_PARM_DESC(tx_bufs_to_clean, "num txbufs to clean in xmit");
static int do_pause_sender;
module_param_named(pause_sender, do_pause_sender, int, 0444);
MODULE_PARM_DESC(pause_sender, "pause sender in case of FIFO error");


static unsigned char pause_packet[ETH_ZLEN] = {
       0x01, 0x80, 0xC2, 0x00, 0x00, 0x01,     /* dest MAC */
       0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     /* will be my MAC */
       0x88, 0x08,                             /* type/lengh */
       0x00, 0x01,                             /* the PAUSE opcade */
       0x00, 0xEF                              /* pause value */
};

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
	s64 now;

	spin_lock_irqsave(&ep->systim_lock, flags);
	now = timecounter_read(&ep->tc);
	now += delta;
	timecounter_init(&ep->tc, &ep->cc, now);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

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
static int le1000_phc_gettime(struct ptp_clock_info *ptp, struct timespec *ts)
{
	struct e1000_private *ep = container_of(ptp, struct e1000_private,
						     ptp_clock_info);
	unsigned long flags;
	u32 remainder;
	u64 ns;

	spin_lock_irqsave(&ep->systim_lock, flags);
	ns = timecounter_read(&ep->tc);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

	ts->tv_sec = div_u64_rem(ns, NSEC_PER_SEC, &remainder);
	ts->tv_nsec = remainder;

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
			      const struct timespec *ts)
{
	struct e1000_private *ep = container_of(ptp, struct e1000_private,
						     ptp_clock_info);
	unsigned long flags;
	u64 ns;

	ns = timespec_to_ns(ts);

	/* reset the timecounter */
	spin_lock_irqsave(&ep->systim_lock, flags);
	timecounter_init(&ep->tc, &ep->cc, ns);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

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
	struct e1000_private *ep = container_of(ptp, struct e1000_private,
						     ptp_clock_info);

	if (rq->type == PTP_CLK_REQ_PPS) {
		pr_warn("le1000_phc_enable: TODO: call to mpv pps init\n");
		/* mpv_set_pps(on);*/
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
	.gettime	= le1000_phc_gettime,
	.settime	= le1000_phc_settime,
	.enable		= le1000_phc_enable,
};


static int debug = -1;

static int e1000_debug = 0;

#define l_e1000_netif_msg_reset(dev) \
       ((dev)->msg_enable & (NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR))


static int l_e1000_supports_msix(struct pci_dev *pdev)
{
	if ((pdev->vendor == PCI_VENDOR_ID_MCST_TMP) &&
		(pdev->device == 0x8022)) {
		return 4;
	}
	return 0;
}

static int l_e1000_supports_msi(struct pci_dev *pdev)
{
	return ((pdev->vendor == PCI_VENDOR_ID_MCST_TMP) &&
		(pdev->device == 0x8022));
}


#if LE1000_CHEKS_TX_RING
static void dump_tx_ring_state(struct e1000_private *ep);

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
	pr_warning("check_tx_ring %s: %s: %s %d\n",
		ep->dev->name, str, reason, i);
	pr_warning("Pevious values: cur_tx = %u, dirty_tx = %u\n",
		ep->oc_tx, ep->od_tx);
	dump_tx_ring_state(ep);
	checked--;
	return 1;
}
#else
#define	check_tx_ring(a,b) {}
#endif

static const char *version = DRV_NAME ".c:v" DRV_VERSION " " DRV_RELDATE " alexmipt@mcst.ru\n";

/* l_e1000_ptp_read - utility function which is used in init timecounter only
 */
static cycle_t l_e1000_ptp_read(const struct cyclecounter *cc)
{
	return 0; /* it is need for init only */
}

/* For IEEE-1588 testing in KPI-2 */
static u32 max_min_tstmp[8] = {0, 0, 0xffffffff, 0xffffffff, 0, 0, 0, 0};
#define	MAX_TX_TSMP	0
#define	MAX_RX_TSMP	1
#define	MIN_TX_TSMP	2
#define	MIN_RX_TSMP	3
#define	LST_TX_TSMP	4
#define	LST_RX_TSMP	5
#define	PRV_TX_TSMP	6
#define	PRV_RX_TSMP	7
/**
 * l_e1000_hwtstamp - utility function for IEEE 1588 in IOHUB2
 * @ep: board private structure
 * @skb: particular skb to include time stamp
 * @entry: descriptor entry
 *
 * If the time stamp is valid, convert it into the timecounter ns value
 * and store that result into the shhwtstamps structure which is passed
 * up the network stack.
 **/
static void l_e1000_hwtstamp(struct e1000_private *ep, struct sk_buff *skb,
	u32 etmr)
{
	u64 ns;
	struct skb_shared_hwtstamps *hwtstamps;
	unsigned long flags;

/*
	skb->tstamp = ktime_get_real();
*/
	spin_lock_irqsave(&ep->systim_lock, flags);
	ns = timecounter_cyc2time(&ep->tc, etmr);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ns);
}

static void dump_ring_state(struct net_device *dev);

static u32 e1000_read_e_csr(struct e1000_private *ep){
	u32 val = 0;
	if (ep->base_ioaddr){
		val = readl(ep->base_ioaddr + E_CSR);
		DEBUG_RD_E_CSR("=== e_csr >>>---->>> 0x%x\n", val);
		return val;
	}
	return 0xabcdefab;
}

static void e1000_write_e_csr(struct e1000_private *ep, int val)
{
	if (ep->base_ioaddr)
		writel(val, ep->base_ioaddr + E_CSR);
}

static u32 e1000_read_mgio_csr(struct e1000_private *ep)
{
	if (ep->base_ioaddr)
		return readl(ep->base_ioaddr + MGIO_CSR);

	return 0xabcdefab;
}

static void e1000_write_mgio_csr(struct e1000_private *ep, int val)
{
	if (ep->base_ioaddr)
		writel(val, ep->base_ioaddr + MGIO_CSR);
}

static u32 e1000_read_mgio_data(struct e1000_private *ep)
{
	if (ep->base_ioaddr)
		return readl(ep->base_ioaddr + MGIO_DATA);

	return 0xabcdefab;
}

static void e1000_write_mgio_data(struct e1000_private *ep, int val)
{
	if (ep->base_ioaddr)
		writel(val, ep->base_ioaddr + MGIO_DATA);
}

static u32 e1000_read_e_base_address(struct e1000_private *ep)
{
	if (ep->base_ioaddr)
		return readl(ep->base_ioaddr + E_BASE_ADDR);

	return 0xabcdefab;
}

static void e1000_write_e_base_address(struct e1000_private *ep, int val)
{
	if (ep->base_ioaddr)
		writel(val, ep->base_ioaddr + E_BASE_ADDR);
}

static u32 e1000_read_dma_base_address(struct e1000_private *ep)
{
	if (ep->base_ioaddr)
		return readl(ep->base_ioaddr + DMA_BASE_ADDR);

	return 0xabcdefab;
}

static void e1000_write_dma_base_address(struct e1000_private *ep, int val){
	if (ep->base_ioaddr){
		writel(val, ep->base_ioaddr + DMA_BASE_ADDR);
	}
}

static u32 e1000_read_psf_csr(struct e1000_private *ep){
	if (ep->base_ioaddr){
		return readl(ep->base_ioaddr + PSF_CSR);
	}
	return 0xabcdefab;
}

static void e1000_write_psf_csr(struct e1000_private *ep, int val){
	if (ep->base_ioaddr){
		writel(val, ep->base_ioaddr + PSF_CSR);
	}
}

static u32 e1000_read_psf_data(struct e1000_private *ep){
	if (ep->base_ioaddr){
		return readl(ep->base_ioaddr + PSF_DATA);
	}
	return 0xabcdefab;
}

static void e1000_write_psf_data(struct e1000_private *ep, int val){
	if (ep->base_ioaddr){
		writel(val, ep->base_ioaddr + PSF_DATA);
	}
}

static struct e1000_access e1000_io = {
	.read_e_csr 		= 	e1000_read_e_csr,
    	.write_e_csr		=	e1000_write_e_csr,
	.read_mgio_csr		=	e1000_read_mgio_csr,	
	.write_mgio_csr		=	e1000_write_mgio_csr,
    	.read_mgio_data		=	e1000_read_mgio_data,
    	.write_mgio_data	=	e1000_write_mgio_data,
    	.read_e_base_address	=	e1000_read_e_base_address,
	.write_e_base_address	=	e1000_write_e_base_address,	
	.read_dma_base_address	=	e1000_read_dma_base_address,
	.write_dma_base_address	=	e1000_write_dma_base_address,
	.read_psf_csr		=	e1000_read_psf_csr,
	.write_psf_csr		=	e1000_write_psf_csr,
	.read_psf_data		=	e1000_read_psf_data,
	.write_psf_data		=	e1000_write_psf_data
};

static char *chipname = "L-E1000";

static void e1000_watchdog(unsigned long arg)
{
    struct net_device *dev = (struct net_device *)arg;
    struct e1000_private *ep = netdev_priv(dev);

    /* Print the link status if it has changed */
    if (ep->mii) {
	e1000_set_phy_mode(dev);
	mii_check_media (&ep->mii_if, netif_msg_link(ep), 0);
    }

    mod_timer (&(ep->watchdog_timer), E1000_WATCHDOG_TIMEOUT);
}

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
		 * called for load? */
		mcast_table[crc >> 4] = cpu_to_le16((mcast_table[crc >> 4]) |
						    (1 << (crc & 0xf)));
	}
	return;
}

/* Initialize the E1000 Rx and Tx rings. */
static int
e1000_init_ring(struct net_device *dev)
{
    struct e1000_private *ep = netdev_priv(dev);
    int i;

    ep->tx_full = 0;
    ep->cur_rx = ep->cur_tx = 0;
    ep->last_tx_intr = 0;
    ep->dirty_tx = 0;

    for (i = 0; i < RX_RING_SIZE; i++) {
	struct sk_buff *rx_skbuff = ep->rx_skbuff[i];
	if (rx_skbuff == NULL) {
	    if (!(rx_skbuff = ep->rx_skbuff[i] = dev_alloc_skb (PKT_BUF_SZ + CRC_SZ + 2))) {
		/* there is not much, we can do at this point */
		if (e1000_debug & NETIF_MSG_DRV)
		    printk(KERN_ERR "%s: e1000_init_ring dev_alloc_skb failed.\n",
			    dev->name);
		return -1;
	    }
	    skb_reserve (rx_skbuff, 2);
	}

	rmb();
	if (ep->rx_dma_addr[i] == 0)
	    ep->rx_dma_addr[i] = pci_map_single(ep->pci_dev, rx_skbuff->data,
		    (PKT_BUF_SZ + CRC_SZ), PCI_DMA_FROMDEVICE);
	ep->rx_ring[i].base = cpu_to_le32((u32)(ep->rx_dma_addr[i]));
	ep->rx_ring[i].buf_length = cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
	wmb();	/* Make sure owner changes after all others are visible */
	ep->rx_ring[i].status |= cpu_to_le16(RX_ST_OWN);
	DEBUG_INIT_RING("e1000_init_ring(): make recieve buf %d, "
	       		"base = 0x%x , buf_len = 0x%x [0x%x]\n", 
			i, le32_to_cpu(ep->rx_ring[i].base),
			le16_to_cpu(ep->rx_ring[i].buf_length), (PKT_BUF_SZ + CRC_SZ));
    }
    /* The Tx buffer address is filled in as needed, but we do need to clear
     * the upper ownership bit. */
    for (i = 0; i < TX_RING_SIZE; i++) {
	ep->tx_ring[i].status = 0;	/* CPU owns buffer */
	wmb();	/* Make sure adapter sees owner change */
	ep->tx_ring[i].base = 0;
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
    DEBUG_INIT_RING("e1000_init_ring: Receive  Desc Ring DMA Addr | Rlen[3:0]: 0x%x\n", 
						le32_to_cpu(ep->init_block->rdra));
    DEBUG_INIT_RING("e1000_init_ring: Transmit Desc Ring DMA Addr | Tlen[3:0]: 0x%x\n",  
						le32_to_cpu(ep->init_block->tdra));
    DEBUG_INIT_RING("e1000_init_ring: init block mode: 0x%x\n", le16_to_cpu(ep->init_block->mode));

    if (ep->csr_1588) {
	    ep->cc.read = l_e1000_ptp_read;
	    ep->cc.mask = CLOCKSOURCE_MASK(32);
	    ep->cc.shift = 22;
	    /* mult = (1 << shift) / freq */
	    ep->cc.mult = (1 << ep->cc.shift) / 125000000;
	    timecounter_init(&ep->tc, &ep->cc, ktime_to_ns(ktime_get_real()));
    }
    wmb();	/* Make sure all changes are visible */
    return 0;
}

static int
e1000_open(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	int rc, i;
	int val;
	unsigned int init_block_addr_part = 0;
	unsigned long irqflags = IRQF_NO_THREAD |
				(ep->shared_irq ? IRQF_SHARED : 0);
	if (netif_msg_ifup(ep))
	    printk(KERN_DEBUG "e1000_open(): begin\n");
	
	/* Reset the PCNET32 */
	ep->a->write_e_csr(ep, STOP);

       /* wait for stop */
        for (i=0; i<1000; i++)
            if (ep->a->read_e_csr(ep) & STOP)
              break;

        if (i >= 100 && netif_msg_drv(ep)) {
            printk(KERN_ERR "%s: e1000_restart timed out waiting for stop.\n",
                dev->name);
		return -EAGAIN;
        }

	napi_enable(&ep->napi);

	/* No  harm to request irq so early. Card stopped */
	if (ep->msix_entries) {
		// MSIX supported
		ep->irq = ep->msix_entries[ep->bar].vector;
		DEBUG_IRQ("%s uses MSIX irq %d\n", dev->name, ep->irq);
	} else {
		ep->irq = ep->pci_dev->irq;
	}
	rc = request_irq(ep->irq, &e1000_interrupt,
			irqflags, dev->name, (void *)dev);
	if (rc) {
		napi_disable(&ep->napi);
		pr_err("%s: Could not request irq %d\n", dev->name, dev->irq);
		return rc;
	}
	/* Check for a valid station address */
	if (!is_valid_ether_addr(dev->dev_addr)) {
		rc = -EINVAL;
		goto err_free_irq;
	}
	

	ep->init_block->mode = le16_to_cpu(e1000_mode);
	ep->init_block->laddrf = 0x0000000000000000;
	
	if (netif_msg_ifup(ep))
		printk(KERN_DEBUG "%s: e1000_open(): irq %u tx/rx rings %#llx/%#llx "
				  "init %#llx.\n",
	       		dev->name, dev->irq,
	       		(u64)(ep->dma_addr + offsetof(struct e1000_dma_area, tx_ring)),
	       		(u64)(ep->dma_addr + offsetof(struct e1000_dma_area, rx_ring)),
	       		(u64)(ep->dma_addr + offsetof(struct e1000_dma_area, init_block)));

	e1000_load_multicast(dev);
	/* Re-initialize the PCNET32, and start it when done. */
	/* low 32 bits */
	init_block_addr_part = (ep->dma_addr + offsetof(struct e1000_dma_area,
		    		init_block)) & 0xffffffff;
	ep->a->write_e_base_address(ep, init_block_addr_part);
	/* high 32 bits */
	init_block_addr_part = ((u64)(ep->dma_addr + offsetof(struct e1000_dma_area,
		    		init_block)) >> 32) & 0xffffffff; 
	ep->a->write_dma_base_address(ep, init_block_addr_part);

        /* Setup PHY MII/GMII enable */
        val = mdio_read(dev, ep->mii_if.phy_id, PHY_AUX_CTRL);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x12 (AUX_CTRL) : "
                "           :             0x%x\n", val);
        /* Setup PHY 10/100/1000 Link on 10M Link */
        val = mdio_read(dev, ep->mii_if.phy_id, PHY_LED_CTRL);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x13 (LED_CTRL) : "
                "           :             0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x0      (BMCR) : "
                "           :             0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0x1);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x1             : "
                "first reading :          0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0x1);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x1             : "
                "second reading :         0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0x10);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x10            : "
                "           :             0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0x11);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x11            : "
                "           :             0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0x14);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x14            : "
                "           :             0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, 0x15);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x15            : "
                "           :             0x%x\n", val);
        val = mdio_read(dev, ep->mii_if.phy_id, PHY_BIST_CFG2);
        DEBUG_MDIO_RD("e1000_open: PHY reg # 0x1a (BIST_CFG2): "
                "           :             0x%x\n", val);
	
  	/* If we have mii, print the link status and start the watchdog */
	if (ep->mii) {
		e1000_set_phy_mode(dev);
		mii_check_media (&ep->mii_if, netif_msg_link(ep), 1);
		mod_timer (&(ep->watchdog_timer), E1000_WATCHDOG_TIMEOUT);
	}

	/* start e1000 */
	if (e1000_restart(dev, INEA|STRT)) {
		rc = -ENOMEM;
		goto err_free_ring;
	}
	/*le1000_ptp_init(ep);*/

	if (netif_msg_ifup(ep))
	    printk(KERN_DEBUG "e1000_open(): end\n");

	return 0;	/* Always succeed */	

err_free_ring:
    /* free any allocated skbuffs */
    for (i = 0; i < RX_RING_SIZE; i++) {
	ep->rx_ring[i].status = 0;
	if (ep->rx_skbuff[i]) {
	    pci_unmap_single(ep->pci_dev, ep->rx_dma_addr[i], (PKT_BUF_SZ + CRC_SZ),
		    PCI_DMA_FROMDEVICE);
	    dev_kfree_skb(ep->rx_skbuff[i]);
	}
	ep->rx_skbuff[i] = NULL;
	ep->rx_dma_addr[i] = 0;
    }

err_free_irq:
//    raw_spin_unlock_irqrestore(&ep->lock, flags);
    free_irq(ep->irq, dev);
    napi_disable(&ep->napi);
    if (netif_msg_ifup(ep))
	    printk(KERN_DEBUG "%s: e1000_open(): end badlyi. rc = %d\n", dev->name, rc);
    return rc;
}

static void try_to_cleanup_tx_bufs(struct e1000_private *ep,
				struct net_device *dev)
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
			printk("try_to_cleanup_tx_bufs: base == 0 on first loop ? cur = %d, dirty = %d\n",
				ep->cur_tx, ep->dirty_tx);
			break;
		}
		status = (short)le16_to_cpu(ep->tx_ring[dirty_tx].status);
		if (status < 0) {
			break;   /* It still hasn't been Txed */
		}
		if (status & TD_ERR) {
			break;
		}
		first_loop = 0;
		ep->tx_ring[dirty_tx].base = 0;
		ep->tx_ring[dirty_tx].status = 0;

		if (status & (TD_MORE|TD_ONE))
			ep->stats.collisions++;
		ep->stats.tx_packets++;
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
#else
				pci_unmap_single(ep->pci_dev, dmaaddr,
				skb->len, PCI_DMA_TODEVICE);
#endif
				dev_kfree_skb_irq(skb);
			} else {
				ep->skb_to_pause_sent = 0;
			}
                }
                dirty_tx = (dirty_tx + 1) & (TX_RING_MOD_MASK);
	}
	ep->dirty_tx = dirty_tx;
	if (netif_msg_tx_err(ep)) {
		pr_info("%s: try_to_cleanup_tx_bufs : %d bufs cleaned\n",
				dev->name, num);
	}
}


static int
e1000_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
    struct e1000_private *ep = netdev_priv(dev);
    s16 status;
    int entry;
//	int delta;
    unsigned long flags;
    void *packet;
    struct ethhdr *eth;
    int i;
    int len;
    dma_addr_t dmaaddr;
 
    len = (skb->len <= ETH_ZLEN) ? ETH_ZLEN : skb->len;

    if (netif_queue_stopped(dev))
	return 1;

    if (skb->len < ETH_ZLEN) {
	if (skb_padto(skb, ETH_ZLEN)) {
	    /* there is not much, we can do at this point */
	    if (netif_msg_tx_err(ep))
		printk(KERN_ERR "%s: e1000_start_xmit skb_padto failed.\n",
			dev->name);
	    return -1;
	}
	skb->len = ETH_ZLEN;
    }
    // we map it here out from raw_spinlock because mapping locks mutex
    if (skb == ep->skb_to_pause) {
    	dmaaddr = ep->skb_to_pause_dma;
    } else {
        dmaaddr = pci_map_single(ep->pci_dev, skb->data, len,
             PCI_DMA_TODEVICE);
    }
    raw_spin_lock_irqsave(&ep->lock, flags);

	check_tx_ring(ep, "start_xmit begin");

    /* Mask to ring buffer boundary. */
	entry = ep->cur_tx;

	if (skb == ep->skb_to_pause) {
	if (ep->tx_ring[entry].base != 0 ||
		ep->tx_ring[(entry + 1) & TX_RING_MOD_MASK].base != 0) {
		try_to_cleanup_tx_bufs(ep, dev);
	}
	if (ep->tx_ring[entry].base != 0 ||
		ep->tx_ring[(entry + 1) & TX_RING_MOD_MASK].base != 0) {
		/* we need at least 2 free tx descs - one for us
		 * and 1 for possible general pkt
		 */
		raw_spin_unlock_irqrestore(&ep->lock, flags);
		if (netif_msg_rx_err(ep)) {
			printk("%s: Could not send pause packet to sender\n",
				dev->name);
		}
		return -1;
	}
	if (netif_msg_rx_err(ep)) {
		printk("%s: Send pause packet to sender\n", dev->name);
	}

     }

    /* Default status -- will not enable Successful-TxDone
     * interrupt when that option is available to us.
     */
    status = TX_ST_OWN | TX_ST_ENP | TX_ST_STP;

    /* Fill in a Tx ring entry */

    /* Mask to ring buffer boundary. */

    /* Caution: the write order is important here, set the status
     * with the "ownership" bits last. */

    if (CAN_DISABLE_TXINT(ep)) {
	unsigned int num_dirties =
	       (ep->cur_tx - ep->last_tx_intr) & TX_RING_MOD_MASK;
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
    ep->tx_dma_addr[entry] = dmaaddr;
    ep->tx_ring[entry].base = cpu_to_le32((u32)(ep->tx_dma_addr[entry]));
    wmb(); /* Make sure owner changes after all others are visible */
    ep->tx_ring[entry].status = cpu_to_le16(status);

    ep->cur_tx = (ep->cur_tx + 1) & TX_RING_MOD_MASK;
    ep->stats.tx_bytes += len;

    if (netif_msg_tx_queued(ep))
    	printk("i%s: e1000_start_xmit: base: 0x%x; buf_length: 0x%x [0x%x]"
	       " status: 0x%x; misc: 0x%x\n", dev->name,
		le32_to_cpu(ep->tx_ring[entry].base),
		le16_to_cpu(ep->tx_ring[entry].buf_length),
		len,
		le16_to_cpu(ep->tx_ring[entry].status),
		le32_to_cpu(ep->tx_ring[entry].misc));

    packet = (void *) ep->tx_skbuff[entry]->data;
    eth = (struct ethhdr *) packet;
    if (netif_msg_pktdata(ep)){
    	for (i = 0; i != 6; i++){
		printk("e1000_start_xmit: eth: src 0x%x, dst 0x%x\n",
			eth->h_source[i], eth->h_dest[i]);
	}
    	for (i = 0; i != ((len) / 4); i++){
       		printk("TX packet: int # %d  0x%x \n", i, *(u32 *)packet);
		packet += 4;
    	}
    	for (i = 0; i != ((len) % 4); i++){
    	    printk("TX packet: byte # %d  0x%x \n", i, *(u8 *)packet);
	    packet += 1;
    	}
    }	

    /* Trigger an immediate send poll. */
    e1000_kick_xmit(ep);

    dev->trans_start = jiffies;
    if (ep->tx_ring[ep->cur_tx].base != 0) {
    	check_tx_ring(ep, "xmit tries to clean");
	try_to_cleanup_tx_bufs(ep, dev);
    	check_tx_ring(ep, "xmit  after clean");
    }
    if (ep->tx_ring[ep->cur_tx].base != 0) {
        if (netif_msg_tx_err(ep)) {
		printk("%s: transmitter queue is full "
			"cur_tx = %d, dirty_tx =%d\n",
			dev->name, ep->cur_tx, ep->dirty_tx);
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
		printk("%s: transmitter was unqueueed from xmit"
			"cur_tx= %d, dirty_tx= %d\n",
			dev->name, ep->cur_tx, ep->dirty_tx);
	}
    }
    check_tx_ring(ep, "end_xmit begin");
    raw_spin_unlock_irqrestore(&ep->lock, flags);
    return 0;
}

static int
e1000_rx(struct e1000_private *ep, int budget)
{
    int entry = ep->cur_rx & RX_RING_MOD_MASK;
    struct net_device *dev = ep->dev;
    int boguscnt = RX_RING_SIZE;
    int work_done = 0;

    /* If we own the next entry, it's a new packet. Send it up. */
    while (((s16)le16_to_cpu(ep->rx_ring[entry].status)) >= 0) {
	int status = (short)le16_to_cpu(ep->rx_ring[entry].status);

	if (work_done == budget) {
		if (netif_msg_rx_err(ep)) {
			printk("%s: rx budget %d overloaded.\n",
				dev->name, budget); 
		}
		break;
	}
	
	DEBUG_E1000_RX("interrupt->e1000_rx: status = 0x%x\n", status);
	if ((status & 0xff00) != (RD_ENP|RD_STP)) {/* There was an error. */
		if (netif_msg_rx_err(ep)) {
			ep->stats.rx_errors++;
			printk("%s reciever error: bl=0x%x, ml=0x%x."
				" error status = 0x%x ", dev->name,
 				(short)le16_to_cpu(ep->rx_ring[entry].buf_length),
 				(short)le16_to_cpu(ep->rx_ring[entry].msg_length),
				status);
		}
	    /*
	     * There is a tricky error noted by John Murphy,
	     * <murf@perftech.com> to Russ Nelson: Even with full-sized
	     * buffers it's possible for a jabber packet to use two
	     * buffers, with only the last correctly noting the error.
	     */
	    if (status & RD_ENP) {
	        if (netif_msg_rx_err(ep)) {
			printk(" ENP");
		} /* No detailed rx_errors counter to increment at the */
			/* end of a packet.*/
	    }
	    if (status & RD_FRAM) {
	        if (netif_msg_rx_err(ep)) {
			printk(" FRAM");
		}
		ep->stats.rx_frame_errors++;
	    }	
	    if (status & RD_OFLO) {
	        if (netif_msg_rx_err(ep)) {
	              printk(" OFLO ");
		}
               ep->stats.rx_over_errors++;
            }
	    if (status & RD_CRC) {
	        if (netif_msg_rx_err(ep)) {
			printk(" CRC ");
		}
               ep->stats.rx_crc_errors++;
            }
	    if (status & RD_BUFF) {
	        if (netif_msg_rx_err(ep)) {
	               printk(" BUFF ");
		}
               ep->stats.rx_fifo_errors++;
            }
	    if (netif_msg_rx_err(ep)) {
	            printk("\n");
	    }
	    ep->rx_ring[entry].status &= cpu_to_le16(RD_ENP|RD_STP);
	} else {
	    /* Malloc up new buffer, compatible with net-2e. */
	    short pkt_len = (le16_to_cpu(ep->rx_ring[entry].msg_length) & 0xfff) - CRC_SZ;
	    struct sk_buff *skb;

	    /* Discard oversize frames. */
	    if (unlikely(pkt_len > PKT_BUF_SZ)) {
		if (netif_msg_rx_err(ep))
		    printk("%s: Impossible packet size %d!\n",
			    dev->name, pkt_len);
		ep->stats.rx_errors++;
	    } else if (pkt_len < 60) {
		if (netif_msg_rx_err(ep))
		    printk("%s: Runt packet!\n", dev->name);
		ep->stats.rx_errors++;
	    } else {
		int rx_in_place = 0;

		if (pkt_len > rx_copybreak) {
		    struct sk_buff *newskb;
		    
		    if ((newskb = netdev_alloc_skb(dev, PKT_BUF_SZ + CRC_SZ + 2))) {
			skb_reserve (newskb, 2);
			skb = ep->rx_skbuff[entry];
			pci_unmap_single(ep->pci_dev, ep->rx_dma_addr[entry],
					(PKT_BUF_SZ + CRC_SZ), PCI_DMA_FROMDEVICE);
			skb_put (skb, pkt_len);
			ep->rx_skbuff[entry] = newskb;
			newskb->dev = dev;
			ep->rx_dma_addr[entry] =
			    pci_map_single(ep->pci_dev, newskb->data,
				    (PKT_BUF_SZ + CRC_SZ), PCI_DMA_FROMDEVICE);
			ep->rx_ring[entry].base = 
					cpu_to_le32(ep->rx_dma_addr[entry]);
			rx_in_place = 1;
			DEBUG_E1000_RX("interrupt->e1000_rx: new sbk is alloced, "
			       "rx_in_place = 1\n");
		    } else {
			DEBUG_E1000_RX("interrupt->e1000_rx: new sbk is failed to alloc\n");
			skb = NULL;
		    }
		} else {
			DEBUG_E1000_RX("interrupt->e1000_rx: pkt_len 0x%x <= rx_copybreak 0x%x\n",
                                pkt_len, rx_copybreak);
		    skb = netdev_alloc_skb(dev, pkt_len + 2);
		}

		if (skb == NULL) {
		    int i;
		    if (netif_msg_rx_err(ep))
			printk("%s: Memory squeeze, deferring packet.\n",
				dev->name);
		    for (i = 0; i < RX_RING_SIZE; i++)
			if ((short)le16_to_cpu(ep->rx_ring[(entry+i)
				    & RX_RING_MOD_MASK].status) < 0)
			    break;

		    if (i > RX_RING_SIZE - 2) {
			ep->stats.rx_dropped++;
			ep->rx_ring[entry].status = 0;
			ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
			wmb();	/* Make sure adapter sees owner change */
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
			max_min_tstmp[PRV_RX_TSMP] =
				max_min_tstmp[LST_RX_TSMP];
			max_min_tstmp[LST_RX_TSMP] = et;
		}
		if (netif_msg_1588(ep)) {
			u32 et = le32_to_cpu(ep->rx_ring[entry].etmr);
			if (rx_prev_etmr >= et) {
				pr_warn("%s cs=%7x Rx= 0x%8x prv= 0x%8x "
					" maxt %8x r %8x c=%16llu\n",
					dev->name, ep->csr_1588,
					et, rx_prev_etmr,
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
		    DEBUG_E1000_RX("interrupt->e1000_rx: rx_in_place = 0\n");
		    skb_reserve(skb,2); /* 16 byte align */
		    skb_put(skb,pkt_len);	/* Make room */
		    pci_dma_sync_single_for_cpu(ep->pci_dev,
						ep->rx_dma_addr[entry],
						(PKT_BUF_SZ + CRC_SZ),
						PCI_DMA_FROMDEVICE);
		    packet = (void *) ep->rx_skbuff[entry]->data;
		    eth = (struct ethhdr *) packet;
		    for (i = 0; i != 6; i++){
			DEBUG_E1000_RX_HEAD("interrupt->e1000_rx: eth: src 0x%x, dst 0x%x\n",
				eth->h_source[i], eth->h_dest[i]);
		    }
		    for (i = 0; i != (pkt_len / 4); i++){
		    	DEBUG_E1000_RX_BODY("RX packet: int # %d  0x%x \n", i, *(u32 *)packet);
			packet += 4;
		    }
		    for (i = 0; i != (pkt_len % 4); i++){
                        DEBUG_E1000_RX_BODY("RX packet: byte # %d  0x%x \n", i, *(u8 *)packet);
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
		skb->protocol=eth_type_trans(skb,dev);
		netif_receive_skb(skb);
		dev->last_rx = jiffies;
		ep->stats.rx_packets++;
		ep->a->write_e_csr(ep, RINT | ep->csr_1588);
		work_done++;
	    }

	}
	/*
	 * The docs say that the buffer length isn't touched, but Andrew Boyd
	 * of QNX reports that some revs of the 79C965 clear it.
	 */
	ep->rx_ring[entry].buf_length = cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
	wmb(); /* Make sure owner changes after all others are visible */
	ep->rx_ring[entry].status = 0;
	ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
	entry = (++ep->cur_rx) & RX_RING_MOD_MASK;
#ifdef CONFIG_MCST
	if (!net_dev_has_own_threads(dev))
#endif
		if (--boguscnt <= 0) {	/* don't stay in loop forever */
			if (netif_msg_rx_err(ep)) {
               		        printk("%s: %d pkts recieved. Recieve deffered\n",
					dev->name, -boguscnt + RX_RING_SIZE + 1);
			}
			break;
		}
    }

    return work_done;
}

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

		if (netif_msg_intr(ep))
			pr_info("%s: TX interrupt: status = 0x%x\n",
				 dev->name, status);
		if (status < 0)
			break; /* It still hasn't been Txed */
		first_loop = 0;

		if (status & TD_ERR) {
			if (netif_msg_intr(ep))
				pr_info("%s: TX interrupt: base: 0x%x; "
					"buf_length: 0x%x; "
					"status: 0x%x; misc: 0x%x\n",
					dev->name,
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

			if (netif_msg_intr(ep))
				pr_info("%s: TX interrupt: misc = 0x%x\n",
					 dev->name, err_status);
			ep->stats.tx_errors++;

			if (netif_msg_tx_err(ep))
				pr_err("%s: Tx error status=%04x err_status=%08x\n",
					dev->name, status, err_status);
			if (err_status & TD_RTRY)
				ep->stats.tx_aborted_errors++;
			if (err_status & TD_LCAR)
				ep->stats.tx_carrier_errors++;
			if (err_status & TD_LCOL)
				ep->stats.tx_window_errors++;
#ifndef DO_DXSUFLO
		    if (err_status & TD_UFLO) {
			ep->stats.tx_fifo_errors++;
			/* Ackk!  On FIFO errors the Tx unit is turned off! */
			/* Remove this verbosity later! */
			if (netif_msg_tx_err(ep))
				pr_err("%s: Tx UFLO error!\n", dev->name);
			must_restart = 1;
		    }
#else
		    if (err_status & TD_UFLO) {
			ep->stats.tx_fifo_errors++;
			if (!ep->dxsuflo) {
				/* If controller doesn't recover ... */
				/* Ack! On FIFO errors the Tx unit is
				 * turned off! */
				/* Remove this verbosity later! */
				if (netif_msg_tx_err(ep))
					printk(KERN_ERR "%s: Tx UFLO error! CSR0=%4.4x\n",
						dev->name, csr0);
				must_restart = 1;
			}
		    }
#endif
		} else {
		    if (status & (TD_MORE|TD_ONE))
			ep->stats.collisions++;
		    ep->stats.tx_packets++;
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
				if (et == 0 ||
					tx_prev_etmr > et) {
					pr_warn("%s cs=%7x Tx= 0x%8x prv= 0x%8x"
						" maxt %8x r %8x c=%16llu\n",
						dev->name, ep->csr_1588, et,
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
				pci_unmap_single(ep->pci_dev, dmaaddr,
					 skb->len, PCI_DMA_TODEVICE);
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
		if (netif_msg_tx_err(ep))
			pr_info("%s: transmitter was unqueueed "
				"cur_tx = %d, dirty_tx = %d\n",
				dev->name, ep->cur_tx, ep->dirty_tx);
	}
no_unqueue:
	check_tx_ring(ep, "e1000_tx end");
	raw_spin_unlock_irqrestore(&ep->lock, flags);

	return must_restart;
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

static void
e1000_purge_tx_ring(struct net_device *dev)
{
    struct e1000_private *ep = netdev_priv(dev);
    int i;

    for (i = 0; i < TX_RING_SIZE; i++) {
	ep->tx_ring[i].status = 0;	/* CPU owns buffer */
	wmb();	/* Make sure adapter sees owner change */
	if (ep->tx_skbuff[i] && (ep->tx_skbuff[i] != ep->skb_to_pause)) {
#ifdef CAN_UNMAP_SKB_IN_CONSUME
                ep->tx_skbuff[i]->dmaaddr = ep->tx_dma_addr[i];
		ep->tx_skbuff[i]->pci_dev = ep->pci_dev;
#else

		pci_unmap_single(ep->pci_dev, ep->tx_dma_addr[i],
		    ep->tx_skbuff[i]->len, PCI_DMA_TODEVICE);
#endif
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
    dev->trans_start = jiffies;
}

/* the e1000 has been issued a stop or reset.  Wait for the stop bit
 * then flush the pending transmit operations, re-initialize the ring,
 * and tell the chip to initialize.
 */
static int 
e1000_restart(struct net_device *dev, unsigned int csr0_bits)
{
	struct e1000_private *ep = netdev_priv(dev);
	int i;

	DEBUG_E1000_RESTART("e1000_restart: start\n");
	if (l_e1000_netif_msg_reset(ep)) {
		printk("%s: reset started\n", dev->name);
	}
	/* wait for stop */
	for (i = 0; i < 1000; i++)
		if (ep->a->read_e_csr(ep) & STOP)
			break;

	if (i >= 100 && netif_msg_drv(ep))
		pr_err("%s: e1000_restart timed out waiting for stop.\n",
			dev->name);

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
	ep->a->write_e_csr(ep, INIT | ep->csr_1588);
	i = 0;
	while (i++ < 1000)
		if (ep->a->read_e_csr(ep) & IDON)
			break;

	if (i >= 100 && l_e1000_netif_msg_reset(ep))
		pr_err("%s: initialization is not completed, status register "
			"0x%08x\n", dev->name, ep->a->read_e_csr(ep));

	DEBUG_E1000_RESTART("e1000_restart: e_csr register after "
			    "initialization: 0x%x, must be 0x%x\n",
			     ep->a->read_e_csr(ep), (IDON | INTR | INIT));

	ep->a->write_e_csr(ep, csr0_bits);
	if (l_e1000_netif_msg_reset(ep)) {
		printk("%s: reset done\n", dev->name);
		dump_init_block(dev);
	}
	DEBUG_E1000_RESTART("e1000_restart: finish\n");
	return 0;
}



static void e1000_pause_sender(struct e1000_private *ep)
{
	if (!ep->mii_if.full_duplex) {
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
	e1000_start_xmit(ep->skb_to_pause, ep->mii_if.dev);
		
}
 
 

/** The E1000 interrupt handlers. */
static irqreturn_t e1000_interrupt(int irq, void *dev_id)
{
	struct net_device *dev = dev_id;
	struct e1000_private *ep;
	u16 csr0, csr_ack;

	ep = netdev_priv(dev);
	csr0 = ep->a->read_e_csr(ep);
	if (!(csr0 & INTR))
		return IRQ_NONE; /* Not our interrupt */

	csr0 &= (BABL|CERR|MISS|MERR|RINT|TINT);

	if (ep->napi_scheduled) {
		/*
		 * e1000_kick_xmit occasualy enabled interrurpts
		 * Disable it and do nothing
		 */
again_1:
		ep->a->write_e_csr(ep, IDON | ep->csr_1588);
		/* Be sure it reached the card */
		if (ep->a->read_e_csr(ep) & INEA) {
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
	ep->a->write_e_csr(ep, (csr0 & ~(TINT | RINT)) | IDON | ep->csr_1588);

	if (netif_msg_intr(ep)) {
		pr_info("%s: interrupt  csr0=0x%x new csr=0x%x.\n",
			 dev->name, csr0, ep->a->read_e_csr(ep));
	}

	/* Log misc errors. */
	if (csr0 & BABL) {
		ep->stats.tx_errors++; /* Tx babble. */
		if (netif_msg_intr(ep)) {
			pr_info("%s: Babble (transmit timed out), status %4.4x.\n",
				 dev->name, csr0);
		}
		csr0 &= ~BABL;
	}

	if (csr0 & CERR) {
		ep->stats.collisions++;
		if (netif_msg_intr(ep)) {
			pr_info("%s: CERR (collisions), status %4.4x.\n",
				 dev->name, csr0);
		}
		csr0 &= ~CERR;
	}

	if (csr0 & MISS) {
		ep->stats.rx_errors++; /* Missed a Rx frame. */
		if (netif_msg_rx_err(ep)) {
			pr_info("%s: Receiver packet missed, status %4.4x.\n",
				 dev->name, csr0);
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
		ep->a->write_e_csr(ep, csr_ack | INEA | ep->csr_1588);

		return IRQ_HANDLED;
	}

	/* Do this before napi_schedule() to notify e1000_kick_xmit() faster */
	if (ep->xmit_enabled_intr) {
again_2:
		ep->a->write_e_csr(ep, ep->csr_1588);
		if (ep->a->read_e_csr(ep) & INEA) {
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
	ep->a->write_e_csr(ep, TINT | RINT | ep->csr_1588);
	/* Rx interrupt */
	work_done = e1000_rx(ep, budget);

	/* Tx interrupt */
	must_restart = e1000_tx(dev);

	if (must_restart) {
		/* reset the chip to clear the error condition, then restart */
		raw_spin_lock_irqsave(&ep->lock, flags);
		ep->a->write_e_csr(ep, STOP);
		e1000_restart(dev, STRT | ep->csr_1588);
		work_done = 0;
		raw_spin_unlock_irqrestore(&ep->lock, flags);
		netif_wake_queue(dev);
	}

	if (netif_msg_intr(ep))
		pr_info("%s: exiting interrupt, csr0=%x.\n",
			 dev->name, ep->a->read_e_csr(ep));

	if (work_done < budget || must_restart) {
		/*
		 * We are going to enable interrupts. Notify
		 * e1000_kick_xmit() about this.
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
			ep->a->write_e_csr(ep, INEA | ep->csr_1588);
		}
	}
	return work_done;
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
		ep->a->write_e_csr(ep, TDMD | ep->csr_1588);

		/* Check it again */
		if (!ep->napi_scheduled && !ep->napi_wanted) {
			/* Pairs with smp_wmb() in e1000_poll()
			 * and e1000_interrupt() */
			ep->xmit_enabled_intr = 1;
			smp_rmb();
			ep->a->write_e_csr(ep, INEA | ep->csr_1588);
		}
	} else {
		ep->xmit_enabled_intr = 1;
		ep->a->write_e_csr(ep, TDMD|INEA | ep->csr_1588);
	}
}
	
static int e1000_close(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	int i;

	del_timer_sync(&ep->watchdog_timer);

	if (netif_msg_ifdown(ep))
		pr_debug("%s: Shutting down ethercard, status was %2.2x.\n",
			  dev->name, ep->a->read_e_csr(ep));

	napi_disable(&ep->napi);
	netif_stop_queue(dev);

	/* We stop the PCNET32 here -- it occasionally polls memory
	 * if we don't. */
	ep->a->write_e_csr(ep, STOP);

	free_irq(ep->irq, dev);

	/* free all allocated skbuffs */
	for (i = 0; i < RX_RING_SIZE; i++) {
		ep->rx_ring[i].status = 0;
		ep->rx_ring[i].base = 0;
		wmb(); /* Make sure adapter sees owner change */

		if (ep->rx_skbuff[i]) {
			pci_unmap_single(ep->pci_dev, ep->rx_dma_addr[i],
					 (PKT_BUF_SZ + CRC_SZ),
					 PCI_DMA_FROMDEVICE);
			dev_kfree_skb(ep->rx_skbuff[i]);
		}

		ep->rx_skbuff[i] = NULL;
		ep->rx_dma_addr[i] = 0;
	}

	for (i = 0; i < TX_RING_SIZE; i++) {
		ep->tx_ring[i].status = 0;	/* CPU owns buffer */
		ep->tx_ring[i].base = 0;
		wmb(); /* Make sure adapter sees owner change */

		if (ep->tx_skbuff[i]) {
			pci_unmap_single(ep->pci_dev, ep->tx_dma_addr[i],
					 ep->tx_skbuff[i]->len,
					 PCI_DMA_TODEVICE);
			dev_kfree_skb(ep->tx_skbuff[i]);
		}

		ep->tx_skbuff[i] = NULL;
		ep->tx_dma_addr[i] = 0;
	}

	return 0;
}

static void dump_rx_ring_state(struct e1000_private *ep)
{
	int i;
	pr_warning("RX ring: cur_rx = %u\n", ep->cur_rx);
	for (i = 0 ; i < RX_RING_SIZE; i++) {
		pr_warning("   RX %03d base %08x buf len %04x msg len %04x status "
			"%04x\n", i,
			le32_to_cpu(ep->rx_ring[i].base),
			le16_to_cpu((-ep->rx_ring[i].buf_length& 0xffff) ),
			le16_to_cpu(ep->rx_ring[i].msg_length),
			(u16)le16_to_cpu((ep->rx_ring[i].status)));
	}
	pr_warning("\n");
}

static void dump_tx_ring_state(struct e1000_private *ep)
{
	int i;
	pr_warning("TX ring: cur_rx = %u, dirty_tx = %u %s\n",
		ep->cur_tx, ep->dirty_tx, ep->tx_full ? " (full)" : "");
	for (i = 0 ; i < TX_RING_SIZE; i++) {
		pr_warning("   TX %03d base %08x buf len %04x misc %04x status "
			"%04x\n", i,
			le32_to_cpu(ep->tx_ring[i].base),
			le16_to_cpu((-ep->tx_ring[i].buf_length) & 0xffff),
			le32_to_cpu(ep->tx_ring[i].misc),
			le16_to_cpu((u16)(ep->tx_ring[i].status)));
	}
	pr_warning("\n");
}

static void
dump_ring_state(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	dump_rx_ring_state(ep);
	dump_tx_ring_state(ep);
}

static void
dump_init_block(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);

	pr_warning("%s:%s: Init block (%p)state:\n", dev->name, ep->name,
						  ep->init_block);
	pr_warning("   MODE 0x%04x PADDR 0x%02x%02x%02x%02x%02x%02x "
		"LADDRF 0x%016llx\n",
		le16_to_cpu(ep->init_block->mode),
		ep->init_block->paddr[5], ep->init_block->paddr[4],
		ep->init_block->paddr[3], ep->init_block->paddr[2],
		ep->init_block->paddr[1], ep->init_block->paddr[0],
		ep->init_block->laddrf);
	pr_warning("   Receive  Desc Ring Addr: 0x%08x\n",
		ep->init_block->rdra);
	pr_warning("   Transmit Desc Ring Addr: 0x%08x\n",
		ep->init_block->tdra);
	pr_warning("CSR = 0x%x\n", e1000_read_e_csr(ep));
}

static struct net_device_stats *
e1000_get_stats(struct net_device *dev)
{
    struct e1000_private *ep = netdev_priv(dev);
    return &ep->stats;
}

/*
 * Set or clear the multicast filter for this adaptor.
 */
static void e1000_set_multicast_list(struct net_device *dev)
{
    unsigned long flags;
    struct e1000_private *ep = netdev_priv(dev);

    DEBUG_MULT_CAST("e1000_set_multicast_list(): begin\n");
    raw_spin_lock_irqsave(&ep->lock, flags);
    if (dev->flags&IFF_PROMISC) {
	/* Log any net taps. */
	if (netif_msg_hw(ep))
	    printk(KERN_INFO "%s: Promiscuous mode enabled.\n", dev->name);
	ep->init_block->mode |= cpu_to_le16(PROM);
    } else {
	ep->init_block->mode &= ~cpu_to_le16(PROM);
	e1000_load_multicast (dev);
    }

    ep->a->write_e_csr(ep, STOP); /* Temporarily stop the lance. */
    e1000_restart(dev, (INEA|STRT | ep->csr_1588)); /*  Resume normal operation */
    netif_wake_queue(dev);

    raw_spin_unlock_irqrestore(&ep->lock, flags);
    DEBUG_MULT_CAST("e1000_set_multicast_list(): end\n");
}

static int e1000_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct e1000_private *ep = netdev_priv(dev);
	int rc = 0;
	struct hwtstamp_config config;

	switch (cmd) {
	case SIOCDEVPRIVATE + 10:
		pr_warning("napi_scheduled = %d\n", ep->napi_scheduled);
		pr_warning("xmit_enabled_intr = %d\n", ep->xmit_enabled_intr);
		pr_warning("napi state = 0x%lx\n", ep->napi.state);
		dump_init_block(dev);
		dump_ring_state(dev);
		break;
	case SIOCDEVPRIVATE + 11:
	case SIOCSHWTSTAMP+1:
		copy_to_user(rq->ifr_data, max_min_tstmp,
				sizeof(max_min_tstmp));
		return 0;
	case SIOCDEVPRIVATE + 12:
	case SIOCSHWTSTAMP+2:
		{int i;
			for (i = 0; i < 8; i++)
				max_min_tstmp[i] = 0;
			max_min_tstmp[MIN_TX_TSMP] = 0xffffffff;
			max_min_tstmp[MIN_RX_TSMP] = 0xffffffff;
			return 0;
		}
	case SIOCSHWTSTAMP:
		if (copy_from_user(&config, rq->ifr_data, sizeof(config)))
			return -EFAULT;
		ep->hwtstamp_config = config;
		if (ep->pci_dev->device != 0x8016) {
			pr_err("SIOCSHWTSTAMP is not supported. Devid= 0x%x\n",
				ep->pci_dev->device);
			return -EFAULT;
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
		if (ep->mii) {
			rc = generic_mii_ioctl(&ep->mii_if,
					if_mii(rq), cmd, NULL);
		} else {
			rc = -EOPNOTSUPP;
		}
	}
	return rc;
}

static void
e1000_tx_timeout (struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->lock, flags);
	/* Transmitter timeout, serious problems. */
	if (netif_msg_timer(ep)) {
		printk(KERN_ERR "%s: transmit timed out, status %4.4x, resetting.\n",
			dev->name, ep->a->read_e_csr(ep));
		dump_init_block(dev);
		dump_ring_state(dev);
	}
	ep->a->write_e_csr(ep, STOP);
	ep->stats.tx_errors++;
	if (netif_msg_tx_err(ep)) {
		dump_ring_state(dev);
	}

	e1000_restart(dev, INEA|STRT | ep->csr_1588);

	dev->trans_start = jiffies;
	netif_wake_queue(dev);

	raw_spin_unlock_irqrestore(&ep->lock, flags);
}

static int e1000_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
    struct e1000_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r = -EOPNOTSUPP;

    if (ep->mii) {
//	raw_spin_lock_irqsave(&ep->lock, flags);
	mii_ethtool_gset(&ep->mii_if, cmd);
//	raw_spin_unlock_irqrestore(&ep->lock, flags);
	r = 0;
    }
    return r;
}

static int e1000_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
    struct e1000_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r = -EOPNOTSUPP;

    if (ep->mii) {
//	raw_spin_lock_irqsave(&ep->lock, flags);
	r = mii_ethtool_sset(&ep->mii_if, cmd);
	e1000_set_phy_mode(dev);
//	raw_spin_unlock_irqrestore(&ep->lock, flags);
    }
    return r;
}

static void e1000_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
    struct e1000_private *ep = netdev_priv(dev);

    strcpy (info->driver, DRV_NAME);
    strcpy (info->version, DRV_VERSION);
    if (ep->pci_dev)
	strcpy (info->bus_info, pci_name(ep->pci_dev));
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
    struct e1000_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r = -EOPNOTSUPP;

    if (ep->mii) {
//	raw_spin_lock_irqsave(&ep->lock, flags);
	r = mii_nway_restart(&ep->mii_if);
//	raw_spin_unlock_irqrestore(&ep->lock, flags);
    }
    return r;
}

static u32 e1000_get_link(struct net_device *dev)
{
    struct e1000_private *ep = netdev_priv(dev);
//    unsigned long flags;
    int r;

//    raw_spin_lock_irqsave(&ep->lock, flags);
    if (ep->mii) {
	r = mii_link_ok(&ep->mii_if);
    } else {
	/* FIXME */
	r = 0;
    }
//    raw_spin_unlock_irqrestore(&ep->lock, flags);

    return r;
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
    memcpy(data, e1000_gstrings_test, 
		sizeof(e1000_gstrings_test));
}

static int e1000_get_regs_len(struct net_device *dev)
{
    return(E1000_NUM_REGS * sizeof(u16));
}

static void e1000_get_regs(struct net_device *dev, struct ethtool_regs *regs,
	void *ptr)
{
    int i;
    u32 *buff = ptr;
    u16 *mii_buff = NULL;
    struct e1000_private *ep = netdev_priv(dev);
    struct e1000_access *a = ep->a;
//    unsigned long flags;

//    raw_spin_lock_irqsave(&ep->lock, flags);

    /* read e1000 registers */
    *buff++ = a->read_e_csr(ep);
    *buff++ = a->read_mgio_csr(ep);
    *buff++ = a->read_psf_csr(ep);
    *buff++ = a->read_psf_data(ep);

    /* read mii phy registers */
	
    if (ep->mii) {
	mii_buff = (u16 *)buff;
	for (i=0; i<32; i++) {
	    *mii_buff++ = mdio_read(dev, ep->mii_if.phy_id, i);
	}
    }
 
    i = mii_buff - (u16 *)ptr;
    for (; i < E1000_NUM_REGS; i++)
	*mii_buff++ = 0;

//    raw_spin_unlock_irqrestore(&ep->lock, flags);
}

static int e1000_get_coalesce(struct net_device *dev, struct ethtool_coalesce *ec)
{
	struct e1000_private *ep = netdev_priv(dev);

	memset(ec, 0, sizeof(*ec));
	if (CAN_DISABLE_TXINT(ep)) {
		ec->tx_max_coalesced_frames = ep->tx_coal_frame;
	}
	if (SUPPORT_COALESCE(ep)) {
		__u32 r = readl(ep->base_ioaddr + INT_DELAY); 
		ec->tx_coalesce_usecs = (r & 0xFFFF) / 125;
		ec->rx_coalesce_usecs = (r >> 16) / 125;
	}
	return 0;
}

#define	MAX_TX_COAL_FRAMES	64
#define MAX_COAL_USEC		(0xFFFF / 125)
static int e1000_set_coalesce(struct net_device *dev, struct ethtool_coalesce *ec)
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
	if (SUPPORT_COALESCE(ep)) {
		__u32 r = (ec->tx_coalesce_usecs * 125) |
			((ec->rx_coalesce_usecs * 125) << 16);
		writel(r, ep->base_ioaddr + INT_DELAY);
	}
	return 0;
}
	
static int e1000_get_ts_info(struct net_device *netdev,
			      struct ethtool_ts_info *info)
{
	struct e1000_private *ep = netdev_priv(netdev);

	if (ep->pci_dev->device != 0x8016) {
		pr_err("so_timestamping is not supported for devid=0x%x\n",
			ep->pci_dev->device);
		return -EFAULT;
	}
	ethtool_op_get_ts_info(netdev, info);

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
    .get_settings	= e1000_get_settings,
    .set_settings	= e1000_set_settings,
    .get_drvinfo	= e1000_get_drvinfo,
    .get_msglevel	= e1000_get_msglevel,
    .set_msglevel	= e1000_set_msglevel,
    .nway_reset		= e1000_nway_reset,
    .get_link		= e1000_get_link,
    .get_ringparam	= e1000_get_ringparam,
    .get_strings	= e1000_get_strings,
//    .self_test		= e1000_ethtool_test,
    .get_regs_len	= e1000_get_regs_len,
    .get_regs		= e1000_get_regs,
    .get_coalesce	= e1000_get_coalesce,
    .set_coalesce	= e1000_set_coalesce,
	.get_ts_info        = e1000_get_ts_info,
};

/* This routine assumes that the ep->lock is held */
static int mdio_read(struct net_device *dev, int phy_id, int reg_num)
{
    struct e1000_private *ep = netdev_priv(dev);
    u32 rd; 
    u16 val_out = 0;
    int i = 0;

    if (!ep->mii)
	return 0;

    rd = 0;
    rd	|= 0x2 << MGIO_CS_OFF;
    rd 	|= 0x1 << MGIO_ST_OF_F_OFF;
    rd	|= 0x2 << MGIO_OP_CODE_OFF; /* Read */
    rd	|= (phy_id  & 0x1f) << MGIO_PHY_AD_OFF;
    rd	|= (reg_num & 0x1f) << MGIO_REG_AD_OFF;


    ep->a->write_mgio_data(ep, rd);
    rd = 0;
    for (i = 0; i != 1000; i++){
	if (ep->a->read_mgio_csr(ep) & RRDY){
		rd = (u16)ep->a->read_mgio_data(ep);
		val_out = rd & 0xffff;
		DEBUG_MDIO_RD("*************>> mdio_read : reg 0x%x >>>>>> 0x%x\n",
                                reg_num, val_out);
		return val_out;
	}
    }	

    DEBUG_MDIO_RD("mdio_read: Unable to read from MGIO_DATA reg\n");
    return val_out;
}

/* This routine assumes that the ep->lock is held */
static void mdio_write(struct net_device *dev, int phy_id, int reg_num, int val)
{
    struct e1000_private *ep = netdev_priv(dev);
    u32 wr;
    int i = 0;

    if (!ep->mii)
	return;

    wr = 0;
    wr	|= 0x2 << MGIO_CS_OFF;
    wr 	|= 0x1 << MGIO_ST_OF_F_OFF;
    wr	|= 0x1 << MGIO_OP_CODE_OFF; /* Write */
    wr	|= (phy_id  & 0x1f) << MGIO_PHY_AD_OFF;
    wr	|= (reg_num & 0x1f) << MGIO_REG_AD_OFF;
    wr	|= val & 0xffff;

    DEBUG_MDIO_WR("*************>> mdio_write : reg 0x%x <<<<<< 0x%x\n", 
				reg_num, val);
    ep->a->write_mgio_data(ep, wr);
    for (i = 0; i != 1000; i++){
	if (ep->a->read_mgio_csr(ep) & RRDY)
		return;
    }
    DEBUG_MDIO_WR("mdio_write: Unable to write MGIO_DATA reg: val = 0x%x\n", wr);
    return;
}

static void
e1000_set_phy_mode(struct net_device *dev)
{
	struct e1000_private *ep = netdev_priv(dev);
	unsigned int val;
	unsigned int lpa;
	unsigned int advertise;
	unsigned int media;
	unsigned int lpa2 = 0;
	unsigned int advertise2 = 0;
	int speed = 0;
	static int informed = 0;

	if ((assigned_speed != SPEED_1000) &&
		(assigned_speed != SPEED_100) &&
		(assigned_speed != SPEED_10)) {
		pr_warning("%s: Wrong assigned speed %d. Set speed = 100\n",
			dev->name, assigned_speed);
		assigned_speed = SPEED_100;
	}
	lpa = mdio_read(dev, ep->mii_if.phy_id, MII_LPA);
	advertise = mdio_read(dev, ep->mii_if.phy_id, MII_ADVERTISE);
	DEBUG_SETPHY("e1000_set_phy_mode: MII lpa 0x%x advertise 0x%x\n",
		lpa, advertise);
	if (ep->mii_if.supports_gmii) {
		lpa2 = mdio_read(dev, ep->mii_if.phy_id, MII_STAT1000);
		advertise2 = mdio_read(dev, ep->mii_if.phy_id, MII_CTRL1000);
		DEBUG_SETPHY("e1000_set_phy_mode: GMII status 0x%x control "
			"0x%x\n", lpa2, advertise2);
		if ((advertise2 & (ADVERTISE_1000HALF | ADVERTISE_1000FULL)) &&
			(lpa2 & (LPA_1000FULL | LPA_1000HALF)))
			speed = SPEED_1000;
	}
	if (speed == 0) {
		media = mii_nway_result(lpa & advertise);
		if (media & (ADVERTISE_100FULL | ADVERTISE_100HALF))
			speed = SPEED_100;
		else
			speed = SPEED_10;
	}
	if (speed > assigned_speed) {
		if (!informed) {
			pr_info("%s: decrease speed to %d due to module param\n",
				dev->name, assigned_speed);
			informed = 1;
		}
		speed = assigned_speed;
		if (ep->mii_if.supports_gmii && (speed < SPEED_1000)) {
			lpa2 &= ~(LPA_1000FULL | LPA_1000HALF);
			mdio_write(dev, ep->mii_if.phy_id, MII_STAT1000, lpa2);
			advertise2 &= ~(ADVERTISE_1000HALF |
						ADVERTISE_1000FULL);
			mdio_write(dev, ep->mii_if.phy_id,
					MII_CTRL1000, advertise2);
		}
		if (speed == SPEED_10) {
			lpa &= ~(LPA_100FULL | LPA_100BASE4 | LPA_100HALF);
			mdio_write(dev, ep->mii_if.phy_id, MII_LPA, lpa);
			advertise &= ~(ADVERTISE_1000XFULL |
				ADVERTISE_1000XHALF |
				ADVERTISE_1000XPSE_ASYM |
				ADVERTISE_1000XPAUSE);
			advertise |= (ADVERTISE_10FULL | ADVERTISE_10HALF);
			mdio_write(dev, ep->mii_if.phy_id,
				MII_ADVERTISE, advertise);
		}
	}
	DEBUG_SETPHY("e1000_set_phy_mode will set %d Mbits %s-duplex mode\n",
		speed, (ep->mii_if.full_duplex) ? "full" : "half");
	val = e1000_read_mgio_csr(ep);
	DEBUG_SETPHY("e1000_set_phy_mode: mgio_csr before set : 0x%x\n", val);
	val |= HARD;
	e1000_write_mgio_csr(ep, val);
	DEBUG_SETPHY("e1000_set_phy_mode: mgio_csr after writing HARD = 1 "
		"in : 0x%x\n", e1000_read_mgio_csr(ep));
	val &= ~(FETH|GETH|FDUP);
	if (ep->mii_if.full_duplex && !half_duplex)
		val |= FDUP;
	if (speed >= SPEED_1000)
		val |= GETH;
	else if (speed >= SPEED_100)
		val |= FETH;
	
	e1000_write_mgio_csr(ep, val);
	DEBUG_SETPHY("e1000_set_phy_mode: mgio_csr after setting "
		"%d Mbits %s-duplex mode : 0x%x\n",
		speed, (ep->mii_if.full_duplex) ? "full" : "half",
		e1000_read_mgio_csr(ep));
}


static const struct net_device_ops e1000_netdev_ops = {
        .ndo_open       = e1000_open,
	.ndo_stop	= e1000_close,
        .ndo_start_xmit = e1000_start_xmit,
        .ndo_tx_timeout = e1000_tx_timeout,
	.ndo_set_rx_mode = e1000_set_multicast_list,
	.ndo_do_ioctl	= e1000_ioctl,
	.ndo_get_stats	= e1000_get_stats,
	.ndo_set_mac_address    = eth_mac_addr,
};

static int
e1000_probe1(unsigned long ioaddr, unsigned char *base_ioaddr,
		int shared, struct pci_dev *pdev, struct resource *res,
		int bar, struct msix_entry *msix_entries, int msi_status)
{
	int i = 0;
	struct e1000_private *ep = NULL;
	struct net_device *dev = NULL;
	unsigned int soft_reset;
	int fdx, mii, gmii;
	int ret = -ENODEV;
	unsigned int init_block_addr_part = 0;
	u32 val = 0;
	u16	vendor_id, device_id;
	void *p = NULL;
	struct e1000_dma_area *m;
	size_t sz;

	dev = alloc_etherdev(sizeof(struct e1000_private));
	if (!dev) {
		if (e1000_debug & NETIF_MSG_PROBE)
			    pr_alert(KERN_ERR PFX "Memory allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;
	
	}
	ep = netdev_priv(dev);
	sz = ALIGN(sizeof (struct e1000_dma_area), 32);
	p = kzalloc_node(sz, GFP_KERNEL | GFP_DMA, dev_to_node(&pdev->dev));
	if (!p) {
		if (e1000_debug & NETIF_MSG_PROBE)
	        	pr_alert(KERN_ERR PFX "Memory allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;
	}
	m = (struct e1000_dma_area *)PTR_ALIGN(p, 32);
	ep->dma_area = p;
	ep->dma_addr = pci_map_single(pdev, p,
		sizeof(*m), PCI_DMA_BIDIRECTIONAL);
	ep->init_block = &m->init_block;
	ep->tx_ring = m->tx_ring;
	ep->rx_ring = m->rx_ring;
	SET_NETDEV_DEV(dev, &pdev->dev);
	dev->base_addr = ioaddr;
	ep->dev = dev;
	if (pci_read_config_byte(pdev, PCI_REVISION_ID, &ep->revision)) {
		pr_alert("%s: Can't read REVISION_ID\n", pci_name(pdev));
	}
	pci_read_config_word(pdev, PCI_VENDOR_ID, &vendor_id);
	pci_read_config_word(pdev, PCI_DEVICE_ID, &device_id);
	if (vendor_id == 0x1fff && device_id == 0x8016) {
		ep->csr_1588 = ATME | TMCE;
		ep->ptp_clock_info = le1000_ptp_clock_info;
		ep->ptp_clock = ptp_clock_register(&ep->ptp_clock_info,
					&(pdev->dev));
		ep->ptp_clock_info.max_adj = 0xffffffff;
		if (IS_ERR(ep->ptp_clock)) {
			ep->ptp_clock = NULL;
			pr_err("ptp_clock_register failed\n");
		} else {
			pr_warning("registered PHC clock\n");
		}
		pr_warning("%s: Ethernet controller supports IEEE 1588 in IOHUB2\n",
			pci_name(pdev));
	} else {
		ep->csr_1588 = 0;
	}
#if 0
	ep->dma_addr = pci_map_single(pdev, (void *)ep, sizeof(*ep),
                                             PCI_DMA_BIDIRECTIONAL);
#endif
	ep->pci_dev = pdev;
	ep->base_ioaddr = base_ioaddr;
	ep->a = &e1000_io;
	/* Setup STOP bit; Force e1000 resetting  */
	ep->a->write_e_csr(ep, STOP); /* RINT => 0; TINT => 0; IDON => 0; INTR => 0; 
			       * INEA => 0; RXON => 0; TXON => 0; TMDM => 0;
			       * STRT => 0; INIT => 0; 
			       * access to E_BASE_ADDR is allowed */
	/* PHY Resetting */
	soft_reset = 0;
	soft_reset |= (E1000_RSET_POLARITY | SRST);
	ep->a->write_mgio_csr(ep, soft_reset); /* startup software reset */
        soft_reset = ep->a->read_mgio_csr(ep);
	soft_reset &= ~(SRST);
	ep->a->write_mgio_csr(ep, soft_reset); /* stop software reset */
	DEBUG_PROBE("E1000 probe: software reset PHY completed\n");

	raw_spin_lock_init(&ep->lock);

	l_cards_without_mac ++;
	/* Setup HW (MAC), also known as "Physical" address.
	 * because uknown for now, assumed to be 10:20:30:40:50:60 HEX */
	for (i = 0; i < 6; i++) {
		dev->dev_addr[i] = l_base_mac_addr[i];
	}
#ifdef	SET_DEFAULT_MAC
	dev->dev_addr[5] = l_base_mac_addr[5];
#else	/* use base IP address based on machine serial number */
	dev->dev_addr[5] += (l_cards_without_mac - 1) & 0xff;
#endif	/* SET_DEFAULT_MAC */

	fdx = 1; mii = 1; gmii = 1;
	SET_NETDEV_DEV(dev, &pdev->dev);
	ep->name = chipname;
	ep->shared_irq = shared;
	ep->mii_if.full_duplex = fdx;
	ep->mii_if.supports_gmii = gmii;
	ep->mii_if.phy_id_mask = 0x1f;
    	ep->mii_if.reg_num_mask = 0x1f;
	ep->mii = mii;
	ep->msg_enable = e1000_debug;
	ep->options = E1000_PORT_ASEL;
	ep->mii_if.dev = dev;
	ep->mii_if.mdio_read = mdio_read;
	ep->mii_if.mdio_write = mdio_write;

	/* Setup init block */
	/************************************************************************/
	ep->init_block->mode = cpu_to_le16(e1000_mode);
	ep->init_block->laddrf = 0x0000000000000000;
	for (i = 0; i < 6; i++)
		ep->init_block->paddr[i] = dev->dev_addr[i];
//	ep->init_block.paddr[2] = 0x40;
	ep->init_block->laddrf	=  0x0000000000000000;
	ep->init_block->rdra = cpu_to_le32((u32)(ep->dma_addr +
			offsetof(struct e1000_dma_area, rx_ring)));
	ep->init_block->rdra |= cpu_to_le32(E1000_LOG_RX_BUFFERS);
	ep->init_block->tdra = cpu_to_le32((u32)(ep->dma_addr +
			offsetof(struct e1000_dma_area, tx_ring)));
	ep->init_block->tdra |= cpu_to_le32(E1000_LOG_TX_BUFFERS);
	DEBUG_PROBE("e1000_probe1: Receive  Desc Ring DMA Addr | Rlen[3:0]: 0x%x\n", 
			le32_to_cpu(ep->init_block->rdra));
	DEBUG_PROBE("e1000_probe1: Transmit Desc Ring DMA Addr | Tlen[3:0]: 0x%x\n", 
			le32_to_cpu(ep->init_block->tdra));
	/***********************************************************************/
	/* low 32 bits */
	init_block_addr_part = (ep->dma_addr + offsetof(struct e1000_dma_area,
		    		init_block)) & 0xffffffff;
	ep->a->write_e_base_address(ep, init_block_addr_part);
	DEBUG_PROBE("e1000_probe1: Init Block Low  DMA addr: "
	       "0x%x (align = 64 bytes)\n", init_block_addr_part);
	/* high 32 bits */
	init_block_addr_part = ((u64)(ep->dma_addr + offsetof(struct e1000_dma_area,
		    		init_block)) >> 32) & 0xffffffff; 
	ep->a->write_dma_base_address(ep, init_block_addr_part);
	DEBUG_PROBE("e1000_probe1: Init Block High DMA addr: 0x%x\n", init_block_addr_part);
	/************************************************************************/

	dev->irq = pdev->irq;
	if (e1000_debug & NETIF_MSG_PROBE)
		printk(" assigned IRQ %u.\n", dev->irq);
	else {
		printk("%s: assigned IRQ #%u\n", pci_name(pdev), dev->irq);
	}
	/* Set the mii phy_id so that we can query the link state */
	if (ep->mii)
		ep->mii_if.phy_id = 0x01;

	/* Setup PHY MII/GMII enable */
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_AUX_CTRL);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x12 (AUX_CTRL) : "
		"after reset :            0x%x\n", val);
	val &= ~(RGMII_EN_1 | RGMII_EN_0);
	mdio_write(dev, ep->mii_if.phy_id, PHY_AUX_CTRL, val);
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_AUX_CTRL);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x12 (AUX_CTRL) : "
		"after turn in GMI mode : 0x%x\n", val);
	/* Setup PHY 10/100/1000 Link on 10M Link */
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_LED_CTRL);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x13 (LED_CTRL) : "
                "after reset :            0x%x\n", val);  
	val |= RED_LEN_EN;
	mdio_write(dev, ep->mii_if.phy_id, PHY_LED_CTRL, val);
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_LED_CTRL);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x13 (LED_CTRL) : "
                "after led is enabled :   0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0); 
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x0      (BMCR) : "
                "           :             0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0x1);
        DEBUG_PROBE("e1000_probe1: PHY reg # 0x1             : "
                "first reading :          0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0x1);
        DEBUG_PROBE("e1000_probe1: PHY reg # 0x1             : "
                "second reading :         0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0x10);
        DEBUG_PROBE("e1000_probe1: PHY reg # 0x10            : "
                "           :             0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0x11);
        DEBUG_PROBE("e1000_probe1: PHY reg # 0x11            : "
                "           :             0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0x14);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x14            : "
                "           :             0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, 0x15);
        DEBUG_PROBE("e1000_probe1: PHY reg # 0x15            : "
                "           :             0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_BIST_CFG2);  
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x1a (BIST_CFG2): "
                "           :             0x%x\n", val);
	val |= LINK_SEL;
	mdio_write(dev, ep->mii_if.phy_id, PHY_BIST_CFG2, val); 
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_BIST_CFG2);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x1a (BIST_CFG2): "
                "after link_sel = 1 :    0x%x\n", val);
	/* move e1000 link status select to default 0 link */
	val = ep->a->read_mgio_csr(ep);
	val &= ~LSTS;
        val |= SLSP;
	ep->a->write_mgio_csr(ep, val);
#define SET_10_100_1000_MODE_BY_HANDLE 0
#if	SET_10_100_1000_MODE_BY_HANDLE	
	val = ep->a->read_mgio_csr(ep);
	DEBUG_PROBE("e1000_probe1: mgio_csr after reset : 0x%x\n", val);
	val |= HARD;
	ep->a->write_mgio_csr(ep, val);
	mb();
	DEBUG_PROBE("e1000_probe1: mgio_csr after writing HARD = 1 in : 0x%x\n", 
							ep->a->read_mgio_csr(ep));
	val &= ~(FETH|GETH|FDUP);
	ep->a->write_mgio_csr(ep, val);
	mb();
	DEBUG_PROBE("e1000_probe1: mgio_csr after resetting (FETH|GETH|FDUP) in : 0x%x\n",
                                                        ep->a->read_mgio_csr(ep));
#else
	e1000_set_phy_mode(dev);
#endif
	if (CAN_DISABLE_TXINT(ep)) {
		ep->tx_coal_frame = TX_RING_SIZE / 4;
	}
	init_timer (&ep->watchdog_timer);
	ep->watchdog_timer.data = (unsigned long) dev;
	ep->watchdog_timer.function = e1000_watchdog;

	/* The E1000-specific entries in the device structure. */
	dev->ethtool_ops = &e1000_ethtool_ops;
	dev->netdev_ops = &e1000_netdev_ops;
	dev->watchdog_timeo = (5*HZ);

	netif_napi_add(dev, &ep->napi, e1000_poll, L_E1000_NAPI_WEIGHT);
	ep->napi_scheduled = 0;

	/* Fill in the generic fields of the device structure. */
	if (register_netdev(dev))
		goto err_free_consistent;


	if (e1000_debug & NETIF_MSG_PROBE)
		printk(KERN_INFO "%s: registered as %s\n", dev->name, ep->name);
	l_cards_without_mac_found++;

// 	e1000_loopback_test(dev, &data1);
	/* Setup STOP bit; Force e1000 resetting  */
	ep->a->write_e_csr(ep, STOP);

	ep->resource = res;
	ep->bar = bar;
	ep->msix_entries = msix_entries;
	ep->msi_status = msi_status;

	if (do_pause_sender) {
		/* We will send special pkt to sender
		 * to pause its activite in case of MISS
		 * error
		 */
		struct sk_buff *skb;
		skb = dev_alloc_skb(ETH_ZLEN + CRC_SZ + 2);
		if (skb) {
			skb_reserve(skb,2); /* 16 byte align */
			skb_put(skb, ETH_ZLEN + CRC_SZ);	/* Make room */
		        skb_copy_to_linear_data(skb, pause_packet, ETH_ZLEN);
			*(skb->data +6) = dev->dev_addr[0];
			*(skb->data +7) = dev->dev_addr[1];
			*(skb->data +8) = dev->dev_addr[2];
			*(skb->data +9) = dev->dev_addr[3];
			*(skb->data +10) = dev->dev_addr[4];
			*(skb->data +11) = dev->dev_addr[5];
			if (do_pause_sender > 128) {
				*(skb->data +16) = (do_pause_sender & 0xFF00) >> 8;
				*(skb->data +17) = do_pause_sender & 0xFF;
			}
		 	ep->skb_to_pause = skb;
			ep->skb_to_pause_dma = pci_map_single(ep->pci_dev,
				skb->data, ETH_ZLEN, PCI_DMA_TODEVICE);
			ep->skb_to_pause_sent = 0;
		}
	}
	pr_alert("%s : L-E1000 (rev. %d) %s\n",
		dev->name, ep->revision, pci_name(pdev));

	return 0;

err_free_consistent:
	pci_unmap_single(ep->pci_dev, ep->dma_addr, sizeof(*ep),
			PCI_DMA_FROMDEVICE);
err_release_region:
	if (dev) {
		free_netdev(dev);
	}
	if (p) {
		kfree(p);
	}
	release_region(ioaddr, E1000_TOTAL_SIZE);
	return ret;
}


#ifdef CONFIG_MCST_RT
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

#else
#define is_rt_device(pdev, bar)	(0)
#define was_rt_device(ep)	(0)
#define IS_RT_DEVICE(pdev) (0)
#endif

static int
e1000_probe_pci_bar(struct pci_dev *pdev, const struct pci_device_id *ent,
			int bar, struct msix_entry *msix_entries, int msi_status)
{
    unsigned long ioaddr;
    unsigned char *base_ioaddr;
    struct resource *res;
    int   err;

    ioaddr = pci_resource_start (pdev, bar);
    if (!ioaddr) {
	if (e1000_debug & NETIF_MSG_PROBE)
	    printk (KERN_ERR PFX "card has no PCI IO resources, aborting\n");
	return -ENODEV;
    }

    if (!pci_dma_supported(pdev, E1000_DMA_MASK)) {
	if (e1000_debug & NETIF_MSG_PROBE)
	    printk(KERN_ERR PFX "architecture does not support 32bit PCI busmaster DMA\n");
	return -ENODEV;
    }

    res = request_mem_region(ioaddr, E1000_TOTAL_SIZE, "e1000_probe_pci");
    if (res == NULL) {
	if (e1000_debug & NETIF_MSG_PROBE)
	    printk(KERN_ERR PFX "memio address range already allocated\n");
	return -EBUSY;
    }

    base_ioaddr = ioremap(ioaddr, E1000_TOTAL_SIZE);
    if (base_ioaddr == NULL){
	printk(KERN_ERR PFX "Unable to map base ioaddr = 0x%lx\n", ioaddr);
	return -ENOMEM;
    }
#ifdef CONFIG_MCST_RT
	if (is_rt_device(pdev, bar)) {
		if (num_l_e1000_rt >= (MAX_NUM_L_E1000_RT - 1)) {
			pr_warn("l_e1000: max rt devices reached.\n");
			err = -ENOMEM;
		} else {
			struct net_device *dev = dev_get_drvdata(&pdev->dev);
			struct e1000_private *ep = netdev_priv(dev);
			err = e1000_rt_probe1(ioaddr, base_ioaddr, 1, pdev, res,
					bar, msix_entries, msi_status);
			if (err >= 0) {
				dev = dev_get_drvdata(&pdev->dev);
				l_1000_rts[num_l_e1000_rt] = netdev_priv(dev);;
				num_l_e1000_rt++;
			}
		}

	} else
#endif
		err =  e1000_probe1(ioaddr, base_ioaddr, 1, pdev, res,
				bar, msix_entries, msi_status);
    if (err < 0) {
        release_resource(res);
        iounmap(base_ioaddr);
	pci_disable_device(pdev);
    }
    return err;
}


static int 
e1000_probe_pci(struct pci_dev *pdev, const struct pci_device_id *ent)
{
    int res, err = 0;
    int bar;
    struct msix_entry *msix_entries = NULL;
    int num_msix_entries;
    int msi_status = L_E1000_NOMSI;
    int i;

    err = pci_enable_device(pdev);
    if (err < 0) {
	if (e1000_debug & NETIF_MSG_PROBE)
	    printk(KERN_ERR PFX "failed to enable device -- err=%d\n", err);
	return err;
    }
    pci_set_master(pdev);
    num_msix_entries = l_e1000_supports_msix(pdev);
    if (num_msix_entries > 0) {
        DEBUG_IRQ("%s supports %d MSIX interrupts\n", pci_name(pdev), num_msix_entries); 
    	msix_entries = kzalloc_node(num_msix_entries * sizeof(struct msix_entry),
				GFP_KERNEL, dev_to_node(&pdev->dev));
	if (msix_entries) {
		for (i = 0; i < num_msix_entries; i++) {
			msix_entries[i].entry = i;
		}
	}
	res = pci_enable_msix(pdev, msix_entries, num_msix_entries);
	if (res) {
		kfree(msix_entries);
		msix_entries = NULL;
		num_msix_entries = 0;
		DEBUG_IRQ("%s cannot use msix interrupts. reason = %d\n", pci_name(pdev), res);
	} else {
		msi_status = L_E1000_MSIX;
	}
    }
    if ((msi_status == L_E1000_NOMSI) && l_e1000_supports_msi(pdev)) {
    	res = pci_enable_msi(pdev);
    	if (res == 0) {
		msi_status = L_E1000_MSI;
	} else {
		DEBUG_IRQ("%s cannot use msi interrupt. reason = %d\n", pci_name(pdev), res);
	}
    }

    for (bar = 0; bar < 4; bar++) {
    	res = e1000_probe_pci_bar(pdev, ent, bar, msix_entries, msi_status);
	if (res && !err) {
		err = res;
	}
	if (ent->vendor != PCI_VENDOR_ID_MCST_TMP) {
		break;
	}
	if (ent->device != 0x8022) {
		break;
	}
    }
    return err;
}


static void e1000_remove(struct pci_dev *pdev)
{
	struct net_device *dev = dev_get_drvdata(&pdev->dev);
        struct e1000_private *ep = netdev_priv(dev);

	if (was_rt_device(ep)) {
		e1000_rt_remove(pdev);
		return;
	}
        dev_set_drvdata(&pdev->dev, NULL);
        unregister_netdev(dev);
        iounmap(ep->base_ioaddr);
        release_resource(ep->resource);
        pci_release_region(pdev, E1000_TOTAL_SIZE);

        pci_unmap_single(pdev, ep->dma_addr, sizeof(*ep),
                        PCI_DMA_FROMDEVICE);
	kfree(ep->dma_area);
	if (ep->ptp_clock) {
		ptp_clock_unregister(ep->ptp_clock);
		ep->ptp_clock = NULL;
		pr_info("removed PHC\n");
	}
        free_netdev(dev);
	if (ep->msi_status == L_E1000_MSIX) {
		pci_disable_msix(pdev);
	} else if (ep->msi_status == L_E1000_MSI) {
		pci_disable_msi(pdev);
	}
        pci_disable_device(pdev);
}

#if 0 /* TODO */
static int e1000_resume(struct pci_dev *pdev)
{
	struct net_device *dev = dev_get_drvdata(&pdev->dev);
        struct e1000_private *ep = netdev_priv(dev);
	unsigned int init_block_addr_part;
	unsigned int soft_reset;
	u32 val;

	/* Setup STOP bit; Force e1000 resetting */
	ep->a->write_e_csr(ep, STOP); /* RINT => 0; TINT => 0; IDON => 0;
				       * INTR => 0; INEA => 0; RXON => 0;
				       * TXON => 0; TMDM => 0; STRT => 0;
				       * INIT => 0; access to E_BASE_ADDR
				       * is allowed */

	/* PHY Resetting */
	soft_reset = 0;
	soft_reset |= (E1000_RSET_POLARITY | SRST);
	ep->a->write_mgio_csr(ep, soft_reset); /* startup software reset */
        soft_reset = ep->a->read_mgio_csr(ep);
	soft_reset &= ~(SRST);
	ep->a->write_mgio_csr(ep, soft_reset); /* stop software reset */
	DEBUG_RESUME("e1000_resume: software reset PHY completed\n");

	/* Setup DMA low 32 bits */
	init_block_addr_part = (ep->dma_addr +
		offsetof(struct e1000_private, init_block)) & 0xffffffff;
	ep->a->write_e_base_address(ep, init_block_addr_part);
	DEBUG_RESUME("e1000_resume: Init Block Low  DMA addr: "
	       "0x%x (align = 64 bytes)\n", init_block_addr_part);

	/* Setup DMA high 32 bits */
	init_block_addr_part = ((u64)(ep->dma_addr +
		offsetof(struct e1000_private, init_block)) >> 32) &
			0xffffffff; 
	ep->a->write_dma_base_address(ep, init_block_addr_part);
	DEBUG_RESUME("e1000_resume: Init Block High DMA addr: 0x%x\n",
		init_block_addr_part);

	/* Setup PHY MII/GMII enable */
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_AUX_CTRL);
	DEBUG_RESUME("e1000_resume: PHY reg # 0x12 (AUX_CTRL) : "
		"after reset :            0x%x\n", val);
	val &= ~(RGMII_EN_1 | RGMII_EN_0);
	mdio_write(dev, ep->mii_if.phy_id, PHY_AUX_CTRL, val);
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_AUX_CTRL);
	DEBUG_RESUME("e1000_resume: PHY reg # 0x12 (AUX_CTRL) : "
		"after turn in GMI mode : 0x%x\n", val);

	/* Setup PHY 10/100/1000 Link on 10M Link */
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_LED_CTRL);
	DEBUG_RESUME("e1000_resume: PHY reg # 0x13 (LED_CTRL) : "
               "after reset :            0x%x\n", val);  
	val |= RED_LEN_EN;
	mdio_write(dev, ep->mii_if.phy_id, PHY_LED_CTRL, val);
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_LED_CTRL);
	DEBUG_RESUME("e1000_resume: PHY reg # 0x13 (LED_CTRL) : "
                "after led is enabled :   0x%x\n", val);
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_BIST_CFG2);
	DEBUG_RESUME("e1000_resume: PHY reg # 0x1a (BIST_CFG2): "
                "after reset :            0x%x\n", val);
	val |= LINK_SEL;
	mdio_write(dev, ep->mii_if.phy_id, PHY_BIST_CFG2, val); 
	val = mdio_read(dev, ep->mii_if.phy_id, PHY_BIST_CFG2);
	DEBUG_RESUME("e1000_resume: PHY reg # 0x1a (BIST_CFG2): "
                "after link_sel = 1 :     0x%x\n", val);

	/* Move e1000 link status select to default 0 link */
	val = ep->a->read_mgio_csr(ep);
	val &= ~LSTS;
        val |= SLSP;
	ep->a->write_mgio_csr(ep, val);

	e1000_set_phy_mode(dev);

	/* Setup STOP bit; Force e1000 resetting */
	ep->a->write_e_csr(ep, STOP);

	/* Unmask interrupt in IOAPIC */
	DEBUG_RESUME("%s: e1000_resume() unmask 0x%x interrupt in IOAPIC\n",
		pci_name(pdev), pdev->irq);
	irq_to_desc(pdev->irq)->chip->unmask(pdev->irq);

	return 0;
}
#endif

static struct pci_driver e1000_driver = {
        .name           = "L-E1000",
        .id_table       = e1000_pci_tbl,
        .probe          = e1000_probe_pci,
        .remove         = e1000_remove,
#if 0
	.resume         = e1000_resume,
#endif
};

#ifdef CONFIG_SYSCTL
/* Place file num_tx_bufs_to_clean_on_xmit in /proc/sys/dev/l_e1000 */
static ctl_table l_e1000_table[] = {
	{
		.procname	= "num_bufs_to_clean_on_tx",
		.data		= &num_tx_bufs_to_clean,
		.maxlen		= sizeof (int),
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

#else /* CONFIG_SYSCTL */
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
}


extern int e1000;
static int __init e1000_init_module(void)
{
	int r;
	printk(KERN_INFO "%s", version);
	if (!e1000) {
		pr_alert("Ethernet e1000 driver not allowed. "
			"Use e1000 in command line\n");
		return (-ENODEV);
	}
	
	e1000_debug = netif_msg_init(debug,
		NETIF_MSG_DRV |
		NETIF_MSG_PROBE  |
		NETIF_MSG_LINK   |
		NETIF_MSG_TIMER   |
		/* NETIF_MSG_TX_QUEUED | */
		/* NETIF_MSG_PKTDATA   | */
		/* NETIF_MSG_RX_ERR    | */
		/*  NETIF_MSG_TX_ERR    | */ 
		/* NETIF_MSG_INTR      | */
	0);

        r = pci_register_driver(&e1000_driver);
	if (r == 0) {
		l_e1000_sysctl_register();
	}
	return r;
}

module_param(debug, int, 0);
MODULE_PARM_DESC(debug, DRV_NAME " debug level");
module_param(max_interrupt_work, int, 0);
MODULE_PARM_DESC(max_interrupt_work, DRV_NAME " maximum events handled per interrupt");
module_param(rx_copybreak, int, 0);
MODULE_PARM_DESC(rx_copybreak, DRV_NAME " copy breakpoint for copy-only-tiny-frames");

module_init(e1000_init_module);
module_exit(e1000_cleanup_module);

