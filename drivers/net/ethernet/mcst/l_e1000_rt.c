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
#include <linux/mcst_net_rt.h>

#include <asm/dma.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <asm/irqflags.h>
#include <asm/irq.h>

#include "l_e1000.h"

#ifdef	CONFIG_MCST
#include <asm/setup.h>
#endif


MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("P2P connection special driver for L-E1000 ethernet card");

#define PCI_DEVICE_ID_E1000     0x4d45
#define PCI_SUBVENDOR_ID_E1000  0x0000

#define DEBUG_MDIO_RD_ON        0       /* Debug for mdio_read primitive */
#define DEBUG_MDIO_WR_ON        0       /* Debug for mdio_write primitive */
#define DEBUG_RD_E_CSR_ON       0       /* Debug for read_e_csr primitive */
#define DEBUG_WR_E_CSR_ON       0       /* Debug for write_e_csr primitive */
#define DEBUG_INIT_RING_ON      0       /* Debug for init_ring function */
#define DEBUG_E1000_RX_ON       0       /* Debug for rx function */
#define DEBUG_E1000_RX_HEAD_ON  0       /* Show rx packet header */
#define DEBUG_E1000_RX_BODY_ON  0       /* Show rx packet body  */
#define DEBUG_E1000_RESTART_ON  0
#define DEBUG_LOOPBACK_ON       0       
#define DEBUG_PROBE_ON          0
#define DEBUG_SETPHT_ON         0
#define DEBUG_MULT_CAST_ON      0
#define DEBUG_INIT_BLOCK_ON     1
#define DEBUG_RESUME_ON         0



#define DEBUG_MDIO_RD           if (DEBUG_MDIO_RD_ON) printk
#define DEBUG_MDIO_WR           if (DEBUG_MDIO_WR_ON) printk
#define DEBUG_INIT_RING         if (DEBUG_INIT_RING_ON) printk
#define DEBUG_RD_E_CSR          if (DEBUG_RD_E_CSR_ON) printk
#define DEBUG_WR_E_CSR          if (DEBUG_WR_E_CSR_ON) printk   
#define DEBUG_E1000_RX          if (DEBUG_E1000_RX_ON) printk
#define DEBUG_E1000_RX_HEAD     if (DEBUG_E1000_RX_HEAD_ON) printk
#define DEBUG_E1000_RX_BODY     if (DEBUG_E1000_RX_BODY_ON) printk
#define DEBUG_E1000_RESTART     if (DEBUG_E1000_RESTART_ON) printk
#define DEBUG_LOOPBACK          if (DEBUG_LOOPBACK_ON) printk
#define DEBUG_PROBE             if (DEBUG_PROBE_ON) printk
#define DEBUG_SETPHY            if (DEBUG_SETPHT_ON) printk
#define DEBUG_MULT_CAST         if (DEBUG_MULT_CAST_ON) printk
#define DEBUG_RESUME            if (DEBUG_RESUME_ON) printk



#define E1000_DMA_MASK          0xffffffff
#define e1000_rt_mode              (FULL | PROM)

#define DRV_NAME        "l_e1000-rt"
#define DRV_VERSION     "1.00"
#define DRV_RELDATE     "15.08.2013"
#define PFX             DRV_NAME ": "


#define E1000_NUM_REGS 168

#define E1000_DMA_MASK          0xffffffff
#define E1000_TOTAL_SIZE        0x20

#define E1000_WATCHDOG_TIMEOUT (jiffies + (2 * HZ))

#define E1000_PORT_MII      0x03
#define E1000_PORT_ASEL     0x04




/*
 * Set the number of Tx and Rx buffers, using Log_2(# buffers).
 * Reasonable default values are 16 Tx buffers, and 256 Rx buffers.
 * That translates to 4 (16 == 2^^4) and 8 (256 == 2^^8).
 */
#ifndef E1000_LOG_TX_BUFFERS
#define E1000_LOG_TX_BUFFERS 0 //4
#define E1000_LOG_RX_BUFFERS 1 //8
#endif

#define TX_RING_SIZE            (1 << (E1000_LOG_TX_BUFFERS))
#define TX_RING_MOD_MASK        (TX_RING_SIZE - 1)
#define TX_RING_LEN_BITS        ((E1000_LOG_TX_BUFFERS) << 12)

#define RX_RING_SIZE            (1 << (E1000_LOG_RX_BUFFERS))
#define RX_RING_MOD_MASK        (RX_RING_SIZE - 1)
#define RX_RING_LEN_BITS        ((E1000_LOG_RX_BUFFERS) << 4)

#define ETHERNET_BUF_SIZE              1544


#define PKT_BUF_SZ              1514 /*(1500 data + 14 header) */

/* Each packet consists of header 14 bytes + [46 min - 1500 max] data + 4 bytes crc 
 * e1000 makes crc automatically when sending a packet so you havn't to take care
 * about it allocating memory for the packet being sent. As to received packets e1000
 * doesn't hew crc off so you'll have to alloc an extra 4 bytes of memory in addition to
 * common packet size */

#define CRC_SZ  4


/* E1000 Rx and Tx ring descriptors. */


struct e1000_rx_head {
	u32                 base;         /*u32*/ /* RBADR     [31:0] */
	s16                 buf_length;   /*s16*/ /* BCNT only [13:0] */
	s16                 status;       /*s16*/
	s16                 msg_length;   /*s16*/ /* MCNT only [13:0] */
	u16 reserved1;
	u32 reserved2;
} __attribute__((packed));

struct e1000_tx_head {
	u32                 base;         /*u32*/ /* TBADR     [31:0] */
	s16                 buf_length;   /*s16*/ /* BCNT only [13:0] */
	s16                 status;       /*s16*/
	u32                 misc;         /*u32*/ /* [31:26] + [3:0]  */
	u32 reserved;
} __attribute__((packed));

struct rx_buf {
	u8 b[ETHERNET_BUF_SIZE] __attribute__((aligned(8)));
};

struct e1000_rt_dma_area {
	init_block_t         init_block __attribute__((aligned(32)));
	struct e1000_rx_head rx_ring[RX_RING_SIZE] __attribute__((aligned(16)));
	struct e1000_tx_head tx_ring               __attribute__((aligned(16)));
	u8      tx_buf[ETHERNET_BUF_SIZE]          __attribute__((aligned(8)));
	struct rx_buf      rx_buf[RX_RING_SIZE]    __attribute__((aligned(8)));
};
/*
 * The first three fields of pcnet32_private are read by the ethernet device
 * so we allocate the structure should be allocated by pci_alloc_consistent().
 */
struct e1000_rt_private {
	init_block_t              *init_block;
	struct e1000_rx_head      *rx_ring;
	struct e1000_tx_head      *tx_ring;
	u8                        *tx_buf;
	struct rx_buf             *rx_buf;
	void                      *dma_area;
	dma_addr_t                dma_addr;
	struct pci_dev            *pci_dev;
	struct net_device         *dev;
	int			  msi_status;
	int                        bar;              /* MSIX support */
	struct msix_entry          *msix_entries;    /* MSIX support */
	int                       irq;
	struct resource           *resource;
	raw_spinlock_t            lock;
	const char                *name;
	unsigned char             *base_ioaddr; /* iomapped device regs */    
	unsigned int              cur_rx;       /* The next free ring entry */
	unsigned int              last_tx_intr;
	struct net_device_stats   stats;
	unsigned int              mii;
	struct mii_if_info        mii_if;
//	struct timer_list         watchdog_timer;
	unsigned char             recieved;
	unsigned char             opened;
	unsigned char             revision;
	unsigned char             pinned;
	int                       tx_inprogress;
	int                       rx_len; 
	int                       last_tx_res;
	int                       rx_skipped;
	struct task_struct        *rx_waiter;
	struct timer_list         watchdog_timer;
	u32                       msg_enable;     /* debug message level */
};

static irqreturn_t e1000_rt_interrupt(int , void *);
static int mdio_read(struct net_device* , int , int);
static void e1000_rt_set_phy_mode(struct net_device *dev);
static void dump_init_block(struct net_device *dev);

#if defined(SEPARATE_RT_LE1000_DRIVER)
static int debug = -1;
#endif
static int e1000_rt_debug = 0;


u32 e1000_read_e_csr(struct e1000_rt_private *ep)
{
	u32 val = 0;
	if (ep->base_ioaddr) {
		val = readl(ep->base_ioaddr + E_CSR);
		DEBUG_RD_E_CSR("=== e_csr >>>---->>> 0x%x\n", val);
		return val;
	}
	return 0xabcdefab;
}

static void e1000_write_e_csr(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		DEBUG_WR_E_CSR("=== e_csr <<<----<<< 0x%x\n", val);
		writel(val, ep->base_ioaddr + E_CSR);
	}
}

static u32 e1000_read_mgio_csr(struct e1000_rt_private *ep)
{
	if (ep->base_ioaddr) {
		return readl(ep->base_ioaddr + MGIO_CSR);
	}
	return 0xabcdefab;
}

static void e1000_write_mgio_csr(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		writel(val, ep->base_ioaddr + MGIO_CSR);
	}
}

static u32 e1000_read_mgio_data(struct e1000_rt_private *ep)
{
	if (ep->base_ioaddr) {
		return readl(ep->base_ioaddr + MGIO_DATA);
	}
	return 0xabcdefab;
}

static void e1000_write_mgio_data(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		writel(val, ep->base_ioaddr + MGIO_DATA);
	}
}

#if 0
static u32 e1000_read_e_base_address(struct e1000_rt_private *ep)
{
	if (ep->base_ioaddr) {
		return readl(ep->base_ioaddr + E_BASE_ADDR);
	}
	return 0xabcdefab;
}
#endif

static void e1000_write_e_base_address(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		writel(val, ep->base_ioaddr + E_BASE_ADDR);
	}
}

#if 0
static u32 e1000_read_dma_base_address(struct e1000_rt_private *ep)
{
	if (ep->base_ioaddr) {
		return readl(ep->base_ioaddr + DMA_BASE_ADDR);
	}
	return 0xabcdefab;
}
#endif



static void e1000_write_dma_base_address(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		writel(val, ep->base_ioaddr + DMA_BASE_ADDR);
	}
}

static u32 e1000_read_psf_csr(struct e1000_rt_private *ep)
{
	if (ep->base_ioaddr) {
		return readl(ep->base_ioaddr + PSF_CSR);
	}
	return 0xabcdefab;
}

#if 0
static void e1000_write_psf_csr(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		writel(val, ep->base_ioaddr + PSF_CSR);
	}
}
#endif

static u32 e1000_read_psf_data(struct e1000_rt_private *ep)
{
	if (ep->base_ioaddr) {
		return readl(ep->base_ioaddr + PSF_DATA);
	}
	return 0xabcdefab;
}
#if 0
static void e1000_write_psf_data(struct e1000_rt_private *ep, int val)
{
	if (ep->base_ioaddr) {
		writel(val, ep->base_ioaddr + PSF_DATA);
	}
}
#endif

static int mdio_read(struct net_device *dev, int phy_id, int reg_num)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	u32 rd;
	u16 val_out = 0;
	int i = 0;

	if (!ep->mii)
		return 0;

	rd = 0;
	rd  |= 0x2 << MGIO_CS_OFF;
	rd  |= 0x1 << MGIO_ST_OF_F_OFF;
	rd  |= 0x2 << MGIO_OP_CODE_OFF; /* Read */
	rd  |= (phy_id  & 0x1f) << MGIO_PHY_AD_OFF;
	rd  |= (reg_num & 0x1f) << MGIO_REG_AD_OFF;


	e1000_write_mgio_data(ep, rd);
	rd = 0;
	for (i = 0; i != 1000; i++){
		if (e1000_read_mgio_csr(ep) & RRDY){
			rd = (u16)e1000_read_mgio_data(ep);
			val_out = rd & 0xffff;
			DEBUG_MDIO_RD("*** mdio_read : reg 0x%x >> 0x%x\n",
				reg_num, val_out);
			return val_out;
		}
	}  

	DEBUG_MDIO_RD("mdio_read: Unable to read from MGIO_DATA reg\n");
	return val_out;
}


static void mdio_write(struct net_device *dev, int phy_id, int reg_num, int val)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	u32 wr;
	int i = 0;

	if (!ep->mii)
		return;

	wr = 0;
	wr  |= 0x2 << MGIO_CS_OFF;
	wr  |= 0x1 << MGIO_ST_OF_F_OFF;
	wr  |= 0x1 << MGIO_OP_CODE_OFF; /* Write */
	wr  |= (phy_id  & 0x1f) << MGIO_PHY_AD_OFF;
	wr  |= (reg_num & 0x1f) << MGIO_REG_AD_OFF;
	wr  |= val & 0xffff;

	DEBUG_MDIO_WR("** mdio_write : reg 0x%x <<< 0x%x\n",
			reg_num, val);
	e1000_write_mgio_data(ep, wr);
	for (i = 0; i != 1000; i++){
		if (e1000_read_mgio_csr(ep) & RRDY)
			return;
	}
	DEBUG_MDIO_WR("mdio_write: Unable to write MGIO_DATA reg: val = 0x%x\n", wr);
	return;
}

static int assigned_speed = SPEED_1000;
static int half_duplex;
#if defined(SEPARATE_RT_LE1000_DRIVER)
module_param_named(speed, assigned_speed, int, 0444);
MODULE_PARM_DESC(speed, "used to restrict speed to 10 or 100");
module_param_named(hd, half_duplex, int, 0444);
MODULE_PARM_DESC(hd, "work in half duplex mode");
#endif
static void
e1000_rt_set_phy_mode(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	unsigned int val;
	unsigned int lpa;
	unsigned int advertise;
	unsigned int media;
	unsigned int lpa2;
	unsigned int advertise2;
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


/* Here dummy stuff commin interface */

static int e1000_rt_open(struct net_device *dev)
{
	return -EBUSY;
}

static int e1000_rt_close(struct net_device *dev)
{
	return 0;
}

static int
e1000_rt_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	dev_kfree_skb(skb);
	return -EBUSY;
}

static int e1000_rt_ioctl(struct net_device *dev, struct ifreq *rq, int cmd);

static struct net_device_stats *e1000_rt_get_stats(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	return &ep->stats;
}


static const struct net_device_ops e1000_netdev_ops = {
	.ndo_open       = e1000_rt_open,
	.ndo_stop       = e1000_rt_close,
	.ndo_start_xmit = e1000_rt_start_xmit,
	.ndo_do_ioctl   = e1000_rt_ioctl,
	.ndo_get_stats  = e1000_rt_get_stats,
	.ndo_set_mac_address    = eth_mac_addr,
#ifdef CONFIG_MCST_RT
	.ndo_unlocked_ioctl     = 1,
#endif
};


/* End of dummy interface */



static void e1000_watchdog(unsigned long arg)
{
	struct net_device *dev = (struct net_device *)arg;
	struct e1000_rt_private *ep = netdev_priv(dev);

	if (!ep->mii) {
		return;
	}
	/* Print the link status if it has changed */
	e1000_rt_set_phy_mode(dev);
	mii_check_media (&ep->mii_if, netif_msg_link(ep), 0);
	mod_timer (&(ep->watchdog_timer), E1000_WATCHDOG_TIMEOUT);
}



/* Initialize the E1000 Rx and Tx rings. */
static int e1000_rt_init_ring(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	struct e1000_rx_head *rh;
	int i;

	ep->cur_rx = 0;

	for (i = 0; i < RX_RING_SIZE; i++) {
		rh = &ep->rx_ring[i];
		rh->base = cpu_to_le32(ep->dma_addr +
			offsetof(struct e1000_rt_dma_area, rx_buf[i]));
		rh->buf_length = cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
		wmb();
		rh->status |= cpu_to_le16(RX_ST_OWN);
		DEBUG_INIT_RING("e1000_init_ring(): make recieve buf %d, "
			"base = 0x%x , buf_len = 0x%x [0x%x]\n",
			i, le32_to_cpu(rh->base),
			le16_to_cpu(rh->buf_length), (PKT_BUF_SZ + CRC_SZ));
	}
/*
	for (i = 0; i < TX_RING_SIZE; i++) {
		th = ep->tx_ring[i];
		th->status = 0;
		wmb();
		th->base = cpu_to_le32(dma_ep->tx_buf[i]);
		DEBUG_INIT_RING("e1000_init_ring(): make recieve buf %d, "
			"base = 0x%x , buf_len = 0x%x [0x%x]\n",
			i, le32_to_cpu(rh->base),
			le16_to_cpu(rh->buf_length), (PKT_BUF_SZ + CRC_SZ));
	}
*/
	ep->tx_ring->status = 0;
	wmb();
	ep->tx_ring->base = cpu_to_le32(ep->dma_addr +
			offsetof(struct e1000_rt_dma_area, tx_buf));

	for (i = 0; i < 6; i++) {
		ep->init_block->paddr[i] = dev->dev_addr[i];
	}
	ep->init_block->rdra = cpu_to_le32((u32)(ep->dma_addr +
		offsetof(struct e1000_rt_dma_area, rx_ring)));
	ep->init_block->rdra |= cpu_to_le32(E1000_LOG_RX_BUFFERS);
	ep->init_block->tdra = cpu_to_le32((u32)(ep->dma_addr +
		offsetof(struct e1000_rt_dma_area, tx_ring)));
	ep->init_block->tdra |= cpu_to_le32(E1000_LOG_TX_BUFFERS);
	DEBUG_INIT_RING("e1000_init_ring: Receive  Desc Ring DMA Addr | Rlen[3:0]: 0x%x\n",
			le32_to_cpu(ep->init_block->rdra));
	DEBUG_INIT_RING("e1000_init_ring: Transmit Desc Ring DMA Addr | Tlen[3:0]: 0x%x\n",
			le32_to_cpu(ep->init_block->tdra));
	DEBUG_INIT_RING("e1000_init_ring: init block mode: 0x%x\n",
			le16_to_cpu(ep->init_block->mode));

	wmb();      /* Make sure all changes are visible */
	return 0;
}

/* Must be called ep->lock locked */
static void
e1000_rt_restart(struct net_device *dev, struct e1000_rt_private *ep)
{
	int i;
	e1000_write_e_csr(ep, STOP);
	ep->last_tx_res = -EIO;
	ep->rx_skipped = -0xefffffff;
	ep->tx_inprogress = 0;
	ep->recieved = 0;

	if (netif_msg_hw(ep)) {
		pr_warning("%s: restatrt\n", dev->name);
	}
	e1000_write_e_csr(ep, STOP);
	for (i = 0; i < 1000; i++) {
		if (e1000_read_e_csr(ep) & STOP) {
			break;
		}
	}
	if (i >= 1000) {
		pr_warning("%s: e1000_restart timed out waiting for stop.\n",
			dev->name);
	}
	e1000_rt_init_ring(dev);

	e1000_write_e_csr(ep, INIT);
	i = 0;
	while (i++ < 1000) {
		if (e1000_read_e_csr(ep) & IDON) {
			break;
		}
	}
        if (i >= 1000) {
                pr_warning("%s: initialization is not completed, status register "
                        "0x%08x\n", dev->name, e1000_read_e_csr(ep));
        }

	e1000_write_e_csr(ep,(INEA|STRT));
}

static irqreturn_t e1000_rt_interrupt(int irq, void *dev_id)
{
	struct net_device *dev = dev_id;
	struct e1000_rt_private *ep = netdev_priv(dev);
	unsigned long flags;
	u16 csr0;


	raw_spin_lock_irqsave(&ep->lock, flags);
	csr0 = e1000_read_e_csr(ep);
	if (!(csr0 & INTR)) {
		raw_spin_unlock_irqrestore(&ep->lock, flags);
		return IRQ_NONE; /* Not our interrupt */
	}
	if (netif_msg_intr(ep)) {
		pr_info("%s intr: csr0 = 0x%08x\n", dev->name, csr0);
	}
	/* Acknowledge all of the current interrupt sources ASAP. */
	csr0 &= (BABL|CERR|MISS|MERR|RINT|TINT);
	e1000_write_e_csr(ep, csr0|IDON);

	if (csr0 & (MERR | BABL)) {
		e1000_rt_restart(dev, ep);
		raw_spin_unlock_irqrestore(&ep->lock, flags);
		return IRQ_HANDLED;
	}
	if (csr0 & MISS) {
		ep->stats.rx_errors++;
		ep->rx_skipped++;
		ep->recieved = 0;
		if (netif_msg_rx_err(ep)) {
			pr_info("%s error: MISS\n", dev->name);
		}
	}

	if (csr0 & TINT) {
		// It's possible don't process TINT here,
		// we do it in rt_write as well
		int status = (short)le16_to_cpu(ep->tx_ring->status);
		if (status < 0) {
			goto end_of_tint;
		}
		if (status & TD_ERR) {
			int err_status = le32_to_cpu(ep->tx_ring->misc);
			ep->stats.tx_errors++;
			if (netif_msg_tx_err(ep)) {
				pr_warning("%s: Tx error status=%04x"
					" err_status=%08x\n",
					dev->name, status, err_status);
			}
			if (err_status & TD_RTRY) {
				ep->stats.tx_aborted_errors++;
				ep->last_tx_res = EIO;
			}
			if (err_status & TD_LCAR) {
				ep->stats.tx_carrier_errors++;
				ep->last_tx_res = EPIPE;
			}
			if (err_status & TD_LCOL) {
				ep->stats.tx_window_errors++;
				ep->last_tx_res = EIO;
			}
			if (err_status & TD_UFLO) {
				ep->stats.tx_fifo_errors++;
				e1000_rt_restart(dev, ep);
				raw_spin_unlock_irqrestore(&ep->lock, flags);		
				return IRQ_HANDLED;
			}
		} else {
			ep->stats.tx_packets++;
		}
		ep->last_tx_res = 0;
		ep->tx_ring->status = 0;
	}
end_of_tint:
	if (csr0 & RINT) {
		int entry = ep->cur_rx;
		int status = (short)le16_to_cpu(ep->rx_ring[entry].status);
		if ((status & 0xff00) != (RD_ENP|RD_STP)) {/* There was an error. */
			if (netif_msg_rx_err(ep)) {
				pr_warning("%s: Tx error status=%04x",
					dev->name, status);
			}
			if (status & RD_FRAM) {
				ep->stats.rx_frame_errors++;
			}
			if (status & RD_OFLO) {
				ep->stats.rx_over_errors++;
			}
			if (status & RD_CRC) {
				ep->stats.rx_crc_errors++;
			}
			if (status & RD_BUFF) {
				ep->stats.rx_fifo_errors++;
			}
			ep->rx_skipped += (!!ep->recieved) + 1;
			ep->recieved = 0;
			ep->rx_ring[entry].status = 0;
			ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
		} else {  /* recieved OK */
			ep->stats.rx_packets++;
			ep->stats.rx_bytes +=
				(le16_to_cpu(ep->rx_ring[entry].msg_length) & 0xfff) - CRC_SZ;
			if (netif_msg_rx_status(ep)) {
				pr_warning("%s intr: pkt recieved %d. recieved = %d "
					"; skipped = %d; pinned = %d\n",
					dev->name, entry, ep->recieved,
					ep->rx_skipped, ep->pinned);
			}
			if (ep->recieved && !ep->pinned) {
				ep->rx_skipped++;
				ep->recieved = entry + 1;
				entry = (++entry) & RX_RING_MOD_MASK;
				if (!(ep->rx_ring[entry].status & cpu_to_le16(RD_OWN))) {
					ep->rx_ring[entry].status = 0;
					ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
				}
			} else {
				ep->recieved = ++entry;
			}
			ep->cur_rx = entry & RX_RING_MOD_MASK;
			if (ep->rx_waiter) {
				wake_up_process(ep->rx_waiter);
			}
		}
	}
        raw_spin_unlock_irqrestore(&ep->lock, flags);
	e1000_write_e_csr(ep, INEA);

	return IRQ_HANDLED;
}
			


static int e1000_rt_write(struct net_device *dev, struct ifreq *rq)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	el_netdev_udata_t *ud;
	int r;
	int len = 0;
	char *u_buf = 0;
	u16  proto = 0;
	u16 status = le16_to_cpu(ep->tx_ring->status);
	// XXX to sync users
	if (xchg(&ep->tx_inprogress, 1)) {
		return -EBUSY;
	}
	if (status & TD_OWN) {
		ep->tx_inprogress = 0;
		return -EBUSY;
	}
	ud = (el_netdev_udata_t *)(rq->ifr_data);
	r = get_user(len, &ud->tx_len);
	r |= get_user(proto, &ud->proto);
	r |= get_user(u_buf, &ud->tx_buf);
	if (r) {
		return -EFAULT;
	}
	if (len > ETH_DATA_LEN) {
		return -EINVAL;
	}
	if (copy_from_user(&ep->tx_buf[2 * ETH_ALEN + 2], u_buf, len)) {
		return -EFAULT;
	}
	if (copy_from_user(&ep->tx_buf[0], &ud->dst_mac, ETH_ALEN)) {
		return -EFAULT;
	}
	if (copy_from_user(&ep->tx_buf[ETH_ALEN], &ud->src_mac, ETH_ALEN)) {
		return -EFAULT;
	}
	*((u16 *)(&ep->tx_buf[2 * ETH_ALEN])) = cpu_to_be16((u16)(proto));
	// Do real transfer
	len += ETH_HLEN;
	if (len <= ETH_ZLEN) {
		len = ETH_ZLEN;
	}
	if (netif_msg_tx_queued(ep)) {
		int *b = (int *)ep->tx_buf;
		pr_info("TX %s: len = %d\n", dev->name, len);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
		b[0], b[1], b[2], b[3]);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
			 b[4], b[5], b[6], b[7]);
	}
	raw_spin_lock_irq(&ep->lock);
	if (ep->opened <= 0) {
		raw_spin_unlock_irq(&ep->lock);
		ep->tx_inprogress = 0;
		return -ENODEV;
	}
	// to synchronize with reset in interrupt handler
	status = le16_to_cpu(ep->tx_ring->status);
	if (status & TD_ERR) {
		int err_status = le32_to_cpu(ep->tx_ring->misc);
		// process error ourselves
		e1000_write_e_csr(ep, TINT);
		ep->stats.tx_errors++;
		if (netif_msg_tx_err(ep)) {
			pr_warning("%s: Tx error status=%04x"
				" err_status=%08x\n",
				dev->name, status, err_status);
		}
		if (err_status & TD_RTRY) {
			ep->stats.tx_aborted_errors++;
			ep->last_tx_res = EIO;
		}
		if (err_status & TD_LCAR) {
			ep->stats.tx_carrier_errors++;
			ep->last_tx_res = ENOTCONN;
		}
		if (err_status & TD_LCOL) {
			ep->stats.tx_window_errors++;
			ep->last_tx_res = EIO;
		}
		if (err_status & TD_UFLO) {
			ep->stats.tx_fifo_errors++;
			e1000_rt_restart(dev, ep);
			ep->last_tx_res = EIO;
		}
	}
	ep->tx_ring->buf_length = cpu_to_le16(-len);
	ep->tx_ring->misc = 0x00000000;
	status = TX_ST_OWN | TX_ST_ENP | TX_ST_STP;
	if (CAN_DISABLE_TXINT(ep)) {
		status |= TX_ST_NOINTR;
	}
	ep->tx_ring->status = cpu_to_le16(status);
	wmb();
	ep->tx_inprogress = 0;
	ep->stats.tx_bytes += len;
	e1000_write_e_csr(ep, INEA|TDMD);
	raw_spin_unlock_irq(&ep->lock);
	put_user(ep->last_tx_res, &ud->timeout);
	if (netif_msg_tx_queued(ep)) {
		pr_info("%s Tx started\n", dev->name);
	}
	return 0;
}

#ifdef CONFIG_COMPAT

static int e1000_rt_compat_write(struct net_device *dev, struct ifreq *rq)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
        el_netdev_udata_compat_t ud, *udp;
	int len = 0;
	char *u_buf = 0;
	u16  proto = 0;
	u16 status = le16_to_cpu(ep->tx_ring->status);

	// XXX to sync users
	if (xchg(&ep->tx_inprogress, 1)) {
		return -EBUSY;
	}
	if (status & TD_OWN) {
		ep->tx_inprogress = 0;
		return -EBUSY;
	}
        udp = (el_netdev_udata_compat_t *)(rq->ifr_data);
        if (copy_from_user(&ud, udp, sizeof (el_netdev_udata_compat_t))) {
                return -EFAULT;
        }
	if (ud.tx_len <= 0) {
		return -EINVAL;
	}
        if (ud.tx_len > ETH_DATA_LEN) {
                return -EINVAL;
        }
	len = ud.tx_len;
	proto = ud.proto;
	u_buf = (char *)(long)ud.tx_buf;
	if (copy_from_user(&ep->tx_buf[2 * ETH_ALEN + 2], u_buf, len)) {
		return -EFAULT;
	}
        memcpy(&ep->tx_buf[0], ud.dst_mac, ETH_ALEN);
        memcpy(&ep->tx_buf[ETH_ALEN], ud.src_mac, ETH_ALEN);
	*((u16 *)(ep->tx_buf + 2 * ETH_ALEN)) = cpu_to_be16((u16)(ud.proto));
	// Do real transfer
	len += ETH_HLEN;
	if (len <= ETH_ZLEN) {
		len = ETH_ZLEN;
	}
	if (netif_msg_tx_queued(ep)) {
		int *b = (int *)ep->tx_buf;
		pr_info("TX %s: len = %d\n", dev->name, len);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
		b[0], b[1], b[2], b[3]);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
			 b[4], b[5], b[6], b[7]);
	}
	raw_spin_lock_irq(&ep->lock);
	if (ep->opened <= 0) {
		raw_spin_unlock_irq(&ep->lock);
		ep->tx_inprogress = 0;
		return -ENODEV;
	}
	// to synchronize with reset in interrupt handler
	status = le16_to_cpu(ep->tx_ring->status);
	if (status & TD_ERR) {
		int err_status = le32_to_cpu(ep->tx_ring->misc);
		// process error ourselves
		e1000_write_e_csr(ep, TINT);
		ep->stats.tx_errors++;
		if (netif_msg_tx_err(ep)) {
			pr_warning("%s: Tx error status=%04x"
				" err_status=%08x\n",
				dev->name, status, err_status);
		}
		if (err_status & TD_RTRY) {
			ep->stats.tx_aborted_errors++;
			ep->last_tx_res = EIO;
		}
		if (err_status & TD_LCAR) {
			ep->stats.tx_carrier_errors++;
			ep->last_tx_res = ENOTCONN;
		}
		if (err_status & TD_LCOL) {
			ep->stats.tx_window_errors++;
			ep->last_tx_res = EIO;
		}
		if (err_status & TD_UFLO) {
			ep->stats.tx_fifo_errors++;
			e1000_rt_restart(dev, ep);
			ep->last_tx_res = EIO;
		}
	}
	ep->tx_ring->buf_length = cpu_to_le16(-len);
	ep->tx_ring->misc = 0x00000000;
	status = TX_ST_OWN | TX_ST_ENP | TX_ST_STP;
	if (CAN_DISABLE_TXINT(ep)) {
		status |= TX_ST_NOINTR;
	}
	ep->tx_ring->status = cpu_to_le16(status);
	wmb();
	ep->tx_inprogress = 0;
	ep->stats.tx_bytes += len;
	e1000_write_e_csr(ep, INEA|TDMD);
	raw_spin_unlock_irq(&ep->lock);
	put_user(ep->last_tx_res, &udp->timeout);
	if (netif_msg_tx_queued(ep)) {
		pr_info("%s Tx started\n", dev->name);
	}
	return 0;
}

#endif   /* CONFIG_COMPAT */
static int e1000_rt_read(struct e1000_rt_private *ep, struct ifreq *rq)
{
	el_netdev_udata_t *ud;
	char *buf = NULL;
	int skipped;
	int proto;
	int entry;
	int len = -1;
	int msg_len;
	int r;
	int timeout= -1;
	char *u_buf = 0;

	ud = (el_netdev_udata_t *)(rq->ifr_data);
	r = get_user(len, &ud->rx_len);
	r |= get_user(timeout, &ud->timeout);
	r |= get_user(u_buf, &ud->rx_buf);
	if (r) {
		return -EFAULT;
	}
	if (timeout > 0) {
	timeout = (timeout * HZ) / 1000;
	}
	raw_spin_lock_irq(&ep->lock);
	if (ep->opened <= 0) {
		raw_spin_unlock_irq(&ep->lock);
		return -ENODEV;
	}
	if (ep->rx_waiter) {
		raw_spin_unlock_irq(&ep->lock);
		return -EBUSY;
	}


	while (!ep->recieved) {
               // we dont have data
		if (timeout == 0) {
			raw_spin_unlock_irq(&ep->lock);
			return -ETIMEDOUT;
		}
		current->state = TASK_INTERRUPTIBLE;
		ep->rx_waiter = current;
                raw_spin_unlock_irq_no_resched(&ep->lock);
		if (timeout > 0) {
			timeout = schedule_timeout(timeout);
		} else {
			schedule();
		}
		if (signal_pending(current)) {
			ep->rx_waiter = NULL;
			return -EINTR;
		}
		raw_spin_lock_irq(&ep->lock);
		ep->rx_waiter = NULL;
	}
	entry = ep->recieved - 1;
	skipped = ep->rx_skipped;
	buf = ep->rx_buf[entry].b;
	proto = (int)be16_to_cpu(*((u16 *)(buf + 2 * ETH_ALEN)));
	msg_len =  (le16_to_cpu(ep->rx_ring[entry].msg_length) & 0xfff) -
			ETH_HLEN - CRC_SZ;
	// we can't copy to user under raw_spinlock.
	// just mark it to notify we use this buffer
	ep->pinned = 1;
        ep->recieved = 0;
	ep->rx_skipped = 0;

	if ((ep->cur_rx != entry) &&
		!(le16_to_cpu(ep->rx_ring[ep->cur_rx].status) & RD_OWN)) {
		ep->rx_ring[ep->cur_rx].status = 0;
		ep->rx_ring[ep->cur_rx].status |= cpu_to_le16(RD_OWN);
		wmb();
	}

        raw_spin_unlock_irq(&ep->lock);

	buf += 2 * ETH_ALEN + 2;
	len = (len > msg_len) ? msg_len : len;
        if (copy_to_user(u_buf, buf, len)) {
                return -EFAULT;
        }
	if (netif_msg_rx_status(ep)) {
		int *b = (int *)ep->rx_buf[entry].b;
		pr_info("%s RX_STATUS: buf = %d, len = %d\n",
			ep->dev->name, entry, len);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
			b[0], b[1], b[2], b[3]); 
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
			b[4], b[5], b[6], b[7]);
	} 

	// Now return the buffer to a card
	ep->rx_ring[entry].status = 0;
	ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
	wmb();
	ep->pinned = 0;
        r  = put_user(len, &ud->rx_len);
        r |= put_user(skipped, &ud->skipped);
        r |= put_user(proto, &ud->proto);
        if (r) {
                return -EFAULT;
        }
        return 0;
}


#ifdef CONFIG_COMPAT


static int e1000_rt_compat_read(struct e1000_rt_private *ep, struct ifreq *rq)
{
        el_netdev_udata_compat_t *udp, ud;
	char *buf = NULL;
	int skipped;
	int proto;
	int entry;
	int len = -1;
	int msg_len;
	int r;
	int timeout= -1;
	char *u_buf = 0;

        udp = (el_netdev_udata_compat_t *)(rq->ifr_data);
        if (copy_from_user(&ud, udp, sizeof (el_netdev_udata_compat_t))) {
                return -EFAULT;
        }
        len = ud.rx_len;
	if (len < ETH_HLEN) {
		return -EINVAL;
	}
        timeout = ud.timeout;
        u_buf = (char *)(long)ud.rx_buf;
	if (timeout > 0) {
		timeout = (timeout * HZ) / 1000;
	}
	raw_spin_lock_irq(&ep->lock);
	if (ep->opened <= 0) {
		raw_spin_unlock_irq(&ep->lock);
		return -ENODEV;
	}
	if (ep->rx_waiter) {
		raw_spin_unlock_irq(&ep->lock);
		return -EBUSY;
	}


	while (!ep->recieved) {
               // we dont have data
		if (timeout == 0) {
			raw_spin_unlock_irq(&ep->lock);
			return -ETIMEDOUT;
		}
		current->state = TASK_INTERRUPTIBLE;
		ep->rx_waiter = current;
                raw_spin_unlock_irq_no_resched(&ep->lock);
		if (timeout > 0) {
			timeout = schedule_timeout(timeout);
		} else {
			schedule();
		}
		if (signal_pending(current)) {
			ep->rx_waiter = NULL;
			return -EINTR;
		}
		raw_spin_lock_irq(&ep->lock);
		ep->rx_waiter = NULL;
	}
	entry = ep->recieved - 1;
	skipped = ep->rx_skipped;
	buf = ep->rx_buf[entry].b;
	proto = (int)be16_to_cpu(*((u16 *)(buf + 2 * ETH_ALEN)));
	msg_len =  (le16_to_cpu(ep->rx_ring[entry].msg_length) & 0xfff) -
			ETH_HLEN - CRC_SZ;
	// we can't copy to user under raw_spinlock.
	// just mark it to notify we use this buffer
	ep->pinned = 1;
        ep->recieved = 0;
	ep->rx_skipped = 0;

	if ((ep->cur_rx != entry) &&
		!(le16_to_cpu(ep->rx_ring[ep->cur_rx].status) & RD_OWN)) {
		ep->rx_ring[ep->cur_rx].status = 0;
		ep->rx_ring[ep->cur_rx].status |= cpu_to_le16(RD_OWN);
		wmb();
	}

        raw_spin_unlock_irq(&ep->lock);

	buf += 2 * ETH_ALEN + 2;
	len = (len > msg_len) ? msg_len : len;
        if (copy_to_user(u_buf, buf, len)) {
                return -EFAULT;
        }
	if (netif_msg_rx_status(ep)) {
		int *b = (int *)ep->rx_buf[entry].b;
		pr_info("%s RX_STATUS: buf = %d, len = %d\n",
			ep->dev->name, entry, len);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
			b[0], b[1], b[2], b[3]); 
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n",
			b[4], b[5], b[6], b[7]);
	} 

	// Now return the buffer to a card
	ep->rx_ring[entry].status = 0;
	ep->rx_ring[entry].status |= cpu_to_le16(RD_OWN);
	wmb();
	ep->pinned = 0;
        r  = put_user(len, &udp->rx_len);
        r |= put_user(skipped, &udp->skipped);
        r |= put_user(proto, &udp->proto);
        if (r) {
                return -EFAULT;
        }
        return 0;
}

#endif	/* CONFIG_COMPAT */

static int
e1000_rt_netdev_open(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int rc = 0;
	unsigned int init_block_addr_part = 0;
	int i;
	unsigned long irqflags = IRQF_ONESHOT | IRQF_SHARED;

	if (netif_msg_ifup(ep)) {
		pr_info("e1000_rt_netdev_open(): begin\n");
	}

	raw_spin_lock_irq(&ep->lock);
	if (ep->opened) {
		raw_spin_unlock_irq(&ep->lock);
		if (netif_msg_ifup(ep)) {
			pr_info("Already opened\n");
		}
		rc = -EBUSY;
		goto err;
	}
	ep->opened  = 1;
	raw_spin_unlock_irq(&ep->lock);

	/* Reset the PCNET32 */
	e1000_write_e_csr(ep, STOP);
	/* wait for stop */
	for (i = 0; i < 1000; i++) {
		if (e1000_read_e_csr(ep) & STOP) {
			break;
		}
	}
	if (i >= 100 && netif_msg_drv(ep)) {
		pr_warning("%s: e1000_restart timed out waiting for stop.\n",
			dev->name);
		rc = -EAGAIN;
		goto err;
	}

	/* Check for a valid station address */
	if (!is_valid_ether_addr(dev->dev_addr)) {
		pr_warning("%s: not valid eth address\n", dev->name);
		rc = -EINVAL;
		goto err;
	}

	ep->init_block->mode = le16_to_cpu(e1000_rt_mode);
	ep->init_block->laddrf = 0x0000000000000000;

	if (netif_msg_ifup(ep)) {
		pr_info("%s: e1000_open(): irq %u tx/rx rings %#llx/%#llx "
			"init %#llx.\n",
			dev->name, dev->irq,
			(u64)(ep->dma_addr + offsetof(struct e1000_rt_dma_area, tx_ring)),
			(u64)(ep->dma_addr + offsetof(struct e1000_rt_dma_area, rx_ring)),
			(u64)(ep->dma_addr + offsetof(struct e1000_rt_dma_area, init_block)));
	}

	e1000_rt_init_ring(dev);

	/* Re-initialize the PCNET32, and start it when done. */
	/* low 32 bits */
	init_block_addr_part = (ep->dma_addr + offsetof(struct e1000_rt_dma_area,
		init_block)) & 0xffffffff;
	e1000_write_e_base_address(ep, init_block_addr_part);
	/* high 32 bits */
	init_block_addr_part = ((u64)(ep->dma_addr +
		offsetof(struct e1000_rt_dma_area,
			init_block)) >> 32) & 0xffffffff;
	e1000_write_dma_base_address(ep, init_block_addr_part);

	/* start e1000 */
	e1000_write_e_csr(ep, INIT);


	e1000_rt_set_phy_mode(dev);
	mii_check_media(&ep->mii_if, netif_msg_link(ep), 1);
	mod_timer (&(ep->watchdog_timer), E1000_WATCHDOG_TIMEOUT);
	i = 0;
	while (i++ < 1000) {
		if (e1000_read_e_csr(ep) & IDON) {
			break;
		}
	}
	if (netif_msg_ifup(ep)) {
		pr_info("e1000_open(): e_csr register after "
			"initialization: 0x%x, must be 0x%x\n",
			e1000_read_e_csr(ep),
			(IDON | INTR | INIT));
	}
	if (i >= 1000) {
		pr_warning("%s:e1000_open(): e_csr register after "
			"initialization: 0x%x, must be 0x%x\n",
			dev->name, e1000_read_e_csr(ep),
			(IDON | INTR | INIT));
		rc = -EAGAIN;
		goto err;
	}
	/* clear IDON */
	e1000_write_e_csr(ep, IDON);
	if (netif_msg_ifup(ep)) {
		pr_info("e1000_open(): e_csr register after "
                       "clear IDON bit: 0x%x, must be 0x%x\n",
                       e1000_read_e_csr(ep), (INIT));
		dump_init_block(dev);
	}


	/* Card is ready to work. It's time to request irq */
	if (ep->msix_entries) {
		// MSIX supported
		ep->irq = ep->msix_entries[ep->bar].vector;
	} else {
		ep->irq = ep->pci_dev->irq;
	}

	if (request_threaded_irq(ep->irq, &e1000_rt_interrupt, NULL,
			irqflags, dev->name, (void *)dev)) {
		pr_warning("%s: Could not request irq\n", dev->name);
                rc = -EAGAIN;
		goto err;
        }

		
	/* setup Interrupt enable and start bits */
	e1000_write_e_csr(ep, INEA|STRT);
	if (netif_msg_ifup(ep)) {
		pr_info("e1000_open(): e_csr register after "
			"setting STRT bit: 0x%x, must be 0x%x\n",
			e1000_read_e_csr(ep),
			(INEA | RXON | TXON | STRT | INIT));
		pr_info("e1000_open(): end\n");
	}
	return 0;       /* Always succeed */

err:
	e1000_write_e_csr(ep, STOP);
	if (netif_msg_ifup(ep)) {
		pr_debug("e1000_open(): end badly. error = %d\n", -rc);
	}
	ep->opened = 0;
	return rc;
}





static void e1000_rt_netdev_close(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	if (netif_msg_ifdown(ep)) {
		pr_debug("e1000_rt_netdev_close begin\n");
	}
	del_timer_sync(&ep->watchdog_timer);
	raw_spin_lock_irq(&ep->lock);
	if (ep->opened == 0) {
		if (netif_msg_ifdown(ep)) {
			pr_debug("Not opened\n");
		}
		raw_spin_unlock_irq(&ep->lock);
		return;
	}
	if (ep->opened < 0) {
		if (netif_msg_ifdown(ep)) {
			pr_debug("Already closing\n");
		}
		raw_spin_unlock_irq(&ep->lock);
		return;	
	}
	ep->opened = -1;
	raw_spin_unlock_irq(&ep->lock);


	if (netif_msg_ifdown(ep)) {
		pr_debug("%s: Shutting down ethercard, status was %2.2x.\n",
			dev->name, e1000_read_e_csr(ep));
	}
	e1000_write_e_csr(ep, STOP);
	free_irq(ep->irq, dev);
	ep->opened = 0;
	if (netif_msg_ifdown(ep)) {
		pr_debug("e1000_rt_netdev_close closed\n");
	}

	return;
}





/*    Ethtool support functions   */

static int e1000_rt_get_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int r = -EOPNOTSUPP;

	if (ep->mii) {
		mii_ethtool_gset(&ep->mii_if, cmd);
		r = 0;
	}
	return r;
}

static int e1000_rt_set_settings(struct net_device *dev, struct ethtool_cmd *cmd)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int r = -EOPNOTSUPP;

	if (ep->mii) {
		r = mii_ethtool_sset(&ep->mii_if, cmd);
		e1000_rt_set_phy_mode(dev);
	}
	return r;
}

static void e1000_rt_get_drvinfo(struct net_device *dev, struct ethtool_drvinfo *info)
{
	struct e1000_rt_private *ep = netdev_priv(dev);

	strcpy (info->driver, DRV_NAME);
	strcpy (info->version, DRV_VERSION);
	if (ep->pci_dev)
		strcpy (info->bus_info, pci_name(ep->pci_dev));
	else
		sprintf(info->bus_info, "VLB 0x%lx", dev->base_addr);
}

static u32 e1000_rt_get_msglevel(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	return ep->msg_enable;
}

static void e1000_rt_set_msglevel(struct net_device *dev, u32 value)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	ep->msg_enable = value;
}

static int e1000_rt_nway_reset(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int r = -EOPNOTSUPP;

	if (ep->mii) {
		r = mii_nway_restart(&ep->mii_if);
	}
	return r;
}


static u32 e1000_rt_get_link(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int r;

	if (ep->mii) {
		r = mii_link_ok(&ep->mii_if);
	} else {
		/* FIXME */
		r = 0;
	}

	return r;
}

static void e1000_rt_get_ringparam(struct net_device *dev,
                        struct ethtool_ringparam *ering)
{
	struct e1000_rt_private *ep = netdev_priv(dev);

	ering->tx_max_pending = TX_RING_SIZE - 1;
	ering->tx_pending = 0;
	ering->rx_max_pending = RX_RING_SIZE - 1;
	ering->rx_pending = ep->cur_rx;
}



static int e1000_rt_get_regs_len(struct net_device *dev)
{
	return(E1000_NUM_REGS * sizeof(u16));
}


static void e1000_rt_get_regs(struct net_device *dev, struct ethtool_regs *regs,
				void *ptr)
{
	int i;
	u32 *buff = ptr;
	u16 *mii_buff = NULL;
	struct e1000_rt_private *ep = netdev_priv(dev);


	/* read e1000 registers */
	*buff++ = e1000_read_e_csr(ep);
	*buff++ = e1000_read_mgio_csr(ep);
	*buff++ = e1000_read_psf_csr(ep);
	*buff++ = e1000_read_psf_data(ep);

	/* read mii phy registers */

	if (ep->mii) {
		mii_buff = (u16 *)buff;
		for (i = 0; i < 32; i++) {
		*mii_buff++ = mdio_read(dev, ep->mii_if.phy_id, i);
	}
	}

	i = mii_buff - (u16 *)ptr;
	for (; i < E1000_NUM_REGS; i++)
		*mii_buff++ = 0;
}

static struct ethtool_ops e1000_ethtool_ops = {
	.get_settings       = e1000_rt_get_settings,
	.set_settings       = e1000_rt_set_settings,
	.get_drvinfo        = e1000_rt_get_drvinfo,
	.get_msglevel       = e1000_rt_get_msglevel,
	.set_msglevel       = e1000_rt_set_msglevel,
	.nway_reset         = e1000_rt_nway_reset,
	.get_link           = e1000_rt_get_link,
	.get_ringparam      = e1000_rt_get_ringparam,
	.get_regs_len       = e1000_rt_get_regs_len,
	.get_regs           = e1000_rt_get_regs,
};


/* ioctl - main intrface for netdev */

static void
dump_ring_state(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int i;

	pr_warning("%s:%s: Ring data dump:  cur_rx %u.\n",
		dev->name, ep->name, ep->cur_rx);
	for (i = 0 ; i < RX_RING_SIZE; i++) {
		pr_warning("   RX %03d base %08x buf len %04x msg len %04x status "
			"%04x\n", i,
			le32_to_cpu(ep->rx_ring[i].base),
			le16_to_cpu((-ep->rx_ring[i].buf_length& 0xffff) ),
			le16_to_cpu(ep->rx_ring[i].msg_length),
			(u16)le16_to_cpu((ep->rx_ring[i].status)));
		}
	pr_warning("\n");
	pr_warning("   TX %03d base %08x buf len %04x misc %04x status "
		"%04x\n", 0,
		le32_to_cpu(ep->tx_ring->base),
		le16_to_cpu((-ep->tx_ring->buf_length) & 0xffff),
		le32_to_cpu(ep->tx_ring->misc),
		le16_to_cpu((u16)(ep->tx_ring->status)));
	pr_warning("\n");
}


static void
dump_init_block(struct net_device *dev)
{
	struct e1000_rt_private *ep = netdev_priv(dev);

	pr_warning("%s:%s: Init block (%p - 0x%08lx)state:\n",
		dev->name, ep->name, ep->init_block, (unsigned long)ep->dma_addr);
	pr_warning("   MODE 0x%04x PADDR 0x%02x%02x%02x%02x%02x%02x "
		"LADDRF 0x%016llx\n",
		le16_to_cpu(ep->init_block->mode),
		ep->init_block->paddr[5], ep->init_block->paddr[4],
		ep->init_block->paddr[3], ep->init_block->paddr[2],
		ep->init_block->paddr[1], ep->init_block->paddr[0],
		ep->init_block->laddrf);
	pr_warning("   Receive  Desc Ring Addr: 0x%08x\n",
		le32_to_cpu(ep->init_block->rdra));
	pr_warning("   Transmit Desc Ring Addr: 0x%08x\n",
		le32_to_cpu(ep->init_block->tdra));
	pr_warning("CSR = 0x%08x\n", e1000_read_e_csr(ep));
}



static int e1000_rt_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct e1000_rt_private *ep = netdev_priv(dev);
	int rc = 0;

	switch (cmd) {
	case SIOCDEV_RTND_OPEN :
		rc = e1000_rt_netdev_open(dev);
		break;
	case SIOCDEV_RTND_CLOSE :
		e1000_rt_netdev_close(dev);
		rc = 0;
		break;
	case SIOCDEV_RTND_READ :
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
			rc = e1000_rt_compat_read(ep, rq);
			break;
		}
#endif
		rc = e1000_rt_read(ep, rq);
		break;
	case SIOCDEV_RTND_WRITE :
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
                        rc = e1000_rt_compat_write(dev, rq);
                        break;
		}
#endif
		rc = e1000_rt_write(dev, rq);
		break;
	case SIOCDEVPRIVATE + 10 :
		pr_warning("===== Dump state of l_e1000_rt %s ====\n", dev->name);
		pr_warning("tx_inprogress = %d;\tlast_tx_res = %d\n",
			ep->tx_inprogress, ep->last_tx_res);
		pr_warning("recieved = %d;\tpinned = %d;\trx_skipped = %d\n",
			ep->recieved, ep->pinned, ep->rx_skipped);
		pr_warning("rx_waiter = %p\n", ep->rx_waiter);
		dump_init_block(dev);
		dump_ring_state(dev);
		break;
	default:
		/* SIOC[GS]MIIxxx ioctls */
		if (ep->mii) {
			rc = generic_mii_ioctl(&ep->mii_if, if_mii(rq), cmd, NULL);
		} else {
			rc = -EOPNOTSUPP;
		}
	}
	return rc;
}

/*         Probing     */


int e1000_rt_probe1(unsigned long ioaddr, unsigned char *base_ioaddr,
		int shared, struct pci_dev *pdev, struct resource *res,
		int bar,  struct msix_entry *msix_entries, int msi_status)
{
	int i = 0;
	struct e1000_rt_private *ep = NULL;
	struct net_device *dev = NULL;
	unsigned int soft_reset;
	int fdx, mii, gmii;
	int ret = -ENODEV;
	unsigned int init_block_addr_part = 0;
	u32 val = 0;
	void *p = NULL;
	struct e1000_rt_dma_area *m;
	size_t sz;

	dev = alloc_etherdev(sizeof(struct e1000_rt_private));
	if (!dev) {
		if (e1000_rt_debug & NETIF_MSG_PROBE)
			pr_alert(PFX "Memory allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;

	}
	ep = netdev_priv(dev);
	sz = ALIGN(sizeof (struct e1000_rt_dma_area), 32);
	p = kzalloc_node(sz, GFP_KERNEL | GFP_DMA, dev_to_node(&pdev->dev));
	if (!p) {
		pr_alert("L_E1000 RT: Memory allocation failed.\n");
		ret = -ENOMEM;
		goto err_release_region;
	}
	m = (struct e1000_rt_dma_area *)PTR_ALIGN(p, 32);
	ep->dma_area = p;
	ep->dma_addr = pci_map_single(pdev, p,
		sizeof(*m), PCI_DMA_BIDIRECTIONAL);
	ep->init_block = &m->init_block;
	ep->tx_ring = &m->tx_ring;
	ep->rx_ring = m->rx_ring;
	ep->rx_buf = m->rx_buf;
	ep->tx_buf = m->tx_buf;
	SET_NETDEV_DEV(dev, &pdev->dev);
	dev->base_addr = ioaddr;
	if (pci_read_config_byte(pdev, PCI_REVISION_ID, &ep->revision)) {
		pr_alert("%s: Can't read REVISION_ID\n", pci_name(pdev));
	}
	ep->pci_dev = pdev;
	ep->dev = dev;
	ep->base_ioaddr = base_ioaddr;
        /* Setup STOP bit; Force e1000 resetting  */
        e1000_write_e_csr(ep, STOP); /* RINT => 0; TINT => 0; IDON => 0; INTR => 0; 
                               * INEA => 0; RXON => 0; TXON => 0; TMDM => 0;
                               * STRT => 0; INIT => 0; 
                               * access to E_BASE_ADDR is allowed */
        /* PHY Resetting */
	soft_reset = 0;
	soft_reset |= (E1000_RSET_POLARITY | SRST);
	e1000_write_mgio_csr(ep, soft_reset); /* startup software reset */
	soft_reset = e1000_read_mgio_csr(ep);
	soft_reset &= ~(SRST);
	e1000_write_mgio_csr(ep, soft_reset); /* stop software reset */
	DEBUG_PROBE("E1000 probe: software reset PHY completed\n");

	raw_spin_lock_init(&ep->lock);

	l_cards_without_mac ++;
	/* Setup HW (MAC), also known as "Physical" address.
	 * because uknown for now, assumed to be 10:20:30:40:50:60 HEX */
	for (i = 0; i < 6; i++) {
		dev->dev_addr[i] = l_base_mac_addr[i];
	}
#ifdef  SET_DEFAULT_MAC
	dev->dev_addr[5] = l_base_mac_addr[5];
#else   /* use base IP address based on machine serial number */
	dev->dev_addr[5] += (l_cards_without_mac - 1) & 0xff;
#endif  /* SET_DEFAULT_MAC */

	fdx = 1; mii = 1; gmii = 1;
	SET_NETDEV_DEV(dev, &pdev->dev);
	ep->name = "l_e1000-rt";
	ep->mii_if.full_duplex = fdx;
	ep->mii_if.supports_gmii = gmii;
	ep->mii_if.phy_id_mask = 0x1f;
	ep->mii_if.reg_num_mask = 0x1f;
	ep->mii_if.dev = dev;
	ep->msg_enable = e1000_rt_debug;
//	ep->options = E1000_PORT_ASEL;
	ep->mii_if.mdio_read = mdio_read;
	ep->mii_if.mdio_write = mdio_write;
	ep->mii = mii;

	/* Setup init block */
	/*************************************************/
	ep->init_block->mode = cpu_to_le16(e1000_rt_mode);
	ep->init_block->laddrf = 0x0000000000000000;
	for (i = 0; i < 6; i++)
		ep->init_block->paddr[i] = dev->dev_addr[i];
	ep->init_block->laddrf   =  0x0000000000000000;
	ep->init_block->rdra = cpu_to_le32((u32)(ep->dma_addr +
		offsetof(struct e1000_rt_dma_area, rx_ring)));
	ep->init_block->rdra |= cpu_to_le32(E1000_LOG_RX_BUFFERS);
	ep->init_block->tdra = cpu_to_le32((u32)(ep->dma_addr +
		offsetof(struct e1000_rt_dma_area, tx_ring)));
	ep->init_block->tdra |= cpu_to_le32(E1000_LOG_TX_BUFFERS);
	DEBUG_PROBE("e1000_probe1: Receive  Desc Ring DMA Addr | Rlen[3:0]: 0x%x\n",
		le32_to_cpu(ep->init_block->rdra));
	DEBUG_PROBE("e1000_probe1: Transmit Desc Ring DMA Addr | Tlen[3:0]: 0x%x\n",
		le32_to_cpu(ep->init_block->tdra));
	/*****************************************************/
	/* low 32 bits */
	init_block_addr_part = (ep->dma_addr + offsetof(struct e1000_rt_dma_area,
		init_block)) & 0xffffffff;
	e1000_write_e_base_address(ep, init_block_addr_part);
	DEBUG_PROBE("e1000_probe1: Init Block Low  DMA addr: "
		"0x%x (align = 64 bytes)\n", init_block_addr_part);
	/* high 32 bits */
	init_block_addr_part = ((u64)(ep->dma_addr + offsetof(struct e1000_rt_dma_area,
		init_block)) >> 32) & 0xffffffff;
	e1000_write_dma_base_address(ep, init_block_addr_part);
	DEBUG_PROBE("e1000_probe1: Init Block High DMA addr: 0x%x\n", init_block_addr_part);
	/********************************************************/

	dev->irq = pdev->irq;
	if (e1000_rt_debug & NETIF_MSG_PROBE)
		pr_info("%s: assigned IRQ %u.\n", pci_name(pdev), dev->irq);
	else {
		pr_info("%s: assigned IRQ #%u\n", pci_name(pdev), dev->irq);
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
        /* Setup PHY 10/100/1000 Link on 10M Link */
        val = mdio_read(dev, ep->mii_if.phy_id, PHY_LED_CTRL);
        DEBUG_PROBE("e1000_probe1: PHY reg # 0x13 (LED_CTRL) : "
                "after reset :            0x%x\n", val);
        val |= RED_LEN_EN;
        mdio_write(dev, ep->mii_if.phy_id, PHY_LED_CTRL, val);

	val = mdio_read(dev, ep->mii_if.phy_id, PHY_BIST_CFG2);
	DEBUG_PROBE("e1000_probe1: PHY reg # 0x1a (BIST_CFG2): "
		"           :             0x%x\n", val);
	val |= LINK_SEL;
	mdio_write(dev, ep->mii_if.phy_id, PHY_BIST_CFG2, val);

        /* move e1000 link status select to default 0 link */
        val = e1000_read_mgio_csr(ep);
        val &= ~LSTS;
        val |= SLSP;
        e1000_write_mgio_csr(ep, val);
	e1000_rt_set_phy_mode(dev);

	init_timer (&ep->watchdog_timer);
	ep->watchdog_timer.data = (unsigned long) dev;
	ep->watchdog_timer.function = e1000_watchdog;

	/* The E1000-specific entries in the device structure. */
	dev->ethtool_ops = &e1000_ethtool_ops;
	dev->netdev_ops = &e1000_netdev_ops;
	dev->watchdog_timeo = (5*HZ);

	/* Fill in the generic fields of the device structure. */
	if (register_netdev(dev))
		goto err_free_consistent;

	if (pdev) {
		pci_set_drvdata(pdev, dev);
	}


        e1000_write_e_csr(ep, STOP);
	ep->resource = res;
	ep->bar = bar;
	ep->msix_entries = msix_entries;
	ep->msi_status = msi_status;

        pr_alert("%s : L-E1000 (rev. %d) %s used as RT device\n",
		dev->name, ep->revision, pci_name(ep->pci_dev));

	return 0;

err_free_consistent:
	pci_unmap_single(ep->pci_dev, ep->dma_addr, sizeof(*ep),
		PCI_DMA_BIDIRECTIONAL);
	free_netdev(dev);
err_release_region:
	if (dev) {
		free_netdev(dev);
	}
	if (p) {
		kfree(p);
	}
	return ret;
}




void e1000_rt_remove(struct pci_dev *pdev)
{
	struct net_device *dev = dev_get_drvdata(&pdev->dev);
	struct e1000_rt_private *ep = netdev_priv(dev);

	dev_set_drvdata(&pdev->dev, NULL);
	unregister_netdev(dev);
	iounmap(ep->base_ioaddr);
	release_resource(ep->resource);
	pci_release_region(pdev, E1000_TOTAL_SIZE);
	pci_unmap_single(ep->pci_dev, ep->dma_addr, sizeof(*ep),
                PCI_DMA_FROMDEVICE);
	kfree(ep->dma_area);
	free_netdev(dev);
	if (ep->msi_status == L_E1000_MSIX) {
		pci_disable_msix(pdev);
	} else if (ep->msi_status == L_E1000_MSI) {
		pci_disable_msi(pdev);
	}
	pci_disable_device(pdev);
}



#if defined(SEPARATE_RT_LE1000_DRIVER)
DEFINE_PCI_DEVICE_TABLE(e1000_rt_pci_tbl) = {
        {
                .vendor = PCI_VENDOR_ID_INTEL,
                .device = PCI_DEVICE_ID_E1000,
                .subvendor = PCI_SUBVENDOR_ID_E1000,
                .subdevice = PCI_ANY_ID,
        },
        {0, }
};

MODULE_DEVICE_TABLE (pci, e1000_rt_pci_tbl);
static int
e1000_rt_probe_pci(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	unsigned long ioaddr;
	unsigned char *base_ioaddr;
	struct resource *res;
	int err;

	err = pci_enable_device(pdev);
	if (err < 0) {
		if (e1000_rt_debug & NETIF_MSG_PROBE)
			pr_info(PFX "failed to enable device -- err=%d\n", err);
			return err;
	}
	pci_set_master(pdev);

	ioaddr = pci_resource_start (pdev, 0);
	if (!ioaddr) {
		if (e1000_rt_debug & NETIF_MSG_PROBE)
			pr_info(PFX "card has no PCI IO resources, aborting\n");
		return -ENODEV;
	}

	if (!pci_dma_supported(pdev, E1000_DMA_MASK)) {
		if (e1000_rt_debug & NETIF_MSG_PROBE)
			pr_info(PFX "architecture does not support 32bit PCI busmaster DMA\n");
		return -ENODEV;
	}
	res = request_mem_region(ioaddr, E1000_TOTAL_SIZE, "e1000_rt_pci");
	if (res == NULL) {
		if (e1000_rt_debug & NETIF_MSG_PROBE)
			pr_info(PFX "memio address range already allocated\n");
		return -EBUSY;
	}

	base_ioaddr = ioremap(ioaddr, E1000_TOTAL_SIZE);
	if (base_ioaddr == NULL){
		pr_warning(PFX "Unable to map base ioaddr = 0x%lx\n", ioaddr);
		release_resource(res);
		return -ENOMEM;
	}
	err =  e1000_rt_probe1(ioaddr, base_ioaddr, 1, pdev, res);
	if (err < 0) {
		release_resource(res);
		iounmap(base_ioaddr);
		pci_disable_device(pdev);
	}
	return err;
}




static struct pci_driver e1000_rt_driver = {
	.name           = "L-E1000-RT",
	.id_table       = e1000_rt_pci_tbl,
	.probe          = e1000_rt_probe_pci,
	.remove         = e1000_rt_remove,
};



static void __exit e1000_rt_cleanup_module(void)
{
	pci_unregister_driver(&e1000_rt_driver);
}

extern int e1000;
static int __init e1000_rt_init_module(void)
{
	pr_warning("L-E1000-RT driver loading\n");
	if (!e1000) {
		pr_alert("Ethernet e1000 driver not allowed. "
			"Use e1000 in command line\n");
		return (-ENODEV);
	}

	e1000_rt_debug = netif_msg_init(debug,
		NETIF_MSG_DRV        |
		NETIF_MSG_PROBE      |
		NETIF_MSG_LINK       |
		NETIF_MSG_TX_QUEUED  |
		NETIF_MSG_RX_STATUS  | 
		/* NETIF_MSG_PKTDATA   | */
		 NETIF_MSG_RX_ERR    |
		 NETIF_MSG_TX_ERR    |
		 NETIF_MSG_INTR      |
		NETIF_MSG_HW         |
		NETIF_MSG_IFUP       | 
	0);

	return pci_register_driver(&e1000_rt_driver);
}

module_param(debug, int, 0);
MODULE_PARM_DESC(debug, DRV_NAME " debug level");

module_init(e1000_rt_init_module);
module_exit(e1000_rt_cleanup_module);
#endif
