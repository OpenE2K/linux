#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/ioport.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/cpumask.h>
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
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pci_ids.h>
#include <linux/timecounter.h>		/* for IEEE 1588 */
#include <linux/net_tstamp.h>		/* for IEEE 1588 */
#include <linux/ptp_clock_kernel.h>	/* for IEEE 1588 */
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>

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
#include <asm/io_epic.h>
#include <asm/pci.h>

/* only for printk */
#include <linux/marvell_phy.h>


#define DRV_VERSION	"2.00"
#define DRV_RELDATE	"20.02.2020"
static const char *version = "mgb.c: v" DRV_VERSION " " DRV_RELDATE
			     " rev@mcst.ru, kalita_a@mcst.ru\n";


/* TI DP83867 phy identifier values (not in .h) */
#define DP83867_PHY_ID		0x2000a231


static int assigned_speed = SPEED_1000;
module_param_named(rate, assigned_speed, int, 0444);
MODULE_PARM_DESC(rate, "used to set rate to 2500");

static int check_tx_q_ring = 0;
module_param_named(check_tx, check_tx_q_ring, int, 0444);
MODULE_PARM_DESC(check_tx, "turn on checking tx rings");

static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, KBUILD_MODNAME " debug level");

static int rx_copybreak = 200;
module_param(rx_copybreak, int, 0);
MODULE_PARM_DESC(rx_copybreak,
		 KBUILD_MODNAME " copy breakpoint for copy-only-tiny-frames");

static int half_duplex;
module_param_named(hd, half_duplex, int, 0444);
MODULE_PARM_DESC(hd, "work in half duplex mode");

static int an_clause_73 = 0;
module_param(an_clause_73, int, 0444);
MODULE_PARM_DESC(an_clause_73, "use clause 73 autunegotiation");

static int mpll_mode = -1;
module_param_named(mpllmode, mpll_mode, int, 0444);
MODULE_PARM_DESC(mpllmode, "PCS MPLL mode: 0-normal, 1-bifurcation, 2-2.5G");

static int mgb_status = 2;
module_param_named(status, mgb_status, int, 0444);
MODULE_PARM_DESC(status, "0 - disable, 1 - enable, other - use devtree");


static DEFINE_MUTEX(mgb_mutex);


/* Register Map */
#define E_CSR		0x00 /* Ethernet Control/Status Register */
#define E_CAP		0x04 /* Ethernet Capabilities Register */
#define E_Q0CSR		0x08 /* Queue0 Control/Status Register */
#define E_Q1CSR		0x0C /* Queue1 Control/Status Register */
#define MGIO_CSR	0x10 /* MGIO   Control/Status Register */
#define MGIO_DATA	0x14 /* MGIO   Data Register */
#define E_BASE_ADDR	0x18 /* Ethernet Base Address Register */
#define DMA_BASE_ADDR	0x1C /* DMA      Base Address Register */
#define PSF_CSR		0x20 /* Pause Frame Control/Status Register */
#define PSF_DATA	0x24 /* Pause Frame Data Register */
#define IRQ_DELAY	0x28 /* Interrupt Delay Register */
#define SH_INIT_CNTRL	0x2C /* Shadow Init Control Register */
#define SH_DATA_L	0x30 /* Shadow Data Low Register */
#define SH_DATA_H	0x34 /* Shadow Data High Register */
#define RX_QUEUE_ARB	0x38 /* RX Queue Arbitration Register */
#define PSF_DATA1	0x3C /* Pause Frame Data1 Register */

#define MGB_TOTAL_SIZE	0x40 /* Size of Regs Pool */


/* E_CSR Register Fields */
#define SWINT		(1 << 22) /* RW,   SW Interrupt to do reset*/
#define PSFI		(1 << 21) /* R,    Pause Frame Interrupt */
#define SINT		(1 << 20) /* R,    Status Interrupt */
#define INTR		(1 << 19) /* R,    Interrupt Flag */
#define INEA		(1 << 18) /* RW,   Interrupt Enable */
#define ERR		(1 << 17) /* R,    Error */
#define SLVE		(1 << 16) /* RW1C, Slave Error */
#define BABL		(1 << 15) /* RW1C, Babble */
#define MERR		(1 << 14) /* RW1C, Memory Error */
#define CERR		(1 << 13) /* RW1C, Collission Error */
#define E_SYS_INT	(1 << 12) /* R,    System Interrupt */
#define Q1_TX_INT	(1 << 11) /* R,    Q1 Transmitter Interrupt */
#define Q1_RX_INT	(1 << 10) /* R,    Q1 Reciever Interrupt */
#define Q0_TX_INT	(1 <<  9) /* R,    Q0 Transmitter Interrupt */
#define Q0_RX_INT	(1 <<  8) /* R,    Q0 Reciever Interrupt */
#define IDON		(1 <<  7) /* RW1C, Initialization Done */
#define RXON1		(1 <<  6) /* R,    Reciever Q1 On */
#define TXON1		(1 <<  5) /* R,    Transmitter Q1 On */
#define RXON0		(1 <<  4) /* R,    Reciever Q0 On */
#define TXON01		(1 <<  3) /* R,    Transmitter Q0 On */
#define STOP		(1 <<  2) /* RW1,  Stop */
#define STRT		(1 <<  1) /* RW1,  Start */
#define INIT		(1 <<  0) /* RW1,  Initialize */
/*
 * E_SYS_INT =  PSFI |  SINT | (INTR & INEA)
 * INTR            =  IDON |  MERR | BABL |  SLVE
 */

/* E_CAP Register Fields */
#define ETMR_ADD_ENA	(1 << 23) /* RW, Ethernet Timer Adding Enable */
#define ETMR_CLR_ENA	(1 << 22) /* RW, Ethernet Timer Clear Enable */
#define UDP_PCS_ENA_TX	(1 << 21) /* RW, UDP Pkt Checksum Enabled on Xmit */
#define UDP_PCS_ENA_RX	(1 << 20) /* RW, UDP Pkt Checksum Enabled on Recievr */
#define TCP_PCS_ENA_TX	(1 << 19) /* RW, TCP Pkt Checksum Enabled on Xmit */
#define TCP_PCS_ENA_RX	(1 << 18) /* RW, TCP Pkt Checksum Enabled on Reciever */
#define IPV4_HCS_ENA_TX	(1 << 17) /* RW, IPV4 Hdr Checksum Enabled on Xmit */
#define IPV4_HCS_ENA_RX	(1 << 16) /* RW, IPV4 Hdr Checksum Enabled on Rcv*/
#define ETMR_ADD_SUP	(1 <<  7) /* R,  Ethernet Timer Adding Supported */
#define ETMR_CLR_SUP	(1 <<  6) /* R,  Ethernet Timer Clearing Supported */
#define UDP_PCS_SUP_TX	(1 <<  5) /* R,  UDP Pkt Checksum Supported on Xmit */
#define UDP_PCS_SUP_RX	(1 <<  4) /* R,  UDP Pkt Checksum Supported on Rcv */
#define TCP_PCS_SUP_TX	(1 <<  3) /* R,  TCP Pkt Checksum Supported on Xmit */
#define TCP_PCS_SUP_RX	(1 <<  2) /* R,  TCP Pkt Checksum Supported on Rcv */
#define IPV4_HCS_SUP_TX	(1 <<  1) /* R,  IPV4 Hdr Checksum Supported on Xmit */
#define IPV4_HCS_SUP_RX	(1 <<  0) /* R,  IPV4 Hdr Checksum Supported on Rcv */

/* Q0_CSR and Q1_CSR registers fields */
#define Q_C_TINT_EN	(1 <<  9) /* W1,   Clear Enable TX Interrupt */
#define Q_C_RINT_EN	(1 <<  8) /* W1,   Clear Enable R Interrupt */
#define Q_C_MISS_EN	(1 <<  7) /* W1,   Clear Enable MISS Interrupt */
#define Q_TDMD		(1 <<  6) /* RW1,  Transmit Demand */
#define Q_TINT_EN	(1 <<  5) /* RW1,  Enable TX Interrupt */
#define Q_TINT		(1 <<  4) /* RW1C, Transmitter Interrupt */
#define Q_RINT_EN	(1 <<  3) /* RW1,  Enable RX Interrupt */
#define Q_RINT		(1 <<  2) /* RW1C, Reciever Interrupt */
#define Q_MISS_EN	(1 <<  1) /* RW1,  Enable MISS Interrupt */
#define Q_MISS		(1 <<  0) /* RW1C, Missed Packet */
/*
 * Q_RX_INT = (Q_MISS & Q_MISS0_EN) | (Q_RINT & Q_RINT_EN);
 * Q_TX_INT = (Q_TINT & Q_TINT0_EN)
 */

/* MGIO_CSR Register Fields */
#define MG_CPLS		(1 << 31) /* R/W1C,CHANGED PCS LINK STATUS */
#define MG_PINT		(1 << 30) /* RO,   PCS Interrupt */
#define MG_PLST		(1 << 29) /* RO,   PCS Link Status */
#define MG_EMST		(1 << 28) /* RO,   2.5G Ethernet Mode Status */
#define MG_CTFL		(1 << 27) /* R/W1C,CHANGED TRANSMITTER FAULT */
#define MG_TFLT		(1 << 26) /* R,    TRANSMITTER FAULT */
#define MG_CRLS		(1 << 25) /* R/W1C,CHANGED RECEIVER LOSS */
#define MG_RLOS		(1 << 24) /* R,    RECIEVER LOSS */
#define MG_ECPL		(1 << 23) /* RW,   ENABLE ON CPLS */
#define MG_FEPL		(1 << 22) /* RW***,FAST ETHERNET POLARITY */
#define MG_GEPL		(1 << 21) /* RW***,GIGABIT ETHERNET POLARITY */
#define MG_LSTS1	(1 << 20) /* RW,   LINK STATUS SELECT 1 */
#define MG_SLST		(1 << 19) /* RW,   SOFT LINK STATUS */
#define MG_LSTS0	(1 << 18) /* RW,   LINK STATUS SELECT 0 */
#define MG_FDUP		(1 << 17) /* RW/R*,FULL DUPLEX */
#define MG_FETH		(1 << 16) /* RW/R*,FAST ETHERNET */
#define MG_GETH		(1 << 15) /* RW/R* GIGABIT ETHERNET */
#define MG_HARD		(1 << 14) /* RW,   HARD/SOFT */
#define MG_RRDY		(1 << 13) /* R/W1C,RESULT READY */
#define MG_CMAB		(1 << 12) /* R/W1C,CHANGED MODULE ABSENT */
#define MG_MABS		(1 << 11) /* R,    MODULE ABSENT */
#define MG_CLST		(1 << 10) /* R/W1C,CHANGED LINK STATUS */
#define MG_LSTA		(1 <<  9) /* R,    LINK STATUS */
#define MG_EFTC		(1 <<  8) /* RW,   ENABLE CTFL INTR */
#define MG_OUTS		(1 <<  7) /* RW,   DISABLE TRANSMIT / SAVE POWER */
#define MG_RSTP(p)	((p) << 6)/* RW    RESET POLARITY */
#define MG_ERDY		(1 <<  5) /* RW,   ENABLE RRDY INTR */
#define MG_ECRL		(1 <<  4) /* RW,   ENABLE CRLS INTR */
#define MG_ECST		(1 <<  3) /* RW,   ENABLE CLST INTR */
#define MG_SRST		(1 <<  2) /* RW,   SOFTWARE RESET */
#define MG_ECMB		(1 <<  1) /* RW,   ENABLE CMAB INTR */
#define MG_SINT		(1 <<  0) /* R,    Status Interrupt */

#define MG_W1C_MASK	(MG_CLST | MG_CMAB | MG_RRDY | MG_CRLS | MG_CTFL)

/* MGIO_DATA registers shifts*/
#define MGIO_DATA_OFF		0
#define MGIO_CS_OFF		16
#define MGIO_REG_AD_OFF		18
#define MGIO_PHY_AD_OFF		23
#define MGIO_OP_CODE_OFF	28
#define MGIO_ST_OF_F_OFF	30

/* IRQ_DELAY access defines */
#define mgb_set_irq_delay(tx_cnt, tx_del, rx_cnt, rx_del) \
	((rx_del & 0xff) | ((rx_cnt & 0xff) << 8) | \
	((tx_del & 0xff) << 16) | ((tx_cnt & 0xff) << 24))

#define mgb_get_irqd_tx_cnt(irqd)	((irqd & 0xff000000) >> 24)
#define mgb_get_irqd_tx_del(irqd)	((irqd & 0x00ff0000) >> 16)
#define mgb_get_irqd_rx_cnt(irqd)	((irqd & 0x0000ff00) >>  8)
#define mgb_get_irqd_rx_del(irqd)	(irqd & 0xff)

/* PSF_CSR Register Fields */
#define PSF_SPDM	(1 << 21) /* W1,   SENT PAUSE DEMAND */
#define PSF_ESPW	(1 << 20) /* RW,   ENABLE SENT PAUSE ON WRITE */
#define PSF_WPSE	(1 << 19) /* RC,   WRITE PAUSE SENT ERROR */
#define PSF_WPSD	(1 << 18) /* RC,   WRITE PAUSE SENT DONE */
#define PSF_EWPS	(1 << 17) /* RW,   ENABLE ON WPSE(D) */
#define PSF_ESPC	(1 << 16) /* RW,   ENABLE SENT PAUSE ON CB */
#define PSF_CBSE	(1 << 15) /* RC,   CLEAR BUFFER SENT ERROR */
#define PSF_CBSD	(1 << 14) /* RC,   CREAR BUFFER SENT DONE */
#define PSF_ECBS	(1 << 13) /* RW,   ENABLE ON CBSE(D) */
#define PSF_ESPF	(1 << 12) /* RW,   ENABLE SENT PAUSE ON FB */
#define PSF_FBSE	(1 << 11) /* RC,   FULL BUFFER SENT ERROR */
#define PSF_FBSD	(1 << 10) /* RC,   FULL BUFFER SENT DONE */
#define PSF_EFBS	(1 <<  9) /* RW,   ENABLE ON FBSE(D) */
#define PSF_ESPM	(1 <<  8) /* RW,   ENABLE SENT PAUSE ON MISS */
#define PSF_MPSE	(1 <<  7) /* RC,   MISS PAUSE SENT ERROR */
#define PSF_MPSD	(1 <<  6) /* RC,   MISS PAUSE SENT DONE */
#define PSF_EMPS	(1 <<  5) /* RW,   ENABLE ON MPSE(D) */
#define PSF_PSEX	(1 <<  4) /* RC,   PAUSE EXPIRIED */
#define PSF_EPSX	(1 <<  3) /* RW,   ENABLE ON PSEX */
#define PSF_PSFR	(1 <<  2) /* RC,   PAUSE  FRAME RECEIVED */
#define PSF_EPSF	(1 <<  1) /* RW,   ENABLE ON PSFR */
#define PSF_PSFI	(1 <<  0) /* R*,   PAUSE  FRAME INTERRUPT */

/* SH_INIT_CNTR Register Fields */
#define SH_W_LADDRF1		(1 << 9)  /* RW1  */
#define SH_W_PROM_PADDR1	(1 << 8)  /* RW1  */
#define SH_R_FDRA1_TRRA1	(1 << 7)  /* RW1  */
#define SH_R_LADDRF1		(1 << 6)  /* RW1  */
#define SH_R_MODE_PADDR1	(1 << 5)  /* RW1  */
#define SH_W_LADDRF0		(1 << 4)  /* RW1  */
#define SH_W_PROM_PADDR0	(1 << 3)  /* RW1  */
#define SH_R_FDRA1_TRRA0	(1 << 2)  /* RW1  */
#define SH_R_LADDRF0		(1 << 1)  /* RW1  */
#define SH_R_MODE_PADDR0	(1 << 0)  /* RW1  */

/* PCS MPLL MODE */
#define PCS_NORMAL_MODE		0
#define PCS_BIFURCATION_MODE	1
#define PCS_2G5_MODE		2

static const char mgb_gstrings_test[][ETH_GSTRING_LEN] = {
	"Loopback test  (offline)"
};


#define MGB_DMA_MASK	0xffffffff

/*
 */
#define MGB_MAX_LOG_BUFFERS	11
#define MGB_MAX_TX_RING_SIZE	(1 << MGB_MAX_LOG_BUFFERS)
#define MGB_MAX_RX_RING_SIZE	(1 << MGB_MAX_LOG_BUFFERS)

#define MGB_LOG_TX_BUFFERS	9
#define MGB_LOG_RX_BUFFERS	9
#define TX_RING_SIZE		(1 << ep->log_tx_buffs)
#define TX_RING_MOD_MASK	(TX_RING_SIZE - 1)
#define TX_HISTERESIS		4
#define RX_RING_SIZE		(1 << ep->log_rx_buffs)
#define RX_RING_MOD_MASK	(RX_RING_SIZE - 1)

#define SMALL_PKT_SZ		1536
#define MGB_MAX_DATA_LEN	3000
#define PKT_BUF_SZ		(MGB_MAX_DATA_LEN + ETH_HLEN)

/* Each packet consists of header 14 bytes + [46 min - 1500 max] data + 4 bytes
 * crc. mgb adds crc automatically when sending a packet so you havn't to take
 * care about it allocating memory for the packet being sent. As to received
 * packets mgb doesn't hew crc off so you'll have to alloc an extra 4 bytes of
 * memory in addition to common packet size
 */

#define CRC_SZ	4
static unsigned int rx_prev_etmr = 0;	/* for debug */
static unsigned int tx_prev_etmr = 0;	/* for debug */

#define MGB_NAPI_WEIGHT	64


/* MGB Rx and Tx ring descriptors. */

struct mgb_rx_head {
	u32	base;		/* RBADR [31:0] */
	s16	buf_length;	/* BCNT only [13:0] */
	s16	status;
	s16	msg_length;	/* MCNT only [13:0] */
	u16	reserved1;
	u32	etmr;		/* timer count for ieee 1588 */
} __packed;

/* RX Descriptor status bits */
#define RD_OWN		(1 << 15)
#define RD_ERR		(1 << 14)
#define RD_FRAM		(1 << 13)
#define RD_OFLO		(1 << 12)
#define RD_CRC		(1 << 11)
#define RD_BUFF		(1 << 10)
#define RD_STP		(1 << 9)
#define RD_ENP		(1 << 8)
#define RD_PAM		(1 << 6)
#define RD_LAFM		(1 << 5)
#define RD_BAM		(1 << 4)
#define RD_CSER		(1 << 3)
#define RD_IHCS		(1 << 2)
#define RD_TPCS		(1 << 1)
#define RD_UPCS		(1 << 0)


struct mgb_tx_head {
	u32	base;		/* TBADR [31:0] */
	s16	buf_length;	/* BCNT only [13:0] */
	u16	status;
	u32	misc;		/* [31:26] + [3:0] tramsmit retry count */
	u32	etmr;		/* timer count for ieee 1588 */
} __packed;

/* TX Descriptor status bits */
#define TD_OWN		(1 << 15)
#define TD_ERR		(1 << 14)
#define TD_AFCS		(1 << 13)
#define TD_NOINTR	(1 << 13)
#define TD_MORE		(1 << 12)
#define TD_ONE		(1 << 11)
#define TD_DEF		(1 << 10)
#define TD_STP		(1 << 9)
#define TD_ENP		(1 << 8)
#define TD_HDE		(1 << 3)
#define TD_IHCS		(1 << 2)
#define TD_TPCS		(1 << 1)
#define TD_UPCS		(1 << 0)

/* TX Descriptor misc bits */
#define TD_RTRY		(1 << 26)
#define TD_LCAR		(1 << 27)
#define TD_LCOL		(1 << 28)
#define TD_UFLO		(1 << 30)
#define TD_BUFF		(1 << 31)


struct mgb_private;

struct mgb_q {
	struct mgb_private	*ep;
	raw_spinlock_t		lock;
	struct napi_struct	napi;

	struct mgb_rx_head	*rx;
	dma_addr_t		rx_dma;
	struct sk_buff		**rx_skbuff;
	dma_addr_t		*rx_dma_skbuff;
	unsigned int		cur_rx;
	char			rx_name[IFNAMSIZ + 4];

	struct mgb_tx_head	*tx;
	dma_addr_t		tx_dma;
	struct sk_buff		**tx_skbuff;
	dma_addr_t		*tx_dma_skbuff;
	unsigned int		cur_tx;
	unsigned int		dirty_tx;
	unsigned int		full_tx;
	char			tx_name[IFNAMSIZ + 4];

	struct net_device_stats	stats;
};

/* Must be 46 bytes exactly; MGB works in LE mode, so
 * initialization must be in acordance with that
 */
typedef struct init_block {
	u16	mode;
	u8	paddr0[6];
	u64	laddrf0;
	u32	rdra0; /* 31:4 = addr of recieving desc ring (16 bytes align) +
			* 3:0  = number of descriptors (the power of two)
			*/
	u32	tdra0; /* 31:4 = addr of xmit desc ring (16 bytes align) +
			* 3:0  = number of descriptors (the power of two)
			*/
	u8	paddr1[6];
	u64	laddrf1;
	u32	rdra1; /* 31:4 = addr of recieving desc ring (16 bytes align) +
			* 3:0  = number of descriptors (the power of two)
			*/
	u32	tdra1; /* 31:4 = addr of transm desc ring (16 bytes align) +
			* 3:0  = number of descriptors (the power of two)
			*/
} __packed init_block_t;


/* Init Block mode bits */
#define DRX0		(1 << 0)  /* queue 0 receiver disable */
#define DTX0		(1 << 1)  /* queue 0 transmitter disable */
#define LOOP		(1 << 2)  /* loopback */
#define DTCR		(1 << 3)  /* disable transmit crc */
#define COLL		(1 << 4)  /* force collision; actual only in
				   * "internal loopback" mode */
#define DRTY		(1 << 5)  /* disable retry */
#define INTL		(1 << 6)  /* Internal loopback */
#define EMBA		(1 << 7)  /* enable modified back-off algorithm */
#define EJMF		(1 << 8)  /* enable jambo frame */
#define EPSF		(1 << 9)  /* enable pause frame */
#define FULL		(1 << 10) /* full packet mode */
#define DRX1		(1 << 11) /* queue 1 receiver disable */
#define DTX1		(1 << 12) /* queue 1 transmitter disable */
#define PROM0		(1 << 14) /* queue 0 promiscuous mode */
#define PROM1		(1 << 15) /* queue 1 promiscuous mode */

#define mgb_default_mode	(EPSF)


struct mgb_stats {
	unsigned long swint;
	unsigned long merr;
	unsigned long babl;
	unsigned long cerr;
	unsigned long slve;
};

struct mgb_private {
	init_block_t		*init_block;
	dma_addr_t		initb_dma;
	unsigned long		flags;
	struct mgb_q		*mgb_qs[2];
	/* void			*dma_area; */
	struct pci_dev		*pci_dev;
	struct net_device	*dev;
	struct resource		*resource;
	unsigned char		*base_ioaddr;
	raw_spinlock_t		mgio_lock;
	struct mutex		mx;
	struct net_device_stats	stats;
	struct mgb_stats	l_stats;
	/* PHY: */
	struct mii_bus		*mii_bus;
	int			extphyaddr;	/* Address of External PHY */
	int			pcsaddr;	/* Address of Internal PHY */
	u32			pcs_dev_id;
	struct device_node	*phy_node;	/* Connection to External PHY */
	int			mpll_mode;      /* Normal=0,
						 * Bifurcation=1, 2G5=2 */
#if 0
	struct phy_device	*pcsdev;
#endif
	/* */
	u32			e_cap;
	u32			irq_delay;
	int			mgb_ticks_per_usec;
	/* char			revision; */
	unsigned char		log_rx_buffs;
	unsigned char		log_tx_buffs;
	unsigned char		linkup;
	/* For IEEE 1588 */
	struct hwtstamp_config	hwtstamp_config;
	struct ptp_clock	*ptp_clock;
	struct ptp_clock_info	ptp_clock_info;
	spinlock_t		systim_lock;
	struct cyclecounter	cc;
	struct timecounter	tc;
	/* For Debug */
	u32			msg_enable;	/* debug message level */
#ifdef CONFIG_DEBUG_FS
	struct dentry		*mgb_dbg_board;
	u32			reg_last_value;
#endif /*CONFIG_DEBUG_FS*/
};


/* Bits for flags */
#define MGB_F_RESETING		0
#define MGB_F_XMIT		1
#define MGB_F_XMIT0		MGB_F_XMIT
#define MGB_F_XMIT1		(MGB_F_XMIT + 1)
#define MGB_F_TX		3
#define MGB_F_TX0		MGB_F_TX
#define MGB_F_TX1		(MGB_F_TX + 1)
#define MGB_F_RX		5
#define MGB_F_RX0		MGB_F_RX
#define MGB_F_RX1		(MGB_F_RX + 1)
#define MGB_F_SYNC		31
#define MGB_F_ALL		0x7e

/* Shift according to pci_dev->irq */
#define MGB_T0_INTR	0	/* tx queue0 interrupt */
#define MGB_T1_INTR	1	/* tx queue1 interrupt */
#define MGB_R0_INTR	2	/* rx queue0 interrupt */
#define MGB_R1_INTR	3	/* rx queue1 interrupt */
#define MGB_SYS_INTR	4	/* system interrupt */


#define mgb_nq(ep, q)		(!!(ep->mgb_qs[0] != q))
#define mgb_opened(ep)		(ep->mgb_qs[0]->rx != NULL)
#define mgb_netif_err(ep)	(netif_msg_tx_err(ep) || netif_msg_tx_err(ep))


static irqreturn_t mgb_sys_interrupt(int , void *);
static irqreturn_t mgb_restart_card(int , void *);
static irqreturn_t mgb_rx_interrupt(int , void *);
static irqreturn_t mgb_tx_interrupt(int , void *);
static int mgb_poll(struct napi_struct *napi, int budget);
static void mgb_check_link_status(struct mgb_private *ep, u32 mgio_csr);
static int mgio_read_clause_45(struct mgb_private *ep, int mii_id, int reg_num);
static void mgio_write_clause_45(struct mgb_private *ep, int mii_id,
				 int reg_num, int val);

static int mgb_debug = 0;


#define mgb_netif_msg_reset(dev) \
	((dev)->msg_enable & (NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR))


#ifdef MODULE
static inline bool mgb_is_eiohub_proto(void)
{
	return true;
	/*return false;*/
}
#else /* !MODULE */
#define mgb_is_eiohub_proto is_prototype
#endif /* MODULE */


/** TITLE: FREEZING stuff */

static inline int mgb_set_flag_bit(int nr, unsigned long *flag)
{
	unsigned long f;

	local_irq_save(f);
	while (!test_and_set_bit(MGB_F_SYNC, flag)) {
		;
	};
	if (test_bit(MGB_F_RESETING, flag)) {
		local_irq_restore(f);
		return 1;
	}
	set_bit(nr, flag);
	clear_bit(MGB_F_SYNC, flag);
	local_irq_restore(f);

	return 0;
}

static inline int mgb_wait_for_freeze(unsigned long *flag)
{
	int i = 1000;

	if (test_and_set_bit(MGB_F_RESETING, flag)) {
		return -EAGAIN;
	}
	while ((*flag & MGB_F_ALL) && (--i > 0)) {
		udelay(100);
	}
	clear_bit(MGB_F_RESETING, flag);
	if (i <= 0) {
		return -EBUSY;
	}

	return 0;
}


/** TITLE: ACCESS to MGB Registers */

static u32 mgb_read_e_csr(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + E_CSR);
}
static void mgb_write_e_csr(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + E_CSR);
}

static u32 mgb_read_e_cap(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + E_CAP);
}
static void mgb_write_e_cap(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + E_CAP);
}

static u32 mgb_read_q_csr(struct mgb_private *ep, int nq)
{
	BUG_ON(!ep->base_ioaddr);
	if (nq == 0)
		return readl(ep->base_ioaddr + E_Q0CSR);
	else
		return readl(ep->base_ioaddr + E_Q1CSR);
}
static void mgb_write_q_csr(struct mgb_private *ep, int nq, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	if (nq == 0)
		writel(val, ep->base_ioaddr + E_Q0CSR);
	else
		writel(val, ep->base_ioaddr + E_Q1CSR);
}

static u32 mgb_read_mgio_csr(struct mgb_private *ep)
{
	u32 r;

	BUG_ON(!ep->base_ioaddr);
	r = readl(ep->base_ioaddr + MGIO_CSR);

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s: dreg == 0x%08x\n", __func__, r);

	return r;
}
static void mgb_write_mgio_csr(struct mgb_private *ep, u32 val)
{
	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s: creg := 0x%08x\n", __func__, val);

	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + MGIO_CSR);
}

static u32 mgb_read_mgio_data(struct mgb_private *ep)
{
	u32 r;

	BUG_ON(!ep->base_ioaddr);
	r = readl(ep->base_ioaddr + MGIO_DATA);

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s: dreg == 0x%08x\n", __func__, r);

	return r;
}
static void mgb_write_mgio_data(struct mgb_private *ep, u32 val)
{
	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s: dreg := 0x%08x\n", __func__, val);

	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + MGIO_DATA);
}

static u32 mgb_read_e_base_address(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + E_BASE_ADDR);
}
static void mgb_write_e_base_address(struct mgb_private *ep, u32 val)
{
	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			 "%s: BASE_ADDR := 0x%08X\n", __func__, val);

	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + E_BASE_ADDR);
}

static u32 mgb_read_dma_base_address(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + DMA_BASE_ADDR);
}
static void mgb_write_dma_base_address(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + DMA_BASE_ADDR);
}

static u32 mgb_read_psf_csr(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + PSF_CSR);
}
static void mgb_write_psf_csr(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + PSF_CSR);
}

static u32 mgb_read_psf_data(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + PSF_DATA);
}
static void mgb_write_psf_data(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + PSF_DATA);
}

static u32 mgb_read_irq_delay(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + IRQ_DELAY);
}
static void mgb_write_irq_delay(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + IRQ_DELAY);
}

static u32 mgb_read_sh_init_cntrl(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + SH_INIT_CNTRL);
}
static void mgb_write_sh_init_cntrl(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + SH_INIT_CNTRL);
}

static u32 mgb_read_sh_data_l(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + SH_DATA_L);
}
static void mgb_write_sh_data_l(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + SH_DATA_L);
}

static u32 mgb_read_sh_data_h(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + SH_DATA_H);
}
static void mgb_write_sh_data_h(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + SH_DATA_H);
}

static u32 mgb_read_rx_queue_arb(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + RX_QUEUE_ARB);
}
static void mgb_write_rx_queue_arb(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + RX_QUEUE_ARB);
}

static u32 mgb_read_psf_data1(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + PSF_DATA1);
}
static void mgb_write_psf_data1(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + PSF_DATA1);
}


/** TITLE: PHY handling */

#define MGB_PHY_WAIT_NUM	500

static inline int mgb_wait_rrdy(struct mgb_private *ep)
{
	int i;

	for (i = 0; i < MGB_PHY_WAIT_NUM; i++) {
		if (mgb_read_mgio_csr(ep) & MG_RRDY)
			break;
		udelay(1);
	}

	return i == MGB_PHY_WAIT_NUM;
}

/** external phy */

static int mgio_read_clause_22(struct mgb_private *ep, int phy_id, int reg_num)
{	/* Clause 22 standart */
	int val_out = 0;
	unsigned long flags;

	u32 rd = 0x60020000 |
		((phy_id  & 0x1f) << MGIO_PHY_AD_OFF) |
		((reg_num & 0x1f) << MGIO_REG_AD_OFF);

	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	mgb_write_mgio_csr(ep, (mgb_read_mgio_csr(ep) & ~MG_W1C_MASK) |
					MG_RRDY);
	mgb_write_mgio_data(ep, rd);
	if (mgb_wait_rrdy(ep)) {
		raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
		dev_err(&ep->pci_dev->dev,
			"%s: Unable to read from MGIO_DATA reg\n", __func__);
		return -1;
	}
	val_out = (int)(mgb_read_mgio_data(ep) & 0xffff);
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			 "%s: mgio_data=0x%08x, phy=%d reg(0x%08x)=0x%04x\n",
			__func__, rd, phy_id, reg_num, val_out);

	return val_out;
}

static void mgio_write_clause_22(struct mgb_private *ep, int phy_id,
				 int reg_num, int val)
{	/* Clause 22 standart */
	u32 wr = 0x50020000 |
		((phy_id  & 0x1f) << MGIO_PHY_AD_OFF) |
		((reg_num & 0x1f) << MGIO_REG_AD_OFF) |
		(val & 0xffff);
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	mgb_write_mgio_csr(ep, (mgb_read_mgio_csr(ep) & ~MG_W1C_MASK) |
					MG_RRDY);
	mgb_write_mgio_data(ep, wr);
	if (mgb_wait_rrdy(ep)) {
		raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
		dev_err(&ep->pci_dev->dev,
			"%s: Unable to write MGIO_DATA reg\n", __func__);
		return;
	}
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			 "%s: mgio_data=0x%08x, phy=%d reg(0x%08x):=0x%04x\n",
			__func__, wr, phy_id, reg_num, val);

	return;
}

/* mii_bus->read wrapper for read PHYs */
static int mgb_mdio_read_reg(struct mii_bus *bus, int mii_id, int regnum)
{
	struct mgb_private *ep = bus->priv;

	if (regnum & MII_ADDR_C45)
		return mgio_read_clause_45(ep, mii_id, regnum & ~MII_ADDR_C45);
	else
		return mgio_read_clause_22(ep, mii_id, regnum);
}

/* mii_bus->write wrapper for write PHYs */
static int mgb_mdio_write_reg(struct mii_bus *bus, int mii_id, int regnum,
			      u16 value)
{
	struct mgb_private *ep = bus->priv;

	if (regnum & MII_ADDR_C45)
		mgio_write_clause_45(ep, mii_id, regnum & ~MII_ADDR_C45, value);
	else
		mgio_write_clause_22(ep, mii_id, regnum, value);

	return 0;
}

static void mgb_set_mac_phymode(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
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

#if 0
	/* disable auto mac control from all phys */
	unsigned long flags;
	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	val = mgb_read_mgio_csr(ep);
	val |= MG_HARD;
	mgb_write_mgio_csr(ep, val);

	val &= ~(MG_FETH | MG_GETH | MG_FDUP | MG_SLST);
#endif

	if (phydev->speed == SPEED_1000) {
		val |= MG_GETH;
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s speed == 1000\n",
				phydev_name(dev->phydev));
	} else if (phydev->speed == SPEED_100) {
		val |= MG_FETH;
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s speed == 100\n",
				phydev_name(dev->phydev));
	} else {
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s speed == 10\n",
				phydev_name(dev->phydev));
	}

	if (phydev->duplex == DUPLEX_FULL) {
		val |= MG_FDUP;
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s duplex == FULL\n",
				 phydev_name(dev->phydev));
	}

#if 0
	if (phydev->link)
		val |= MG_SLST;

	mgb_write_mgio_csr(ep, val);
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
#endif

	/* FIXME: */
	mgb_check_link_status(ep, mgb_read_mgio_csr(ep));
}

/* callback - external phy change state */
static void mgb_phylink_handler(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (!dev->phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	mgb_set_mac_phymode(dev);

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

static int mgb_pcs_vs_reset(struct mgb_private *ep);

/* called at begin of open() */
static int mgb_extphy_connect(struct mgb_private *ep)
{
	struct phy_device *phydev;
	int ret;

	if (mgb_pcs_vs_reset(ep)) {
		return 1;
	}

	if (ep->extphyaddr == -1)
		return 0;

	phydev = mdiobus_get_phy(ep->mii_bus, ep->extphyaddr);

	ret = phy_connect_direct(ep->dev, phydev, mgb_phylink_handler,
				 PHY_INTERFACE_MODE_SGMII);
	if (ret) {
		dev_err(&ep->dev->dev, "connect to phy %s failed\n",
			phydev_name(phydev));
		return ret;
	}

	phy_read_status(phydev);

	if (assigned_speed != SPEED_1000)
		phy_set_max_speed(phydev, SPEED_100);

	/* Ensure to advertise everything, incl. pause */
	linkmode_copy(phydev->advertising, phydev->supported);

	if (netif_msg_link(ep))
		phy_attached_info(phydev);

	return 0;
}

/* called at end of open() - start phy */
static void mgb_init_extphy(struct mgb_private *ep)
{
	struct net_device *dev = ep->dev;

	if (!dev->phydev) {
		dev_dbg_once(&dev->dev, "phydev not init\n");
		return;
	}

	if (dev->phydev->autoneg == AUTONEG_ENABLE) {
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "phy %s restart autoneg\n",
				 phydev_name(dev->phydev));

		phy_restart_aneg(dev->phydev);
	}

	phy_start(dev->phydev);
}

/** internal phy (PCS) */

/* PCS PHY consists of seferal devices.
 * We describe register as a pair - device number[22:5] and reg number [15:16].
 * Here are some registers we need on
 */

static int mgio_read_clause_45(struct mgb_private *ep, int mii_id, int reg_num)
{
	u32 rd;
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	mgb_write_mgio_csr(ep,
			   (mgb_read_mgio_csr(ep) & ~MG_W1C_MASK) | MG_RRDY);
	rd = (0x2UL << MGIO_CS_OFF) |
	     (reg_num & ((0x1fUL << MGIO_REG_AD_OFF) | 0xffff)) |
	     ((mii_id & 0x1f) << MGIO_PHY_AD_OFF);
	mgb_write_mgio_data(ep, rd);
	if (mgb_wait_rrdy(ep))
		goto bad_result;

	mgb_write_mgio_csr(ep,
			   (mgb_read_mgio_csr(ep) & ~MG_W1C_MASK) | MG_RRDY);
	rd |= 0x3UL << MGIO_OP_CODE_OFF;
	mgb_write_mgio_data(ep, rd);
	if (mgb_wait_rrdy(ep))
		goto bad_result;

	rd = mgb_read_mgio_data(ep) & 0xffff;
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			 "%s: phy=%d reg(0x%08x)=0x%04x\n",
			__func__, mii_id, reg_num, rd);

	return (int)rd;

bad_result:
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
	dev_err(&ep->pci_dev->dev,
		"%s: Unable to read from MGIO_DATA reg 0x%x\n",
		__func__, reg_num);
	return -1;
}

static void mgio_write_clause_45(struct mgb_private *ep, int mii_id,
				 int reg_num, int val)
{
	u32 wr;
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	mgb_write_mgio_csr(ep,
			   (mgb_read_mgio_csr(ep) & ~MG_W1C_MASK) | MG_RRDY);
	wr = (0x2 << MGIO_CS_OFF) |
	     (reg_num & ((0x1f << MGIO_REG_AD_OFF) | 0xffff)) |
	     ((mii_id & 0x1f) << MGIO_PHY_AD_OFF);
	mgb_write_mgio_data(ep, wr);
	if (mgb_wait_rrdy(ep))
		goto bad_result;

	wr &= ~0xffff;
	wr |= (0x2 << MGIO_CS_OFF) |
	      (0x1 << MGIO_OP_CODE_OFF) |
	      (val & 0xffff);
	mgb_write_mgio_csr(ep,
			   (mgb_read_mgio_csr(ep) & ~MG_W1C_MASK) | MG_RRDY);
	mgb_write_mgio_data(ep, wr);
	if (mgb_wait_rrdy(ep))
		goto bad_result;

	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			 "%s: phy=%d reg(0x%08x):=0x%04x\n",
			 __func__, mii_id, reg_num, val);

	return;

bad_result:
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
	dev_err(&ep->pci_dev->dev,
		"%s: Unable to write MGIO_DATA reg 0x%x\n", __func__, reg_num);
	return;
}

/* PCS Register read/write functions */
static u16 mgb_pcs_read(struct mgb_private *ep, int regnum)
{
	return (u16)mgio_read_clause_45(ep, ep->pcsaddr, regnum);
}

static void mgb_pcs_write(struct mgb_private *ep, int regnum, u16 value)
{
	mgio_write_clause_45(ep, ep->pcsaddr, regnum, value);
}

#define PCS_DEV_ID_1G_2G5	0x7996CED0
#define PCS_DEV_ID_1G_2G5_10G	0x7996CED1

#define PMA_and_PMD_MMD	(0x1 << 18)
#define PCS_MMD		(0x3 << 18)
#define AN_MMD		(0x7 << 18)
#define VS_MMD1		(0x1e << 18)
#define VS_MII_MMD	(0x1f << 18)

#define SR_XS_PCS_CTRL1		(0x0000 | PCS_MMD)
#define SR_XS_PCS_DEV_ID1	(0x0002 | PCS_MMD)
#define SR_XS_PCS_DEV_ID2	(0x0003 | PCS_MMD)
#define SR_XS_PCS_CTRL2		(0x0007 | PCS_MMD)
#define VR_XS_PCS_DIG_CTRL1	(0x8000 | PCS_MMD)

#define SR_MII_CTRL		(0x0000 | VS_MII_MMD)
#define VR_MII_AN_CTRL		(0x8001 | VS_MII_MMD)
#define SR_MII_AN_ADV		(0x0004 | VS_MII_MMD)
#define VR_MII_DIG_CTRL1	(0x8000 | VS_MII_MMD)
#define VR_MII_AN_INTR_STS	(0x8002 | VS_MII_MMD)
#define VR_MII_LINK_TIMER_CTRL	(0x800a | VS_MII_MMD)

#define SR_VSMMD_CTRL		(0x0009 | VS_MMD1)

#define VR_AN_INTR		(0x8002 | AN_MMD)
#define SR_AN_CTRL		(0x0000 | AN_MMD)
#define SR_AN_LP_ABL1		(0x0013 | AN_MMD)
#define SR_AN_LP_ABL2		(0x0014 | AN_MMD)
#define SR_AN_LP_ABL3		(0x0015 | AN_MMD)
#define SR_AN_XNP_TX1		(0x0016 | AN_MMD)
#define SR_AN_XNP_TX2		(0x0017 | AN_MMD)
#define SR_AN_XNP_TX3		(0x0018 | AN_MMD)

#define VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL	(0x8070 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0	(0x8071 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLA_CTRL1		(0x8072 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2	(0x8073 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0	(0x8074 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLB_CTRL1		(0x8075 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2	(0x8076 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLA_CTRL3		(0x8077 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_MPLLB_CTRL3		(0x8078 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1	(0x8031 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2	(0x8032 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL	(0x8033 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL	(0x8034 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0	(0x8036 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1	(0x8037 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2	(0x8052 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3	(0x8053 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL	(0x8054 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL	(0x8056 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL	(0x8057 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0		(0x8058 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4	(0x805C | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL	(0x805D | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0	(0x8090 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL	(0x8091 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0	(0x8092 | PMA_and_PMD_MMD)
#define VR_XS_PMA_Gen5_12G_VCO_CAL_REF0		(0x8096 | PMA_and_PMD_MMD)

/* Initiate the Vendor specific software reset */
/* reset for both controllers are configured via func 0 */
static int mgb_pcs_vs_reset(struct mgb_private *ep)
{
	/**if (ep->pcs_dev_id != PCS_DEV_ID_1G_2G5_10G)
		return 0;*/

	if (PCI_FUNC(ep->pci_dev->devfn) == 0) {
		int i;

		if (ep->mpll_mode == PCS_2G5_MODE)
			mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1, 0xa004);
		else
			mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1, 0xa000);

		for (i = 0; i < MGB_PHY_WAIT_NUM; i++) {
			if ((mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1) &
				0x8000) == 0) {
				break;
			}
			udelay(1);
		}
		if (i == MGB_PHY_WAIT_NUM) {
			dev_warn(&ep->pci_dev->dev, "could not reset PCS\n");
			return 1;
		}
	}
	return 0;
}

static void mgb_pcs_first_init(struct mgb_private *ep)
{
	int i;

	/** eth1g_double_pcs_regs_config.txt */
	/** eth1g_bifurcation_double_pcs_regs_config.txt */
	/** eth2_5G_bifurcation_double_pcs_regs_config.txt */
	/* 1./2. Wait RST to 1'h0 */
	for (i = 0; i <= MGB_PHY_WAIT_NUM; i++) {
		if ((mgb_pcs_read(ep, SR_XS_PCS_CTRL1) & 0x8000) == 0)
			break;
		udelay(1);
	}
	if (i >= MGB_PHY_WAIT_NUM)
		dev_warn(&ep->pci_dev->dev,
			 "could not reset PCS at first init\n");

	/*if (ep->pcs_dev_id != PCS_DEV_ID_1G_2G5_10G)
		goto skip_funk0_init;*/

	/* 3. Configuration MPLL Registers */
	/* NOT: mpll registers for both controllers are configured via geth_1 */
	if (ep->mpll_mode == PCS_2G5_MODE) {
		/** eth2_5G_bifurcation_double_pcs_regs_config.txt */
		dev_info(&ep->pci_dev->dev,
			"configure PCS MPLL: 2.5G MODE\n");
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2, 0x0200);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0, 0x0028);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_MPLLB_CTRL1, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2, 0x0299);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_MPLLB_CTRL3, 0x0007);
	} else if (ep->mpll_mode == PCS_BIFURCATION_MODE) {
		/** eth1g_bifurcation_double_pcs_regs_config.txt */
		dev_info(&ep->pci_dev->dev,
			"configure PCS MPLL: BIFURCATION MODE\n");
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2, 0x0200);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0, 0x0028);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_MPLLB_CTRL1, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2, 0x0299);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_MPLLB_CTRL3, 0x0007);
	} else { /* PCS_NORMAL_MODE */
		/** eth1g_double_pcs_regs_config.txt */
		dev_info(&ep->pci_dev->dev,
			 "configure PCS MPLL: NORMAL MODE\n");
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL, 0x0001);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0, 0x0020);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_MPLLA_CTRL1, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2, 0x0200);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0, 0x8000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_MPLLA_CTRL3, 0x003A);
	}

	/*skip_funk0_init:*/

	/* 4. Configuration Registers */
	if (ep->mpll_mode == PCS_2G5_MODE) {
		/** eth2_5G_bifurcation_double_pcs_regs_config.txt */
		/* 4.2. Check PCS_TYPE_SEL (SR_XS_PCS_CTRL2) to 4'h1 */
		mgb_pcs_write(ep, SR_XS_PCS_CTRL2, 0x0001);
		/* 4.3. Enable 2.5G GMII Mode */
		mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1,
			      mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1) | 0x2004);
		/* 4.4. Check SS13 (SR_PMA_CTRL1(only for Backplane Ethernet)
		 * or SR_XS_PCS_CTRL1) to 1'h0 */
		/* TODO: ... */
		/* 4.5. Program the register bits for 12G PHY */
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL, 0x0011);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1, 0x1510);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2, 0x0100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL, 0x000F);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL, 0x0002);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0, 0x2000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1, 0x0020);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2, 0x0100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3, 0x0002);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL, 0x0002);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL, 0x0101);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0, 0x77A6);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4, 0x0010);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0, 0x5100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL, 0x00F1);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0, 0x0550);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_VCO_CAL_REF0, 0x0022);
	} else if (ep->mpll_mode == PCS_BIFURCATION_MODE) {
		mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1,
			      mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1) & ~0x0004);
		/** eth1g_bifurcation_double_pcs_regs_config.txt */
		/* 4.2. Check PCS_TYPE_SEL (SR_XS_PCS_CTRL2) to 4'h1 */
		mgb_pcs_write(ep, SR_XS_PCS_CTRL2, 0x0001);
		/* 4.3. Check SS13 (SR_PMA_CTRL1(only for Backplane Ethernet)
		 * or SR_XS_PCS_CTRL1) to 1'h0 */
		/* TODO: ... */
		/* 4.4. Program the register bits for 12G PHY */
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL, 0x0011);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1, 0x1500);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2, 0x0100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL, 0x000F);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL, 0x0007);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0, 0x2800);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2, 0x0100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3, 0x0003);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL, 0x0003);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL, 0x0101);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0, 0x77A6);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4, 0x0010);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0, 0x5100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL, 0x00F1);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0, 0x0540);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_VCO_CAL_REF0, 0x002A);
	} else { /* PCS_NORMAL_MODE */
		mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1,
			      mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1) & ~0x0004);
		/** eth1g_double_pcs_regs_config.txt */
		/* 4.2. Check PCS_TYPE_SEL (SR_XS_PCS_CTRL2) to 4'h1 */
		mgb_pcs_write(ep, SR_XS_PCS_CTRL2, 0x0001);
		/* 4.3. Check SS13 (SR_PMA_CTRL1) to 1'h0 */
		/* TODO: ... */
		/* 4.4. Program the register bits for 12G PHY */
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1, 0x1500);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2, 0x0100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL, 0x000F);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL, 0x0003);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0, 0x2800);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2, 0x0100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3, 0x0003);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL, 0x0003);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL, 0x0101);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0, 0x77A6);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4, 0x0010);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL, 0x0000);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0, 0x5100);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL, 0x0071);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0, 0x0540);
		mgb_pcs_write(ep, VR_XS_PMA_Gen5_12G_VCO_CAL_REF0, 0x002A);
	}
}

static void mgb_sw_reset_mgio(struct mgb_private *ep)
{
	int r;
	unsigned long flags;

	/**if (ep->pcs_dev_id != PCS_DEV_ID_1G_2G5_10G)
		return;*/

	/* do for func0 only! */
	if (PCI_FUNC(ep->pci_dev->devfn) == 0) {
		raw_spin_lock_irqsave(&ep->mgio_lock, flags);
		r = mgb_read_mgio_csr(ep);
		r &= ~MG_W1C_MASK;
		r |= MG_SRST; /* RST */
		/*r |= MG_OUTS;*/ /* TX_DISABLE */
		mgb_write_mgio_csr(ep, r); /* software reset */
		r &= ~MG_SRST; /* ~RST */
		usleep_range(10, 20); /* reset delay */
		mgb_write_mgio_csr(ep, r); /* wait for reset */
		raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
	}
}

/* Programming Guidelines for Clause 37 Auto-Negotiation */
static int mgb_set_pcs_an_clause_37(struct mgb_private *ep, int sgmii)
{
	int r;

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s\n", __func__);

	r = mgb_pcs_read(ep, SR_AN_CTRL);
	r &= ~0x1000; /* AN_EN = 0*/
	mgb_pcs_write(ep, SR_AN_CTRL, r);

	r = mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1);
	r |= 0x1000; /* CL37_BP */
	mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1, r);

	r = mgb_pcs_read(ep, SR_MII_CTRL);
	r &= ~0x1000; /* AN_ENABLE = 0*/
	mgb_pcs_write(ep, SR_MII_CTRL, r);

	if (sgmii) {
		r = mgb_pcs_read(ep, VR_MII_AN_CTRL) & ~0xf;
		r |= 0x4; /* PCS_MODE=2, TX_CONFIG=0, MII_AN_INTR_EN=0 */
		mgb_pcs_write(ep, VR_MII_AN_CTRL, r);
		r = mgb_pcs_read(ep, VR_MII_DIG_CTRL1);
		r |= (1 << 9); /* MAC_AUTO_SW=1 */
		mgb_pcs_write(ep, VR_MII_DIG_CTRL1, r);
		if (!(mgb_pcs_read(ep, VR_MII_DIG_CTRL1) & 1)) {
			/* PHY_MODE_CTRL == 0 */
			r = mgb_pcs_read(ep, VR_MII_AN_CTRL);
			r |= 0x10; /* SGMII_LINK_STS */
			mgb_pcs_write(ep, VR_MII_AN_CTRL, r);
			r = mgb_pcs_read(ep, SR_MII_CTRL) & ~0x2000;
			r |= 0x40; /* SS13=0, SS6 */
			mgb_pcs_write(ep, SR_MII_CTRL, r);
			r = mgb_pcs_read(ep, SR_MII_AN_ADV);
			r &= ~0x20; /* ~FD */
			mgb_pcs_write(ep, SR_MII_AN_ADV, r);
		}
	}
	r = mgb_pcs_read(ep, SR_MII_CTRL);
	r |= 0x1000; /* AN_ENABLE=1*/
	mgb_pcs_write(ep, SR_MII_CTRL, r);

	return 0;
}

#define MGB_PHY_WAIT_AN	300

/* Programming Guidelines for Clause 73 Auto-Negotiation */
static int mgb_set_pcs_an_clause_73(struct mgb_private *ep)
{
	int i;
	int r;

	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev, "%s\n", __func__);

#if 0
	r = mgb_pcs_read(ep, SR_AN_CTRL);
	r |= 0x200;	/* AN_EN = 0*/
	mgb_pcs_write(ep, SR_AN_CTRL, r);
#endif
	for (i = 0; i < MGB_PHY_WAIT_AN; i++) {
		r = mgb_pcs_read(ep, VR_AN_INTR);
		if (r & 0x7) { /* AN_INT_CMPLT | AN_INC_LINK | AN_PG_RCV */
			break;
		}
	}
	if (i == MGB_PHY_WAIT_AN) {
		dev_warn(&ep->dev->dev, "Could not set autonegotiation mode\n");
		return 1;
	}

	if (r & 0x1) { /* AN_INT_CMPLT */
	/* Ready */
		return 0;
	}

	if ((r & 0x4) == 0) { /* AN_PG_RCV == 0 */
		goto wait_an_int_cmplt;
	}
	r &= ~0x4; /* AN_PG_RCV = 0 */
	mgb_pcs_write(ep, VR_AN_INTR, r);
	(void)mgb_pcs_read(ep, SR_AN_LP_ABL1);
	(void)mgb_pcs_read(ep, SR_AN_LP_ABL2);
	(void)mgb_pcs_read(ep, SR_AN_LP_ABL3);

	r = mgb_pcs_read(ep, SR_AN_LP_ABL1);
	if ((r & 0x800) == 0) { /* AN_LP_ADV_NP == 0 */
		goto wait_an_int_cmplt;
	}

	for (i = 0; i < MGB_PHY_WAIT_AN; i++) {
		int j;
		mgb_pcs_write(ep, SR_AN_XNP_TX3, 0);
		mgb_pcs_write(ep, SR_AN_XNP_TX2, 0);
		mgb_pcs_write(ep, SR_AN_XNP_TX1, 0);
		for (j = 0; j < MGB_PHY_WAIT_AN; j++) {
			if (mgb_pcs_read(ep, VR_AN_INTR) & 0x4) {
				break;
			}
		}
		if (j == MGB_PHY_WAIT_AN) {
			return 1;
		}
		r = mgb_pcs_read(ep, VR_AN_INTR);
		mgb_pcs_write(ep, VR_AN_INTR, r & ~0x4);/*AN_PG_RCV=0*/
		(void)mgb_pcs_read(ep, SR_AN_LP_ABL1);
		(void)mgb_pcs_read(ep, SR_AN_LP_ABL2);
		(void)mgb_pcs_read(ep, SR_AN_LP_ABL3);
		r = mgb_pcs_read(ep, SR_AN_LP_ABL1);
		if ((r & 0x800) == 0) { /* AN_LP_ADV_NP == 0 */
			break;
		}
	}
	if (i == MGB_PHY_WAIT_AN) {
		return 1;
	}
wait_an_int_cmplt:
	for (i = 0; i < MGB_PHY_WAIT_AN; i++) {
		r = mgb_pcs_read(ep, VR_AN_INTR);
		if (r & 0x1) { /* AN_INT_CMPLT */
			break;
		}
	}
	if (i == MGB_PHY_WAIT_AN) {
		return 1;
	}
	return 0;
}

/* caled in probe() - init internal PCS/PMA phy */
static int mgb_set_pcsphy_mode(struct net_device *dev)
{
	int r = 1;
	struct mgb_private *ep = netdev_priv(dev);

	ep->pcsaddr = mgb_is_eiohub_proto() ? 2 : 1;

	ep->pcs_dev_id = mgb_pcs_read(ep, SR_XS_PCS_DEV_ID1) << 16 |
			 mgb_pcs_read(ep, SR_XS_PCS_DEV_ID2);
	dev_info(&ep->pci_dev->dev,
		 "pcs[%d] id: 0x%08x - %s\n",
		 ep->pcsaddr, ep->pcs_dev_id,
		 (ep->pcs_dev_id == PCS_DEV_ID_1G_2G5_10G) ? "1G/2.5G/10G" :
		 (ep->pcs_dev_id == PCS_DEV_ID_1G_2G5) ? "1G/2.5G" : "unknown");

	/* Switch DWC_xpcs to 1G speed mode XXX */

	mgb_sw_reset_mgio(ep);

	mgb_pcs_first_init(ep);

	/*
	if (mgb_pcs_vs_reset(ep)) {
		return 1;
	}
	*/

	if (ep->extphyaddr != -1) {
		/* External PHY present */
		r = mgb_set_pcs_an_clause_37(ep, 1); /* SGMII */
	} else {
		if (an_clause_73) {
			r = mgb_set_pcs_an_clause_73(ep);
		} else {
			r = mgb_set_pcs_an_clause_37(ep, 0); /* default */
		}
	}
	if (r) {
		dev_err(&dev->dev,
			"could not set clause %d autonegotiation\n",
			(ep->extphyaddr != -1) ? 37 : (an_clause_73 ? 73 : 37));
	} else {
		if (netif_msg_link(ep))
			dev_info(&dev->dev,
				"uses clause %d autonegotiation\n",
				(ep->extphyaddr != -1) ? 37 :
					(an_clause_73 ? 73 : 37));
	}
	return r;
}

/** mdio bus */

/* printk only */
static void mgb_print_extphy(struct mgb_private *ep, u32 id)
{
	struct pci_dev *pdev = ep->pci_dev;

	if ((id & MARVELL_PHY_ID_MASK) == MARVELL_PHY_ID_88E1111) {
		dev_info(&pdev->dev,
			 "found phy id 0x%08X - Marvell 88E1111\n", id);
	} else if (id == DP83867_PHY_ID) {
		dev_info(&pdev->dev,
			 "found external phy id 0x%08X - TI DP83867\n", id);
	} else {
		dev_info(&pdev->dev,
			 "found external phy id 0x%08X - unknown phy\n", id);
	}
}

/* called from probe() */
static int mgb_mdio_register(struct mgb_private *ep)
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
	snprintf(new_bus->id, MII_BUS_ID_SIZE, KBUILD_MODNAME"-%x",
		 PCI_DEVID(pdev->bus->number, pdev->devfn));

	new_bus->read = mgb_mdio_read_reg;
	new_bus->write = mgb_mdio_write_reg;

	ret = mdiobus_register(new_bus);
	if (ret) {
		dev_err(&pdev->dev,
			"Error on mdiobus_register\n");
		return ret;
	}
	ep->mii_bus = new_bus;

	/* external PHY disabled in devtree */
	if (ep->extphyaddr == -1)
		return 0;

	/* find external PHY */
	phydev = phy_find_first(new_bus);
	if (!phydev) {
		ep->extphyaddr = -1;

		if (netif_msg_link(ep))
			dev_info(&pdev->dev,
				 "register mdiobus %s (no external phy)\n",
				 new_bus->id);
	} else {
		if (phydev->mdio.addr == 0) {
			if (mgio_read_clause_22(ep, 0, 2) == 0xFFFF) {
				ep->extphyaddr = -1;

				if (netif_msg_link(ep))
					dev_info(&pdev->dev,
						"register mdiobus %s "
						"(no external phy found)\n",
						new_bus->id);

				return 0;
			}
		}

		ep->extphyaddr = phydev->mdio.addr;

		/* reset external PHY via BMCR_RESET bit */
		genphy_soft_reset(phydev);
		mdelay(1);

		/* PHY will be woken up in open() */
		phydev->irq = PHY_POLL;
		phy_suspend(phydev);

		if (netif_msg_link(ep))
			mgb_print_extphy(ep, phydev->phy_id);

		if (netif_msg_link(ep))
			dev_info(&pdev->dev,
				"register mdiobus %s with phy %s\n",
				new_bus->id, phydev_name(phydev));
	}

	return 0;
}


/** TITLE: DUMPING MGB Structures stuff */

static void mgb_dump_rx_ring_state(struct mgb_private *ep, int qn)
{
	int i;
	struct mgb_q *q = ep->mgb_qs[qn];

	if (q == NULL) {
		dev_err(&ep->dev->dev, "No queue %d\n", qn);
		return;
	}
	if (!q->rx) {
		dev_err(&ep->dev->dev, "No RX ring for queue %d\n", qn);
		return;
	}

	dev_warn(&ep->dev->dev,
		 "RX ring queue %d: cur_rx = %u\n", qn, q->cur_rx);

	for (i = 0; i < RX_RING_SIZE; i++) {
		dev_warn(&ep->dev->dev,
			 "RX %03d base %08x buf len %04x"
			 " msg len %04x status %04x\n", i,
			 le32_to_cpu(q->rx[i].base),
			 le16_to_cpu(-(q->rx[i].buf_length & 0xffff)),
			 le16_to_cpu(q->rx[i].msg_length),
			 le16_to_cpu((q->rx[i].status)));
	}
	pr_cont("\n");
}

static void mgb_dump_tx_ring_state(struct mgb_private *ep, int qn)
{
	int i;
	struct mgb_q *q = ep->mgb_qs[qn];

	if (q == NULL) {
		dev_err(&ep->dev->dev, "No queue %d\n", qn);
		return;
	}
	if (!q->tx) {
		dev_err(&ep->dev->dev, "No TX ring for queue %d\n", qn);
		return;
	}

	dev_warn(&ep->dev->dev,
		 "TX ring queue %d: cur_tx = %u, dirty_tx = %u %s\n",
		 qn, q->cur_tx, q->dirty_tx, q->full_tx ? " (full)" : "");

	for (i = 0; i < TX_RING_SIZE; i++) {
		dev_warn(&ep->dev->dev,
			 "TX %03d base %08x buf len %04x misc %08x status "
			 "%04x\n", i,
			 le32_to_cpu(q->tx[i].base),
			 le16_to_cpu(-(q->tx[i].buf_length & 0xffff)),
			 le32_to_cpu(q->tx[i].misc),
			 le16_to_cpu((u16)(q->tx[i].status)));
	}
	pr_cont("\n");
}

static void mgb_dump_queues_state(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	mgb_dump_rx_ring_state(ep, 0);
	mgb_dump_tx_ring_state(ep, 0);
	mgb_dump_rx_ring_state(ep, 1);
	mgb_dump_tx_ring_state(ep, 1);
}

static void mgb_dump_init_block(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	dev_warn(&dev->dev,
		 "Init block of mgb %px state. MODE = 0x%04x\n",
		 ep->init_block, le16_to_cpu(ep->init_block->mode));
	dev_warn(&dev->dev,
		 "PADDR0 0x%02x%02x%02x%02x%02x%02x LADDRF0 0x%016llx\n",
		 ep->init_block->paddr0[5], ep->init_block->paddr0[4],
		 ep->init_block->paddr0[3], ep->init_block->paddr0[2],
		 ep->init_block->paddr0[1], ep->init_block->paddr0[0],
		 ep->init_block->laddrf0);
	dev_warn(&dev->dev,
		 "PADDR1 0x%02x%02x%02x%02x%02x%02x LADDRF1 0x%016llx\n",
		 ep->init_block->paddr1[5], ep->init_block->paddr1[4],
		 ep->init_block->paddr1[3], ep->init_block->paddr1[2],
		 ep->init_block->paddr1[1], ep->init_block->paddr1[0],
		 ep->init_block->laddrf1);
	dev_warn(&dev->dev,
		 "Receive Desc Ring Addrs: 0x%08x 0x%08x\n",
		 ep->init_block->rdra0, ep->init_block->rdra1);
	dev_warn(&dev->dev,
		 "Transmit Desc Ring Addr: 0x%08x 0x%08x\n",
		 ep->init_block->tdra0, ep->init_block->tdra1);
	dev_warn(&dev->dev, "E_CSR = 0x%x\n", mgb_read_e_csr(ep));
	dev_warn(&dev->dev, "E_CAP = 0x%x\n", mgb_read_e_cap(ep));
	dev_warn(&dev->dev, "Q0_CSR = 0x%x\n", mgb_read_q_csr(ep, 0));
	dev_warn(&dev->dev, "Q1_CSR = 0x%x\n", mgb_read_q_csr(ep, 1));
}


/** TITLE: IEEE 1588 stuff */

/**
 * mgb_phc_adjfreq - adjust the frequency of the hardware clock
 * @ptp: ptp clock structure
 * @delta: Desired frequency change in parts per billion
 *
 * Adjust the frequency of the PHC cycle counter by the indicated delta from
 * the base frequency.
 **/
static int mgb_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	/* TODO write to RTC if SCLKR_RTC */
	return 0;
}

/*
 * mgb_phc_adjtime - Shift the time of the hardware clock
 * @ptp: ptp clock structure
 * @delta: Desired change in nanoseconds
 */
/* Adjust the timer by resetting the timecounter structure */
static int mgb_phc_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct mgb_private *ep = container_of(ptp, struct mgb_private,
					      ptp_clock_info);
	unsigned long flags;

	spin_lock_irqsave(&ep->systim_lock, flags);
	timecounter_adjtime(&ep->tc, delta);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

	return 0;
}

/**
 * mgb_phc_gettime - Reads the current time from the hardware clock
 * @ptp: ptp clock structure
 * @ts: timespec structure to hold the current time value
 *
 * Read the timecounter and return the correct value in ns after converting
 * it into a struct timespec.
 **/
static int mgb_phc_gettime(struct ptp_clock_info *ptp, struct timespec64 *ts)
{
	struct mgb_private *ep = container_of(ptp, struct mgb_private,
					      ptp_clock_info);
	unsigned long flags;
	u64 ns;

	spin_lock_irqsave(&ep->systim_lock, flags);
	ns = timecounter_read(&ep->tc);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

	*ts = ns_to_timespec64(ns);

	return 0;
}

/**
 * mgb_phc_settime - Set the current time on the hardware clock
 * @ptp: ptp clock structure
 * @ts: timespec containing the new time for the cycle counter
 *
 * Reset the timecounter to use a new base value instead of the kernel
 * wall timer value.
 **/
static int mgb_phc_settime(struct ptp_clock_info *ptp,
			      const struct timespec64 *ts)
{
	struct mgb_private *ep = container_of(ptp, struct mgb_private,
					      ptp_clock_info);
	unsigned long flags;
	u64 ns;

	ns = timespec64_to_ns(ts);

	/* reset the timecounter */
	spin_lock_irqsave(&ep->systim_lock, flags);
	timecounter_init(&ep->tc, &ep->cc, ns);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

	return 0;
}

/**
 * mgb_phc_enable - enable or disable an ancillary feature
 * @ptp: ptp clock structure
 * @request: Desired resource to enable or disable
 * @on: Caller passes one to enable or zero to disable
 *
 * Enable (or disable) ancillary features of the PHC subsystem.
 * Currently, no ancillary features are supported.
 **/
static int mgb_phc_enable(struct ptp_clock_info *ptp,
			  struct ptp_clock_request *rq, int on)
{
	if (rq->type == PTP_CLK_REQ_PPS) {
		pr_warn(KBUILD_MODNAME ": %s: TODO: call to mpv pps init\n",
			__func__);
		/* mpv_set_pps(on);*/
		return 0;
	}
	return -ENOTSUPP;
}

static struct ptp_clock_info mgb_ptp_clock_info = {
	.owner		= THIS_MODULE,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.pps		= 1,
	.adjfreq	= mgb_phc_adjfreq,
	.adjtime	= mgb_phc_adjtime,
	.gettime64	= mgb_phc_gettime,
	.settime64	= mgb_phc_settime,
	.enable		= mgb_phc_enable,
};

/* mgb_ptp_read - utility function which is used in init timecounter only */
static u64 mgb_ptp_read(const struct cyclecounter *cc)
{
	return 0; /* it is need for init only */
}

/* For IEEE-1588 testing in KPI-2 */
static u32 maxm_ts[8] = {0, 0, 0xffffffff, 0xffffffff, 0, 0, 0, 0};
#define	MAX_TTS	0
#define	MAX_RTS	1
#define	MIN_TTS	2
#define	MIN_RTS	3
#define	LST_TTS	4
#define	LST_RTS	5
#define	PRV_TTS	6
#define	PRV_RTS	7

/**
 * mgb_hwtstamp - utility function for IEEE 1588 in IOHUB2
 * @ep: board private structure
 * @skb: particular skb to include time stamp
 * @entry: descriptor entry
 *
 * If the time stamp is valid, convert it into the timecounter ns value
 * and store that result into the shhwtstamps structure which is passed
 * up the network stack.
 **/
static void mgb_hwtstamp(struct mgb_private *ep, struct sk_buff *skb,
	u32 etmr)
{
	u64 ns;
	struct skb_shared_hwtstamps *hwtstamps;
	unsigned long flags;

	spin_lock_irqsave(&ep->systim_lock, flags);
	ns = timecounter_cyc2time(&ep->tc, etmr);
	spin_unlock_irqrestore(&ep->systim_lock, flags);

	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	hwtstamps->hwtstamp = ns_to_ktime(ns);
}


/** TITLE: BUFFER RINGS handling */

static void mgb_free_skbs(struct pci_dev *pdev, struct sk_buff **skbs,
		dma_addr_t *dmas, int ring_sz, int dir)
{
	int i;

	for (i = 0; i < ring_sz; i++) {
		if (skbs[i]) {
			BUG_ON(dmas[i] == 0);
			pci_unmap_single(pdev, dmas[i], skbs[i]->len, dir);
			dev_kfree_skb(skbs[i]);
		}
		skbs[i] = NULL;
		dmas[i] = 0;
	}
}


/** TITLE: INITIALIZING / CLEANING Rx and Tx queues. */

static int mgb_alloc_queue(struct mgb_private *ep, int nq)
{
	struct mgb_q *q;

	q = kzalloc(sizeof(struct mgb_q), GFP_KERNEL);
	if (!q) {
		return -ENOMEM;
	}
	ep->mgb_qs[nq] = q;
	q->ep = ep;
	raw_spin_lock_init(&q->lock);

	return 0;
}

static void mgb_free_queue(struct mgb_private *ep, int nq)
{
	kfree(ep->mgb_qs[nq]);
	ep->mgb_qs[nq] = NULL;
}

static void mgb_unset_queue(struct mgb_q *q)
{
	struct mgb_private *ep = q->ep;

	if (q->tx_skbuff) {
		if (q->tx_dma_skbuff) {
			mgb_free_skbs(ep->pci_dev, q->tx_skbuff,
				q->tx_dma_skbuff, TX_RING_SIZE,
				PCI_DMA_TODEVICE);
			kfree(q->tx_dma_skbuff);
			q->tx_dma_skbuff = 0;
		}
		kfree(q->tx_skbuff);
		q->tx_skbuff = NULL;
	}
	if (q->tx_dma) {
		dma_free_coherent(&q->ep->pci_dev->dev,
			sizeof(struct mgb_rx_head) * TX_RING_SIZE,
			q->tx, q->tx_dma);
		q->tx = NULL;
		q->tx_dma = 0;
	}
	if (q->rx_skbuff) {
		if (q->rx_dma_skbuff) {
			mgb_free_skbs(ep->pci_dev, q->rx_skbuff,
				q->rx_dma_skbuff, RX_RING_SIZE,
				PCI_DMA_FROMDEVICE);
			kfree(q->rx_dma_skbuff);
			q->rx_dma_skbuff = 0;
		}
		kfree(q->rx_skbuff);
		q->rx_skbuff = NULL;
	}
	if (q->rx_dma) {
		dma_free_coherent(&q->ep->pci_dev->dev,
			sizeof(struct mgb_rx_head) * RX_RING_SIZE,
			q->rx, q->rx_dma);
		q->rx = NULL;
		q->rx_dma = 0;
	}
}

static void mgb_unset_queues(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	netif_stop_queue(dev);

	if (ep->mgb_qs[1]) {
		mgb_unset_queue(ep->mgb_qs[1]);
	}
	if (ep->mgb_qs[0]) {
		mgb_unset_queue(ep->mgb_qs[0]);
	}
}

static int mgb_set_queue(struct mgb_q *q)
{
	struct mgb_private *ep = q->ep;

	q->rx = dma_alloc_coherent(&q->ep->pci_dev->dev,
			sizeof(struct mgb_rx_head) * RX_RING_SIZE,
			&q->rx_dma, GFP_KERNEL);
	if (!q->rx) {
		goto nomem;
	}
	if ((long)q->rx & 0x7) {
		dev_err(&ep->dev->dev,
			"Allocated rx ring is not correcly alligned."
			" ring = %px\n", q->rx);
		goto nomem;
	}
	memset(q->rx, 0, sizeof(struct mgb_rx_head) * RX_RING_SIZE);
	q->tx = dma_alloc_coherent(&q->ep->pci_dev->dev,
			sizeof(struct mgb_tx_head) * TX_RING_SIZE,
			&q->tx_dma, GFP_KERNEL);
	if (!q->tx) {
		goto nomem;
	}
	if ((long)q->tx & 0x7) {
		dev_err(&ep->dev->dev,
			"Allocated tx ring is not correcly alligned."
			" ring = %px\n", q->rx);
		goto nomem;
	}
	memset(q->tx, 0, sizeof(struct mgb_tx_head) * TX_RING_SIZE);
	q->rx_skbuff = kzalloc(sizeof(struct sk_buff *) * RX_RING_SIZE,
					GFP_KERNEL);
	if (!q->rx_skbuff) {
		goto nomem;
	}
	q->tx_skbuff = kzalloc(sizeof(struct sk_buff *) * TX_RING_SIZE,
					GFP_KERNEL);
	if (!q->tx_skbuff) {
		goto nomem;
	}
	q->rx_dma_skbuff = kzalloc(sizeof(dma_addr_t) * RX_RING_SIZE,
					GFP_KERNEL);
	if (!q->rx_dma_skbuff) {
		goto nomem;
	}
	q->tx_dma_skbuff = kzalloc(sizeof(dma_addr_t) * TX_RING_SIZE,
					GFP_KERNEL);
	if (!q->tx_dma_skbuff) {
		goto nomem;
	}
	return 0;

nomem:
	mgb_unset_queue(q);
	return -ENOMEM;
}

static int mgb_set_queues(struct mgb_private *ep)
{
	if (ep->mgb_qs[0] == NULL) {
		return -ENOMEM;
	}
	if (mgb_set_queue(ep->mgb_qs[0])) {
		return -ENOMEM;
	}
	if (ep->mgb_qs[1] == NULL) {
		return 0;
	}
	if (mgb_set_queue(ep->mgb_qs[1])) {
		mgb_unset_queue(ep->mgb_qs[0]);
		return -ENOMEM;
	}
	return 0;
}

static int mgb_reset_queue(struct mgb_q *q)
{
	struct mgb_private *ep = q->ep;
	int i;

	q->full_tx = 0;
	q->cur_rx = 0;
	q->cur_tx = 0;
	q->dirty_tx = 0;

	for (i = 0; i < RX_RING_SIZE; i++) {
		struct sk_buff *rx_skbuff = q->rx_skbuff[i];
		struct mgb_rx_head *rxr = q->rx + i;
		if (rx_skbuff == NULL) {
			WARN_ON(in_atomic());
			rx_skbuff = dev_alloc_skb(PKT_BUF_SZ + CRC_SZ + 2);
			if (!rx_skbuff) {
				dev_err(&ep->dev->dev,
					"%s: dev_alloc_skb failed.\n",
					__func__);
				return -ENOMEM;
			}
			q->rx_skbuff[i] = rx_skbuff;
			skb_reserve(rx_skbuff, 2);
		}
		if (q->rx_dma_skbuff[i] == 0) {
			q->rx_dma_skbuff[i] = pci_map_single(ep->pci_dev,
				rx_skbuff->data, (PKT_BUF_SZ + CRC_SZ),
				PCI_DMA_FROMDEVICE);
			if (pci_dma_mapping_error(ep->pci_dev,
				q->rx_dma_skbuff[i])) {
				q->rx_dma_skbuff[i] = 0;
				return 1;
			}
		}
		rxr->base = cpu_to_le32((u32)(q->rx_dma_skbuff[i]));
		rxr->buf_length = cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
		/* HW sync */
		wmb();
		rxr->status |= cpu_to_le16(RD_OWN);
	}

	/* TODO - try to resend skb's having TX_OWN bit */
	for (i = 0; i < TX_RING_SIZE; i++) {
		struct mgb_tx_head *txr = q->tx + i;
		struct sk_buff *skb = q->tx_skbuff[i];
		txr->status = 0;	/* CPU owns buffer */
		wmb();
		txr->base = 0;
		if (skb) {
			if (q->tx_dma_skbuff[i]) {
				pci_unmap_single(ep->pci_dev,
					q->tx_dma_skbuff[i],
					skb->len, PCI_DMA_TODEVICE);
			} else {
				dev_warn(&ep->dev->dev,
					 "unmapped skb in tx ring\n");
			}
			dev_kfree_skb_any(skb);
		}
		q->tx_skbuff[i] = NULL;
		q->tx_dma_skbuff[i] = 0;
	}

	return 0;
}


static int mgb_reset_queues(struct mgb_private *ep)
{
	int r;

	if (ep->mgb_qs[0]) {
		r = mgb_reset_queue(ep->mgb_qs[0]);
		if (r) {
			return r;
		}
	}
	if (ep->mgb_qs[1]) {
		r = mgb_reset_queue(ep->mgb_qs[1]);
		if (r) {
			return r;
		}
	}

	return 0;
}


/** TITLE: OPEN / CLOSE stuff */

static void mgb_set_dma_and_initblock(struct mgb_private *ep)
{
	struct net_device *dev = ep->dev;
	u16 mode = mgb_default_mode;
	int i;

	ep->init_block->laddrf0 = 0UL;
	ep->init_block->laddrf1 = 0UL;

	for (i = 0; i < 6; i++)
		ep->init_block->paddr0[i] = dev->dev_addr[i];

	for (i = 0; i < 6; i++)
		ep->init_block->paddr1[i] = dev->dev_addr[i];

	ep->init_block->rdra0 = cpu_to_le32((u32)(ep->mgb_qs[0]->rx_dma |
			ep->log_rx_buffs));
	ep->init_block->tdra0 = cpu_to_le32((u32)(ep->mgb_qs[0]->tx_dma |
			ep->log_tx_buffs));

	if (ep->dev->num_rx_queues == 2) {
		ep->init_block->rdra1 =
			cpu_to_le32((u32)(ep->mgb_qs[1]->rx_dma |
			ep->log_rx_buffs));
		ep->init_block->tdra1 =
			cpu_to_le32((u32)(ep->mgb_qs[1]->tx_dma |
			ep->log_tx_buffs));
	} else {
		ep->init_block->rdra1 = 0;
		ep->init_block->tdra1 = 0;
		mode |= DRX1 | DTX1;
	}

	ep->init_block->mode = cpu_to_le16(mode);
	mgb_write_e_base_address(ep, (u32)(ep->initb_dma));
	mgb_write_dma_base_address(ep, (u32)(ep->initb_dma >> 32));
	mgb_write_e_csr(ep, INIT);
}

static char *mgb_set_mq_name(struct mgb_q *mq, int pin)
{
	switch (pin) {
	case MGB_R0_INTR:
		snprintf(mq->rx_name, IFNAMSIZ, "%s-r0", mq->ep->dev->name);
		return mq->rx_name;
	case MGB_T0_INTR:
		snprintf(mq->tx_name, IFNAMSIZ, "%s-t0", mq->ep->dev->name);
		return mq->tx_name;
	case MGB_R1_INTR:
		snprintf(mq->rx_name, IFNAMSIZ, "%s-r1", mq->ep->dev->name);
		return mq->rx_name;
	case MGB_T1_INTR:
		snprintf(mq->tx_name, IFNAMSIZ, "%s-t1", mq->ep->dev->name);
		return mq->tx_name;
	default:
		dev_err(&mq->ep->dev->dev,
			"%s: Uncorrect pin argument %d\n", __func__, pin);
		return NULL;
	}
}

static int request_mgb_irq(struct mgb_private *ep, unsigned int pin,
			   irq_handler_t fn, struct mgb_q *mq)
{
	unsigned int irq = pin + ep->pci_dev->irq;
	char *nm = mgb_set_mq_name(mq, pin);

	if (netif_msg_intr(ep))
		dev_info(&ep->dev->dev,
			 "mgb requests irq %s  msi_irq %u\n",
			 nm, irq);

	return request_irq(irq, fn, IRQF_NO_THREAD, nm, mq);
}

static int request_mgb_sys_irq(struct mgb_private *ep,
			       irq_handler_t fn1, irq_handler_t fn2)
{
	unsigned int irq = MGB_SYS_INTR + ep->pci_dev->irq;

	if (netif_msg_intr(ep))
		dev_info(&ep->dev->dev,
			 "mgb requests threaded irq for msi_irq %u\n", irq);

	return request_threaded_irq(irq, fn1, fn2, 0, ep->dev->name, ep);
}

static void free_mgb_irq(struct mgb_private *ep, unsigned int pin, void *arg)
{
	unsigned int irq = pin + ep->pci_dev->irq;

	if (netif_msg_intr(ep))
		dev_info(&ep->dev->dev,
			 "mgb frees irq: msi_irq %u\n", irq);

	irq_set_affinity_hint(irq, NULL);
	free_irq(irq, arg);
}

static void mgb_distribute_irqs(struct mgb_private *ep)
{
	int i;
	int step = 0;
	struct cpumask m;
	struct cpumask dev_m;
	int fc = PCI_FUNC(ep->pci_dev->devfn);
	int irq;

	if (ep->mgb_qs[1] == NULL) {
		return;
	}
	if (num_online_cpus() < 4) {
		return;
	}
	cpumask_copy(&dev_m, cpumask_of_node(dev_to_node(&ep->dev->dev)));
	for (i = 0; i < num_possible_cpus(); i++) {
		if (!cpu_online(i)) {
			continue;
		}
		cpumask_clear(&m);
		cpumask_set_cpu(i, &m);
		if (!cpumask_intersects(&m, &dev_m)) {
			continue;
		}
		irq = ep->pci_dev->irq;
		if (step == 0) {
			irq += fc ? MGB_T0_INTR : MGB_R0_INTR;
		} else if (step == 1) {
			irq += fc ? MGB_T1_INTR : MGB_R1_INTR;
		} else if (step == 2) {
			irq += fc ? MGB_R1_INTR : MGB_T1_INTR;
		} else if (step == 3) {
			irq += fc ? MGB_R0_INTR : MGB_T0_INTR;
		} else {
			break;
		}
		if (irq_set_affinity_hint(irq, &m)) {
				break;
		}
		step++;
	}
}

static int mgb_assign_irqs(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int rc;

	rc = request_mgb_irq(ep, MGB_R0_INTR, mgb_rx_interrupt, ep->mgb_qs[0]);
	if (rc) {
		goto first_err;
	}
	rc = request_mgb_irq(ep, MGB_T0_INTR, mgb_tx_interrupt, ep->mgb_qs[0]);
	if (rc) {
		goto err_free_1irqs;
	}
	if (ep->mgb_qs[1]) {
		rc = request_mgb_irq(ep, MGB_R1_INTR, mgb_rx_interrupt,
					ep->mgb_qs[1]);
		if (rc) {
			goto err_free_2irqs;
		}
		rc = request_mgb_irq(ep, MGB_T1_INTR, mgb_tx_interrupt,
					ep->mgb_qs[1]);
		if (rc) {
			goto err_free_3irqs;
		}
	}
	rc = request_mgb_sys_irq(ep, mgb_sys_interrupt, mgb_restart_card);
	if (!rc) {
		mgb_distribute_irqs(ep);
		return 0;
	}

	if (ep->mgb_qs[1])
		free_mgb_irq(ep, MGB_T1_INTR, ep->mgb_qs[1]);
err_free_3irqs:
	if (ep->mgb_qs[1])
		free_mgb_irq(ep, MGB_R1_INTR, ep->mgb_qs[1]);
err_free_2irqs:
	free_mgb_irq(ep, MGB_T0_INTR, ep->mgb_qs[0]);
err_free_1irqs:
	free_mgb_irq(ep, MGB_R0_INTR, ep->mgb_qs[0]);
first_err:
	return -EINVAL;
}

static void mgb_free_irqs(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	free_mgb_irq(ep, MGB_SYS_INTR, (void *)ep);
	free_mgb_irq(ep, MGB_R0_INTR, ep->mgb_qs[0]);
	free_mgb_irq(ep, MGB_T0_INTR, ep->mgb_qs[0]);
	if (ep->mgb_qs[1]) {
		free_mgb_irq(ep, MGB_R1_INTR, ep->mgb_qs[1]);
		free_mgb_irq(ep, MGB_T1_INTR, ep->mgb_qs[1]);
	}
}

static int mgb_open(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int rc;

	mutex_lock(&ep->mx);
	if (mgb_opened(ep)) {
		rc = -EBUSY;
		goto err;
	}
	if (netif_msg_ifup(ep))
		dev_info(&dev->dev, "%s: begin\n", __func__);

	ep->e_cap = IPV4_HCS_ENA_RX | IPV4_HCS_ENA_TX |
			TCP_PCS_ENA_RX | TCP_PCS_ENA_TX |
			UDP_PCS_ENA_RX | UDP_PCS_ENA_TX;
	ep->irq_delay = mgb_set_irq_delay(64, 255, 0, 255);

	rc = mgb_set_queues(ep);
	if (rc) {
		goto err;
	}
	rc = mgb_assign_irqs(dev);
	if (rc) {
		mgb_unset_queues(dev);
		goto err;
	}

	/* External PHY connect */
	rc = mgb_extphy_connect(ep);
	if (rc) {
		dev_err(&dev->dev, "phy_connect error.\n");
		goto err;
	}

	napi_enable(&(ep->mgb_qs[0]->napi));
	if (ep->mgb_qs[1])
		napi_enable(&(ep->mgb_qs[1]->napi));

	/* External PHY start */
	if (dev->phydev) {
		mgb_init_extphy(ep);
	}

	/* start card */
	mgb_restart_card(MGB_SYS_INTR, ep);
	if (mgb_read_e_csr(ep) & STRT) {
		goto ok;
	}
	/* Here if open unsuccessful */
	if (dev->phydev) {
		phy_stop(dev->phydev);
		phy_disconnect(dev->phydev);
	}
	napi_disable(&(ep->mgb_qs[0]->napi));
	if (ep->mgb_qs[1]) {
		napi_disable(&(ep->mgb_qs[1]->napi));
	}

err:
	mgb_free_irqs(dev);
	mgb_unset_queues(dev);

	rc = -EFAULT;
	if (netif_msg_ifup(ep))
		dev_err(&dev->dev, "mgb not opened, error %d\n", rc);
ok:
	mutex_unlock(&ep->mx);
	return rc;
}

static int mgb_close(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (netif_msg_ifdown(ep))
		dev_info(&dev->dev, "Shutting down ethercard\n");

	mutex_lock(&ep->mx);
	if (!mgb_opened(ep)) {
		/* not opened */
		mutex_unlock(&ep->mx);
		return -EBUSY;
	}

	if (!ep->linkup) {
		netif_carrier_off(dev);
		ep->linkup = 0;
	}

	/* External PHY stop */
	if (dev->phydev) {
		phy_stop(dev->phydev);
		phy_disconnect(dev->phydev);
		dev->phydev = NULL;
	}

	mgb_write_e_csr(ep, STOP);
	mgb_wait_for_freeze(&ep->flags);
	napi_disable(&(ep->mgb_qs[0]->napi));
	if (ep->mgb_qs[1]) {
		napi_disable(&(ep->mgb_qs[1]->napi));
	}

	mgb_free_irqs(dev);
	mgb_unset_queues(dev);

	mutex_unlock(&ep->mx);

	return 0;
}


/** TITLE: TRANSMIT stuff */

#define	check_tx_ring(a, b) \
	do {if (check_tx_q_ring) check_tx_q((a), (b)); } while (0)
static int check_tx_q(struct mgb_q *q, char *str)
{
	struct mgb_private *ep = q->ep;
	static int checked = 10;
	int cur_tx = q->cur_tx;
	int dirty_tx = q->dirty_tx;
	int i;
	int base;
	char *reason;

	if (checked <= 0)
		return 1;


	if (cur_tx == dirty_tx) {
		/* all entries are dirty or all entries are clean */
		base = !!q->tx[0].base;
		for (i = 0; i < TX_RING_SIZE; i++) {
			if (base != !!q->tx[i].base) {
				reason = "Bad entry ";
				goto bad_ring;
			}
		}
		return 0;
	}

	if (q->tx[dirty_tx].base == 0) {
		reason = "Bad dirty_tx";
		i = dirty_tx;
		goto bad_ring;
	}
	base = 1;
	i = (dirty_tx + 1) & TX_RING_MOD_MASK;
	while (i != dirty_tx) {
		if (q->tx[i].base == 0) {
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
		if (q->tx[i].base != 0) {
			reason = "Dirty_entry ";
			goto bad_ring;
		}
		i = (i + 1) & TX_RING_MOD_MASK;
	}
	return 0;

bad_ring:
	dev_warn(&ep->dev->dev,
		 "check_tx_ring: %s: %s %d\n", str, reason, i);
	mgb_dump_tx_ring_state(ep, mgb_nq(ep, q));
	checked--;

	return 1;
}

#if 0
static void try_to_cleanup_tx_bufs(struct mgb_private *ep,
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
			dev_info(&dev->dev,
				 "try_to_cleanup_tx_bufs: base == 0"
				 " on first loop ? cur = %d, dirty = %d\n",
				 ep->cur_tx, ep->dirty_tx);
			break;
		}
		status = (short)le16_to_cpu(ep->tx_ring[dirty_tx].status);
		if (status & TD_OWN) {
			break;   /* It still hasn't been Txed */
		}
		if (status & TD_ERR) {
			break;
		}
		first_loop = 0;
		ep->tx_ring[dirty_tx].base = 0;
		ep->tx_ring[dirty_tx].status = 0;

		if (status & (TD_MORE|TD_ONE))
			q->stats.collisions++;
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
				if (dmaaddr) {
					pci_unmap_single(ep->pci_dev, dmaaddr,
						skb->len, PCI_DMA_TODEVICE);
				}
#endif
				dev_kfree_skb_irq(skb);
			} else {
				ep->skb_to_pause_sent = 0;
			}
		}
		dirty_tx = (dirty_tx + 1) & (TX_RING_MOD_MASK);
	}
	ep->dirty_tx = dirty_tx;
	if (netif_msg_tx_err(ep))
		dev_info(&dev->dev,
			 "try_to_cleanup_tx_bufs : %d bufs cleaned\n", num);
}
#endif

static void mgb_dump_skb_data(struct mgb_private *ep, int nq,
			struct sk_buff *skb)
{
	void *packet = (void *)skb->data;
	struct ethhdr *eth = (struct ethhdr *)packet;
	int i;
	int len;
	dev_info(&ep->dev->dev,
		 "mbg %s-%d :len = %d, data = %px, "
		 "src = %02x:%02x:%02x:%02x:%02x:%02x, "
		 "dst = %02x:%02x:%02x:%02x:%02x:%02x, proto = 0x%04x\n",
		 ep->dev->name, nq, skb->len, packet,
		 eth->h_source[0], eth->h_source[1], eth->h_source[2],
		 eth->h_source[3], eth->h_source[4], eth->h_source[5],
		 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
		 eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
		 be16_to_cpu(eth->h_proto));

	if (!netif_msg_pktdata(ep))
		return;

	len = (skb->len);
	if (((long)packet & 1) == 1) {
		dev_info(&ep->dev->dev,
			 "packet: byte   %0x02x\n", *(u8 *)packet);
		packet += 1;
		len -= 1;
	}
	if (((long)packet & 2) == 2) {
		dev_info(&ep->dev->dev,
			 "packet: short    0x%04x\n", (*(u16 *)packet));
		packet += 2;
		len -= 2;
	}
	len = len / 4;
	if (len > 16)
		len = 16;
	for (i = 0; i < len; i++) {
		dev_info(&ep->dev->dev,
			 "packet: int # %d  0x%08x\n", i, *(u32 *)packet);
		packet += 4;
	}
}

static inline s16 mgb_get_tx_csum_flags(struct mgb_private *ep,
					struct sk_buff *skb)
{
	if (skb->ip_summed != CHECKSUM_PARTIAL) {
		return 0;
	}
	if (skb->protocol != htons(ETH_P_IP)) {
		goto calc_sum;
	}
	if ((ep->e_cap & (IPV4_HCS_ENA_TX | TCP_PCS_ENA_TX | UDP_PCS_ENA_TX))
		!= (IPV4_HCS_ENA_TX | TCP_PCS_ENA_TX | UDP_PCS_ENA_TX)) {
		goto calc_sum;
	}
	if (skb->csum_offset == offsetof(struct tcphdr, check)) {
		return TD_IHCS | TD_TPCS;
	}
	if (skb->csum_offset == offsetof(struct tcphdr, check)) {
		return TD_IHCS | TD_TPCS;
	}

calc_sum:
	skb_checksum_help(skb);

	return 0;
}

static int mgb_start_xmit_to_q(struct sk_buff *skb, struct mgb_q *q)
{
	struct mgb_private *ep = q->ep;
	struct net_device *dev = ep->dev;
	int nq = mgb_nq(ep, q);
	dma_addr_t dmaaddr;
	u16 status;
	int entry;
	unsigned long flags;
	int len = skb->len;

/*
	if (netif_msg_tx_queued(ep))
		dev_info(&dev->dev, "%s: entered\n", __func__);
*/
	status = TD_OWN | TD_ENP | TD_STP |
		mgb_get_tx_csum_flags(ep, skb);

	dmaaddr = pci_map_single(ep->pci_dev, skb->data, len,
			PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(ep->pci_dev, dmaaddr)) {
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: queue %d Could not map skb\n",
				 __func__, nq);

		return NETDEV_TX_BUSY;
	}
	raw_spin_lock_irqsave(&q->lock, flags);

	if (mgb_set_flag_bit(MGB_F_XMIT + nq, &ep->flags)) {
		raw_spin_unlock_irqrestore(&q->lock, flags);
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: queue %d xmit stopped by reset.\n",
				 __func__, nq);

		return NETDEV_TX_BUSY;
	}
	check_tx_ring(q, "start_xmit begin");
	entry = q->cur_tx;
	/* Caution: the write order is important here, set the status
	 * with the "ownership" bits last.
	 */

	q->tx[entry].buf_length = cpu_to_le16(-len);
	q->tx[entry].misc = 0x00000000;
	q->tx_skbuff[entry] = skb;
	q->tx_dma_skbuff[entry] = dmaaddr;
	q->tx[entry].base = cpu_to_le32((u32)dmaaddr);
	wmb(); /* Make sure owner changes after all others are visible */
	q->tx[entry].status = cpu_to_le16(status);

	q->stats.tx_bytes += len;
	q->stats.tx_packets++;

	if (netif_msg_tx_queued(ep)) {
		dev_info(&dev->dev,
			 "%s: queue %d: base: 0x%x; cur = %d, dirty = %d, "
			 "buf_len: %d status: 0x%x; Q_CSR = 0x%08x\n",
			 __func__, nq,
			 le32_to_cpu(q->tx[entry].base), entry, q->dirty_tx,
			 len,
			 le16_to_cpu(q->tx[entry].status),
			 mgb_read_q_csr(ep, nq));
		mgb_dump_skb_data(ep, nq, skb);
	}

	/* Trigger an immediate send poll. */
	mgb_write_q_csr(ep, nq, Q_TDMD);

	q->cur_tx = (entry + 1) & TX_RING_MOD_MASK;
	if (q->tx[q->cur_tx].base != 0) {
		if (netif_msg_tx_err(ep) || netif_msg_tx_queued(ep)) {
			dev_info(&dev->dev,
				 "queue %d: transmitter queue is full "
				 "cur_tx = %d, dirty_tx =%d, status = %04x\n",
				 nq, q->cur_tx, q->dirty_tx,
				 le16_to_cpu(q->tx[q->cur_tx].status));
		}
		q->full_tx = 1;
		q->stats.tx_compressed++;
		netif_stop_subqueue(dev, nq);
	}
	check_tx_ring(q, "end_xmit begin");
	clear_bit(MGB_F_XMIT + nq, &ep->flags);
	raw_spin_unlock_irqrestore(&q->lock, flags);

	return NETDEV_TX_OK;
}


static inline int mgb_tx_q_mapping(struct mgb_private *ep,
				struct sk_buff *skb)
{
	unsigned int r_idx = skb->queue_mapping;

	if (r_idx >= ep->dev->num_tx_queues)
		r_idx = r_idx % ep->dev->num_tx_queues;

	return r_idx;
}

static netdev_tx_t mgb_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int nq = mgb_tx_q_mapping(ep, skb);

	if (skb_put_padto(skb, ETH_ZLEN)) {
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: Could not skb_put_padto\n", __func__);

		return NETDEV_TX_OK;
	}
	/*
	if (netif_msg_tx_queued(ep))
		dev_info(&dev->dev, "%s: queue %d\n", __func__, nq);
	*/
	if (__netif_subqueue_stopped(dev, nq)) {
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: xmit to queue %d stopped\n",
				 __func__, nq);

		return NETDEV_TX_BUSY;
	}

	return mgb_start_xmit_to_q(skb, ep->mgb_qs[nq]);
}

static int mgb_tx(struct mgb_q *q)
{
	struct mgb_private *ep = q->ep;
	struct net_device *dev = ep->dev;
	unsigned int dirty_tx;
	int delta, must_restart = 0;
	int first_loop = 1;
	int nq = mgb_nq(ep, q);
	unsigned long flags;

	raw_spin_lock_irqsave(&q->lock, flags);
	dirty_tx = q->dirty_tx;

	if (mgb_set_flag_bit(MGB_F_TX + nq, &ep->flags)) {
		raw_spin_unlock_irqrestore(&q->lock, flags);
		return NETDEV_TX_BUSY;
	}
	while ((dirty_tx != q->cur_tx) || first_loop) {
		int entry = dirty_tx;
		struct mgb_tx_head *tx_ring = &q->tx[entry];
		u16 status = (u16)le16_to_cpu(tx_ring->status);

		if (netif_msg_intr(ep))
			dev_info(&dev->dev,
				 "queue %d: TX interrupt: status = 0x%04x "
				 "dirty = %d, cur = %d\n",
				 nq, status, dirty_tx, q->cur_tx);

		if (status & TD_OWN)
			break; /* It still hasn't been Txed */

		first_loop = 0;

		if (status & TD_ERR) {
			/* There was an major error, log it. */
			u32 err_status = le32_to_cpu(tx_ring->misc);

			q->stats.tx_errors++;

			if (netif_msg_tx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: TX error on %d: base: 0x%x;"
					 " buf_length: 0x%x;"
					 " status: 0x%x; misc: 0x%08x\n",
					 nq, entry,
					 le32_to_cpu(tx_ring->base),
					 le16_to_cpu(tx_ring->buf_length),
					 status,
					 err_status);

			if (err_status & TD_RTRY)
				q->stats.tx_aborted_errors++;
			if (err_status & TD_LCAR)
				q->stats.tx_carrier_errors++;
			if (err_status & TD_LCOL)
				q->stats.tx_window_errors++;
			if (err_status & TD_UFLO) {
				q->stats.tx_fifo_errors++;
				/* On FIFO errors the Tx unit is turned off! */
				if (netif_msg_tx_err(ep))
					dev_err(&dev->dev,
						"queue %d: Tx UFLO error!\n",
						nq);

				must_restart = 1;
				break;
			}
		} else if (status & (TD_MORE | TD_ONE)) {
			q->stats.collisions++;
			if (netif_msg_tx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: Tx collision "
					 "on %d status=%04x\n",
					 nq, entry, status);
		}

		tx_ring->base = 0;
		tx_ring->status = 0;

		/* We must free the original skb */
		if (q->tx_skbuff[entry]) {
			dma_addr_t dmaaddr = q->tx_dma_skbuff[entry];
			struct sk_buff *skb = q->tx_skbuff[entry];
			u32 et = le32_to_cpu(tx_ring->etmr);
			if (ep->e_cap & (ETMR_ADD_ENA | ETMR_CLR_ENA) ==
					(ETMR_ADD_ENA | ETMR_CLR_ENA)) {
				mgb_hwtstamp(ep, skb, et);
				if (netif_msg_1588(ep)) {
					if (maxm_ts[MAX_TTS] < et)
						maxm_ts[MAX_TTS] = et;
					if (maxm_ts[MIN_TTS] >
						(et - maxm_ts[LST_TTS]) &&
						et != maxm_ts[LST_TTS]) {
						maxm_ts[MIN_TTS] =
							et - maxm_ts[LST_TTS];
						maxm_ts[PRV_TTS] =
							maxm_ts[LST_TTS];
						maxm_ts[LST_TTS] = et;
					}
					u32 et = le32_to_cpu(q->tx[entry].etmr);
					if (et == 0 ||
						tx_prev_etmr > et) {
						dev_warn(&dev->dev,
							 "queue %d cs=%7x "
							 "Tx= 0x%8x maxt %8x "
							 "r %8x c=%16lu\n",
							 nq, et,
							 tx_prev_etmr,
							 maxm_ts[MAX_TTS],
							 maxm_ts[MAX_RTS],
							 (unsigned long)
								get_cycles());
					}
					tx_prev_etmr = et;
				}
			}
			q->tx_skbuff[entry] = NULL;
			q->tx_dma_skbuff[entry] = 0;
			tx_ring->status = 0;
			q->dirty_tx = (dirty_tx + 1) & TX_RING_MOD_MASK;
			raw_spin_unlock_irqrestore(&q->lock, flags);

			if (dmaaddr) {
				pci_unmap_single(ep->pci_dev, dmaaddr,
						 skb->len, PCI_DMA_TODEVICE);
			}
			dev_kfree_skb_any(skb);
			raw_spin_lock_irqsave(&q->lock, flags);
			dirty_tx = q->dirty_tx;
		} else {
			if (netif_msg_tx_err(ep)) {
				dev_info(&dev->dev,
					 "%s: queue %d no skbbuf\n",
					 __func__, nq);
				break;
			}
			dirty_tx = (dirty_tx + 1) & TX_RING_MOD_MASK;
		}
	}

	q->dirty_tx = dirty_tx;
	delta = (q->cur_tx - dirty_tx) & (TX_RING_MOD_MASK);

	if (q->full_tx &&
		netif_tx_queue_stopped(netdev_get_tx_queue(dev, nq)) &&
		delta < TX_RING_SIZE - TX_HISTERESIS) {
		if (q->tx[q->cur_tx].base) {
			goto no_unqueue;
		}
		/* The ring is no longer full, clear tbusy. */
		q->full_tx = 0;
		netif_tx_wake_queue(netdev_get_tx_queue(dev, nq));
		if (netif_msg_tx_err(ep))
			dev_info(&dev->dev,
				 "queue %d: transmitter woke queuee "
				 "cur_tx = %d, dirty_tx = %d\n",
				 nq, q->cur_tx, q->dirty_tx);
	}

no_unqueue:
	clear_bit(MGB_F_TX + nq, &ep->flags);
	raw_spin_unlock_irqrestore(&q->lock, flags);

	return must_restart;
}


/** TITLE: RECIEVE stuff */

static void mgb_handle_rx_err(struct mgb_q *q, int nq, s16 status)
{
	struct mgb_private *ep = q->ep;

	if (netif_msg_rx_err(ep))
		dev_info(&ep->dev->dev,
			 "queue %d reciever error: status = 0x%x ",
			 nq, status);

	if (status & RD_ENP) {
		if (netif_msg_rx_err(ep))
			pr_cont(" ENP");
		/* No detailed rx_errors counter to increment at the */
		/* end of a packet.*/
	}
	if (status & RD_FRAM) {
		if (netif_msg_rx_err(ep))
			pr_cont(" FRAM");

		q->stats.rx_frame_errors++;
	}
	if (status & RD_OFLO) {
		if (netif_msg_rx_err(ep))
			pr_cont(" OFLO ");

		q->stats.rx_over_errors++;
	}
	if (status & RD_CRC) {
		if (netif_msg_rx_err(ep))
			pr_cont(" CRC ");

		q->stats.rx_crc_errors++;
	}
	if (status & RD_BUFF) {
		if (netif_msg_rx_err(ep))
			pr_cont(" BUFF ");

		q->stats.rx_fifo_errors++;
	}
	if (status & RD_CSER) {
		if (netif_msg_rx_err(ep))
			pr_cont(" CSER ");

		q->stats.rx_crc_errors++;
	}
	if (netif_msg_rx_err(ep)) {
		pr_cont("\n");
	}
}

static int mgb_rx(struct mgb_q *q, int budget)
{
	struct mgb_private *ep = q->ep;
	int entry = q->cur_rx;
	struct net_device *dev = ep->dev;
	int boguscnt = RX_RING_SIZE;
	int nq = mgb_nq(ep, q);
	int work_done = 0;
	int rx_in_place = 0;

	/* If we own the next entry, it's a new packet. Send it up. */
	while (((s16)le16_to_cpu(q->rx[entry].status)) >= 0) {
		int status = (short)le16_to_cpu(q->rx[entry].status);
		short pkt_len;
		struct sk_buff *skb;
		if (work_done == budget) {
			if (netif_msg_rx_status(ep))
				dev_info(&dev->dev,
					 "queue %d: rx budget %d overloaded.\n",
					 nq, budget);

			break;
		}

		if (status & RD_ERR) { /* error. */
			q->stats.rx_errors++;
			mgb_handle_rx_err(q, nq, status);
			q->rx[entry].status &= cpu_to_le16(RD_ENP|RD_STP);
			goto next_pkt;
		}
		/* Malloc up new buffer, compatible with net-2e. */
		pkt_len = (le16_to_cpu(q->rx[entry].msg_length) &
				 0xfff) - CRC_SZ;

		/* Discard oversize frames. */
		if (unlikely(pkt_len > PKT_BUF_SZ)) {
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: %s wrong packet size %d!\n",
					 nq, __func__, pkt_len);

			q->stats.rx_length_errors++;
			goto next_pkt;
		}
		if (unlikely(pkt_len < 60)) {
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: Runt packet!\n", nq);

			q->stats.rx_length_errors++;
			goto next_pkt;
		}
		pci_dma_sync_single_for_cpu(ep->pci_dev,
					q->rx_dma_skbuff[entry],
					(PKT_BUF_SZ + CRC_SZ),
					PCI_DMA_FROMDEVICE);
		rx_in_place = 0;
		if (pkt_len > rx_copybreak) {
			struct sk_buff *newskb;
			if ((newskb = netdev_alloc_skb(dev,
						PKT_BUF_SZ + CRC_SZ + 2))) {
				skb_reserve(newskb, 2);
				dma_addr_t a = pci_map_single(ep->pci_dev,
							newskb->data,
							(PKT_BUF_SZ + CRC_SZ),
							PCI_DMA_FROMDEVICE);
				if (pci_dma_mapping_error(ep->pci_dev, a)) {
					skb = newskb;
					goto still_copy;
				}
				skb = q->rx_skbuff[entry];
				q->rx_skbuff[entry] = newskb;
				pci_unmap_single(ep->pci_dev,
					q->rx_dma_skbuff[entry],
					(PKT_BUF_SZ + CRC_SZ),
					PCI_DMA_FROMDEVICE);
				skb_put(skb, pkt_len);
				newskb->dev = dev;
				q->rx_dma_skbuff[entry] = a;
				q->rx[entry].base = cpu_to_le32(a);
				rx_in_place = 1;
			} else {
				skb = NULL;
			}
		} else {
			skb = netdev_alloc_skb(dev, pkt_len + 2);
		}
still_copy:
		if (skb == NULL) {
			break;
		}
		if (ep->e_cap & (ETMR_ADD_ENA | ETMR_CLR_ENA) ==
			(ETMR_ADD_ENA | ETMR_CLR_ENA)) {
			u32 et = le32_to_cpu(q->rx[entry].etmr);
			mgb_hwtstamp(ep, skb, et);
			if (netif_msg_1588(ep)) {
				if (maxm_ts[MAX_RTS] < et)
					maxm_ts[MAX_RTS] = et;
				if (maxm_ts[MIN_RTS] >
					(et - maxm_ts[LST_RTS]) &&
					et != maxm_ts[LST_RTS]) {
					maxm_ts[MIN_RTS] =
						et - maxm_ts[LST_RTS];
				}
				maxm_ts[PRV_RTS] =
					maxm_ts[LST_RTS];
				maxm_ts[LST_RTS] = et;
			}
		}
		if (netif_msg_1588(ep)) {
			u32 et = le32_to_cpu(q->rx[entry].etmr);
			if (rx_prev_etmr >= et) {
				dev_warn(&dev->dev,
					 "queue %d: cap=0x%x Rx= 0x%8x "
					 "prv= 0x%8x maxt %8x r %8x c=%16lu\n",
					 nq, ep->e_cap,
					 et, rx_prev_etmr,
					 maxm_ts[MAX_TTS],
					 maxm_ts[MAX_RTS],
					 (unsigned long)get_cycles());
			}
			rx_prev_etmr = et;
		}
		skb->dev = dev;
		if (!rx_in_place) {
			skb_reserve(skb, 2); /* 16 byte align */
			skb_put(skb, pkt_len);	/* Make room */
			skb_copy_to_linear_data(skb,
				(unsigned char *)(q->rx_skbuff[entry]->data),
				pkt_len);
		}
		if (netif_msg_rx_status(ep)) {
			dev_info(&dev->dev,
				 "queue %d: %s recieved pkt len = %d\n",
				 nq, __func__, skb->len);
			mgb_dump_skb_data(ep, nq, skb);
		}
		if (status & (RD_TPCS | RD_UPCS)) {
			skb->ip_summed = CHECKSUM_UNNECESSARY;
			skb->csum_level = 0;
		} else if (status & RD_CSER) {
			q->stats.rx_length_errors++;
		}
		q->stats.rx_bytes += skb->len;
		q->stats.rx_packets++;
		skb->protocol = eth_type_trans(skb, dev);
		netif_receive_skb(skb);
		work_done++;
next_pkt:
		q->rx[entry].buf_length = cpu_to_le16(-(PKT_BUF_SZ + CRC_SZ));
		/* HW card sync */
		wmb();
		BUG_ON(q->rx[entry].base == 0);
		q->rx[entry].status = cpu_to_le16(RD_OWN);

		entry = (++entry) & RX_RING_MOD_MASK;
		if (--boguscnt <= 0) {	/* don't stay in loop forever */
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: %d pkts recieved. "
					 "Recieve deffered\n",
					 nq, RX_RING_SIZE);

			break;
		}
	}
	q->cur_rx = entry;

	return work_done;
}


/** TITLE: MGB interrupt handlers stuff. */

static int mgb_poll(struct napi_struct *napi, int budget)
{
	struct mgb_q *q = container_of(napi, struct mgb_q, napi);
	struct mgb_private *ep = q->ep;
	int nq = mgb_nq(ep, q);
	int work_done = 0;

	if (netif_msg_rx_status(ep))
		dev_info(&ep->dev->dev,
			 "queue %d: %s started\n", nq, __func__);

repeat:
	work_done += mgb_rx(q, budget - work_done);

	if (work_done >= budget) {
		if (netif_msg_rx_status(ep))
			dev_info(&ep->dev->dev,
				 "queue %d: napi will be continued. "
				 "budget = %d, done = %d\n",
				 nq, budget, work_done);

		return work_done;
	}
	/* Set interrupt enable. */
	mgb_write_q_csr(ep, nq, Q_RINT_EN | Q_MISS_EN | Q_RINT);
	if (!(le16_to_cpu(q->rx[q->cur_rx].status) & RD_OWN)) {
		/* we still have pkts to handle */
		mgb_write_q_csr(ep, nq, Q_RINT | Q_C_RINT_EN | Q_C_MISS_EN);
		if (netif_msg_rx_status(ep))
			dev_info(&ep->dev->dev,
				 "queue %d: %s repeated loop. "
				 "budget = %d, done = %d\n",
				 nq, __func__,
				 budget, work_done);

		goto repeat;
	}
	clear_bit(MGB_F_RX + nq, &ep->flags);
	napi_complete(&q->napi);

	if (netif_msg_rx_status(ep))
		dev_info(&ep->dev->dev,
			 "queue %d: napi complete. q_csr = 0x%08x\n",
			 nq, mgb_read_q_csr(ep, nq));

	return work_done;
}

static irqreturn_t mgb_rx_interrupt(int irq, void *dev_id)
{
	struct mgb_q *q = (struct mgb_q *)dev_id;
	struct mgb_private *ep = q->ep;
	struct net_device *dev = ep->dev;
	int nq = mgb_nq(ep, q);
	u16 q_csr;

	q_csr = mgb_read_q_csr(ep, nq);

	if (netif_msg_intr(ep))
		dev_info(&dev->dev,
			 "queue %d: %s: qcsr = 0x%08x\n",
			 nq, __func__, q_csr);

	if (!(q_csr & (Q_RINT | Q_MISS))) {
		if (netif_msg_intr(ep)) {
			dev_warn(&dev->dev,
				 "queue %d: bogus RX interrupt. "
				 "q_csr = 0x%08x\n",
				 nq, q_csr);
		}
		return IRQ_NONE; /* Not our interrupt */
	}
	if (q_csr & Q_MISS) {
		q->stats.rx_errors++; /* Missed a Rx frame. */
		mgb_write_q_csr(ep, nq, Q_MISS);
		if (netif_msg_intr(ep)) {
			dev_info(&dev->dev,
				 "queue %d: Receiver packet missed, "
				 "status %4.4x.\n",
				 nq, q_csr);
		}
	}
	if (q_csr & Q_RINT) {
		mgb_write_q_csr(ep, nq, Q_RINT);
		if (napi_schedule_prep(&q->napi)) {
			if (mgb_set_flag_bit(MGB_F_RX + nq, &ep->flags)) {
				clear_bit(NAPI_STATE_SCHED, &(&q->napi)->state);
				return IRQ_HANDLED;
			}
			mgb_write_q_csr(ep, nq, Q_RINT | Q_MISS |
					Q_C_RINT_EN | Q_C_MISS_EN);
			if (netif_msg_intr(ep))
				dev_info(&dev->dev,
					 "queue %d: napi scheduled\n", nq);

			__napi_schedule(&q->napi);
		}
	}

	return IRQ_HANDLED;
}

static irqreturn_t mgb_tx_interrupt(int irq, void *dev_id)
{
	struct mgb_q *q = (struct mgb_q *)dev_id;
	struct mgb_private *ep = q->ep;
	struct net_device *dev = ep->dev;
	int nq = mgb_nq(ep, q);
	u16 q_csr;

	q_csr = mgb_read_q_csr(ep, nq);

	if (netif_msg_intr(ep))
		dev_info(&dev->dev,
			 "queue %d: %s: qcsr = 0x%08x\n", nq, __func__, q_csr);

	if (!(q_csr & Q_TINT)) {
		if (netif_msg_intr(ep))
			dev_info(&dev->dev,
				 "bogus TX interrupt from queue %d\n", nq);

		return IRQ_NONE;
	}

repeat:
	mgb_write_q_csr(ep, nq, Q_TINT | Q_C_TINT_EN);
	if (mgb_tx(q)) {
		/* reset required */
		mgb_write_e_csr(ep, INEA | SWINT);
		return IRQ_HANDLED;
	}
	mgb_write_q_csr(ep, nq, Q_TINT | Q_TINT_EN);
	if (!(le16_to_cpu(q->tx[q->dirty_tx].status) & TD_OWN) &&
			(q->tx[q->dirty_tx].status != 0)) {
		goto repeat;
	}

	return IRQ_HANDLED;
}

static inline int mgb_get_lstc_intr_enable(int mgio_csr)
{
	if (!(mgio_csr & MG_LSTS0) && (mgio_csr & MG_LSTS1))
		return MG_ECPL;

	return MG_ECRL;
}

static void mgb_set_regs_after_reset(struct mgb_private *ep)
{
	int mgio_csr;
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	mgio_csr = mgb_read_mgio_csr(ep);

	mgb_write_e_cap(ep, ep->e_cap);
	mgb_write_q_csr(ep, 0, Q_TINT_EN | Q_RINT_EN | Q_MISS_EN);
	if (ep->mgb_qs[1]) {
		mgb_write_q_csr(ep, 1, Q_TINT_EN | Q_RINT_EN | Q_MISS_EN);
	}
	mgb_write_mgio_csr(ep, mgio_csr |
		MG_GEPL | MG_FEPL | mgb_get_lstc_intr_enable(mgio_csr));
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);

	/* XXX init mgio_csr - ECST, ? */
	mgb_write_psf_csr(ep, PSF_ESPF | PSF_ESPC | PSF_ESPM);
	mgb_write_psf_data(ep, 0);	/* we does not have plans to
					 * send PAUSE FRAME manualy
					 */
	mgb_write_psf_data1(ep, 64 | (64 << 16));
	mgb_write_irq_delay(ep, ep->irq_delay);
	mgb_write_rx_queue_arb(ep, ep->mgb_qs[1] ?
		(1 << 11) | 5 : /* MACSUM_ADDDEST + hwd_def2 */
		0);
}

static int mgb_wakeup_card(struct mgb_private *ep)
{
	int i = 0;

	mgb_write_e_csr(ep, STOP);
	while (i++ < 1000)
		if (mgb_read_e_csr(ep) & STOP)
			break;

	if (i >= 1000 && mgb_netif_msg_reset(ep)) {
			dev_err(&ep->dev->dev,
				"initialization not completed, "
				"not stopped. e_csr = 0x%x\n",
				mgb_read_e_csr(ep));
		return 1;
	}
	if (mgb_reset_queues(ep)) {
		dev_err(&ep->dev->dev,
			"Could not reinit card after reset. No memory\n");
		return 1;
	}
	mgb_set_dma_and_initblock(ep);

	mgb_set_regs_after_reset(ep);
	i = 0;
	if (ep->e_cap & (ETMR_ADD_ENA | ETMR_CLR_ENA) ==
		(ETMR_ADD_ENA | ETMR_CLR_ENA)) {
		ep->cc.read = mgb_ptp_read;
		ep->cc.mask = CYCLECOUNTER_MASK(32);
		ep->cc.shift = 22;
		/* mult = (1 << shift) / freq */
		ep->cc.mult = (1 << ep->cc.shift) /
				125000000; /* 125 MHz ? TODO */
		timecounter_init(&ep->tc, &ep->cc,
			ktime_to_ns(ktime_get_real()));
	}

	mgb_write_e_csr(ep, STRT);
	while (i++ < 1000) {
		int csr;
		csr = mgb_read_e_csr(ep);
		if (csr & IDON) {
			mgb_write_e_csr(ep, IDON);
			break;
		}
	}
	if (i >= 1000) {
		dev_err(&ep->dev->dev,
			"initialization not completed,"
			" not IDON. e_csr = 0x%x\n",
			mgb_read_e_csr(ep));
		return 1;
	}
	mgb_set_regs_after_reset(ep);
	mgb_write_e_csr(ep, INEA);

	if (mgb_netif_msg_reset(ep))
		dev_info(&ep->dev->dev, "Card started\n");

	return 0;
}

static void mgb_check_link_status(struct mgb_private *ep, u32 mgio_csr)
{
	int speed = 10;
	int up;

	if (netif_msg_link(ep))
		dev_dbg(&ep->dev->dev,
			 "%s: mgio_csr = 0x%08x\n", __func__, mgio_csr);

	if (mgio_csr & MG_GETH) {
		speed = 1000;
	} else if (mgio_csr & MG_FETH) {
		speed = 100;
	}
	if (mgio_csr & MG_LSTS0) {
		if (mgio_csr & MG_LSTS1) {
			up = !!(mgio_csr & MG_RLOS);
		} else {
			up = !!(mgio_csr & MG_SLST);
		}
	} else if (mgio_csr & MG_LSTS1) {
		up = !!(mgio_csr & MG_PLST);
	} else	{
		up = !!(mgio_csr & MG_LSTA);
	}
	if (up) {
		u16 i;
		struct net_device *dev = ep->dev;

		if (netif_msg_link(ep) && !ep->linkup)
			dev_info(&ep->dev->dev,
				 "link up, %dMbps, %s-duplex\n",
				 speed, mgio_csr & MG_FDUP ? "full" : "half");

		ep->linkup = 1;
		for (i = 0; i < dev->num_tx_queues; i++) {
			if (!ep->mgb_qs[i]->full_tx) {
				netif_wake_subqueue(dev, i);
			}
		}
		netif_carrier_on(dev);
	} else {
		if (netif_msg_link(ep))
			dev_info(&ep->dev->dev, "link down\n");

		ep->linkup = 0;
		netif_carrier_off(ep->dev);
		netif_tx_stop_all_queues(ep->dev);
	}
}

static irqreturn_t mgb_restart_card(int irq, void *dev_id)
{
	struct mgb_private *ep = (struct mgb_private *)dev_id;
	struct net_device *dev = ep->dev;
	int i;

	if (mgb_netif_msg_reset(ep))
		dev_info(&dev->dev, "reset started\n");

	netif_tx_lock(dev);
	if (mgb_wait_for_freeze(&ep->flags)) {
		dev_err(&dev->dev,
			"%s: Could not freeze card. f = 0x%0lx\n",
			__func__, ep->flags);
		mgb_write_e_csr(ep, 0);
		netif_tx_unlock(dev);

		return IRQ_HANDLED;
	}
	ep->flags = 0;
	mgb_write_e_csr(ep, STOP);
	/* wait for stop */
	for (i = 0; i < 1000; i++)
		if (mgb_read_e_csr(ep) & STOP)
			break;

	if (i >= 1000 && netif_msg_drv(ep)) {
		dev_err(&dev->dev,
			"%s: timed out waiting for stop.e_csr = 0x%x\n",
			__func__, mgb_read_e_csr(ep));
		mgb_write_e_csr(ep, 0); /* disable INEA */
		netif_tx_unlock(dev);

		return IRQ_HANDLED;
	}
	if (!mgb_wakeup_card(ep) && mgb_netif_msg_reset(ep)) {
		dev_info(&dev->dev, "reset done\n");
	}
	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq;

		txq = netdev_get_tx_queue(dev, i);
		txq->trans_start = jiffies;
		netif_tx_wake_queue(txq);
	}

	netif_tx_unlock(dev);
	mgb_check_link_status(ep, mgb_read_mgio_csr(ep));

	return IRQ_HANDLED;
}

static void mgb_handle_mgio_interrupt(struct mgb_private *ep)
{
	u32 mgio_csr;

	/* irq disabled */
	raw_spin_lock(&ep->mgio_lock);
	mgio_csr = mgb_read_mgio_csr(ep);
	mgb_write_mgio_csr(ep, mgio_csr);
	raw_spin_unlock(&ep->mgio_lock);

	if (netif_msg_intr(ep))
		dev_info(&ep->dev->dev,
			 "%s: mgio_csr = 0x%08x\n", __func__, mgio_csr);

	if (mgio_csr & (MG_CLST | MG_CPLS)) {
		mgb_check_link_status(ep, mgio_csr);
	}
}

static void mgb_handle_pause_frame_interrupt(struct mgb_private *ep)
{
	mgb_read_psf_csr(ep); /* just to clear interrupts */
}

static irqreturn_t mgb_sys_interrupt(int irq, void *dev_id)
{
	struct mgb_private *ep = (struct mgb_private *)dev_id;
	struct net_device *dev = ep->dev;
	u32 csr0;

	csr0 = mgb_read_e_csr(ep);

	if (netif_msg_intr(ep))
		dev_info(&dev->dev,
			 "%s: e_csr = 0x%08x\n", __func__, csr0);

	if (csr0 & (MERR | SWINT)) {
		if (csr0 & MERR) {
			ep->l_stats.merr++;
		}
		if (csr0 & SWINT) {
			ep->l_stats.swint++;
		}
		/* clear INEA and activate reset */
		mgb_write_e_csr(ep, 0);

		return IRQ_WAKE_THREAD;
	}

	/* Log misc errors. */
	mgb_write_e_csr(ep, csr0 & (BABL | CERR | SLVE | INEA));
	if (csr0 & BABL) {
		ep->l_stats.babl++; /* Tx babble. */
		if (mgb_netif_err(ep)) {
			dev_info(&dev->dev,
				 "BABL error, status 0x%08x.\n", csr0);
		}
	}
	if (csr0 & CERR) {
		ep->l_stats.cerr++;
		if (mgb_netif_err(ep)) {
			dev_info(&dev->dev,
				 "CERR error, status %4.4x.\n", csr0);
		}
	}
	if (csr0 & SLVE) {
		ep->l_stats.slve++;
		if (mgb_netif_err(ep)) {
			dev_info(&dev->dev,
				 "SLVE (collisions), status %4.4x.\n", csr0);
		}
	}
	if (csr0 & SINT) {
		mgb_handle_mgio_interrupt(ep);
	}
	if (csr0 & PSFI) {
		mgb_handle_pause_frame_interrupt(ep);
	}

	return IRQ_HANDLED;
}


/** TITLE: NET_DEVICE_OPS stuff */

static struct net_device_stats *mgb_get_stats(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct mgb_q *q;
	struct net_device_stats *s;
	struct net_device_stats *ss = &ep->stats;

	memset(ss, 0, sizeof(*ss));
	q = ep->mgb_qs[0];
	if (q) {
		s = &q->stats;
		memcpy(ss, s, sizeof(*ss));
	}
	q = ep->mgb_qs[1];
	if (q) {
		s = &q->stats;
		ss->rx_packets		+= s->rx_packets;
		ss->tx_packets		+= s->tx_packets;
		ss->rx_bytes		+= s->rx_bytes;
		ss->tx_bytes		+= s->tx_bytes;
		ss->rx_errors		+= s->rx_errors;
		ss->tx_errors		+= s->tx_errors;
		ss->rx_dropped		+= s->rx_dropped;
		ss->tx_dropped		+= s->tx_dropped;
		ss->multicast		+= s->multicast;
		ss->collisions		+= s->collisions;
		ss->rx_length_errors	+= s->rx_length_errors;
		ss->rx_over_errors	+= s->rx_over_errors;
		ss->rx_crc_errors	+= s->rx_crc_errors;
		ss->rx_frame_errors	+= s->rx_frame_errors;
		ss->rx_fifo_errors	+= s->rx_fifo_errors;
		ss->rx_missed_errors	+= s->rx_missed_errors;
		ss->tx_aborted_errors	+= s->tx_aborted_errors;
		ss->tx_carrier_errors	+= s->tx_carrier_errors;
		ss->tx_fifo_errors	+= s->tx_fifo_errors;
		ss->tx_heartbeat_errors	+= s->tx_heartbeat_errors;
		ss->tx_window_errors	+= s->tx_window_errors;
		ss->rx_compressed	+= s->rx_compressed;
		ss->tx_compressed	+= s->tx_compressed;
	}
	return ss;
}

static void mgb_load_multicast(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	init_block_t *ib = ep->init_block;
	struct netdev_hw_addr *ha;
	u32 crc;

	/* allways held laddrf0 and laddrf1 equal */
	if (dev->flags & IFF_ALLMULTI) {
		ib->laddrf0 = 0xffffffffffffffffLL;
		ib->laddrf1 = 0xffffffffffffffffLL;
		return;
	}
	/* clear the multicast filter */
	ib->laddrf0 = 0;

	/* Add addresses */
	netdev_for_each_mc_addr(ha, dev) {
		crc = ether_crc_le(6, ha->addr);
		crc = crc >> 26;
		ib->laddrf0 |= cpu_to_le64(1 << crc);
	}
	ib->laddrf1 = ib->laddrf0;
	return;
}

static void mgb_write_init_block_mode(struct mgb_private *ep)
{
	u8 *p;
	int i;

	p = &ep->init_block->paddr0[0];
	mgb_write_sh_data_h(ep, (p[0] << 24) | (p[1] << 16) |
				(p[2] << 8) | p[3]);
	mgb_write_sh_data_l(ep, (p[4] << 24) | (p[5] << 16) |
				ep->init_block->mode);
	mgb_write_sh_init_cntrl(ep, SH_W_PROM_PADDR0);

	i = 0;
	while (mgb_read_sh_init_cntrl(ep) & SH_W_PROM_PADDR0 &&
		i++ < 100) {
		udelay(1);
	}
	if (i >= 100) {
		dev_err(&ep->dev->dev,
			"%s: bit SH_W_PROM_PADDR0 stuck\n", __func__);
	}
}

static void mgb_set_multicast_list(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int i;

	mutex_lock(&ep->mx);
	if (dev->flags & IFF_PROMISC) {
		if (netif_msg_drv(ep))
			dev_info(&dev->dev, "Promiscuous mode enabled.\n");

		if (ep->init_block->mode & (cpu_to_le16(PROM0) |
					cpu_to_le16(PROM1))) {
			goto unlock;
		}
		ep->init_block->mode |= cpu_to_le16(PROM0) |
					cpu_to_le16(PROM1);
	} else {
		mgb_load_multicast(dev);
		mgb_write_sh_data_h(ep, ep->init_block->laddrf0 >> 32);
		mgb_write_sh_data_l(ep, ep->init_block->laddrf0 & 0xffffffff);
		mgb_write_sh_init_cntrl(ep, SH_W_LADDRF0);
		i = 0;
		while (mgb_read_sh_init_cntrl(ep) & SH_W_LADDRF0 &&
			i++ < 100) {
			udelay(1);
		}
		if (i >= 100) {
			dev_err(&dev->dev,
				"%s: bit SH_W_LADDRF0 stuck\n", __func__);
			goto unlock;
		}
		mgb_write_sh_data_h(ep, ep->init_block->laddrf1 >> 32);
		mgb_write_sh_data_l(ep, ep->init_block->laddrf1 & 0xffffffff);
		mgb_write_sh_init_cntrl(ep, SH_W_LADDRF1);
		i = 0;
		while (mgb_read_sh_init_cntrl(ep) & SH_W_LADDRF1 &&
			i++ < 100) {
			udelay(1);
		}
		if (i >= 100) {
			dev_err(&dev->dev,
				"%s: bit SH_W_LADDRF1 stuck\n", __func__);
		}
		if (ep->init_block->mode & (cpu_to_le16(PROM0) |
					cpu_to_le16(PROM1))) {
			ep->init_block->mode &= ~(cpu_to_le16(PROM0) |
						cpu_to_le16(PROM1));
		} else {
			goto unlock;
		}
	}
	/* change Promiscuous mode */
	mgb_write_init_block_mode(ep);

unlock:
	mutex_unlock(&ep->mx);
}

static int mgb_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	int rc = -EINVAL;
	struct hwtstamp_config config;
	int i;

	switch (cmd) {
	case SIOCDEVPRIVATE + 10:
		mutex_lock(&mgb_mutex);
		mgb_dump_init_block(dev);
		mgb_dump_queues_state(dev);
		mutex_unlock(&mgb_mutex);
		break;
	case SIOCDEVPRIVATE + 11:
		return copy_to_user(rq->ifr_data, maxm_ts,
			sizeof(maxm_ts)) ? -EFAULT : 0;
	case SIOCDEVPRIVATE + 12:
		for (i = 0; i < 8; i++)
			maxm_ts[i] = 0;
		maxm_ts[MIN_TTS] = 0xffffffff;
		maxm_ts[MIN_RTS] = 0xffffffff;
		return 0;
	case SIOCGHWTSTAMP:
		return copy_to_user(rq->ifr_data, &config,
				sizeof(config)) ? -EFAULT : 0;
	case SIOCSHWTSTAMP:
		if ((ep->e_cap & (ETMR_ADD_SUP | ETMR_CLR_SUP)) !=
			(ETMR_ADD_SUP | ETMR_CLR_SUP)) {
			return -EINVAL;
		}
		if (copy_from_user(&config, rq->ifr_data, sizeof(config)))
			return -EFAULT;
		ep->hwtstamp_config = config;
		if (config.rx_filter == HWTSTAMP_FILTER_NONE) {
			ep->e_cap &= ~(ETMR_ADD_ENA | ETMR_CLR_ENA);
		} else {
			ep->e_cap |= (ETMR_ADD_ENA | ETMR_CLR_ENA);
		}
		mgb_write_e_cap(ep, ep->e_cap);
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
		if (mgb_is_eiohub_proto()) {
			rc = -EINVAL;
		} else {
			if (dev->phydev) {
				rc = phy_mii_ioctl(dev->phydev, rq, cmd);
			} else {
				dev_dbg_once(&dev->dev, "phydev not init\n");
				rc = -EINVAL;
			}
		}
	}
	return rc;
}

static void mgb_tx_timeout(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (!ep->linkup)
		return;

	dev_err(&dev->dev,
		"transmit timed out, status 0x%x, resetting.\n",
		mgb_read_e_csr(ep));

	mutex_lock(&mgb_mutex);
	mgb_dump_init_block(dev);
	mgb_dump_queues_state(dev);
	mutex_unlock(&mgb_mutex);

	/* Initiate restart card */
	mgb_write_e_csr(ep, INEA | SWINT);
}

static int mgb_change_mtu(struct net_device *dev, int new_mtu)
{
	if (new_mtu < (ETH_ZLEN - ETH_HLEN) || new_mtu > MGB_MAX_DATA_LEN)
		return -EINVAL;

	dev->mtu = new_mtu;

	return 0;
}

#ifdef CONFIG_NET_POLL_CONTROLLER
static void mgb_poll_controller(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	mgb_tx_interrupt(0, ep->mgb_qs[0]);
	mgb_rx_interrupt(0, ep->mgb_qs[0]);
	if (ep->mgb_qs[1]) {
		mgb_tx_interrupt(0, ep->mgb_qs[1]);
		mgb_rx_interrupt(0, ep->mgb_qs[1]);
	}
}
#endif

static int mgb_set_mac_addr(struct net_device *dev, void *p)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct sockaddr *addr = p;
	u8 *da;
	u32 sh_l, sh_h;
	int i;

	if (netif_running(dev))
		return -EBUSY;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);

	da = (u8 *)dev->dev_addr;
	sh_h = (da[0] << 24) | (da[1] << 16) | (da[2] << 8) | da[3];
	sh_l = (da[4] << 24) | (da[5] << 16) |
		(ep->init_block->mode & PROM0 ? (1 << 14) : 0) |
		(ep->init_block->mode & PROM1 ? (1 << 15) : 0);

	mgb_write_sh_data_h(ep, sh_h);
	mgb_write_sh_data_l(ep, sh_l);
	mgb_write_sh_init_cntrl(ep, SH_W_PROM_PADDR0 | SH_W_PROM_PADDR1);

	i = 0;
	while (mgb_read_sh_init_cntrl(ep) &
			(SH_W_PROM_PADDR0 | SH_W_PROM_PADDR1) && i++ < 100) {
		udelay(1);
	}
	if (i >= 100) {
		dev_err(&dev->dev,
			"%s: bit SH_W_PROM_PADDR0 | SH_W_PROM_PADDR1 stuck\n",
			__func__);
		return -EFAULT;
	}
	if (netif_msg_hw(ep))
		dev_info(&ep->dev->dev,
			"%s: changed MAC addr to"
			" 0x%02x:0x%02x:0x%02x:0x%02x:0x%02x:0x%02x\n",
			__func__, da[0], da[1], da[2], da[3], da[4], da[5]);

	return 0;
}

static const struct net_device_ops mgb_netdev_ops = {
	.ndo_open		= mgb_open,
	.ndo_stop		= mgb_close,
	.ndo_start_xmit		= mgb_start_xmit,
	.ndo_tx_timeout		= mgb_tx_timeout,
	.ndo_set_rx_mode	= mgb_set_multicast_list,
	.ndo_do_ioctl		= mgb_ioctl,
	.ndo_get_stats		= mgb_get_stats,
	.ndo_change_mtu		= mgb_change_mtu,
	.ndo_set_mac_address	= mgb_set_mac_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= mgb_poll_controller,
#endif
};


/** TITLE: ETHERTOOL stuff */

static int mgb_get_link_ksettings(struct net_device *dev,
				  struct ethtool_link_ksettings *cmd)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (!dev->phydev) {
		dev_dbg_once(&dev->dev, "phydev not init\n");
		return -ENODEV;
	}

	phy_ethtool_ksettings_get(dev->phydev, cmd);
	return 0;
}

static int mgb_set_link_ksettings(struct net_device *dev,
				  const struct ethtool_link_ksettings *cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	int r = -EOPNOTSUPP;

	if (!dev->phydev) {
		dev_dbg_once(&dev->dev, "phydev not init\n");
		return -ENODEV;
	}

	r = phy_ethtool_ksettings_set(dev->phydev, cmd);
	if (r == 0)
		mgb_set_mac_phymode(dev);

	return r;
}

static void mgb_get_drvinfo(struct net_device *dev,
			    struct ethtool_drvinfo *info)
{
	struct mgb_private *ep = netdev_priv(dev);

	strcpy(info->driver, KBUILD_MODNAME);
	strcpy(info->version, DRV_VERSION);
	strcpy(info->bus_info, pci_name(ep->pci_dev));
}

static u32 mgb_get_msglevel(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	return ep->msg_enable;
}

static void mgb_set_msglevel(struct net_device *dev, u32 value)
{
	struct mgb_private *ep = netdev_priv(dev);

	ep->msg_enable = value;
}

static int mgb_nway_reset(struct net_device *dev)
{
	return phy_ethtool_nway_reset(dev);
}

static u32 mgb_get_link(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (dev->phydev)
		return dev->phydev->link;
	else
		return ep->linkup;
}

static void mgb_get_ringparam(struct net_device *dev,
			      struct ethtool_ringparam *ering)
{
	struct mgb_private *ep = netdev_priv(dev);

	ering->tx_max_pending = (1 << MGB_MAX_LOG_BUFFERS);
	ering->tx_pending = TX_RING_SIZE;
	ering->rx_max_pending = (1 << MGB_MAX_LOG_BUFFERS);
	ering->rx_pending = RX_RING_SIZE;
}

static int mgb_set_ringparam(struct net_device *dev,
			     struct ethtool_ringparam *ring)
{
	struct mgb_private *ep = netdev_priv(dev);
	u32 tx = ring->tx_pending;
	u32 rx = ring->rx_pending;
	unsigned char log_rx_buffs = 0;
	unsigned char log_tx_buffs = 0;

	if ((ring->rx_mini_pending) || (ring->rx_jumbo_pending)) {
		return -EINVAL;
	}
	if (rx > MGB_MAX_RX_RING_SIZE || rx == 0 || (rx & (rx - 1))) {
		return -EINVAL;
	}
	if (tx > MGB_MAX_TX_RING_SIZE || tx == 0 || (tx & (tx - 1))) {
		return -EINVAL;
	}
	if ((rx == ep->log_rx_buffs) && (tx == TX_RING_SIZE)) {
		return 0;
	}
	while (1) {
		if (rx & 1) {
			break;
		}
		rx = rx >> 1;
		log_rx_buffs++;
	}
	while (1) {
		if (tx & 1) {
			break;
		}
		tx = tx >> 1;
		log_tx_buffs++;
	}
	mutex_lock(&ep->mx);
	if (mgb_opened(ep)) {
		/* card opened */
		mutex_unlock(&ep->mx);
		return -EBUSY;
	}
	mgb_unset_queues(dev);
	ep->log_rx_buffs = log_rx_buffs;
	ep->log_tx_buffs = log_tx_buffs;
	mutex_unlock(&ep->mx);

	return 0;
}

static void mgb_get_strings(struct net_device *dev, u32 stringset, u8 *data)
{
	memcpy(data, mgb_gstrings_test, sizeof(mgb_gstrings_test));
}

#define MGB_NUM_REGS \
	((MGB_TOTAL_SIZE) + (32 * sizeof(u16)) + (32 * sizeof(u16)))
static int mgb_get_regs_len(struct net_device *dev)
{
	return MGB_NUM_REGS;
}

static void mgb_get_regs(struct net_device *dev, struct ethtool_regs *regs,
			 void *ptr)
{
	int i;
	u16 *mii_buff = NULL;
	u32 *buff = ptr;
	struct mgb_private *ep = netdev_priv(dev);

	/* read mgb registers */
	*buff++ = mgb_read_e_csr(ep);
	*buff++ = mgb_read_e_cap(ep);
	*buff++ = mgb_read_q_csr(ep, 0);
	*buff++ = mgb_read_q_csr(ep, 1);
	*buff++ = mgb_read_mgio_csr(ep);
	*buff++ = mgb_read_mgio_data(ep);
	*buff++ = mgb_read_e_base_address(ep);
	*buff++ = mgb_read_dma_base_address(ep);
	*buff++ = mgb_read_psf_csr(ep);
	*buff++ = mgb_read_psf_data(ep);
	*buff++ = mgb_read_irq_delay(ep);
	*buff++ = mgb_read_sh_init_cntrl(ep);
	*buff++ = mgb_read_sh_data_l(ep);
	*buff++ = mgb_read_sh_data_h(ep);
	*buff++ = mgb_read_rx_queue_arb(ep);
	*buff++ = mgb_read_psf_data1(ep);
	mii_buff = (u16 *)buff;

	/* read pcs phy registers */
	for (i = 0; i < 32; i++)
		*mii_buff++ = mgb_pcs_read(ep, i);

	/* read mii phy registers */
	if (ep->extphyaddr == -1)
		return;

	for (i = 0; i < 32; i++)
		*mii_buff++ = mdiobus_read(ep->mii_bus, ep->extphyaddr, i);
}

static int mgb_get_coalesce(struct net_device *dev,
			    struct ethtool_coalesce *ec)
{
	struct mgb_private *ep = netdev_priv(dev);
	u32 irqd = ep->irq_delay;

	memset(ec, 0, sizeof(*ec));
	ec->tx_max_coalesced_frames = mgb_get_irqd_tx_cnt(irqd);
	ec->rx_max_coalesced_frames = mgb_get_irqd_rx_cnt(irqd);
	ec->tx_coalesce_usecs = (2048 * mgb_get_irqd_tx_del(irqd)) /
						ep->mgb_ticks_per_usec;
	ec->rx_coalesce_usecs = (2048 * mgb_get_irqd_rx_del(irqd)) /
						ep->mgb_ticks_per_usec;
	return 0;
}

static int mgb_set_coalesce(struct net_device *dev,
			    struct ethtool_coalesce *ec)
{
	struct mgb_private *ep = netdev_priv(dev);
	u32 tx_max_coalesced_frames = ec->tx_max_coalesced_frames;
	u32 rx_max_coalesced_frames = ec->rx_max_coalesced_frames;
	u32 tx_coalesce_usecs = ec->tx_coalesce_usecs;
	u32 rx_coalesce_usecs = ec->rx_coalesce_usecs;

	tx_coalesce_usecs *= ep->mgb_ticks_per_usec / 2048;
#if 0
	if (tx_coalesce_usecs == 0 &&
		ec->tx_coalesce_usecs != 0) {
		tx_coalesce_usecs = 1;
	}
#endif
	if ((tx_coalesce_usecs > 255) || (tx_coalesce_usecs == 0)) {
		tx_coalesce_usecs = 255;
	}
	rx_coalesce_usecs *= ep->mgb_ticks_per_usec / 2048;
#if 0
	if (rx_coalesce_usecs == 0 &&
		ec->rx_coalesce_usecs != 0) {
		rx_coalesce_usecs = 1;
	}
#endif
	if ((rx_coalesce_usecs > 255) || (rx_coalesce_usecs == 0)) {
		rx_coalesce_usecs = 255;
	}
	if (tx_max_coalesced_frames > min(255, TX_RING_SIZE)) {
		tx_max_coalesced_frames = min(255, TX_RING_SIZE);
	}
	if (rx_max_coalesced_frames > min(255, RX_RING_SIZE)) {
		rx_max_coalesced_frames = min(255, RX_RING_SIZE);
	}
	ep->irq_delay = mgb_set_irq_delay(tx_max_coalesced_frames,
				tx_coalesce_usecs,
				rx_max_coalesced_frames,
				rx_coalesce_usecs);
	mgb_write_irq_delay(ep, ep->irq_delay);

	return 0;
}

static int mgb_get_ts_info(struct net_device *netdev,
			   struct ethtool_ts_info *info)
{
	struct mgb_private *ep = netdev_priv(netdev);

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

static void mgb_get_pauseparam(struct net_device *netdev,
			       struct ethtool_pauseparam *pause)
{
	struct mgb_private *ep = netdev_priv(netdev);
	u32 pf;

	if (!(le16_to_cpu(ep->init_block->mode) & EPSF)) {
		pause->autoneg = 0;
		pause->rx_pause = 0;
		pause->tx_pause = 0;
		return;
	}
	pf = mgb_read_psf_csr(ep);
	pause->autoneg = 0;
	pause->rx_pause = 0;
	pause->tx_pause = !!((pf & (PSF_ESPF | PSF_ESPC | PSF_ESPM)));
}

static int mgb_set_pauseparam(struct net_device *netdev,
			      struct ethtool_pauseparam *pause)
{
	struct mgb_private *ep = netdev_priv(netdev);
	u32 pf;
	u16 mode = le16_to_cpu(ep->init_block->mode);

	if (pause->autoneg == AUTONEG_ENABLE) {
		return -EINVAL;
	}
	if (!pause->rx_pause && pause->tx_pause) {
		return -EINVAL;
	}
	if (!pause->rx_pause && !pause->tx_pause) {
		ep->init_block->mode = cpu_to_le16(mode & ~EPSF);
		mgb_write_init_block_mode(ep);
		return 0;
	}
	pf = mgb_read_psf_csr(ep);
	if (pause->tx_pause) {
		pf |= PSF_ESPF | PSF_ESPC | PSF_ESPM;
	} else {
		pf &= ~(PSF_ESPF | PSF_ESPC | PSF_ESPM);
	}
	mgb_write_psf_csr(ep, pf);
	if (!(mode & EPSF)) {
		ep->init_block->mode = cpu_to_le16(mode | EPSF);
		mgb_write_init_block_mode(ep);
	}
	return 0;
}

static struct ethtool_ops mgb_ethtool_ops = {
	.get_link_ksettings	= mgb_get_link_ksettings,
	.set_link_ksettings	= mgb_set_link_ksettings,
	.get_drvinfo		= mgb_get_drvinfo,
	.get_msglevel		= mgb_get_msglevel,
	.set_msglevel		= mgb_set_msglevel,
	.nway_reset		= mgb_nway_reset,
	.get_link		= mgb_get_link,
	.get_ringparam		= mgb_get_ringparam,
	.set_ringparam		= mgb_set_ringparam,
	.get_strings		= mgb_get_strings,
	.get_regs_len		= mgb_get_regs_len,
	.get_regs		= mgb_get_regs,
	.get_coalesce		= mgb_get_coalesce,
	.set_coalesce		= mgb_set_coalesce,
	.get_ts_info		= mgb_get_ts_info,
	.get_pauseparam		= mgb_get_pauseparam,
	.set_pauseparam		= mgb_set_pauseparam,
};


/** TITLE: DEBUG_FS stuff */

#ifdef CONFIG_DEBUG_FS
/* Usage: mount -t debugfs none /sys/kernel/debug */
/* for debug level: */
/* echo 8 > /proc/sys/kernel/printk */

/* /sys/kernel/debug/mgb/ */
static struct dentry *mgb_dbg_root = NULL;

/* /sys/kernel/debug/mgb/<pcidev>/REG_MGB */

#define DPREG_MGB(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%02X: %08X - %s\n", \
		(R), val = readl(ep->base_ioaddr + (R)), (N)); \
} while (0)

static char mgb_dbg_reg_mgb_buf[PAGE_SIZE] = "";

const u_int32_t mgb_dbg_reg_id_mgb[16] = {
	E_CSR,
	E_CAP,
	E_Q0CSR,
	E_Q1CSR,
	MGIO_CSR,
	MGIO_DATA,
	E_BASE_ADDR,
	DMA_BASE_ADDR,
	PSF_CSR,
	PSF_DATA,
	IRQ_DELAY,
	SH_INIT_CNTRL,
	SH_DATA_L,
	SH_DATA_H,
	RX_QUEUE_ARB,
	PSF_DATA1,
};
const char *mgb_dbg_reg_name_mgb[16] = {
	"Ethernet Control/Status",
	"Ethernet Capabilities",
	"Queue0 Control/Status",
	"Queue1 Control/Status",
	"MGIO Control/Status",
	"MGIO Data",
	"Ethernet Base Address",
	"DMA Base Address",
	"Pause Frame Control/Status",
	"Pause Frame Data",
	"Interrupt Delay",
	"Shadow Init Control",
	"Shadow Data Low",
	"Shadow Data High",
	"RX Queue Arbitration",
	"Pause Frame Data1",
};

static ssize_t mgb_dbg_reg_mgb_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct mgb_private *ep = filp->private_data;
	char *buf = mgb_dbg_reg_mgb_buf;
	u32 val;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - MGB registers dump (hex) =\n",
			  ep->dev->name, pci_name(ep->pci_dev));

	for (i = 0; i < ARRAY_SIZE(mgb_dbg_reg_id_mgb); i++) {
		DPREG_MGB(mgb_dbg_reg_id_mgb[i],
			  mgb_dbg_reg_name_mgb[i]);
		if (mgb_dbg_reg_id_mgb[i] == E_CSR) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "    %sINIT %sSTRT %sSTOP %sIDON\n",
					  (val & INIT) ? "+" : "-",
					  (val & STRT) ? "+" : "-",
					  (val & STOP) ? "+" : "-",
					  (val & IDON) ? "+" : "-");
		}
		if (mgb_dbg_reg_id_mgb[i] == MGIO_CSR) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "    %sLSTA %sHARD %sGETH %sFETH"
					  " %sFDUP %sLSTS0 %sSLST %sLSTS1"
					  " %sRLOS %sTFLT %sPLST\n",
					  (val & MG_LSTA)  ? "+" : "-",
					  (val & MG_HARD)  ? "+" : "-",
					  (val & MG_GETH)  ? "+" : "-",
					  (val & MG_FETH)  ? "+" : "-",
					  (val & MG_FDUP)  ? "+" : "-",
					  (val & MG_LSTS0) ? "+" : "-",
					  (val & MG_SLST)  ? "+" : "-",
					  (val & MG_LSTS1) ? "+" : "-",
					  (val & MG_RLOS)  ? "+" : "-",
					  (val & MG_TFLT)  ? "+" : "-",
					  (val & MG_PLST)  ? "+" : "-");
		}
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mgb_dbg_reg_mgb_read */

static const struct file_operations mgb_dbg_reg_mgb_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mgb_dbg_reg_mgb_read,
};

/* /sys/kernel/debug/mgb/<pcidev>/REG_PHY */

#define DPREG_PHY(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%04X: %04X - %s\n", \
		(R), mdiobus_read(ep->mii_bus, ep->extphyaddr, (R)), (N)); \
} while (0)

static char mgb_dbg_reg_phy_buf[PAGE_SIZE] = "";

const u_int32_t mgb_dbg_reg_id_phy[23] = {
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
const char *mgb_dbg_reg_name_phy[23] = {
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

static ssize_t mgb_dbg_reg_phy_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct mgb_private *ep = filp->private_data;
	char *buf = mgb_dbg_reg_phy_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - PHY_IEEE registers dump (hex) =\n",
			  ep->dev->name, pci_name(ep->pci_dev));

	for (i = 0; i < ARRAY_SIZE(mgb_dbg_reg_id_phy); i++) {
		DPREG_PHY(mgb_dbg_reg_id_phy[i],
			  mgb_dbg_reg_name_phy[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mgb_dbg_reg_phy_read */

static const struct file_operations mgb_dbg_reg_phy_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mgb_dbg_reg_phy_read,
};

/* /sys/kernel/debug/mgb/<pcidev>/REG_PCS */

#define DPREG_PCS(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%06X: %04X - %s\n", \
		(R), mgb_pcs_read(ep, (R)), (N)); \
} while (0)

static char mgb_dbg_reg_pcs_buf[PAGE_SIZE] = "";

const u_int32_t mgb_dbg_reg_id_pcs[47] = {
	SR_XS_PCS_CTRL1,
	SR_XS_PCS_DEV_ID1,
	SR_XS_PCS_DEV_ID2,
	SR_XS_PCS_CTRL2,
	VR_XS_PCS_DIG_CTRL1,
	SR_MII_CTRL,
	VR_MII_AN_CTRL,
	SR_MII_AN_ADV,
	VR_MII_DIG_CTRL1,
	VR_MII_AN_INTR_STS,
	VR_MII_LINK_TIMER_CTRL,
	SR_VSMMD_CTRL,
	VR_AN_INTR,
	SR_AN_CTRL,
	SR_AN_LP_ABL1,
	SR_AN_LP_ABL2,
	SR_AN_LP_ABL3,
	SR_AN_XNP_TX1,
	SR_AN_XNP_TX2,
	SR_AN_XNP_TX3,
	VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL,
	VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0,
	VR_XS_PMA_Gen5_12G_MPLLA_CTRL1,
	VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2,
	VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0,
	VR_XS_PMA_Gen5_12G_MPLLB_CTRL1,
	VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2,
	VR_XS_PMA_Gen5_12G_MPLLA_CTRL3,
	VR_XS_PMA_Gen5_12G_MPLLB_CTRL3,
	VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1,
	VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2,
	VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL,
	VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL,
	VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0,
	VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1,
	VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2,
	VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3,
	VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL,
	VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL,
	VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL,
	VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0,
	VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4,
	VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL,
	VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0,
	VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL,
	VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0,
	VR_XS_PMA_Gen5_12G_VCO_CAL_REF0,
};
const char *mgb_dbg_reg_name_pcs[47] = {
	"SR_XS_PCS_CTRL1",
	"SR_XS_PCS_DEV_ID1",
	"SR_XS_PCS_DEV_ID2",
	"SR_XS_PCS_CTRL2",
	"VR_XS_PCS_DIG_CTRL1",
	"SR_MII_CTRL",
	"VR_MII_AN_CTRL",
	"SR_MII_AN_ADV",
	"VR_MII_DIG_CTRL1",
	"VR_MII_AN_INTR_STS",
	"VR_MII_LINK_TIMER_CTRL",
	"SR_VSMMD_CTRL",
	"VR_AN_INTR",
	"SR_AN_CTRL",
	"SR_AN_LP_ABL1",
	"SR_AN_LP_ABL2",
	"SR_AN_LP_ABL3",
	"SR_AN_XNP_TX1",
	"SR_AN_XNP_TX2",
	"SR_AN_XNP_TX3",
	"VR_XS_PMA_Gen5_12G_16G_MPLL_CMN_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL0",
	"VR_XS_PMA_Gen5_12G_MPLLA_CTRL1",
	"VR_XS_PMA_Gen5_12G_16G_MPLLA_CTRL2",
	"VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL0",
	"VR_XS_PMA_Gen5_12G_MPLLB_CTRL1",
	"VR_XS_PMA_Gen5_12G_16G_MPLLB_CTRL2",
	"VR_XS_PMA_Gen5_12G_MPLLA_CTRL3",
	"VR_XS_PMA_Gen5_12G_MPLLB_CTRL3",
	"VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL1",
	"VR_XS_PMA_Gen5_12G_16G_TX_GENCTRL2",
	"VR_XS_PMA_Gen5_12G_16G_TX_BOOST_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_TX_RATE_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL0",
	"VR_XS_PMA_Gen5_12G_16G_TX_EQ_CTRL1",
	"VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL2",
	"VR_XS_PMA_Gen5_12G_16G_RX_GENCTRL3",
	"VR_XS_PMA_Gen5_12G_16G_RX_RATE_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_RX_CDR_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_RX_ATTN_CTRL",
	"VR_XS_PMA_Gen5_12G_RX_EQ_CTRL0",
	"VR_XS_PMA_Gen5_12G_16G_RX_EQ_CTRL4",
	"VR_XS_PMA_Gen5_12G_AFE_DFE_EN_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_MISC_CTRL0",
	"VR_XS_PMA_Gen5_12G_16G_REF_CLK_CTRL",
	"VR_XS_PMA_Gen5_12G_16G_VCO_CAL_LD0",
	"VR_XS_PMA_Gen5_12G_VCO_CAL_REF0",
};

static ssize_t mgb_dbg_reg_pcs_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct mgb_private *ep = filp->private_data;
	char *buf = mgb_dbg_reg_pcs_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - PCS registers dump (hex) =\n",
			  ep->dev->name, pci_name(ep->pci_dev));

	for (i = 0; i < ARRAY_SIZE(mgb_dbg_reg_id_pcs); i++) {
		DPREG_PCS(mgb_dbg_reg_id_pcs[i],
			  mgb_dbg_reg_name_pcs[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mgb_dbg_reg_pcs_read */

static const struct file_operations mgb_dbg_reg_pcs_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mgb_dbg_reg_pcs_read,
};

/* /sys/kernel/debug/mgb/<pcidev>/reg_ops */
static char mgb_dbg_reg_ops_buf[256] = "";

static ssize_t mgb_dbg_reg_ops_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	struct mgb_private *ep = filp->private_data;
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

static ssize_t mgb_dbg_reg_ops_write(struct file *filp,
				     const char __user *buffer,
				     size_t count, loff_t *ppos)
{
	struct mgb_private *ep = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(mgb_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(mgb_dbg_reg_ops_buf,
				     sizeof(mgb_dbg_reg_ops_buf)-1,
				     ppos,
				     buffer,
				     count);
	if (len < 0)
		return len;

	mgb_dbg_reg_ops_buf[len] = '\0';

	if (strncmp(mgb_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mgb_dbg_reg_ops_buf[5], "%x %x", &reg, &value);
		if (cnt == 2) {
			ep->reg_last_value = value;
			if (ep->base_ioaddr)
				writel(value, ep->base_ioaddr + (reg << 2));
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops usage: write <reg> <val>\n");
		}
	} else if (strncmp(mgb_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mgb_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			value = (u32)-1;
			if (ep->base_ioaddr)
				value = readl(ep->base_ioaddr + (reg << 2));
			ep->reg_last_value = value;
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops usage: read <reg>\n");
		}
	} else if (strncmp(mgb_dbg_reg_ops_buf, "writephy ", 9) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mgb_dbg_reg_ops_buf[8], "%x %x", &reg, &value);
		if (ep->extphyaddr == -1) {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "Error on writephy: no external PHY\n");
		} else if (cnt == 2) {
			ep->reg_last_value = value;
			mdiobus_write(ep->mii_bus, ep->extphyaddr, reg, value);
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops usage:"
				 " writephy <reg> <val>\n");
		}
	} else if (strncmp(mgb_dbg_reg_ops_buf, "readphy ", 8) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mgb_dbg_reg_ops_buf[7], "%x", &reg);
		if (ep->extphyaddr == -1) {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "Error on readphy: no external PHY\n");
		} else if (cnt == 1) {
			value = (u32)mdiobus_read(ep->mii_bus, ep->extphyaddr,
						  reg);
			ep->reg_last_value = value;
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops usage: readphy <reg>\n");
		}
	} else if (strncmp(mgb_dbg_reg_ops_buf, "writepcs ", 9) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mgb_dbg_reg_ops_buf[8], "%x %x", &reg, &value);
		if (cnt == 2) {
			ep->reg_last_value = value;
			mgb_pcs_write(ep, reg, value);
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops usage:"
				 " writepcs <reg> <val>\n");
		}
	} else if (strncmp(mgb_dbg_reg_ops_buf, "readpcs ", 8) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mgb_dbg_reg_ops_buf[7], "%x", &reg);
		if (cnt == 1) {
			value = (u32)mgb_pcs_read(ep, reg);
			ep->reg_last_value = value;
		} else {
			ep->reg_last_value = 0xFFFFFFFF;
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops usage: readpcs <reg>\n");
		}
	} else {
		ep->reg_last_value = 0xFFFFFFFF;
		dev_warn(&ep->pci_dev->dev,
			 "debugfs reg_ops: Unknown command %s\n",
			 mgb_dbg_reg_ops_buf);
		pr_cont("    Available commands:\n");
		pr_cont("      read <reg>\n");
		pr_cont("      write <reg> <val>\n");
		pr_cont("      readphy <reg>\n");
		pr_cont("      writephy <reg> <val>\n");
		pr_cont("      readpcs <reg>\n");
		pr_cont("      writepcs <reg> <val>\n");
	}

	return count;
}

static const struct file_operations mgb_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mgb_dbg_reg_ops_read,
	.write = mgb_dbg_reg_ops_write,
};

static void mgb_dbg_board_init(struct mgb_private *ep)
{
	const char *name = pci_name(ep->pci_dev);
	struct dentry *pfile;

	ep->mgb_dbg_board = debugfs_create_dir(name, mgb_dbg_root);
	if (ep->mgb_dbg_board) {
		/* ./reg_ops */
		pfile = debugfs_create_file("reg_ops", 0600,
					    ep->mgb_dbg_board, ep,
					    &mgb_dbg_reg_ops_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_ops for %s failed\n", name);
		}
		/* MGB */
		pfile = debugfs_create_file("REG_MGB", 0400,
					    ep->mgb_dbg_board, ep,
					    &mgb_dbg_reg_mgb_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_mgb for %s failed\n", name);
		}
		/* PHY */
		pfile = debugfs_create_file("REG_PHY", 0400,
					    ep->mgb_dbg_board, ep,
					    &mgb_dbg_reg_phy_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_phy for %s failed\n", name);
		}
		/* PCS */
		pfile = debugfs_create_file("REG_PCS", 0400,
					    ep->mgb_dbg_board, ep,
					    &mgb_dbg_reg_pcs_fops);
		if (!pfile) {
			dev_warn(&ep->pci_dev->dev,
				 "debugfs reg_pcs for %s failed\n", name);
		}
	} else {
		dev_warn(&ep->pci_dev->dev,
			 "debugfs entry for %s failed\n", name);
	}
}

static void mgb_dbg_board_exit(struct mgb_private *ep)
{
	if (!ep)
		return;

	if (ep->mgb_dbg_board)
		debugfs_remove_recursive(ep->mgb_dbg_board);
	ep->mgb_dbg_board = NULL;
}

#endif /*CONFIG_DEBUG_FS*/


/** TITLE: PROBE stuff */

static int mgb_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
{
	int err = 0;
	resource_size_t ioaddr;
	unsigned char *base_ioaddr;
	struct resource *res;
	struct mgb_private *ep = NULL;
	struct net_device *dev = NULL;
	struct device_node *np = dev_of_node(&pdev->dev);
	const char *of_status_prop = NULL;
	const char *of_phymode_prop = NULL;

	/* check cmdline param */
	if (mgb_status == 0) {
		dev_warn(&pdev->dev, "device disabled in cmdline\n");
		return -ENODEV;
	} else if (mgb_status > 1) {
		/* check devtree config */
		if (np) {
			of_status_prop = of_get_property(np, "status", NULL);
			if (!strcmp(of_status_prop, "disabled")) {
				dev_warn(&pdev->dev,
					"device disabled in devicetree\n");
				return -ENODEV;
			}
		} else {
			dev_warn(&pdev->dev,
				 "devicetree for node not found!\n");
		}
	}

	dev_info(&pdev->dev, "initializing PCI device %04x:%04x\n",
		 pdev->vendor, pdev->device);

#if 0	/* Now Stepan inits it correctly */
	/* XXX just to debug on prototipe */
	pdev->irq = PCI_FUNC(pdev->devfn) ?
		ioepic_pin_to_irq(23, pdev) :
		ioepic_pin_to_irq(3, pdev);
	dev_info(&pdev->dev, "base irq = %d\n", pdev->irq);
#endif
	err = pci_enable_device(pdev);
	if (err < 0) {
		dev_err(&pdev->dev, "failed to enable device -- err=%d\n", err);
		return err;
	}
	pci_set_master(pdev);

	ioaddr = pci_resource_start(pdev, 0);
	if (!ioaddr) {
		dev_err(&pdev->dev, "card has no PCI resource0\n");
		err = -ENODEV;
		goto err1;
	}

	if (!pci_dma_supported(pdev, MGB_DMA_MASK)) {
		dev_err(&pdev->dev,
			"architecture does not support"
			" 32bit PCI busmaster DMA\n");
		err = -ENODEV;
		goto err1;
	}

	res = request_mem_region(ioaddr, MGB_TOTAL_SIZE, KBUILD_MODNAME);
	if (res == NULL) {
		dev_err(&pdev->dev, "memio address range already allocated\n");
		dev_err(&pdev->dev,
			"mem_region: 0x%llx + 0x%llx, "
			"we use len = 0x%x\n", ioaddr,
			pci_resource_len(pdev, 0), MGB_TOTAL_SIZE);
		err = -EBUSY;
		goto err1;
	}

	base_ioaddr = ioremap(ioaddr, MGB_TOTAL_SIZE);
	if (base_ioaddr == NULL) {
		dev_err(&pdev->dev,
			"unable to map base ioaddr = 0x%llx\n", ioaddr);
		err = -ENOMEM;
		goto err_release_reg;
	}

	if (num_online_cpus() == 1) {
		dev = alloc_etherdev(sizeof(struct mgb_private));
	} else {
		dev = alloc_etherdev_mqs(sizeof(struct mgb_private), 2, 2);
	}
	if (!dev) {
		dev_err(&pdev->dev, "memory allocation failed.\n");
		err = -ENOMEM;
		goto err_iounmap;
	}
	dev->base_addr = ioaddr;
	dev->irq = pdev->irq;
	SET_NETDEV_DEV(dev, &pdev->dev);
	pci_set_drvdata(pdev, dev);

	ep = netdev_priv(dev);
	ep->pci_dev = pdev;
	ep->base_ioaddr = base_ioaddr;
	ep->dev = dev;
	ep->resource = res;
	ep->flags = 0;
	ep->msg_enable = mgb_debug;

	if (mpll_mode != -1)
		ep->mpll_mode = mpll_mode;

	ep->mgb_ticks_per_usec = mgb_is_eiohub_proto() ? 125 : 480;

	raw_spin_lock_init(&ep->mgio_lock);
	mutex_init(&ep->mx);

	l_set_ethernet_macaddr(pdev, dev->dev_addr);
	dev_info(&pdev->dev, "MAC = %012llX\n",
		 be64_to_cpu(*(u64 *)(dev->dev_addr) << 16));

	mgb_write_e_csr(ep, STOP); /* Stop card */
	/* Check for a valid station address */
	if (!is_valid_ether_addr(dev->dev_addr)) {
		dev_err(&pdev->dev, "card MAC address invalid\n");
		err = -EINVAL;
		goto err_iounmap;
	}

	ep->log_rx_buffs = MGB_LOG_RX_BUFFERS;
	ep->log_tx_buffs = MGB_LOG_TX_BUFFERS;

	ep->ptp_clock_info = mgb_ptp_clock_info;
#if 0	/* TODO check PPS is supplied to MPV */
	ep->ptp_clock = ptp_clock_register(&ep->ptp_clock_info,
					&(pdev->dev));
	ep->ptp_clock_info.max_adj = 1000000000;
#else
	pr_err("failed to register MPV pps source\n");
	ep->ptp_clock = ERR_PTR(-EINVAL);
#endif
	if (IS_ERR(ep->ptp_clock)) {
		ep->ptp_clock = NULL;
		dev_warn(&pdev->dev, "ptp_clock_register failed\n");
	} else if (netif_msg_probe(ep)) {
		dev_info(&pdev->dev, "registered PHC clock\n");
	}

	/* Setup init block */
	ep->init_block = dma_alloc_coherent(&pdev->dev,
		sizeof(*ep->init_block), &ep->initb_dma, GFP_KERNEL);
	if (!ep->init_block) {
		dev_err(&pdev->dev,
			"init block memory allocation failed.\n");
		err = -ENOMEM;
		goto err_free_netdev;
	}
	if ((long)ep->init_block & 0x3f) {
		/* must be alligned */
		dev_err(&pdev->dev,
			"allocated init block is not alligned. Fix driver\n");
		err = -ENOMEM;
		goto free_init_block;
	}
	err = mgb_alloc_queue(ep, 0);
	if (err) {
		dev_err(&pdev->dev, "queue allocation failed.\n");
		goto free_init_block;
	}
	if (dev->num_tx_queues == 2) {
		err = mgb_alloc_queue(ep, 1);
		if (err) {
			dev_err(&pdev->dev, "queue allocation failed.\n");
			goto err_free_qs;
		}
	}

	/* MGB specific entries in the device structure. */
	dev->ethtool_ops = &mgb_ethtool_ops;
	dev->netdev_ops = &mgb_netdev_ops;
	dev->watchdog_timeo = (5*HZ);

	netif_napi_add(dev, &ep->mgb_qs[0]->napi,
		mgb_poll, MGB_NAPI_WEIGHT);
	if (ep->mgb_qs[1])
		netif_napi_add(dev, &ep->mgb_qs[1]->napi,
			mgb_poll, MGB_NAPI_WEIGHT);

	/* check devtree config */
	if (np) {
		if (of_get_property(np, "sfp", NULL)) {
			ep->extphyaddr = -1;
			dev_info(&pdev->dev,
				 "disable external PHY, use SFP+\n");
		} else {
			if (!of_property_read_string(np, "phy-mode",
						&of_phymode_prop)) {
				dev_info(&pdev->dev,
					"phy-mode - %s\n", of_phymode_prop);
			}
		}
	}

	/* PHY register mdio bus */
	err = mgb_mdio_register(ep);
	if (err) {
		dev_err(&pdev->dev, "register mdio failed.\n");
		err = -ENODEV;
		goto err_free_qs;
	}

	if (register_netdev(dev)) {
		dev_err(&pdev->dev, "register netdev failed.\n");
		err = -ENODEV;
		goto err_mdio_unregister;
	}

	if (mgb_set_pcsphy_mode(dev)) {
		dev_err(&pdev->dev, "could not set PHY\n");
		err = -EIO;
		goto err_free_all;
	}

#ifdef CONFIG_DEBUG_FS
	mgb_dbg_board_init(ep);
#endif /*CONFIG_DEBUG_FS*/

	dev_info(&pdev->dev, "network interface %s init done\n",
		 dev_name(&dev->dev));
	return 0;

err_free_all:
	unregister_netdev(dev);
err_mdio_unregister:
	if (ep->mii_bus)
		mdiobus_unregister(ep->mii_bus);
err_free_qs:
	if (ep->mgb_qs[0])
		mgb_free_queue(ep, 0);
	if (ep->mgb_qs[1])
		mgb_free_queue(ep, 1);
free_init_block:
	dma_free_coherent(&pdev->dev,
		sizeof(*ep->init_block),
		ep->init_block,
		ep->initb_dma);
err_free_netdev:
	if (ep->ptp_clock) {
		ptp_clock_unregister(ep->ptp_clock);
		ep->ptp_clock = NULL;
	}
	free_netdev(dev);
err_iounmap:
	iounmap(base_ioaddr);
err_release_reg:
	release_mem_region(ioaddr, MGB_TOTAL_SIZE);
err1:
	dev_err(&pdev->dev, "could not enable PCI device, aborting\n");
	dev_set_drvdata(&pdev->dev, NULL);
	pci_disable_device(pdev);
	return err;
}

static void mgb_remove(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct mgb_private *ep = netdev_priv(dev);

#ifdef CONFIG_DEBUG_FS
	mgb_dbg_board_exit(ep);
#endif /*CONFIG_DEBUG_FS*/

	unregister_netdev(dev);

	if (ep->mii_bus)
		mdiobus_unregister(ep->mii_bus);

	if (ep->mgb_qs[0])
		mgb_free_queue(ep, 0);
	if (ep->mgb_qs[1])
		mgb_free_queue(ep, 1);

	dma_free_coherent(&pdev->dev,
		sizeof(*ep->init_block),
		ep->init_block,
		ep->initb_dma);

	if (ep->ptp_clock) {
		ptp_clock_unregister(ep->ptp_clock);
		ep->ptp_clock = NULL;
	}
	free_netdev(dev);

	iounmap(ep->base_ioaddr);

	release_mem_region(dev->base_addr, MGB_TOTAL_SIZE);

	dev_set_drvdata(&pdev->dev, NULL);
	pci_disable_device(pdev);
}

#ifdef CONFIG_PM
static void mgb_shutdown(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct mgb_private *ep = netdev_priv(dev);
	int i;

	if (!netif_running(dev)) {
		return;
	}
	napi_disable(&ep->mgb_qs[0]->napi);
	if (ep->mgb_qs[1]) {
		napi_disable(&ep->mgb_qs[1]->napi);
	}
	mgb_write_e_csr(ep, STOP);
	/* wait for stop */
	for (i = 0; i < 1000; i++)
		if (mgb_read_e_csr(ep) & STOP)
			break;

	if (i >= 100 && netif_msg_drv(ep))
		dev_err(&pdev->dev, "timed out waiting for stop.\n");

	netif_carrier_off(dev);

	pci_save_state(pdev);
	pci_clear_master(pdev);
}

static int mgb_suspend(struct pci_dev *pdev, pm_message_t state)
{
	mgb_shutdown(pdev);
	return 0;
}

static int mgb_resume(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct mgb_private *ep = netdev_priv(dev);

	if (!netif_running(dev)) {
		return 0;
	}
	/* Card must be stopped */
	if (mgb_wakeup_card(ep)) {
		dev_err(&pdev->dev, "Could not wake up MGB card\n");
		return 1;
	}
	napi_enable(&ep->mgb_qs[0]->napi);
	if (ep->mgb_qs[1]) {
		napi_enable(&ep->mgb_qs[1]->napi);
	}
	netif_carrier_on(dev);
	return 0;
}
#endif	/*CONFIG_PM*/

const struct pci_device_id mgb_pci_tbl[] = {
	{
		.vendor = PCI_VENDOR_ID_MCST_TMP,
		.device = PCI_DEVICE_ID_MCST_MGB,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{0, }
};

MODULE_DEVICE_TABLE(pci, mgb_pci_tbl);

static struct pci_driver mgb_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= mgb_pci_tbl,
	.probe		= mgb_probe,
	.remove		= mgb_remove,
#ifdef CONFIG_PM
	.shutdown	= mgb_shutdown,
	.resume		= mgb_resume,
	.suspend	= mgb_suspend,
#endif
};

static void __exit mgb_cleanup_module(void)
{
	pci_unregister_driver(&mgb_driver);

#ifdef CONFIG_DEBUG_FS
	if (mgb_dbg_root)
		debugfs_remove_recursive(mgb_dbg_root);
#endif /*CONFIG_DEBUG_FS*/
}

static int __init mgb_init_module(void)
{
	int status;

	pr_info(KBUILD_MODNAME ": %s", version);

	mgb_debug = netif_msg_init(debug,
		NETIF_MSG_DRV |			/* netif_msg_drv */
		NETIF_MSG_PROBE |		/* netif_msg_probe */
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
	mgb_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (mgb_dbg_root == NULL)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
#endif /*CONFIG_DEBUG_FS*/

	status = pci_register_driver(&mgb_driver);
	if (status != 0) {
		pr_err(KBUILD_MODNAME ": Could not register driver\n");
#ifdef CONFIG_DEBUG_FS
		if (mgb_dbg_root)
			debugfs_remove_recursive(mgb_dbg_root);
#endif /*CONFIG_DEBUG_FS*/
	}

	return status;
}

module_init(mgb_init_module);
module_exit(mgb_cleanup_module);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Vadim A. Revyakin");
MODULE_DESCRIPTION("mgb ethernet card of e2k family CPUs driver");
MODULE_SUPPORTED_DEVICE("MGB, DeviceID:" PCI_DEVICE_ID_MCST_MGB
			", VendorID:" PCI_VENDOR_ID_MCST_TMP);
MODULE_VERSION(DRV_VERSION);
