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
#include <net/ip.h>
#include <linux/pci_ids.h>
#include <linux/net_tstamp.h>		/* for IEEE 1588 */
#include <linux/ptp_clock_kernel.h>	/* for IEEE 1588 */
#include <linux/timex.h>		/* for IEEE 1588 */
#include <linux/clocksource.h>
#include <linux/phy.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_mdio.h>
#include <linux/of_net.h>
#include <linux/bpf.h>
#include <linux/bpf_trace.h>
#include <net/xdp.h>
#include <net/page_pool.h>
#include <linux/mcst_net_rt.h>

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
#include <asm/pci.h>
#ifdef CONFIG_E2K
#include <asm/sclkr.h>
#else
#include <asm-l/clk_rt.h>
#endif

/* only for printk */
#include <linux/marvell_phy.h>

#define DRV_VERSION	"1.0"

/* TI DP83867 phy identifier values (not in .h) */
#define DP83867_PHY_ID		0x2000a231

/* Realtek RTL8211F phy identifier values (not in .h) */
#define RTL8211F_PHY_ID		0x001CC916


/* #define DBG_PTP */

static int assigned_speed = SPEED_1000;
module_param_named(rate, assigned_speed, int, 0444);
MODULE_PARM_DESC(rate, "used to set rate to 2500");


static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, KBUILD_MODNAME " debug level");

#define MGB_MAX_NETDEV_NUMBER	(MAX_NUMNODES * 2)

static int an_clause_73[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 0};
module_param_array(an_clause_73, int, NULL, 0444);
MODULE_PARM_DESC(an_clause_73,
		 KBUILD_MODNAME " Array: apply clause 73 auto-negotiation to internal PHY");

static int an_sgmii[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 0};
module_param_array(an_sgmii, int, NULL, 0444);
MODULE_PARM_DESC(an_sgmii,
	 KBUILD_MODNAME  " Array: apply sgmii mode to clause 37 auto-negotiation for internal PHY");

static int an_monitor = 1;
module_param(an_monitor, int, 0444);
MODULE_PARM_DESC(an_monitor,
		 KBUILD_MODNAME  " monitor auto-negotiation activity");

static int mgb_status[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 2};
module_param_array(mgb_status, int, NULL, 0444);
MODULE_PARM_DESC(mgb_status, " Array: 0 - disable, 1 - enable, other - use devtree");

static int mgb_phy_mode[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 2};
module_param_array(mgb_phy_mode, int, NULL, 0444);
MODULE_PARM_DESC(mgb_phy_mode, " Array: 0 - SFP+, 1 - RJ45, other - use devtree");

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

/* eldwcxpcs.ko */
int eldwcxpcs_get_mpll_mode(struct pci_dev *pdev);
/* PCS MPLL MODE */
#define MPLL_MODE_10G		0
#define MPLL_MODE_1G		1
#define MPLL_MODE_2G5		2
#define MPLL_MODE_1G_BIF	3

#define MGB_FREQ	480000000


/* Each packet consists of header 14 bytes(ETH_HLEN) +
 * [46 min - 1500 max] data + 4 bytes * crc(ETH_FCS_LEN). mgb adds
 * crc automatically when sending a packet so you havn't to take
 * care about it allocating memory for the packet being sent. As to received
 * packets mgb doesn't hew crc off so you'll have to alloc an extra 4 bytes of
 * memory in addition to common packet size
 */

#define MGB_MAX_DATA_LEN	ETH_DATA_LEN

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


#define MGB_RT_XFER_BUF_SZ	(((ETH_FRAME_LEN + 0xf) >> 4) << 4)

/* MGB Rx and Tx ring descriptors. */

struct mgb_rx_head {
	u32	base;		/* RBADR [31:0] */
	s16	buf_length;	/* BCNT only [13:0] */
	s16	status;
	s16	msg_length;	/* MCNT only [13:0] */
	u16	reserved1;
	u32	etmr;		/* timer count for ieee 1588 */
} __packed;


struct mgb_tx_head {
	u32	base;		/* TBADR [31:0] */
	s16	buf_length;	/* BCNT only [13:0] */
	u16	status;
	u32	misc;		/* [31:26] + [3:0] tramsmit retry count */
	u32	etmr;		/* timer count for ieee 1588 */
} __packed;

typedef struct {
	struct mgb_rx_head	rx_ring __aligned(16);
	struct mgb_tx_head	tx_ring __aligned(16);
	char			rx_buf[MGB_RT_XFER_BUF_SZ] __aligned(16);
	char			tx_buf[MGB_RT_XFER_BUF_SZ] __aligned(16);
} mgb_rt_dma_data_t;



struct mgb_private;

struct mgb_rx_stats {
	u64			packets;
	u64			bytes;
	u64			errors;
	u64			dropped;
	u64			multicast;
	u64			length_errors;
	u64			over_errors;
	u64			crc_errors;
	u64			frame_errors;
	u64			fifo_errors;
	u64			missed_errors;
};

struct mgb_tx_stats {
	u64			packets;
	u64			bytes;
	u64			errors;
	u64			dropped;
	u64			collisions;
	u64			aborted_errors;
	u64			carrier_errors;
	u64			fifo_errors;
	u64			heartbeat_errors;
	u64			window_errors;
	u64			compressed;
};

typedef struct {
	unsigned long swint;
	unsigned long merr;
	unsigned long babl;
	unsigned long cerr;
	unsigned long slve;
} mgb_stats_t;


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

#define mgb_default_mode	(PROM0)
#define enable_sent_pause_flags (PSF_ESPF | PSF_ESPC | PSF_ESPM)
/* TX Pause Frame control is disabled by default, as it may affect
 * network performance. Use ethtool -A to enable the feature.
 */
#define default_psf_csr (0)



struct mgb_private {
	init_block_t		*init_block;
	dma_addr_t		initb_dma;
	mgb_rt_dma_data_t	*dma_data;
	dma_addr_t		dma_data_dma; /*  dma_addr of dma_data */
	struct mgb_rx_head		*rx_desc;
	struct mgb_tx_head		*tx_desc;
	char                    *rx_buf;
	char                    *tx_buf;
	unsigned long		flags;
	struct pci_dev		*pci_dev;
	struct net_device	*dev;
	struct resource		*resource;
	unsigned char		*base_ioaddr;
	raw_spinlock_t		mgio_lock;
	struct mutex		mx;
	/* PHY: */
	struct mii_bus		*mii_bus;
	int			extphyaddr;	/* Address of External PHY */
	int			pcsaddr;	/* Address of Internal PHY */
	u32			pcs_dev_id;
	struct device_node	*phy_node;	/* Connection to External PHY */
	int			mpll_mode;      /* Normal=1, 2G5=2, Bif=3 */
	int			nd_number;
	int			mgb_ticks_per_usec;
	/* For Debug */
	u32			msg_enable;	/* debug message level */
#ifdef CONFIG_DEBUG_FS
	struct dentry		*mgb_dbg_board;
	u32			reg_last_value;
#endif /*CONFIG_DEBUG_FS*/
	/* Auto-Negotiation */
	struct timer_list	an_link_timer;
	struct timer_list	an_monitor_timer;
	unsigned long		an_status;
	int			an_sgmii;
	int			an_clause_73;
	atomic_t		an_cnt;
	/* RX */
	u8			linkup;
	u8			rx_got;
	u8			opened;
	raw_spinlock_t		rx_lock;
	struct mutex		rx_mx;
	struct task_struct	*rx_waiter;
	struct mgb_tx_stats	tx_stats;
	struct mgb_rx_stats	rx_stats;
	mgb_stats_t		stats;
};

#define dma_dma_data(ep)	((mgb_rt_dma_data_t *)ep->dma_data_dma)

#define MGB_F_AN_STRT		(0)
#define MGB_F_AN_DONE		(1)
#define MGB_F_AN_BUSY		(2)
#define MGB_F_AN_FAIL		(3)
#define MGB_F_AN_CL37		(4)
#define MGB_F_AN_SGMII		(5)
#define MGB_F_AN_CL73		(6)
#define MGB_F_AN_XNP		(7)

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
#define MGB_F_TX_NAPI	20
#define MGB_F_TX0_NAPI	MGB_F_TX_NAPI
#define MGB_F_TX1_NAPI	(MGB_F_TX_NAPI + 1)
#define MGB_F_RX_NAPI	22
#define MGB_F_RX0_NAPI	MGB_F_RX_NAPI
#define MGB_F_RX1_NAPI	(MGB_F_RX_NAPI + 1)
#define MGB_F_SYNC		31
#define MGB_F_ALL		0x7e

/* Shift according to pci_dev->irq */
#define MGB_T0_INTR	0	/* tx queue0 interrupt */
#define MGB_T1_INTR	1	/* tx queue1 interrupt */
#define MGB_R0_INTR	2	/* rx queue0 interrupt */
#define MGB_R1_INTR	3	/* rx queue1 interrupt */
#define MGB_SYS_INTR	4	/* system interrupt */


#define mgb_netif_err(ep)	(netif_msg_tx_err(ep) || netif_msg_tx_err(ep))


static irqreturn_t mgb_sys_interrupt(int , void *);
static irqreturn_t mgb_restart_card(int, void *);
static irqreturn_t mgb_rx_interrupt(int , void *);
static int mgb_wakeup_card(struct mgb_private *ep);
static void mgb_check_link_status(struct mgb_private *ep, u32 mgio_csr);
static int mgio_read_clause_45(struct mgb_private *ep, int mii_id, int reg_num);
static void mgio_write_clause_45(struct mgb_private *ep, int mii_id,
				 int reg_num, int val);
static int mgb_max_mtu_config(struct net_device *dev);
static u32 mgb_get_link(struct net_device *dev);
static void mgb_link_timer(struct timer_list *t);
static void mgb_an_monitor_timer(struct timer_list *t);
static void mgb_run_auto_negotiation(struct net_device *dev);
static void mgb_monitor_auto_negotiation(struct net_device *dev);

static int mgb_debug = 0;


#define mgb_netif_msg_reset(dev) \
	((dev)->msg_enable & (NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR))




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

static u32 mgb_read_q_csr(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + E_Q0CSR);
}
static void mgb_write_q_csr(struct mgb_private *ep, u32 val)
{
	BUG_ON(!ep->base_ioaddr);
	writel(val, ep->base_ioaddr + E_Q0CSR);
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

static u32 mgb_read_sh_data_l(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + SH_DATA_L);
}

static u32 mgb_read_sh_data_h(struct mgb_private *ep)
{
	BUG_ON(!ep->base_ioaddr);
	return readl(ep->base_ioaddr + SH_DATA_H);
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


static void mgb_check_phydev_link_status(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct phy_device *phydev = dev->phydev;

	if (!phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	if (phydev->link) {
		int max_mtu = mgb_max_mtu_config(dev);

		if (dev->mtu > max_mtu) {
			rtnl_lock();
			dev_set_mtu(dev, max_mtu);
			rtnl_unlock();
		}
		if (!ep->linkup) {
			/* Restart AN */
			if (an_monitor)
				del_timer(&ep->an_monitor_timer);

			if (!test_bit(MGB_F_AN_BUSY, &ep->an_status)) {
				set_bit(MGB_F_AN_STRT, &ep->an_status);
				clear_bit(MGB_F_AN_DONE, &ep->an_status);
				clear_bit(MGB_F_AN_FAIL, &ep->an_status);
				mgb_run_auto_negotiation(dev);
			}

			if (netif_msg_link(ep))
				dev_info(&dev->dev,
					 "link up, %dMbps, %s-duplex\n",
					 phydev->speed,
					 phydev->duplex == DUPLEX_FULL ? "full" : "half");
		}

		ep->linkup = 1;
		netif_carrier_on(dev);
	} else {
		if (netif_msg_link(ep) && ep->linkup)
			dev_info(&dev->dev, "link down\n");

		ep->linkup = 0;
		netif_carrier_off(dev);
	}
}

static void mgb_set_mac_phymode(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct phy_device *phydev = dev->phydev;

	if (!phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	phy_read_status(phydev);


	mgb_check_phydev_link_status(dev);
}

/* callback - external phy change state */
static void mgb_phylink_handler(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct phy_device *phydev = dev->phydev;

	if (!phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	mgb_set_mac_phymode(dev);

	if (!netif_carrier_ok(dev) && netif_msg_ifup(ep))
		dev_info(&dev->dev, "phy %s no carrier\n",
			 phydev_name(dev->phydev));

	phy_print_status(dev->phydev);
}

/* called at begin of open() */
static int mgb_extphy_connect(struct mgb_private *ep)
{
	struct phy_device *phydev;
	int ret;

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

#ifndef __sparc__
/* e2k e12g phy */
#define PCS_DEV_ID_1G_2G5	0x7996CED0
#define PCS_DEV_ID_1G_2G5_10G	0x7996CED1
#else /* sparc */
/* sparc e16g phy */
#define PCS_DEV_ID_1G_2G5	0x7996CED2
#define PCS_DEV_ID_1G_2G5_10G	0x7996CED3
#endif

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
#define SR_MII_LP_BABL		(0x0005 | VS_MII_MMD)
#define SR_MII_EXT_STS		(0x000f | VS_MII_MMD)
#define VR_MII_DIG_CTRL1	(0x8000 | VS_MII_MMD)
#define VR_MII_AN_INTR_STS	(0x8002 | VS_MII_MMD)
#define VR_MII_LINK_TIMER_CTRL	(0x800a | VS_MII_MMD)

#define SR_VSMMD_CTRL		(0x0009 | VS_MMD1)

#define VR_AN_INTR		(0x8002 | AN_MMD)
#define SR_AN_CTRL		(0x0000 | AN_MMD)
#define SR_AN_STS		(0x0001 | AN_MMD)
#define SR_AN_ADV1		(0x0010 | AN_MMD)
#define SR_AN_ADV2		(0x0011 | AN_MMD)
#define SR_AN_ADV3		(0x0012 | AN_MMD)
#define SR_AN_LP_ABL1		(0x0013 | AN_MMD)
#define SR_AN_LP_ABL2		(0x0014 | AN_MMD)
#define SR_AN_LP_ABL3		(0x0015 | AN_MMD)
#define SR_AN_XNP_TX1		(0x0016 | AN_MMD)
#define SR_AN_XNP_TX2		(0x0017 | AN_MMD)
#define SR_AN_XNP_TX3		(0x0018 | AN_MMD)
#define SR_AN_LP_XNP_ABL1   (0x0019 | AN_MMD)
#define SR_AN_LP_XNP_ABL2   (0x001A | AN_MMD)
#define SR_AN_LP_XNP_ABL3   (0x001B | AN_MMD)
#define SR_AN_COMP_STS		(0x0030 | AN_MMD)

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
#define VR_XS_PMA_Gen5_12G_16G_MISC_STS		(0x8098 | PMA_and_PMD_MMD)


#define MGB_PHY_WAIT_AN	300
#define MGB_CL37_TIMER_DELAY	((HZ / 50) ? : 1) /* 20 msecs */

static void mgb_check_pcs_an_clause_37(struct mgb_private *ep)
{
	int r;

	if (test_bit(MGB_F_AN_BUSY, &ep->an_status))
		return;

	r = mgb_pcs_read(ep, VR_MII_AN_INTR_STS);
	if (r & 0x1) { /* CL37_ANCMPLT_INTR==1 */
		if (unlikely(netif_msg_ifup(ep)))
			dev_info(&ep->dev->dev, "AN_CL37_MONITOR: AN complete\n");
		r &= ~0x0001;
		mgb_pcs_write(ep, VR_MII_AN_INTR_STS, r);
	}
	mod_timer(&ep->an_monitor_timer, jiffies + MGB_CL37_TIMER_DELAY);
}

/* Programming Guidelines for Clause 37 Auto-Negotiation */
static int mgb_set_pcs_an_clause_37(struct mgb_private *ep)
{
	int r;
	struct device *dev = &ep->dev->dev;

	if (test_bit(MGB_F_AN_BUSY, &ep->an_status)) {

		if (atomic_dec_and_test(&ep->an_cnt)) {
			set_bit(MGB_F_AN_FAIL, &ep->an_status);
			set_bit(MGB_F_AN_DONE, &ep->an_status);
			clear_bit(MGB_F_AN_BUSY, &ep->an_status);
			if (unlikely(netif_msg_ifup(ep)))
				dev_info(dev, "AN_CL37: Auto-negotiation failed\n");

			return 1;
		}
		r = mgb_pcs_read(ep, VR_MII_AN_INTR_STS);
		if (r & 0x1) { /* CL37_ANCMPLT_INTR==1 */
			if (unlikely(netif_msg_ifup(ep))) {
				dev_info(dev, "AN_CL37: Auto-negotiation done: 0x%X\n", r);
				if (test_bit(MGB_F_AN_SGMII, &ep->an_status)) {
					dev_info(dev, "AN_CL37(SGMII): Link is %s\n",
						 (r & 0x0002) ? "UP" : "DOWN");
				}
			}
			r &= ~0x0001;
			mgb_pcs_write(ep, VR_MII_AN_INTR_STS, r);
			set_bit(MGB_F_AN_DONE, &ep->an_status);
			clear_bit(MGB_F_AN_BUSY, &ep->an_status);

			return 0;
		}
		mod_timer(&ep->an_link_timer, jiffies + MGB_CL37_TIMER_DELAY);

		return 1;
	}

	if (!test_bit(MGB_F_AN_STRT, &ep->an_status)) {
		if (unlikely(netif_msg_ifup(ep)))
			dev_info(dev, "AN_CL37: Unexpected status(0x%lX)\n",
				 ep->an_status);

		return 1;
	}

	/* Disable Clause 73 AN */
	r = mgb_pcs_read(ep, SR_AN_CTRL);
	r &= ~0x1000; /* AN_EN=0 */
	mgb_pcs_write(ep, SR_AN_CTRL, r);

	r = mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1);
	r |= 0x1000; /* CL37_BP=1 */
	mgb_pcs_write(ep, VR_XS_PCS_DIG_CTRL1, r);

	/* Disable Clause 37 AN */
	r = mgb_pcs_read(ep, SR_MII_CTRL);
	r &= ~0x1000; /* AN_ENABLE=0 */
	mgb_pcs_write(ep, SR_MII_CTRL, r);

	if (test_bit(MGB_F_AN_SGMII, &ep->an_status)) {
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
			r |= 0x40; /* SS13=0, SS6=1: 1Gbps */
			mgb_pcs_write(ep, SR_MII_CTRL, r);
			r = mgb_pcs_read(ep, SR_MII_AN_ADV);
			r |= 0x20; /* FD=1 */
			if (mgb_default_mode | EPSF)
				r |= 0x0180; /* PAUSE ability */
			mgb_pcs_write(ep, SR_MII_AN_ADV, r);
		}
	} else {
		/* BASE-X */
		r = mgb_pcs_read(ep, SR_MII_AN_ADV);
		r |= 0x20; /* FD=1 */
		if (mgb_default_mode | EPSF)
			r |= 0x0180; /* PAUSE ability */
		mgb_pcs_write(ep, SR_MII_AN_ADV, r);
	}
	r = mgb_pcs_read(ep, VR_MII_AN_INTR_STS);
	/* Clear CL37_ANCMPLT_INTR */
	r &= ~0x0001;
	mgb_pcs_write(ep, VR_MII_AN_INTR_STS, r);
	/* Enable Clause 37 AN */
	r = mgb_pcs_read(ep, SR_MII_CTRL);
	r |= 0x1000; /* AN_ENABLE=1 */
	mgb_pcs_write(ep, SR_MII_CTRL, r);
	r = mgb_pcs_read(ep, SR_MII_CTRL);
	r |= 0x200; /* RESTART_AN=1 */
	mgb_pcs_write(ep, SR_MII_CTRL, r);

	atomic_set(&ep->an_cnt, MGB_PHY_WAIT_AN);
	set_bit(MGB_F_AN_BUSY, &ep->an_status);
	clear_bit(MGB_F_AN_STRT, &ep->an_status);

	if (unlikely(netif_msg_ifup(ep)))
		dev_info(dev, "AN_CL37: Run auto-negotiation\n");
	mod_timer(&ep->an_link_timer, jiffies + MGB_CL37_TIMER_DELAY);

	return 1;
}

#define MGB_TIMER_DELAY	2

static void mgb_check_pcs_an_clause_73(struct mgb_private *ep)
{
	int r;

	if (test_bit(MGB_F_AN_BUSY, &ep->an_status))
		return;

	r = mgb_pcs_read(ep, VR_AN_INTR);
	if (r & 0x7) { /* AN_INT_CMPLT | AN_INC_LINK | AN_PG_RCV */
		if (unlikely(netif_msg_ifup(ep))) {
			struct device *dev = &ep->dev->dev;

			if (r & 0x1) { /* AN_INT_CMPLT */
				dev_info(dev, "AN_CL73_MONITOR: AN complete\n");
			}
			if (r & 0x2) { /* AN_INC_LINK */
				dev_info(dev, "AN_CL73_MONITOR: Incompatible link\n");
			}
			if (r & 0x4) { /* AN_PG_RCV */
				dev_info(dev, "AN_CL73_MONITOR: Page received:\n");
				dev_info(dev, "AN_CL73_MONITOR: SR_AN_LP_ABL1: 0x%X\n",
					 mgb_pcs_read(ep, SR_AN_LP_ABL1));
				dev_info(dev, "AN_CL73_MONITOR: SR_AN_LP_ABL2: 0x%X\n",
					 mgb_pcs_read(ep, SR_AN_LP_ABL2));
				dev_info(dev, "AN_CL73_MONITOR: SR_AN_LP_ABL3: 0x%X\n",
					 mgb_pcs_read(ep, SR_AN_LP_ABL3));
			}
		}
		r &= ~0x0007;
		mgb_pcs_write(ep, VR_AN_INTR, r);
	}
	mod_timer(&ep->an_monitor_timer, jiffies + 10);
}

/* Programming Guidelines for Clause 73 Auto-Negotiation */
static int mgb_set_pcs_an_clause_73(struct mgb_private *ep)
{
	int r;
	struct device *dev = &ep->dev->dev;

	if (test_bit(MGB_F_AN_STRT, &ep->an_status)) {
		/* Disable Clause 37 AN */
		r = mgb_pcs_read(ep, SR_MII_CTRL);
		r &= ~0x1000; /* AN_ENABLE=0 */
		mgb_pcs_write(ep, SR_MII_CTRL, r);

		/* Disable Clause 73 AN */
		r = mgb_pcs_read(ep, SR_AN_CTRL);
		r &= ~0x1000; /* AN_EN = 0 */
		mgb_pcs_write(ep, SR_AN_CTRL, r);

		r = mgb_pcs_read(ep, SR_AN_ADV1);
		if (mgb_default_mode | EPSF)
			r |= 0x0C00; /* 73.6: D[11:10] PAUSE capability */
		mgb_pcs_write(ep, SR_AN_ADV1, r);
		/* NULL messages */
		mgb_pcs_write(ep, SR_AN_XNP_TX3, 0);
		mgb_pcs_write(ep, SR_AN_XNP_TX2, 0);
		mgb_pcs_write(ep, SR_AN_XNP_TX1, 0);

		r = mgb_pcs_read(ep, VR_AN_INTR);
		/* Clear AN_INT_CMPLT, AN_INC_LINK, AN_PG_RCV first */
		r &= ~0x0007;
		mgb_pcs_write(ep, VR_AN_INTR, r);

		/* Enable Clause 73 AN */
		r = mgb_pcs_read(ep, SR_AN_CTRL);
		r |= 0x1000; /* AN_EN = 1 */
		mgb_pcs_write(ep, SR_AN_CTRL, r);

		/* Restart the auto-negotiation */
		r = mgb_pcs_read(ep, SR_AN_CTRL);
		r |= 0x200;	/* RSTRT_AN=1 */
		mgb_pcs_write(ep, SR_AN_CTRL, r);

		atomic_set(&ep->an_cnt, MGB_PHY_WAIT_AN);
		set_bit(MGB_F_AN_BUSY, &ep->an_status);
		clear_bit(MGB_F_AN_STRT, &ep->an_status);

		if (unlikely(netif_msg_ifup(ep)))
			dev_info(dev, "AN_CL73: Run auto-negotiation\n");
		mod_timer(&ep->an_link_timer, jiffies + MGB_TIMER_DELAY);

		return 1;
	}

	if (!test_bit(MGB_F_AN_BUSY, &ep->an_status)) {
		if (unlikely(netif_msg_ifup(ep)))
			dev_info(dev, "AN_CL73: Unexpected status(0x%lX)\n",
				 ep->an_status);

		return 1;
	}

	if (atomic_dec_and_test(&ep->an_cnt)) {
		set_bit(MGB_F_AN_FAIL, &ep->an_status);
		set_bit(MGB_F_AN_DONE, &ep->an_status);
		clear_bit(MGB_F_AN_BUSY, &ep->an_status);
		if (unlikely(netif_msg_ifup(ep)))
			dev_info(dev, "AN_CL73: Auto-negotiation failed\n");

		return 1;
	}

	r = mgb_pcs_read(ep, VR_AN_INTR);
	if (r & 0x7) { /* AN_INT_CMPLT | AN_INC_LINK | AN_PG_RCV */
		if (r & 0x1) { /* AN_INT_CMPLT */
			if (unlikely(netif_msg_ifup(ep))) {
				if (r & 0x2) /* AN_INC_LINK */
					dev_info(dev, "AN_CL73: AN Incompatible Link\n");
				if (r & 0x4) { /* AN_PG_RCV */
					dev_info(dev, "AN_CL73: AN Page received\n");
					dev_info(dev, "AN_CL73: SR_AN_LP_ABL1: 0x%X\n",
						 mgb_pcs_read(ep, SR_AN_LP_ABL1));
					dev_info(dev, "AN_CL73: SR_AN_LP_ABL2: 0x%X\n",
						 mgb_pcs_read(ep, SR_AN_LP_ABL2));
					dev_info(dev, "AN_CL73: SR_AN_LP_ABL3: 0x%X\n",
						 mgb_pcs_read(ep, SR_AN_LP_ABL3));
				}
				dev_info(dev, "AN_CL73: Auto-negotiation done: 0x%X\n", r);
			}
			/* Clear AN_INT_CMPLT, AN_INC_LINK, and AN_PG_RCV */
			r &= ~0x0007;
			mgb_pcs_write(ep, VR_AN_INTR, r);

			set_bit(MGB_F_AN_DONE, &ep->an_status);
			clear_bit(MGB_F_AN_XNP, &ep->an_status);
			clear_bit(MGB_F_AN_BUSY, &ep->an_status);

			return 0;
		}
		if (r & 0x2) { /* AN_INC_LINK */
			if (unlikely(netif_msg_ifup(ep)))
				dev_info(dev,
					 "AN_CL73: AN Incompatible Link: 0x%X\n",
					 r);
			r &= ~0x0002; /* Clear AN_INC_LINK */
			mgb_pcs_write(ep, VR_AN_INTR, r);
		}
	} else {
		mod_timer(&ep->an_link_timer, jiffies + MGB_TIMER_DELAY);

		return 1;
	}

	if ((r & 0x4) == 0) { /* Wait for AN_PG_RCV */
		mod_timer(&ep->an_link_timer, jiffies + MGB_TIMER_DELAY);

		return 1;
	}
	if (unlikely(netif_msg_ifup(ep)))
		dev_info(dev, "AN_CL73: AN Page received: 0x%X\n", r);

	r &= ~0x0004; /* Clear AN_PG_RCV */
	mgb_pcs_write(ep, VR_AN_INTR, r);

	if (test_bit(MGB_F_AN_XNP, &ep->an_status)) {
		mgb_pcs_read(ep, SR_AN_LP_XNP_ABL1);
		mgb_pcs_read(ep, SR_AN_LP_XNP_ABL2);
		mgb_pcs_read(ep, SR_AN_LP_XNP_ABL3);
		r = mgb_pcs_read(ep, SR_AN_LP_XNP_ABL1);
		if ((r & 0x8000) == 0) { /* AN_LP_XNP_NP == 0 */
			/*  The link partner does not want to exchange the Next
			 *  Page after the current Page.
			 *  Wait for AN_INT_CMPLT.
			 */
			if (unlikely(netif_msg_ifup(ep)))
				dev_info(dev, "AN_CL73: AN_LP_XNP_NP==0: 0x%lX\n",
					 ep->an_status);
			clear_bit(MGB_F_AN_XNP, &ep->an_status);
		} else {
			/* Wait for AN_PG_RCV. */
			if (unlikely(netif_msg_ifup(ep)))
				dev_info(dev, "AN_CL73: AN_LP_ADV_NP==1: 0x%lX\n",
					 ep->an_status);
		}
		mod_timer(&ep->an_link_timer, jiffies + MGB_TIMER_DELAY);

		return 1;
	} else {
		/* Base Page Received */
		if (unlikely(netif_msg_ifup(ep))) {
			dev_info(dev, "AN_CL73: SR_AN_LP_ABL1: 0x%X\n",
				 mgb_pcs_read(ep, SR_AN_LP_ABL1));
			dev_info(dev, "AN_CL73: SR_AN_LP_ABL2: 0x%X\n",
				 mgb_pcs_read(ep, SR_AN_LP_ABL2));
			dev_info(dev, "AN_CL73: SR_AN_LP_ABL3: 0x%X\n",
				 mgb_pcs_read(ep, SR_AN_LP_ABL3));
		}

		r = mgb_pcs_read(ep, SR_AN_LP_ABL1);
		if ((r & 0x8000) == 0) { /* AN_LP_ADV_NP == 0 */
			/*  The link partner does not want to exchange the Next
			 *  Page after the Base Page.
			 *  Wait for AN_INT_CMPLT.
			 */
			if (unlikely(netif_msg_ifup(ep)))
				dev_info(dev, "AN_CL73: AN_LP_ADV_NP==0: 0x%lX\n",
					 ep->an_status);
			mod_timer(&ep->an_link_timer, jiffies + MGB_TIMER_DELAY);

			return 1;
		}
	}
	mgb_pcs_write(ep, SR_AN_XNP_TX3, 0);
	mgb_pcs_write(ep, SR_AN_XNP_TX2, 0);
	mgb_pcs_write(ep, SR_AN_XNP_TX1, 0);
	/* Wait for AN_PG_RCV. */
	set_bit(MGB_F_AN_XNP, &ep->an_status);

	mod_timer(&ep->an_link_timer, jiffies + MGB_TIMER_DELAY);

	return 1;
}

static void mgb_an_monitor_timer(struct timer_list *t)
{
	struct mgb_private *ep = from_timer(ep, t, an_monitor_timer);

	mgb_monitor_auto_negotiation(ep->dev);
}

static void mgb_link_timer(struct timer_list *t)
{
	struct mgb_private *ep = from_timer(ep, t, an_link_timer);

	mgb_run_auto_negotiation(ep->dev);
}

static void mgb_monitor_auto_negotiation(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (test_bit(MGB_F_AN_CL73, &ep->an_status)) {
		mgb_check_pcs_an_clause_73(ep);
	} else if (test_bit(MGB_F_AN_CL37, &ep->an_status)) {
		mgb_check_pcs_an_clause_37(ep);
	} else
		return;
}

static void mgb_run_auto_negotiation(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int r = 1;

	if (test_bit(MGB_F_AN_CL73, &ep->an_status)) {
		r = mgb_set_pcs_an_clause_73(ep);
	} else if (test_bit(MGB_F_AN_CL37, &ep->an_status)) {
		r = mgb_set_pcs_an_clause_37(ep);
	} else {
		dev_err(&dev->dev,
			"Auto-Negotiation invalid status: 0x%lX\n",
			ep->an_status);
		return;
	}

	if (r) {
		if (test_bit(MGB_F_AN_FAIL, &ep->an_status)) {
			int an_37 = test_bit(MGB_F_AN_CL37, &ep->an_status);

			dev_err(&dev->dev,
				"Clause %d%s Auto-Negotiation: failed\n",
				an_37 ? 37 : 73,
				an_37 ?
				((test_bit(MGB_F_AN_SGMII, &ep->an_status)) ?
				"(SGMII)" : "(BASE-X)") : "");
			if (an_monitor)
				mod_timer(&ep->an_monitor_timer, jiffies + 10);
		}
	} else {
		if (netif_msg_link(ep)) {
			int an_37 = test_bit(MGB_F_AN_CL37, &ep->an_status);

			dev_info(&dev->dev,
				 "Clause %d%s Auto-Negotiation: passed\n",
				 an_37 ? 37 : 73,
				 an_37 ?
				 ((test_bit(MGB_F_AN_SGMII, &ep->an_status)) ?
				 "(SGMII)" : "(BASE-X)") : "");
		}
		if (an_monitor)
			mod_timer(&ep->an_monitor_timer, jiffies + 10);
	}
}

static void mgb_set_pcsphy_mode(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	ep->pcsaddr = 1;

	ep->pcs_dev_id = mgb_pcs_read(ep, SR_XS_PCS_DEV_ID1) << 16 |
			 mgb_pcs_read(ep, SR_XS_PCS_DEV_ID2);
	dev_info(&ep->pci_dev->dev,
		 "pcs[%d] id: 0x%08x - %s\n",
		 ep->pcsaddr, ep->pcs_dev_id,
		 (ep->pcs_dev_id == PCS_DEV_ID_1G_2G5_10G) ? "1G/2.5G/10G" :
		 (ep->pcs_dev_id == PCS_DEV_ID_1G_2G5) ? "1G/2.5G" : "unknown");

	if (ep->extphyaddr != -1) {
		clear_bit(MGB_F_AN_CL73, &ep->an_status);
		set_bit(MGB_F_AN_CL37, &ep->an_status);
		set_bit(MGB_F_AN_SGMII, &ep->an_status);
	} else {
		if (ep->an_clause_73) {
			set_bit(MGB_F_AN_CL73, &ep->an_status);
			clear_bit(MGB_F_AN_CL37, &ep->an_status);
			clear_bit(MGB_F_AN_SGMII, &ep->an_status);
		} else {
			set_bit(MGB_F_AN_CL37, &ep->an_status);
			if (ep->an_sgmii)
				set_bit(MGB_F_AN_SGMII, &ep->an_status);
			else
				clear_bit(MGB_F_AN_SGMII, &ep->an_status);
		}
	}

	if (unlikely(netif_msg_ifup(ep))) {
		/* Clause 73 AN */
		if (mgb_pcs_read(ep, SR_AN_CTRL) & 0x1000) {
			/* AN_EN */
			dev_info(&dev->dev,
				 "Clause 73 AN is enabled by default\n");
		}
		/* Clause 37 AN */
		if (mgb_pcs_read(ep, SR_MII_CTRL) & 0x1000) {
			/* AN_ENABLE */
			dev_info(&dev->dev,
				 "Clause 37 AN is enabled by default\n");
		}
	}

	set_bit(MGB_F_AN_STRT, &ep->an_status);
	clear_bit(MGB_F_AN_BUSY, &ep->an_status);
	clear_bit(MGB_F_AN_DONE, &ep->an_status);
	clear_bit(MGB_F_AN_FAIL, &ep->an_status);
	mgb_run_auto_negotiation(dev);
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
	} else if (id == RTL8211F_PHY_ID) {
		dev_info(&pdev->dev,
			 "found external phy id 0x%08X - Realtek RTL8211F\n",
			 id);
	} else {
		dev_info(&pdev->dev,
			 "found external phy id 0x%08X - unknown phy\n", id);
	}
}

static inline void mgb_sfp_default_settings(struct mgb_private *ep)
{
	ep->an_sgmii = 0;
	ep->an_clause_73 = 1;
}

/* called from probe() */
static int mgb_mdio_register(struct mgb_private *ep,
			     struct device_node *np)
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
	new_bus->irq[0] = PHY_MAC_INTERRUPT;
	snprintf(new_bus->id, MII_BUS_ID_SIZE, KBUILD_MODNAME"-%x",
		 PCI_DEVID(pdev->bus->number, pdev->devfn));

	new_bus->read = mgb_mdio_read_reg;
	new_bus->write = mgb_mdio_write_reg;

	/* of_mdiobus_register() allows auto-probed phy devices to be
	 * supplied with information passed in via DT.
	 * But we have to be sure that their addresses (phydev->mdio.addr)
	 * are "fixed" by a board.
	 */
	if ((mgb_phy_mode[ep->nd_number] > 1) && np) {
		struct device_node *node = of_get_child_by_name(np, "mdio");

		if (node) {
			ret = of_mdiobus_register(new_bus, node);
		} else {
			dev_info(&pdev->dev,
				 "register mdiobus %s (no mdio found in DT, scan bus for phy devices)\n",
				 new_bus->id);
			ret = mdiobus_register(new_bus);
		}
	} else {
		ret = mdiobus_register(new_bus);
	}
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
		mgb_sfp_default_settings(ep);

		if (netif_msg_link(ep))
			dev_info(&pdev->dev,
				 "register mdiobus %s (no external phy)\n",
				 new_bus->id);
	} else {
		if (phydev->mdio.addr == 0) {
			if (mgio_read_clause_22(ep, 0, 2) == 0xFFFF) {
				ep->extphyaddr = -1;
				mgb_sfp_default_settings(ep);

				if (netif_msg_link(ep))
					dev_info(&pdev->dev,
						"register mdiobus %s (no external phy found)\n",
						new_bus->id);

				return 0;
			}
		}
		if (phydev->phy_id == 0) {
			if (netif_msg_link(ep))
				dev_err(&pdev->dev,
					"register mdiobus %s (external phy with id=0 found, ignore it. Please, update DT!)\n",
					new_bus->id);

			mdiobus_unregister(ep->mii_bus);
			ep->mii_bus = NULL;

			return -ENODEV;
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

static void mgb_dump_state(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	mutex_lock(&mgb_mutex);
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
	dev_warn(&dev->dev, "Q0_CSR = 0x%x\n", mgb_read_q_csr(ep));
	dev_warn(&dev->dev, "RX: base %08x buf len %04x msg len %04x status %04x\n",
		 le32_to_cpu(ep->rx_desc->base),
		 le16_to_cpu(-(ep->rx_desc->buf_length & 0xffff)),
		 le16_to_cpu(ep->rx_desc->msg_length),
		 le16_to_cpu(ep->rx_desc->status));
	dev_warn(&dev->dev, "TX: base 0x%08x buf len %04x misc %08x status %04x\n",
		 le32_to_cpu(ep->tx_desc->base),
		 le16_to_cpu(-(ep->tx_desc->buf_length & 0xffff)),
		 le32_to_cpu(ep->tx_desc->misc),
		 le16_to_cpu((u16)(ep->tx_desc->status)));
	mutex_unlock(&mgb_mutex);
}



/** TITLE: INITIALIZING / CLEANING Rx and Tx queues. */


static int mgb_rt_set_rings(struct mgb_private *ep)
{
	ep->dma_data = dma_alloc_coherent(&ep->pci_dev->dev,
		sizeof(mgb_rt_dma_data_t), &ep->dma_data_dma, GFP_KERNEL);
	if (!ep->dma_data) {
		return -ENOMEM;
	}
	ep->rx_desc = &ep->dma_data->rx_ring;
	ep->tx_desc = &ep->dma_data->tx_ring;
	ep->rx_buf = &ep->dma_data->rx_buf[0];
	ep->tx_buf = &ep->dma_data->tx_buf[0];
	return 0;
}



/** TITLE: OPEN / CLOSE stuff , irq handlers*/

static void mgb_rt_set_dma_and_initblock(struct mgb_private *ep)
{
	struct net_device *dev = ep->dev;
	u16 mode = mgb_default_mode;
	init_block_t *init_block = ep->init_block;
	int i;

	init_block->laddrf0 = 0UL;
	init_block->laddrf1 = 0UL;

	for (i = 0; i < 6; i++)
		init_block->paddr0[i] = dev->dev_addr[i];

	for (i = 0; i < 6; i++)
		init_block->paddr1[i] = dev->dev_addr[i];

	/* One rx buf and one tx buf */
	init_block->rdra0 = cpu_to_le32((u64)(&dma_dma_data(ep)->rx_ring));
	init_block->tdra0 = cpu_to_le32((u64)(&dma_dma_data(ep)->tx_ring));
	init_block->rdra1 = 0;
	init_block->tdra1 = 0;

	ep->rx_desc->base = cpu_to_le32((u64)&dma_dma_data(ep)->rx_buf);
	ep->rx_desc->buf_length = cpu_to_le16(-(MGB_RT_XFER_BUF_SZ));
	ep->rx_desc->msg_length = 0;
	ep->rx_desc->status = cpu_to_le16(RD_OWN);

	ep->tx_desc->base = cpu_to_le32((u64)&dma_dma_data(ep)->tx_buf);

	mode = DRX1 | DTX1 | PROM0;
	init_block->mode = cpu_to_le16(mode);
	mgb_write_e_base_address(ep, (u32)(ep->initb_dma) & 0xffffffff);
	mgb_write_dma_base_address(ep, (u32)((ep->initb_dma >> 32) & 0xffffffff));
	mgb_write_e_csr(ep, INIT);
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




static int mgb_rt_open(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int rc;

	mutex_lock(&ep->mx);
	if (ep->opened) {
		if (netif_msg_ifup(ep)) {
			pr_info("Already opened\n");
		}
		rc = -EBUSY;
		goto out;
	}

	ep->linkup = 0;
	ep->rx_got = 0;
	ep->rx_waiter = NULL;
	/* start card */
	mgb_write_e_csr(ep, STOP);
	/* wait for stop */
	int i;
	for (i = 0; i < 1000; i++)
		if (mgb_read_e_csr(ep) & STOP)
			break;
	if (i >= 1000) {
		dev_err(&dev->dev, "%s: timed out waiting for stop. e_csr = 0x%x\n",
			__func__, mgb_read_e_csr(ep));
		mgb_write_e_csr(ep, 0); /* disable INEA */
		rc = -ETIMEDOUT;
		goto out;
	}
	/* assign rx irq, no need to assign tx rq */
	rc = request_irq(MGB_R0_INTR + ep->pci_dev->irq,  mgb_rx_interrupt,
			 IRQF_NO_THREAD, "mgb-rt-rx", ep);
	if (rc) {
		dev_err(&dev->dev, "%s: Could not register rx irq handler\n", __func__);
		goto out;
	}
	rc = request_mgb_sys_irq(ep, mgb_sys_interrupt, mgb_restart_card);
	if (rc) {
		free_irq(MGB_R0_INTR + ep->pci_dev->irq, ep);
		dev_err(&dev->dev, "%s: Could not register sysirq handler\n", __func__);
		goto out;
	}
	/* External PHY connect */
	rc = mgb_extphy_connect(ep);
	if (rc) {
		dev_err(&dev->dev, "phy_connect error.\n");
		goto out;
	}
	/* External PHY start */
	if (dev->phydev) {
		mgb_init_extphy(ep);
	}
	rc = mgb_wakeup_card(ep);
	if (rc) {
		if (dev->phydev) {
			phy_stop(dev->phydev);
			phy_disconnect(dev->phydev);
		}
		free_irq(MGB_R0_INTR + ep->pci_dev->irq, ep);
		free_irq(MGB_SYS_INTR + ep->pci_dev->irq, ep);
		dev_err(&dev->dev, "%s: Could not start card\n", __func__);
		goto out;
	}
	ep->opened  = 1;
out:
	mutex_unlock(&ep->mx);
	return rc;
}

static int mgb_rt_close(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	int i;

	mutex_lock(&ep->mx);
	raw_spin_lock_irq(&ep->rx_lock);
	if (!ep->opened) {
		/* not opened */
		raw_spin_unlock_irq(&ep->rx_lock);
		mutex_unlock(&ep->mx);
		return -EBUSY;
	}
	ep->opened = 0;
	if (ep->rx_waiter) {
		send_sig(SIGKILL, ep->rx_waiter, 1);
	}

	raw_spin_unlock_irq(&ep->rx_lock);

	if (ep->linkup) {
		netif_carrier_off(dev);
		ep->linkup = 0;
		if (netif_msg_link(ep))
			dev_info(&dev->dev, "link down\n");
		}

	/* External PHY stop */
	if (dev->phydev) {
		phy_stop(dev->phydev);
		phy_disconnect(dev->phydev);
		dev->phydev = NULL;
	}

	mgb_write_e_csr(ep, STOP);
	for (i = 0; i < 1000; i++)
		if (mgb_read_e_csr(ep) & STOP)
			break;
	if (i >= 1000) {
		dev_err(&dev->dev, "%s: timed out waiting for stop. e_csr = 0x%x\n",
			__func__, mgb_read_e_csr(ep));
	}
	free_irq(MGB_R0_INTR + ep->pci_dev->irq, ep);
	free_irq(MGB_SYS_INTR + ep->pci_dev->irq, ep);
	mutex_unlock(&ep->mx);
	return 0;
}


/** TITLE: TRANSMIT stuff */


static netdev_tx_t mgb_rt_start_xmit(struct sk_buff *skb,
					struct net_device *dev)
{
	dev_kfree_skb(skb);
	return -EBUSY;
}




/** TITLE: RECEIVE stuff */

static void mgb_handle_rx_err(struct mgb_private *ep, s16 status)
{
	struct net_device *dev = ep->dev;

	if (netif_msg_rx_err(ep)) {
		dev_info(&dev->dev,  "%s: rx hw error status=0x%x",  __func__, status);
	}
	ep->rx_stats.errors++;
	if (status & RD_FRAM)
		ep->rx_stats.frame_errors++;
	if (status & RD_OFLO)
		ep->rx_stats.over_errors++;
	if (status & RD_CRC)
		ep->rx_stats.crc_errors++;
	if (status & RD_BUFF)
		ep->rx_stats.fifo_errors++;
}






/** TITLE: MGB interrupt handlers stuff. */

static irqreturn_t mgb_rx_interrupt(int irq, void *dev_id)
{
	struct mgb_private *ep = (struct mgb_private *)dev_id;
	struct net_device *dev = ep->dev;
	u16 q_csr;

	/* irq disabled */
	q_csr = mgb_read_q_csr(ep);

	if (netif_msg_intr(ep)) {
		dev_info(&dev->dev, "%s: qcsr0 = 0x%08x\n",  __func__, q_csr);
	}
	if (!(q_csr & (Q_RINT | Q_MISS))) {
		if (netif_msg_intr(ep)) {
			dev_warn(&dev->dev, "%s:bogus RX interrupt = 0x%08x\n",
				 __func__, q_csr);
		}
		return IRQ_NONE; /* Not our interrupt */
	}
	raw_spin_lock(&ep->rx_lock);
	mgb_write_q_csr(ep, Q_RINT | Q_MISS | Q_C_RINT_EN | Q_C_MISS_EN);
	if (q_csr & Q_RINT) {
		ep->rx_got = 1;
		if (q_csr & Q_MISS) {
			ep->rx_stats.missed_errors++;
			ep->rx_got++;
		}
	} else {
		ep->rx_got = 0;
		dev_err(&dev->dev, "%s: No Q_RINT but interrupted\n", __func__);
	}
	if (ep->rx_waiter == NULL) {
		dev_err(&dev->dev, "%s: No rx_waiter for rx interrupt\n", __func__);
		goto handled;
	}
	wake_up_process(ep->rx_waiter);
	ep->rx_waiter = NULL;
handled:
	raw_spin_unlock(&ep->rx_lock);
	return IRQ_HANDLED;
}

static inline int mgb_get_lstc_intr_enable(int mgio_csr,
					   struct mgb_private *ep)
{
	if (!(mgio_csr & MG_LSTS0) && (mgio_csr & MG_LSTS1)) {
		if (test_bit(MGB_F_AN_CL73, &ep->an_status))
			return MG_ECPL;
		if (test_bit(MGB_F_AN_SGMII, &ep->an_status))
			return MG_ECST;
		else
			return MG_ECRL | MG_ECPL;
	}
	return MG_ECRL;
}

static void mgb_set_regs_after_reset(struct mgb_private *ep)
{
	int mgio_csr;
	unsigned long flags;

	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	mgio_csr = mgb_read_mgio_csr(ep);
	mgb_write_e_cap(ep, 0);
	mgb_write_q_csr(ep, 0);

	if (ep->extphyaddr == -1) {
		if (test_bit(MGB_F_AN_CL37, &ep->an_status) &&
		    !test_bit(MGB_F_AN_SGMII, &ep->an_status)) {
			/* BASE-X */
			mgio_csr |= MG_HARD;
			mgb_write_mgio_csr(ep, mgio_csr);
			mgio_csr |= (MG_GETH | MG_FDUP);
			mgio_csr &= ~MG_FETH;
		}
		mgio_csr |= (mgb_get_lstc_intr_enable(mgio_csr, ep));
	}
	mgio_csr |= (MG_GEPL | MG_FEPL);
	mgb_write_mgio_csr(ep, mgio_csr);
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);

	mgb_write_psf_csr(ep, 0);
	mgb_write_psf_data(ep, 0);
	mgb_write_psf_data1(ep, 0);
	mgb_write_irq_delay(ep, 0);
	mgb_write_rx_queue_arb(ep, 0);
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
			"initialization not completed, not stopped. e_csr = 0x%x\n",
			mgb_read_e_csr(ep));
		return 1;
	}

	mgb_rt_set_dma_and_initblock(ep);
	mgb_set_regs_after_reset(ep);

	mgb_write_e_csr(ep, STRT);
	i = 0;
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
			"initialization not completed, not IDON. e_csr = 0x%x\n",
			mgb_read_e_csr(ep));
		return 1;
	}
	mgb_write_e_csr(ep, INEA);

	if (mgb_netif_msg_reset(ep))
		dev_info(&ep->dev->dev, "Card started. e_csr = 0x%08x\n",
			 mgb_read_e_csr(ep));

	return 0;
}

static int mgb_link_up(struct mgb_private *ep, u32 mgio_csr)
{
	int up;

	if (mgio_csr & MG_LSTS0) {
		if (mgio_csr & MG_LSTS1)
			up = !(mgio_csr & MG_RLOS);
		else
			up = !!(mgio_csr & MG_SLST);
	} else if (mgio_csr & MG_LSTS1) {
		up = !!(mgio_csr & MG_PLST);
		if (up && test_bit(MGB_F_AN_CL37, &ep->an_status)) {
			if (test_bit(MGB_F_AN_SGMII, &ep->an_status))
				up = !!(mgio_csr & MG_LSTA);
			else
				up = !(mgio_csr & MG_RLOS);
		} else if (up && test_bit(MGB_F_AN_CL73, &ep->an_status)) {
			up = !(mgio_csr & MG_RLOS);
		}
	} else {
		up = !!(mgio_csr & MG_LSTA);
	}

	return up;
}

static int mgb_1gb_link_up(struct mgb_private *ep)
{
	u32 r = mgb_read_mgio_csr(ep);

	if ((r & MG_GETH) && mgb_get_link(ep->dev))
		return 1;

	return 0;
}
static int mgb_max_mtu_config(struct net_device *dev)
{
	int max_mtu = ETH_DATA_LEN;

	if (mgb_1gb_link_up(netdev_priv(dev)))
		max_mtu = MGB_MAX_DATA_LEN;

	return max_mtu;
}

static void mgb_check_link_status(struct mgb_private *ep, u32 mgio_csr)
{
	struct net_device *dev = ep->dev;
	int speed = 10;

	if (netif_msg_link(ep))
		dev_dbg(&ep->dev->dev,
			 "%s: mgio_csr = 0x%08x\n", __func__, mgio_csr);

	if (mgio_csr & MG_GETH) {
		speed = 1000;
	} else if (mgio_csr & MG_FETH) {
		speed = 100;
	}
	if (mgio_csr & MG_EMST)
		speed = (speed * 5) / 2;

	if (mgb_link_up(ep, mgio_csr)) {
		if (!ep->linkup) {
			if (an_monitor)
				del_timer(&ep->an_monitor_timer);

			if (!test_bit(MGB_F_AN_BUSY, &ep->an_status)) {
				set_bit(MGB_F_AN_STRT, &ep->an_status);
				clear_bit(MGB_F_AN_DONE, &ep->an_status);
				clear_bit(MGB_F_AN_FAIL, &ep->an_status);
				mgb_run_auto_negotiation(dev);
			}

			if (netif_msg_link(ep)) {
				dev_info(&dev->dev,
					 "link up, %dMbps, %s-duplex\n",
					 speed,
					 mgio_csr & MG_FDUP ? "full" : "half");
			}
		}
		ep->linkup = 1;
		netif_carrier_on(dev);
	} else {
		if (netif_msg_link(ep) && ep->linkup)
			dev_info(&dev->dev, "link down\n");

		ep->linkup = 0;
		netif_carrier_off(dev);
		netif_tx_stop_all_queues(dev);
	}
}


static irqreturn_t mgb_restart_card(int irq, void *dev_id)
{
	(void)mgb_wakeup_card((struct mgb_private *)dev_id);
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

	if (mgio_csr & (MG_CLST | MG_CRLS | MG_CPLS)) {
		if (unlikely(netif_msg_ifup(ep)))
			dev_info(&ep->dev->dev,
				 "%s: mgio_csr = 0x%08x\n"
				 "%10sCHANGED: %sPCS LINK STATUS\n"
				 "%10sCHANGED: %sRECEIVER LOSS\n"
				 "%10sCHANGED: %sLINK STATUS\n",
				 __func__, mgio_csr,
				 (mgio_csr & MG_CPLS)  ? "+" : "-",
				 (mgio_csr & MG_PLST)  ? "+" : "-",
				 (mgio_csr & MG_CRLS)  ? "+" : "-",
				 (mgio_csr & MG_RLOS)  ? "+" : "-",
				 (mgio_csr & MG_CLST)  ? "+" : "-",
				 (mgio_csr & MG_LSTA)  ? "+" : "-");
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
			ep->stats.merr++;
		}
		if (csr0 & SWINT) {
			ep->stats.swint++;
		}
		/* clear INEA and activate reset */
		mgb_write_e_csr(ep, 0);

		return IRQ_WAKE_THREAD;
	}

	/* Log misc errors. */
	mgb_write_e_csr(ep, csr0 & (BABL | CERR | SLVE | INEA));
	if (csr0 & BABL) {
		ep->stats.babl++; /* Tx babble. */
		if (mgb_netif_err(ep)) {
			dev_info(&dev->dev,
				 "BABL error, status 0x%08x.\n", csr0);
		}
	}
	if (csr0 & CERR) {
		ep->stats.cerr++;
		if (mgb_netif_err(ep)) {
			dev_info(&dev->dev,
				 "CERR error, status %4.4x.\n", csr0);
		}
	}
	if (csr0 & SLVE) {
		ep->stats.slve++;
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

static void mgb_rt_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct mgb_private *ep = netdev_priv(dev);

	stats->rx_packets	+= ep->rx_stats.packets;
	stats->rx_bytes		+= ep->rx_stats.bytes;
	stats->rx_errors	+= ep->rx_stats.errors;
	stats->rx_dropped	+= ep->rx_stats.dropped;
	stats->rx_length_errors	+= ep->rx_stats.length_errors;
	stats->rx_over_errors	+= ep->rx_stats.over_errors;
	stats->rx_crc_errors	+= ep->rx_stats.crc_errors;
	stats->rx_frame_errors	+= ep->rx_stats.frame_errors;
	stats->rx_fifo_errors	+= ep->rx_stats.fifo_errors;
	stats->multicast	+= ep->rx_stats.multicast;
	stats->rx_missed_errors	+= ep->rx_stats.missed_errors;

	stats->tx_packets		+= ep->tx_stats.packets;
	stats->tx_bytes			+= ep->tx_stats.bytes;
	stats->tx_errors		+= ep->tx_stats.errors;
	stats->tx_dropped		+= ep->tx_stats.dropped;
	stats->collisions		+= ep->tx_stats.collisions;
	stats->tx_aborted_errors	+= ep->tx_stats.aborted_errors;
	stats->tx_carrier_errors	+= ep->tx_stats.carrier_errors;
	stats->tx_fifo_errors		+= ep->tx_stats.fifo_errors;
	stats->tx_heartbeat_errors	+= ep->tx_stats.heartbeat_errors;
	stats->tx_window_errors		+= ep->tx_stats.window_errors;
	stats->tx_compressed		+= ep->tx_stats.compressed;
}


/* TITLE: ioctl */


static int do_mgb_rt_read(struct mgb_private *ep, el_netdev_udata_t *kud)
{
	char *buf = NULL;
	int skipped;
	int proto;
	int len = kud->rx_len;
	long timeout = kud->timeout;
	char *u_buf = kud->rx_buf;
	int msg_len;
	struct net_device *dev = ep->dev;

	if (timeout < 0) {
		timeout = MAX_SCHEDULE_TIMEOUT;
	} else {
		timeout = (timeout * HZ) / 1000;
	}
	raw_spin_lock_irq(&ep->rx_lock);
	if (!ep->opened) {
		raw_spin_unlock_irq(&ep->rx_lock);
		return -ENODEV;
	}
	if (ep->rx_waiter) {
		raw_spin_unlock_irq(&ep->rx_lock);
		return -EBUSY;
	}

	if (netif_msg_rx_status(ep)) {
		dev_info(&dev->dev, "Ready to read %d bytes\n", len);
	}
	s16 status;
	while (!ep->rx_got) {
		status = (s16)le16_to_cpu(ep->rx_desc->status);
		if (!(status & RD_OWN)) {
			u32 q_csr = mgb_read_q_csr(ep);
			if (q_csr & Q_RINT) {
				ep->rx_got = 1;
				if (q_csr & Q_MISS) {
					ep->rx_got++;
				}
				mgb_write_q_csr(ep,  Q_RINT | Q_MISS);
				break;
			}
			dev_err(&dev->dev, "%s: !(status & RD_OWN) but no Q_RINT\n", __func__);
			ep->rx_desc->status = cpu_to_le16(RD_OWN);
			wmb();  /* to sync with card hw */
		}
		/* we dont have data */
		if (timeout == 0) {
			raw_spin_unlock_irq(&ep->rx_lock);
			return -ETIMEDOUT;
		}
		set_current_state(TASK_INTERRUPTIBLE);
		ep->rx_waiter = current;
		mgb_write_q_csr(ep,  Q_RINT_EN | Q_MISS_EN);
		if (netif_msg_intr(ep)) {
			dev_info(&dev->dev, "%s: schedule_timeout q_csr = 0x%08x\n",
				__func__,  mgb_read_q_csr(ep));
		}
		raw_spin_unlock_irq_no_resched(&ep->rx_lock);
		timeout = schedule_timeout(timeout);
		if (signal_pending(current)) {
			ep->rx_waiter = NULL;
			return -EINTR;
		}
		raw_spin_lock_irq(&ep->rx_lock);
		ep->rx_waiter = NULL;
		if (!ep->opened) {
			raw_spin_unlock_irq(&ep->rx_lock);
			return -ENODEV;
		}
	}
	skipped = ep->rx_got - 1;
	ep->rx_got = 0;
	ep->rx_waiter = NULL;
	raw_spin_unlock_irq(&ep->rx_lock);
	buf = ep->rx_buf;
	proto = (int)be16_to_cpu(*((u16 *)(buf + 2 * ETH_ALEN)));
	msg_len =  (le16_to_cpu(ep->rx_desc->msg_length) & 0xfff) - ETH_HLEN - ETH_FCS_LEN;
	buf += 2 * ETH_ALEN + 2;
	len = (len > msg_len) ? msg_len : len;
	if (copy_to_user(u_buf, buf, len)) {
		return -EFAULT;
	}
	if (netif_msg_rx_status(ep)) {
		buf = ep->rx_buf;
		pr_info("%s RX_STATUS: len = %d\n", ep->dev->name, len);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n", buf[0], buf[1], buf[2], buf[3]);
		pr_info("0x%08x 0x%08x 0x%08x 0x%08x\n", buf[4], buf[5], buf[6], buf[7]);
	}
	status = (s16)le16_to_cpu(ep->rx_desc->status);
	/* Now return the buffer to a card */
	ep->rx_desc->status = cpu_to_le16(RD_OWN);
	wmb(); /* to sync with card hw */
	if (status & RD_ERR) {
		mgb_handle_rx_err(ep, status);
		return -EIO;
	}
	kud->rx_len = len;
	kud->skipped = skipped;
	kud->proto = proto;
	return 0;
}


static int mgb_rt_read(struct mgb_private *ep, void __user *data)
{
	el_netdev_udata_t *ud = (el_netdev_udata_t *)data;
	el_netdev_udata_t kud;
	int r;
	r = get_user(kud.rx_len, &ud->rx_len);
	r |= get_user(kud.timeout, &ud->timeout);
	r |= get_user(kud.rx_buf, &ud->rx_buf);
	if (r) {
		return -EFAULT;
	}
	r = do_mgb_rt_read(ep, &kud);
	if (r) {
		return r;
	}
	r  = put_user(kud.rx_len, &ud->rx_len);
	r |= put_user(kud.skipped, &ud->skipped);
	r |= put_user(kud.proto, &ud->proto);
	if (r) {
		return -EFAULT;
	}
	return 0;
}




static int do_mgb_rt_write(struct mgb_private *ep, el_netdev_udata_t *kud)
{
	struct net_device *dev = ep->dev;
	int len = kud->tx_len;
	char *u_buf = kud->tx_buf;
	u16  proto = kud->proto;
	u16 status;

	if (len + ETH_HLEN > ETH_DATA_LEN) {
		return -EINVAL;
	}
	if (copy_from_user(&ep->tx_buf[ETH_HLEN], u_buf, len)) {
		return -EFAULT;
	}
	int i;
	for (i = 0; i < ETH_ALEN; i++) {
		ep->tx_buf[i] = ep->dev->dev_addr[i]; /* my addr */
	}
	for (i = 0; i < ETH_ALEN; i++) {
		ep->tx_buf[ETH_ALEN + i] = 0xff; /* broadcast addr */
	}
	*((u16 *)(&ep->tx_buf[2 * ETH_ALEN])) = cpu_to_be16((u16)(proto));
	/* Do real transfer */
	len += ETH_HLEN;
	if (len <= ETH_ZLEN) {
		len = ETH_ZLEN;
	}
	if (netif_msg_tx_queued(ep)) {
		int *b = (int *)ep->tx_buf;
		dev_info(&dev->dev, "TX: len = %d\n", len - ETH_HLEN);
		dev_info(&dev->dev, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			 b[0], b[1], b[2], b[3]);
		dev_info(&dev->dev, "0x%08x 0x%08x 0x%08x 0x%08x\n",
			 b[4], b[5], b[6], b[7]);
	}
	raw_spin_lock_irq(&ep->rx_lock);
	if (!(ep->opened)) {
		raw_spin_unlock_irq(&ep->rx_lock);
		return -ENODEV;
	}
	status = le16_to_cpu(ep->tx_desc->status);
	if (status & TD_OWN) {
		raw_spin_unlock_irq(&ep->rx_lock);
		return -EBUSY;
	}
	int last_tx_res = 0;
	if (status & TD_ERR) {
		int err_status = le32_to_cpu(ep->tx_desc->misc);
		ep->tx_stats.errors++;
		if (netif_msg_tx_err(ep)) {
			dev_warn(&dev->dev, "Tx error status=%04x err_status=%08x\n",
				status, err_status);
		}
		if (err_status & TD_RTRY) {
			ep->tx_stats.aborted_errors++;
			last_tx_res = EIO;
		}
		if (err_status & TD_LCAR) {
			ep->tx_stats.carrier_errors++;
			last_tx_res = ENOTCONN;
		}
		if (err_status & TD_LCOL) {
			ep->tx_stats.window_errors++;
			last_tx_res = EIO;
		}
		if (err_status & TD_UFLO) {
			ep->tx_stats.fifo_errors++;
			mgb_write_e_csr(ep, INEA | SWINT); /* restart card */
			last_tx_res = EIO;
		}
	}
	ep->tx_desc->buf_length = cpu_to_le16(-len);
	ep->tx_desc->misc = 0x00000000;
	ep->tx_desc->status = cpu_to_le16(TD_OWN | TD_ENP | TD_STP);
	wmb(); /* to sync with card hw */
	mgb_write_q_csr(ep, Q_TDMD);
	ep->tx_stats.bytes += len;
	ep->tx_stats.packets++;
	raw_spin_unlock_irq(&ep->rx_lock);
	kud->timeout = last_tx_res;
	if (netif_msg_tx_queued(ep)) {
		dev_info(&ep->dev->dev, "%s Tx started. base = 0x%08x, len = %d\n",
			__func__, ep->tx_desc->base, len);
	}
	return 0;
}

static int mgb_rt_write(struct mgb_private *ep, void __user *data)
{
	el_netdev_udata_t *ud = (el_netdev_udata_t *)data;
	el_netdev_udata_t kud;
	int r;
	r = get_user(kud.tx_len, &ud->tx_len);
	r |= get_user(kud.proto, &ud->proto);
	r |= get_user(kud.tx_buf, &ud->tx_buf);
	if (r) {
		return -EFAULT;
	}
	r = do_mgb_rt_write(ep, &kud);
	if (r) {
		return r;
	}
	return put_user(kud.timeout, &ud->timeout);
}



#ifdef CONFIG_COMPAT

static int mgb_rt_compat_write(struct mgb_private *ep, void __user *data)
{
	el_netdev_udata_compat_t *ud = (el_netdev_udata_compat_t *)data;
	el_netdev_udata_t kud;
	int r;
	r = get_user(kud.tx_len, &ud->tx_len);
	r |= get_user(kud.proto, &ud->proto);
	r |= get_user(kud.tx_buf, &ud->tx_buf);
	if (r) {
		return -EFAULT;
	}
	r = do_mgb_rt_write(ep, &kud);
	if (r) {
		return r;
	}
	return put_user(kud.timeout, &ud->timeout);
}


static int mgb_rt_compat_read(struct mgb_private *ep, void __user *data)
{
	el_netdev_udata_compat_t *ud = (el_netdev_udata_compat_t *)data;
	el_netdev_udata_t kud;
	int r;
	r = get_user(kud.rx_len, &ud->rx_len);
	r |= get_user(kud.timeout, &ud->timeout);
	r |= get_user(kud.rx_buf, &ud->rx_buf);
	if (r) {
		return -EFAULT;
	}
	r = do_mgb_rt_read(ep, &kud);
	if (r) {
		return r;
	}
	r  = put_user(kud.rx_len, &ud->rx_len);
	r |= put_user(kud.skipped, &ud->skipped);
	r |= put_user(kud.proto, &ud->proto);
	if (r) {
		return -EFAULT;
	}
	return 0;
}

#endif /* CONFIG_COMPAT */

static int mgb_rt_siocdevprivate(struct net_device *dev, struct ifreq *rq,
				 void __user *data, int cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	int rc = 0;

	switch (cmd) {
	case SIOCDEV_RTND_OPEN :
		rc = mgb_rt_open(dev);
		break;
	case SIOCDEV_RTND_CLOSE :
		rc = mgb_rt_close(dev);
		break;
	case SIOCDEV_RTND_READ :
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
			rc = mgb_rt_compat_read(ep, data);
			break;
		}
#endif
		rc = mgb_rt_read(ep, data);
		break;
	case SIOCDEV_RTND_WRITE :
#ifdef CONFIG_COMPAT
		if (is_compat_task()) {
			rc = mgb_rt_compat_write(ep, data);
			break;
		}
#endif
		rc = mgb_rt_write(ep, data);
		break;
	case SIOCDEVPRIVATE + 10 :
		mgb_dump_state(dev);
		break;
	default:
		/* SIOC[GS]MIIxxx ioctls */
		if (dev->phydev) {
			rc = phy_mii_ioctl(dev->phydev, rq, cmd);
		} else {
			dev_dbg_once(&dev->dev, "phydev not init\n");
			rc = -EOPNOTSUPP;
		}
	}
	return rc;
}



static const struct net_device_ops mgb_netdev_ops = {
	.ndo_start_xmit		= mgb_rt_start_xmit,
	.ndo_siocdevprivate	= mgb_rt_siocdevprivate,
	.ndo_get_stats64	= mgb_rt_get_stats64,
#ifdef CONFIG_MCST_RT
	.ndo_unlocked_ioctl	= 1,
#endif
};


/** TITLE: ETHERTOOL stuff */


static void mgb_ethtool_ksettings_fix(struct net_device *dev,
				      struct ethtool_link_ksettings *cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	u32 r = mgb_read_mgio_csr(ep);

	if (mgb_get_link(dev)) {
		if (r & MG_FDUP)
			cmd->base.duplex = DUPLEX_FULL;
		else
			cmd->base.duplex = DUPLEX_HALF;
		if (r & MG_GETH) {
			if (r & MG_EMST)
				cmd->base.speed = SPEED_2500;
			else
				cmd->base.speed = SPEED_1000;
		} else if (r & MG_FETH) {
			cmd->base.speed = SPEED_100;
		} else {
			cmd->base.speed = SPEED_10;
		}
	} else {
		cmd->base.speed = SPEED_UNKNOWN;
		cmd->base.duplex = DUPLEX_UNKNOWN;
	}
}

static void mgb_pcs_ethtool_ksettings_get(struct net_device *dev,
					  struct ethtool_link_ksettings *cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	u32 r = mgb_read_mgio_csr(ep);
	u32 supported = 0, advertising = 0;
	u16 an_status = mgb_pcs_read(ep, SR_AN_COMP_STS);
	u16 an_control;
	u16 pcs_control = mgb_pcs_read(ep, VR_XS_PCS_DIG_CTRL1);
	int is_an_enable, is_1000basekx, is_2_5g_mode_enable;

	cmd->base.port = PORT_MII;
	cmd->base.phy_address = 0;
	if (mgb_default_mode & EPSF)
		supported |= (SUPPORTED_Pause | SUPPORTED_Asym_Pause);
	is_2_5g_mode_enable = (int)(pcs_control & 0x0004);
	is_1000basekx = (int)(an_status & 0x0002);
	if (ep->an_clause_73) {
		an_control = mgb_pcs_read(ep, SR_AN_CTRL);
		is_an_enable = (int)(an_control & 0x1000);
	} else {
		an_control = mgb_pcs_read(ep, SR_MII_CTRL);
		is_an_enable = (int)(an_control & 0x1000);
	}
	if (is_an_enable) {
		supported |= SUPPORTED_Autoneg;
		advertising |= ADVERTISED_Autoneg;
		cmd->base.autoneg = AUTONEG_ENABLE;
	} else {
		cmd->base.autoneg = AUTONEG_DISABLE;
	}
	if (test_bit(MGB_F_AN_SGMII, &ep->an_status)) {
		if (is_2_5g_mode_enable) {
			supported |= SUPPORTED_2500baseX_Full;
			advertising |= ADVERTISED_2500baseX_Full;
		} else {
			supported |= (SUPPORTED_1000baseT_Full | SUPPORTED_1000baseT_Half |
					  SUPPORTED_100baseT_Full | SUPPORTED_100baseT_Half |
					  SUPPORTED_10baseT_Full | SUPPORTED_10baseT_Half);
			advertising |= (ADVERTISED_1000baseT_Full | ADVERTISED_1000baseT_Half |
					  ADVERTISED_100baseT_Full | ADVERTISED_100baseT_Half |
					  ADVERTISED_10baseT_Full | ADVERTISED_10baseT_Half);
		}
	} else {
		if (is_2_5g_mode_enable) {
			supported |= SUPPORTED_2500baseX_Full;
			advertising |= ADVERTISED_2500baseX_Full;
		} else {
			supported |= (is_1000basekx) ?
						SUPPORTED_1000baseKX_Full :
						SUPPORTED_1000baseT_Full;
			if (supported & SUPPORTED_1000baseKX_Full)
				advertising |= ADVERTISED_1000baseKX_Full;
			else
				advertising |= ADVERTISED_1000baseT_Full;
		}
	}
	mgb_ethtool_ksettings_fix(dev, cmd);
	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.supported,
						supported);
	ethtool_convert_legacy_u32_to_link_mode(cmd->link_modes.advertising,
						advertising);
}

static int mgb_get_link_ksettings(struct net_device *dev,
				  struct ethtool_link_ksettings *cmd)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (ep->extphyaddr == -1) {
		mgb_pcs_ethtool_ksettings_get(dev, cmd);
		return 0;
	}
	if (!dev->phydev) {
		dev_dbg_once(&dev->dev, "phydev not init\n");
		return -ENODEV;
	}

	phy_ethtool_ksettings_get(dev->phydev, cmd);
	/* bug 145704 */
	mgb_ethtool_ksettings_fix(dev, cmd);
	return 0;
}

static int mgb_set_link_ksettings(struct net_device *dev,
				  const struct ethtool_link_ksettings *cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	int r = -EOPNOTSUPP;

	if (ep->extphyaddr == -1) {
		return r;
	}
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
	struct mgb_private *ep = netdev_priv(dev);

	if (test_and_clear_bit(MGB_F_AN_DONE, &ep->an_status)) {
		set_bit(MGB_F_AN_STRT, &ep->an_status);
		clear_bit(MGB_F_AN_FAIL, &ep->an_status);
		mgb_run_auto_negotiation(dev);
	}

	return 0;
}

static u32 mgb_get_link(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	if (dev->phydev)
		return dev->phydev->link;
	else
		return ep->linkup;
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
	*buff++ = mgb_read_q_csr(ep);
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



static struct ethtool_ops mgb_ethtool_ops = {
	.supported_coalesce_params = ETHTOOL_COALESCE_USECS |
				ETHTOOL_COALESCE_MAX_FRAMES,
	.get_link_ksettings	= mgb_get_link_ksettings,
	.set_link_ksettings	= mgb_set_link_ksettings,
	.get_drvinfo		= mgb_get_drvinfo,
	.get_msglevel		= mgb_get_msglevel,
	.set_msglevel		= mgb_set_msglevel,
	.nway_reset		= mgb_nway_reset,
	.get_link		= mgb_get_link,
	.get_regs_len		= mgb_get_regs_len,
	.get_regs		= mgb_get_regs,
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
			    "    %sLSTA %sHARD %sGETH %sFETH %sFDUP %sLSTS0 %sSLST %sLSTS1 %sRLOS %sTFLT %sEMST %sPLST\n",
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
					  (val & MG_EMST)  ? "+" : "-",
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

const u_int32_t mgb_dbg_reg_id_phy[24] = {
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
	0x0010,
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
const char *mgb_dbg_reg_name_phy[24] = {
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
	"TI_PHYCR: SGMII Enable (bit 11)",
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

	if (ep->extphyaddr == -1) {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "= %s | %s - No external PHY\n",
				  ep->dev->name, pci_name(ep->pci_dev));
	} else {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "= %s | %s - PHY_IEEE registers dump (hex) =\n",
				  ep->dev->name, pci_name(ep->pci_dev));

		for (i = 0; i < ARRAY_SIZE(mgb_dbg_reg_id_phy); i++) {
			DPREG_PHY(mgb_dbg_reg_id_phy[i],
				  mgb_dbg_reg_name_phy[i]);
		}
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
		(R), val = mgb_pcs_read(ep, (R)), (N)); \
} while (0)

static char mgb_dbg_reg_pcs_buf[PAGE_SIZE] = "";

const u32 mgb_dbg_reg_id_pcs[] = {
	SR_XS_PCS_CTRL1,
	SR_XS_PCS_DEV_ID1,
	SR_XS_PCS_DEV_ID2,
	SR_XS_PCS_CTRL2,
	VR_XS_PCS_DIG_CTRL1,
	SR_MII_CTRL,
	VR_MII_AN_CTRL,
	SR_MII_AN_ADV,
	SR_MII_LP_BABL,
	SR_MII_EXT_STS,
	VR_MII_DIG_CTRL1,
	VR_MII_AN_INTR_STS,
	VR_MII_LINK_TIMER_CTRL,
	SR_VSMMD_CTRL,
	VR_AN_INTR,
	SR_AN_CTRL,
	SR_AN_STS,
	SR_AN_ADV1,
	SR_AN_ADV2,
	SR_AN_ADV3,
	SR_AN_LP_ABL1,
	SR_AN_LP_ABL2,
	SR_AN_LP_ABL3,
	SR_AN_XNP_TX1,
	SR_AN_XNP_TX2,
	SR_AN_XNP_TX3,
	SR_AN_COMP_STS,
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
	VR_XS_PMA_Gen5_12G_16G_MISC_STS,
};

const char *mgb_dbg_reg_name_pcs[] = {
	"SR_XS_PCS_CTRL1",
	"SR_XS_PCS_DEV_ID1",
	"SR_XS_PCS_DEV_ID2",
	"SR_XS_PCS_CTRL2",
	"VR_XS_PCS_DIG_CTRL1",
	"SR_MII_CTRL",
	"VR_MII_AN_CTRL",
	"SR_MII_AN_ADV",
	"SR_MII_LP_BABL: Clause 37 AN LP BP Ability(valid only for 1000BASE-X)",
	"SR_MII_EXT_STS",
	"VR_MII_DIG_CTRL1",
	"VR_MII_AN_INTR_STS",
	"VR_MII_LINK_TIMER_CTRL",
	"SR_VSMMD_CTRL",
	"VR_AN_INTR: VR AN MMD Interrupt",
	"SR_AN_CTRL: AN control (45.2.7.1: 7.0)",
	"SR_AN_STS: AN status (45.2.7.2: 7.1)",
	"SR_AN_ADV1: AN advertisement register (45.2.7.6: 7.16)",
	"SR_AN_ADV2: AN advertisement register (45.2.7.6: 7.17)",
	"SR_AN_ADV3: AN advertisement register (45.2.7.6: 7.18)",
	"SR_AN_LP_ABL1: AN LP Base Page ability (45.2.7.7: 7.19)",
	"SR_AN_LP_ABL2: AN LP Base Page ability (45.2.7.7: 7.20)",
	"SR_AN_LP_ABL3: AN LP Base Page ability (45.2.7.7: 7.21)",
	"SR_AN_XNP_TX1: AN XNP transmit (45.2.7.8: 7.22)",
	"SR_AN_XNP_TX2: AN XNP transmit (45.2.7.8: 7.23)",
	"SR_AN_XNP_TX3: AN XNP transmit (45.2.7.8: 7.24)",
	"SR_AN_COMP_STS: Backplane Ethernet, BASE-R copper status (45.2.7.12: 7.48)",
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
	"VR_XS_PMA_Gen5_12G_16G_MISC_STS",
};

static ssize_t mgb_dbg_reg_pcs_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct mgb_private *ep = filp->private_data;
	char *buf = mgb_dbg_reg_pcs_buf;
	u16 val;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - PCS registers dump (hex) =\n",
			  ep->dev->name, pci_name(ep->pci_dev));

	for (i = 0; i < ARRAY_SIZE(mgb_dbg_reg_id_pcs); i++) {
		DPREG_PCS(mgb_dbg_reg_id_pcs[i],
			  mgb_dbg_reg_name_pcs[i]);
		if (mgb_dbg_reg_id_pcs[i] == SR_AN_CTRL) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sAuto-Negotiation Enable:\n"
					"+: The host determines the link speed based on\n"
					" the outcome of the Clause 73 auto-negotiation.\n",
					(val & 0x1000)  ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == SR_AN_STS) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sLink partner AN ability\n"
					"%20sAuto-negotiation Link Status:\n"
					"+: Clause 73 auto-negotiation process is complete and the\n"
					"process successfully determined a valid link.\n"
					"%20sAN ability\n"
					"%20sRemote fault\n"
					"%20sAN complete\n"
					"%20sPage received\n",
					(val & 0x0001) ? "+" : "-",
					(val & 0x0004) ? "+" : "-",
					(val & 0x0008) ? "+" : "-",
					(val & 0x0010) ? "+" : "-",
					(val & 0x0020) ? "+" : "-",
					(val & 0x0040) ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == SR_AN_COMP_STS) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sBACKPLANE\n"
					"%20s1000BASE-KX\n",
					(val & 0x0001) ? "+" : "-",
					(val & 0x0002) ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == VR_XS_PCS_DIG_CTRL1) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sEN_2_5G_MODE\n"
					"%20sCL37_BP\n",
					(val & 0x0004) ? "+" : "-",
					(val & 0x1000) ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == VR_MII_DIG_CTRL1) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sPHY_MODE_CTRL(SGMII only)\n"
					"%20sEN_2_5G_MODE\n"
					"%20sMAC_AUTO_SW(SGMII Auto-Reconfiguration)\n"
					"%20sCL37_BP\n",
					(val & 0x0001) ? "+" : "-",
					(val & 0x0004) ? "+" : "-",
					(val & 0x0200) ? "+" : "-",
					(val & 0x1000) ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == SR_MII_AN_ADV) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sFD\n",
					(val & 0x0020)  ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == VR_MII_AN_CTRL) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20s:PCS_MODE\n"
					"%20sSGMII_LINK_STS\n",
					(val & 0x0004) ? "SGMII" : "BASE-X",
					(val & 0x0010) ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == SR_MII_LP_BABL) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sLP_FD\n"
					"%20sLP_HD\n"
					"%20sLP_PAUSE\n"
					"%20sLP_ACK\n",
					(val & 0x0020) ? "+" : "-",
					(val & 0x0040) ? "+" : "-",
					(val & 0x0180) ? "+" : "-",
					(val & 0x4000) ? "+" : "-");
		}
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

	if (strncmp(mgb_dbg_reg_ops_buf, "writephy ", 9) == 0) {
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
				 "debugfs reg_ops usage: writephy <reg> <val>\n");
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
				 "debugfs reg_ops usage: writepcs <reg> <val>\n");
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
	} else if (strncmp(mgb_dbg_reg_ops_buf, "write", 5) == 0) {
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

static int mgb_nd_number;

static int mgb_rt_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
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
	int mpllm;
	u8 mac_addr[6/*ETH_ALEN*/];

	/* check cmdline param */
	if (mgb_status[mgb_nd_number % MGB_MAX_NETDEV_NUMBER] == 0) {
		dev_info(&pdev->dev, "device %d disabled in cmdline\n",
			 mgb_nd_number);
		mgb_nd_number++;
		return -ENODEV;
	} else if (mgb_status[mgb_nd_number % MGB_MAX_NETDEV_NUMBER] > 1) {
		/* check devtree config */
		if (np) {
			of_status_prop = of_get_property(np, "status", NULL);
			if (of_status_prop) {
				if (!strcmp(of_status_prop, "disabled")) {
					dev_info(&pdev->dev,
						 "device %d disabled in devicetree\n",
						 mgb_nd_number);
					of_node_put(np);
					mgb_nd_number++;
					return -ENODEV;
				}
				dev_info(&pdev->dev,
					 "device %d enabled in devicetree\n",
					 mgb_nd_number);
			} else {
				dev_info(&pdev->dev,
					 "no status found in DT, device %d enabled!\n",
					 mgb_nd_number);
			}
		}
	} else {
		dev_info(&pdev->dev, "device %d enabled in cmdline\n",
			 mgb_nd_number);
	}

	mgb_nd_number++;
	/* PCS MPLL mode: 0-10G, 1-1G, 2-2.5G, 3-bifurcation */
	mpllm = eldwcxpcs_get_mpll_mode(pdev);
	if (mpllm < 0) {
		dev_err(&pdev->dev,
			 "wrong PCS MPLL mode (%d)\n", mpllm);
		return -ENODEV;
	} else {
		dev_dbg(&pdev->dev,
			 "PCS MPLL mode (%d)\n", mpllm);
	}
	if (mpllm == MPLL_MODE_10G) {
		if (PCI_FUNC(pdev->devfn) == 0) {
			dev_warn(&pdev->dev,
				 "1G device disabled, use 10G device\n");
			return -ENODEV;
		}
	}
	dev_info(&pdev->dev, "initializing PCI device %04x:%04x\n",
		 pdev->vendor, pdev->device);

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

	res = request_mem_region(ioaddr, MGB_TOTAL_SIZE, KBUILD_MODNAME);
	if (res == NULL) {
		dev_err(&pdev->dev, "memio address range already allocated\n"
			"mem_region: 0x%llx + 0x%llx we use len = 0x%x\n",
			ioaddr, pci_resource_len(pdev, 0), MGB_TOTAL_SIZE);
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

	dev = alloc_etherdev(sizeof(struct mgb_private));
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

	ep->mpll_mode = mpllm;
	ep->mgb_ticks_per_usec = 480;

	raw_spin_lock_init(&ep->mgio_lock);
	mutex_init(&ep->mx);
	raw_spin_lock_init(&ep->rx_lock);
	mutex_init(&ep->rx_mx);

	l_set_ethernet_macaddr(pdev, (char *)mac_addr);
	eth_hw_addr_set(dev, mac_addr);
	dev_info(&pdev->dev,
#ifdef __sparc__
		 "MAC = %012llX\n", be64_to_cpu(*(u64 *)(dev->dev_addr) >> 16));
#else
		 "MAC = %012llX\n", be64_to_cpu(*(u64 *)(dev->dev_addr) << 16));
#endif

	mgb_write_e_csr(ep, STOP); /* Stop card */
	/* Check for a valid station address */
	if (!is_valid_ether_addr(dev->dev_addr)) {
		dev_err(&pdev->dev, "card MAC address invalid\n");
		err = -EINVAL;
		goto err_iounmap;
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

	err = mgb_rt_set_rings(ep);
	if (err) {
		dev_err(&pdev->dev, "mgb_rt_set_rings failed.\n");
		goto free_init_block;
	}

	/* MGB specific entries in the device structure. */
	dev->ethtool_ops = &mgb_ethtool_ops;
	dev->netdev_ops = &mgb_netdev_ops;
	dev->watchdog_timeo = (5*HZ);



	/* check cmdline param */
	if (mgb_phy_mode[ep->nd_number] == 0) {
		ep->extphyaddr = -1;
		ep->an_sgmii = an_sgmii[ep->nd_number];
		ep->an_clause_73 = an_clause_73[ep->nd_number];
		dev_warn(&pdev->dev,
			 "disable external PHY, SFP+ selected in cmdline\n");
	} else if (mgb_phy_mode[ep->nd_number] == 1) {
		ep->an_sgmii = 1;
		ep->an_clause_73 = 0;
		dev_warn(&pdev->dev,
			 "external PHY selected in cmdline\n");
	} else {
		/* check devtree config */
		if (np) {
			if (!of_property_read_string(np, "phy-mode",
						     &of_phymode_prop)) {
				ep->an_sgmii = 1;
				ep->an_clause_73 = 0;
				dev_info(&pdev->dev, "phy-mode - %s\n",
					 of_phymode_prop);
			} else {
				ep->extphyaddr = -1;
				mgb_sfp_default_settings(ep);
				dev_info(&pdev->dev,
					"disable external PHY, use SFP+\n");
			}
		} else {
			dev_info(&pdev->dev, "sgmii = %d, clause_73 = %d\n",
				 ep->an_sgmii, ep->an_clause_73);
		}
	}

	/* PHY register mdio bus */
	err = mgb_mdio_register(ep, np);
	of_node_put(np);
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

	ep->an_status = 0;
	timer_setup(&ep->an_link_timer, mgb_link_timer, 0);
	if (an_monitor)
		timer_setup(&ep->an_monitor_timer, mgb_an_monitor_timer, 0);

	mgb_set_pcsphy_mode(dev);
#ifdef CONFIG_DEBUG_FS
	mgb_dbg_board_init(ep);
#endif /*CONFIG_DEBUG_FS*/

	dev_info(&pdev->dev, "network interface %s init done\n",
		 dev_name(&dev->dev));
	return 0;

err_mdio_unregister:
	if (ep->mii_bus)
		mdiobus_unregister(ep->mii_bus);
err_free_qs:
	dma_free_coherent(&pdev->dev,
			  sizeof(mgb_rt_dma_data_t),
			  ep->dma_data,
			  ep->dma_data_dma);
free_init_block:
	dma_free_coherent(&pdev->dev,
		sizeof(*ep->init_block),
		ep->init_block,
		ep->initb_dma);
err_free_netdev:
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

static void mgb_rt_remove(struct pci_dev *pdev)
{
	struct net_device *dev = pci_get_drvdata(pdev);
	struct mgb_private *ep = netdev_priv(dev);

	mgb_rt_close(dev);

#ifdef CONFIG_DEBUG_FS
	mgb_dbg_board_exit(ep);
#endif /*CONFIG_DEBUG_FS*/

	del_timer_sync(&ep->an_link_timer);
	if (an_monitor)
		del_timer_sync(&ep->an_monitor_timer);

	unregister_netdev(dev);

	if (ep->mii_bus) {
		mdiobus_unregister(ep->mii_bus);
	}
	dma_free_coherent(&pdev->dev,
			  sizeof(mgb_rt_dma_data_t),
			  ep->dma_data,
			  ep->dma_data_dma);
	dma_free_coherent(&pdev->dev,
		sizeof(*ep->init_block),
		ep->init_block,
		ep->initb_dma);

	free_netdev(dev);

	iounmap(ep->base_ioaddr);

	release_mem_region(dev->base_addr, MGB_TOTAL_SIZE);

	dev_set_drvdata(&pdev->dev, NULL);
	pci_disable_device(pdev);
}


const struct pci_device_id mgb_rt_pci_tbl[] = {
	{
		.vendor = PCI_VENDOR_ID_MCST_TMP,
		.device = PCI_DEVICE_ID_MCST_MGB,
		.subvendor = PCI_ANY_ID,
		.subdevice = PCI_ANY_ID,
	},
	{0, }
};

MODULE_DEVICE_TABLE(pci, mgb_rt_pci_tbl);

static struct pci_driver mgb_driver = {
	.name		= KBUILD_MODNAME,
	.id_table	= mgb_rt_pci_tbl,
	.probe		= mgb_rt_probe,
	.remove		= mgb_rt_remove,
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

#ifndef CONFIG_MCST_RT
	return -ENODEV;
#else
	int status;
	mgb_debug = netif_msg_init(debug,
		/*NETIF_MSG_DRV |*/			/* netif_msg_drv */
		/*NETIF_MSG_PROBE |*/		/* netif_msg_probe */
		NETIF_MSG_LINK |		/* netif_msg_link */
		/*NETIF_MSG_TIMER |*/		/* netif_msg_timer */
		/*NETIF_MSG_IFDOWN |*/		/* netif_msg_ifdown */
		/*NETIF_MSG_IFUP |*/		/* netif_msg_ifup */
		/*NETIF_MSG_RX_ERR |*/		/* netif_msg_rx_err */
		/*NETIF_MSG_TX_ERR |*/		/* netif_msg_tx_err */
		/*NETIF_MSG_TX_QUEUED |*/		/* netif_msg_tx_queued */
		/*NETIF_MSG_INTR  |*/		/* netif_msg_intr */
		/*NETIF_MSG_TX_DONE |*/		/* netif_msg_tx_done */
		/*NETIF_MSG_RX_STATUS |*/		/* netif_msg_rx_status */
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
#endif /* */
}

module_init(mgb_init_module);
module_exit(mgb_cleanup_module);

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("mgb_rt driver for MCST mgb ethernet card");
MODULE_VERSION(DRV_VERSION);
