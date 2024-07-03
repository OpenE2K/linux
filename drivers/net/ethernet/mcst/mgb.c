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

#define DRV_VERSION	"2.11"

/* TI DP83867 phy identifier values (not in .h) */
#define DP83867_PHY_ID		0x2000a231

/* Realtek RTL8211F phy identifier values (not in .h) */
#define RTL8211F_PHY_ID		0x001CC916

/* #define DBG_PTP */

static int assigned_speed = SPEED_1000;
module_param_named(rate, assigned_speed, int, 0444);
MODULE_PARM_DESC(rate, "used to set rate to 2500");

static int check_tx_q_ring = 0;
module_param_named(check_tx, check_tx_q_ring, int, 0444);
MODULE_PARM_DESC(check_tx, "turn on checking tx rings");

static int debug = -1;
module_param(debug, int, 0);
MODULE_PARM_DESC(debug, KBUILD_MODNAME " debug level");

/* Disable RX buffer-buffer copy */
static int rx_copybreak;
module_param(rx_copybreak, int, 0);
MODULE_PARM_DESC(rx_copybreak,
		 KBUILD_MODNAME " copy breakpoint for copy-only-tiny-frames");

static int half_duplex;
module_param_named(hd, half_duplex, int, 0444);
MODULE_PARM_DESC(hd, "work in half duplex mode");

#define MGB_MAX_NETDEV_NUMBER	(MAX_NUMNODES * 2)

static int an_clause_73[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 1};
module_param_array(an_clause_73, int, NULL, 0444);
MODULE_PARM_DESC(an_clause_73,
		 KBUILD_MODNAME " Array: apply clause 73 auto-negotiation to internal PHY");

static int an_sgmii[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 0};
module_param_array(an_sgmii, int, NULL, 0444);
MODULE_PARM_DESC(an_sgmii,
		 KBUILD_MODNAME  " Array: apply sgmii mode to clause 37 auto-negotiation for internal PHY");

static int an_monitor;
module_param(an_monitor, int, 0444);
MODULE_PARM_DESC(an_monitor,
		 KBUILD_MODNAME  " monitor auto-negotiation activity");

static int mgb_status[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 2};
module_param_array(mgb_status, int, NULL, 0444);
MODULE_PARM_DESC(mgb_status, " Array: 0 - disable, 1 - enable, other - use devtree");

static int mgb_phy_mode[MGB_MAX_NETDEV_NUMBER] = {[0 ... MGB_MAX_NETDEV_NUMBER - 1] = 2};
module_param_array(mgb_phy_mode, int, NULL, 0444);
MODULE_PARM_DESC(mgb_phy_mode, " Array: 0 - SFP+, 1 - RJ45, other - use devtree");

static int mpv_pps_in = 1;
module_param(mpv_pps_in, int, 0444);
MODULE_PARM_DESC(mpv_pps_in, "A number of mpv_in bus used to send pps signal to ethernet controller: 0-2");

static int tx_hwtstamp_filter_all = 1;
module_param(tx_hwtstamp_filter_all, int, 0644);
MODULE_PARM_DESC(tx_hwtstamp_filter_all, "1 - save hw timestamps for all sent packets");

static int rx_hwtstamp_filter_all = 1;
module_param(rx_hwtstamp_filter_all, int, 0644);
MODULE_PARM_DESC(rx_hwtstamp_filter_all, "1 - save hw timestamps for all received packets");

/* It is need TAI timestamp if PTP uses GPS/GLONAS based master clock.
 * It is need UTC timestamp if PTP uses NTP based master clock.
 * It is need to add ptp_utc2tai_offset if TAI is needed but
 * (ktime_get_clocktai_ns() - ktime_get_real()) == 0 seconds
 * while expected result =ptp_utc2tai_offset seconds.
 */
static int ptp_utc2tai_offset = 37;
module_param(ptp_utc2tai_offset, int, 0644);
MODULE_PARM_DESC(ptp_utc2tai_offset, "An offset value to convert timestamp to TAI if need");

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


static const char mgb_gstrings_test[][ETH_GSTRING_LEN] = {
	"Loopback test  (offline)"
};


#define MGB_FREQ	480000000
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

/* The socket JUMBO buffer has to fit into PAGE_SIZE.
 * MGB supports max. 4KB JUMBO size.
 */
#if defined(CONFIG_E90S)
#define MGB_BUF_LEN			(4 * 1024)
#else
#define MGB_BUF_LEN			(3 * 1024)
#endif

#define MGB_MAX_DATA_LEN	(MGB_BUF_LEN - ETH_HLEN - ETH_FCS_LEN)
#define PKT_BUF_SZ			MGB_BUF_LEN

/* Each packet consists of header 14 bytes(ETH_HLEN) +
 * [46 min - 1500 max] data + 4 bytes * crc(ETH_FCS_LEN). mgb adds
 * crc automatically when sending a packet so you havn't to take
 * care about it allocating memory for the packet being sent. As to received
 * packets mgb doesn't hew crc off so you'll have to alloc an extra 4 bytes of
 * memory in addition to common packet size
 */

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

struct mgb_rx_queue_stats {
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
	struct u64_stats_sync	syncp;
};

struct mgb_tx_queue_stats {
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
	struct u64_stats_sync	syncp;
};

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

	struct mgb_rx_queue_stats rx_stats;
	struct mgb_tx_queue_stats tx_stats;
	atomic64_t		missed_errors;
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

#define mgb_default_mode	(EPSF | EJMF)
#define enable_sent_pause_flags (PSF_ESPF | PSF_ESPC | PSF_ESPM)
/* TX Pause Frame control is disabled by default, as it may affect
 * network performance. Use ethtool -A to enable the feature.
 */
#define default_psf_csr (0)


struct mgb_stats {
	unsigned long swint;
	unsigned long merr;
	unsigned long babl;
	unsigned long cerr;
	unsigned long slve;
	/* Maximum number of packets waiting to be processed in TX queues. */
	int max_tx_q[2];
	/* Maximum number of packets waiting to be processed in RX queues. */
	int max_rx_q[2];
};

struct mgb_private {
	init_block_t		*init_block;
	dma_addr_t		initb_dma;
	unsigned long		flags;
	struct mgb_q		*mgb_qs[2];
	struct pci_dev		*pci_dev;
	struct net_device	*dev;
	struct resource		*resource;
	unsigned char		*base_ioaddr;
	raw_spinlock_t		mgio_lock;
	struct mutex		mx;
	struct mgb_stats	l_stats;
	struct workqueue_struct	*workqueue;
	struct work_struct	rx_mode_work;
	/* PHY: */
	struct mii_bus		*mii_bus;
	int			extphyaddr;	/* Address of External PHY */
	int			pcsaddr;	/* Address of Internal PHY */
	u32			pcs_dev_id;
	struct device_node	*phy_node;	/* Connection to External PHY */
	int			mpll_mode;      /* Normal=1, 2G5=2, Bif=3 */
	u32			e_cap;
	u32			irq_delay;
	u32			psf_csr;
	int			mgb_ticks_per_usec;
	unsigned char		log_rx_buffs;
	unsigned char		log_tx_buffs;
	unsigned char		linkup;
	int			nd_number;
	/* For IEEE 1588 */
	struct hwtstamp_config	hwtstamp_config;
	struct ptp_clock	*ptp_clock;
	struct ptp_clock_info	ptp_clock_info;
	s32                     phc_adjtime;
	spinlock_t		systim_lock;
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
};

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
static int mgb_change_mtu(struct net_device *dev, int new_mtu);
static int mgb_max_mtu_config(struct net_device *dev);
static u32 mgb_get_link(struct net_device *dev);
static void mgb_link_timer(struct timer_list *t);
static void mgb_an_monitor_timer(struct timer_list *t);
static void mgb_run_auto_negotiation(struct net_device *dev);
static void mgb_monitor_auto_negotiation(struct net_device *dev);

static int mgb_debug = 0;


#define mgb_netif_msg_reset(dev) \
	((dev)->msg_enable & (NETIF_MSG_RX_ERR | NETIF_MSG_TX_ERR))


static inline bool mgb_is_eiohub_proto(struct mgb_private *ep)
{
	if (is_iohub_asic(ep->pci_dev))
		return false;
	else
		return true;
}

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

static void mgb_check_phydev_link_status(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct phy_device *phydev = dev->phydev;

	if (!phydev) {
		dev_warn_once(&dev->dev, "phydev not init\n");
		return;
	}

	if (phydev->link) {
		u16 i;
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
		for (i = 0; i < dev->num_tx_queues; i++) {
			if (!ep->mgb_qs[i]->full_tx)
				netif_wake_subqueue(dev, i);
		}
		netif_carrier_on(dev);
	} else {
		if (netif_msg_link(ep) && ep->linkup)
			dev_info(&dev->dev, "link down\n");

		ep->linkup = 0;
		netif_carrier_off(dev);
		netif_tx_stop_all_queues(dev);
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

	if (!netif_running(dev)) {
		if (netif_msg_ifup(ep))
			dev_info(&dev->dev, "netif not running\n");
		return;
	}

#if 0
	/* disable auto mac control from all phys */
	unsigned long flags;
	unsigned int val;
	raw_spin_lock_irqsave(&ep->mgio_lock, flags);
	val = mgb_read_mgio_csr(ep);
	val |= MG_HARD;
	mgb_write_mgio_csr(ep, val);

	val &= ~(MG_FETH | MG_GETH | MG_FDUP | MG_SLST);
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
	if (phydev->link)
		val |= MG_SLST;

	mgb_write_mgio_csr(ep, val);
	raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
#endif

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

	if (!netif_carrier_ok(dev) &&
	    netif_msg_ifup(ep))
		dev_info(&dev->dev, "phy %s no carrier\n",
			 phydev_name(dev->phydev));

	if (netif_running(dev))
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
				dev_info(dev,
					 "AN_CL37: Auto-negotiation done: 0x%X\n",
					 r);
				if (test_bit(MGB_F_AN_SGMII, &ep->an_status)) {
					dev_info(dev,
						 "AN_CL37(SGMII): Link is %s\n",
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
				dev_info(dev,
					 "AN_CL73: Auto-negotiation done: 0x%X\n",
					 r);
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

	if (test_bit(MGB_F_AN_CL73, &ep->an_status))
		mgb_check_pcs_an_clause_73(ep);
	else if (test_bit(MGB_F_AN_CL37, &ep->an_status))
		mgb_check_pcs_an_clause_37(ep);
	else
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

	ep->pcsaddr = mgb_is_eiohub_proto(ep) ? 2 : 1;

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
	new_bus->irq[0] = PHY_IGNORE_INTERRUPT;
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
				 "register mdiobus %s (no mdio found in DT, "
				 "scan bus for phy devices)\n",
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
						"register mdiobus %s "
						"(no external phy found)\n",
						new_bus->id);

				return 0;
			}
		}
		if (phydev->phy_id == 0) {
			if (netif_msg_link(ep))
				dev_err(&pdev->dev,
					"register mdiobus %s "
					"(external phy with id=0 found, ignore it. "
					"Please, update DT!)\n",
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
		 "RX ring queue %d: max_rx_q = %u cur_rx = %u\n",
		 qn, ep->l_stats.max_rx_q[qn], q->cur_rx);

	ep->l_stats.max_rx_q[qn] = 0;

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
		 "TX ring queue %d: max_tx_q = %u cur_tx = %u, dirty_tx = %u %s\n",
		 qn, ep->l_stats.max_tx_q[qn], q->cur_tx, q->dirty_tx, q->full_tx ? " (full)" : "");
	dev_warn(&ep->dev->dev,
		 "trans_start = %lu jiffies = %lu\n",
		 netdev_get_tx_queue(ep->dev, qn)->trans_start, jiffies);

	ep->l_stats.max_tx_q[qn] = 0;

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
 * mgb_phc_adjfreq - adjust the frequency of timekeeping
 * @ptp: not used
 * @delta: Desired frequency change in parts per billion
 **/
static int mgb_phc_adjfreq(struct ptp_clock_info *ptp, s32 delta)
{
	struct __kernel_timex txc;
	s64 delta64 = delta;
	int ret;
#define NOMINAL_TICK	10000
#define ADJ_HZ	100

	memset(&txc, 0, sizeof(struct __kernel_timex));
	txc.tick = delta64 / NSEC_PER_USEC / ADJ_HZ;
	delta64 -= txc.tick * NSEC_PER_USEC * ADJ_HZ;
	txc.freq = (delta64 << 16) / NSEC_PER_USEC;
	txc.tick += NOMINAL_TICK;
	txc.modes = ADJ_FREQUENCY | ADJ_TICK;
	ret = do_adjtimex(&txc);
#ifdef DBG_PTP
	pr_warn("%s tick %lld freq %lld ret %d\n",
		 __func__, txc.tick, txc.freq, ret);
#endif
	return ret;
}

/*
 * mgb_phc_adjtime - Shift the time of the hardware clock
 * @ptp: not used
 * @delta: Desired change in nanoseconds
 */
/* Adjust the timer */
static int mgb_phc_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct mgb_private *ep = container_of(ptp, struct mgb_private,
					      ptp_clock_info);
	ep->phc_adjtime += delta;
	return 0;
}

/**
 * mgb_phc_gettime - Reads the current time from the hardware clock
 * @ptp: ptp clock structure
 * @ts: timespec structure to hold the current time value
 *
 * Read the time
 **/
static int mgb_phc_gettimex(struct ptp_clock_info *ptp, struct timespec64 *ts,
			    struct ptp_system_timestamp *sts)
{
	struct mgb_private *ep = container_of(ptp, struct mgb_private,
					      ptp_clock_info);
	ptp_read_system_prets(sts);
	*ts = ktime_to_timespec64(ktime_get_clocktai_ns() + ep->phc_adjtime
		+ ptp_utc2tai_offset);
#ifdef DBG_PTP
	pr_warn("%s tai - utc = %lld - %lld = %lld seconds\n",
		 __func__, ktime_get_clocktai_ns() / NSEC_PER_SEC,
		ktime_get_real() / NSEC_PER_SEC,
		(ktime_get_clocktai_ns() - ktime_get_real()) / NSEC_PER_SEC);
#endif
	ptp_read_system_postts(sts);
	return 0;
}

/**
 * mgb_phc_settime - Set the current time on the hardware clock
 * @ptp: ptp clock structure
 * @ts: timespec containing the new time for the cycle counter
 *
 * Set timcounter offset
 **/
static int mgb_phc_settime(struct ptp_clock_info *ptp,
			      const struct timespec64 *ts)
{
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
	return -ENOTSUPP;
}

static struct ptp_clock_info mgb_ptp_clock_info = {
	.owner		= THIS_MODULE,
	.n_alarm	= 0,
	.n_ext_ts	= 0,
	.n_per_out	= 0,
	.pps		= 0,
	.max_adj	= 1000000000,
	.adjfreq	= mgb_phc_adjfreq,
	.adjtime	= mgb_phc_adjtime,
	.gettimex64	= mgb_phc_gettimex,
	.settime64	= mgb_phc_settime,
	.enable		= mgb_phc_enable,
};

/**
 * mgb_hwtstamp - utility function for IEEE 1588 in IOHUB2
 * @ep: board private structure
 * @skb: particular skb to include time stamp
 * @entry: descriptor entry
 *
 * If the time stamp is valid, convert it into the ns value
 * and store that result into the shhwtstamps structure which is passed
 * up the network stack.
 **/
static void mgb_hwtstamp(struct mgb_private *ep, struct sk_buff *skb,
	u32 etmr)
{
	struct skb_shared_hwtstamps *hwtstamps;
	int mgb_freq = MGB_FREQ;
	s64 ns_mgb, now_tai;
	s64 ns_clksrc, delta, sec_clksrc;

	now_tai = ktime_get_clocktai_ns() + ptp_utc2tai_offset * NSEC_PER_SEC;
	if (!ep->ptp_clock)
		return;
	hwtstamps = skb_hwtstamps(skb);
	memset(hwtstamps, 0, sizeof(*hwtstamps));
	if (unlikely(etmr > mgb_freq)) {
#ifdef DBG_PTP
		pr_warn("%s ERR etmr %d 0x%x > mgb_freq %d\n", __func__,
			etmr, etmr, mgb_freq);
#endif
		hwtstamps->hwtstamp = now_tai;
		return;
	}
#ifdef CONFIG_E2K
	ns_clksrc = read_sclkr_sync();
#else
	ns_clksrc = read_clk_rt(NULL);
#endif
	delta = now_tai - ns_clksrc;
	sec_clksrc = ns_clksrc % NSEC_PER_SEC;
	if (mpv_get_freq_ptr)
		mgb_freq = mpv_get_freq_ptr(mpv_pps_in);

	if (mgb_freq <= 0) {
		dev_warn(&ep->dev->dev,
			"mgb_hwtstamp: ERROR mgb_freq=%d\n", mgb_freq);
		return;
	}
	ns_mgb = (ns_clksrc / NSEC_PER_SEC) * NSEC_PER_SEC +
					etmr * NSEC_PER_SEC / mgb_freq;
	if (ns_mgb > ns_clksrc)
		ns_mgb -= NSEC_PER_SEC;
	hwtstamps->hwtstamp = ns_mgb + delta + ep->phc_adjtime;
#ifdef DBG_PTP
	pr_warn("%s %s e_tmr=%d now_tai - hwts = %lld - %lld = %lld now_tai-get_clocktai= %lld\n",
		 __func__, (!!in_irq()) ? "tx" : "rx" ,
		etmr, now_tai, hwtstamps->hwtstamp, now_tai - hwtstamps->hwtstamp,
		now_tai - ktime_get_clocktai_ns());
#endif
	/* hwtstamps->hwtstamp = now_tai;  //  for experimental comparison */
}

/** TITLE: BUFFER RINGS handling */

static void mgb_free_skbs(struct pci_dev *pdev, struct sk_buff **skbs,
		dma_addr_t *dmas, int ring_sz, int dir)
{
	int i;

	for (i = 0; i < ring_sz; i++) {
		if (skbs[i]) {
			BUG_ON(dmas[i] == 0);
			pci_unmap_single(pdev, dmas[i],
					 (dir == PCI_DMA_FROMDEVICE) ?
						PKT_BUF_SZ :
						skbs[i]->len,
					 dir);
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
	int node = dev_to_node(&ep->pci_dev->dev);

	q = kzalloc_node(sizeof(struct mgb_q), GFP_KERNEL, node);
	if (!q) {
		return -ENOMEM;
	}
	ep->mgb_qs[nq] = q;
	q->ep = ep;
	raw_spin_lock_init(&q->lock);
	atomic64_set(&q->missed_errors, 0);

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
	int node;

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
	node = dev_to_node(&ep->pci_dev->dev);
	q->rx_skbuff = kzalloc_node(sizeof(struct sk_buff *) * RX_RING_SIZE,
				    GFP_KERNEL, node);
	if (!q->rx_skbuff) {
		goto nomem;
	}
	q->tx_skbuff = kzalloc_node(sizeof(struct sk_buff *) * TX_RING_SIZE,
				    GFP_KERNEL, node);
	if (!q->tx_skbuff) {
		goto nomem;
	}
	q->rx_dma_skbuff = kzalloc_node(sizeof(dma_addr_t) * RX_RING_SIZE,
					GFP_KERNEL, node);
	if (!q->rx_dma_skbuff) {
		goto nomem;
	}
	q->tx_dma_skbuff = kzalloc_node(sizeof(dma_addr_t) * TX_RING_SIZE,
					GFP_KERNEL, node);
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
			rx_skbuff = netdev_alloc_skb(ep->dev, PKT_BUF_SZ + 2);
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
				rx_skbuff->data, PKT_BUF_SZ,
				PCI_DMA_FROMDEVICE);
			if (pci_dma_mapping_error(ep->pci_dev,
				q->rx_dma_skbuff[i])) {
				q->rx_dma_skbuff[i] = 0;
				return 1;
			}
		}
		rxr->base = cpu_to_le32((u32)(q->rx_dma_skbuff[i]));
		rxr->buf_length = cpu_to_le16(-(PKT_BUF_SZ));
		/* HW sync */
		wmb();
		rxr->status |= cpu_to_le16(RD_OWN);
	}

	/* There is no point to try resending all this staff because 5 secs
	 * timeout is too long for network connections. All these packets are
	 * already outdated and may be already retransmitted by peers several
	 * times. Let's just drop all of them.
	 */
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
		ep->l_stats.max_rx_q[0] = 0;
		ep->l_stats.max_tx_q[0] = 0;
		r = mgb_reset_queue(ep->mgb_qs[0]);
		if (r) {
			return r;
		}
	}
	if (ep->mgb_qs[1]) {
		ep->l_stats.max_rx_q[1] = 0;
		ep->l_stats.max_tx_q[1] = 0;
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
		snprintf(mq->rx_name, IFNAMSIZ, "%s-rx-0", mq->ep->dev->name);
		return mq->rx_name;
	case MGB_T0_INTR:
		snprintf(mq->tx_name, IFNAMSIZ, "%s-tx-0", mq->ep->dev->name);
		return mq->tx_name;
	case MGB_R1_INTR:
		snprintf(mq->rx_name, IFNAMSIZ, "%s-rx-1", mq->ep->dev->name);
		return mq->rx_name;
	case MGB_T1_INTR:
		snprintf(mq->tx_name, IFNAMSIZ, "%s-tx-1", mq->ep->dev->name);
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
	if (num_online_cpus() < 2) {
		return;
	}
	cpumask_copy(&dev_m, cpumask_of_node(dev_to_node(&ep->dev->dev)));
	do {
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
	} while (step < 4);
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

	ep->linkup = 0;
	ep->e_cap = IPV4_HCS_ENA_RX | IPV4_HCS_ENA_TX |
			TCP_PCS_ENA_RX | TCP_PCS_ENA_TX |
			UDP_PCS_ENA_RX | UDP_PCS_ENA_TX;

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
	flush_workqueue(ep->workqueue);
	destroy_workqueue(ep->workqueue);
	del_timer_sync(&ep->an_link_timer);
	if (an_monitor)
		del_timer_sync(&ep->an_monitor_timer);
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

	/* No fragments! */
	if (ip_is_fragment(ip_hdr(skb)))
		goto calc_sum;

	if (skb->csum_offset == offsetof(struct tcphdr, check)) {
		ip_hdr(skb)->check = 0;
		tcp_hdr(skb)->check = 0;
		return TD_IHCS | TD_TPCS;
	}
	if (skb->csum_offset == offsetof(struct udphdr, check)) {
		ip_hdr(skb)->check = 0;
		udp_hdr(skb)->check = 0;
		return TD_IHCS | TD_UPCS;
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

	status = TD_OWN | TD_ENP | TD_STP |
		mgb_get_tx_csum_flags(ep, skb);

	dmaaddr = pci_map_single(ep->pci_dev, skb->data, len,
			PCI_DMA_TODEVICE);
	if (pci_dma_mapping_error(ep->pci_dev, dmaaddr)) {
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: queue %d Could not map skb\n",
				 __func__, nq);
		dev_kfree_skb_any(skb);

		return NETDEV_TX_OK;
	}
	raw_spin_lock_irqsave(&q->lock, flags);

	if (unlikely(q->full_tx)) {
		raw_spin_unlock_irqrestore(&q->lock, flags);
		pci_unmap_single(ep->pci_dev, dmaaddr,
				 len, PCI_DMA_TODEVICE);
		dev_kfree_skb_any(skb);

		return NETDEV_TX_OK;
	}

	if (mgb_set_flag_bit(MGB_F_XMIT + nq, &ep->flags)) {
		raw_spin_unlock_irqrestore(&q->lock, flags);
		pci_unmap_single(ep->pci_dev, dmaaddr,
				 len, PCI_DMA_TODEVICE);
		if (netif_msg_tx_queued(ep))
			dev_info(&dev->dev,
				 "%s: queue %d xmit stopped by reset.\n",
				 __func__, nq);
		dev_kfree_skb_any(skb);

		return NETDEV_TX_OK;
	}
	check_tx_ring(q, "start_xmit begin");

	if (unlikely(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP) &&
	    ((ep->e_cap & (ETMR_ADD_ENA | ETMR_CLR_ENA)) ==
	    (ETMR_ADD_ENA | ETMR_CLR_ENA)))
		skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;

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

	if (netif_msg_tx_queued(ep)) {
		dev_info(&dev->dev,
			 "%s: queue %d: base: 0x%x; cur = %d, dirty = %d, "
			 "buf_len: %d status: 0x%x; Q_CSR = 0x%08x ip_summed = %d\n",
			 __func__, nq,
			 le32_to_cpu(q->tx[entry].base), entry, q->dirty_tx,
			 len,
			 le16_to_cpu(q->tx[entry].status),
			 mgb_read_q_csr(ep, nq),
			 skb->ip_summed);
		mgb_dump_skb_data(ep, nq, skb);
	}

	q->cur_tx = (entry + 1) & TX_RING_MOD_MASK;
	if (((q->cur_tx + 1) & TX_RING_MOD_MASK) == q->dirty_tx) {
		if (netif_msg_tx_err(ep) || netif_msg_tx_queued(ep)) {
			dev_info(&dev->dev,
				 "queue %d: transmitter queue is full "
				 "cur_tx = %d, dirty_tx =%d, status = %04x\n",
				 nq, q->cur_tx, q->dirty_tx,
				 le16_to_cpu(q->tx[q->cur_tx].status));
		}
		q->full_tx = 1;
		u64_stats_update_begin(&q->tx_stats.syncp);
		q->tx_stats.compressed++;
		u64_stats_update_end(&q->tx_stats.syncp);
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

	if (ep->pci_dev->revision < 3) {
		/* bug 145701: All outgoing traffic is redirected to the 0th queue. */
		r_idx = 0;
	} else {
		if (r_idx >= ep->dev->num_tx_queues)
			r_idx = r_idx % ep->dev->num_tx_queues;
	}

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
	int nq = mgb_nq(ep, q);
	unsigned long flags;
	int count = 0;

	raw_spin_lock_irqsave(&q->lock, flags);
	dirty_tx = q->dirty_tx;

	delta = (q->cur_tx - dirty_tx) & (TX_RING_MOD_MASK);
	if (delta == 0 && q->full_tx)
		delta = TX_RING_SIZE;
	if (ep->l_stats.max_tx_q[nq] < delta)
		ep->l_stats.max_tx_q[nq] = delta;

	if (unlikely(!delta && !(q->tx[q->dirty_tx].status))) {
		raw_spin_unlock_irqrestore(&q->lock, flags);
		return 0;
	}
	while (((dirty_tx + 1) & (TX_RING_MOD_MASK)) != q->cur_tx) {
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

		count++;

		if (unlikely(status & TD_ERR)) {
			/* There was an major error, log it. */
			u32 err_status = le32_to_cpu(tx_ring->misc);

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

			u64_stats_update_begin(&q->tx_stats.syncp);
			q->tx_stats.errors++;
			if (err_status & TD_RTRY)
				q->tx_stats.aborted_errors++;
			if (err_status & TD_LCAR)
				q->tx_stats.carrier_errors++;
			if (err_status & TD_LCOL)
				q->tx_stats.window_errors++;
			if (err_status & TD_UFLO) {
				q->tx_stats.fifo_errors++;
				must_restart = 1;
			}
			u64_stats_update_end(&q->tx_stats.syncp);
			if (must_restart)
				break;
		} else if (unlikely(status & (TD_MORE | TD_ONE))) {
			u64_stats_update_begin(&q->tx_stats.syncp);
			q->tx_stats.collisions++;
			u64_stats_update_end(&q->tx_stats.syncp);
			if (netif_msg_tx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: Tx collision "
					 "on %d status=%04x\n",
					 nq, entry, status);
		}

		tx_ring->base = 0;
		tx_ring->status = 0;

		/* We must free the original skb */
		if (likely(q->tx_skbuff[entry])) {
			dma_addr_t dmaaddr = q->tx_dma_skbuff[entry];
			struct sk_buff *skb = q->tx_skbuff[entry];
			u32 et = le32_to_cpu(tx_ring->etmr);

			u64_stats_update_begin(&q->tx_stats.syncp);
			q->tx_stats.bytes += skb->len;
			q->tx_stats.packets++;
			u64_stats_update_end(&q->tx_stats.syncp);

			if (unlikely(tx_hwtstamp_filter_all ||
			    (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)) &&
			    ((ep->e_cap & (ETMR_ADD_ENA | ETMR_CLR_ENA)) ==
				(ETMR_ADD_ENA | ETMR_CLR_ENA))) {
				mgb_hwtstamp(ep, skb, et);
#ifdef DBG_PTP
				dev_info(&dev->dev,
					"%s: TX e_tmr=%d hwts=%lld ktime=%lld tx_flags 0x%x\n",
					__func__, et, skb_hwtstamps(skb)->hwtstamp,
					ktime_get_ns(), skb_shinfo(skb)->tx_flags);
#endif
				/* Notify the stack */
				if (skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP)
					skb_tstamp_tx(skb, skb_hwtstamps(skb));
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

	if (count)
		netdev_get_tx_queue(dev, nq)->trans_start = jiffies;

	raw_spin_unlock_irqrestore(&q->lock, flags);

	if (must_restart)
		mgb_write_e_csr(ep, INEA | SWINT);

	if (count)
		return 1;

	return 0;
}


/** TITLE: RECEIVE stuff */

static void mgb_handle_rx_err(struct mgb_q *q, int nq, s16 status)
{
	struct mgb_private *ep = q->ep;

	if (netif_msg_rx_err(ep))
		dev_info(&ep->dev->dev,
			 "queue %d receiver error: status = 0x%x ",
			 nq, status);

	u64_stats_update_begin(&q->rx_stats.syncp);
	q->rx_stats.errors++;
	if (status & RD_FRAM)
		q->rx_stats.frame_errors++;
	if (status & RD_OFLO)
		q->rx_stats.over_errors++;
	if (status & RD_CRC)
		q->rx_stats.crc_errors++;
	if (status & RD_BUFF)
		q->rx_stats.fifo_errors++;
	u64_stats_update_end(&q->rx_stats.syncp);
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
			mgb_handle_rx_err(q, nq, status);
			q->rx[entry].status &= cpu_to_le16(RD_ENP|RD_STP);
			goto next_pkt;
		}
		/* Malloc up new buffer, compatible with net-2e. */
		pkt_len = (le16_to_cpu(q->rx[entry].msg_length) &
				 0xfff) - ETH_FCS_LEN;

		/* Discard oversize frames. */
		if (unlikely(pkt_len > (dev->mtu + ETH_HLEN))) {
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: %s wrong packet size %d!\n",
					 nq, __func__, pkt_len);

			u64_stats_update_begin(&q->rx_stats.syncp);
			q->rx_stats.length_errors++;
			u64_stats_update_end(&q->rx_stats.syncp);
			goto next_pkt;
		}
		if (unlikely(pkt_len < ETH_ZLEN)) {
			if (netif_msg_rx_err(ep))
				dev_info(&dev->dev,
					 "queue %d: Runt packet!\n", nq);

			u64_stats_update_begin(&q->rx_stats.syncp);
			q->rx_stats.length_errors++;
			u64_stats_update_end(&q->rx_stats.syncp);
			goto next_pkt;
		}
		pci_dma_sync_single_for_cpu(ep->pci_dev,
					q->rx_dma_skbuff[entry],
					PKT_BUF_SZ,
					PCI_DMA_FROMDEVICE);
		rx_in_place = 0;
		if (pkt_len > rx_copybreak) {
			struct sk_buff *newskb;
			if ((newskb = netdev_alloc_skb(dev,
				(PKT_BUF_SZ + 2)))) {
				skb_reserve(newskb, 2);
				dma_addr_t a = pci_map_single(ep->pci_dev,
							newskb->data,
							PKT_BUF_SZ,
							PCI_DMA_FROMDEVICE);
				if (pci_dma_mapping_error(ep->pci_dev, a)) {
					skb = newskb;
					goto still_copy;
				}
				skb = q->rx_skbuff[entry];
				q->rx_skbuff[entry] = newskb;
				pci_unmap_single(ep->pci_dev,
					q->rx_dma_skbuff[entry],
					PKT_BUF_SZ,
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
			q->rx[entry].status = cpu_to_le16(RD_OWN);
			break;
		}
		if ((ep->e_cap & (ETMR_ADD_ENA | ETMR_CLR_ENA)) ==
			(ETMR_ADD_ENA | ETMR_CLR_ENA)) {
			u32 et = le32_to_cpu(q->rx[entry].etmr);
			mgb_hwtstamp(ep, skb, et);
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
				 "queue %d: %s received pkt len = %d status = 0x%04X\n",
				 nq, __func__, skb->len, status);
			mgb_dump_skb_data(ep, nq, skb);
		}

		u64_stats_update_begin(&q->rx_stats.syncp);
		if (likely(status & (RD_TPCS | RD_UPCS | RD_IHCS))) {
			if (unlikely(status & RD_CSER)) {
				skb_checksum_none_assert(skb);
				q->rx_stats.crc_errors++;
			} else {
				skb->ip_summed = CHECKSUM_UNNECESSARY;
				skb->csum_level = 0;
			}
		}
		q->rx_stats.bytes += skb->len;
		q->rx_stats.packets++;
		if (status & RD_LAFM)
			q->rx_stats.multicast++;
		u64_stats_update_end(&q->rx_stats.syncp);

		skb->protocol = eth_type_trans(skb, dev);
		/* Include GRO processing */
		napi_gro_receive(&q->napi, skb);
		work_done++;
next_pkt:
		q->rx[entry].buf_length = cpu_to_le16(-(PKT_BUF_SZ));
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

	if (ep->l_stats.max_rx_q[nq] < work_done)
		ep->l_stats.max_rx_q[nq] = work_done;

	return work_done;
}


/** TITLE: MGB interrupt handlers stuff. */

static int mgb_poll(struct napi_struct *napi, int budget)
{
	struct mgb_q *q = container_of(napi, struct mgb_q, napi);
	struct mgb_private *ep = q->ep;
	int nq = mgb_nq(ep, q);
	int work_done = 0;

	if (test_bit(MGB_F_TX_NAPI + nq, &ep->flags)) {
		int done;

		if (netif_msg_rx_status(ep))
			dev_info(&ep->dev->dev,
				"TX queue %d: %s started\n", nq, __func__);
repeat_tx:
		done = mgb_tx(q);
		mgb_write_q_csr(ep, nq, Q_TINT | Q_TINT_EN);
		if (!done)
			goto done_tx;
		if (!(le16_to_cpu(q->tx[q->dirty_tx].status) & TD_OWN) &&
			(q->tx[q->dirty_tx].status != 0)) {
			mgb_write_q_csr(ep, nq, Q_TINT | Q_C_TINT_EN);
			goto repeat_tx;
		}
done_tx:
		clear_bit(MGB_F_TX + nq, &ep->flags);
		clear_bit(MGB_F_TX_NAPI + nq, &ep->flags);
	}

	if (test_bit(MGB_F_RX_NAPI + nq, &ep->flags)) {
		if (netif_msg_rx_status(ep))
			dev_info(&ep->dev->dev,
				"RX queue %d: %s started\n", nq, __func__);
repeat_rx:
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

			goto repeat_rx;
		}
		clear_bit(MGB_F_RX + nq, &ep->flags);
		clear_bit(MGB_F_RX_NAPI + nq, &ep->flags);
	}
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
		atomic64_inc(&q->missed_errors); /* Missed a Rx frame. */
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
		if (!test_bit(MGB_F_RX_NAPI + nq, &ep->flags)) {
			if (mgb_set_flag_bit(MGB_F_RX + nq, &ep->flags)) {
				return IRQ_HANDLED;
			}
			mgb_write_q_csr(ep, nq, Q_RINT | Q_MISS |
					Q_C_RINT_EN | Q_C_MISS_EN);
			set_bit(MGB_F_RX_NAPI + nq, &ep->flags);
			napi_schedule(&q->napi);
			if (netif_msg_intr(ep))
				dev_info(&dev->dev, "queue RX %d: napi scheduled\n", nq);
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

	mgb_write_q_csr(ep, nq, Q_TINT);
	if (!test_bit(MGB_F_TX_NAPI + nq, &ep->flags)) {
		if (mgb_set_flag_bit(MGB_F_TX + nq, &ep->flags)) {
			return IRQ_HANDLED;
		}
		mgb_write_q_csr(ep, nq, Q_TINT | Q_C_TINT_EN);
		set_bit(MGB_F_TX_NAPI + nq, &ep->flags);
		napi_schedule(&q->napi);
		if (netif_msg_intr(ep))
			dev_info(&dev->dev, "queue TX %d: napi scheduled\n", nq);
	}

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

	mgb_write_e_cap(ep, ep->e_cap);
	mgb_write_q_csr(ep, 0, Q_TINT_EN | Q_RINT_EN | Q_MISS_EN);
	if (ep->mgb_qs[1]) {
		mgb_write_q_csr(ep, 1, Q_TINT_EN | Q_RINT_EN | Q_MISS_EN);
	}
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

	mgb_write_psf_csr(ep, ep->psf_csr);
	mgb_write_psf_data(ep, 0);	/* we have no plans to
					 * send PAUSE FRAME manually
					 */
	mgb_write_psf_data1(ep, 64 | (64 << 16));
	mgb_write_irq_delay(ep, ep->irq_delay);
	mgb_write_rx_queue_arb(ep, ep->mgb_qs[1] ?
		(1 << 11) | 5 : /* MACSUM_ADDDEST + hwd_def2 */
		0);
}

static void mgb_phy_reset(struct mgb_private *ep)
{
	struct phy_device *phydev = ep->dev->phydev;

	if (ep->extphyaddr == -1)
		return;

	if (phydev && (phydev->phy_id == RTL8211F_PHY_ID)) {
		unsigned long flags;
		u32 r;

		raw_spin_lock_irqsave(&ep->mgio_lock, flags);
		r = mgb_read_mgio_csr(ep);
		r &= ~MG_W1C_MASK;
		r |= MG_SRST;				/* RST */
		mgb_write_mgio_csr(ep, r);	/* software reset */
		r &= ~MG_SRST;				/* ~RST */
		mdelay(20);					/* 10ms min */
		mgb_write_mgio_csr(ep, r);
		raw_spin_unlock_irqrestore(&ep->mgio_lock, flags);
		mdelay(100);				/* wait for reset min 15ms@156 */
	}
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
			"initialization not completed,"
			" not IDON. e_csr = 0x%x\n",
			mgb_read_e_csr(ep));
		return 1;
	}
	mgb_phy_reset(ep);
	mgb_set_regs_after_reset(ep);
	mgb_write_e_csr(ep, INEA);

	if (mgb_netif_msg_reset(ep))
		dev_info(&ep->dev->dev, "Card started\n");

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
		u16 i;

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
		for (i = 0; i < dev->num_tx_queues; i++) {
			if (!ep->mgb_qs[i]->full_tx) {
				netif_wake_subqueue(dev, i);
			}
		}
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
	struct mgb_private *ep = (struct mgb_private *)dev_id;
	struct net_device *dev = ep->dev;
	int i;
	unsigned long flags;

	if (mgb_netif_msg_reset(ep))
		dev_info(&dev->dev, "reset started\n");

	local_irq_save(flags);
	netif_tx_lock(dev);
	if (mgb_wait_for_freeze(&ep->flags)) {
		dev_err(&dev->dev,
			"%s: Could not freeze card. f = 0x%0lx\n",
			__func__, ep->flags);
		mgb_write_e_csr(ep, 0);
		netif_tx_unlock(dev);
		local_irq_restore(flags);

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
		local_irq_restore(flags);

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
	local_irq_restore(flags);

	if (ep->extphyaddr == -1)
		mgb_check_link_status(ep, mgb_read_mgio_csr(ep));
	else
		mgb_check_phydev_link_status(dev);

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

static void mgb_get_stats64(struct net_device *dev, struct rtnl_link_stats64 *stats)
{
	struct mgb_private *ep = netdev_priv(dev);
	int i;
	int nqs = dev->num_tx_queues;

	for (i = 0; i < nqs; i++) {
		struct mgb_q *q = ep->mgb_qs[i];

		if (q) {
			unsigned int start;

			do {
				start = u64_stats_fetch_begin_irq(&q->rx_stats.syncp);
				stats->rx_packets	+= q->rx_stats.packets;
				stats->rx_bytes		+= q->rx_stats.bytes;
				stats->rx_errors	+= q->rx_stats.errors;
				stats->rx_dropped	+= q->rx_stats.dropped;
				stats->rx_length_errors	+= q->rx_stats.length_errors;
				stats->rx_over_errors	+= q->rx_stats.over_errors;
				stats->rx_crc_errors	+= q->rx_stats.crc_errors;
				stats->rx_frame_errors	+= q->rx_stats.frame_errors;
				stats->rx_fifo_errors	+= q->rx_stats.fifo_errors;
				stats->multicast	+= q->rx_stats.multicast;
			} while (u64_stats_fetch_retry_irq(&q->rx_stats.syncp, start));

			stats->rx_missed_errors	+= atomic64_read(&q->missed_errors);

			do {
				start = u64_stats_fetch_begin_irq(&q->tx_stats.syncp);
				stats->tx_packets	+= q->tx_stats.packets;
				stats->tx_bytes		+= q->tx_stats.bytes;
				stats->tx_errors	+= q->tx_stats.errors;
				stats->tx_dropped	+= q->tx_stats.dropped;
				stats->collisions	+= q->tx_stats.collisions;
				stats->tx_aborted_errors	+= q->tx_stats.aborted_errors;
				stats->tx_carrier_errors	+= q->tx_stats.carrier_errors;
				stats->tx_fifo_errors	+= q->tx_stats.fifo_errors;
				stats->tx_heartbeat_errors	+= q->tx_stats.heartbeat_errors;
				stats->tx_window_errors	+= q->tx_stats.window_errors;
				stats->tx_compressed	+= q->tx_stats.compressed;
			} while (u64_stats_fetch_retry_irq(&q->tx_stats.syncp, start));
		}
	}
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
		ib->laddrf0 |= cpu_to_le64(1UL << crc);
	}
	ib->laddrf1 = ib->laddrf0;
	return;
}

static void mgb_write_init_block_mode(struct mgb_private *ep)
{
	int i;
	u32 paddr_l_mode;
	u32 paddr_h;

	mgb_write_sh_init_cntrl(ep, SH_R_MODE_PADDR0);

	i = 0;
	while (mgb_read_sh_init_cntrl(ep) & SH_R_MODE_PADDR0 && i++ < 100)
		udelay(1);

	if (i >= 100) {
		dev_err(&ep->dev->dev,
			"%s: bit SH_R_PROM_PADDR0 stuck\n", __func__);
		return;
	}

	paddr_l_mode = mgb_read_sh_data_l(ep);
	paddr_h = mgb_read_sh_data_h(ep);
	mgb_write_sh_data_h(ep, paddr_h);
	mgb_write_sh_data_l(ep, ((paddr_l_mode & 0xFFFF0000) |
			(le16_to_cpu(ep->init_block->mode))));
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

static void mgb_set_rx_mode(struct net_device *dev)
{
	struct mgb_private *ep = netdev_priv(dev);

	queue_work(ep->workqueue, &ep->rx_mode_work);
}

static void mgb_set_multicast_list(struct work_struct *work)
{
	struct mgb_private *ep = container_of(work, struct mgb_private,
				rx_mode_work);
	struct net_device *dev = ep->dev;
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
		mgb_write_sh_data_h(ep, le64_to_cpu(ep->init_block->laddrf0) >> 32);
		mgb_write_sh_data_l(ep, le64_to_cpu(ep->init_block->laddrf0) & 0xffffffff);
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
		mgb_write_sh_data_h(ep, le64_to_cpu(ep->init_block->laddrf1) >> 32);
		mgb_write_sh_data_l(ep, le64_to_cpu(ep->init_block->laddrf1) & 0xffffffff);
		mgb_write_sh_init_cntrl(ep, SH_W_LADDRF1);
		i = 0;
		while (mgb_read_sh_init_cntrl(ep) & SH_W_LADDRF1 &&
			i++ < 100) {
			udelay(1);
		}
		if (i >= 100) {
			dev_err(&dev->dev,
				"%s: bit SH_W_LADDRF1 stuck\n", __func__);
			goto unlock;
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

/*
 * mgb_ptp_get_ts_config - get hardware time stamping config
 */
static int mgb_ptp_get_ts_config(struct net_device *dev, struct ifreq *rq)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct hwtstamp_config config = ep->hwtstamp_config;

	return copy_to_user(rq->ifr_data, &config, sizeof(config)) ?
		-EFAULT : 0;
}

/*
 * mgb_ptp_set_ts_config - set hardware time stamping config
 */
static int mgb_ptp_set_ts_config(struct net_device *dev, struct ifreq *rq)
{
	struct mgb_private *ep = netdev_priv(dev);
	struct hwtstamp_config config;

	if (copy_from_user(&config, rq->ifr_data, sizeof(config)))
		return -EFAULT;
	if (config.rx_filter == HWTSTAMP_FILTER_NONE) {
		ep->e_cap &= ~(ETMR_ADD_ENA | ETMR_CLR_ENA);
	} else {
		ep->e_cap |= (ETMR_ADD_ENA | ETMR_CLR_ENA);
	}
	mgb_write_e_cap(ep, ep->e_cap);

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
	/* save these settings for future reference */
	ep->hwtstamp_config = config;

	return copy_to_user(rq->ifr_data, &config, sizeof(config)) ?
		-EFAULT : 0;
}

static int mgb_ioctl(struct net_device *dev, struct ifreq *rq, int cmd)
{
	struct mgb_private *ep = netdev_priv(dev);
	int rc = -EOPNOTSUPP;

	switch (cmd) {
	case SIOCDEVPRIVATE + 10:
		mutex_lock(&mgb_mutex);
		mgb_dump_init_block(dev);
		mgb_dump_queues_state(dev);
		mutex_unlock(&mgb_mutex);
		return 0;
	case SIOCGHWTSTAMP:
		return mgb_ptp_get_ts_config(dev, rq);
	case SIOCSHWTSTAMP:
		return mgb_ptp_set_ts_config(dev, rq);
	default:
		/* SIOC[GS]MIIxxx ioctls */
		if (mgb_is_eiohub_proto(ep)) {
			rc = -EOPNOTSUPP;
		} else {
			if (dev->phydev) {
				rc = phy_mii_ioctl(dev->phydev, rq, cmd);
			} else {
				dev_dbg_once(&dev->dev, "phydev not init\n");
				rc = -EOPNOTSUPP;
			}
		}
	}
	return rc;
}

static void mgb_tx_timeout(struct net_device *dev, unsigned int txqueue)
{
	struct mgb_private *ep = netdev_priv(dev);
	int i;
	int clean_queues = 0;
	int num_queues = dev->num_tx_queues;
	u32 e_csr;

	if (!ep->linkup)
		return;

	e_csr = mgb_read_e_csr(ep);

	/* The __QUEUE_STATE_DRV_XOFF flag is used by driver to stop
	 * the transmit queue. This usually happens only in one case:
	 * if the queue is full (see mgb_start_xmit_to_q).
	 * The netif_tx_* functions are used to manipulate this flag.
	 * The __QUEUE_STATE_STACK_XOFF flag is used by the network
	 * stack to stop the transmit queue independently.
	 * The netif_xmit_stopped() is called by dev_watchdog() to check
	 * if the queue has been stopped by the driver or stack (either
	 * of the XOFF bits are set in the state). The driver should only
	 * check __QUEUE_STATE_DRV_XOFF here. If it's up, this is
	 * a serious reason to reset hw. Otherwise, just ignore this call.
	 */

	for (i = 0; i < num_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

		if (netif_tx_queue_stopped(txq)) {
			dev_err(&dev->dev, "TX queue %d is stopped by driver.\n", i);
			continue;
		}
		clean_queues++;
	}

	mutex_lock(&mgb_mutex);
	mgb_dump_init_block(dev);
	mgb_dump_queues_state(dev);
	mutex_unlock(&mgb_mutex);

	if (clean_queues == num_queues) {
		dev_err(&dev->dev,
			"transmit timed out, status 0x%x. Clean queues.\n",
			e_csr);
		return;
	}

	dev_err(&dev->dev,
		"transmit timed out, status 0x%x, resetting.\n",
		e_csr);

	/* Initiate restart card */
	mgb_write_e_csr(ep, INEA | SWINT);
}

static int mgb_max_mtu_config(struct net_device *dev)
{
	int max_mtu = ETH_DATA_LEN;

	if (mgb_1gb_link_up(netdev_priv(dev)))
		max_mtu = MGB_MAX_DATA_LEN;

	return max_mtu;
}

static int mgb_change_mtu(struct net_device *dev, int new_mtu)
{
	int max_mtu = mgb_max_mtu_config(dev);

	if (new_mtu < dev->min_mtu || new_mtu > max_mtu)
		return -EINVAL;

	dev_info(&dev->dev, "changing MTU from %d to %d\n",
		 dev->mtu, new_mtu);
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
	struct sockaddr *addr = (struct sockaddr *)p;
	u8 *da;

	/* The sequence of actions to change MAC address:
	 * 1. to stop a card;
	 * 2. to update MAC address in net device;
	 * 3. to start the card.
	 * The update of init block will be done in
	 * mgb_wakeup_card().
	 */

	if (netif_running(dev))
		return -EBUSY;

	memcpy(dev->dev_addr, addr->sa_data, dev->addr_len);
	da = (u8 *)dev->dev_addr;
	dev_info(&ep->dev->dev,
		 "changed MAC address to %02x:%02x:%02x:%02x:%02x:%02x\n",
		 da[0], da[1], da[2], da[3], da[4], da[5]);

	return 0;
}

static const struct net_device_ops mgb_netdev_ops = {
	.ndo_open		= mgb_open,
	.ndo_stop		= mgb_close,
	.ndo_start_xmit		= mgb_start_xmit,
	.ndo_tx_timeout		= mgb_tx_timeout,
	.ndo_set_rx_mode	= mgb_set_rx_mode,
	.ndo_do_ioctl		= mgb_ioctl,
	.ndo_get_stats64	= mgb_get_stats64,
	.ndo_change_mtu		= mgb_change_mtu,
	.ndo_set_mac_address	= mgb_set_mac_addr,
#ifdef CONFIG_NET_POLL_CONTROLLER
	.ndo_poll_controller	= mgb_poll_controller,
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

	tx_coalesce_usecs = DIV_ROUND_UP((tx_coalesce_usecs * ep->mgb_ticks_per_usec), 2048);
	if (tx_coalesce_usecs == 0 &&
		((ec->tx_coalesce_usecs != 0) ||
		 (ep->pci_dev->revision < 3))) {
		/* bug 145388: To keep tx_coalesce_usecs not equal to zero. */
		tx_coalesce_usecs = 1;
	}
	if (tx_coalesce_usecs > 255)
		return -EINVAL;

	rx_coalesce_usecs = DIV_ROUND_UP((rx_coalesce_usecs * ep->mgb_ticks_per_usec), 2048);
	if (rx_coalesce_usecs == 0 &&
		((ec->rx_coalesce_usecs != 0) ||
		 (ep->pci_dev->revision < 3))) {
		/* bug 145388: To keep rx_coalesce_usecs not equal to zero. */
		rx_coalesce_usecs = 1;
	}
	if (rx_coalesce_usecs > 255)
		return -EINVAL;

	if (ep->pci_dev->revision < 3) {
		/* bug 145388: To keep rx/tx_max_coalesce_frames equal to zero. */
		tx_max_coalesced_frames = 0;
		rx_max_coalesced_frames = 0;
	} else {
		if (tx_max_coalesced_frames > min(255, TX_RING_SIZE))
			return -EINVAL;
		if (rx_max_coalesced_frames > min(255, RX_RING_SIZE))
			return -EINVAL;
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

	info->so_timestamping = SOF_TIMESTAMPING_TX_SOFTWARE |
				SOF_TIMESTAMPING_RX_SOFTWARE |
				SOF_TIMESTAMPING_SOFTWARE |
				SOF_TIMESTAMPING_TX_HARDWARE |
				SOF_TIMESTAMPING_RX_HARDWARE |
				SOF_TIMESTAMPING_RAW_HARDWARE;

	info->tx_types = BIT(HWTSTAMP_TX_OFF) |
			BIT(HWTSTAMP_TX_ON);

	info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			    BIT(HWTSTAMP_FILTER_PTP_V1_L4_SYNC) |
			    BIT(HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_L4_SYNC) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_L2_SYNC) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_EVENT) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_SYNC) |
			    BIT(HWTSTAMP_FILTER_PTP_V2_DELAY_REQ) |
			    BIT(HWTSTAMP_FILTER_ALL);

	if (ep->ptp_clock)
		info->phc_index = ptp_clock_index(ep->ptp_clock);
	else
		info->phc_index = -1;

	return 0;
}

static u32 mgb_get_pause_autoneg(struct net_device *netdev,
				 struct ethtool_link_ksettings *cmd)
{
	if (!mgb_get_link_ksettings(netdev, cmd)) {
		u32 advertising = *cmd->link_modes.advertising;

		if ((advertising & ADVERTISED_Autoneg) &&
		    (advertising & (ADVERTISED_Pause |
		    ADVERTISED_Asym_Pause)))
			return AUTONEG_ENABLE;
	}

	return AUTONEG_DISABLE;
}

static void mgb_get_pauseparam(struct net_device *netdev,
			       struct ethtool_pauseparam *pause)
{
	struct mgb_private *ep = netdev_priv(netdev);
	u32 pf = mgb_read_psf_csr(ep);
	struct ethtool_link_ksettings cmd;

	pause->autoneg = mgb_get_pause_autoneg(netdev, &cmd);

	/* That's because EPSF bit is ON in the init block by default
	 * (see mgb_default_mode). And there is no way to update
	 * the bit on fly: only to call mgb_restart_card(). It's
	 * not applicable now.
	 */
	pause->rx_pause = 1;
	pause->tx_pause = !!((pf & enable_sent_pause_flags));
}

static int mgb_set_pauseparam(struct net_device *netdev,
			      struct ethtool_pauseparam *pause)
{
	struct mgb_private *ep = netdev_priv(netdev);
	u32 pf = mgb_read_psf_csr(ep);
	struct ethtool_link_ksettings cmd;

	/* Ignore any auto negotiation updates here. */
	if (pause->autoneg != mgb_get_pause_autoneg(netdev, &cmd))
		return -EINVAL;

	/* See comment in mgb_get_pauseparam(). */
	if (!pause->rx_pause)
		return -EINVAL;

	if (pause->tx_pause) {
		pf |= enable_sent_pause_flags;
		ep->psf_csr |= enable_sent_pause_flags;
	} else {
		pf &= ~enable_sent_pause_flags;
		ep->psf_csr &= ~enable_sent_pause_flags;
	}

	mgb_write_psf_csr(ep, pf);

	return 0;
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
					  " %sRLOS %sTFLT %sEMST %sPLST\n",
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
					"+: The host determines the link speed based on"
					" the outcome of the Clause 73 auto-negotiation.\n",
					(val & 0x1000)  ? "+" : "-");
		}
		if (mgb_dbg_reg_id_pcs[i] == SR_AN_STS) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%20sLink partner AN ability\n"
					"%20sAuto-negotiation Link Status:\n"
					"+: Clause 73 auto-negotiation process is complete and the "
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

static void mgb_ptp_init(struct mgb_private *ep)
{
	struct pci_dev *pdev = ep->pci_dev;

	ep->hwtstamp_config.tx_type = HWTSTAMP_TX_OFF;
	ep->hwtstamp_config.rx_filter = HWTSTAMP_FILTER_NONE;
	ep->hwtstamp_config.flags = 0;
	if (!send_pps_mpv)
		request_module("mpv");

	if (!send_pps_mpv) {
		ep->ptp_clock = ERR_PTR(-EINVAL);
	} else {
		if (send_pps_mpv(mpv_pps_in, 1)) {
			dev_warn(&pdev->dev, "send_pps_mpv() failed\n");
			ep->ptp_clock = ERR_PTR(-EINVAL);
		} else {
			ep->ptp_clock_info = mgb_ptp_clock_info;
			ep->ptp_clock = ptp_clock_register(&ep->ptp_clock_info,
							   &pdev->dev);
			dev_warn(&pdev->dev, "send_pps_mpv() OK\n");
		}
	}
	if (IS_ERR(ep->ptp_clock)) {
		ep->ptp_clock = NULL;
		dev_warn(&pdev->dev, "mgb_ptp_init failed\n");
		return;
	} else if (netif_msg_probe(ep)) {
		dev_info(&pdev->dev, "registered PHC clock\n");
	}
	ep->phc_adjtime = 0;
}


/** TITLE: PROBE stuff */

static int mgb_nd_number;

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
	int mpllm;

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
	ep->nd_number = (mgb_nd_number - 1) % MGB_MAX_NETDEV_NUMBER;

	ep->mpll_mode = mpllm;

	ep->mgb_ticks_per_usec = mgb_is_eiohub_proto(ep) ? 125 : 480;

	raw_spin_lock_init(&ep->mgio_lock);
	mutex_init(&ep->mx);

	l_set_ethernet_macaddr(pdev, dev->dev_addr);
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

	ep->log_rx_buffs = MGB_LOG_RX_BUFFERS;
	ep->log_tx_buffs = MGB_LOG_TX_BUFFERS;
	/* tx_max_coalesced_frames = 0
	 * tx_coalesce_usecs       = 12 usecs
	 * rx_max_coalesced_frames = 0
	 * rx_coalesce_usecs       = 21 usecs
	 */
	ep->irq_delay = mgb_set_irq_delay(0, 3, 0, 5);
	ep->psf_csr = default_psf_csr;

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

	dev->min_mtu = (ETH_ZLEN - ETH_HLEN);
	dev->max_mtu = MGB_MAX_DATA_LEN;

	dev->features |= NETIF_F_IP_CSUM;

	netif_napi_add(dev, &ep->mgb_qs[0]->napi,
		mgb_poll, MGB_NAPI_WEIGHT);
	if (ep->mgb_qs[1])
		netif_napi_add(dev, &ep->mgb_qs[1]->napi,
			mgb_poll, MGB_NAPI_WEIGHT);

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

	dev_info(&pdev->dev,
		 "Accepted AN parameters for device %d: clause %d%s\n",
		 ep->nd_number,
		 ep->an_clause_73 ? 73 : 37,
		 ep->an_sgmii ? "(SGMII)" : "");

	ep->an_status = 0;
	timer_setup(&ep->an_link_timer, mgb_link_timer, 0);
	if (an_monitor)
		timer_setup(&ep->an_monitor_timer, mgb_an_monitor_timer, 0);

	ep->workqueue = create_singlethread_workqueue(netdev_name(dev));
	if (!ep->workqueue) {
		pr_err("Cannot create workqueue\n");
		goto err_mdio_unregister;
	}
	INIT_WORK(&ep->rx_mode_work, mgb_set_multicast_list);

	mgb_set_pcsphy_mode(dev);
	mgb_ptp_init(ep);
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
	if (ep->mgb_qs[0]) {
		netif_napi_del(&ep->mgb_qs[0]->napi);
		mgb_free_queue(ep, 0);
	}
	if (ep->mgb_qs[1]) {
		netif_napi_del(&ep->mgb_qs[1]->napi);
		mgb_free_queue(ep, 1);
	}
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

	flush_workqueue(ep->workqueue);
	destroy_workqueue(ep->workqueue);

	del_timer_sync(&ep->an_link_timer);
	if (an_monitor)
		del_timer_sync(&ep->an_monitor_timer);

	unregister_netdev(dev);

	if (ep->mii_bus)
		mdiobus_unregister(ep->mii_bus);

	if (ep->mgb_qs[0]) {
		netif_napi_del(&ep->mgb_qs[0]->napi);
		mgb_free_queue(ep, 0);
	}
	if (ep->mgb_qs[1]) {
		netif_napi_del(&ep->mgb_qs[1]->napi);
		mgb_free_queue(ep, 1);
	}

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

	if (ep->extphyaddr == -1)
		mgb_check_link_status(ep, mgb_read_mgio_csr(ep));
	else
		mgb_check_phydev_link_status(dev);

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

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("mgb ethernet card of e2k family CPUs driver");
MODULE_SUPPORTED_DEVICE("MGB, DeviceID:" PCI_DEVICE_ID_MCST_MGB
			", VendorID:" PCI_VENDOR_ID_MCST_TMP);
MODULE_VERSION(DRV_VERSION);
