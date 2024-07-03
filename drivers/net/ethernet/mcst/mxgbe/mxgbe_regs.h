/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_REGS_H__
#define MXGBE_REGS_H__


#include "xgbe_regs.h"


/**
 *  Bitfield tool
 */
#define GET_FIELD(r, p, m)  (((r) >> (p)) & (m))
#define GET_BIT(r, p)       (((r) >> (p)) & (1))

#define SET_FIELD(d, p, m)  (((m) & (d)) << (p))
#define SET_BIT(p)          (1UL << (p))


/**
 ******************************************************************************
 * PCI Config Space
 ******************************************************************************
 */

#define MXGBE_PCI_BAR_NUMS	1	/* BAR0 - 1Mb */

#define MXGBE_DEVICE_ID			0x8026
#define MXGBE_VENDOR_ID			0x1FFF
#define MXGBE_REVISION_ID_BOARD		0x01
#define MXGBE_REVISION_ID_E16C_R2000P	0x02


/**
 ******************************************************************************
 * BAR0:
 ******************************************************************************
 */

/**
 * ch1.4 - MSI-X
 */

/* MSIX */
#define MSIX_IDX_MAC_LINK	512
#define MSIX_IDX_MAC_PAUSE	513
#define MSIX_IDX_DMA_ERROR	543
#define MSIX_V_NUM		544
/* IRQST */
#define MSIX_IRQST_RXBASE	(IRQST_0)
#define MSIX_IRQST_TXBASE	(IRQST_8)
#define MSIX_IRQST_MACBASE	(IRQST_16)


/** ch1.5 - Reset (HW) */


/** ch2.3 - MAC */


/** ch2.4 - MDIO (PHY) */


/** ch2.5 - I2C */


/** ch2.6 - GPIO */


/**
 * ch3.4 (ch4.4) - Queue
 */

/* Q_CTRL registers bits */
#define Q_CTRL_SET_RESET	SET_BIT(31)			/* RW [31]    */
#define Q_CTRL_GET_RESET(r)	GET_BIT((r), 31)		/* RW [31]    */
#define Q_CTRL_SET_HADDR(d)	SET_FIELD((d), 21, 0x07)	/* RW [23:21] */
#define Q_CTRL_GET_HADDR(r)	GET_FIELD((r), 21, 0x07)	/* RW [23:21] */
#define Q_CTRL_SET_PRIO(d)	SET_FIELD((d), 16, 0x07)	/* RW [18:16] */
#define Q_CTRL_GET_PRIO(r)	GET_FIELD((r), 16, 0x07)	/* RW [18:16] */
#define Q_CTRL_SET_REGHADDR(d)	SET_FIELD((d), 6,  0x03)	/* RW [07:06] */
#define Q_CTRL_REGHADDR_SEXT	0x00	/* sign extend [60] */
#define Q_CTRL_REGHADDR_QCTRL	0x01	/* Q_CTLT [31:23] */
#define Q_CTRL_REGHADDR_TCHA	0x02	/* TC_HADDR long descr */
#define Q_CTRL_SET_DESCRL	SET_BIT(5)		/* RW [05]    */
#define Q_CTRL_GET_DESCRL(r)	GET_BIT((r), 5)		/* RW [05]    */
#define Q_CTRL_SET_AUTOWRB	SET_BIT(4)		/* RW [04]    */
#define Q_CTRL_SET_WRDONEMEM	SET_BIT(3)		/* RW [03]    */
#define Q_CTRL_SET_WRTAILMEM	SET_BIT(2)		/* RW [02]    */
#define Q_CTRL_GET_NOTDONE(r)	GET_BIT((r), 1)		/* RW [01]    */
#define Q_CTRL_SET_START	SET_BIT(0)		/* RW [00]    */
/* Q_IRQ registers bits */
#define Q_IRQ_ENSETBITS		SET_BIT(31)	/* WO */
#define Q_IRQ_EN_ERROR		SET_BIT(18)	/* R/W */
#define Q_IRQ_EN_EMPTY		SET_BIT(17)	/* R/W */
#define Q_IRQ_EN_WRBACK		SET_BIT(16)	/* R/W */
#define Q_IRQ_EN_ALL		(Q_IRQ_EN_ERROR | \
				 Q_IRQ_EN_EMPTY | \
				 Q_IRQ_EN_WRBACK)
#define Q_IRQ_REQSETBITS	SET_BIT(15)	/* WO */
#define Q_IRQ_REQ_ERROR		SET_BIT(2)	/* R/W */
#define Q_IRQ_REQ_EMPTY		SET_BIT(1)	/* R/W */
#define Q_IRQ_REQ_WRBACK	SET_BIT(0)	/* R/W */
#define Q_IRQ_REQ_ALL		(Q_IRQ_REQ_ERROR | \
				 Q_IRQ_REQ_EMPTY | \
				 Q_IRQ_REQ_WRBACK)
#define Q_IRQ_CLEARALL		(Q_IRQ_EN_ALL | Q_IRQ_REQ_ALL)
#define Q_IRQ_SETALL		(Q_IRQ_ENSETBITS | Q_IRQ_EN_ALL | \
				 Q_IRQ_REQSETBITS | Q_IRQ_REQ_ALL)
/* Q_EMPTYTHR registers bits */
#define Q_EMPTYTHR_SET_N(d)	SET_FIELD((d), 0, 0xFF)		/* RW [07:00] */
/* Q_RDYTHR registers bits */
#define Q_RDYTHR_SET_TO(d)	SET_FIELD((d), 8, 0xFFFF)	/* RW [23:08] */
#define Q_RDYTHR_GET_TO(r)	GET_FIELD((r), 8, 0xFFFF)	/* RW [23:08] */
#define Q_RDYTHR_SET_N(d)	SET_FIELD((d), 0, 0xFF)		/* RW [07:00] */
#define Q_RDYTHR_GET_N(r)	GET_FIELD((r), 0, 0xFF)		/* RW [07:00] */
/* Q_ADDR - [63:05], [04:00]==0 */
/* Q_TAILADDR - [63:02], [01:00]==0 */
/* Q_SIZE registers bits */
#define Q_SIZE_MIN		(1 << 8)
#define Q_SIZE_MAX		(1 << 16)
/* Q_HEAD registers bits */
#define Q_HEAD_SET_PTR(d)	SET_FIELD((d), 0, 0xFFFF)	/* RW [15:00] */
#define Q_HEAD_GET_PTR(r)	GET_FIELD((r), 0, 0xFFFF)	/* RW [15:00] */
/* Q_TAIL registers bits */
#define Q_TAIL_GET_PTR(r)	GET_FIELD((r), 0, 0xFFFF)	/* RW [15:00] */


/**
 * ch3.5 - TXQ
 */

#define TXQ_BASE		(TXQ_0)
#define TXQ_SIZE		((TXQ_1) - (TXQ_0))
#define TXQ_MINNUM		4
#define TXQ_MAXNUM		256
#define TXQ_REG_ADDR(q, r)	((TXQ_BASE) + ((TXQ_SIZE) * (q)) + (r))


/**
 * ch3.6 - TX
 */

/* Common TX/RX */
#define MXGBE_MAX_REG_PRI	8

/* TX */
#define TX_SIZE_PRI_MIN		2048
#define TX_MASK_PRI0_DEF	0x01
#define TX_MASK_PRI1_DEF	0x02
#define TX_MASK_PRI2_DEF	0x04
#define TX_MASK_PRI3_DEF	0x08
#define TX_MASK_PRI4_DEF	0x10
#define TX_MASK_PRI5_DEF	0x20
#define TX_MASK_PRI6_DEF	0x40
#define TX_MASK_PRI7_DEF	0x80
#define TX_Q_CH_DEF		0xFFFF


/**
 * ch4.5 - RXQ
 */

#define RXQ_BASE		(RXQ_0)
#define RXQ_SIZE		((RXQ_1) - (RXQ_0))
#define RXQ_MINNUM		4
#define RXQ_MAXNUM		256
#define RXQ_REG_ADDR(q, r)	(RXQ_BASE + (RXQ_SIZE * (q)) + (r))


/**
 * ch4.6 - RX
 */

#define RX_SIZE_PRI_MIN		2048
#define RX_MASK_PRI0_DEF	0x01
#define RX_MASK_PRI1_DEF	0x02
#define RX_MASK_PRI2_DEF	0x04
#define RX_MASK_PRI3_DEF	0x08
#define RX_MASK_PRI4_DEF	0x10
#define RX_MASK_PRI5_DEF	0x20
#define RX_MASK_PRI6_DEF	0x40
#define RX_MASK_PRI7_DEF	0x80
#define RX_Q_CH_DEF		0xFFFF
#define RX_CTRL_RWODSTMAC	SET_BIT(12)
#define RX_CTRL_TCPRCS		SET_BIT(11)
#define RX_CTRL_SET_QPRIO(d)	SET_FIELD((d), 8, 0x7)
#define RX_CTRL_CFIDEIST(d)	SET_FIELD((d), 7, 0x1)
#define RX_CTRL_CHKCFIDEI	SET_BIT(6)
#define RX_CTRL_PARSETCP	SET_BIT(5)
#define RX_CTRL_PARSEIP		SET_BIT(4)
#define RX_CTRL_RMULTICAST1	SET_BIT(3)
#define RX_CTRL_RMULTICAST0	SET_BIT(2)
#define RX_CTRL_RBROADCAST	SET_BIT(1)
#define RX_CTRL_RAWMODE		SET_BIT(0)
#define RX_DSTMAC_TBLSIZE	8
#define RX_DSTMAC_SETIDX(d)	(0x80000000 | (SET_FIELD((d), 27, 0x0F)))
#define RX_DSTMAC_SETMAC(d)	SET_FIELD((d), 0, 0x00FFFFFF)
#define RX_DSTMAC_RECFRAME	SET_BIT(28)
#define RX_MCASTHASH_TBLSIZE	(8192 / 16)
#define RX_MCASTHASH_SETIDX(d)	(0x80000000 | (SET_FIELD((d), 16, 0x1FF)))
#define RX_MCASTHASH_SETHASH(d)	SET_FIELD((d), 0, 0xFFFF)
#define RX_VLANFILT_TBLSIZE	(16384 / 16)
#define RX_VLANFILT_SETIDX(d)	(0x80000000 | (SET_FIELD((d), 16, 0x3FF)))
#define RX_VLANFILT_SETPRIO(d)	SET_FIELD((d), 0, 0xFFFF)

#define RX_HASH_ENALL		SET_BIT(26)
#define RX_HASH_ENDPORT		SET_BIT(25)
#define RX_HASH_ENSPORT		SET_BIT(24)
#define RX_HASH_ENDIP		SET_BIT(23)
#define RX_HASH_ENSIP		SET_BIT(22)
#define RX_HASH_ENIPP		SET_BIT(21)
#define RX_HASH_ENVLAN		SET_BIT(20)
#define RX_HASH_ENETHT		SET_BIT(19)
#define RX_HASH_ENSMAC		SET_BIT(18)
#define RX_HASH_ENDMAC		SET_BIT(17)
#define RX_HASH_ADD_DEF		SET_FIELD((0), 9, 0xFF)
#define RX_HASH_ADD(d)		SET_FIELD((d), 9, 0xFF)  /* == 0..255 */
#define RX_HASH_DIV_DEF		0x001
#define RX_HASH_DIV(d)		SET_FIELD((d), 0, 0x1FF) /* == 1..256 */


/**
 ******************************************************************************
 * Descriptor:
 ******************************************************************************
 */
#ifdef __e2k__
typedef union {	/* +0x00 */
	struct { /* Transmit + CPU */
		uint64_t IPV6		: 1; /* [00]    */
		uint64_t IPCSUM		: 1; /* [01]    */
		uint64_t L4CSUM		: 1; /* [02]    */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t MSS		:14; /* [29:16] */
		uint64_t _res1_		: 1; /* [30]    */
		uint64_t NTCP_UDP	: 1; /* [31]    */
		uint64_t TCPHDR		: 4; /* [35:32] */
		uint64_t IPHDR		: 5; /* [40:36] */
		uint64_t _res2_		: 1; /* [41]    */
		uint64_t L4HDR		: 6; /* [47:42] */
		uint64_t FRMSIZE	:16; /* [63:48] */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t _res1_		: 3; /* [02:00] */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t ERRBITS	:16; /* [31:16] */
		uint64_t _res2_		:32; /* [63:32] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t _res1_		: 3; /* [02:00] */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t _res2_		:48; /* [63:16] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t _res1_		: 1; /* [00]    */
		uint64_t BFERR		: 1; /* [01]    */
		uint64_t TOOBIG		: 1; /* [02]    */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t L3HDR		: 5; /* [20:16] */
		uint64_t TYPE		: 3; /* [23:21] */
		uint64_t L4HDR		: 8; /* [31:24] */
		uint64_t DATOFFS	: 9; /* [40:32] */
		uint64_t SIVLAN		: 1; /* [41]    */
		uint64_t SOVLAN		: 1; /* [42]    */
		uint64_t IPCSUMOK	: 1; /* [43]    */
		uint64_t NTCP_UDP	: 1; /* [44]    */
		uint64_t L4CSUM		: 1; /* [45]    */
		uint64_t L4CSUMOK	: 1; /* [46]    */
		uint64_t MERGED		: 1; /* [47]    */
		uint64_t FRMSIZE	:16; /* [63:48] */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_ctrl_t;
#else
typedef union {	/* +0x00 */
	struct { /* Transmit + CPU */
		uint64_t FRMSIZE	:16; /* [63:48] */
		uint64_t L4HDR		: 6; /* [47:42] */
		uint64_t _res2_		: 1; /* [41]    */
		uint64_t IPHDR		: 5; /* [40:36] */
		uint64_t TCPHDR		: 4; /* [35:32] */
		uint64_t NTCP_UDP	: 1; /* [31]    */
		uint64_t _res1_		: 1; /* [30]    */
		uint64_t MSS		:14; /* [29:16] */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t L4CSUM		: 1; /* [02]    */
		uint64_t IPCSUM		: 1; /* [01]    */
		uint64_t IPV6		: 1; /* [00]    */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t _res2_		:32; /* [63:32] */
		uint64_t ERRBITS	:16; /* [31:16] */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t _res1_		: 3; /* [02:00] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t _res2_		:48; /* [63:16] */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t _res1_		: 3; /* [02:00] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t FRMSIZE	:16; /* [63:48] */
		uint64_t MERGED		: 1; /* [47]    */
		uint64_t L4CSUMOK	: 1; /* [46]    */
		uint64_t L4CSUM		: 1; /* [45]    */
		uint64_t NTCP_UDP	: 1; /* [44]    */
		uint64_t IPCSUMOK	: 1; /* [43]    */
		uint64_t SOVLAN		: 1; /* [42]    */
		uint64_t SIVLAN		: 1; /* [41]    */
		uint64_t DATOFFS	: 9; /* [40:32] */
		uint64_t L4HDR		: 8; /* [31:24] */
		uint64_t TYPE		: 3; /* [23:21] */
		uint64_t L3HDR		: 5; /* [20:16] */
		uint64_t BUFSIZE	:13; /* [15:03] */
		uint64_t TOOBIG		: 1; /* [02]    */
		uint64_t BFERR		: 1; /* [01]    */
		uint64_t _res1_		: 1; /* [00]    */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_ctrl_t;
#endif

/* Transmit + CPU */
#define TC_MSS_NOSPLIT		0
#define TC_MSS_MIN		256
#define TC_MSS_MAX		16383

/* Receive + Device */
#define RD_TYPE_T1T2		0
#define RD_TYPE_WRNFCS		1
#define RD_TYPE_LT64		2
#define RD_TYPE_RAW		3
#define RD_TYPE_FULLIPV4	4
#define RD_TYPE_PARTIPV4	5
#define RD_TYPE_IPV6		6
#define RD_TYPE_IPV6BIGHEAD	7


#ifdef __e2k__
typedef union {	/* +0x08 */
	struct { /* Transmit + CPU */
		uint64_t BUFPTR		:61; /* [60:00] */
		uint64_t SPLIT		: 2; /* [62:61] */
		uint64_t OWNER		: 1; /* [63]    */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t BUFPTR		:61; /* [60:00] */
		uint64_t _res1_		: 2; /* [62:61] */
		uint64_t OWNER		: 1; /* [63]    */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t BUFPTR		:61; /* [60:00] */
		uint64_t _res1_		: 2; /* [62:61] */
		uint64_t OWNER		: 1; /* [63]    */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t BUFPTR		:61; /* [60:00] */
		uint64_t SPLIT		: 2; /* [62:61] */
		uint64_t OWNER		: 1; /* [63]    */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_addr_t;
#else
typedef union {	/* +0x08 */
	struct { /* Transmit + CPU */
		uint64_t OWNER		: 1; /* [63]    */
		uint64_t SPLIT		: 2; /* [62:61] */
		uint64_t BUFPTR		:61; /* [60:00] */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t OWNER		: 1; /* [63]    */
		uint64_t _res1_		: 2; /* [62:61] */
		uint64_t BUFPTR		:61; /* [60:00] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t OWNER		: 1; /* [63]    */
		uint64_t _res1_		: 2; /* [62:61] */
		uint64_t BUFPTR		:61; /* [60:00] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t OWNER		: 1; /* [63]    */
		uint64_t SPLIT		: 2; /* [62:61] */
		uint64_t BUFPTR		:61; /* [60:00] */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_addr_t;
#endif

/* Transmit + CPU */
#define TC_SPLIT_NO		0
#define TC_SPLIT_FIRST		1
#define TC_SPLIT_MID		3
#define TC_SPLIT_LAST		2
#define XX_OWNER_HW		0
#define XX_OWNER_CPU		1

/* Receive + Device */
#define RD_SPLIT_NO		0
#define RD_SPLIT_FIRST		1
#define RD_SPLIT_MID		3
#define RD_SPLIT_LAST		2


#ifdef __e2k__
typedef union {	/* +0x10 for long only */
	struct { /* Transmit + CPU */
		uint64_t IVLAN		:16; /* [15:00] */
		uint64_t OVLAN		:16; /* [31:16] */
		uint64_t _res1_		:30; /* [61:32] */
		uint64_t SIVLAN		: 1; /* [62]    */
		uint64_t SOVLAN		: 1; /* [63]    */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t _res1_		:32; /* [31:00] */
		uint64_t TICKS		:32; /* [63:32] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t _res1_		:64; /* [63:00] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t IVLAN		:16; /* [15:00] */
		uint64_t OVLAN		:16; /* [31:16] */
		uint64_t TICKS		:32; /* [63:32] */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_vlan_t;
#else
typedef union {	/* +0x10 for long only */
	struct { /* Transmit + CPU */
		uint64_t SOVLAN		: 1; /* [63]    */
		uint64_t SIVLAN		: 1; /* [62]    */
		uint64_t _res1_		:30; /* [61:32] */
		uint64_t OVLAN		:16; /* [31:16] */
		uint64_t IVLAN		:16; /* [15:00] */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t TICKS		:32; /* [63:32] */
		uint64_t _res1_		:32; /* [31:00] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t _res1_		:64; /* [63:00] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t TICKS		:32; /* [63:32] */
		uint64_t OVLAN		:16; /* [31:16] */
		uint64_t IVLAN		:16; /* [15:00] */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_vlan_t;
#endif

#ifdef __e2k__
typedef union {	/* +0x18 for long only */
	struct { /* Transmit + CPU */
		uint64_t _res1_		:64; /* [63:00] */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t SECONDS	:48; /* [47:00] */
		uint64_t TIMEBITS	: 8; /* [55:48] */
		uint64_t _res1_		: 8; /* [63:56] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t _res1_		:64; /* [63:00] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t SECONDS	:48; /* [47:00] */
		uint64_t TIMEBITS	: 8; /* [55:48] */
		uint64_t _res1_		: 8; /* [63:56] */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_time_t;
#else
typedef union {	/* +0x18 for long only */
	struct { /* Transmit + CPU */
		uint64_t _res1_		:64; /* [63:00] */
	} __packed TC;
	struct { /* Transmit + Device */
		uint64_t _res1_		: 8; /* [63:56] */
		uint64_t TIMEBITS	: 8; /* [55:48] */
		uint64_t SECONDS	:48; /* [47:00] */
	} __packed TD;
	struct { /* Receive + CPU */
		uint64_t _res1_		:64; /* [63:00] */
	} __packed RC;
	struct { /* Receive + Device */
		uint64_t _res1_		: 8; /* [63:56] */
		uint64_t TIMEBITS	: 8; /* [55:48] */
		uint64_t SECONDS	:48; /* [47:00] */
	} __packed RD;
	uint64_t r;
} __packed mxgbe_time_t;
#endif


typedef struct mxgbe_descr {
	mxgbe_ctrl_t ctrl;
	mxgbe_addr_t addr;
#ifdef USE_LONG_DESCR
	mxgbe_vlan_t vlan;
	mxgbe_time_t time;
#endif /* USE_LONG_DESCR */
} mxgbe_descr_t;


#endif /* MXGBE_REGS_H__ */
