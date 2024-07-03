/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_debudfs.c - MXGBE module device driver
 *
 * DEBUGFS Driver Part
 * Usage: mount -t debugfs none /sys/kernel/debug
 *
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_CNT  - RO - read TX/RX_CNT
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_I2C  - RO - read MAC & SFP
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_IRQ  - RO - read IRQ regs
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_MAC  - RO - read MAC regs
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_MISC - RO - read PRST,I2C,GPIO,MDIO
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_PHY  - RO - read PHY (VSC8488)
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_RX   - RO - read RX regs
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_RXQ  - RO - read RXQ regs
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_TX   - RO - read TX regs
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_TXQ  - RO - read TXQ regs
 * /sys/kernel/debug/mxgbe/<pcidev>/reg_ops  - RW - read/write registers
 *     Available commands for file write:
 *         read <reg>
 *         write <reg> <value>
 *     Read file to get result
 */

#ifdef CONFIG_DEBUG_FS

#include <linux/debugfs.h>

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "mxgbe_mac.h"
#include "mxgbe_phy.h"
#include "mxgbe_i2c.h"

#include "mxgbe_debugfs.h"
#include "kcompat.h"


/* /sys/kernel/debug/mxgbe */
static struct dentry *mxgbe_dbg_root;


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

/* MAC */
const u_int32_t mxgbe_dbg_reg_id_mac[31] = {
	MAC_LOOPBACK,
	MAC_LINK_STAT,
	MAC_LINK_CHG,
	MAC_RAW,
	MAC_PAUSE_CTRL,
	MAC_PAUSE_TXSTATE,
	MAC_PAUSE_TXPRI0,
	MAC_PAUSE_TXPRI1,
	MAC_PAUSE_TXPRI2,
	MAC_PAUSE_TXPRI3,
	MAC_PAUSE_TXPRI4,
	MAC_PAUSE_TXPRI5,
	MAC_PAUSE_TXPRI6,
	MAC_PAUSE_TXPRI7,
	MAC_PAUSE_RXCTRL,
	MAC_PAUSE_RXSTATE,
	MAC_PAUSE_RXPRI0,
	MAC_PAUSE_RXPRI1,
	MAC_PAUSE_RXPRI2,
	MAC_PAUSE_RXPRI3,
	MAC_PAUSE_RXPRI4,
	MAC_PAUSE_RXPRI5,
	MAC_PAUSE_RXPRI6,
	MAC_PAUSE_RXPRI7,
	MAC_PAUSE_CHG,
	MAC_PAUSE_MAC,
	MAC_PAUSE_MAC + 4,
	MAC_MAX_RATE,
	MAC_MIN_IPG,
	MAC_MAX_PPS,
	MAC_PAUSE_CONSTS,
};
const char *mxgbe_dbg_reg_name_mac[31] = {
	"MAC_LOOPBACK: loopback control (def: 0)",
	"MAC_LINK_STAT: XGMI/XAUI link status (def: -)",
	"MAC_LINK_CHG: MSI-X MAC_LINK interrupt control (def: 0)",
	"MAC_RAW: RAW mode enable (def: 0)",
	"MAC_PAUSE_CTRL: pause and prio-pause frame control (def: 0)",
	"MAC_PAUSE_TXSTATE: TX state (freeze on prio) (def: -)",
	"MAC_PAUSE_TXPRI0: Tx pause cnt [0] (def: -)",
	"MAC_PAUSE_TXPRI1: Tx pause cnt [1] (def: -)",
	"MAC_PAUSE_TXPRI2: Tx pause cnt [2] (def: -)",
	"MAC_PAUSE_TXPRI3: Tx pause cnt [3] (def: -)",
	"MAC_PAUSE_TXPRI4: Tx pause cnt [4] (def: -)",
	"MAC_PAUSE_TXPRI5: Tx pause cnt [5] (def: -)",
	"MAC_PAUSE_TXPRI6: Tx pause cnt [6] (def: -)",
	"MAC_PAUSE_TXPRI7: Tx pause cnt [7] (def: -)",
	"MAC_PAUSE_RXCTRL: enable pause frame (on prio) (def: 0)",
	"MAC_PAUSE_RXSTATE: pause frames info (def: -)",
	"MAC_PAUSE_RXPRI0: pause frames info [0] (def: -)",
	"MAC_PAUSE_RXPRI1: pause frames info [1] (def: -)",
	"MAC_PAUSE_RXPRI2: pause frames info [2] (def: -)",
	"MAC_PAUSE_RXPRI3: pause frames info [3] (def: -)",
	"MAC_PAUSE_RXPRI4: pause frames info [4] (def: -)",
	"MAC_PAUSE_RXPRI5: pause frames info [5] (def: -)",
	"MAC_PAUSE_RXPRI6: pause frames info [6] (def: -)",
	"MAC_PAUSE_RXPRI7: pause frames info [7] (def: -)",
	"MAC_PAUSE_CHG: MSI-X MAC_PAUSE interrupt control (def: 0)",
	"MAC_PAUSE_MAC_L: source MAC for pause frame (def: 0)",
	"MAC_PAUSE_MAC_H:",
	"MAC_MAX_RATE: speed limit control (def: 0x01000000)",
	"MAC_MIN_IPG: ipg gap min size (def: 0)",
	"MAC_MAX_PPS: max speed limit (def: 0)",
	"MAC_PAUSE_CONSTS: ",
};

/* TX */
const u_int32_t mxgbe_dbg_reg_id_tx[37] = {
	TX_QNUM,
	TX_BUFSIZE,
	TX_OFFS_PRI0,
	TX_OFFS_PRI1,
	TX_OFFS_PRI2,
	TX_OFFS_PRI3,
	TX_OFFS_PRI4,
	TX_OFFS_PRI5,
	TX_OFFS_PRI6,
	TX_OFFS_PRI7,
	TX_SIZE_PRI0,
	TX_SIZE_PRI1,
	TX_SIZE_PRI2,
	TX_SIZE_PRI3,
	TX_SIZE_PRI4,
	TX_SIZE_PRI5,
	TX_SIZE_PRI6,
	TX_SIZE_PRI7,
	TX_MASK_PRI0,
	TX_MASK_PRI1,
	TX_MASK_PRI2,
	TX_MASK_PRI3,
	TX_MASK_PRI4,
	TX_MASK_PRI5,
	TX_MASK_PRI6,
	TX_MASK_PRI7,
	TX_Q_CH0,
	TX_Q_CH1,
	TX_Q_CH2,
	TX_Q_CH3,
	TX_Q_CH4,
	TX_Q_CH5,
	TX_Q_CH6,
	TX_Q_CH7,
	TX_BYTE_CNT,
	TX_PACK_CNT,
	TX_MAX_REQ_SIZE,
};
const char *mxgbe_dbg_reg_name_tx[37] = {
	"TX_QNUM: tx queue size (4..256)",
	"TX_BUFSIZE: tx buffer length (def: -)",
	"TX_OFFS_PRI0: offset in buf for prio 0 (def: 0)",
	"TX_OFFS_PRI1: offset in buf for prio 1 (def: 0)",
	"TX_OFFS_PRI2: offset in buf for prio 2 (def: 0)",
	"TX_OFFS_PRI3: offset in buf for prio 3 (def: 0)",
	"TX_OFFS_PRI4: offset in buf for prio 4 (def: 0)",
	"TX_OFFS_PRI5: offset in buf for prio 5 (def: 0)",
	"TX_OFFS_PRI6: offset in buf for prio 6 (def: 0)",
	"TX_OFFS_PRI7: offset in buf for prio 7 (def: 0)",
	"TX_SIZE_PRI0: size in buf for prio 0 (def: 0)",
	"TX_SIZE_PRI1: size in buf for prio 1 (def: 0)",
	"TX_SIZE_PRI2: size in buf for prio 2 (def: 0)",
	"TX_SIZE_PRI3: size in buf for prio 3 (def: 0)",
	"TX_SIZE_PRI4: size in buf for prio 4 (def: 0)",
	"TX_SIZE_PRI5: size in buf for prio 5 (def: 0)",
	"TX_SIZE_PRI6: size in buf for prio 6 (def: 0)",
	"TX_SIZE_PRI7: size in buf for prio 7 (def: 0)",
	"TX_MASK_PRI0: channel select for prio 0 (def: 0x01)",
	"TX_MASK_PRI1: channel select for prio 1 (def: 0x02)",
	"TX_MASK_PRI2: channel select for prio 2 (def: 0x04)",
	"TX_MASK_PRI3: channel select for prio 3 (def: 0x08)",
	"TX_MASK_PRI4: channel select for prio 4 (def: 0x10)",
	"TX_MASK_PRI5: channel select for prio 5 (def: 0x20)",
	"TX_MASK_PRI6: channel select for prio 6 (def: 0x40)",
	"TX_MASK_PRI7: channel select for prio 7 (def: 0x80)",
	"TX_Q_CH0: credit fo prio 0 (def: 0xFFFF)",
	"TX_Q_CH1: credit fo prio 1 (def: 0xFFFF)",
	"TX_Q_CH2: credit fo prio 2 (def: 0xFFFF)",
	"TX_Q_CH3: credit fo prio 3 (def: 0xFFFF)",
	"TX_Q_CH4: credit fo prio 4 (def: 0xFFFF)",
	"TX_Q_CH5: credit fo prio 5 (def: 0xFFFF)",
	"TX_Q_CH6: credit fo prio 6 (def: 0xFFFF)",
	"TX_Q_CH7: credit fo prio 7 (def: 0xFFFF)",
	"TX_BYTE_CNT: TX bytes",
	"TX_PACK_CNT: TX packets",
	"TX_MAX_REQ_SIZE: ",
};

/* RX */
const u_int32_t mxgbe_dbg_reg_id_rx[53] = {
	RX_QNUM,
	RX_BUFSIZE,
	RX_OFFS_PRI0,
	RX_OFFS_PRI1,
	RX_OFFS_PRI2,
	RX_OFFS_PRI3,
	RX_OFFS_PRI4,
	RX_OFFS_PRI5,
	RX_OFFS_PRI6,
	RX_OFFS_PRI7,
	RX_SIZE_PRI0,
	RX_SIZE_PRI1,
	RX_SIZE_PRI2,
	RX_SIZE_PRI3,
	RX_SIZE_PRI4,
	RX_SIZE_PRI5,
	RX_SIZE_PRI6,
	RX_SIZE_PRI7,
	RX_CTRL,
	/* RX_DSTMAC, */
	/* RX_MCASTHASH, */
	/* RX_VLANFILT, */
	RX_MASK_PRI0,
	RX_MASK_PRI1,
	RX_MASK_PRI2,
	RX_MASK_PRI3,
	RX_MASK_PRI4,
	RX_MASK_PRI5,
	RX_MASK_PRI6,
	RX_MASK_PRI7,
	RX_Q_CH0,
	RX_Q_CH1,
	RX_Q_CH2,
	RX_Q_CH3,
	RX_Q_CH4,
	RX_Q_CH5,
	RX_Q_CH6,
	RX_Q_CH7,
	RX_PTP,
	RX_RAW,
	RX_IP,
	RX_TCP,
	RX_UDP,
	RX_BYTE_CNT,
	RX_PACK_CNT,
	RX_FILT_CNT,
	RX_DROP_CNT,
	RX_ERR_CNT,
	RX_FULL_TH0,
	RX_FULL_TH1,
	RX_FULL_TH2,
	RX_FULL_TH3,
	RX_FULL_TH4,
	RX_FULL_TH5,
	RX_FULL_TH6,
	RX_FULL_TH7,
};
const char *mxgbe_dbg_reg_name_rx[53] = {
	"RX_QNUM: tx queue size (4..256)",
	"RX_BUFSIZE: tx buffer length (def: -)",
	"RX_OFFS_PRI0: offset in buf for prio 0 (def: 0)",
	"RX_OFFS_PRI1: offset in buf for prio 1 (def: 0)",
	"RX_OFFS_PRI2: offset in buf for prio 2 (def: 0)",
	"RX_OFFS_PRI3: offset in buf for prio 3 (def: 0)",
	"RX_OFFS_PRI4: offset in buf for prio 4 (def: 0)",
	"RX_OFFS_PRI5: offset in buf for prio 5 (def: 0)",
	"RX_OFFS_PRI6: offset in buf for prio 6 (def: 0)",
	"RX_OFFS_PRI7: offset in buf for prio 7 (def: 0)",
	"RX_SIZE_PRI0: size in buf for prio 0 (def: 0)",
	"RX_SIZE_PRI1: size in buf for prio 1 (def: 0)",
	"RX_SIZE_PRI2: size in buf for prio 2 (def: 0)",
	"RX_SIZE_PRI3: size in buf for prio 3 (def: 0)",
	"RX_SIZE_PRI4: size in buf for prio 4 (def: 0)",
	"RX_SIZE_PRI5: size in buf for prio 5 (def: 0)",
	"RX_SIZE_PRI6: size in buf for prio 6 (def: 0)",
	"RX_SIZE_PRI7: size in buf for prio 7 (def: 0)",
	"RX_CTRL: Rx mode control (def: 0)",
	/* "RX_DSTMAC: W/O (def: -)", */
	/* "RX_MCASTHASH: W/O (def: -)", */
	/* "RX_VLANFILT: (def: -)", */
	"RX_MASK_PRI0: channel select for prio 0 (def: 0x01)",
	"RX_MASK_PRI1: channel select for prio 1 (def: 0x02)",
	"RX_MASK_PRI2: channel select for prio 2 (def: 0x04)",
	"RX_MASK_PRI3: channel select for prio 3 (def: 0x08)",
	"RX_MASK_PRI4: channel select for prio 4 (def: 0x10)",
	"RX_MASK_PRI5: channel select for prio 5 (def: 0x20)",
	"RX_MASK_PRI6: channel select for prio 6 (def: 0x40)",
	"RX_MASK_PRI7: channel select for prio 7 (def: 0x80)",
	"RX_Q_CH0: credit fo prio 0 (def: 0xFFFF)",
	"RX_Q_CH1: credit fo prio 1 (def: 0xFFFF)",
	"RX_Q_CH2: credit fo prio 2 (def: 0xFFFF)",
	"RX_Q_CH3: credit fo prio 3 (def: 0xFFFF)",
	"RX_Q_CH4: credit fo prio 4 (def: 0xFFFF)",
	"RX_Q_CH5: credit fo prio 5 (def: 0xFFFF)",
	"RX_Q_CH6: credit fo prio 6 (def: 0xFFFF)",
	"RX_Q_CH7: credit fo prio 7 (def: 0xFFFF)",
	"RX_PTP: queue case control for IEEE1588 (def: 1)",
	"RX_RAW: queue case control for RAW (def: 1)",
	"RX_IP: queue case control for IP (def: 1)",
	"RX_TCP: queue case control for TCP (def: 1)",
	"RX_UDP: queue case control for UDP (def: 1)",
	"RX_BYTE_CNT: RX bytes",
	"RX_PACK_CNT: RX packets",
	"RX_FILT_CNT: RX packets dropped/filtered",
	"RX_DROP_CNT: RX packets dropped/overbuf",
	"RX_ERR_CNT: RX packets errors",
	"RX_FULL_TH0: ",
	"RX_FULL_TH1: ",
	"RX_FULL_TH2: ",
	"RX_FULL_TH3: ",
	"RX_FULL_TH4: ",
	"RX_FULL_TH5: ",
	"RX_FULL_TH6: ",
	"RX_FULL_TH7: ",
};

/* TX/RX Q */
const u_int32_t mxgbe_dbg_reg_id_q[11] = {
	Q_CTRL,
	Q_IRQ,
	Q_EMPTYTHR,
	Q_RDYTHR,
	Q_ADDR,
	Q_ADDR + 4,
	Q_TAILADDR,
	Q_TAILADDR + 4,
	Q_SIZE,
	Q_HEAD,
	Q_TAIL,
};
const char *mxgbe_dbg_reg_name_q[11] = {
	"Q_CTRL: queue control (def:0)",
	"Q_IRQ: irq control (def:0)",
	"Q_EMPTYTHR: tx irq level (def:0)",
	"Q_RDYTHR: done irq level (def:0)",
	"Q_ADDR_L: queue address (def:-)",
	"Q_ADDR_H:",
	"Q_TAILADDR_L: tail ptr copy addr (def:-)",
	"Q_TAILADDR_H:",
	"Q_SIZE: queue size (def:0x100)",
	"Q_HEAD: head ptr (def:0)",
	"Q_TAIL: tail ptr (def:0)",
};

/* IRQST */
const u_int32_t mxgbe_dbg_reg_id_irq[17] = {
	IRQST_0,
	IRQST_1,
	IRQST_2,
	IRQST_3,
	IRQST_4,
	IRQST_5,
	IRQST_6,
	IRQST_7,
	IRQST_8,
	IRQST_9,
	IRQST_10,
	IRQST_11,
	IRQST_12,
	IRQST_13,
	IRQST_14,
	IRQST_15,
	IRQST_16,
};
const char *mxgbe_dbg_reg_name_irq[17] = {
	"IRQST_0:  irq status: RXQ   0.. 31 (def: 0)",
	"IRQST_1:  irq status: RXQ  32.. 63 (def: 0)",
	"IRQST_2:  irq status: RXQ  64.. 95 (def: 0)",
	"IRQST_3:  irq status: RXQ  96..127 (def: 0)",
	"IRQST_4:  irq status: RXQ 128..159 (def: 0)",
	"IRQST_5:  irq status: RXQ 160..191 (def: 0)",
	"IRQST_6:  irq status: RXQ 192..223 (def: 0)",
	"IRQST_7:  irq status: RXQ 224..255 (def: 0)",
	"IRQST_8:  irq status: TXQ   0.. 31 (def: 0)",
	"IRQST_9:  irq status: TXQ  32.. 63 (def: 0)",
	"IRQST_10: irq status: TXQ  64.. 95 (def: 0)",
	"IRQST_11: irq status: TXQ  96..127 (def: 0)",
	"IRQST_12: irq status: TXQ 128..159 (def: 0)",
	"IRQST_13: irq status: TXQ 160..191 (def: 0)",
	"IRQST_14: irq status: TXQ 192..223 (def: 0)",
	"IRQST_15: irq status: TXQ 224..255 (def: 0)",
	"IRQST_16: irq status: MAC *        (def: 0)",
};

/* MISC */
const u_int32_t mxgbe_dbg_reg_id_misc[25] = {
	/* PRST */
	PRST_CST,
	/* I2C */
	I2C_0_PRERLO,
	I2C_0_PRERHI,
	I2C_0_CTR,
	I2C_0_RX_TXR,
	I2C_0_CR,
	I2C_0_SR,
	I2C_1_PRERLO,
	I2C_1_PRERHI,
	I2C_1_CTR,
	I2C_1_RX_TXR,
	I2C_1_CR,
	I2C_1_SR,
	I2C_2_PRERLO,
	I2C_2_PRERHI,
	I2C_2_CTR,
	I2C_2_RX_TXR,
	I2C_2_CR,
	I2C_2_SR,
	I2C_REG_READY,
	I2C_MAC,
	I2C_MAC + 4,
	/* GPIO */
	GPIO_IN,
	/* MDIO */
	MDIO_CSR,
	MDIO_DATA,
};
const char *mxgbe_dbg_reg_name_misc[25] = {
	/* PRST */
	"PRST_CST: reset status (def: 0x400003FF)",
	/* I2C */
	"I2C_0_PRERLO:",
	"I2C_0_PRERHI:",
	"I2C_0_CTR:",
	"I2C_0_RX_TXR:",
	"I2C_0_CR:",
	"I2C_0_SR:",
	"I2C_1_PRERLO:",
	"I2C_1_PRERHI:",
	"I2C_1_CTR:",
	"I2C_1_RX_TXR:",
	"I2C_1_CR:",
	"I2C_1_SR:",
	"I2C_2_PRERLO:",
	"I2C_2_PRERHI:",
	"I2C_2_CTR:",
	"I2C_2_RX_TXR:",
	"I2C_2_CR:",
	"I2C_2_SR:",
	"I2C_REG_READY:",
	"I2C_MAC_L: MAC Address",
	"I2C_MAC_H",
	/* GPIO */
	"GPIO_IN: gpio input state (def: -)",
	/* MDIO */
	"MDIO_CSR: MDIO status (def: -), used bit 13 (R/C)",
	"MDIO_DATA: data from PHY (def: -)",
};

#define PMA_and_PMD_MMD	(0x1 << 16)
#define PCS_MMD		(0x3 << 16)
#define AN_MMD		(0x7 << 16)
#define VS_MMD1		(0x1e << 16)
#define VS_MII_MMD	(0x1f << 16)

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

#define SR_PMA_KR_PMD_CTRL	(0x0096 | PMA_and_PMD_MMD)
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
#define SR_XS_PCS_KR_STS2	 (0x0021 | PCS_MMD)
#define VR_XS_PCS_DIG_STS	 (0x8010 | PCS_MMD)

/* PHY */
#if 0 /* old ext phy */
const u_int32_t mxgbe_dbg_reg_id_phy[12] = {
	/* Global */
	0x1E0000,
	0x1E0001,
	/* GPIO */
	/* PMA */
	0x1E7FD6,
	0x1E7FE1,
	/* Channel */
	0x010000,
	0x010001,
	0x010004,
	0x010005,
	0x010006,
	0x010007,
	0x010008,
	0x01000A,
#else
const u_int32_t mxgbe_dbg_reg_id_phy[51] = {
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
	SR_PMA_KR_PMD_CTRL,
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
	SR_XS_PCS_KR_STS2,
	VR_XS_PCS_DIG_STS,
#endif
};
#if 0 /* old ext phy */
const char *mxgbe_dbg_reg_name_phy[12] = {
	/* Global */
	"Device ID (def: 0x8488)",
	"Device Revision (def: 0x0005)",
	/* GPIO */
	/* PMA */
	"Temperature Monitor (def: 0x40xx)", /* page: 131, 174-175 */
	"Watchdog counter (def: 0x0000)",
	/* Channel */
	"PMA Control 1 (def: 0x2040)",
	"PMA Status 1 (def: 0x0006)",
	"PMA/PMD Speed Ability (def: 0x0001)",
	"PMA/PMD Devices (def: 0x001E)",
	"PMA/PMD Devices (def: 0x0000)",
	"PMA/PMD Control 2 (def: 0x0007)",
	"PMA/PMD Status 2 (def: 0xB1EF)",
	"PMA/PMD Receive SigDet (def: 0x0000)",
#else
const char *mxgbe_dbg_reg_name_phy[51] = {
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
	"SR_PMA_KR_PMD_CTRL",
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
	"SR_XS_PCS_KR_STS2",
	"VR_XS_PCS_DIG_STS",
#endif
};

/* CNT */
const u_int32_t mxgbe_dbg_reg_id_cnt[7] = {
	TX_BYTE_CNT,
	TX_PACK_CNT,
	RX_BYTE_CNT,
	RX_PACK_CNT,
	RX_FILT_CNT,
	RX_DROP_CNT,
	RX_ERR_CNT,
};
const char *mxgbe_dbg_reg_name_cnt[7] = {
	"TX_BYTE_CNT: TX bytes",
	"TX_PACK_CNT: TX packets",
	"RX_BYTE_CNT: RX bytes",
	"RX_PACK_CNT: RX packets",
	"RX_FILT_CNT: RX packets dropped/filtered",
	"RX_DROP_CNT: RX packets dropped/overbuf",
	"RX_ERR_CNT: RX packets errors",
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/
 ******************************************************************************
 **/

#define DPREG_32(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%05X: %08X - %s\n", \
		(R), mxgbe_rreg32(priv->bar0_base, (R)), (N)); \
} while (0)

#define DPREG_32_I(R, N, I) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%05X: %08X - %s%d\n", \
		(R), mxgbe_rreg32(priv->bar0_base, (R)), (N), (I)); \
} while (0)

#define DPREG_32_I16(R, N, I) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%05X: %08X %08X %08X %08X - %s%d\n", \
		(R) + ((I) << 4), \
		mxgbe_rreg32(priv->bar0_base, (R) + ((I) << 4) + 0x0C), \
		mxgbe_rreg32(priv->bar0_base, (R) + ((I) << 4) + 0x08), \
		mxgbe_rreg32(priv->bar0_base, (R) + ((I) << 4) + 0x04), \
		mxgbe_rreg32(priv->bar0_base, (R) + ((I) << 4) + 0x00), \
		(N), (I)); \
} while (0)

#define DPREG_PHY(D, R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%02X.%04X: %04X - %s\n", \
		(D), (R), \
		mdiobus_read(priv->mii_bus, \
				priv->pcsaddr, ((D) << 18) | (R)), (N)); \
} while (0)

#define DPREG_64C(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%05X: %016llX - %s\n", \
		(R), mxgbe_rreg64c(priv->bar0_base, (R)), (N)); \
} while (0)


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_MAC
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_mac_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_mac_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_mac_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - MAC registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_mac); i++) {
		DPREG_32(mxgbe_dbg_reg_id_mac[i], mxgbe_dbg_reg_name_mac[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_mac_read */

static const struct file_operations mxgbe_dbg_reg_mac_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_mac_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_TX
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_tx_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_tx_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_tx_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - TX registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_tx); i++) {
		DPREG_32(mxgbe_dbg_reg_id_tx[i], mxgbe_dbg_reg_name_tx[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_tx_read */

static const struct file_operations mxgbe_dbg_reg_tx_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_tx_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_TXQ
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_txq_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_txq_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i, q;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_txq_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - TXQ registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (q = 0; q < priv->num_tx_queues; q++) {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "TXQ%d:\n", q);
		for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_q); i++) {
			DPREG_32(TXQ_REG_ADDR(q, mxgbe_dbg_reg_id_q[i]),
				 (q == 0) ? mxgbe_dbg_reg_name_q[i] : "");
		}
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_txq_read */

static const struct file_operations mxgbe_dbg_reg_txq_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_txq_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_RX
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_rx_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_rx_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_rx_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - RX registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_rx); i++) {
		DPREG_32(mxgbe_dbg_reg_id_rx[i], mxgbe_dbg_reg_name_rx[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_rx_read */

static const struct file_operations mxgbe_dbg_reg_rx_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_rx_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_RXQ
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_rxq_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_rxq_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i, q;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_rxq_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - RXQ registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (q = 0; q < priv->num_rx_queues; q++) {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "RXQ%d:\n", q);
		for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_q); i++) {
			DPREG_32(RXQ_REG_ADDR(q, mxgbe_dbg_reg_id_q[i]),
				 (q == 0) ? mxgbe_dbg_reg_name_q[i] : "");
		}
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_rxq_read */

static const struct file_operations mxgbe_dbg_reg_rxq_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_rxq_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_IRQ
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_irq_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_irq_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_irq_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - IRQST register dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_irq); i++) {
		DPREG_32(mxgbe_dbg_reg_id_irq[i], mxgbe_dbg_reg_name_irq[i]);
	}

	/* PBA: BAR=0 offset=000f8000 */
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - MSIX PBA register dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < 17; i++) {
		DPREG_32_I(MSIX_B_0 + (i << 2), "MSIX_B_", i);
	}

	/* Vector table: BAR=0 offset=000f0000 */
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - MSIX Vector table dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "       +C       +8       +4       +0\n");
	len = priv->msix_rx_num + priv->msix_tx_num + priv->msix_mac_num;
	for (i = 0; i < len + 1; i++) {
		DPREG_32_I16(MSIX_V_0, "MSIX_V_", i);
	}


	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_irq_read */

static const struct file_operations mxgbe_dbg_reg_irq_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_irq_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_MISC
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_misc_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_misc_read(struct file *filp, char __user *buffer,
				       size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_misc_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - MISC registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_misc); i++) {
		DPREG_32(mxgbe_dbg_reg_id_misc[i], mxgbe_dbg_reg_name_misc[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_misc_read */

static const struct file_operations mxgbe_dbg_reg_misc_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_misc_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_PHY
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_phy_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_phy_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_phy_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - PHY registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_phy); i++) {
		DPREG_PHY(mxgbe_dbg_reg_id_phy[i] >> 16,
			  mxgbe_dbg_reg_id_phy[i] & 0xFFFF,
			  mxgbe_dbg_reg_name_phy[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_phy_read */

static const struct file_operations mxgbe_dbg_reg_phy_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_phy_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_I2C
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_i2c_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_i2c_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	u8 v8;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_i2c_buf;
	char sfp_buf[256];

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;


	/* MAC EEPROM */
	if (priv->i2c_2) {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"= %s | %s - I2C: EEPROM dump (hex) =\n",
				priv->ndev->name, pci_name(priv->pdev));
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"EEPROM 0x%05X:",
				I2C_EEPROM_MAC_BASE);
		for (i = 0; i < 6; i++) {
			v8 = mxgbe_i2c_rd(priv->i2c_2, I2C_EEPROM_ADDR,
					i + I2C_EEPROM_MAC_BASE);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					"%s%02X", (i == 0) ? " " : "-", v8);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, " - MAC\n");
	}

	/* SFP+ */
	if (priv->i2c_0) {
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"= %s | %s - I2C: 1-SFP+ dump (hex) =\n",
				priv->ndev->name, pci_name(priv->pdev));
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"      00 01 02 03 04 05 06 07 08 " \
				"09 0A 0B 0C 0D 0E 0F\n");
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"      -- -- -- -- -- -- -- -- -- " \
				"-- -- -- -- -- -- --");
		for (i = 0; i < 256; i++) {
			v8 = mxgbe_i2c_rd(priv->i2c_0, I2C_SFP1_ADDR, i);
			sfp_buf[i] = v8;
			if (!(i % 16)) {
				offs += scnprintf(buf + offs,
						  PAGE_SIZE - 1 - offs,
						  "\n0x%02X: %02X ", i, v8);
			} else {
				offs += scnprintf(buf + offs,
						  PAGE_SIZE - 1 - offs,
						  "%02X ", v8);
			}
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
		sfp_buf[36] = 0;
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"Vendor name: %s\n", sfp_buf + 20);
		sfp_buf[60] = 0;
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"Vendor OUI/PN: %s\n", sfp_buf + 40);
		sfp_buf[84] = 0;
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				"Vendor SN: %s\n", sfp_buf + 68);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_i2c_read */

static const struct file_operations mxgbe_dbg_reg_i2c_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_i2c_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/REG_CNT
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_cnt_buf[PAGE_SIZE] = "";

static ssize_t mxgbe_dbg_reg_cnt_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mxgbe_priv_t *priv = filp->private_data;
	char *buf = mxgbe_dbg_reg_cnt_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	/* TX/RX_CNT */
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - TX/RX_CNT registers dump (hex) =\n",
			  priv->ndev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mxgbe_dbg_reg_id_cnt); i++) {
		DPREG_64C(mxgbe_dbg_reg_id_cnt[i],
			  mxgbe_dbg_reg_name_cnt[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mxgbe_dbg_reg_cnt_read */

static const struct file_operations mxgbe_dbg_reg_cnt_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_cnt_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mxgbe/<pcidev>/reg_ops
 ******************************************************************************
 **/

static char mxgbe_dbg_reg_ops_buf[256] = "";

/**
 * mxgbe_dbg_reg_ops_read - read for reg_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t mxgbe_dbg_reg_ops_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	mxgbe_priv_t *priv = filp->private_data;
	char *buf;
	int len;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	buf = kasprintf(GFP_KERNEL, "0x%08x\n", priv->reg_last_value);
	if (!buf)
		return -ENOMEM;

	if (count < strlen(buf)) {
		kfree(buf);
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	kfree(buf);
	return len;
} /* mxgbe_dbg_reg_ops_read */

u16 mxgbe_pcs_read(mxgbe_priv_t *priv, int regnum);
void mxgbe_pcs_write(mxgbe_priv_t *priv, int regnum, u16 value);

/**
 * mxgbe_dbg_reg_ops_write - write into reg_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t mxgbe_dbg_reg_ops_write(struct file *filp,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	mxgbe_priv_t *priv = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(mxgbe_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(mxgbe_dbg_reg_ops_buf,
				     sizeof(mxgbe_dbg_reg_ops_buf)-1,
				     ppos,
				     buffer,
				     count);
	if (len < 0)
		return len;

	mxgbe_dbg_reg_ops_buf[len] = '\0';

	/* parse cmd >>> */
	if (strncmp(mxgbe_dbg_reg_ops_buf, "writepcs ", 9) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mxgbe_dbg_reg_ops_buf[8], "%x %x", &reg, &value);
		if (cnt == 2) {
			priv->reg_last_value = value;
			mxgbe_pcs_write(priv, reg, value);
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			pr_err(KBUILD_MODNAME
				 ": debugfs reg_ops usage:"
				 " writepcs <reg> <val>\n");
		}
	} else if (strncmp(mxgbe_dbg_reg_ops_buf, "readpcs ", 8) == 0) {
		u32 reg, value;
		int cnt;

		cnt = sscanf(&mxgbe_dbg_reg_ops_buf[7], "%x", &reg);
		if (cnt == 1) {
			value = (u32)mxgbe_pcs_read(priv, reg);
			priv->reg_last_value = value;
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			pr_err(KBUILD_MODNAME
				 ": debugfs reg_ops usage: readpcs <reg>\n");
		}
	} else if (strncmp(mxgbe_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&mxgbe_dbg_reg_ops_buf[5], "%x %x", &reg, &value);
		if (cnt == 2) {
			priv->reg_last_value = value;
			mxgbe_wreg32(priv->bar0_base, reg, value);
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			pr_err(KBUILD_MODNAME
			       ": debugfs reg_ops usage: write <reg> <val>\n");
		}
	} else if (strncmp(mxgbe_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&mxgbe_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			value = mxgbe_rreg32(priv->bar0_base, reg);
			priv->reg_last_value = value;
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			pr_err(KBUILD_MODNAME
			       ": debugfs reg_ops usage: read <reg>\n");
		}
	} else {
		priv->reg_last_value = 0xFFFFFFFF;
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops: Unknown command %s\n",
		       mxgbe_dbg_reg_ops_buf);
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops: Available commands:\n");
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops:   read <reg>\n");
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops:   write <reg> <val>\n");
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops:   readpcs <reg>\n");
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops:   writepcs <reg> <val>\n");
	}
	/* parse cmd <<< */

	return count;
} /* mxgbe_dbg_reg_ops_write */


static const struct file_operations mxgbe_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mxgbe_dbg_reg_ops_read,
	.write = mxgbe_dbg_reg_ops_write,
};


/**
 ******************************************************************************
 * Board Init Part
 ******************************************************************************
 **/

void mxgbe_dbg_rename(mxgbe_priv_t *priv, const char *name)
{
	if (priv->mxgbe_dbg_board)
		priv->mxgbe_dbg_board = debugfs_rename(mxgbe_dbg_root,
						priv->mxgbe_dbg_board,
						mxgbe_dbg_root,
						name);
} /* mxgbe_dbg_rename */

/**
 * mxgbe_dbg_board_init - setup the debugfs directory
 **/
void mxgbe_dbg_board_init(mxgbe_priv_t *priv)
{
	const char *name = pci_name(priv->pdev);
	struct dentry *pfile;

	priv->mxgbe_dbg_board = debugfs_create_dir(name, mxgbe_dbg_root);
	if (priv->mxgbe_dbg_board) {
		/* reg_ops */
		pfile = debugfs_create_file("reg_ops", 0600,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_ops_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create reg_ops file failed\n");
		}
		/* MAC */
		pfile = debugfs_create_file("REG_MAC", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_mac_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_MAC file failed\n");
		}
		/* TX */
		pfile = debugfs_create_file("REG_TX", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_tx_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_TX file failed\n");
		}
		/* TXQ */
		pfile = debugfs_create_file("REG_TXQ", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_txq_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_TXQ file failed\n");
		}
		/* RX */
		pfile = debugfs_create_file("REG_RX", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_rx_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_RX file failed\n");
		}
		/* RXQ */
		pfile = debugfs_create_file("REG_RXQ", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_rxq_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_RXQ file failed\n");
		}
		/* IRQ */
		pfile = debugfs_create_file("REG_IRQ", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_irq_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_IRQ file failed\n");
		}
		/* MISC */
		pfile = debugfs_create_file("REG_MISC", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_misc_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_MISC file failed\n");
		}
		/* PHY */
		pfile = debugfs_create_file("REG_PHY", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_phy_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_PHY file failed\n");
		}
		/* I2C */
		pfile = debugfs_create_file("REG_I2C", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_i2c_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_I2C file failed\n");
		}
		/* CNT */
		pfile = debugfs_create_file("REG_CNT", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_reg_cnt_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REG_CNT file failed\n");
		}
#if 0
		/* rxq0_descr */
		pfile = debugfs_create_file("rxq0_descr", 0400,
					    priv->mxgbe_dbg_board, priv,
					    &mxgbe_dbg_rxq0_descr_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create rxq0_descr file failed\n");
		}
#endif /* 0 */
	} else {
		dev_warn(&priv->pdev->dev, "debugfs create dir failed\n");
	}
} /* mxgbe_dbg_board_init */


/**
 * mxgbe_dbg_board_exit - clear out debugfs entries
 **/
void mxgbe_dbg_board_exit(mxgbe_priv_t *priv)
{
	if (priv->mxgbe_dbg_board)
		debugfs_remove_recursive(priv->mxgbe_dbg_board);

	priv->mxgbe_dbg_board = NULL;
} /* mxgbe_dbg_board_exit */


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

/**
 * start up debugfs for the driver
 * Usage: mount -t debugfs none /sys/kernel/debug
 **/
void mxgbe_dbg_init(void)
{
	mxgbe_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!mxgbe_dbg_root)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
} /* mxgbe_dbg_init */


/**
 * clean out the driver's debugfs entries
 **/
void mxgbe_dbg_exit(void)
{
	if (mxgbe_dbg_root)
		debugfs_remove_recursive(mxgbe_dbg_root);

	mxgbe_dbg_root = NULL;
} /* mxgbe_dbg_exit */

#endif /* CONFIG_DEBUG_FS */
