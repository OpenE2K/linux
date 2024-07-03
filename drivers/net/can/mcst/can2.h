/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MCST_CAN2_H__
#define MCST_CAN2_H__

/* mvorontsov
 */

/*#define CAN2_REVISION (32'd190118)*/ /* date +%y%m%d */

#define RX_FIFO_DEPTH (5)

/*
 * regs
 */
#define CAN2_REGS__ADR_WD		(12/*Byte oriented*/)
/*
 * Revision
 */
#define CAN2_REGS__REV_ID		(0x000)
#define CAN2_REGS__REVISION		0
/*
 * General
 */
#define CAN2_REGS__TIMINGS		(0x004)
#define CAN2_REGS__PRESCALER		0
#define CAN2_REGS__PROP_SEG		16
#define CAN2_REGS__PHASE_SEG		24
#define CAN2_REGS__FILTER		(0x008)
#define CAN2_REGS__FILT			0
/*
 * Control/State
 */
#define CAN2_REGS__CTLSTA		(0x010)
#define CAN2_REGS__RESET		0
#define CAN2_REGS__ENABLE		1
#define CAN2_REGS__LOOPBACK		2
#define CAN2_REGS__SNIFF		3
#define CAN2_REGS__STATEIRQ		4
/**/
#define CAN2_REGS__STATE		16
/**/
#define CAN2_REGS__LEC_STUFF_ERR	24
#define CAN2_REGS__LEC_FORM_ERR		25
#define CAN2_REGS__LEC_ACK_ERR		26
#define CAN2_REGS__LEC_BIT1_ERR		27
#define CAN2_REGS__LEC_BIT0_ERR		28
#define CAN2_REGS__LEC_CRC_ERR		29
/**/
#define CAN2_REGS__ERR_COUNTERS		(0x304)
#define CAN2_REGS__TXERRORS		0
#define CAN2_REGS__RXERRORS		16
/*
 * TX
 */
#define CAN2_REGS__TX_ID		(0x100)
#define CAN2_REGS__TX_ID_FIELD		0
/**/
#define CAN2_REGS__TX_DATA0		(0x104)
#define CAN2_REGS__TX_DATA1		(0x108)
/**/
#define CAN2_REGS__TX_CTRL		(0x10C)
#define CAN2_REGS__TX_CTRL_IDE		0
#define CAN2_REGS__TX_CTRL_RTR		1
#define CAN2_REGS__TX_CTRL_DLC		12
#define CAN2_REGS__TX_CTRL_RTYINF	16
#define CAN2_REGS__TX_CTRL_MBOX		28
/**/
#define CAN2_REGS__TX_STATUS		(0x110)
#define CAN2_REGS__TX_STAT_PEND		0
#define CAN2_REGS__TX_STAT_BUSY		16
#define CAN2_REGS__TX_IRQ		(0x118)
#define CAN2_REGS__TX_IRQ_EN		0
/*
 * RX
 */
#define CAN2_REGS__RX_ID_PTRN_0		(0x200)
#define CAN2_REGS__RX_ID_PTRN_1		(0x204)
#define CAN2_REGS__RX_ID_PTRN_2		(0x208)
#define CAN2_REGS__RX_ID_PTRN_3		(0x20C)
#define CAN2_REGS__RX_PTRN_ID		0
/**/
#define CAN2_REGS__RX_CTRL_PTRN_0	(0x210)
#define CAN2_REGS__RX_CTRL_PTRN_1	(0x214)
#define CAN2_REGS__RX_CTRL_PTRN_2	(0x218)
#define CAN2_REGS__RX_CTRL_PTRN_3	(0x21C)
#define CAN2_REGS__RX_PTRN_IDE		0
#define CAN2_REGS__RX_PTRN_RTR		1
#define CAN2_REGS__RX_MIN_DLC		8
#define CAN2_REGS__RX_MAX_DLC		12
/**/
#define CAN2_REGS__RX_ID_MASK_0		(0x220)
#define CAN2_REGS__RX_ID_MASK_1		(0x224)
#define CAN2_REGS__RX_ID_MASK_2		(0x228)
#define CAN2_REGS__RX_ID_MASK_3		(0x22C)
#define CAN2_REGS__RX_MASK_ID		0
/**/
#define CAN2_REGS__RX_CTRL_MASK_0	(0x230)
#define CAN2_REGS__RX_CTRL_MASK_1	(0x234)
#define CAN2_REGS__RX_CTRL_MASK_2	(0x238)
#define CAN2_REGS__RX_CTRL_MASK_3	(0x23C)
#define CAN2_REGS__RX_MASK_IDE		0
#define CAN2_REGS__RX_MASK_RTR		1
/**/
#define CAN2_REGS__RX_ID		(0x240)
#define CAN2_REGS__RX_ID_FIELD		0
/**/
#define CAN2_REGS__RX_CTRL		(0x244)
#define CAN2_REGS__RX_IDE		0
#define CAN2_REGS__RX_RTR		1
#define CAN2_REGS__RX_DLC		12
#define CAN2_REGS__RX_TIME		16
/**/
#define CAN2_REGS__RX_DATA0		(0x248)
#define CAN2_REGS__RX_DATA1		(0x24C)
/**/
#define CAN2_REGS__RX_COUNTERS		(0x250)
#define CAN2_REGS__RX_PEND		0
#define CAN2_REGS__RX_DROPS		16
#define CAN2_REGS__RX_ENA_IRQ		(0x254)
#define CAN2_REGS__RX_ENA		0
/**/
#define CAN2_REGS__RX_IRQ_TH		16
/*
 * Interrupts
 */
#define CAN2_REGS__IRQ_PEND		(0x300)
#define CAN2_REGS__STATE_IRQ_PEND	0
#define CAN2_REGS__TX_IRQ_PEND		1
#define CAN2_REGS__RX_IRQ_PEND		2

#endif /* MCST_CAN2_H__ */
