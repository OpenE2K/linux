/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * CAN bus driver for MCST ELCAN/CAN2 controller
 */

#ifndef ELCAN_H
#define ELCAN_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/delay.h>
#include <linux/list.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/pm_runtime.h>

#include <linux/netdevice.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>

#include <linux/can.h>
#include <linux/can/dev.h>
#include <linux/can/error.h>
#include <linux/can/led.h>

#ifndef MODULE
#undef CONFIG_DEBUG_FS
#endif
#ifdef CONFIG_DEBUG_FS
#include <linux/debugfs.h>
#endif

#include "can2.h"


#define ELCAN_DRIVER_VERSION	"1.0.0"

#define ELCAN_PCH_FREQ		100000000	/* 100 MHz */

#define ELCAN_MSG_OBJ_TX_NUM	16	/* Mailbox 0..15 */

#define ELCAN_MSG_OBJ_RX_NUM	32

/* Wait for ~1 sec for reset complete */
#define INIT_WAIT_RST		1000


enum reg {
	/* Revision */
	ELCAN_REV_ID_REG = 0,
	/* General */
	ELCAN_TIMINGS_REG,
	ELCAN_FILTER_REG,
	/* Control/State */
	ELCAN_CTLSTA_REG,
	ELCAN_ERROR_COUNTERS_REG,
	/* TX */
	ELCAN_TX_ID_REG,
	ELCAN_TX_DATA0_REG,
	ELCAN_TX_DATA1_REG,
	ELCAN_TX_CTRL_REG,
	ELCAN_TX_STATUS_REG,
	ELCAN_TX_IRQ_REG,
	/* RX-mask */
	ELCAN_RX_ID_PATTERN_0_REG,
	ELCAN_RX_ID_PATTERN_1_REG,
	ELCAN_RX_ID_PATTERN_2_REG,
	ELCAN_RX_ID_PATTERN_3_REG,
	ELCAN_RX_CTRL_PATTERN_0_REG,
	ELCAN_RX_CTRL_PATTERN_1_REG,
	ELCAN_RX_CTRL_PATTERN_2_REG,
	ELCAN_RX_CTRL_PATTERN_3_REG,
	ELCAN_RX_ID_MASK_0_REG,
	ELCAN_RX_ID_MASK_1_REG,
	ELCAN_RX_ID_MASK_2_REG,
	ELCAN_RX_ID_MASK_3_REG,
	ELCAN_RX_CTRL_MASK_0_REG,
	ELCAN_RX_CTRL_MASK_1_REG,
	ELCAN_RX_CTRL_MASK_2_REG,
	ELCAN_RX_CTRL_MASK_3_REG,
	/* RX */
	ELCAN_RX_ID_REG,
	ELCAN_RX_CTRL_REG,
	ELCAN_RX_DATA0_REG,
	ELCAN_RX_DATA1_REG,
	ELCAN_RX_COUNTERS_REG,
	ELCAN_RX_ENA_IRQ_REG,
	/* Interrupts */
	ELCAN_IRQ_PEND_REG,
};

static const u16 reg_map_elcan[] = {
	/* Revision */
	[ELCAN_REV_ID_REG]		= CAN2_REGS__REV_ID,
	/* General */
	[ELCAN_TIMINGS_REG]		= CAN2_REGS__TIMINGS,
	[ELCAN_FILTER_REG]		= CAN2_REGS__FILTER,
	/* Control/State */
	[ELCAN_CTLSTA_REG]		= CAN2_REGS__CTLSTA,
	[ELCAN_ERROR_COUNTERS_REG]	= CAN2_REGS__ERR_COUNTERS,
	/* TX */
	[ELCAN_TX_ID_REG]		= CAN2_REGS__TX_ID,
	[ELCAN_TX_DATA0_REG]		= CAN2_REGS__TX_DATA0,
	[ELCAN_TX_DATA1_REG]		= CAN2_REGS__TX_DATA1,
	[ELCAN_TX_CTRL_REG]		= CAN2_REGS__TX_CTRL,
	[ELCAN_TX_STATUS_REG]		= CAN2_REGS__TX_STATUS,
	[ELCAN_TX_IRQ_REG]		= CAN2_REGS__TX_IRQ,
	/* RX-mask */
	[ELCAN_RX_ID_PATTERN_0_REG]	= CAN2_REGS__RX_ID_PTRN_0,
	[ELCAN_RX_ID_PATTERN_1_REG]	= CAN2_REGS__RX_ID_PTRN_1,
	[ELCAN_RX_ID_PATTERN_2_REG]	= CAN2_REGS__RX_ID_PTRN_2,
	[ELCAN_RX_ID_PATTERN_3_REG]	= CAN2_REGS__RX_ID_PTRN_3,
	[ELCAN_RX_CTRL_PATTERN_0_REG]	= CAN2_REGS__RX_CTRL_PTRN_0,
	[ELCAN_RX_CTRL_PATTERN_1_REG]	= CAN2_REGS__RX_CTRL_PTRN_1,
	[ELCAN_RX_CTRL_PATTERN_2_REG]	= CAN2_REGS__RX_CTRL_PTRN_2,
	[ELCAN_RX_CTRL_PATTERN_3_REG]	= CAN2_REGS__RX_CTRL_PTRN_3,
	[ELCAN_RX_ID_MASK_0_REG]	= CAN2_REGS__RX_ID_MASK_0,
	[ELCAN_RX_ID_MASK_1_REG]	= CAN2_REGS__RX_ID_MASK_1,
	[ELCAN_RX_ID_MASK_2_REG]	= CAN2_REGS__RX_ID_MASK_2,
	[ELCAN_RX_ID_MASK_3_REG]	= CAN2_REGS__RX_ID_MASK_3,
	[ELCAN_RX_CTRL_MASK_0_REG]	= CAN2_REGS__RX_CTRL_MASK_0,
	[ELCAN_RX_CTRL_MASK_1_REG]	= CAN2_REGS__RX_CTRL_MASK_1,
	[ELCAN_RX_CTRL_MASK_2_REG]	= CAN2_REGS__RX_CTRL_MASK_2,
	[ELCAN_RX_CTRL_MASK_3_REG]	= CAN2_REGS__RX_CTRL_MASK_3,
	/* RX */
	[ELCAN_RX_ID_REG]		= CAN2_REGS__RX_ID,
	[ELCAN_RX_CTRL_REG]		= CAN2_REGS__RX_CTRL,
	[ELCAN_RX_DATA0_REG]		= CAN2_REGS__RX_DATA0,
	[ELCAN_RX_DATA1_REG]		= CAN2_REGS__RX_DATA1,
	[ELCAN_RX_COUNTERS_REG]		= CAN2_REGS__RX_COUNTERS,
	[ELCAN_RX_ENA_IRQ_REG]		= CAN2_REGS__RX_ENA_IRQ,
	/* Interrupts */
	[ELCAN_IRQ_PEND_REG]		= CAN2_REGS__IRQ_PEND,
};

/* elcan private data structure */
struct elcan_priv {
	struct can_priv		can;		/* must be the first member */
	struct napi_struct	napi;
	struct net_device	*dev;		/* net dev */
	struct device		*device;	/* pdev->dev */
	struct pci_dev		*pdev;		/* pci dev */
	void __iomem		*base;		/* pci_iomap() */
	void			*priv;		/* for board-specific data */
	const u16		*regs;		/* reg_map_elcan */
	u32 (*read_reg) (const struct elcan_priv *priv, enum reg index);
	void (*write_reg) (const struct elcan_priv *priv, enum reg index,
			   u32 val);
	void (*caninit) (const struct elcan_priv *priv, bool enable);

#ifdef CONFIG_DEBUG_FS
	struct dentry		*elcan_dbg_board;
	u32			reg_last_value;
#endif /*CONFIG_DEBUG_FS*/

	/* status */
	atomic_t		sie_pending;
	u32			last_status;

	/* xmit */
	atomic_t tx_active;
	u32 dlc[ELCAN_MSG_OBJ_TX_NUM];
};

int elcan_register_dev(struct net_device *dev);
void elcan_unregister_dev(struct net_device *dev);
struct net_device *elcan_alloc_dev(void);
void elcan_free_dev(struct net_device *dev);

#endif /* ELCAN_H */
