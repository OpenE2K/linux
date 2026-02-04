/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_DBG_H__
#define MXGBE_DBG_H__


/**
 ******************************************************************************
 * Debug mask
 * for debug level:
 * echo 8 > /proc/sys/kernel/printk
 * and build module with DEBUG=y
 ******************************************************************************
 **/

/* for Module parameter debug_mask*/
#define MXGBE_DBG_MSK_NAME	0x00000002	/* func name */
#define MXGBE_DBG_MSK_MAC	0x00000010	/* mac */
#define MXGBE_DBG_MSK_NET	0x00000020	/* net */
#define MXGBE_DBG_MSK_MEM	0x00000040	/* ALLOC_RAM */
#define MXGBE_DBG_MSK_I2C	0x00000080	/* i2c */
#define MXGBE_DBG_MSK_IRQ	0x00000100	/* msi-x & mac irq */
#define MXGBE_DBG_MSK_TX	0x00000200	/* TX/TXQ */
#define MXGBE_DBG_MSK_RX	0x00000400	/* RX/RXQ */
#define MXGBE_DBG_MSK_PHY	0x00000800	/* mdio */
#define MXGBE_DBG_MSK_REGS	0x00001000	/* r/w regs */
#define MXGBE_DBG_MSK_GPIO	0x00002000	/* gpio */
#define MXGBE_DBG_MSK_NET_SKB	0x00004000	/* net skb */
#define MXGBE_DBG_MSK_NET_TX	0x00008000	/* net Tx */
#define MXGBE_DBG_MSK_NET_RX	0x00010000	/* net Rx */
#define MXGBE_DBG_MSK_TX_IRQ	0x00020000	/* Tx irq */
#define MXGBE_DBG_MSK_RX_IRQ	0x00040000	/* Rx irq */


/**
 ******************************************************************************
 *  Debug
 *
 *  DEBUG - defined in makefile
 ******************************************************************************
 **/

#undef PDEBUG
#ifdef DEBUG
#define PDEBUG(msk, fmt, args...) \
do { \
	if (mxgbe_debug_mask & msk) { \
		pr_debug(KBUILD_MODNAME ": " "[%lld] " fmt, \
		ktime_to_ns(ktime_get()), ## args); \
	} \
} while (0)
#else
#define PDEBUG(msk, fmt, args...) do {} while (0)
#endif

#undef nPDEBUG
#define nPDEBUG(msk, fmt, args...) do {} while (0)

#ifdef DEBUG
#define DEV_DBG(msk, dev, fmt, args...) \
do { \
	if (mxgbe_debug_mask & msk) { \
		dev_dbg(dev, fmt, ## args); \
	} \
} while (0)
#else
#define DEV_DBG(msk, dev, fmt, args...) do {} while (0)
#endif

#undef nDEV_DBG
#define nDEV_DBG(msk, dev, fmt, args...) do {} while (0)

#ifdef DEBUG
#define assert(expr) \
do { \
	if (!(expr)) { \
		printk(KERN_CRIT KBUILD_MODNAME \
		       ": Assertion failed! %s,%s,%s,line=%d\n", \
		       #expr, __FILE__, __func__, __LINE__); \
	} \
} while (0)
#else
#define assert(expr) do {} while (0)
#endif

#undef FDEBUG
#ifdef DEBUG
#define FDEBUG PDEBUG(MXGBE_DBG_MSK_NAME, "%s: %s +%d\n", \
	__func__, __FILE__, __LINE__)
#else
#define FDEBUG do {} while (0)
#endif

#undef nFDEBUG
#define nFDEBUG do {} while (0)


#endif /* MXGBE_DBG_H__ */
