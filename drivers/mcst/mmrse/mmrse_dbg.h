/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MMRSE_DBG_H__
#define MMRSE_DBG_H__


/**
 * Debug mask
 * for Module parameter debug_mask
 *
 * for debug level:
 * echo 8 > /proc/sys/kernel/printk
 * and build module with DEBUG=y
 */
#define DBG_MSK_CDEV	0x00000001
#define DBG_MSK_CDEV_BC	0x00000002
#define DBG_MSK_CDEV_RT	0x00000004
#define DBG_MSK_CDEV_BM	0x00000008
#define DBG_MSK_IRQ	0x00000010
#define DBG_MSK_IRQ_BC	0x00000020
#define DBG_MSK_IRQ_RT	0x00000040
#define DBG_MSK_IRQ_BM	0x00000080

extern uint32_t debug_mask;


/**
 *  Debug
 *
 *  DEBUG - defined in makefile
 */
#undef PDEBUG
#ifdef DEBUG
#define PDEBUG(msk, fmt, args...) \
do { \
	if (debug_mask & msk) { \
		pr_debug(KBUILD_MODNAME ": " fmt, ## args); \
	} \
} while (0)
#else
#define PDEBUG(msk, fmt, args...) do {} while (0)
#endif

#ifdef DEBUG
#define DEV_DBG(msk, dev, fmt, args...) \
do { \
	if (debug_mask & msk) { \
		dev_dbg(dev, fmt, ## args); \
	} \
} while (0)
#else
#define DEV_DBG(msk, dev, fmt, args...) do {} while (0)
#endif

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


#endif /* MMRSE_DBG_H__ */
