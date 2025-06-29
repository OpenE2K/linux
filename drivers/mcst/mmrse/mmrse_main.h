/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MMRSE_MAIN_H__
#define MMRSE_MAIN_H__


#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/delay.h>
#include <linux/io.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <linux/version.h>
#include <linux/audit.h>
#include <linux/poll.h>

#ifndef DEBUG
#include <linux/mcst/mmrse_io.h>
#else
#include "mmrse_io.h"
#endif

#ifndef MODULE
#undef CONFIG_DEBUG_FS
#endif


/**
 *  PCI
 */
#define DEVICE_ID		0x801B
#define VENDOR_ID		0x1FFF
#define SUBSYSTEM_DEVICE_ID	PCI_ANY_ID
#define SUBSYSTEM_VENDOR_ID	PCI_ANY_ID

/* old MMR/M:
#define DEVICE_ID		0x8002
#define VENDOR_ID		0x1FFF
*/


/**
 *  Private structs
 */
typedef struct {
	/* pci */
	struct pci_dev	*pdev;		/* PCI device information struct */
	void __iomem	*reg_base;	/* ioremap'ed address to registers */
	void __iomem	*buf_base;	/* ioremap'ed address to buffers */
	int		dma_dis;	/* DMA disabled */

	/* cdev */
	struct cdev	cdev;
	struct cdev	cdev_bc;
	struct cdev	cdev_rt;
	struct cdev	cdev_bm;
	struct device	*dev;
	struct device	*dev_bc;
	struct device	*dev_rt;
	struct device	*dev_bm;
	unsigned int	minor;
	unsigned int	minor_bc;
	unsigned int	minor_rt;
	unsigned int	minor_bm;

	spinlock_t	cdev_open_lock;
	int		bc_device_open;
	int		rt_device_open;
	int		bm_device_open;
	/* <<< cdev_open_lock */

	/* buffs in main memory */
	size_t			dma_buff_size;	/* BC buffs + monitor log */
	size_t			bc_buff_size;	/* (monitor log offset) */
	void			*dma_buff;	/* CPU-viewed address */
	dma_addr_t		dma_buff_handle; /* device-viewed address */

	/* Bus Controller */
	wait_queue_head_t	wq_bc_event;	/* Send message complete */
	/* Saved in bc_irq: */
	spinlock_t		bc_lock;
	int			bc_last_result;
	uint16_t		bc_last_sw;
	uint16_t		bc_last_dw;
	/* <<< bc_lock */

	/* Remote Terminal */
	wait_queue_head_t	wq_rt_event;
	spinlock_t		rt_lock;
	uint32_t		last_rt_command_reg;
	uint32_t		last_rt_command_cnt;
	/* <<< rt_lock */
	/*struct fasync_struct *async_queue;*/	/* fasync method */

	/* Bus Monitor */
	size_t			bm_log_size;
	wait_queue_head_t	wq_bm_event;	/* New message in log */
	int			log_item;	/* Log contains data */
	spinlock_t		bm_lock;

#ifdef CONFIG_DEBUG_FS
	struct dentry		*mmrse_dbg_board;
	u32			reg_last_value;
#endif /*CONFIG_DEBUG_FS*/

	mmrse_stats_t		stats;
} mmrse_priv_t;


/* don't change this constants */
#define MMRSE_CDEV_MAIN  0
#define MMRSE_CDEV_BC    1
#define MMRSE_CDEV_RT    2
#define MMRSE_CDEV_BM    3


extern const struct file_operations mmrse_bc_dev_fops;
extern const struct file_operations mmrse_rt_dev_fops;
extern const struct file_operations mmrse_bm_dev_fops;


#endif /* MMRSE_MAIN_H__ */
