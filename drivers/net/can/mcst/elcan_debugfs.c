/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * elcan_debudfs.c - ELCAN/CAN2 module device driver
 *
 * DEBUGFS Driver Part
 *
 * Usage: mount -t debugfs none /sys/kernel/debug
 *
 * /sys/kernel/debug/<MODNAME>/<pcidev>/REG_COMMON  - RO - read COMMON regs
 * /sys/kernel/debug/<MODNAME>/<pcidev>/REG_TX      - RO - read TX regs
 * /sys/kernel/debug/<MODNAME>/<pcidev>/REG_RX_MASK - RO - read RX_MASK regs
 * /sys/kernel/debug/<MODNAME>/<pcidev>/REG_RX      - RO - read RX regs
 * /sys/kernel/debug/<MODNAME>/<pcidev>/reg_ops - RW - read/write registers
 *     Available commands for file write:
 *         read <reg>
 *         write <reg> <value>
 *     Read file to get result
 */

#include "elcan.h"


#ifdef CONFIG_DEBUG_FS

static struct dentry *elcan_dbg_root;


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

/* COMMON */
const u_int32_t elcan_dbg_reg_id_common[6] = {
	ELCAN_REV_ID_REG,
	ELCAN_TIMINGS_REG,
	ELCAN_FILTER_REG,
	ELCAN_CTLSTA_REG,
	ELCAN_ERROR_COUNTERS_REG,
	ELCAN_IRQ_PEND_REG,
};
const char *elcan_dbg_reg_name_common[6] = {
	"REV_ID: [31:00]REVISION (def: 0x0002E6A6)",
	"TIMING: [31:24]PHASE, [23:16]PROP, [15:00]PRESCALER (def: 0x0401FFFF)",
	"FILTER: [15:00]FILT (def: 0)",
	"CTLSTA: [17:16]STATE, [04]SIRQ, [03]SNIFF, [02]LB, [01]EN, [00]RST"
		" (def: 0x00020000)",
	"ERROR_COUNTERS: [31:16]RXERRORS, [15:00]TXERRORS (def: 0)",
	"IRQ_PEND: [02]RXIRQ, [01]TXIRQ, [00]STATEIRQ (def: 0)",
};

/* TX */
const u_int32_t elcan_dbg_reg_id_tx[6] = {
	ELCAN_TX_ID_REG,
	ELCAN_TX_DATA0_REG,
	ELCAN_TX_DATA1_REG,
	ELCAN_TX_CTRL_REG,
	ELCAN_TX_STATUS_REG,
	ELCAN_TX_IRQ_REG,
};
const char *elcan_dbg_reg_name_tx[6] = {
	"TX_ID: [28:18]BaseID, [17:00]ExID (def: 0x1FFFFFFF)",
	"TX_DATA0: [31:00]DATA (def: -)",
	"TX_DATA1: [31:00]DATA (def: -)",
	"TX_CTRL: [31:28]MBOX, [16]RTYINF, [15:12]DLC, [01]RTR, [00]IDE"
		" (def: - 0x?0000003)",
	"TX_STATUS: [31:16]BUSY, [15:00]PEND (def: 0)",
	"TX_IRQ: [15:00]IRQ_EN (def: 0)",
};

/* RX_MASK */
const u_int32_t elcan_dbg_reg_id_rx_mask[16] = {
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
};
const char *elcan_dbg_reg_name_rx_mask[16] = {
	"RX_ID_PATTERN_0: [28:00]ID (def: 0)",
	"RX_ID_PATTERN_1: -//- (def: 0)",
	"RX_ID_PATTERN_2: -//- (def: 0)",
	"RX_ID_PATTERN_3: -//- (def: 0)",
	"RX_CTRL_PATTERN_0: [15:12]MAX_DLC, [11:08]MIN_DLC, " \
		"[01]RTR, [00]IDE (def: 0)",
	"RX_CTRL_PATTERN_1: -//- (def: 0)",
	"RX_CTRL_PATTERN_2: -//- (def: 0)",
	"RX_CTRL_PATTERN_3: -//- (def: 0)",
	"RX_ID_MASK_0: [28:00]ID (def: 0)",
	"RX_ID_MASK_1: -//- (def: 0)",
	"RX_ID_MASK_2: -//- (def: 0)",
	"RX_ID_MASK_3: -//- (def: 0)",
	"RX_CTRL_MASK_0: [01]RTR, [00]IDE (def: 0)",
	"RX_CTRL_MASK_1: -//- (def: 0)",
	"RX_CTRL_MASK_2: -//- (def: 0)",
	"RX_CTRL_MASK_3: -//- (def: 0)",
};

/* RX */
const u_int32_t elcan_dbg_reg_id_rx[6] = {
	ELCAN_RX_ID_REG,
	ELCAN_RX_CTRL_REG,
	ELCAN_RX_DATA0_REG,
	ELCAN_RX_DATA1_REG,
	ELCAN_RX_COUNTERS_REG,
	ELCAN_RX_ENA_IRQ_REG,
};
const char *elcan_dbg_reg_name_rx[6] = {
	"RX_ID: [28:00]ID (def: 0)",
	"RX_CTRL: [31:16]TIME, [15:12]DLC, [01]RTR, [00]IDE (def: -)",
	"RX_DATA0: data (def: -)",
	"RX_DATA1: data (def: -)",
	"RX_COUNTERS: [31:16]DROP, [15:00]PEND (def: 0)",
	"RX_ENA_IRQ: [31:16]IRQ_TH, [00]ENA (def: 0xFFFF0000)",
};


/**
 ******************************************************************************
 * /sys/kernel/debug/elcan/<pcidev>/
 ******************************************************************************
 **/

#define DPREG_32(R, N) \
do { \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%05X: %08X - %s\n", \
		(R), priv->read_reg(priv, (R)), (N)); \
} while (0)


/**
 ******************************************************************************
 * /sys/kernel/debug/elcan/<pcidev>/REG_COMMON
 ******************************************************************************
 **/

static char elcan_dbg_reg_common_buf[PAGE_SIZE] = "";

static ssize_t elcan_dbg_reg_common_read(struct file *filp,
					 char __user *buffer, size_t count,
					 loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct elcan_priv *priv = filp->private_data;
	char *buf = elcan_dbg_reg_common_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - COMMON registers dump (hex) =\n",
			  priv->dev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(elcan_dbg_reg_id_common); i++) {
		DPREG_32(elcan_dbg_reg_id_common[i],
			 elcan_dbg_reg_name_common[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* elcan_dbg_reg_common_read */

static const struct file_operations elcan_dbg_reg_common_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = elcan_dbg_reg_common_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/elcan/<pcidev>/REG_TX
 ******************************************************************************
 **/

static char elcan_dbg_reg_tx_buf[PAGE_SIZE] = "";

static ssize_t elcan_dbg_reg_tx_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct elcan_priv *priv = filp->private_data;
	char *buf = elcan_dbg_reg_tx_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - TX registers dump (hex) =\n",
			  priv->dev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(elcan_dbg_reg_id_tx); i++) {
		DPREG_32(elcan_dbg_reg_id_tx[i], elcan_dbg_reg_name_tx[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* elcan_dbg_reg_tx_read */

static const struct file_operations elcan_dbg_reg_tx_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = elcan_dbg_reg_tx_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/elcan/<pcidev>/REG_RX_MASK
 ******************************************************************************
 **/

static char elcan_dbg_reg_rx_mask_buf[PAGE_SIZE] = "";

static ssize_t elcan_dbg_reg_rx_mask_read(struct file *filp,
					  char __user *buffer, size_t count,
					  loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct elcan_priv *priv = filp->private_data;
	char *buf = elcan_dbg_reg_rx_mask_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - RX_MASK registers dump (hex) =\n",
			  priv->dev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(elcan_dbg_reg_id_rx_mask); i++) {
		DPREG_32(elcan_dbg_reg_id_rx_mask[i],
			 elcan_dbg_reg_name_rx_mask[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* elcan_dbg_reg_rx_mask_read */

static const struct file_operations elcan_dbg_reg_rx_mask_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = elcan_dbg_reg_rx_mask_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/elcan/<pcidev>/REG_RX
 ******************************************************************************
 **/

static char elcan_dbg_reg_rx_buf[PAGE_SIZE] = "";

static ssize_t elcan_dbg_reg_rx_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	struct elcan_priv *priv = filp->private_data;
	char *buf = elcan_dbg_reg_rx_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s | %s - RX registers dump (hex) =\n",
			  priv->dev->name, pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(elcan_dbg_reg_id_rx); i++) {
		DPREG_32(elcan_dbg_reg_id_rx[i], elcan_dbg_reg_name_rx[i]);
	}

	if (count < strlen(buf)) {
		return -ENOSPC;
	}

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* elcan_dbg_reg_rx_read */

static const struct file_operations elcan_dbg_reg_rx_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = elcan_dbg_reg_rx_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/elcan/<pcidev>/reg_ops
 ******************************************************************************
 **/

static char elcan_dbg_reg_ops_buf[256] = "";

/**
 * elcan_dbg_reg_ops_read - read for reg_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 */
static ssize_t elcan_dbg_reg_ops_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	struct elcan_priv *priv = filp->private_data;
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
} /* elcan_dbg_reg_ops_read */

/**
 * elcan_dbg_reg_ops_write - write into reg_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 */
static ssize_t elcan_dbg_reg_ops_write(struct file *filp,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	struct elcan_priv *priv = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(elcan_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(elcan_dbg_reg_ops_buf,
				     sizeof(elcan_dbg_reg_ops_buf)-1,
				     ppos,
				     buffer,
				     count);
	if (len < 0)
		return len;

	elcan_dbg_reg_ops_buf[len] = '\0';

	/* parse cmd >>> */
	if (strncmp(elcan_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&elcan_dbg_reg_ops_buf[5], "%x %x", &reg, &value);
		if (cnt == 2) {
			priv->reg_last_value = value;
			priv->write_reg(priv, reg, value);
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			dev_err(&priv->pdev->dev,
				"debugfs reg_ops usage: write <reg> <value>\n");
		}
	} else if (strncmp(elcan_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&elcan_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			value = priv->read_reg(priv, reg);
			priv->reg_last_value = value;
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			dev_err(&priv->pdev->dev,
				"debugfs reg_ops usage: read <reg>\n");
		}
	} else {
		priv->reg_last_value = 0xFFFFFFFF;
		dev_err(&priv->pdev->dev,
			"debugfs reg_ops: Unknown command %s\n",
			elcan_dbg_reg_ops_buf);
		pr_cont("    Available commands:\n");
		pr_cont("      read <reg>\n");
		pr_cont("      write <reg> <value>\n");
	}
	/* parse cmd <<< */

	return count;
} /* elcan_dbg_reg_ops_write */


static const struct file_operations elcan_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = elcan_dbg_reg_ops_read,
	.write = elcan_dbg_reg_ops_write,
};


/**
 ******************************************************************************
 * Board Init Part
 ******************************************************************************
 **/

/**
 * elcan_dbg_board_init - setup the debugfs directory
 */
void elcan_dbg_board_init(struct elcan_priv *priv)
{
	const char *name = pci_name(priv->pdev);
	struct dentry *pfile;

	priv->elcan_dbg_board = debugfs_create_dir(name, elcan_dbg_root);
	if (priv->elcan_dbg_board) {
		/* reg_ops */
		pfile = debugfs_create_file("reg_ops", 0600,
					    priv->elcan_dbg_board, priv,
					    &elcan_dbg_reg_ops_fops);
		if (!pfile) {
			dev_err(&priv->pdev->dev,
				"debugfs create reg_ops failed\n");
		}
		/* COMMON */
		pfile = debugfs_create_file("REG_COMMON", 0400,
					    priv->elcan_dbg_board, priv,
					    &elcan_dbg_reg_common_fops);
		if (!pfile) {
			dev_err(&priv->pdev->dev,
				"debugfs create REG_COMMON failed\n");
		}
		/* TX */
		pfile = debugfs_create_file("REG_TX", 0400,
					    priv->elcan_dbg_board, priv,
					    &elcan_dbg_reg_tx_fops);
		if (!pfile) {
			dev_err(&priv->pdev->dev,
				"debugfs create REG_TX failed\n");
		}
		/* RX_MASK */
		pfile = debugfs_create_file("REG_RX_MASK", 0400,
					    priv->elcan_dbg_board, priv,
					    &elcan_dbg_reg_rx_mask_fops);
		if (!pfile) {
			dev_err(&priv->pdev->dev,
				"debugfs create REG_RX_MASK failed\n");
		}
		/* RX */
		pfile = debugfs_create_file("REG_RX", 0400,
					    priv->elcan_dbg_board, priv,
					    &elcan_dbg_reg_rx_fops);
		if (!pfile) {
			dev_err(&priv->pdev->dev,
				"debugfs create REG_RX failed\n");
		}
	} else {
		dev_err(&priv->pdev->dev,
			"debugfs create entry failed\n");
	}
} /* elcan_dbg_board_init */

/**
 * elcan_dbg_board_exit - clear out debugfs entries
 */
void elcan_dbg_board_exit(struct elcan_priv *priv)
{
	if (priv->elcan_dbg_board)
		debugfs_remove_recursive(priv->elcan_dbg_board);
	priv->elcan_dbg_board = NULL;
} /* elcan_dbg_board_exit */


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

/**
 * start up debugfs for the driver
 * Usage: mount -t debugfs none /sys/kernel/debug
 */
void elcan_dbg_init(void)
{
	elcan_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (elcan_dbg_root == NULL)
		pr_warning(KBUILD_MODNAME ": Init of debugfs failed\n");
} /* elcan_dbg_init */

/**
 * clean out the driver's debugfs entries
 */
void elcan_dbg_exit(void)
{
	if (elcan_dbg_root)
		debugfs_remove_recursive(elcan_dbg_root);
} /* elcan_dbg_exit */

#endif /* CONFIG_DEBUG_FS */
