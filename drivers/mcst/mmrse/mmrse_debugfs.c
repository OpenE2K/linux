/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * DEBUGFS Driver Part
 * Usage: mount -t debugfs none /sys/kernel/debug
 *
 * /sys/kernel/debug/mmrse/<pcidev>/REGS  - RO - registers dump
 * /sys/kernel/debug/mmrse/<pcidev>/BCSND - RO - BC Send buffs dump
 * /sys/kernel/debug/mmrse/<pcidev>/BCREC - RO - BC Receive buffs dump
 * /sys/kernel/debug/mmrse/<pcidev>/BUF1  - RO - All buffs dump for SA1
 * /sys/kernel/debug/mmrse/<pcidev>/RTOUT - RO - RT Output buffs dump
 * /sys/kernel/debug/mmrse/<pcidev>/RTIN  - RO - RT Input buffs dump
 * /sys/kernel/debug/mmrse/<pcidev>/STATS - RO - Statistics
 * /sys/kernel/debug/mmrse/<pcidev>/reg_ops - RW - read/write registers
 *     Available commands for file write:
 *         read <reg>
 *         write <reg> <value>
 *     Read file to get result
 */

#include "mmrse_main.h"
#include "mmrse_regs.h"

#ifdef CONFIG_DEBUG_FS

#include <linux/debugfs.h>


/* /sys/kernel/debug/mmrse */
static struct dentry *mmrse_dbg_root;

/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/REGS
 ******************************************************************************
 **/

/* REGS */
const u_int32_t mmrse_dbg_regs_id[21] = {
	COMMON_STATUS_REG,
	DMA_LATENCY_REG,
	BC_COMMAND_REG,
	BC_RESULT_REG,
	BC_CONTROL_REG,
	BC_STATUS_REG,
	RT_CONTROL_REG,
	RT_STATUS_REG,
	/*priv->last_rt_command_reg,*/
	RT_TASK_REG,
	RT_IVALID_REG,
	RT_IFLAG_REG,
	RT_IMODE_REG,
	RT_IMASK_REG,
	RT_OVALID_REG,
	RT_OFLAG_REG,
	RT_OMODE_REG,
	RT_OMASK_REG,
	BM_CONTROL_REG,
	BM_SADDR_REG,
	BM_WPTR_REG,
	BM_RPTR_REG,
};
const char *mmrse_dbg_regs_name[21] = {
	"Common_Status",
	"DMA_Latency",
	"BC_Command",
	"BC_Result",
	"BC_Control",
	"BC_Status",
	"RT_Control",
	"RT_Status",
	/*"RT_Command (saved)",*/
	"RT_Task",
	"RT_IValid",
	"RT_IFlag",
	"RT_IMode",
	"RT_IMask",
	"RT_OValid",
	"RT_OFlag",
	"RT_OMode",
	"RT_OMask",
	"BM_Control",
	"BM_SAddr",
	"BM_WPtr",
	"BM_RPtr",
};

#define DPREG_32(R, N) \
do { \
	u32 val = reg32rd(((void *)priv->reg_base) + (R)); \
	offs += \
	scnprintf(buf + offs, PAGE_SIZE - 1 - offs, \
		"%02X: %08X (%02X %02X %02X %02X) - %s\n", \
		(R), val, \
		(val >> 24) & 0xFF, \
		(val >> 16) & 0xFF, \
		(val >> 8)  & 0xFF, \
		(val >> 0)  & 0xFF, \
		(N)); \
} while (0)


static char mmrse_dbg_regs_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_regs_read(struct file *filp, char __user *buffer,
				   size_t count, loff_t *ppos)
{
	int i;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_regs_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - registers dump (hex) =\n",
			  pci_name(priv->pdev));

	for (i = 0; i < ARRAY_SIZE(mmrse_dbg_regs_id); i++) {
		DPREG_32(mmrse_dbg_regs_id[i], mmrse_dbg_regs_name[i]);
	}
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
		"%02X: %08X - %s\n",
		RT_COMMAND_REG, priv->last_rt_command_reg,
		"RT_Command (saved)");

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_regs_read */

static const struct file_operations mmrse_dbg_regs_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_regs_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/BCSND*
 ******************************************************************************
 **/

static char mmrse_dbg_bc_snd_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_bc_snd_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_bc_snd_buf;
	u16 *dma_buff;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - BC Send memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 0; j < 16; j++) {
		dma_buff = (u16 *)priv->dma_buff + (j * 32);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 16; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 16; i < 32; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_bc_snd_read */

static const struct file_operations mmrse_dbg_bc_snd_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_bc_snd_read,
};


static char mmrse_dbg_bc_snd1_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_bc_snd1_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_bc_snd1_buf;
	u16 *dma_buff;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - BC Send memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 16; j < 32; j++) {
		dma_buff = (u16 *)priv->dma_buff + (j * 32);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 16; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 16; i < 32; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_bc_snd1_read */

static const struct file_operations mmrse_dbg_bc_snd1_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_bc_snd1_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/BCREC*
 ******************************************************************************
 **/

static char mmrse_dbg_bc_rec_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_bc_rec_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_bc_rec_buf;
	u16 *dma_buff;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - BC Receive memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 0; j < 16; j++) {
		dma_buff = (u16 *)priv->dma_buff + (j * 32) + (32 * 32);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 16; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 16; i < 32; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_bc_rec_read */

static const struct file_operations mmrse_dbg_bc_rec_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_bc_rec_read,
};


static char mmrse_dbg_bc_rec1_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_bc_rec1_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_bc_rec1_buf;
	u16 *dma_buff;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - BC Receive memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 16; j < 32; j++) {
		dma_buff = (u16 *)priv->dma_buff + (j * 32) + (32 * 32);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 16; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 16; i < 32; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_bc_rec1_read */

static const struct file_operations mmrse_dbg_bc_rec1_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_bc_rec1_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/BUF1
 ******************************************************************************
 **/

static char mmrse_dbg_buf1_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_buf1_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_buf1_buf;
	u16 *dma_buff;
	u32 *ram_buff;
	u32 dat;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - BC Send memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 1; j < 2; j++) {
		dma_buff = (u16 *)priv->dma_buff + (j * 32);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 16; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 16; i < 32; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - BC Receive memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 1; j < 2; j++) {
		dma_buff = (u16 *)priv->dma_buff + (j * 32) + (32 * 32);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 16; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 16; i < 32; i++) {
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", *(dma_buff + i));
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - RT Output memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 1; j < 2; j++) {
		ram_buff = (u32 *)priv->buf_base + (j * 16);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 8; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 8; i < 16; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - RT Input memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 1; j < 2; j++) {
		ram_buff = (u32 *)priv->buf_base + (j * 16) + (32 * 16);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 8; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 8; i < 16; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_buf1_read */

static const struct file_operations mmrse_dbg_buf1_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_buf1_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/RTOUT*
 ******************************************************************************
 **/

static char mmrse_dbg_rt_out_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_rt_out_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_rt_out_buf;
	u32 *ram_buff;
	u32 dat;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - RT Output memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 0; j < 16; j++) {
		ram_buff = (u32 *)priv->buf_base + (j * 16);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 8; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 8; i < 16; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_rt_out_read */

static const struct file_operations mmrse_dbg_rt_out_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_rt_out_read,
};


static char mmrse_dbg_rt_out1_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_rt_out1_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_rt_out1_buf;
	u32 *ram_buff;
	u32 dat;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - RT Output memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 16; j < 32; j++) {
		ram_buff = (u32 *)priv->buf_base + (j * 16);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 8; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 8; i < 16; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_rt_out1_read */

static const struct file_operations mmrse_dbg_rt_out1_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_rt_out1_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/RTIN*
 ******************************************************************************
 **/

static char mmrse_dbg_rt_in_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_rt_in_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_rt_in_buf;
	u32 *ram_buff;
	u32 dat;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - RT Input memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 0; j < 16; j++) {
		ram_buff = (u32 *)priv->buf_base + (j * 16) + (32 * 16);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 8; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 8; i < 16; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_rt_in_read */

static const struct file_operations mmrse_dbg_rt_in_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_rt_in_read,
};


static char mmrse_dbg_rt_in1_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_rt_in1_read(struct file *filp, char __user *buffer,
				     size_t count, loff_t *ppos)
{
	int i, j;
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_rt_in1_buf;
	u32 *ram_buff;
	u32 dat;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - RT Input memory dump (hex) =\n",
			  pci_name(priv->pdev));

	for (j = 16; j < 32; j++) {
		ram_buff = (u32 *)priv->buf_base + (j * 16) + (32 * 16);
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "%02X: ", j);
		for (i = 0; i < 8; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
				  "\n    ");
		for (i = 8; i < 16; i++) {
			dat = buf32rd(ram_buff + i);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat & 0xFFFF);
			offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
					  "%04X ", dat >> 16);
		}
		offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs, "\n");
	}

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_rt_in1_read */

static const struct file_operations mmrse_dbg_rt_in1_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_rt_in1_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/STATS
 ******************************************************************************
 **/

static char mmrse_dbg_stats_buf[PAGE_SIZE] = "";

static ssize_t mmrse_dbg_stats_read(struct file *filp, char __user *buffer,
				    size_t count, loff_t *ppos)
{
	int len;
	int offs = 0;
	mmrse_priv_t *priv = filp->private_data;
	char *buf = mmrse_dbg_stats_buf;

	/* don't allow partial reads */
	if (*ppos != 0)
		return 0;

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "= %s - Statistics =\n",
			  pci_name(priv->pdev));

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: success    - %lld\n", priv->stats.bc_ok);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: crc error  - %lld\n", priv->stats.bc_ecrc);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: timeout    - %lld\n", priv->stats.bc_eto);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: specialSW  - %lld\n", priv->stats.bc_spec);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: wrong cmd  - %lld\n", priv->stats.bc_ecmd);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: pause      - %lld\n", priv->stats.bc_erp);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "BC: unknown    - %lld\n", priv->stats.bc_unk);

	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: DMA        - %lld\n", priv->stats.rt_dma);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: CMD        - %lld\n", priv->stats.rt_cmd);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: RX         - %lld\n", priv->stats.rt_rx);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: TX         - %lld\n", priv->stats.rt_tx);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: msg error  - %lld\n", priv->stats.rt_msgerr);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: instrum.   - %lld\n", priv->stats.rt_instr);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: srv req    - %lld\n", priv->stats.rt_srq);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: broadcast  - %lld\n", priv->stats.rt_bdcst);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: busy       - %lld\n", priv->stats.rt_busy);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: subsystem  - %lld\n", priv->stats.rt_subsys);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: bus accept - %lld\n", priv->stats.rt_busacpt);
	offs += scnprintf(buf + offs, PAGE_SIZE - 1 - offs,
			  "RT: terminal   - %lld\n", priv->stats.rt_term);

	if (count < strlen(buf))
		return -ENOSPC;

	len = simple_read_from_buffer(buffer, count, ppos, buf, strlen(buf));

	return len;
} /* mmrse_dbg_stats_read */

static const struct file_operations mmrse_dbg_stats_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_stats_read,
};


/**
 ******************************************************************************
 * /sys/kernel/debug/mmrse/<pcidev>/reg_ops
 ******************************************************************************
 **/

static char mmrse_dbg_reg_ops_buf[256] = "";

/**
 * mmrse_dbg_reg_ops_read - read for reg_ops datum
 * @filp: the opened file
 * @buffer: where to write the data for the user to read
 * @count: the size of the user's buffer
 * @ppos: file position offset
 **/
static ssize_t mmrse_dbg_reg_ops_read(struct file *filp, char __user *buffer,
				      size_t count, loff_t *ppos)
{
	mmrse_priv_t *priv = filp->private_data;
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
} /* mmrse_dbg_reg_ops_read */

/**
 * mmrse_dbg_reg_ops_write - write into reg_ops datum
 * @filp: the opened file
 * @buffer: where to find the user's data
 * @count: the length of the user's data
 * @ppos: file position offset
 **/
static ssize_t mmrse_dbg_reg_ops_write(struct file *filp,
				       const char __user *buffer,
				       size_t count, loff_t *ppos)
{
	mmrse_priv_t *priv = filp->private_data;
	int len;

	/* don't allow partial writes */
	if (*ppos != 0)
		return 0;
	if (count >= sizeof(mmrse_dbg_reg_ops_buf))
		return -ENOSPC;

	len = simple_write_to_buffer(mmrse_dbg_reg_ops_buf,
				     sizeof(mmrse_dbg_reg_ops_buf)-1,
				     ppos,
				     buffer,
				     count);
	if (len < 0)
		return len;

	mmrse_dbg_reg_ops_buf[len] = '\0';

	/* parse cmd >>> */
	if (strncmp(mmrse_dbg_reg_ops_buf, "write", 5) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&mmrse_dbg_reg_ops_buf[5], "%x %x", &reg, &value);
		if (cnt == 2) {
			priv->reg_last_value = value;
			reg32wr(value, ((void *)priv->reg_base) + reg);
		} else {
			priv->reg_last_value = 0xFFFFFFFF;
			pr_err(KBUILD_MODNAME
			       ": debugfs reg_ops usage: write <reg> <val>\n");
		}
	} else if (strncmp(mmrse_dbg_reg_ops_buf, "read", 4) == 0) {
		u32 reg, value;
		int cnt;
		cnt = sscanf(&mmrse_dbg_reg_ops_buf[4], "%x", &reg);
		if (cnt == 1) {
			value = reg32rd(((void *)priv->reg_base) + reg);
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
		       mmrse_dbg_reg_ops_buf);
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops: Available commands:\n");
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops:   read <reg>\n");
		pr_err(KBUILD_MODNAME
		       ": debugfs reg_ops:   write <reg> <val>\n");
	}
	/* parse cmd <<< */

	return count;
} /* mmrse_dbg_reg_ops_write */

static const struct file_operations mmrse_dbg_reg_ops_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = mmrse_dbg_reg_ops_read,
	.write = mmrse_dbg_reg_ops_write,
};


/**
 ******************************************************************************
 * Board Init Part
 ******************************************************************************
 **/

/**
 * mmrse_dbg_board_init - setup the debugfs directory
 **/
void mmrse_dbg_board_init(mmrse_priv_t *priv)
{
	const char *name = pci_name(priv->pdev);
	struct dentry *pfile;

	priv->mmrse_dbg_board = debugfs_create_dir(name, mmrse_dbg_root);
	if (priv->mmrse_dbg_board) {
		/* reg_ops */
		pfile = debugfs_create_file("reg_ops", 0600,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_reg_ops_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create reg_ops file failed\n");
		}
		/* REGS */
		pfile = debugfs_create_file("REGS", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_regs_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create REGS file failed\n");
		}
		/* BCSND */
		pfile = debugfs_create_file("BCSND", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_bc_snd_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create BCSND file failed\n");
		}
		/* BCSND1 */
		pfile = debugfs_create_file("BCSND1", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_bc_snd1_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create BCSND1 file failed\n");
		}
		/* BCREC */
		pfile = debugfs_create_file("BCREC", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_bc_rec_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create BCREC file failed\n");
		}
		/* BCREC1 */
		pfile = debugfs_create_file("BCREC1", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_bc_rec1_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create BCREC1 file failed\n");
		}
		/* BUF1 */
		pfile = debugfs_create_file("BUF1", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_buf1_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create BUF1 file failed\n");
		}
		/* RTOUT */
		pfile = debugfs_create_file("RTOUT", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_rt_out_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create RTOUT file failed\n");
		}
		/* RTOUT1 */
		pfile = debugfs_create_file("RTOUT1", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_rt_out1_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create RTOUT1 file failed\n");
		}
		/* RTIN */
		pfile = debugfs_create_file("RTIN", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_rt_in_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create RTIN file failed\n");
		}
		/* RTIN1 */
		pfile = debugfs_create_file("RTIN1", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_rt_in1_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create RTIN1 file failed\n");
		}
		/* STATS */
		pfile = debugfs_create_file("STATS", 0400,
					    priv->mmrse_dbg_board, priv,
					    &mmrse_dbg_stats_fops);
		if (!pfile) {
			dev_warn(&priv->pdev->dev,
				 "debugfs create STATS file failed\n");
		}
	} else {
		dev_warn(&priv->pdev->dev, "debugfs create dir failed\n");
	}
} /* mmrse_dbg_board_init */


/**
 * mmrse_dbg_board_exit - clear out debugfs entries
 **/
void mmrse_dbg_board_exit(mmrse_priv_t *priv)
{
	if (priv->mmrse_dbg_board)
		debugfs_remove_recursive(priv->mmrse_dbg_board);

	priv->mmrse_dbg_board = NULL;
} /* mmrse_dbg_board_exit */


/**
 ******************************************************************************
 * Module Part
 ******************************************************************************
 **/

/**
 * start up debugfs for the driver
 * Usage: mount -t debugfs none /sys/kernel/debug
 **/
void mmrse_dbg_init(void)
{
	mmrse_dbg_root = debugfs_create_dir(KBUILD_MODNAME, NULL);
	if (!mmrse_dbg_root)
		pr_warn(KBUILD_MODNAME ": Init of debugfs failed\n");
} /* mmrse_dbg_init */


/**
 * clean out the driver's debugfs entries
 **/
void mmrse_dbg_exit(void)
{
	if (mmrse_dbg_root)
		debugfs_remove_recursive(mmrse_dbg_root);

	mmrse_dbg_root = NULL;
} /* mmrse_dbg_exit */

#endif /* CONFIG_DEBUG_FS */
