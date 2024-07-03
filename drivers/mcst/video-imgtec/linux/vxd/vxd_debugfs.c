/*!
 *****************************************************************************
 *
 * @File       vxd_debugfs.c
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/


#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/debugfs.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/kthread.h>
#include <linux/err.h>
#include <linux/moduleparam.h>
#include <linux/vmalloc.h>
#include <linux/firmware.h>

#include <uapi/vxd_pvdec.h>
#include "vxd_common.h"
#include "vxd_pvdec_regs.h"
#include "vxd_debugfs.h"

/* Debug fs entries */
#define MTX_FIFO_NAME "mtx_fifo"
#define MTX_RAM_NAME "mtx_ram"
#define DRV_STATUS_NAME "drv_status"
#define DRV_FORCE_EMRG_NAME "force_emrg"
#define MTX_STATUS_NAME "mtx_status"
#define MTX_TIMER_DIV_NAME "mtx_timer_div"
#define CORE_HW_STATUS_NAME "hw_on"
#define CORE_CLOCK_FREQ_NAME "core_freq_khz"
#define CORE_FW_BOOT_TIME_NAME "fw_boot_time_us"
#define CORE_FW_WAIT_DBG_FIFO_NAME "fw_wait_dbg_fifo"
#define CORE_UPTIME_NAME "core_uptime_ms"
#define CORE_MEM_USAGE_LAST "mem_usage_last"
#define CORE_KEEP_ON_NAME "keep_hw_on"
#define CORE_UPLOAD_DMA_NAME "fw_upload_dma"
#define CORE_PM_DELAY_NAME "hw_pm_delay"
#define CORE_BOOT_DELAY_NAME "boot_msleep"
#define CORE_DWR_PERIOD_NAME "hw_dwr_period"
#define CORE_HW_CRC_NAME "hw_crc"
#define CORE_MEMSTALLER_NAME "core_memstaller"
#define CORE_PTE_DUMP_NAME "pte_dump"
#define CORE_CUSTOM_FW_NAME "custom_fw"
#define REGIO_NAME "reg_io"

/* Debug fs local buffer size */
#define DBG_TMP_BUF_DWORDS 128

/* Declare 256kB for mtx fifo buffered reader by default */
static unsigned int dbgbuf_ringsize_kb = 256;
module_param(dbgbuf_ringsize_kb, uint, S_IRUSR | S_IRGRP);

static const char regset_entry_name[] = "*()";

static const struct dev_regspace {
	const char *name;
	u32 offset;
	u16 size;

} reg_spaces[DBGFS_REGIO_MAX] = {
		{ "proc", PVDEC_PROC_OFFSET, PVDEC_PROC_SIZE },
		{ "core", PVDEC_CORE_OFFSET, PVDEC_CORE_SIZE },
		{ "bus4_mmu", VIDEO_BUS4_MMU_OFFSET, VIDEO_BUS4_MMU_SIZE },
		{ "entropy", PVDEC_ENTROPY_OFFSET, PVDEC_ENTROPY_SIZE },
		{ "pixel_pipe", PVDEC_PIXEL_OFFSET, PVDEC_PIXEL_SIZE },
		{ "dmac", DMAC_OFFSET, DMAC_SIZE },
		{ "mtx_core", MTX_CORE_OFFSET, MTX_CORE_SIZE },
		{ "core_test", PVDEC_TEST_OFFSET, PVDEC_TEST_SIZE },
		{ "vlr", VLR_OFFSET, VLR_SIZE },
		{ "iqram", IQRAM_OFFSET, IQRAM_SIZE },
};

static int vxd_dbgfs_mtxfifo_reader(void *data)
{
	struct vxd_dev *vxd = (struct vxd_dev *)data;
	struct vxd_dbgfs_ctx *ctx =
		(struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;
	u32 *mtx_fifo_buf = NULL;
	int ret = 0;

	dev_info(vxd->dev, "%s: debug fifo size(dwords) sw: %u hw: %u\n",
			__func__, dbgbuf_ringsize_kb << 8,
			vxd->props.dbg_fifo_size);

	mtx_fifo_buf = kmalloc(vxd->props.dbg_fifo_size * sizeof(u32),
			GFP_KERNEL);
	if (!mtx_fifo_buf) {
		dev_err(vxd->dev,
				"%s: failed to allocate temporary mtx buffer!\n",
				__func__);
		ret = -ENOMEM;
		goto exit;
	}

	ret = kfifo_alloc(&ctx->mtx_fifo.pipe,
			dbgbuf_ringsize_kb << 10, GFP_KERNEL);
	if (ret) {
		dev_err(vxd->dev,
				"%s: failed to allocate kfifo!\n",
				__func__);
		goto kfifo_err;
	}
	mutex_unlock(&ctx->mtx_fifo.lock);

	dev_dbg(vxd->dev, "%s: starting thread!\n",
			__func__);

	/* Try to read until the thread is stopped */
	while (!kthread_should_stop()) {
		size_t read = 0; /* dwords */
		size_t write = 0; /* dwords */

		mutex_lock(&ctx->mtx_fifo.lock);
		write = kfifo_avail(&ctx->mtx_fifo.pipe);
		mutex_unlock(&ctx->mtx_fifo.lock);

		/* Check if we have at least hw dwords of free space,
		 * to read those at once, or if no client -> drop data */
		if (write >= vxd->props.dbg_fifo_size * sizeof(u32) ||
			!ctx->mtx_fifo.attached) {

			read = vxd_read_mtx_fifo(vxd, mtx_fifo_buf,
						vxd->props.dbg_fifo_size * sizeof(u32));
			if ((int)read > 0) {
				mutex_lock(&ctx->mtx_fifo.lock);

				write = kfifo_in(&ctx->mtx_fifo.pipe,
							mtx_fifo_buf, read * sizeof(u32));
				if (!write)
					dev_warn(vxd->dev,
							"%s: kfifo is full, dropping data!\n",
							__func__);

				wake_up(&ctx->queue);
				mutex_unlock(&ctx->mtx_fifo.lock);
			}
		}
		{ /* else */
			/* Put the reader into sleep ... */
			unsigned int enabled;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
			set_current_state(TASK_INTERRUPTIBLE);
#else
			set_task_state(ctx->mtx_fifo.reader,
					TASK_INTERRUPTIBLE);
#endif

			ret = vxd_check_dev(vxd, &enabled);
			if (ret < 0 || !enabled)
				schedule();
			else
				schedule_timeout(msecs_to_jiffies(1));
		}
	}

	dev_dbg(vxd->dev, "%s: stopping thread!\n",
			__func__);

	/* Finally cleanup the extra kfifo buffer */
	kfifo_free(&ctx->mtx_fifo.pipe);
kfifo_err:
	kfree(mtx_fifo_buf);
exit:
	return ret;
}

static int vxd_dbgfs_mtxfifo_open(struct inode *inode, struct file *file)
{
	struct vxd_dev *vxd;
	struct vxd_dbgfs_ctx *ctx;
	int ret;

	if (!inode->i_private)
		return -ENOENT;

	file->private_data = inode->i_private;
	vxd = file->private_data;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	/* We turn on the blocking mode by default */
	vxd->fw_wait_dbg_fifo = 1;
	mutex_unlock(&vxd->mutex);

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	/* Create reader thread when mtx fifo is open for the very first time */
	if (ctx->mtx_fifo.reader == NULL) {
		ctx->mtx_fifo.reader = kthread_create(vxd_dbgfs_mtxfifo_reader,
				vxd, MTX_FIFO_NAME"_reader");
		if (IS_ERR(ctx->mtx_fifo.reader)) {
			int err = PTR_ERR(ctx->mtx_fifo.reader);
			dev_err(vxd->dev, "%s: failed to create reader thread!\n",
					__func__);
			ctx->mtx_fifo.reader = NULL;

			return err;
		}

		mutex_init(&ctx->mtx_fifo.lock);
		mutex_lock(&ctx->mtx_fifo.lock);

		memset(&ctx->mtx_fifo.pipe, 0, sizeof(struct kfifo));

		/* Run on the main cpu core only */
		kthread_bind(ctx->mtx_fifo.reader, 0);

		/* Wake up the reader process
		 * for the very first time */
		wake_up_process(ctx->mtx_fifo.reader);

	} else {
		/* Just reset the fifo if we reopened the pipe */
		if (kfifo_initialized(&ctx->mtx_fifo.pipe))
			kfifo_reset(&ctx->mtx_fifo.pipe);
	}

	ctx->mtx_fifo.attached = 1;

	return 0;
}

static int vxd_dbgfs_mtxfifo_release(struct inode *inode, struct file *file)
{
	struct vxd_dev *vxd;
	struct vxd_dbgfs_ctx *ctx;
	int ret = 0;

	if (!inode->i_private)
		return -ENOENT;

	file->private_data = inode->i_private;
	vxd = file->private_data;
	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	vxd->fw_wait_dbg_fifo = 0;
	mutex_unlock(&vxd->mutex);

	ret = mutex_lock_interruptible(&ctx->mtx_fifo.lock);
	if (ret)
		return ret;

	ctx->mtx_fifo.attached = 0;
	mutex_unlock(&ctx->mtx_fifo.lock);

	return 0;
}

static ssize_t vxd_dbgfs_mtxfifo_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	struct vxd_dbgfs_ctx *ctx = (struct vxd_dbgfs_ctx *)
		vxd->dbgfs_ctx;
	unsigned int read; /* bytes */
	int ret = 0;

	if (count % sizeof(u32))
		return -EINVAL;

	ret = mutex_lock_interruptible(&ctx->mtx_fifo.lock);
	if (ret)
		return ret;

	if (kfifo_initialized(&ctx->mtx_fifo.pipe)) {
		/* Blocking mode */
		if (!(file->f_flags & O_NONBLOCK)) {
			/* Check fifo ... */
			if (kfifo_is_empty(&ctx->mtx_fifo.pipe)) {

				mutex_unlock(&ctx->mtx_fifo.lock);
				/* Wait for some items to be fetched by the reader ... */
				if (wait_event_interruptible(ctx->queue,
							!kfifo_is_empty(&ctx->mtx_fifo.pipe))) {
					dev_dbg(vxd->dev, "%s: signal!\n",
							__func__);
					return -ERESTARTSYS;
				}
				dev_dbg(vxd->dev, "%s: woken up by the reader !\n",
						__func__);

				ret = mutex_lock_interruptible(&ctx->mtx_fifo.lock);
				if (ret)
					return ret;
			}
		}
		/* Just return the number of avialable items,
		 * for non-blocking mode return zero if fifo is empty,
		 * for blocking mode will have at least one word to be returned */
		ret = kfifo_to_user(&ctx->mtx_fifo.pipe, buf, count, &read);

		/* Poke the reader to fill up the fifo */
		wake_up_process(ctx->mtx_fifo.reader);

	} else
		ret = -EINVAL;

	mutex_unlock(&ctx->mtx_fifo.lock);

	return ret ? ret : read;
}

static ssize_t vxd_dbgfs_mtxram_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	struct vxd_dbgfs_ctx *ctx = (struct vxd_dbgfs_ctx *)
		vxd->dbgfs_ctx;
	u32 mtx_ram_buf[DBG_TMP_BUF_DWORDS];
	size_t total = 0; /* total data put to buf, in bytes */
	int ret = 0;
	int dwords = (*ppos) / sizeof(u32);

	if (count % sizeof(u32))
		return -EINVAL;

	while (dwords < ctx->mtx_ram_dwords &&
			count > total) {
		size_t left = ctx->mtx_ram_dwords - dwords;
		size_t to_read = left > DBG_TMP_BUF_DWORDS ?
			DBG_TMP_BUF_DWORDS : left;

		memset(mtx_ram_buf, 0, sizeof(mtx_ram_buf));
		/* TODO: The below call stalls the mtx,
		 * this can be a problem when dumping in the middle
		 * of something,
		 * so put this under global mtx halt function ?
		 */
		ret = vxd_read_mtx_ram(vxd, ctx->mtx_ram_offs + dwords,
				to_read, mtx_ram_buf, sizeof(mtx_ram_buf));
		if (ret < 0)
			break;
		schedule();

		ret = copy_to_user(buf + total,
				mtx_ram_buf, to_read * sizeof(u32));
		if (ret) {
			dev_err(vxd->dev, "%s: mtx ram: copy to user failed\n",
					__func__);
			ret = -EFAULT;
			break;
		}

		dwords += to_read;
		total = dwords * sizeof(u32) - *ppos;
	};

	*ppos = dwords * sizeof(u32);

	/* If IO error detected, return the error. */
	if (ret)
		return ret;

	return total;
}

static ssize_t vxd_dbgfs_regio_raw_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	u32 reg_io_buf[DBG_TMP_BUF_DWORDS];
	size_t total = 0; /* total data put to buf, in bytes */
	int ret = 0;
	int dwords = (*ppos)/sizeof(u32);
	unsigned int enabled;

	if (count % sizeof(u32))
		return -EINVAL;

	/* Before accessing regio with need to be sure
	 * the device is online, otherwise we would get a kernel lockup
	 */
	ret = vxd_check_dev(vxd, &enabled);
	if (ret < 0 || !enabled) {
		dev_err(vxd->dev,
			"%s: cannot read reg_io while device is turned off!\n",
			__func__);
		return -EIO;
	}

	while (dwords < DBGFS_REGIO_RAW_DWORDS &&
			count > total) {
		size_t left = DBGFS_REGIO_RAW_DWORDS - dwords;
		size_t to_read = left > DBG_TMP_BUF_DWORDS ?
			DBG_TMP_BUF_DWORDS : left;

		{
			u32 *dst = reg_io_buf;
			const u32 __iomem *src = vxd->reg_base +
				dwords * sizeof(u32);
			const u32 __iomem *end = src + to_read;

			while (src < end)
				*dst++ = __raw_readl(src++);
		}
		schedule();

		ret = copy_to_user(buf + total,
				reg_io_buf, to_read * sizeof(u32));
		if (ret) {
			dev_err(vxd->dev, "%s: reg_io: copy to user failed\n",
					__func__);
			ret = -EFAULT;
			break;
		}

		dwords += to_read;
		total = dwords * sizeof(u32) - *ppos;
	};

	*ppos = dwords * sizeof(u32);

	/* If IO error detected, return the error. */
	if (ret)
		return ret;

	return total;
}

static ssize_t vxd_dbgfs_drvstatus_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	struct vxd_core_props *props = &vxd->props;
	struct vxd_link *link;
	struct vxd_item *item;

	char *status_buf = NULL;
	size_t total = 0; /* total data put to buf, in bytes */
	int ret = 0;

	if (*ppos)
		return 0;

	if (count >= PAGE_SIZE)
		count = PAGE_SIZE-1;

	status_buf = kmalloc(count, GFP_KERNEL);
	if (status_buf == NULL)
		return -ENOMEM;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		goto exit;

	/* core properties */
	if (total < count)
		total += snprintf(status_buf+total, count-total,
			  "PROPS:\n  id:%08x core_rev:%08x core_id:%08x mtx_ram:%08x\n",
			  props->id, props->core_rev,
			  props->pvdec_core_id,
			  props->mtx_ram_size);

	/* process links */
	if (total < count)
		total += snprintf(status_buf+total, count-total,
			  "processes:\n");
	list_for_each_entry(link, &vxd->links, list) {
		if (total < count)
			total += snprintf(status_buf+total, count-1-total,
				  "  num_items:%08x\n",
				  link->num_items);
	}

	/* messages */
	if (total < count)
		total += snprintf(status_buf+total, count-total, "msgs:\n");
	list_for_each_entry(item, &vxd->msgs, list) {
		if (total < count)
			total += snprintf(status_buf+total, count-1-total,
				  "  str:%x msg:%x\n",
				  item->str_id, item->msg_id);
	}

	/* pending items */
	if (total < count)
		total += snprintf(status_buf+total, count-total,
			  "pending:\n");
	list_for_each_entry(item, &vxd->pend, list) {
		if (total < count)
			total += snprintf(status_buf+total, count-1-total,
				  "  str:%x msg:%x\n",
				  item->str_id, item->msg_id);
	}
	if (total < count)
		total += snprintf(status_buf+total, count-total,
			  "num submitted msgs:%08x\n", vxd->msg_cnt);

	status_buf[count-1] = '\0';
	if (total > count)
		total = count;
	ret = copy_to_user(buf, status_buf, total);
	if (ret) {
		dev_err(vxd->dev, "%s: drv_status: copy to user failed\n",
				__func__);
		ret = -EFAULT;
	}
	mutex_unlock(&vxd->mutex);

exit:
	kfree(status_buf);

	*ppos = total;
	/* If IO error detected, return the error. */
	if (ret)
		return ret;

	return total;
}

static ssize_t vxd_dbgfs_mtxstatus_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	char status_buf[100];
	size_t total = 0; /* total data put to buf, in bytes */
	int ret = 0;

	struct mtx_status {
		u32 pc;
		u32 pcx;
		u32 a0stp;
		u32 a0frp;
	} status;

	if (count < sizeof(struct mtx_status))
		return -EINVAL;

	if (*ppos)
		return 0;

	ret = vxd_read_mtx_status(vxd, (u32 *)&status,
			sizeof(struct mtx_status));
	if (ret < 0) {
		dev_err(vxd->dev, "%s: failed to read mtx_status!\n",
				__func__);
		return ret;
	}

	memset(status_buf, 0, sizeof(status_buf));
	sprintf(status_buf,
		"PC:   0x%08x\nPCX:  0x%08x\nA0STP:0x%08x\nA0FRP:0x%08x\n",
		status.pc, status.pcx, status.a0stp, status.a0frp);

	ret = copy_to_user(buf, status_buf,
			strlen(status_buf));
	if (ret) {
		dev_err(vxd->dev, "%s: mtx_status: copy to user failed\n",
				__func__);
		ret = -EFAULT;
	}

	total = strlen(status_buf);
	*ppos = total;
	/* If IO error detected, return the error. */
	if (ret)
		return ret;

	return total;
}

static ssize_t vxd_dbgfs_memstaller_write(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	u32 conf_buf[8];
	int ret = 0;

	if (*ppos)
		return 0;

	if (count % sizeof(u32))
		return -EINVAL;

	if (count > sizeof(conf_buf))
		return -EINVAL;

	if (copy_from_user(conf_buf, buf, count))
		return -EFAULT;

	ret = vxd_setup_memstaller(vxd, conf_buf, count/sizeof(u32));
	if (ret)
		return ret;

	*ppos = count;

	return count;
}

static ssize_t vxd_dbgfs_force_emrg_write(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	char emrg_buf[25];
	long val = 0;
	int ret = 0;

	if (*ppos)
		return 0;

	if (copy_from_user(emrg_buf, buf, count))
		return -EFAULT;

	if (kstrtol(emrg_buf, 0, &val))
		return -EFAULT;

	ret = vxd_force_emergency(vxd, val);
	if (ret)
		return ret;

	*ppos = count;

	return count;
}

#define PTEDUMP_SIZE 0x1000000
__printf(3, 4)
static void ptedump_printf(char *buf, size_t *len, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);

	if (*len < PTEDUMP_SIZE)
		*len += vsnprintf(buf + *len, PTEDUMP_SIZE-*len, fmt, ap);
	va_end(ap);

	if (*len > PTEDUMP_SIZE)
		*len = PTEDUMP_SIZE;

	if (*len >= PTEDUMP_SIZE-5)
		strcpy(buf + PTEDUMP_SIZE-5, "...\n");
}

static int vxd_dbgfs_ptedump_open(struct inode *inode, struct file *file)
{
	struct vxd_dev *vxd;
	struct vxd_stream *stream;
	struct vxd_link *link;
	struct vxd_dbgfs_ctx *ctx;
	int ret = 0;
	char *dump_buf;
	size_t *total;

	if (!inode->i_private)
		return -ENOENT;

	file->private_data = inode->i_private;
	vxd = file->private_data;

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	ctx->ptedump_buf = vmalloc(PTEDUMP_SIZE);
	if (ctx->ptedump_buf == NULL)
		return -ENOMEM;

	dump_buf = ctx->ptedump_buf;
	total = &ctx->ptedump_size;
	*total = 0;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret) {
		vfree(ctx->ptedump_buf);
		return ret;
	}

	ptedump_printf(dump_buf, total, "MMU dump:\n");

	list_for_each_entry(link, &vxd->links, list) {
		list_for_each_entry(stream, &link->streams, list) {
			uint32_t vaddr = 0;

			ptedump_printf(dump_buf, total,
				  "  link:%p str:%x\n", link->mem_ctx, stream->id);
			/* Scan 32bit virtual space */
			while (vaddr < (1UL<<32)-PAGE_SIZE) {
				phys_addr_t paddr;
				uint8_t flags;

				paddr = img_mmu_get_paddr(stream->mmu_ctx, vaddr, &flags);
				if (flags)
					ptedump_printf(dump_buf, total,
							"    vaddr:0x%x paddr:0x%llx flags:0x%x\n",
							vaddr, paddr, flags);
				/* Advance by page size */
				vaddr += PAGE_SIZE;
			}
		}
	}
	mutex_unlock(&vxd->mutex);
	dump_buf[*total-1] = 0;

	return 0;
}

static int vxd_dbgfs_ptedump_release(struct inode *inode, struct file *file)
{
	struct vxd_dev *vxd;
	struct vxd_dbgfs_ctx *ctx;

	if (!inode->i_private)
		return -ENOENT;

	file->private_data = inode->i_private;
	vxd = file->private_data;
	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;
	vfree(ctx->ptedump_buf);

	return 0;
}

static ssize_t vxd_dbgfs_ptedump_read(struct file *file, char __user *buf,
			size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	struct vxd_dbgfs_ctx *ctx;
	int ret = 0;

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	if (*ppos > ctx->ptedump_size)
		return 0;

	if (count > ctx->ptedump_size - *ppos)
		count = ctx->ptedump_size - *ppos;

	ret = copy_to_user(buf, ctx->ptedump_buf + *ppos, count);
	if (ret) {
		dev_err(vxd->dev, "%s: ptedump: copy to user failed\n",
				__func__);
		ret = -EFAULT;
	}

	*ppos += count;
	/* If IO error detected, return the error. */
	if (ret)
		return ret;

	return count;
}

#define CUSTOM_FW_MAX_SIZE (1 * 1024 *1024)
static int vxd_dbgfs_custom_fw_open(struct inode *inode, struct file *file)
{
	struct vxd_dev *vxd;
	struct vxd_dbgfs_ctx *ctx;

	if (!inode->i_private)
		return -ENOENT;

	file->private_data = inode->i_private;
	vxd = file->private_data;

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	if (!ctx->cfw_buf) {
		ctx->cfw_buf = vmalloc(CUSTOM_FW_MAX_SIZE);
		if (ctx->cfw_buf == NULL)
			return -ENOMEM;
	}

	ctx->cfw_size = 0;

	return 0;
}

static int vxd_dbgfs_custom_fw_release(struct inode *inode, struct file *file)
{
	struct vxd_dev *vxd;
	struct vxd_dbgfs_ctx *ctx;

	if (!inode->i_private)
		return -ENOENT;

	file->private_data = inode->i_private;
	vxd = file->private_data;
	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	dev_info(vxd->dev, "Applying custom firmware: size:%zu\n",
				ctx->cfw_size);

	vxd_reload_fws(vxd);
	/* We can't free the allocated memory
	 * as it is used by the driver */
#if 0
	vfree(ctx->cfw_buf);
	ctx->cfw_buff = NULL;
#endif

	return 0;
}

static ssize_t vxd_dbgfs_custom_fw_write(struct file *file,
		const char __user *buf, size_t count, loff_t *ppos)
{
	struct vxd_dev *vxd = file->private_data;
	struct vxd_dbgfs_ctx *ctx;
	int ret = 0;

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	if (*ppos >= CUSTOM_FW_MAX_SIZE)
		return -ENOMEM;

	if (count > CUSTOM_FW_MAX_SIZE - ctx->cfw_size)
		return -ENOMEM;

	ret = copy_from_user(ctx->cfw_buf + *ppos, buf, count);
	if (ret) {
		dev_err(vxd->dev, "%s: copy from user failed\n",
				__func__);
		ret = -EFAULT;
	}

	*ppos += count;
	ctx->cfw_size = *ppos;
	/* If IO error detected, return the error. */
	if (ret)
		return ret;

	return count;
}

int vxd_dbgfs_request_fw(struct vxd_dev *vxd, const char *name,
		const struct firmware **fw)
{
	struct vxd_dbgfs_ctx *ctx;
	struct firmware *cfw;

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	if (!ctx || !ctx->cfw_buf || !ctx->cfw_size)
		return -EFAULT;

	cfw = kzalloc(sizeof(struct firmware), GFP_KERNEL);
	if (cfw == NULL)
		return -ENOMEM;

	cfw->size = ctx->cfw_size;
	cfw->data = ctx->cfw_buf;
	ctx->cfw_ref++;

	*fw = cfw;

	return 0;
}

int vxd_dbgfs_release_fw(struct vxd_dev *vxd, const struct firmware *fw)
{
	struct vxd_dbgfs_ctx *ctx;

	ctx = (struct vxd_dbgfs_ctx *) vxd->dbgfs_ctx;

	if (!ctx || !ctx->cfw_buf ||
			!ctx->cfw_size || !ctx->cfw_ref)
		return -EFAULT;
	
	ctx->cfw_ref--;

	kfree(fw);

	return 0;
}

static const struct file_operations vxd_dbgfs_mtxfifo_fops = {
	.owner = THIS_MODULE,
	.open = vxd_dbgfs_mtxfifo_open,
	.read = vxd_dbgfs_mtxfifo_read,
	.release = vxd_dbgfs_mtxfifo_release
};

static const struct file_operations vxd_dbgfs_mtxram_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = vxd_dbgfs_mtxram_read,
};

static const struct file_operations vxd_dbgfs_regio_raw_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = vxd_dbgfs_regio_raw_read,
};

static const struct file_operations vxd_dbgfs_drvstatus_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = vxd_dbgfs_drvstatus_read,
};

static const struct file_operations vxd_dbgfs_mtxstatus_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.read = vxd_dbgfs_mtxstatus_read,
};

static const struct file_operations vxd_dbgfs_memstaller_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = vxd_dbgfs_memstaller_write,
};

static const struct file_operations vxd_dbgfs_force_emrg_fops = {
	.owner = THIS_MODULE,
	.open = simple_open,
	.write = vxd_dbgfs_force_emrg_write,
};

static const struct file_operations vxd_dbgfs_ptedump_fops = {
	.owner = THIS_MODULE,
	.open = vxd_dbgfs_ptedump_open,
	.read = vxd_dbgfs_ptedump_read,
	.release = vxd_dbgfs_ptedump_release
};

static const struct file_operations vxd_dbgfs_custom_fw_fops = {
	.owner = THIS_MODULE,
	.open = vxd_dbgfs_custom_fw_open,
	.write = vxd_dbgfs_custom_fw_write,
	.release = vxd_dbgfs_custom_fw_release
};

static inline void clean_regsets(struct vxd_dev *vxd)
{
	struct vxd_dbgfs_ctx *ctx;
	int region;
	int pipe;

	ctx = (struct vxd_dbgfs_ctx *)vxd->dbgfs_ctx;

	for (pipe = 0; pipe < VXD_NUM_PIX_PIPES(vxd->props); pipe++) {
		region = DBGFS_REGIO_MAX;
		while (region--) {
			struct debugfs_regset32 *regset =
				&ctx->regio_set[pipe][region];
			kfree(regset->regs);
		}
	}
}

void vxd_dbgfs_wake(struct vxd_dev *vxd)
{
	struct vxd_dbgfs_ctx *ctx;

	ctx = (struct vxd_dbgfs_ctx *)vxd->dbgfs_ctx;
	if (ctx) {
		if (ctx->mtx_fifo.reader)
			wake_up_process(ctx->mtx_fifo.reader);
	}
}

int vxd_dbgfs_wait(struct vxd_dev *vxd)
{
	struct vxd_dbgfs_ctx *ctx;

	ctx = (struct vxd_dbgfs_ctx *)vxd->dbgfs_ctx;
	if (ctx)
		return ctx->mtx_fifo.attached;

	return 0;
}

int vxd_dbgfs_populate(struct vxd_dev *vxd, const char *root)
{
	struct vxd_dbgfs_ctx *ctx = NULL;
	char entry_name[25];
	struct dentry *root_dir;
	struct dentry *regio_dir;
	int ret = 0;
	int region, ofs;
	int pipe;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx) {
		/* see https://lkml.org/lkml/2014/6/10/382 */
		ret = -ENOMEM;
		goto out_alloc_failed;
	}

	/* Store context in vxd context */
	vxd->dbgfs_ctx = (struct dbgfs_ctx *)ctx;

	root_dir = debugfs_create_dir(root, NULL);
	if (!root_dir) {
		dev_warn(vxd->dev, "%s: failed to create debugfs dir!\n",
				__func__);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	init_waitqueue_head(&ctx->queue);

	ctx->root_dir = root_dir;
	/* Fill context related to mtx ram with default values*/
	ctx->mtx_ram_dwords = DBGFS_DEFAULT_DWORDS_TO_DUMP;
	ctx->mtx_ram_offs = DBGFS_DEFAULT_OFFSET;

	if (!debugfs_create_file(MTX_FIFO_NAME,
				S_IRUGO, root_dir, vxd,
			&vxd_dbgfs_mtxfifo_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, MTX_FIFO_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	if (!debugfs_create_file(MTX_RAM_NAME,
				S_IRUGO, root_dir, vxd,
			&vxd_dbgfs_mtxram_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, MTX_RAM_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	sprintf(entry_name, "%s_%s", MTX_RAM_NAME, "dwords");
	debugfs_create_u32(entry_name, S_IRUGO|S_IWUSR, root_dir, &ctx->mtx_ram_dwords);

	sprintf(entry_name, "%s_%s", MTX_RAM_NAME, "offs");
	debugfs_create_u32(entry_name, S_IRUGO|S_IWUSR, root_dir, &ctx->mtx_ram_offs);

	/* Raw regions - exported as fixed size blob */
	sprintf(entry_name, "%s_%s", REGIO_NAME, "raw");
	debugfs_create_file(entry_name, S_IRUGO, root_dir, vxd,
			    &vxd_dbgfs_regio_raw_fops);

	/* For multipipe we need to dump base region + each pipe separately.
	 * Base region already contains info from pipe selected with
	 * HOST_PIPE_SELECT register.
	 */
	for (pipe = 0; pipe < VXD_NUM_PIX_PIPES(vxd->props); pipe++) {
		/* Create subdirectory for regions */
		sprintf(entry_name, "%s%s%d", REGIO_NAME, "#", pipe);
		regio_dir = debugfs_create_dir(entry_name, root_dir);
		if (!regio_dir) {
			dev_warn(vxd->dev, "%s: failed to create %s subdir!\n",
					__func__, entry_name);
			ret = -ENOENT;
			goto out_entry_failed;
		}

		/* Register regsets with anonymous reg names */
		for (region = 0; region < DBGFS_REGIO_MAX; region++) {
			struct debugfs_regset32 *regset =
				&ctx->regio_set[pipe][region];
			struct debugfs_reg32 *reg32;
			struct dev_regspace *regspace =
				(struct dev_regspace *)&reg_spaces[region];

			regset->base = vxd->reg_base +
				VXD_GET_PIPE_OFF(VXD_NUM_PIX_PIPES(vxd->props), pipe) +
				regspace->offset;
			regset->nregs = regspace->size / sizeof(u32);

			regset->regs =
				kzalloc(sizeof(struct debugfs_reg32) *
				regset->nregs, GFP_KERNEL);
			if (!regset->regs) {
				dev_err(vxd->dev, "%s: failed to alloc regio set!\n",
				__func__);
				ret = -ENOMEM;
				goto out_entry_failed;
			}

			/* Run time initialization */
			reg32 = (struct debugfs_reg32 *)regset->regs;
			for (ofs = 0; ofs < regset->nregs; ofs++) {
				reg32->name = (char *)regset_entry_name;
				reg32->offset = ofs * sizeof(u32);
				reg32++;
			}

			debugfs_create_regset32(regspace->name, S_IRUGO,
						regio_dir, regset);
		}
	}

	/* Simple MTX status entry */
	if (!debugfs_create_file(MTX_STATUS_NAME,
				S_IRUGO, root_dir, vxd,
				&vxd_dbgfs_mtxstatus_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, MTX_STATUS_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	/* Simple DEV status entry */
	if (!debugfs_create_file(DRV_STATUS_NAME,
				S_IRUGO, root_dir, vxd,
				&vxd_dbgfs_drvstatus_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, DRV_STATUS_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	if (!debugfs_create_file(DRV_FORCE_EMRG_NAME,
				S_IWUSR, root_dir, vxd,
				&vxd_dbgfs_force_emrg_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, DRV_FORCE_EMRG_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	/* Core memory staller configuration entry */
	if (!debugfs_create_file(CORE_MEMSTALLER_NAME,
				S_IWUSR, root_dir, vxd,
				&vxd_dbgfs_memstaller_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, CORE_MEMSTALLER_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	/* Entry for dumping MMU page tables */
	if (!debugfs_create_file(CORE_PTE_DUMP_NAME,
				S_IRUGO, root_dir, vxd,
				&vxd_dbgfs_ptedump_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, CORE_PTE_DUMP_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

	/* Entry for uploading custom firmware */
	if (!debugfs_create_file(CORE_CUSTOM_FW_NAME,
				S_IWUSR, root_dir, vxd,
				&vxd_dbgfs_custom_fw_fops)) {
		dev_warn(vxd->dev, "%s: failed to create %s dbg file!\n",
				__func__, CORE_CUSTOM_FW_NAME);
		ret = -ENOENT;
		goto out_entry_failed;
	}

#define VXD_DBGFS_CREATE(_type_, _name_, _vxd_dev_member_) \
	{ \
			debugfs_create_##_type_(_name_, \
				S_IRUGO|S_IWUSR, root_dir, \
				&vxd->_vxd_dev_member_); \
	}

	/* Current core running status */
	VXD_DBGFS_CREATE(bool, CORE_HW_STATUS_NAME, hw_on);
	VXD_DBGFS_CREATE(u32, CORE_CLOCK_FREQ_NAME, stats.boot.freq_khz);
	VXD_DBGFS_CREATE(u32, MTX_TIMER_DIV_NAME, stats.boot.timer_div);
	VXD_DBGFS_CREATE(u64, CORE_FW_BOOT_TIME_NAME, stats.boot.upload_us);
	VXD_DBGFS_CREATE(u64, CORE_UPTIME_NAME, stats.uptime_ms);
	VXD_DBGFS_CREATE(u32, CORE_MEM_USAGE_LAST, stats.mem_usage_last);

	/* Current core run-time params */
	VXD_DBGFS_CREATE(bool, CORE_KEEP_ON_NAME, keep_hw_on);
	VXD_DBGFS_CREATE(bool, CORE_UPLOAD_DMA_NAME, fw_upload_dma);
	VXD_DBGFS_CREATE(u32, CORE_DWR_PERIOD_NAME, hw_dwr_period);
	VXD_DBGFS_CREATE(u32, CORE_HW_CRC_NAME, hw_crc);
	VXD_DBGFS_CREATE(u32, CORE_PM_DELAY_NAME, hw_pm_delay);
	VXD_DBGFS_CREATE(u32, CORE_BOOT_DELAY_NAME, boot_msleep);
	VXD_DBGFS_CREATE(u32, CORE_FW_WAIT_DBG_FIFO_NAME, fw_wait_dbg_fifo);
#undef VXD_DBGFS_CREATE

	return 0;

out_entry_failed:
	clean_regsets(vxd);
	debugfs_remove_recursive(ctx->root_dir);
	kfree(ctx);
	vxd->dbgfs_ctx = NULL;
out_alloc_failed:

	return ret;
}

void vxd_dbgfs_cleanup(struct vxd_dev *vxd)
{
	struct vxd_dbgfs_ctx *ctx;

	ctx = (struct vxd_dbgfs_ctx *)vxd->dbgfs_ctx;
	if (ctx) {
		if (ctx->mtx_fifo.reader) {
			kthread_stop(ctx->mtx_fifo.reader);
			ctx->mtx_fifo.reader = NULL;
		}
		if (ctx->cfw_buf)
			vfree(ctx->cfw_buf);
		clean_regsets(vxd);
		debugfs_remove_recursive(ctx->root_dir);
		kfree(ctx);
		vxd->dbgfs_ctx = NULL;
	}
}

/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
