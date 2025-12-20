/*!
 *****************************************************************************
 *
 * @File       vxd_core.c
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


#include <linux/slab.h>
#include <linux/device.h>
#include <linux/gfp.h>
#include <linux/firmware.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/list.h>
#include <linux/moduleparam.h>
#include <linux/jiffies.h>
#include <linux/list.h>
#include <linux/delay.h>

#include <uapi/vxd.h>
#include <uapi/vxd_pvdec.h>

#include "vxd_common.h"
#include "vxd_debugfs.h"

MODULE_FIRMWARE("pvdec_full_bin.fw");

#define VXD_RENDEC_SIZE (5*1024*1024)

#define VXD_MSG_CNT_SHIFT 8
#define VXD_MSG_CNT_MASK 0xff00
#define VXD_MAX_MSG_CNT ((1 << VXD_MSG_CNT_SHIFT) - 1)
#define VXD_MSG_STR_MASK 0xff
#define VXD_INVALID_ID (-1)
#define VXD_MSG_TTL 3

#define MAP_FIRMWARE_TO_STREAM 1

/* Has to be used with VXD->mutex acquired! */
#define VXD_GEN_MSG_ID(VXD, STR_ID, MSG_ID) \
	do { \
		WARN_ON((STR_ID) > VXD_MSG_STR_MASK); \
		(VXD)->msg_cnt = (VXD)->msg_cnt + 1 % (VXD_MAX_MSG_CNT); \
		(MSG_ID) = ((VXD)->msg_cnt << VXD_MSG_CNT_SHIFT) | \
			((STR_ID) & VXD_MSG_STR_MASK); \
	} while (0)

/* Have to be used with VXD->mutex acquired! */
#define VXD_RET_MSG_ID(VXD) (VXD->msg_cnt--)

#define VXD_MSG_ID_GET_STR_ID(MSG_ID) \
	((MSG_ID) & VXD_MSG_STR_MASK)

#define VXD_MSG_ID_GET_CNT(MSG_ID) \
	(((MSG_ID) & VXD_MSG_CNT_MASK) >> VXD_MSG_CNT_SHIFT)

static const char *drv_fw_name[VXD_STR_TYPE_MAX] = {
	"vxd_loopback.fw",   /* VXD_STR_TYPE_LOOPBACK */
	"pvdec_full_bin.fw", /* VXD_STR_TYPE_NON_SECURE */
	"pvdec_sec_bin.fw"   /* VXD_STR_TYPE_SECURE */
};

/* Driver context */
static struct {
	/* Available memory heaps. List of <struct vxd_heap> */
	struct list_head heaps;
	/* heap id for all internal allocations (rendec, firmware) */
	int internal_heap_id;

	/* Memory Management context for driver */
	struct mem_ctx *mem_ctx;

	/* List of associated <struct vxd_dev> */
	struct list_head devices;

	/* Virtual addresses of shared buffers, common for all streams. */
	struct {
		uint32_t fw_addr; /* Firmware blob */
		uint32_t rendec_addr; /* Rendec buffer */
	} virt_space;

	int initialised;
} drv;

/* node for heaps list */
struct vxd_heap {
	int id;
	struct list_head list; /* Entry in <struct vxd_drv:heaps> */
};

/*
 * module parameters
 */

static unsigned int keep_hw_on;
static unsigned int fw_upload_dma = 1;
static int hw_pm_delay = 100;
#ifdef CONFIG_MCST
static int hw_dwr_period = 1000;
#else
static int hw_dwr_period = 100;
#endif
static unsigned int hw_crc;
static unsigned int boot_msleep = 50;
#ifdef CONFIG_MCST
static unsigned int fw_select = 1 << VXD_STR_TYPE_NON_SECURE;
#else
static unsigned int fw_select = (1 << VXD_STR_TYPE_MAX) - 1;
#endif
module_param(keep_hw_on, uint, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(keep_hw_on, "Never power off HW, even if FW failed to boot.");
module_param(fw_upload_dma, uint, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(fw_upload_dma, "Upload the firmware using DMA.");
module_param(hw_pm_delay, int, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(hw_pm_delay, "Delay, in ms, before powering off the idle HW.");
module_param(hw_dwr_period, int, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(hw_dwr_period, "Device watchdog reset period.");
module_param(hw_crc, uint, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(hw_crc, "Hw signatures to be enabled by FW.");
module_param(boot_msleep, uint, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(boot_msleep, "Number of 100ms cycles to poll for FW boot");
module_param(fw_select, uint, S_IRUSR | S_IRGRP);
MODULE_PARM_DESC(fw_select,
	"Selects bitwise the firmware types: 0-loopback,1-regular,2-secure");

static void img_mmu_callback(enum img_mmu_callback_type callback_type,
				int buff_id, void *data)
{
	struct vxd_dev *vxd = data;

	if (!vxd)
		return;

	if (callback_type == IMG_MMU_CALLBACK_MAP)
		return;

	if (vxd->hw_on)
		vxd_pvdec_mmu_flush(vxd->dev, vxd->reg_base);
}

void vxd_core_early_init(void)
{
	INIT_LIST_HEAD(&drv.heaps);
	drv.internal_heap_id = VXD_INVALID_ID;

	drv.mem_ctx = NULL;

	INIT_LIST_HEAD(&drv.devices);

	drv.virt_space.fw_addr     = PVDEC_BUF_FW_START;
	drv.virt_space.rendec_addr = PVDEC_BUF_RENDEC_START;

	drv.initialised = 0;
}

/*
 * Lazy intialization of main driver context (when first core is probed -- we
 * need heap configuration from sysdev to allocate firmware buffers.
 */
static int vxd_init(struct device *dev,
			const struct heap_config heap_configs[], int heaps)
{
	int ret, i;

	BUILD_BUG_ON(VXD_MAX_STREAM_ID > VXD_MSG_STR_MASK);

	if (drv.initialised)
		return 0;

	dev_dbg(dev, "%s: vxd drv init, params:\n", __func__);
	dev_dbg(dev, "%s:   hw_pm_delay: %d\n", __func__, hw_pm_delay);
	dev_dbg(dev, "%s:   hw_dwr_period: %d\n", __func__, hw_dwr_period);
	dev_dbg(dev, "%s:   keep_hw_on: %d\n", __func__, keep_hw_on);
	dev_dbg(dev, "%s:   fw_upload_dma: %d\n", __func__, fw_upload_dma);
	dev_dbg(dev, "%s:   boot_msleep: %d\n", __func__, boot_msleep);
	dev_dbg(dev, "%s:   fw_select: 0x%x\n", __func__, fw_select);
	dev_dbg(dev, "%s:   hw_crc: 0x%x\n", __func__, hw_crc);

	/* Initialise memory management component */
	for (i = 0; i < heaps; i++) {
		struct vxd_heap *heap;

		dev_dbg(dev, "%s: adding heap of type %d\n",
			__func__, heap_configs[i].type);

		heap = kzalloc(sizeof(struct vxd_heap), GFP_KERNEL);
		if (!heap) {
			ret = -ENOMEM;
			goto heap_add_failed;
		}

		ret = img_mem_add_heap(&heap_configs[i], &heap->id);
		if (ret < 0) {
			dev_err(dev, "%s: failed to init heap (type %d)!\n",
				__func__, heap_configs[i].type);
			kfree(heap);
			goto heap_add_failed;
		}
		list_add(&heap->list, &drv.heaps);

		/* Implicitly, first heap is used for internal allocations */
		if (drv.internal_heap_id < 0) {
			drv.internal_heap_id = heap->id;
			dev_dbg(dev, "%s: using heap %d for internal alloc\n",
				__func__, drv.internal_heap_id);
		}
	}

	/* Do not proceed if internal heap not defined */
	if (drv.internal_heap_id < 0) {
		dev_err(dev, "%s: failed to locate heap for internal alloc\n",
			__func__);
		ret = -EINVAL;
		/* Loop registered heaps just for sanity */
		goto heap_add_failed;
	}

	/* Create memory management context for HW buffers */
	ret = img_mem_create_proc_ctx(&drv.mem_ctx);
	if (ret) {
		dev_err(dev, "%s: failed to create mem context (err:%d)!\n",
			__func__, ret);
		goto create_mem_context_failed;
	}

	drv.initialised = 1;
	dev_dbg(dev, "%s: vxd drv init done\n", __func__);
	return 0;

create_mem_context_failed:
heap_add_failed:
	while (!list_empty(&drv.heaps)) {
		struct vxd_heap *heap;

		heap = list_first_entry(&drv.heaps, struct vxd_heap, list);
		list_del(&heap->list);
		img_mem_del_heap(heap->id);
		kfree(heap);
	}
	drv.internal_heap_id = VXD_INVALID_ID;
	return ret;
}

static inline int vxd_is_secure_mode(struct vxd_dev *vxd)
{
	return vxd->fw_type == VXD_STR_TYPE_SECURE ? 1 : 0;
}

static int vxd_is_apm_required(struct vxd_dev *vxd)
{
	if (vxd->hw_on) {
		if (!vxd->keep_hw_on && vxd->fw_refcnt) {
			if (vxd_is_secure_mode(vxd))
				return 0;
			else
				return 1;
		} else if (!vxd->fw_refcnt) {
			return 1;
		}
	}

	return 0;
}

/*
 * Power on the HW.
 * Call with vxd->mutex acquired.
 */
static int vxd_make_hw_on_locked(struct vxd_dev *vxd, uint32_t fw_ptd)
{
	const struct firmware *fw;
	struct vxd_fw_hdr *fw_hdr;
	struct vxd_ena_params ena_params;
	int ret;

	if (vxd->hw_on)
		return 0;

	dev_dbg(vxd->dev, "%s: enabling HW fw_type %d fw_refcnt %d\n",
		__func__, vxd->fw_type, vxd->fw_refcnt);

	fw = vxd->firmware[vxd->fw_type].fw;
	fw_hdr = vxd->firmware[vxd->fw_type].hdr;
	if (!fw || !fw_hdr) {
		dev_err(vxd->dev, "%s: firmware missing!\n", __func__);
		return -ENOENT;
	}

	memset(&ena_params, 0, sizeof(struct vxd_ena_params));

	ena_params.fw_buf_size = fw->size - sizeof(struct vxd_fw_hdr);
	ena_params.fw_buf_virt_addr = drv.virt_space.fw_addr;
	ena_params.ptd = fw_ptd;

	if (!vxd->fw_upload_dma) {
		ena_params.regs_data.buf = fw->data +
			sizeof(struct vxd_fw_hdr);
	}

	ena_params.boot_poll.msleep_cycles = vxd->boot_msleep;
	ena_params.crc = vxd->hw_crc;
	ena_params.rendec_addr = drv.virt_space.rendec_addr;
	ena_params.rendec_size = (VXD_NUM_PIX_PIPES(vxd->props) *
		VXD_RENDEC_SIZE) / 4096u;

	ena_params.use_dma = vxd->fw_upload_dma;
	ena_params.secure = vxd_is_secure_mode(vxd);
	ena_params.wait_dbg_fifo = vxd->fw_wait_dbg_fifo;

	ena_params.mem_staller.data = vxd->memstaller_conf;
	ena_params.mem_staller.size = vxd->memstaller_size;

#if 0
	/*
	 * Setting the firmware watchdog to ~75% of the host dwr,
	 * to get it fired first, otherwise the host dwr is
	 * the last resort to recover from bad state.
	 */
	ena_params.fwwdt_ms = (vxd->hw_dwr_period * 75) / 100;
#endif

	ret = vxd_pvdec_ena(vxd->dev, vxd->reg_base, &ena_params,
			fw_hdr, &vxd->stats.boot);
	/*
	 * Ignore the return code, proceed as usual, it will be retuned anyway.
	 * The HW is turned on, so we can perform post mortem analysis,
	 * and collect the fw logs when available.
	 */

	vxd->hw_on = 1;
	/* Remember the time hw is powered on */
	ktime_get_real_ts64(&vxd->hw_start);

	/* If we have debugfs client attached, send an event */
	vxd_dbgfs_wake(vxd);

	return ret;
}

/*
 * Power off the HW.
 * Call with vxd->mutex acquired.
 */
static void vxd_make_hw_off_locked(struct vxd_dev *vxd, bool suspending)
{
	int ret;

	if (!vxd->hw_on)
		return;

	/* Process the remaining debug data
	 * If UM tasks are already frozen, skip this */
	while (vxd_dbgfs_wait(vxd) && !suspending &&
		/* Wait for debug data to be flushed */
		(ret = vxd_pvdec_peek_mtx_fifo(vxd->dev, vxd->reg_base))) {
		dev_dbg(vxd->dev, "%s: waiting for debug data... %u\n",
			__func__, ret);
		/* give mutex free */
		mutex_unlock(&vxd->mutex);
		/* yield - give some time for debugfs to fetch the data */
		msleep(20);
		/* take mutex again */
		mutex_lock(&vxd->mutex);
	}

	dev_dbg(vxd->dev, "%s: disabling HW fw_type %d fw_refcnt %d\n",
		__func__, vxd->fw_type, vxd->fw_refcnt);

	ret = vxd_pvdec_dis(vxd->dev, vxd->reg_base);
	vxd->hw_on = 0;
	if (ret)
		dev_err(vxd->dev, "%s: failed to power off the VXD!\n",
				__func__);

	/* Update the up time of the core
	 * Take fw boot time into consideration */
	{
		uint64_t uptime = 0;
		uint64_t boot_time = vxd->stats.boot.upload_us;
		struct timespec64 hw_stop;

		/* Convert fw boot time to ms */
		do_div(boot_time, 1000);

		/* Calculate how long(in milliseconds) the core
		 * has been powered on for the last time */
		ktime_get_real_ts64(&hw_stop);
		uptime = timespec64_to_ns(&hw_stop) -
			 timespec64_to_ns(&vxd->hw_start);
		do_div(uptime, 1000000UL);

		vxd->stats.uptime_ms += uptime + boot_time;
	}
	/* Reset emergency state after power off */
	vxd->emergency = 0;
}

static void vxd_report_item_locked(struct vxd_dev *vxd,
		struct vxd_item *item, uint32_t flags)
{
	struct vxd_stream *stream;

	list_del(&item->list);
	/* Find associated stream */
	stream = idr_find(&vxd->streams, item->str_id);
	if (!stream) {
		/*
		 * Failed to find associated stream. Probably it was
		 * already destroyed -- drop the item
		 */
		dev_dbg(vxd->dev, "%s: drop item %p [0x%x]\n",
				__func__, item, item->msg_id);
		kfree(item);
	} else {
		item->msg.out_flags |= flags;
		list_add_tail(&item->list, &stream->link->items_done);
		dev_dbg(vxd->dev, "%s: waking %p\n", __func__,
				stream->link);
		wake_up(&stream->link->queue);
	}
}

static void vxd_handle_io_error_locked(struct vxd_dev *vxd)
{
	struct vxd_item *item, *tmp;
	uint32_t pend_flags = vxd->hw_dead ? VXD_FW_MSG_FLAG_DEV_ERR :
		VXD_FW_MSG_FLAG_CANCELED;

	list_for_each_entry_safe(item, tmp, &vxd->msgs, list)
		vxd_report_item_locked(vxd, item, VXD_FW_MSG_FLAG_DEV_ERR);

	list_for_each_entry_safe(item, tmp, &vxd->pend, list)
		vxd_report_item_locked(vxd, item, pend_flags);
}

static void vxd_sched_worker_locked(struct vxd_dev *vxd, uint32_t delay_ms)
{
	unsigned long work_at = jiffies + msecs_to_jiffies(delay_ms);
	int ret;

	/*
	 * Try to queue the work.
	 * This may be also called from the worker context,
	 * so we need to re-arm anyway in case of error
	 */
	ret = schedule_delayed_work(&vxd->dwork,
				work_at - jiffies);
	if (ret) {
		/* Work is already in the queue */

		/*
		 * Check if new requested time is "before"
		 * the last "time" we scheduled this work at,
		 * if not, do nothing, the worker will do
		 * recalculation for APM/DWR afterwards
		 */
		if (time_before(work_at, vxd->work_sched_at)) {
			/*
			 * Canceling & rescheduling might be problematic,
			 * so just modify it, when needed
			 */
			ret = mod_delayed_work(system_wq, &vxd->dwork,
					work_at - jiffies);
			if (!ret) {
				dev_err(vxd->dev, "%s: failed to modify work!\n",
					__func__);
				WARN_ON(1);
			}
			/*
			 * Record the 'time' this work
			 * has been rescheduled at
			 */
			vxd->work_sched_at = work_at;
		}
	} else {
		/* Record the 'time' this work has been scheduled at */
		vxd->work_sched_at = work_at;
	}
}

static void vxd_monitor_locked(struct vxd_dev *vxd)
{
	/* HW is dead, not much sense in rescheduling */
	if (vxd->hw_dead)
		return;

	/*
	 * We are not processing anything, but pending list is not empty
	 * probably the message fifo is full, so retrigger the worker.
	 */
	if (!list_empty(&vxd->pend) && list_empty(&vxd->msgs))
		vxd_sched_worker_locked(vxd, 1);

	if (list_empty(&vxd->pend) && list_empty(&vxd->msgs) &&
			vxd_is_apm_required(vxd)) {
		dev_dbg(vxd->dev, "%s: scheduling APM work (%d ms)!\n",
				__func__, vxd->hw_pm_delay);
		/*
		 * No items to process and no items being processed -
		 * disable the HW
		 */
		vxd->pm_start = jiffies;
		vxd_sched_worker_locked(vxd, vxd->hw_pm_delay);
		return;
	}

	if (vxd->hw_dwr_period > 0 && !list_empty(&vxd->msgs)) {
		dev_dbg(vxd->dev, "%s: scheduling DWR work (%d ms)!\n",
				__func__, vxd->hw_dwr_period);
		vxd->dwr_start = jiffies;
		vxd_sched_worker_locked(vxd, vxd->hw_dwr_period);
	}
}

/*
 * Take first item from pending list and submit it to the hardware.
 * Has to be called with vxd->mutex locked.
 */
static int vxd_sched_single_locked(struct vxd_dev *vxd)
{
	struct vxd_item *item = NULL;
	size_t msg_size;
	int ret;

	item = list_first_entry(&vxd->pend, struct vxd_item, list);

	msg_size = item->msg.payload_size/sizeof(u32);

	dev_dbg(vxd->dev, "%s: checking msg_size: %zu, item: %p\n",
			__func__, msg_size, item);

	/* In case of exclusive item check if hw/fw is
	 * currently processing anything.
	 * If so we need to wait until items are returned back. */
	if ((item->msg.out_flags & VXD_FW_MSG_FLAG_EXCL) &&
			!list_empty(&vxd->msgs) &&
				/* We can move forward if message
				 * is about to be dropped. */
				!(item->msg.out_flags & VXD_FW_MSG_FLAG_DROP))

		ret = -EBUSY;
	else
		/* Check if there's enough space
		 * in comms RAM to submit the message. */
		ret = vxd_pvdec_msg_fit(vxd->dev, vxd->reg_base, msg_size);

	if (ret == 0) {
		uint16_t msg_id;

		VXD_GEN_MSG_ID(vxd, item->str_id, msg_id);

		/* submit the message to the hardware */
		ret = vxd_pvdec_send_msg(vxd->dev, vxd->reg_base,
				(u32 *)item->msg.payload, msg_size,
				msg_id);
		if (ret) {
			dev_err(vxd->dev, "%s: failed to send msg!\n",
					__func__);
			VXD_RET_MSG_ID(vxd);
		} else {
			if (item->msg.out_flags & VXD_FW_MSG_FLAG_DROP) {
				list_del(&item->list);
				kfree(item);
				dev_dbg(vxd->dev,
						"%s: drop msg 0x%x! (user requested)\n",
						__func__, msg_id);
			} else {
				item->msg_id = msg_id;
				dev_dbg(vxd->dev,
					"%s: moving item %p, id 0x%x to msgs\n",
				__func__, item, item->msg_id);
				list_move(&item->list, &vxd->msgs);
				item->ttl = VXD_MSG_TTL;
			}

			vxd_monitor_locked(vxd);
		}

	} else if (ret == -EINVAL) {
		dev_warn(vxd->dev, "%s: invalid msg!\n", __func__);
		vxd_report_item_locked(vxd, item, VXD_FW_MSG_FLAG_INV);
		/*
		 * HW is ok, the message was invalid, so don't return an
		 * error
		 */
		ret = 0;
	} else if (ret == -EBUSY) {
		/* Not enough space. Message is already in the pending queue,
		 * so it will be submitted once we've got space. Delayed work
		 * might have been canceled (if we are currently processing
		 * threaded irq), so make sure that DWR will trigger if it's
		 * enabled. */
		if (list_empty(&vxd->msgs)) { /* unlikely */
			dev_warn(vxd->dev, "%s: no space while hw queue empty!\n", __func__);
			vxd_make_hw_off_locked(vxd, false);
			vxd_report_item_locked(vxd, item, VXD_FW_MSG_FLAG_CANCELED);
		} else
			vxd_monitor_locked(vxd);
	} else if (ret != 0) {
		dev_err(vxd->dev, "%s: failed to check space for msg!\n",
				__func__);
	}

	return ret;
}

/*
 * Take items from pending list and submit them to the hardware, if space is
 * available in the ring buffer.
 * Call with vxd->mutex locked
 */
static void vxd_schedule_locked(struct vxd_dev *vxd)
{
	bool emergency = vxd->emergency;
	int ret;

	/* if HW is dead, inform the UM and skip */
	if(vxd->hw_dead) {
		vxd_handle_io_error_locked(vxd);
		return;
	}

	/* vxd->msgs has to be empty when the HW is off */
	WARN_ON(!vxd->hw_on && !list_empty(&vxd->msgs));

	if (list_empty(&vxd->pend)) {
		vxd_monitor_locked(vxd);
		return;
	} else if (emergency) {
		struct vxd_item *item;

		/* In case of emergency, report back any non exclusive item from
		 * the pending head, until the first picture to be replayed comes in. */
		item = list_first_entry(&vxd->pend, struct vxd_item, list);
		if (!(item->msg.out_flags & VXD_FW_MSG_FLAG_EXCL)) {
			/* Reporting as canceled */
			vxd_report_item_locked(vxd, item, VXD_FW_MSG_FLAG_CANCELED);
			return;
		}
	}

	/*
	 * If the emergency routine was fired, the hw was left ON,
	 * so the UM could do the post mortem analysis before
	 * submitting the next items.
	 * Now we can switch off the hardware */
	if (emergency) {
		vxd_make_hw_off_locked(vxd, false);
		dev_info(vxd->dev, "reset done!\n");
		msleep(1);
	}

	/* Try to schedule */
	ret = 0;
	while (!list_empty(&vxd->pend) && ret == 0) {
		struct vxd_item *item;
		struct vxd_stream *stream;

		item = list_first_entry(&vxd->pend, struct vxd_item, list);
		stream = idr_find(&vxd->streams, item->str_id);

		if (vxd->hw_on && (item->msg.out_flags & VXD_FW_MSG_FLAG_EXCL)) {
			vxd_make_hw_off_locked(vxd, false);
			dev_info(vxd->dev, "reset on excl pic done!\n");
			msleep(1);
		}

		ret = vxd_make_hw_on_locked(vxd, stream->ptd);
		if (ret) {
			dev_err(vxd->dev,
				"%s: failed to start HW!\n", __func__);
			vxd->hw_dead = 1;
			vxd_handle_io_error_locked(vxd);
			return;
		}

		ret = vxd_sched_single_locked(vxd);
	}

	if (ret != 0 && ret != -EBUSY) {
		dev_err(vxd->dev, "%s: failed to schedule, emrg: %d!\n",
				__func__, emergency);
		if (emergency) {
			/*
			 * Failed to schedule in the emergency mode --
			 * there's no hope. Power off the HW, mark all
			 * items as failed and return them.
			 */
			vxd_handle_io_error_locked(vxd);
			return;
		} else {
			/* Let worker try to handle it */
			vxd_sched_worker_locked(vxd, 0);
		}
	}
}

/*
 * Increments the firmware reference to track owners (streams)
 * Call with vxd->mutex locked
 */
static int vxd_get_fw_locked(struct vxd_dev *vxd, struct mmu_ctx *stream_ctx,
				uint32_t str_type, int *fw_buf_id)
{
	if (vxd->fw_refcnt) {
		/* We have already asked for the firmware, but
		secure flow case can only decode one stream at time */
		if (str_type == VXD_STR_TYPE_SECURE &&
			vxd->fw_type == str_type) {
			dev_err(vxd->dev,
				"%s: secure multi stream not allowed!\n",
				__func__);
			return -EBUSY;
		}

		/* Mixed mode not allowed as well */
		if (vxd->fw_type != str_type) {
			dev_err(vxd->dev,
				"%s: multi stream mixed mode not allowed!\n",
				__func__);
			return -EBUSY;
		}
	} else {
		if (vxd->firmware[str_type].buf_id == VXD_INVALID_ID) {
			dev_err(vxd->dev, "%s: firmware not available!\n",
				__func__);
			return -ENOENT;
		}

		if (vxd->hw_on && vxd->fw_type != str_type) {
			dev_dbg(vxd->dev, "%s: switching fw_type %d->%d\n",
				__func__, vxd->fw_type, str_type);
			vxd_make_hw_off_locked(vxd, false);
		}

		vxd->fw_type = str_type;

		dev_dbg(vxd->dev, "FW: get %s\n", drv_fw_name[str_type]);
	}

	*fw_buf_id = vxd->firmware[str_type].buf_id;
	vxd->fw_refcnt++;
	dev_dbg(vxd->dev, "FW: %s count %d\n",
		drv_fw_name[str_type], vxd->fw_refcnt);
	return 0;
}

/*
 * Decrements the firmware reference
 * Call with vxd->mutex locked
 */
static void vxd_put_fw_locked(struct vxd_dev *vxd)
{
	vxd->fw_refcnt--;

	dev_dbg(vxd->dev, "FW: %s count %d\n",
		drv_fw_name[vxd->fw_type], vxd->fw_refcnt);

	if (vxd->fw_refcnt > 0)
		return;

	dev_dbg(vxd->dev, "FW: put %s\n", drv_fw_name[vxd->fw_type]);
	/* Poke the monitor to finally switch off the hw, when needed */
	vxd_monitor_locked(vxd);
}

int vxd_deinit(void)
{
	/* Destroy memory management context */
	if (drv.mem_ctx) {
		size_t mem_usage = img_mem_get_usage(drv.mem_ctx);
		u32 MB = mem_usage / (1024 * 1024);
		u32 bytes = mem_usage - (MB * (1024 * 1024));
		u32 kB = (bytes * 1000) / (1024 * 1024);

		pr_err("%s: Total kernel memory used: %u.%u MB\n",
				__func__, MB, kB);

		img_mem_destroy_proc_ctx(drv.mem_ctx);
		drv.mem_ctx = NULL;
	}

	/* Deinitialize memory management component */
	while (!list_empty(&drv.heaps)) {
		struct vxd_heap *heap;

		heap = list_first_entry(&drv.heaps, struct vxd_heap, list);
		list_del(&heap->list);
		img_mem_del_heap(heap->id);
		kfree(heap);
	}
	drv.internal_heap_id = VXD_INVALID_ID;

	drv.initialised = 0;
	return 0;
}

/* Top half */
irqreturn_t vxd_handle_irq(struct device *dev)
{
	struct vxd_dev *vxd = dev_get_drvdata(dev);
	struct vxd_hw_state *hw_state = &vxd->state.hw_state;
	int ret = IRQ_NONE;

	if (!vxd)
		goto exit;

	/* Don't touch core interrupt registers when core is off */
	if (vxd->hw_on)
		ret = vxd_pvdec_clear_int(vxd->reg_base,
				&hw_state->irq_status);

	if (!hw_state->irq_status ||
			ret == IRQ_NONE) {
		WARN_ONCE(1, "Unexpected irq!");
		dev_warn(dev, "Got spurious interrupt!\n");
	}

	dev_dbg(dev, "IRQ 0x%08x\n", hw_state->irq_status);
exit:
	return ret;
}

static void vxd_drop_msg_locked(const struct vxd_dev *vxd)
{
	int ret;

	ret = vxd_pvdec_recv_msg(vxd->dev, vxd->reg_base, NULL, 0);
	if (ret)
		dev_warn(vxd->dev, "%s: failed to receive msg!\n", __func__);
}

static void vxd_dbg_dump_msg(const struct device *dev, const char *func,
		const uint32_t *payload, size_t msg_size)
{
	unsigned int i;

	for (i = 0; i < msg_size; i++)
		dev_dbg(dev, "%s: msg %d: 0x%08x\n", func, i, payload[i]);
}

static struct vxd_item *vxd_get_orphaned_item_locked(struct vxd_dev *vxd,
		uint16_t msg_id, size_t msg_size)
{
	struct vxd_stream *stream;
	uint16_t str_id = VXD_MSG_ID_GET_STR_ID(msg_id);

	/* Try to find associated stream */
	stream = idr_find(&vxd->streams, str_id);
	if (!stream) {
		/*
		 * Failed to find associated stream.
		 */
		dev_dbg(vxd->dev, "%s: failed to find str_id: %u\n",
				__func__, str_id);
		return NULL;
	} else {
		struct vxd_item *item;

		item = kzalloc(sizeof(struct vxd_item) +
				msg_size*sizeof(u32), GFP_KERNEL);
		if (item == NULL)
			return NULL;

		item->msg.out_flags = 0;
		item->msg.stream_id = str_id;
		item->str_id = str_id;
		item->msg.payload_size = msg_size*sizeof(u32);
		if (vxd_pvdec_recv_msg(vxd->dev, vxd->reg_base,
					item->msg.payload, msg_size)) {
			dev_err(vxd->dev,
					"%s: failed to receive msg from VXD!\n",
					__func__);
			item->msg.out_flags |= VXD_FW_MSG_FLAG_DEV_ERR;
		}
		dev_dbg(vxd->dev, "%s: item: %p str_id: %u\n",
				__func__, item, str_id);
		/*
		 * Need to put this item on the vxd->msgs list.
		 * It will be removed after.
		 */
		list_add_tail(&item->list, &vxd->msgs);

		vxd_dbg_dump_msg(vxd->dev, __func__,
				item->msg.payload, msg_size);
		return item;
	}
}

/*
 * MTX Debug fifo size can vary from one tapeout to another. Try to obtain the
 * actual size from HW, but never allow more than 16 pages.
 * */
#define MAX_MTX_FIFO_SIZE (16*PAGE_SIZE)

/*
 * Print the content of MTX debug fifo to the log.
 */
static void vxd_dump_mtx_fifo_locked(struct vxd_dev *vxd)
{
#ifdef DEBUG
	unsigned int ret;
	size_t fifo_size = vxd_pvdec_get_dbg_fifo_size(vxd->reg_base);
	u32 *buf;

	/* Do not dump debug fifo when debugfs is in use */
	if (vxd_dbgfs_wait(vxd))
		return;

	fifo_size = (fifo_size > MAX_MTX_FIFO_SIZE) ? MAX_MTX_FIFO_SIZE :
		fifo_size;

	buf = kmalloc(fifo_size, GFP_KERNEL);

	if (buf) {
		ret = vxd_pvdec_read_mtx_fifo(vxd->dev, vxd->reg_base,
				buf, fifo_size);
		ret *= sizeof(u32);
		ret = (ret > fifo_size) ? fifo_size : ret;
		print_hex_dump(KERN_ERR, "vxd_mtx_fifo: ", DUMP_PREFIX_OFFSET,
				16, 1, buf, ret, true);

		kfree(buf);
	} else {
		dev_err(vxd->dev, "%s: failed to alloc fifo buf!\n",
				__func__);
	}
#endif /* DEBUG */
}

/*
 * Moves all valid items from the queue of items being currently processed to
 * the pending queue.
 * Call with vxd->mutex locked
 */
static void vxd_rewind_msgs_locked(struct vxd_dev *vxd)
{
	struct vxd_item *item, *tmp;

	if (list_empty(&vxd->msgs))
		return;

	list_for_each_entry_safe(item, tmp, &vxd->msgs, list)
		list_move(&item->list, &vxd->pend);
}

/*
 * Rewind all items to
 * the pending queue and report those to UM.
 * Postpone the reset.
 * Call with vxd->mutex locked
 */
static void vxd_emrg_reset_locked(struct vxd_dev *vxd,
		uint32_t flags)
{
	dev_dbg(vxd->dev, "%s: enter\n", __func__);

	cancel_delayed_work(&vxd->dwork);

	vxd_dump_mtx_fifo_locked(vxd);

	/* Record emergency condition ! */
	vxd->emergency = 1;
	/* Stop the core, but leave it online */
	vxd_pvdec_stop(vxd->dev, vxd->reg_base);

	/* If the firmware sends more than one reply per item, it's possible
	 * that corresponding item was already removed from vxd-msgs, but the
	 * HW was still processing it and MMU page fault could happen and
	 * trigger execution of this function. So make sure that vxd->msgs
	 * is not empty before rewinding items. */
	if (!list_empty(&vxd->msgs))
		/* Move all valid items to the pending queue */
		vxd_rewind_msgs_locked(vxd);

	{
		struct vxd_item *item, *tmp;
		list_for_each_entry_safe(item, tmp, &vxd->pend, list) {
			/* Exclusive items that were on the pending list
			 * must be reported as canceled */
			if ((item->msg.out_flags & VXD_FW_MSG_FLAG_EXCL) &&
				!item->msg_id)
				item->msg.out_flags |= VXD_FW_MSG_FLAG_CANCELED;

			vxd_report_item_locked(vxd, item, flags);
		}
	}
}

/*
 * Fetch and process a single message from the MTX->host ring buffer.
 * <no_more> parameter is used to indicate if there are more messages pending.
 * <fatal> parameter indicates if there is some serious situation detected.
 * Has to be called with vxd->mutex locked.
 */
static void vxd_handle_single_msg_locked(struct vxd_dev *vxd,
		bool *no_more, int *fatal)
{
	int ret;
	uint16_t msg_id, str_id;
	size_t msg_size; /* size in dwords */
	struct vxd_item *item = NULL, *tmp, *it;
	struct vxd_stream *stream;
	struct device *dev = vxd->dev;
	bool not_last_msg;

	/* get the message size and id */
	ret = vxd_pvdec_pend_msg_info(dev, vxd->reg_base, &msg_size, &msg_id,
			&not_last_msg);
	if (ret) {
		dev_err(dev, "%s: failed to get pending msg size!\n", __func__);
		*no_more = true; /* worker will HW failure */
		return;
	}

	if (msg_size == 0) {
		*no_more = true;
		return;
	} else {
		*no_more = false;
	}

	str_id = VXD_MSG_ID_GET_STR_ID(msg_id);
	dev_dbg(dev, "%s: [msg] size: %zu, cnt: %u, str_id: %u, id: 0x%x\n",
			__func__, msg_size, VXD_MSG_ID_GET_CNT(msg_id),
			str_id, msg_id);
	dev_dbg(dev, "%s: [msg] not last: %u\n", __func__, not_last_msg);

	cancel_delayed_work(&vxd->dwork);

	/* Find associated item */
	list_for_each_entry_safe_reverse(it, tmp, &vxd->msgs, list) {
		dev_dbg(dev, "%s: checking item %p [0x%x] [des: %d]\n",
				__func__, it, it->msg_id, it->destroy);
		if (it->msg_id == msg_id) {
			item = it;
			break;
		}
	}

	dev_dbg(dev, "%s: found item %p [destroy: %d]\n",
			__func__, item, item ? item->destroy : VXD_INVALID_ID);

	/* Find associated stream */
	stream = idr_find(&vxd->streams, str_id);
	/*
	 * Check for firmware condition in case
	 * when unexpected item is received.
	 */
	if (!item && !stream &&
		(*fatal = vxd_pvdec_check_fw_status(dev, vxd->reg_base))) {
		struct vxd_item *orphan;
		/*
		 * Lets forward the fatal info to UM first, relaying
		 * on the head of the msg queue.
		 */
		/* TODO: forward fatal info to all attached processes */
		item = list_entry(vxd->msgs.prev, struct vxd_item, list);
		orphan = vxd_get_orphaned_item_locked(vxd,
				item->msg_id, msg_size);
		if (!orphan) {
			dev_warn(dev, "%s: drop msg 0x%x! (no orphan)\n",
				__func__, item->msg_id);
			vxd_drop_msg_locked(vxd);
		}

		return;
	}

	if ((item && item->destroy) || !stream) {
		/*
		 * Item was marked for destruction or we failed to find
		 * associated stream. Probably it was already destroyed --
		 * just ignore the message.
		 */
		if (item) {
			list_del(&item->list);
			kfree(item);
			item = NULL;
		}
		dev_warn(dev, "%s: drop msg 0x%x! (no owner)\n",
				__func__, msg_id);
		vxd_drop_msg_locked(vxd);
		return;
	}

	/* Remove item from vxd->msgs list */
	if (item && item->msg_id == msg_id && !not_last_msg)
		list_del(&item->list);

	/*
	 * If there's no such item on a <being processed> list, or the one
	 * found is too small to fit the output, or it's not supposed to be
	 * released, allocate a new one.
	 */
	if (!item || (msg_size*sizeof(u32) > item->msg.payload_size) ||
			not_last_msg) {
		struct vxd_item *new_item;

		new_item = kzalloc(sizeof(struct vxd_item) +
				msg_size*sizeof(u32), GFP_KERNEL);
		if (item) {
			if (!new_item) {
				/*
				 * Failed to allocate new item. Mark item as
				 * errored and continue best effort, provide
				 * only part of the message to the userspace
				 */
				dev_err(dev, "%s: failed to alloc new item!\n",
						__func__);
				msg_size = item->msg.payload_size/sizeof(u32);
				item->msg.out_flags |= VXD_FW_MSG_FLAG_DRV_ERR;
			} else {
				*new_item = *item;
				/* Do not free the old item if subsequent
				 * messages are expected (it also wasn't
				 * removed from the vxd->msgs list, so we are
				 * not losing a pointer here). */
				if (!not_last_msg)
					kfree(item);
				item = new_item;
			}
		} else {
			if (!new_item) {
				/*
				 * We have no place to put the message, we have
				 * to drop it
				 */
				dev_err(dev, "%s: drop msg 0x%08x! (no mem)\n",
						__func__, msg_id);
				vxd_drop_msg_locked(vxd);
				return;
			} else {
				/* There was no corresponding item on the
				 * <being processed> list and we've allocated
				 * a new one. Initialize it */
				new_item->msg.out_flags = 0;
				new_item->msg.stream_id = str_id;
				item = new_item;
			}
		}
	}
	ret = vxd_pvdec_recv_msg(dev, vxd->reg_base, item->msg.payload,
			msg_size);
	if (ret) {
		dev_err(dev, "%s: failed to receive msg from VXD!\n", __func__);
		item->msg.out_flags |= VXD_FW_MSG_FLAG_DEV_ERR;
	}
	item->msg.payload_size = msg_size*sizeof(u32);

	vxd_dbg_dump_msg(dev, __func__, item->msg.payload, msg_size);

	dev_dbg(dev, "%s: adding to done list, item: %p, msg_size: %zu\n",
			__func__, item, msg_size);
	list_add_tail(&item->list, &stream->link->items_done);
	dev_dbg(dev, "%s: waking %p\n", __func__, stream->link);
	wake_up(&stream->link->queue);

	return;
}

/* Bottom half */
irqreturn_t vxd_handle_thread_irq(struct device *dev)
{
	bool no_more = false;
	int fatal = 0;
	struct vxd_dev *vxd = dev_get_drvdata(dev);
	struct vxd_hw_state *hw_state = &vxd->state.hw_state;
	irqreturn_t ret = IRQ_HANDLED;

	if (!vxd)
		return IRQ_NONE;

	dev_dbg(dev, "%s: IRQ\n", __func__);
	mutex_lock(&vxd->mutex);

	/* Spurious interrupt? */
	if (unlikely(!vxd->hw_on || vxd->hw_dead)) {
		ret = IRQ_NONE;
		goto out_unlock;
	}

	/* If we are already in emergency state caused by DWR or MMU PF
	 * it is possible to receive interrupt for outstanding pictures,
	 * as the core is still powered on, while we are doing
	 * post mortem analysis in the user space,
	 * so just ignore that !
	 */
	if (unlikely(vxd->emergency)) {
		dev_warn(dev, "Got interrupt in emergency state, skipping!\n");
		ret = IRQ_NONE;
		goto out_unlock;
	}

	/* If we have debugfs client attached, send an event */
	vxd_dbgfs_wake(vxd);

	/* Check for critical exception - only MMU faults for now */
	if (vxd_pvdec_check_irq(dev, vxd->reg_base,
				hw_state->irq_status) < 0) {
		dev_info(vxd->dev, "device MMU fault: going to reset core...\n");
		vxd_emrg_reset_locked(vxd, VXD_FW_MSG_FLAG_MMU_FAULT);
		goto out_unlock;
	}

	/*
	 * Single interrupt can correspond to multiple messages, handle them
	 * all.
	 */
	while (!no_more)
		vxd_handle_single_msg_locked(vxd, &no_more, &fatal);

	if (fatal) {
		dev_info(vxd->dev, "fw fatal condition: going to reset core...\n");
		/* Try to recover ... */
		vxd_emrg_reset_locked(vxd, (fatal < 0) ? VXD_FW_MSG_FLAG_FATAL : fatal);
	} else {
		/* Try to submit items to the HW */
		vxd_schedule_locked(vxd);
	}

out_unlock:
	hw_state->irq_status = 0;
	mutex_unlock(&vxd->mutex);

	return ret;
}

void *vxd_get_plat_data(const struct device *dev)
{
	struct vxd_dev *vxd = dev_get_drvdata(dev);

	if (!vxd)
		return NULL;
	return vxd->plat_data;
}

int vxd_add_link(struct vxd_dev *vxd, struct vxd_link *link)
{
	int ret;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	list_add(&link->list, &vxd->links);

	mutex_unlock(&vxd->mutex);

	return 0;
}

/*
 * Delete pending items belonging to the stream. Has to be called with
 * vxd->mutex locked!
 */
static void vxd_del_str_pend_locked(struct vxd_dev *vxd,
		struct vxd_stream *str)
{
	struct vxd_item *cur_item, *tmp_item;

	list_for_each_entry_safe(cur_item, tmp_item, &vxd->pend, list)
		if (cur_item->str_id == str->id) {
			list_del(&cur_item->list);
			kfree(cur_item);
		}
}

/*
 * Mark items which belong to the stream and are being processed as no longer
 * valid. Has to be called with vxd->mutex locked!
 */
static void vxd_mark_str_dest_locked(struct vxd_dev *vxd,
		struct vxd_stream *str)
{
	struct vxd_item *cur_item, *tmp_item;

	list_for_each_entry_safe(cur_item, tmp_item, &vxd->msgs, list)
		if (cur_item->str_id == str->id)
			cur_item->destroy = 1;
}

/*
 * Get number of items currently being processed by hardware belonging to the
 * given stream. Has to be called with vxd->mutex locked!
 */
static int vxd_get_proc_items_locked(struct vxd_dev *vxd,
		struct vxd_stream *str)
{
	struct vxd_item *cur_item, *tmp_item;
	int num_items = 0;

	list_for_each_entry_safe(cur_item, tmp_item, &vxd->msgs, list)
		if (cur_item->str_id == str->id)
			num_items++;

	return num_items;
}

/*
 * Get number of items currently being processed by hardware belonging to the
 * given stream.
 */
static int vxd_get_proc_items(struct vxd_dev *vxd, struct vxd_stream *str)
{
	int num_items;

	dev_dbg(vxd->dev, "%s: enter!\n", __func__);
	mutex_lock(&vxd->mutex);

	num_items = vxd_get_proc_items_locked(vxd, str);

	mutex_unlock(&vxd->mutex);

	dev_dbg(vxd->dev, "%s: leaving with %d items!\n", __func__, num_items);

	return num_items;
}

/*
 * Remove all items associated with the stream from the pending list and wait
 * for completion of all items that are being processed. Has to be called with
 * vxd->mutex locked!
 */
static void vxd_purge_stream_locked(struct vxd_dev *vxd,
		struct vxd_link *link, struct vxd_stream *str)
{
	int ret;
	/* Remove pending items. */
	vxd_del_str_pend_locked(vxd, str);
	/* Mark items being processed as no longer valid. */
	vxd_mark_str_dest_locked(vxd, str);

	/*
	 * Wait for completion of all items associated with the stream that
	 * are being processed
	 */
	while (vxd_get_proc_items_locked(vxd, str)) {
		mutex_unlock(&vxd->mutex);

		dev_dbg(vxd->dev, "%s: going to sleep\n", __func__);
		ret = wait_event_timeout(link->queue,
				(!vxd_get_proc_items(vxd, str)),
				msecs_to_jiffies(1000));
		mutex_lock(&vxd->mutex);
		if (!ret) {
			dev_info(vxd->dev, "fw timeout: going to reset core...\n");
			vxd_emrg_reset_locked(vxd, VXD_FW_MSG_FLAG_CANCELED);
		}

		dev_dbg(vxd->dev, "%s: woken up\n", __func__);
	}
}

/*
 * Delete the stream.
 * Has to be called with vxd->mutex and link->mutex locked.
 */
static void vxd_del_stream_locked(struct vxd_dev *vxd, struct vxd_stream *str)
{
	dev_dbg(vxd->dev, "%s: deleting stream %d\n", __func__, str->id);

	img_mmu_unmap(str->mmu_ctx, drv.mem_ctx,
			vxd->firmware[vxd->fw_type].buf_id);
	img_mmu_unmap(str->mmu_ctx, drv.mem_ctx,
			vxd->rendec_buf_id);

	img_mmu_ctx_destroy(str->mmu_ctx);

	idr_remove(&vxd->streams, str->id);
	list_del(&str->list); /* remove from <vxd_link:streams> list */
	kfree(str);
}

void vxd_rm_link(struct vxd_dev *vxd, struct vxd_link *link)
{
	struct vxd_link *cur_link, *tmp_link;
	struct vxd_stream *cur_str, *tmp_str;
	struct vxd_item *cur_item, *tmp_item;
	int streams_active;

	mutex_lock(&vxd->mutex);

	streams_active = !list_empty(&link->streams);

	list_for_each_entry_safe(cur_str, tmp_str, &link->streams, list)
		vxd_purge_stream_locked(vxd, link, cur_str);

	/*
	 * At this point, HW should no longer process any items associated with
	 * the link, and all items should have been transfered to
	 * link->items_done. Remove them.
	 */
	list_for_each_entry_safe(cur_item, tmp_item, &link->items_done, list) {
		list_del(&cur_item->list);
		kfree(cur_item);
	}

	/* Remove link from VXD's list */
	list_for_each_entry_safe(cur_link, tmp_link, &vxd->links, list) {
		if (cur_link == link)
			list_del(&cur_link->list);
	}

	/* Remove streams */
	list_for_each_entry_safe(cur_str, tmp_str, &link->streams, list) {
		vxd_del_stream_locked(vxd, cur_str);
		vxd_put_fw_locked(vxd);
	}

	/* Flush device MMU just for sanity */
	if (vxd->hw_on && streams_active)
		vxd_pvdec_mmu_flush(vxd->dev, vxd->reg_base);

	/*
	 * Destroy memory staller configuration
	 * if any of the links is destroyed
	 */
	kfree(vxd->memstaller_conf);
	vxd->memstaller_conf = NULL;
	vxd->memstaller_size = 0;

	/* Update mem stats - memory usage in the last session */
	vxd->stats.mem_usage_last = img_mem_get_usage(link->mem_ctx);
	{
		u32 MB = vxd->stats.mem_usage_last / (1024 * 1024);
		u32 bytes = vxd->stats.mem_usage_last - (MB * (1024 * 1024));
		u32 kB = (bytes * 1000) / (1024 * 1024);

		dev_dbg(vxd->dev,
			"%s: Total user memory used: %u.%u MB\n",
			__func__, MB, kB);
	}

	mutex_unlock(&vxd->mutex);
}

static void vxd_worker(struct work_struct *work)
{
	struct vxd_dev *vxd = container_of(work, struct vxd_dev, dwork.work);
	struct vxd_hw_state state = { 0 };
	struct vxd_item *item_tail;
	bool fire_dwr = false;

	mutex_lock(&vxd->mutex);

	dev_dbg(vxd->dev, "%s: jif: %ld, pm: %ld dwr: %ld\n", __func__, jiffies,
			vxd->pm_start, vxd->dwr_start);

	/*
	 * Disable the hardware if it has been idle for vxd->hw_pm_delay
	 * milliseconds. Or simply leave the function without doing anything
	 * if the HW is not supposed to be turned off.
	 */
	if (list_empty(&vxd->pend) && list_empty(&vxd->msgs)) {
		if (vxd_is_apm_required(vxd)) {
			unsigned long dst = vxd->pm_start +
				msecs_to_jiffies(vxd->hw_pm_delay);

			if (time_is_before_eq_jiffies(dst)) {
				dev_dbg(vxd->dev, "%s: pm, power off\n",
						__func__);
				vxd_make_hw_off_locked(vxd, false);
			} else {
				unsigned long target = dst - jiffies;

				dev_dbg(vxd->dev, "%s: pm, reschedule: %ld\n",
						__func__, target);
				vxd_sched_worker_locked(vxd,
						jiffies_to_msecs(target));
			}
		}
		goto out_unlock;
	}

	/*
	 * We are not processing anything, but pending list is not empty (if it
	 * was, we would enter <if statement> above. This can happen upon
	 * specific conditions, when input message occupies almost whole
	 * host->MTX ring buffer and is followed by large padding message.
	 */
	if (list_empty(&vxd->msgs)) {
		vxd_schedule_locked(vxd);
		goto out_unlock;
	}

	/* Skip emergency reset if it's disabled. */
	if (vxd->hw_dwr_period <= 0) {
		dev_dbg(vxd->dev, "%s: skip watchdog\n", __func__);
		goto out_unlock;
	} else {
		/* Recalculate DWR when needed */
		unsigned long dst = vxd->dwr_start +
				msecs_to_jiffies(vxd->hw_dwr_period);

		if (time_is_after_jiffies(dst)) {
			unsigned long target = dst - jiffies;

			dev_dbg(vxd->dev, "%s: dwr, reschedule: %ld\n",
					__func__, target);
			vxd_sched_worker_locked(vxd, jiffies_to_msecs(target));
			goto out_unlock;
		}
	}

	/* Get ID of the oldest item being processed by the HW */
	item_tail = list_entry(vxd->msgs.prev, struct vxd_item, list);

	dev_dbg(vxd->dev, "%s: tail_item: %p, id: 0x%x\n", __func__, item_tail,
			item_tail->msg_id);

	/* Get HW and firmware state */
	vxd_pvdec_get_state(vxd->dev, vxd->reg_base,
			VXD_NUM_PIX_PIPES(vxd->props), &state);

	/* Check if the oldest msg did not get back for a while */
	if (vxd->state.msg_id_tail == item_tail->msg_id) {
		/* Decrease ttl for a given message */
		item_tail->ttl--;
		/* Check if total time to live expired */
		if (!item_tail->ttl) {
			dev_info(vxd->dev,
					"message TTL(%ums) expired, force device DWR!",
				VXD_MSG_TTL * vxd->hw_dwr_period);
			fire_dwr = true;

		/* If hw state does not indicate any progress
		 * fire DWR immediately*/
		} else if (!memcmp(&state, &vxd->state.hw_state,
				sizeof(struct vxd_hw_state))) {
			dev_info(vxd->dev,
					"device DWR(%ums) expired!\n",
				vxd->hw_dwr_period);
			fire_dwr = true;
		}
	}

	if (fire_dwr) {
		vxd->state.msg_id_tail = 0;
		memset(&vxd->state.hw_state, 0, sizeof(vxd->state.hw_state));
		dev_info(vxd->dev, " going to reset core...\n");
		vxd_emrg_reset_locked(vxd, VXD_FW_MSG_FLAG_DWR);
	} else {
		/* Record current state */
		vxd->state.msg_id_tail = item_tail->msg_id;
		vxd->state.hw_state = state;

		/* Submit items to the HW, if space is available.  */
		vxd_schedule_locked(vxd);

		dev_dbg(vxd->dev, "%s: scheduling DWR work (%d ms)!\n",
				__func__, vxd->hw_dwr_period);
		vxd->dwr_start = jiffies;
		vxd_sched_worker_locked(vxd, vxd->hw_dwr_period);
	}

out_unlock:
	mutex_unlock(&vxd->mutex);
}

/*
 * Takes the firmware from the file system and allocates a buffer
 */
static int vxd_prepare_fw(struct vxd_dev *vxd, uint32_t type)
{
	const struct firmware *fw;
	struct vxd_fw_hdr *hdr;
	int buf_id;
	void *buf_kptr;
	size_t bin_size;
	int ret;

	/* Try to fetch firmware from debugfs */
	if (vxd_dbgfs_request_fw(vxd, drv_fw_name[type], &fw)) {
		/* Fetch firmware from the file system */
		ret = request_firmware(&fw, drv_fw_name[type], vxd->dev);
		if (ret) {
			dev_err(vxd->dev, "%s: failed to fetch firmware (err:%d)!\n",
				__func__, ret);
			return ret;
		}
	}

	dev_info(vxd->dev, "FW: acquired %s size %zu\n",
		drv_fw_name[type], fw->size);
	/* Sanity verification of the firmware */
	if (fw->size < sizeof(struct vxd_fw_hdr) || !fw->size) {
		dev_err(vxd->dev, "%s: firmware file too small!\n", __func__);
		ret = -EINVAL;
		goto out_release_fw;
	}

	bin_size = fw->size - sizeof(struct vxd_fw_hdr);
	ret = img_mem_alloc(vxd->dev, drv.mem_ctx, drv.internal_heap_id,
				bin_size, 0, &buf_id);
	if (ret) {
		dev_err(vxd->dev, "%s: failed to alloc fw buffer (err:%d)!\n",
			__func__, ret);
		goto out_release_fw;
	}

	hdr = kzalloc(sizeof(struct vxd_fw_hdr), GFP_KERNEL);
	if (!hdr) {
		ret = -ENOMEM;
		goto out_release_buf;
	}

	/* Store firmware header in vxd context */
	memcpy(hdr, fw->data, sizeof(struct vxd_fw_hdr));

	dev_info(vxd->dev, "FW: info cs: %u, bs: %u, id: 0x%08x, ts: %u\n",
		hdr->core_size, hdr->blob_size,
		hdr->firmware_id, hdr->timestamp);

	/* Check if header is consistent */
	if (hdr->core_size > bin_size || hdr->blob_size > bin_size) {
		dev_err(vxd->dev, "%s: got invalid firmware!\n", __func__);
		ret = -EINVAL;
		goto out_release_hdr;
	}

	/* Map the firmware buffer to CPU */
	ret = img_mem_map_km(drv.mem_ctx, buf_id);
	if (ret) {
		dev_err(vxd->dev, "%s: failed to map FW buf to cpu! (%d)\n",
			__func__, ret);
		goto out_release_hdr;
	}

	/* Copy firmware to device buffer */
	buf_kptr = img_mem_get_kptr(drv.mem_ctx, buf_id);
	memcpy(buf_kptr, fw->data + sizeof(struct vxd_fw_hdr),
		fw->size - sizeof(struct vxd_fw_hdr));
	dev_dbg(vxd->dev, "%s: FW: copied to buffer %d kptr 0x%p\n",
		__func__, buf_id, buf_kptr);

	img_mem_sync_cpu_to_device(drv.mem_ctx, buf_id);

	vxd->firmware[type].fw = fw;
	vxd->firmware[type].buf_id = buf_id;
	vxd->firmware[type].hdr = hdr;

	return 0;

out_release_hdr:
	kfree(hdr);
out_release_buf:
	img_mem_free(drv.mem_ctx, buf_id);
out_release_fw:
	if (vxd_dbgfs_release_fw(vxd, fw))
		release_firmware(fw);
	return ret;
}

/*
 * Cleans firmware resources
 */
static void vxd_clean_fw_resources(struct vxd_dev *vxd)
{
	int type;

	for (type = 0; type < VXD_STR_TYPE_MAX; type++) {
		if (vxd->firmware[type].fw == NULL)
			continue;
		img_mem_free(drv.mem_ctx, vxd->firmware[type].buf_id);
		kfree(vxd->firmware[type].hdr);
		if (vxd_dbgfs_release_fw(vxd, vxd->firmware[type].fw))
			release_firmware(vxd->firmware[type].fw);
		dev_info(vxd->dev, "FW: released %s\n", drv_fw_name[type]);
		vxd->firmware[type].buf_id = VXD_INVALID_ID;
	}
}

int vxd_add_dev(struct device *dev,
		const struct heap_config heap_configs[], const int heaps,
		void *plat_data, void __iomem *reg_base, unsigned int reg_size)
{
	struct vxd_dev *vxd;
	struct list_head *entry;
	int core_nr = 0, ret;
	int type;

	vxd = devm_kzalloc(dev, sizeof(struct vxd_dev), GFP_KERNEL);
	if (!vxd) {
		dev_err(dev, "%s: failed to allocate vxd_dev context!",
				__func__);
		return -ENOMEM;
	}
	dev_dbg(dev, "%s: allocated vxd_dev @ %p\n", __func__, vxd);
	vxd->dev = dev;
	vxd->plat_data = plat_data;
	vxd->reg_base = reg_base;
	vxd->reg_size = reg_size;

	/* Read HW properties */
	ret = vxd_pvdec_get_props(vxd->dev, vxd->reg_base, &vxd->props);
	if (ret) {
		dev_err(dev, "%s: failed to fetch core properties!", __func__);
		goto out_free_dev;
	}
	vxd->mmu_config.addr_width = VXD_EXTRN_ADDR_WIDTH(vxd->props);
	dev_info(dev, "%s: hw:%u.%u.%u, num_pix: %d, num_ent: %d, mmu: %d, MTX RAM: %d (%dKB)\n",
		__func__,
		VXD_MAJ_REV(vxd->props), VXD_MIN_REV(vxd->props),
		VXD_MAINT_REV(vxd->props),
		VXD_NUM_PIX_PIPES(vxd->props),
		VXD_NUM_ENT_PIPES(vxd->props),
		VXD_EXTRN_ADDR_WIDTH(vxd->props),
		vxd->props.mtx_ram_size,
		vxd->props.mtx_ram_size / 1024);

	ret = vxd_init(dev, heap_configs, heaps);
	if (ret) {
		dev_err(dev, "%s: main component initialisation failed!",
				__func__);
		goto out_free_dev;
	}

	vxd->fw_refcnt = 0;

	vxd->hw_on = 0;
	vxd->keep_hw_on = keep_hw_on;
	vxd->fw_upload_dma = fw_upload_dma;
	vxd->hw_pm_delay = hw_pm_delay;
	vxd->hw_dwr_period = hw_dwr_period;
	vxd->boot_msleep = boot_msleep;
	vxd->hw_crc = hw_crc;

	vxd->props.internal_heap_id = drv.internal_heap_id;

	mutex_init(&vxd->mutex);
	INIT_LIST_HEAD(&vxd->links);
	INIT_LIST_HEAD(&vxd->msgs);
	INIT_LIST_HEAD(&vxd->pend);
	idr_init(&vxd->streams);

	/* Preparation of the firmware resources */
	for (type = 0; type < VXD_STR_TYPE_MAX; type++) {
		vxd->firmware[type].buf_id = VXD_INVALID_ID;
		vxd->firmware[type].hdr = NULL;
		vxd->firmware[type].fw = NULL;

		/* Skip the fw we don't really want */
		if (!(fw_select & (1 << type)))
			continue;

		ret = vxd_prepare_fw(vxd, type);
		if (ret) {
			dev_err(dev, "%s: %s acquire failed!",
					__func__, drv_fw_name[type]);
			/* Fail only when insecure firmware is not found.
			 * Treat a missing loopback or secure firmware as
			 * non fatal and let it fail on stream creation */
			if (type == VXD_STR_TYPE_NON_SECURE)
				goto out_acquire_fw;
		}
	}

	/* Allocate rendec buffer */
	if ((VXD_RENDEC_SIZE * VXD_NUM_PIX_PIPES(vxd->props)) > PVDEC_BUF_RENDEC_SIZE)
	{
		dev_err(dev, "%s: rendec buffer too big (exceeding 0x%08lx bytes)!\n",
			__func__, PVDEC_BUF_RENDEC_SIZE);
		goto out_acquire_fw;
	}
	ret = img_mem_alloc(dev, drv.mem_ctx, drv.internal_heap_id,
				VXD_RENDEC_SIZE * VXD_NUM_PIX_PIPES(vxd->props),
				0, &vxd->rendec_buf_id);
	if (ret) {
		dev_err(dev, "%s: alloc rendec buffer failed (err:%d)!\n",
			__func__, ret);
		goto out_acquire_fw;
	}

	/* Get number of cores currently registered. */
	list_for_each(entry, &drv.devices)
		core_nr++;

	dev_set_drvdata(dev, vxd);

	INIT_DELAYED_WORK(&vxd->dwork, vxd_worker);

	/* Create userspace node */
	ret = vxd_api_add_dev(dev, core_nr, vxd);
	if (ret) {
		dev_err(dev, "%s: failed to add UM node!", __func__);
		goto out_add_dev;
	}

	/* Add device to driver context */
	list_add(&vxd->list, &drv.devices);

	return ret;

out_add_dev:
	dev_set_drvdata(dev, NULL);
	img_mem_free(drv.mem_ctx, vxd->rendec_buf_id);
out_acquire_fw:
	vxd_clean_fw_resources(vxd);
	vxd_deinit();
out_free_dev:
	devm_kfree(dev, vxd);
	return ret;
}

void vxd_rm_dev(struct device *dev)
{
	struct vxd_dev *vxd = dev_get_drvdata(dev);
	int ret;

	if (!vxd || !vxd->dev) {
		pr_err("trying to deinit in a wrong state!\n");
		return;
	}

	ret = vxd_api_rm_dev(vxd->dev, vxd);
	if (ret)
		dev_err(vxd->dev, "%s: failed to remove UM node!\n", __func__);

	list_del(&vxd->list);

	cancel_delayed_work_sync(&vxd->dwork);

	dev_set_drvdata(dev, NULL);

	vxd_make_hw_off_locked(vxd, false);

	idr_destroy(&vxd->streams);

	img_mem_free(drv.mem_ctx, vxd->rendec_buf_id);

	vxd_clean_fw_resources(vxd);

	devm_kfree(dev, vxd);
}

/*
 * Create a stream, assign unique id and store in a map.
 * Add new stream to  link->streams list.
 * This function has to be called with link->mutex locked
 */
int vxd_create_stream(struct vxd_dev *vxd, struct vxd_link *link,
		uint32_t *str_id, uint32_t str_type)
{
	struct vxd_stream *stream;
	int fw_buf_id;
	int ret;

	stream = kzalloc(sizeof(struct vxd_stream), GFP_KERNEL);
	if (!stream)
		return -ENOMEM;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		goto out_free_stream;

	if (str_type >= VXD_STR_TYPE_MAX) {
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = idr_alloc_cyclic(&vxd->streams, stream, VXD_MIN_STREAM_ID,
				VXD_MAX_STREAM_ID, GFP_KERNEL);
	if (ret < VXD_MIN_STREAM_ID || ret > VXD_MAX_STREAM_ID) {
		dev_err(vxd->dev, "%s: stream id creation failed!\n", __func__);
		ret = -EFAULT;
		goto out_unlock;
	}

	stream->id = ret;
	stream->link = link;
	stream->type = str_type;

	ret = img_mmu_ctx_create(vxd->dev, &vxd->mmu_config,
				link->mem_ctx, drv.internal_heap_id,
				img_mmu_callback, vxd, &stream->mmu_ctx);
	if (ret) {
		dev_err(vxd->dev, "%s: mmu context creation failed!\n",
			__func__);
		goto out_idr_remove;
	}

	ret = vxd_get_fw_locked(vxd, stream->mmu_ctx, str_type, &fw_buf_id);
	if (ret) {
		dev_err(vxd->dev, "%s: cannot get firmware!\n", __func__);
		goto out_free_ctx;
	}

	ret = img_mmu_map(stream->mmu_ctx, drv.mem_ctx, fw_buf_id,
			drv.virt_space.fw_addr, IMG_MMU_PTD_FLAG_READ_ONLY);
	if (ret) {
		dev_err(vxd->dev, "%s: failed to map FW buf to device! (%d)\n",
			__func__, ret);
		goto out_put_fw;
	}

	ret = img_mmu_map(stream->mmu_ctx, drv.mem_ctx, vxd->rendec_buf_id,
			drv.virt_space.rendec_addr, IMG_MMU_PTD_FLAG_NONE);
	if (ret) {
		dev_err(vxd->dev, "%s: failed to map rendec buffer!\n",
			__func__);
		ret = -EFAULT;
		goto out_unmap_fw;
	}

	ret = img_mmu_get_ptd(stream->mmu_ctx, &stream->ptd);
	if (ret) {
		dev_err(vxd->dev, "%s: failed to get PTD!\n", __func__);
		ret = -EFAULT;
		goto out_unmap_rendec;
	}

	list_add(&stream->list, &link->streams);

	dev_dbg(vxd->dev, "%s: new stream id: %d, link: %p, ptd: 0x%08x\n",
		__func__, stream->id, link, stream->ptd);

	*str_id = stream->id;
	mutex_unlock(&vxd->mutex);
	return 0;

out_unmap_rendec:
	img_mmu_unmap(stream->mmu_ctx, drv.mem_ctx, vxd->rendec_buf_id);
out_unmap_fw:
	img_mmu_unmap(stream->mmu_ctx, drv.mem_ctx, fw_buf_id);
out_put_fw:
	vxd_put_fw_locked(vxd);
out_free_ctx:
	img_mmu_ctx_destroy(stream->mmu_ctx);
out_idr_remove:
	idr_remove(&vxd->streams, stream->id);
out_unlock:
	mutex_unlock(&vxd->mutex);
out_free_stream:
	kfree(stream);
	return ret;
}

/*
 * Destroy the stream and remove from link->stream list.
 * This functions blocks until all items associated with this stream which are
 * currently being processed by the HW are done.
 * This function has to be called with link->mutex locked
 */
int vxd_destroy_stream(struct vxd_dev *vxd, struct vxd_link *link,
		uint32_t str_id)
{
	struct vxd_stream *stream;
	int ret;

	dev_dbg(vxd->dev, "%s: stream id: %d\n", __func__, str_id);

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	stream = idr_find(&vxd->streams, str_id);
	if (!stream) {
		dev_err(vxd->dev, "%s: stream %d not found!\n",
			__func__, str_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	vxd_purge_stream_locked(vxd, link, stream);

	vxd_del_stream_locked(vxd, stream);
	vxd_put_fw_locked(vxd);

	/* Flush device MMU just for sanity */
	if (vxd->hw_on)
		vxd_pvdec_mmu_flush(vxd->dev, vxd->reg_base);

	wake_up(&link->queue);

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

int vxd_map_buffer(struct vxd_dev *vxd, struct vxd_link *link,
		uint32_t str_id, uint32_t buff_id,
		uint32_t virt_addr, uint32_t map_flags)
{
	struct vxd_stream *stream;
	uint32_t flags = IMG_MMU_PTD_FLAG_NONE;
	int ret;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	stream = idr_find(&vxd->streams, str_id);
	if (!stream) {
		dev_err(vxd->dev, "%s: stream %d not found!\n",
			__func__, str_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	if ((map_flags & (VXD_MAP_FLAG_READ_ONLY|VXD_MAP_FLAG_WRITE_ONLY)) ==
			(VXD_MAP_FLAG_READ_ONLY|VXD_MAP_FLAG_WRITE_ONLY)) {
		dev_err(vxd->dev, "%s: Bogus mapping flags 0x%x!\n",
			__func__, map_flags);
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Convert permission flags to internal definitions */
	if (map_flags & VXD_MAP_FLAG_READ_ONLY)
		flags |= IMG_MMU_PTD_FLAG_READ_ONLY;

	if (map_flags & VXD_MAP_FLAG_WRITE_ONLY)
		flags |= IMG_MMU_PTD_FLAG_WRITE_ONLY;

	ret = img_mmu_map(stream->mmu_ctx, link->mem_ctx, buff_id,
			virt_addr, flags);
	if (ret) {
		dev_err(vxd->dev, "%s: map failed!\n", __func__);
		goto out_unlock;
	}

	dev_dbg(vxd->dev, "%s: mapped buf %u to 0x%08x, str_id: %u flags: 0x%x\n",
			__func__, buff_id, virt_addr, str_id, flags);

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

int vxd_unmap_buffer(struct vxd_dev *vxd, struct vxd_link *link,
			uint32_t str_id, uint32_t buff_id)
{
	struct vxd_stream *stream;
	int ret;

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	stream = idr_find(&vxd->streams, str_id);
	if (!stream) {
		dev_err(vxd->dev, "%s: stream %d not found!\n",
			__func__, str_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = img_mmu_unmap(stream->mmu_ctx, link->mem_ctx, buff_id);
	if (ret) {
		dev_err(vxd->dev, "%s: map failed!\n", __func__);
		goto out_unlock;
	}

	dev_dbg(vxd->dev, "%s: unmapped buf %u str_id: %u\n",
			__func__, buff_id, str_id);

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * Submit a message to the VXD.
 * <link> is used to verify that requested stream id (item->str_id) is valid
 * for this link
 */
int vxd_send_msg(struct vxd_dev *vxd, struct vxd_item *item,
		const struct vxd_link *link)
{
	int ret;
	struct vxd_stream *stream;

	if (item->msg.payload_size % sizeof(u32)) {
		dev_err(vxd->dev, "msg size not aligned! (%u)\n",
				item->msg.payload_size);
		return -EINVAL;
	}

	ret = mutex_lock_interruptible(&vxd->mutex);
	if (ret)
		return ret;

	stream = idr_find(&vxd->streams, item->str_id);
	if (!stream) {
		dev_warn(vxd->dev, "%s: invalid stream id requested! (%u)\n",
				__func__, item->str_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	if (stream->link != link) {
		dev_warn(vxd->dev, "%s: link doesn't match req. str id!(%u)\n",
				__func__, item->str_id);
		ret = -EINVAL;
		goto out_unlock;
	}

	/* Inject the stream PTD into the message. It was already verified that
	 * there is enough space. */
	item->msg.payload[VXD_PTD_MSG_OFFSET] = stream->ptd;

	list_add_tail(&item->list, &vxd->pend);
	dev_dbg(vxd->dev,
			"%s: added item %p to pend, ptd: 0x%x, str: %u flags: 0x%x\n",
			__func__,
			item, stream->ptd, stream->id, item->msg.out_flags);

	vxd_schedule_locked(vxd);

out_unlock:
	mutex_unlock(&vxd->mutex);

	return ret;
}

/*
 * Reads MTX debug FIFO and puts the data into provided buffer <buf> of size
 * <size> (in bytes)
 */
size_t vxd_read_mtx_fifo(struct vxd_dev *vxd, u32 *buf, size_t size)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);

	if (ret)
		return ret;

	if (!vxd->hw_on) {
		dev_warn(vxd->dev,
			"%s: trying to read mtx_fifo while core disabled!",
			__func__);
		ret = -EIO;
		goto out_unlock;
	}

	ret = vxd_pvdec_read_mtx_fifo(vxd->dev, vxd->reg_base, buf, size);

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * Reads MTX ram @count entries at @addr and puts the data into provided
 * buffer <buf> of size <size> (in bytes)
 */
int vxd_read_mtx_ram(struct vxd_dev *vxd, u32 addr, u32 count,
		u32 *buf, size_t size)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);

	if (ret)
		return ret;

	if (!vxd->hw_on) {
		dev_warn(vxd->dev,
			"%s: trying to read mtx_ram while core disabled!",
			__func__);
		ret = -EIO;
		goto out_unlock;
	}

	if (size < count*sizeof(u32)) {
		dev_err(vxd->dev,
			"%s: buffer(%zu) does not match requested count(%u)!",
			__func__, size, count);
		ret = -EINVAL;
		goto out_unlock;
	}

	ret = vxd_pvdec_dump_mtx_ram(vxd->dev, vxd->reg_base,
			addr, count, buf);

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * Reads MTX status and puts the data into provided
 * buffer <buf> of size <size> (in bytes)
 */
int vxd_read_mtx_status(struct vxd_dev *vxd, u32 *buf, size_t size)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);

	if (ret)
		return ret;

	if (!vxd->hw_on) {
		dev_warn(vxd->dev,
			"%s: trying to read mtx_status while core disabled!",
			__func__);
		ret = -EIO;
		goto out_unlock;
	}

	ret = vxd_pvdec_dump_mtx_status(vxd->dev, vxd->reg_base,
			buf, size / sizeof(u32));

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * This function sets up memory staller configuration
 */
int vxd_setup_memstaller(struct vxd_dev *vxd, u32 *buf, size_t size)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);

	if (ret)
		return ret;

	vxd->memstaller_conf = kmalloc_array(size, sizeof(u32), GFP_KERNEL);
	if (!vxd->memstaller_conf) {
		dev_warn(vxd->dev,
			"%s: cannot allocate buffer for memory staller!",
			__func__);
		ret = -ENOMEM;
		goto out_unlock;
	}

	vxd->memstaller_size = size;
	memcpy(vxd->memstaller_conf, buf, size * sizeof(u32));

out_unlock:
	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * This function forces emergency condition - just for testing
 */
int vxd_force_emergency(struct vxd_dev *vxd, unsigned val)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);

	if (ret)
		return ret;

	dev_warn(vxd->dev, "%s: %x", __func__, val);

	vxd_emrg_reset_locked(vxd, val);

	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * This function reloads firmwares from debugfs - just for testing
 */
int vxd_reload_fws(struct vxd_dev *vxd)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);
	int type;

	if (ret)
		return ret;

	dev_dbg(vxd->dev, "%s", __func__);

	vxd_make_hw_off_locked(vxd, false);

	/* Clean original resources */
	vxd_clean_fw_resources(vxd);

	/* Preparation of the firmware resources
	 * NOTE: every type of fw is swapped with custom fw */
	for (type = 0; type < VXD_STR_TYPE_MAX; type++) {
		vxd->firmware[type].buf_id = VXD_INVALID_ID;
		vxd->firmware[type].hdr = NULL;
		vxd->firmware[type].fw = NULL;

		/* Skip the fw we don't really want */
		if (!(fw_select & (1 << type)))
			continue;

		ret = vxd_prepare_fw(vxd, type);
		if (ret)
			dev_err(vxd->dev, "%s: %s acquire failed!",
					__func__, drv_fw_name[type]);
	}

	mutex_unlock(&vxd->mutex);
	return ret;
}

/*
 * Checks if device is currently turned on/off
 */
int vxd_check_dev(struct vxd_dev *vxd, unsigned int *enabled)
{
	int ret = mutex_lock_interruptible(&vxd->mutex);

	if (ret)
		return ret;

	*enabled = vxd->hw_on;

	mutex_unlock(&vxd->mutex);
	return ret;
}

int vxd_suspend_dev(struct device *dev)
{
	struct vxd_dev *vxd = dev_get_drvdata(dev);

	mutex_lock(&vxd->mutex);
	dev_dbg(dev, "%s: taking a nap!\n", __func__);

	/* Cancel the worker first */
	cancel_delayed_work(&vxd->dwork);
	/* Forcing hardware disable */
	vxd_make_hw_off_locked(vxd, true);
	/* Move all valid items to the pending queue */
	vxd_rewind_msgs_locked(vxd);

	mutex_unlock(&vxd->mutex);

	return 0;
}

int vxd_resume_dev(struct device *dev)
{
	struct vxd_dev *vxd = dev_get_drvdata(dev);
	struct vxd_item *item, *tmp;
	int ret = 0;

	mutex_lock(&vxd->mutex);
	dev_dbg(dev, "%s: waking up!\n", __func__);

	/*
	 * Items are already on the pending list,
	 * so just inform the UM that items have been cancelled.
	 * In this case the UM shall take action similar
	 * to replay procedure.
	 */
	list_for_each_entry_safe(item, tmp, &vxd->pend, list)
		vxd_report_item_locked(vxd, item, VXD_FW_MSG_FLAG_CANCELED);

	mutex_unlock(&vxd->mutex);

	return ret;
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
