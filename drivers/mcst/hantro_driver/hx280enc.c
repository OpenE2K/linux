// SPDX-License-Identifier: GPL-2.0
/*
 *    Hantro encoder hardware driver.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/semaphore.h>
#include <linux/spinlock.h>
#include <linux/io.h>
#include <linux/pci.h>
#include <linux/uaccess.h>
#include <linux/ioport.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/timer.h>
#include "hx280enc.h"
#include <linux/irq.h>
#include <linux/delay.h>
#include "ipoffset/vce_offset.h"

#ifdef VSI_FPGA_MEM
#include "hantro_fpga_mem.h"
#endif

#ifdef VSI_FPGA_PCIE
#include "hantro_pcie.h"
#endif

static u32 resource_shared;

#define HANTRO_VC8KE_REG_BWREAD 215
#define HANTRO_VC8KE_REG_BWWRITE 219
#define VC8KE_BURSTWIDTH 16

static int bencprobed;

/*------------------------------END-------------------------------------*/

/***************************TYPE AND FUNCTION DECLARATION****************/

/* here's all the must remember stuff */

static int ReserveIO(struct hantroenc_t *pcore);
static void ReleaseIO(struct hantroenc_t *pcore);
static void ResetAsic(struct hantroenc_t *dev);
static int CheckCoreOccupation(struct hantroenc_t *dev);
static void ReleaseEncoder(struct hantroenc_t *dev, u32 *core_info,
			   u32 nodenum);

static void polling_isr_timer_start(struct hantroenc_t *penccore);
static void polling_isr_timer_stop(struct hantroenc_t *penccore);

/* IRQ handler */
#if KERNEL_VERSION(2, 6, 18) > LINUX_VERSION_CODE
static irqreturn_t hantroenc_isr(int irq, void *dev_id, struct pt_regs *regs);
#else
static irqreturn_t hantroenc_isr(int irq, void *dev_id);
#endif

/*********************local variable declaration*****************/
unsigned long long sram_base;
unsigned int sram_size;
/* and this is our MAJOR; use 0 for dynamic allocation (recommended)*/
static int hantroenc_major;

/**
 * @brief abort vce when needed
 */
int abort_vce(void __iomem *reg_base)
{
	u32 status;

	status = (u32)ioread32(reg_base + 0x14);
	if (status & 0x1) {
		//Stop VCE by setting reg5 bit0 to 0.
		status &= (~0x01);
		iowrite32(status, reg_base + 0x14);
		return 1;
	}
	return 0;
}

#ifdef VSI_CONFIG_PM
static long EncRestoreRegs(struct hantroenc_t *dev)
{
	long i;
	/* write all regs to hardware */
	u32 *reg_buf = dev->reg_buf;

	for (i = 0; i < ASIC_SWREG_AMOUNT * 4; i += 4)
		iowrite32(reg_buf[i/4], (void __iomem *)(dev->hwregs + i));

	return 0;
}

static long EncStoreRegs(struct hantroenc_t *dev)
{
	long i;
	/* read all registers from hardware */
	u32 *reg_buf = dev->reg_buf;

	for (i = 0; i < ASIC_SWREG_AMOUNT * 4; i += 4)
		reg_buf[i/4] = ioread32((void __iomem *)(dev->hwregs + i));

	return 0;
}

int enc_pm_suspend(void *_dev)
{
	struct hantroenc_t *dev = (struct hantroenc_t *)_dev;

	pr_info("%s start..\n", __func__);

	while (dev) {
		/*if HW is active, need to wait until frame ready interrupt*/
		if ((dev->is_reserved == 0) || (down_interruptible(&dev->core_suspend_sem)))
			continue;

		dev->reg_corrupt = 1;
		if (dev->irq_status & 0x04)
			EncStoreRegs(dev);

		up(&dev->core_suspend_sem);
		dev = dev->next;
	}

	pr_info("%s succeed!\n", __func__);
	return 0;
}

int enc_pm_resume(void *_dev)
{
	u32 *reg_buf;
	struct hantroenc_t *dev = (struct hantroenc_t *)_dev;

	pr_info("%s start..\n", __func__);

	while (dev) {
		if (dev->is_reserved == 0)
			continue;

		reg_buf = dev->reg_buf;

		if (dev->irq_status & 0x04) {
			EncRestoreRegs(dev);
			dev->reg_corrupt = 0;
		}
		dev = dev->next;
	}

	pr_info("%s succeed!\n", __func__);
	return 0;
}
#endif

/******************************************************************************/
static int CheckEncIrq(struct hantroenc_t *dev, u32 *core_info, u32 *irq_status,
		       u32 total_core_num)
{
	unsigned long flags;
	int rdy = 0;
	u32 i = 0;
	u8 core_mapping = 0;
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	core_mapping = (u8)(*core_info & 0xFF);

	//pr_info("core_mapping = %d\n",core_mapping);
	while (core_mapping) {
		if (core_mapping & 0x1) {
			if (i >= total_core_num)
				break;
			spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
			if (dev->irq_received) {
				/* reset the wait condition(s) */
				PDEBUG("check %d irq ready\n", i);
				dev->irq_received = 0;
				rdy = 1;
				*core_info = i;
				*irq_status = dev->irq_status;
			}

			spin_unlock_irqrestore(&parentslice->enc_owner_lock,
					       flags);
			break;
		}
		core_mapping = core_mapping >> 1;
		i++;
		dev = dev->next;
	}
	return rdy;
}

static int CheckEncIrqbyPolling(struct hantroenc_t *dev, u32 *irq_status)
{
	unsigned long flags;
	int rdy = 0;
	u32 irq, hwId, majorId, wClr;
	u32 loop = 30;
	u32 interval = 100;
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	pr_info("%s,%d\n", __func__, __LINE__);

	do {
		spin_lock_irqsave(&parentslice->enc_owner_lock, flags);

		if (dev->irq_received) {
			pr_info("%s,%d\n", __func__, __LINE__);

			PDEBUG("check %d irq ready\n", i);
			dev->irq_received = 0;
			rdy = 1;
			*irq_status = dev->irq_status;
			goto end_1;
		}

		irq = (u32)ioread32((void *)(dev->hwregs + 0x04));
		pr_info("%s,%d,irq %x\n", __func__, __LINE__, irq);

		if (irq & ASIC_STATUS_ALL) {
			if (irq & 0x20)
				iowrite32(0, (void *)(dev->hwregs + 0x14));

			/* clear all IRQ bits. (hwId >= 0x80006100) means
			 * IRQ is cleared by writing 1
			 */
			hwId = ioread32((void *)dev->hwregs);
			majorId = (hwId & 0x0000FF00) >> 8;
			wClr = (majorId >= 0x61) ? irq : (irq & (~0x1FD));
			iowrite32(wClr, (void *)(dev->hwregs + 0x04));

			rdy = 1;
			*irq_status = irq;
			dev->irq_received = 0;
			dev->irq_status = irq;
#ifdef VSI_CONFIG_PM
		//if frame_rdy IRQ is received, then HW will not be used any more.
		if (*irq_status & ASIC_STATUS_FRAME_READY)
			up(&dev->core_suspend_sem);
#endif

			goto end_1;
		}

		spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);
		mdelay(interval);
	} while (loop--);
	goto end_2;
	pr_info("%s,%d\n", __func__, __LINE__);

end_1:
	spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);
end_2:
	return rdy;
}

static unsigned int WaitEncReady(struct hantroenc_t *dev, u32 *core_info,
				 u32 *irq_status, u32 total_core_num)
{
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	PDEBUG("%s\n", __func__);

	if (wait_event_interruptible(parentslice->enc_wait_queue,
				     CheckEncIrq(dev, core_info, irq_status,
						 total_core_num))) {
		PDEBUG("ENC wait_event_interruptible interrupted\n");
		ReleaseEncoder(dev, core_info, total_core_num);
		return -ERESTARTSYS;
	}

	return 0;
}

static int CheckEncAnyIrq(struct hantroenc_t *dev, CORE_WAIT_OUT *out)
{
	int rdy = 0;
	u32 i = 0;
	unsigned long flags;

	while ((dev) && (out->irq_num < CORE_MAX)) {
		struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

		spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
		if (dev->irq_received) {
			dev->irq_received = 0;
			/* reset the wait condition(s) */
			PDEBUG("check %d irq ready\n", i);
			out->irq_status[out->irq_num] = dev->irq_status;
			out->job_id[out->irq_num] = dev->core_id;
			out->irq_num++;
			rdy = 1;
		}
		spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);
		i++;
		dev = dev->next;
	}
	return rdy;
}

static unsigned int WaitEncAnyReady(struct hantroenc_t *dev, CORE_WAIT_OUT *out)
{
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	if (wait_event_interruptible(parentslice->enc_wait_queue,
				     CheckEncAnyIrq(dev, out))) {
		PDEBUG("ENC wait_event_interruptible interrupted\n");
		return -ERESTARTSYS;
	}

	return 0;
}

u32 hantroenc_readbandwidth(int sliceidx, int isreadBW)
{
	int i, slicen = get_slicenumber();
	u32 bandwidth = 0;
	struct hantroenc_t *pcore;
	u8 *rregs;
	u8 *wregs;

	if (sliceidx < 0) {
		for (i = 0; i < slicen; i++) {
			pcore = get_encnodes(i, 0);
			while (pcore) {
				rregs = pcore->hwregs +
					HANTRO_VC8KE_REG_BWREAD * 4;
				wregs = pcore->hwregs +
					HANTRO_VC8KE_REG_BWWRITE * 4;
				if (isreadBW)
					bandwidth += ioread32((void *)rregs);
				else
					bandwidth += ioread32((void *)wregs);
				pcore = pcore->next;
			}
		}
	} else {
		pcore = get_encnodes(sliceidx, 0);
		while (pcore) {
			rregs = pcore->hwregs + HANTRO_VC8KE_REG_BWREAD * 4;
			wregs = pcore->hwregs + HANTRO_VC8KE_REG_BWWRITE * 4;
			if (isreadBW)
				bandwidth += ioread32((void *)rregs);
			else
				bandwidth += ioread32((void *)wregs);
			pcore = pcore->next;
		}
	}
	return bandwidth * VC8KE_BURSTWIDTH;
}

static int CheckCoreOccupation(struct hantroenc_t *dev)
{
	int ret = 0;
	unsigned long flags;
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
	if (!dev->is_reserved) {
		dev->is_reserved = 1;
		dev->pid = current->tgid;
		ret = 1;
		PDEBUG("%s pid=%d\n", __func__, dev->pid);
	}

	spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);

	return ret;
}

static int GetWorkableCore(struct hantroenc_t *dev, u32 *core_info,
			   u32 *core_info_tmp, u32 nodenum)
{
	int ret = 0;
	u32 i = 0;
	u32 cores;
	u8 core_type = 0;
	u32 required_num = 0;

	cores = *core_info;
	required_num = ((cores >> CORE_INFO_AMOUNT_OFFSET) & 0x7) + 1;
	core_type = (u8)(cores & 0xFF);

	if (*core_info_tmp == 0)
		*core_info_tmp = required_num << CORE_INFO_AMOUNT_OFFSET;
	else
		required_num = (*core_info_tmp >> CORE_INFO_AMOUNT_OFFSET);

	PDEBUG("%s:required_num=%d,core_info=%x\n", __func__, required_num,
	       *core_info);

	if (required_num) {
		/* a valid free Core with specified core type */
		for (i = 0; i < nodenum; i++) {
			if (CheckCoreOccupation(dev)) {
				*core_info_tmp = ((((*core_info_tmp >>
						     CORE_INFO_AMOUNT_OFFSET) -
						    1)
						   << CORE_INFO_AMOUNT_OFFSET) |
						  (*core_info_tmp & 0x0FF));
				*core_info_tmp = (*core_info_tmp | (1 << i));
				if ((*core_info_tmp >>
				     CORE_INFO_AMOUNT_OFFSET) == 0) {
					ret = 1;
					*core_info = (dev->core_id << 16) |
						     (*core_info_tmp & 0xFF);
					required_num = 0;
					break;
				}
			}
			dev = dev->next;
		}
	} else {
		ret = 1;
	}

	PDEBUG("*core_info = %x\n", *core_info);
	return ret;
}

static long ReserveEncoder(struct hantroenc_t *dev, u32 *core_info, u32 nodenum)
{
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);
	u32 core_info_tmp = 0;
	/*If HW resources are shared inter cores,
	 *just make sure only one is using the HW
	 */
	if (resource_shared) {
		if (down_interruptible(&parentslice->enc_core_sem))
			return -ERESTARTSYS;
	}

	/* lock a core that has specified core id*/
	if (wait_event_interruptible(parentslice->enc_hw_queue,
				     GetWorkableCore(dev, core_info,
						     &core_info_tmp,
						     nodenum) != 0))
		return -ERESTARTSYS;

	return 0;
}

static void ReleaseEncoder(struct hantroenc_t *dev, u32 *core_info, u32 total_core_num)
{
	unsigned long flags;
	u32 core_num = 0;
	u32 i = 0, core_id;
	u8 core_mapping = 0;
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	core_num = ((*core_info >> CORE_INFO_AMOUNT_OFFSET) & 0x7) + 1;

	core_mapping = (u8)(*core_info & 0xFF);

	PDEBUG("%s:core_num=%d,core_mapping=%x, total_core_num %d\n", __func__, core_num,
	       core_mapping, total_core_num);
	/* release specified core id */
	while (core_mapping) {
		if (core_mapping & 0x1) {
			if (i >= total_core_num)
				break;
			core_id = i;
			spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
			PDEBUG("dev[core_id].pid=%d,current->pid= %x app name %s\n",
			       dev->pid, current->pid, current->tgid, current->comm);
			if (dev->is_reserved) {
				dev->pid = -1;
				dev->is_reserved = 0;
				dev->irq_received = 0;
				dev->irq_status = 0;
#ifdef VSI_CONFIG_PM
				dev->reg_corrupt = 0;
#endif
			}
			spin_unlock_irqrestore(&parentslice->enc_owner_lock,
					       flags);

			//wake_up_interruptible_all(&enc_hw_queue);
		}
		core_mapping = core_mapping >> 1;
		i++;
		dev = dev->next;
	}

	wake_up_interruptible_all(&parentslice->enc_hw_queue);

	if (resource_shared)
		up(&parentslice->enc_core_sem);
}

long hantroenc_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned int id, tmp;
	struct hantroenc_t *pcore;
	u32 core_info;
	hantro_ioctl_id ioctl_id_par;
	int ret;

	switch (cmd) {
	case HANTROENC_IOCGHWOFFSET: {
		__get_user(id, (unsigned long long *)arg);

		ioctl_id_par.data = id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx,
				     ioctl_id_par.ID_PAR.codec_idx);
		if (!pcore)
			return -EFAULT;

		__put_user(pcore->core_cfg.base_addr,
			   (unsigned long long *)arg);
		break;
	}

	case HANTROENC_IOCGHWIOSIZE: {
		u32 io_size;

		__get_user(id, (unsigned long *)arg);

		ioctl_id_par.data = id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx,
				     ioctl_id_par.ID_PAR.codec_idx);
		if (!pcore)
			return -EFAULT;
		io_size = pcore->core_cfg.iosize;
		__put_user(io_size, (u32 *)arg);
		return 0;
	}
	case HANTROENC_IOCGSRAMOFFSET:
		__put_user(sram_base, (unsigned long long *)arg);
		break;
	case HANTROENC_IOCGSRAMEIOSIZE:
		__put_user(sram_size, (unsigned int *)arg);
		break;
	case HANTROENC_IOCG_CORE_NUM:
		tmp = arg;
		return get_slicecorenum(tmp, HANTRO_CORE_ENC);
	case HANTROENC_IOCH_ENC_RESERVE: {
		struct nor32_parameter core_info;

		PDEBUG("Reserve ENC Cores\n");
		ret = copy_from_user(&core_info, (void *)arg,
				     sizeof(struct nor32_parameter));
		if (ret)
			return ret;
		ioctl_id_par.data = core_info.id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx, 0);
		if (!pcore)
			return -EFAULT;
		tmp = get_slicecorenum(ioctl_id_par.ID_PAR.node_idx,
				       HANTRO_CORE_ENC);
		ret = ReserveEncoder(pcore, (u32 *)&core_info.data, tmp);
		if (ret == 0) {
			ret = copy_to_user((void *)arg, &core_info,
					   sizeof(struct nor32_parameter));
		}
		return ret;
	}
	case HANTROENC_IOCH_ENC_RELEASE: {
		struct nor32_parameter core_cfg;

		ret = copy_from_user(&core_cfg, (void *)arg,
				     sizeof(struct nor32_parameter));
		if (ret)
			return ret;
		ioctl_id_par.data = core_cfg.id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx, 0);
		if (!pcore)
			return -EFAULT;
		PDEBUG("Release ENC Core\n");
		tmp = get_slicecorenum(ioctl_id_par.ID_PAR.node_idx,
				       HANTRO_CORE_ENC);
		ReleaseEncoder(pcore, (u32 *)&core_cfg.data, tmp);

		break;
	}

	case HANTRO_IOCG_ENABLE_CORE:
	{
#ifdef VSI_CONFIG_PM
		struct nor32_parameter core_cfg;
		u32 reg_value;

		PDEBUG("Enable ENC Core\n");
		ret = copy_from_user(&core_cfg, (void *)arg,
				     sizeof(struct nor32_parameter));
		if (ret)
			return ret;
		ioctl_id_par.data = core_cfg.id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx, 0);
		if (!pcore)
			return -EFAULT;

		if (pcore->is_reserved == 0)
			return -EPERM;

		if (pcore->reg_corrupt) {
			/*need to re-config HW if exception happen between reserve and enable*/
			pcore->reg_corrupt = 0;
			return -EAGAIN;
		}

		if (down_interruptible(&pcore->core_suspend_sem))
			return -ERESTARTSYS;

		reg_value = (u32)ioread32((void *)(pcore->hwregs + 0x14));
		reg_value |= 0x01;
		iowrite32(reg_value, (void *)(pcore->hwregs + 0x14));
#endif
		break;
	}
	case HANTROENC_IOCG_CORE_WAIT: {
		struct nor32_parameter core_cfg;

		ret = copy_from_user(&core_cfg, (void *)arg,
				     sizeof(struct nor32_parameter));
		if (ret)
			return ret;
		ioctl_id_par.data = core_cfg.id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx, 0);
		if (!pcore)
			return -EFAULT;
#ifdef VSI_CONFIG_PM
		if (pcore->is_reserved == 0)
			return -EPERM;
#endif
		tmp = get_slicecorenum(ioctl_id_par.ID_PAR.node_idx,
				       HANTRO_CORE_ENC);

		core_info = core_cfg.data;
		tmp = WaitEncReady(pcore, &core_info, (u32 *)&core_cfg.data,
				   tmp);
		if (tmp == 0) {
			ret = copy_to_user((void *)arg, &core_cfg,
					   sizeof(struct nor32_parameter));
			return core_info; //return core_id
		}
		ret = copy_to_user((void *)arg, &core_cfg,
				   sizeof(struct nor32_parameter));
		return -1;

		break;
	}

	case HANTROENC_IOCG_CORE_INFO: {
		SUBSYS_CORE_INFO in_data;

		ret = copy_from_user(&in_data, (void *)arg,
				     sizeof(SUBSYS_CORE_INFO));
		if (ret)
			return ret;
		ioctl_id_par.data = in_data.id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx, 0);
		if (!pcore)
			return -EFAULT;

		ret = copy_to_user((void *)arg, &pcore->core_info,
				   sizeof(SUBSYS_CORE_INFO));
		break;
	}
	case HANTROENC_IOCG_ANYCORE_WAIT: {
		CORE_WAIT_OUT out;

		ret = copy_from_user((void *)(&out), (void *)arg,
				     sizeof(CORE_WAIT_OUT));
		if (ret)
			return ret;
		ioctl_id_par.data = out.id;
		pcore = get_encnodes(ioctl_id_par.ID_PAR.node_idx,
				     0); /*from list header*/
		tmp = WaitEncAnyReady(pcore, &out);
		if (tmp == 0) {
			ret = copy_to_user((void *)arg, &out,
					   sizeof(CORE_WAIT_OUT));
			return ret;
		} else {
			return -1;
		}

		break;
	}
	}
	return 0;
}

int hantroenc_release(void)
{
	struct slice_info *parentslice;
	int i, slicen = get_slicenumber();
	struct hantroenc_t *dev;
	unsigned long flags;

	for (i = 0; i < slicen; i++) {
		dev = get_encnodes(i, 0);
		if (!dev)
			continue;
		parentslice = getparentslice(dev, HANTRO_CORE_ENC);
		while (dev) {
			spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
			if (dev->is_reserved == 1 && dev->pid == current->tgid) {
				dev->pid = -1;
				dev->is_reserved = 0;
				dev->irq_received = 0;
				dev->irq_status = 0;
				PDEBUG("release reserved core\n");
			}
			spin_unlock_irqrestore(&parentslice->enc_owner_lock,
					       flags);
			dev = dev->next;
		}
		wake_up_interruptible_all(&parentslice->enc_hw_queue);
		if (resource_shared)
			up(&parentslice->enc_core_sem);
	}
	return 0;
}

int __init hantroenc_init(void)
{
	sram_base = 0;
	sram_size = 0;
	hantroenc_major = 0;
	resource_shared = 0;
	bencprobed = 0;
	return 0;
}

int hantroenc_probe(dtbnode *pnode, int useirq, int loop,
		    struct hantroenc_t *penccore)
{
	int result = 0;
	struct hantroenc_t *pcore = NULL;
	int i, k;

	if (loop == 0) {
#ifndef USE_DTB_PROBE /*simulate and compatible with old code*/
		for (i = 0; i < ARRAY_SIZE(core_array); i++) {
			pcore = vmalloc(sizeof(*pcore));
			if (!pcore)
				break;

			memset(pcore, 0, sizeof(struct hantroenc_t));
			pcore->core_cfg.base_addr = core_array[i].base_addr;
			pcore->core_cfg.iosize = core_array[i].iosize;
			pcore->core_cfg.sliceidx = core_array[i].sliceidx;
			for (k = 0; k < 4; k++)
				pcore->irqlist[k] = -1;
			pcore->irqlist[0] = core_array[i].irq;

			pcore->core_info.type_info |= 1 << CORE_VCE;
			pcore->core_info.offset[CORE_VCE] = 0;
			pcore->core_info.regSize[CORE_VCE] =
				pcore->core_cfg.iosize;
			pcore->core_info.irq[CORE_VCE] = pcore->irqlist[0];

			add_encnode(pcore->core_cfg.sliceidx, pcore);
#ifdef VSI_CONFIG_PM
			sema_init(&pcore->core_suspend_sem, 1);
#endif
		}
#else /*USE_DTB_PROBE*/
		{
			pcore = vmalloc(sizeof(*pcore));
			if (!pcore)
				return -ENOMEM;

			memset(pcore, 0, sizeof(struct hantroenc_t));
			pcore->core_cfg.base_addr = pnode->ioaddr;
			pcore->core_cfg.iosize = pnode->iosize;
			pcore->core_cfg.sliceidx = pnode->sliceidx;
			for (i = 0; i < 4; i++)
				pcore->irqlist[i] = -1;
			pcore->irqlist[0] = pnode->irq[0];

			pcore->core_info.type_info |= 1 << CORE_VCE;
			pcore->core_info.offset[CORE_VCE] = 0;
			pcore->core_info.regSize[CORE_VCE] =
				pcore->core_cfg.iosize;
			pcore->core_info.irq[CORE_VCE] = pcore->irqlist[0];

			add_encnode(pnode->sliceidx, pcore);
		}
#endif /*USE_DTB_PROBE*/
	} else {
		result = ReserveIO(penccore);
		if (result < 0) {
			pr_err("hx280enc: reserve reg 0x%llx-0x%lx fail\n",
			       penccore->core_cfg.base_addr,
			       pcore->core_info.regSize[CORE_VCE]);
			return result;
		}

		ResetAsic(penccore); /* reset hardware */

		if (useirq && penccore->irqlist[0] > 0) {
			result = request_irq(penccore->irqlist[0],
					     hantroenc_isr, IRQF_SHARED,
					     "hx280enc", (void *)penccore);
			if (result < 0) {
				pr_err("hx280enc: request IRQ <%d> fail\n",
				       penccore->irqlist[0]);
				ReleaseIO(penccore);
				return -ENODEV;
			}
		} else {
			polling_isr_timer_start(penccore);
		}
	}
	pr_debug("hx280enc: module inserted. Major <%d>\n", hantroenc_major);

	return 0;
}

void __exit hantroenc_cleanup(void)
{
	int i, k, slicen = get_slicenumber();
	struct hantroenc_t *pcore, *pnext;

	for (i = 0; i < slicen; i++) {
		pcore = get_encnodes(i, 0);
		while (pcore) {
			u32 hwId = pcore->hw_id;
			u32 majorId = (hwId & 0x0000FF00) >> 8;
			u32 wClr = (majorId >= 0x61) ? (0x1FD) : (0);

			pnext = pcore->next;
			iowrite32(0, (void *)(pcore->hwregs +
					      0x14)); /* disable HW */
			iowrite32(wClr, (void *)(pcore->hwregs +
						 0x04)); /* clear enc IRQ */

			/* free the encoder IRQ */
			for (k = 0; k < 4; k++)
				if (pcore->irqlist[k] > 0)
					free_irq(pcore->irqlist[k],
						 (void *)pcore);
				else
					polling_isr_timer_stop(pcore);

			ReleaseIO(pcore);
			vfree(pcore);
			pcore = pnext;
		}
	}
	bencprobed = 0;
	pr_info("hantroenc: module removed\n");
}

static int ReserveIO(struct hantroenc_t *pcore)
{
	u32 hwid;

	if (!request_mem_region(pcore->core_cfg.base_addr,
				pcore->core_info.regSize[CORE_VCE],
				"hx280enc")) {
		pr_info("hantroenc: failed to reserve HW regs\n");
		return -1;
	}

	pcore->hwregs = (u8 *)ioremap(pcore->core_cfg.base_addr,
				      pcore->core_info.regSize[CORE_VCE]);
	if (!pcore->hwregs) {
		pr_info("hantroenc: failed to ioremap HW regs\n");
		release_mem_region(pcore->core_cfg.base_addr,
				   pcore->core_info.regSize[CORE_VCE]);
		return -1;
	}

	/*read hwid and check validness and store it*/
	hwid = (u32)ioread32((void *)pcore->hwregs);
	pr_info("hwid=0x%08x, reg size %ld\n", hwid, pcore->core_info.regSize[CORE_VCE]);

	/* check for encoder HW ID */
	if (((((hwid >> 16) & 0xFFFF) != ((ENC_HW_ID1 >> 16) & 0xFFFF))) &&
	    ((((hwid >> 16) & 0xFFFF) != ((ENC_HW_ID2 >> 16) & 0xFFFF))) &&
	    ((((hwid >> 16) & 0xFFFF) != ((ENC_HW_ID3 >> 16) & 0xFFFF)))) {
		pr_info("hantroenc: HW not found at %llx\n",
			pcore->core_cfg.base_addr);
		ReleaseIO(pcore);
		return -1;
	}
	pcore->hw_id = hwid;

	pr_info("hantroenc: HW at base <%llx> with ID <0x%08x>\n",
		pcore->core_cfg.base_addr, hwid);

	return 0;
}

static void ReleaseIO(struct hantroenc_t *pcore)
{
	if (pcore->hwregs)
		iounmap((void *)pcore->hwregs);
	release_mem_region(pcore->core_cfg.base_addr,
			   pcore->core_info.regSize[CORE_VCE]);
}

#if KERNEL_VERSION(2, 6, 18) > LINUX_VERSION_CODE
static irqreturn_t hantroenc_isr(int irq, void *dev_id, struct pt_regs *regs)
#else
static irqreturn_t hantroenc_isr(int irq, void *dev_id)
#endif
{
	unsigned int handled = 0;
	struct hantroenc_t *dev = (struct hantroenc_t *)dev_id;
	u32 irq_status;
	unsigned long flags;
	struct slice_info *parentslice = getparentslice(dev, HANTRO_CORE_ENC);

	/* If core is not reserved by any user,
	 * but irq is received, just ignore it
	 */
	if (irq > 0)
		pr_info("hantroenc_isr:received IRQ! id %d\n", irq);
	spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
	if (!dev->is_reserved) {
		pr_info("hantroenc_isr:received IRQ but core is not reserved!\n");
		irq_status = (u32)ioread32((void *)(dev->hwregs + 0x04));
		if (irq_status & 0x01) {
			/* clear all IRQ bits. (hwId >= 0x80006100) means IRQ is
			 *cleared by writing 1
			 */
			u32 hwId = ioread32((void *)dev->hwregs);
			u32 majorId = (hwId & 0x0000FF00) >> 8;
			u32 wClr = (majorId >= 0x61) ? irq_status :
						       (irq_status & (~0x1FD));

			/* Disable HW when buffer over-flow happen
			 * HW behavior changed in over-flow
			 * in-pass, HW cleanup HWIF_ENC_E auto
			 * new version:  ask SW cleanup HWIF_ENC_E
			 * when buffer over-flow
			 */
			if (irq_status & 0x20)
				iowrite32(0, (void *)(dev->hwregs + 0x14));
			iowrite32(wClr, (void *)(dev->hwregs + 0x04));
		}
		spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);
		return IRQ_HANDLED;
	}
	spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);

	irq_status = (u32)ioread32((void *)(dev->hwregs + 0x04));
	if (irq_status & 0x01) {
		pr_info("irq_status of %d is:%x\n", dev->core_id, irq_status);
		/* clear all IRQ bits. (hwId >= 0x80006100) means
		 * IRQ is cleared by writing 1
		 */
		u32 hwId = ioread32((void *)dev->hwregs);
		u32 majorId = (hwId & 0x0000FF00) >> 8;
		u32 wClr = (majorId >= 0x61) ? irq_status :
					       (irq_status & (~0x1FD));

		if (irq_status & 0x20)
			iowrite32(0, (void *)(dev->hwregs + 0x14));
		iowrite32(wClr, (void *)(dev->hwregs + 0x04));
		spin_lock_irqsave(&parentslice->enc_owner_lock, flags);
		dev->irq_received = 1;
		dev->irq_status = irq_status & (~0x01);
		spin_unlock_irqrestore(&parentslice->enc_owner_lock, flags);

#ifdef VSI_CONFIG_PM
		//if frame_rdy IRQ is received, then HW will not be used any more.
		if (irq_status & ASIC_STATUS_FRAME_READY)
			up(&dev->core_suspend_sem);
#endif
		wake_up_interruptible_all(&parentslice->enc_wait_queue);
		handled++;
	}
	if (!handled && irq > 0)
		pr_info("IRQ received, but not hantro enc's!\n");


	return IRQ_HANDLED;
}

static void ResetAsic(struct hantroenc_t *dev)
{
#ifndef SIMICS_TEST
	int i;

	iowrite32(0, (void *)(dev->hwregs + 0x14));
	for (i = 4; i < dev->core_info.regSize[CORE_VCE]; i += 4)
		iowrite32(0, (void *)(dev->hwregs + i));
#endif
}



/*******************************************************************
 *  timer related functions
 *******************************************************************/

#define TIMER_POLLING_ISR_INTERVAL         50  // in ms

/**
 * @brief used to add a timer
 * @param void *timer_cb: timer callback, which called when timer expires
 * @param unsigned long timeout: timer's timeout time(ms)
 */
void _add_timer(struct timer_list *timer,
		void (*timer_cb)(struct timer_list *),
		unsigned long timeout)
{
	timer_setup(timer, timer_cb, 0);
	//the expires time is 1s
	timer->expires = jiffies + timeout * HZ / 1000;
	add_timer(timer);

}

/**
 *  @brief the callback of polling isr timer
 */
static void polling_isr_timer_cb(struct timer_list *timer)
{
	struct hantroenc_t *penccore;
	int i, irq;

	penccore = container_of(timer, struct hantroenc_t, polling_isr_timer);
	if (penccore->is_reserved == 1) {
		PDEBUG("trigger core[%d] irq\n", dev->subsys_id);
		hantroenc_isr(-1, penccore);
	}
	mod_timer(timer, TIMER_POLLING_ISR_INTERVAL);
}

/**
 *  @brief start the polling isr timer
 */
static void polling_isr_timer_start(struct hantroenc_t *penccore)
{
	_add_timer(&penccore->polling_isr_timer, polling_isr_timer_cb,
		TIMER_POLLING_ISR_INTERVAL);
}

/**
 *  @brief stop the polling isr timer
 */
static void polling_isr_timer_stop(struct hantroenc_t *penccore)
{
	del_timer(&penccore->polling_isr_timer);
}
