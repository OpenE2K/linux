/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mmrse_dev_bm.c - MMR/M-SE module device driver
 *
 * Char Device part for Bus Monitor
 */

#include "mmrse_main.h"
#include "mmrse_regs.h"
#include "mmrse_dbg.h"


/**
 ******************************************************************************
 * Hardware part
 ******************************************************************************
 **/

/**
 * Reset BM
 *
 * @priv:	driver private struct
 */
inline void mmrse_hw_bm_reset(mmrse_priv_t *priv)
{
	reg32wr(BM_CONTROL_SET_SOFTRST, P_BM_CONTROL_REG(priv->reg_base));
}


/** private */

/**
 * BM Interrupt enable/disable
 *
 * @priv:	driver private struct
 * @intmode:	0 - disable interrupt; BM_CONTROL_SET_INTMODE_* ored:
 *		BM_CONTROL_SET_INTMODE_DATA - log not empty
 *		BM_CONTROL_SET_INTMODE_LPAGE - last page
 */
static inline void hw_bm_en_int_l(mmrse_priv_t *priv, uint32_t intmode)
{
	uint32_t val;

	/* save log size and mode */
	val = BM_CONTROL_LOG_MASK & reg32rd(P_BM_CONTROL_REG(priv->reg_base));

	val |= BM_CONTROL_INTMODE_MASK & intmode;
	reg32wr(val, P_BM_CONTROL_REG(priv->reg_base));
}

/**
 * Init BM
 *
 * @priv:	driver private struct
 * @mem_addr:	page address for log
 * @logsize:	BM_CONTROL_LOGSIZE_??K
 * @mode:	BM_CONTROL_LOGMODE_*
 */
static inline void hw_bm_init(mmrse_priv_t *priv, dma_addr_t mem_addr,
			      uint32_t size, uint32_t mode)
{
	uint32_t val;

	assert((mem_addr >> 32) == 0);
	reg32wr(BM_SADDR_SET_LOGADDR((uint32_t)mem_addr),
		P_BM_SADDR_REG(priv->reg_base));

	/* save irq mode */
	val = BM_CONTROL_INTMODE_MASK &
		reg32rd(P_BM_CONTROL_REG(priv->reg_base));

	val |= BM_CONTROL_SET_LOGSIZE(size) | BM_CONTROL_SET_LOGMODE(mode);
	reg32wr(val, P_BM_CONTROL_REG(priv->reg_base));
}

/**
 * BM Get Read and Write Ptr registers
 *
 * @priv:	driver private struct
 * @rptr:	readed DWORD number
 * @wptr:	last+1 DWORD for read
 *
 * Return Log_Full
 */
static inline long hw_bm_get_ptrs(mmrse_priv_t *priv,
				  uint32_t *rptr, uint32_t *wptr)
{
	*rptr = BM_RPTR_GET_LOGRPTR(reg32rd(P_BM_RPTR_REG(priv->reg_base)));
	*wptr = BM_WPTR_GET_LOGWPTR(reg32rd(P_BM_WPTR_REG(priv->reg_base)));

	return BM_CONTROL_GET_ISFULL(reg32rd(P_BM_CONTROL_REG(priv->reg_base)));
}

/**
 * BM Change Read Ptr register
 *
 * @priv:	driver private struct
 * @rptr:	readed DWORD number
 */
static inline void hw_bm_set_rptr(mmrse_priv_t *priv, uint32_t rptr)
{
	reg32wr(BM_RPTR_SET_LOGRPTR(rptr), P_BM_RPTR_REG(priv->reg_base));
}

/**
 * BM Interrupt acknowledge
 *
 * @priv:	driver private struct
 */
static inline void hw_bm_int_ack(mmrse_priv_t *priv)
{
	reg32wr(BM_WPTR_SET_INTACK, P_BM_WPTR_REG(priv->reg_base));
}


/**
 * Interrupt handler
 */
void mmrse_bm_irq_handler(mmrse_priv_t *priv)
{
	unsigned long bm_flags;

	spin_lock_irqsave(&priv->bm_lock, bm_flags);
	hw_bm_en_int_l(priv, 0); /* disable BM irq */
	priv->log_item = 1;
	spin_unlock_irqrestore(&priv->bm_lock, bm_flags);

	wake_up_interruptible(&priv->wq_bm_event);
	hw_bm_int_ack(priv);

	DEV_DBG(DBG_MSK_IRQ_BM, priv->dev_bm, "IRQ BM\n");
} /* mmrse_bm_irq_handler */


/**
 ******************************************************************************
 * BM file operation part (Char device methods)  /dev/xmmrNm
 ******************************************************************************
 */

/**
 * mmap file operation
 * Remap BM log memory to user
 */
static int bm_cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	phys_addr_t mem_start;
	unsigned long offset = (vma->vm_pgoff << PAGE_SHIFT);
	unsigned long vm_start;

	if (!priv)
		return -ENODEV;

	if (offset >= 0 && offset < priv->bm_log_size) {
		mem_start = virt_to_phys(priv->dma_buff + priv->bc_buff_size);
	} else {
		return -EINVAL;
	}

	mem_start += offset;

	if (vma->vm_start + offset > vma->vm_end) {
		dev_err(priv->dev_bm,
			"MMAP ERROR: Error offset more than size\n");
		return -ENXIO;
	}

	if (vma->vm_end - vma->vm_start > priv->bm_log_size) {
		dev_err(priv->dev_bm,
			"MMAP ERROR: vma->vm_end - vma->vm_start > BUFSIZE\n");
		return -EINVAL;
	}

	vm_start = vma->vm_start;

	vma->vm_flags |= (VM_READ | VM_WRITE); /* | VM_RESERVED | VM_SHM */

	DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
		"MMAP mem: %#llx; off: %#lx; off_r: %#lx; st: %#lx; "
		"mof: %#llx; sof: %#lx; sz: %#lx\n",
		mem_start,
		vma->vm_pgoff,
		offset,
		vma->vm_start,
		mem_start + offset,
		vma->vm_start + offset,
		vma->vm_end - vma->vm_start);

	if (remap_pfn_range(vma, vm_start, (mem_start >> PAGE_SHIFT),
	    vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		dev_err(priv->dev_bm,
			"MMAP ERROR: Error remap memory to user\n");
		return -EAGAIN;
	}

	return 0;
} /* bm_cdev_mmap */

/**
 * ioctl file operation
 * BM specific operations
 */
static long bm_cdev_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	long ret = 0;
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	void __user *uarg = (void __user *) arg;

	if (!priv)
		return -ENODEV;

	if ((_IOC_TYPE(cmd) != MMRSE_IOC_MAGIC)) {
		dev_err(priv->dev_bm,
			"ioctl error: invalid command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	}

	DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
		"CDEV_IOCTL: 0x%X(%d)\n", cmd, cmd);

	switch (cmd) {

	/* BM */
	case MMRSE_IOCTL_BM_STARTSTOP:
	{
		uint64_t log_mode;
		uint64_t log_size;

		if (copy_from_user((caddr_t)&log_mode, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bm,
				"IOCTL_BM_STARTSTOP: copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}
		DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
			"IOCTL_BM_STARTSTOP: %s Monitor\n",
			(log_mode) ? "Start" : "Stop");

		priv->log_item = 0;

		switch (priv->bm_log_size / BM_LOG_PAGE_SIZE) {
		case 64:
			log_size = BM_CONTROL_LOGSIZE_256K;
			break;
		case 32:
			log_size = BM_CONTROL_LOGSIZE_128K;
			break;
		case 16:
			log_size = BM_CONTROL_LOGSIZE_64K;
			break;
		default:
			log_size = BM_CONTROL_LOGSIZE_32K;
			break;
		}
		hw_bm_init(priv, priv->dma_buff_handle + priv->bc_buff_size,
			   log_size, log_mode);

		log_mode = (uint64_t)(priv->bm_log_size);
		if (copy_to_user(uarg, (caddr_t)&log_mode, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bm,
				"IOCTL_BM_STARTSTOP: copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}

	case MMRSE_IOCTL_BM_GET_PTRS:
	{
		long bm_r;
		uint32_t rptr, wptr;
		uint64_t w_r_ptr;
		unsigned long bm_flags;

		ret = hw_bm_get_ptrs(priv, &rptr, &wptr);
		if ((!ret) && (rptr == wptr)) {
			DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
				"IOCTL_BM_GET_PTRS: wait for log items\n");

			/* Enable BM irq */
			spin_lock_irqsave(&priv->bm_lock, bm_flags);
			priv->log_item = 0;
			hw_bm_en_int_l(priv, BM_CONTROL_SET_INTMODE_DATA);
			spin_unlock_irqrestore(&priv->bm_lock, bm_flags);

			/* wait for log items */
			bm_r = wait_event_interruptible_timeout(priv->wq_bm_event,
					(0 != priv->log_item), HZ);
			if (!bm_r) {
				/* timeout time was reached */
				DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
					"IOCTL_BM_GET_PTRS: "
					"timeout was reached\n");
				ret = -ETIMEDOUT;
				break;
			}
			ret = hw_bm_get_ptrs(priv, &rptr, &wptr);
		}
		DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
			"IOCTL_BM_GET_PTRS: Wptr=0x%05X, Rptr=0x%05X  %s\n",
			wptr, rptr, (ret) ? "Log FULL" : "");

		w_r_ptr = (((uint64_t)wptr)<<32) | ((uint64_t)rptr);
		if (copy_to_user(uarg, (caddr_t)&w_r_ptr, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bm,
				"IOCTL_BM_GET_PTRS: copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}

	case MMRSE_IOCTL_BM_SET_RPTR:
	{
		uint32_t rptr;

		if (copy_from_user((caddr_t)&rptr, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bm,
				"IOCTL_BM_SET_RPTR: copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}
		DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm,
			"IOCTL_BM_SET_RPTR: Rptr=0x%05X\n", rptr);

		hw_bm_set_rptr(priv, rptr);
		break;
	}

	default:
		dev_err(priv->dev_bm, "IOCTL ERROR: invalid command 0x%X(%d)\n",
			cmd, cmd);
		return -ENOTTY;
	} /* switch( cmd ) */

	return ret;
} /* bm_cdev_ioctl */


#ifdef CONFIG_COMPAT

static long bm_compat_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	return bm_cdev_ioctl(filp, cmd, arg);
}

#endif /* CONFIG_COMPAT */


/**
 * open file operation
 * BM devices open
 */
static int bm_cdev_open(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = container_of(inode->i_cdev, mmrse_priv_t, cdev_bm);

	if (!priv)
		return -ENODEV;

	filp->private_data = priv;

	spin_lock(&priv->cdev_open_lock);
	if (1 == priv->bm_device_open) {
		spin_unlock(&priv->cdev_open_lock);
		dev_info(priv->dev_bm,
			"BM device allready open and busy!\n");
		return -EBUSY;
	}
	priv->bm_device_open = 1;
	spin_unlock(&priv->cdev_open_lock);

	DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm, "CDEV_OPEN\n");

	kobject_get(&priv->dev_bm->kobj);

	return 0;
} /* bm_cdev_open */

/**
 * close file operation
 * BM devices close
 */
static int bm_cdev_release(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;

	if (!priv)
		return -ENODEV;

	/* HW */
	mmrse_hw_bm_reset(priv);

	DEV_DBG(DBG_MSK_CDEV_BM, priv->dev_bm, "CDEV_CLOSE\n");

	kobject_put(&priv->dev_bm->kobj);

	spin_lock(&priv->cdev_open_lock);
	priv->bm_device_open = 0;
	spin_unlock(&priv->cdev_open_lock);

	filp->private_data = NULL;

	return 0;
} /* bm_cdev_release */


/**
 * BM file operation
 */
const struct file_operations mmrse_bm_dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.mmap		= bm_cdev_mmap,
	.unlocked_ioctl = bm_cdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bm_compat_ioctl,
#endif
	.open		= bm_cdev_open,
	.release	= bm_cdev_release,
};
