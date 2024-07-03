/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mmrse_dev_bc.c - MMR/M-SE module device driver
 *
 * Char Device part for Bus Controller
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
 * Reset BC
 *
 * @priv:	driver private struct
 * @rst:	1 - reset BC, 0 - cmd buf clean
 */
inline void mmrse_hw_bc_reset(mmrse_priv_t *priv, int rst)
{
	if (rst)
		reg32wr(BC_CONTROL_SET_SOFTRST,
			P_BC_CONTROL_REG(priv->reg_base));
	else
		reg32wr(BC_STATUS_SET_BUFCMDCLEAN,
			P_BC_STATUS_REG(priv->reg_base));
}

/**
 * Init BC
 *
 * @priv:	driver private struct
 * @mem_addr:	page address for DMA buffers
 */
inline void mmrse_hw_bc_init(mmrse_priv_t *priv, dma_addr_t mem_addr)
{
	assert((mem_addr >> 32) == 0);

	reg32wr(0
		| BC_CONTROL_SET_BUFADDR((uint32_t)mem_addr)
		| BC_CONTROL_SET_INTMODE_ALL	/* All interrupts */
		| BC_CONTROL_SET_INTMODE_ECBUF,	/* and command buff ready */
		P_BC_CONTROL_REG(priv->reg_base));
}


/**
 * Send Command Word
 *
 * @priv:	driver private struct
 * @cw:	Command Word; Mode codes in Mode Command; first CW for format 3 and 8
 * @dw:	Data Word in Mode Command with Data Word; next CW for format 3 and 8
 * @fmt:	message format: 1..10, if 0 - don't check cw & dw
 */
static inline void hw_bc_send_command(mmrse_priv_t *priv,
				      uint16_t cw, uint16_t dw, int fmt)
{
	switch (fmt) {
	case  1: /* receive data BC -> RT */
	case  7: /* receive data BC -> RT broadcast */

	case  2: /* transmit data RT -> BC */

	case  4: /* send Mode Code */
	case  9: /* send Mode Code broadcast */

	case  5: /* send Mode Code & receive DW */
		reg32wr(BC_COMMAND_SET_CW(cw),
			P_BC_COMMAND_REG(priv->reg_base));
		break;

	case  3: /* RT -> RT */
	case  8: /* RT -> RT broadcast */
		reg32wr(BC_COMMAND_SET_CW0(cw) | BC_COMMAND_SET_CW1(dw),
			P_BC_COMMAND_REG(priv->reg_base));
		break;

	case  6: /* send Mode Code & DW */
	case 10: /* send Mode Code & DW broadcast */
	default:
		reg32wr(BC_COMMAND_SET_CW(cw) | BC_COMMAND_SET_DW(dw),
			P_BC_COMMAND_REG(priv->reg_base));
		break;
	}
}

/**
 * Set Channel
 *
 * @priv:	driver private struct
 * @ch:		1 - select channel-0; 2 - channel-1
 *
 * Return current channel
 */
static inline uint32_t hw_bc_set_channel(mmrse_priv_t *priv, uint32_t ch)
{
	reg32wr(BC_STATUS_SET_CHANNEL(ch), P_BC_STATUS_REG(priv->reg_base));

	return BC_STATUS_GET_CHANNEL(reg32rd(P_BC_STATUS_REG(priv->reg_base)));
}

/**
 * Get Status Word with Data
 *
 * @priv:	driver private struct
 * @sw:		return received Status Word
 * @dw:		return received Data Word
 */
static inline void hw_bc_get_status_dat(mmrse_priv_t *priv,
					uint16_t *sw, uint16_t *dw)
{
	uint32_t val = reg32rd(P_BC_RESULT_REG(priv->reg_base));

	*dw = BC_RESULT_GET_DW(val);
	*sw = BC_RESULT_GET_SW(val);
}

/**
 * Get Status Word and result
 *
 * @priv:	driver private struct
 * @res:	return operation result:
 *	BC_STATUS_RESULT_OK	success
 *	BC_STATUS_RESULT_ECRC	crc error
 *	BC_STATUS_RESULT_ETO	timeout
 *	BC_STATUS_RESULT_ESPEC	special fiels in SW
 *	BC_STATUS_RESULT_ECMD	wrong command
 *	BC_STATUS_RESULT_ERP	pause on receive
 * @fifo_len:	return current len of command fifo
 * @sw:		return received Status Word
 *
 * Return: 1 - irq activ, 0 - no irq
 */
static inline int hw_bc_get_status(mmrse_priv_t *priv, int *res, int *fifo_len,
				   uint16_t *sw, int *sw_val)
{
	uint32_t val = reg32rd(P_BC_STATUS_REG(priv->reg_base));

	*res      = BC_STATUS_GET_RESULT(val);
	*fifo_len = BC_STATUS_GET_BUFCMDLEN(val);
	*sw       = BC_STATUS_GET_SW(val);
	*sw_val   = BC_STATUS_GET_SWVALID(val);

	return BC_STATUS_GET_INTSTAT(val);
}

/**
 * BC Interrupt acknowledge
 *
 * @priv:	driver private struct
 */
static inline void hw_bc_int_ack(mmrse_priv_t *priv)
{
	reg32wr(BC_STATUS_SET_INTACK, P_BC_STATUS_REG(priv->reg_base));
}


/**
 * Interrupt handler
 */
void mmrse_bc_irq_handler(mmrse_priv_t *priv)
{
	uint16_t bc_sw, bc_dw;
	int bc_sw_val;
	int bc_fifo_len;
	int bc_result;
	int bc_irq;
	unsigned long bc_flags;

	bc_irq = hw_bc_get_status(priv, &bc_result, &bc_fifo_len, &bc_sw,
				  &bc_sw_val);
	if (!bc_irq)
		return;

	hw_bc_get_status_dat(priv, &bc_sw, &bc_dw);

	spin_lock_irqsave(&priv->bc_lock, bc_flags);
	priv->bc_last_result = bc_result;
	priv->bc_last_sw = bc_sw;
	priv->bc_last_dw = bc_dw;
	if ((BC_STATUS_RESULT_OK == bc_result) && (!bc_sw_val)) {
		priv->bc_last_result = BC_STATUS_RESULT_NONE;
	}
	spin_unlock_irqrestore(&priv->bc_lock, bc_flags);

	/* debug printf */
	DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
		"IRQ BC %d: result = 0x%X, fifolen = %d, "
		"SW = 0x%04X (%s)\n",
		bc_irq, bc_result, bc_fifo_len,
		bc_sw, (bc_sw_val) ? "valid" : "No SW");

	/* stats */
	switch (bc_result) {
	case BC_STATUS_RESULT_OK:
		priv->stats.bc_ok++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: %s\n",
			(bc_sw_val) ? "success" : "success, No SW");
		break;
	case BC_STATUS_RESULT_ECRC:
		priv->stats.bc_ecrc++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: crc error\n");
		break;
	case BC_STATUS_RESULT_ETO:
		priv->stats.bc_eto++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: timeout\n");
		break;
	case BC_STATUS_RESULT_ESPEC:
		priv->stats.bc_spec++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: special fields in SW\n");
		break;
	case BC_STATUS_RESULT_ECMD:
		priv->stats.bc_ecmd++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: wrong command\n");
		break;
	case BC_STATUS_RESULT_ERP:
		priv->stats.bc_erp++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: pause on receive\n");
		break;
	default:
		priv->stats.bc_unk++;
		DEV_DBG(DBG_MSK_IRQ_BC, priv->dev_bc,
			"IRQ BC: unknown\n");
		break;
	}
	/* debug printf */

	wake_up_interruptible(&(priv->wq_bc_event));
	hw_bc_int_ack(priv);
} /* mmrse_bc_irq_handler */


/**
 ******************************************************************************
 * BC file operation part (Char device methods)  /dev/xmmrNc
 ******************************************************************************
 */

/**
 * mmap file operation
 * Remap BC data buffers to user
 */
static int bc_cdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	phys_addr_t mem_start;
	unsigned long offset = (vma->vm_pgoff << PAGE_SHIFT);
	unsigned long vm_start;

	if (!priv)
		return -ENODEV;

	if (offset >= 0 && offset < BC_BUFF_SIZE) {
		mem_start = virt_to_phys(priv->dma_buff);
	} else {
		return -EINVAL;
	}

	mem_start += offset;

	if (vma->vm_start + offset > vma->vm_end) {
		dev_err(priv->dev_bc,
			"mmap error: offset more than size\n");
		return -ENXIO;
	}

	vm_start = vma->vm_start;

	vma->vm_flags |= (VM_READ | VM_WRITE /*| VM_RESERVED*/); /* | VM_SHM */

	DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
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
		dev_err(priv->dev_bc,
			"mmap error: remap memory to user\n");
		return -EAGAIN;
	}

	return 0;
} /* bc_cdev_mmap */

/**
 * ioctl file operation
 * BC specific operations
 */
static long bc_cdev_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	long ret = 0;
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	void __user *uarg = (void __user *) arg;

	if (!priv)
		return -ENODEV;

	if ((_IOC_TYPE(cmd) != MMRSE_IOC_MAGIC)) {
		dev_err(priv->dev_bc,
			"ioctl error: invalid command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	}

	DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
		"CDEV_IOCTL: 0x%X(%d)\n", cmd, cmd);

	switch (cmd) {
	case MMRSE_IOCTL_BC_SEND_MESSAGE:
	{
		mmr_cmd_t cwdw; /* from and to user */
		void *buf;
		int len;
		uint16_t mode;
		int fifo_len;
		uint16_t sw;
		int bc_sw_val;
		int res;
		unsigned long flags;

		if (copy_from_user((caddr_t)&cwdw, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bc,
				"IOCTL_SEND_MESSAGE: copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}
		DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
			"IOCTL_SEND_MESSAGE: cw = 0x%04X dw = 0x%04X\n",
			cwdw.cw, cwdw.dw);

		/* parse cwdw */
		mode = ((cwdw.cw >> 5) & 0x3F);
		DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
			"IOCTL_SEND_MESSAGE: t/r + mode|saddr = 0x%02X\n",
			mode);
		if (((mode & 0x1F) != 0) &&
		    ((mode & 0x1F) != 30) &&
		    ((mode & 0x1F) != 31)) {
			buf = priv->dma_buff + (mode * 64);
			len = cwdw.cw & 0x1F;
			len = (len == 0) ? 32 : len;
			assert((buf + (sizeof(uint16_t) * len)) <=
			       (priv->dma_buff + BC_BUFF_SIZE));
			DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
				"IOCTL_SEND_MESSAGE: base=%p, buf=%p, len=%d\n",
				priv->dma_buff, buf, len);
		}

		/* send */
		hw_bc_get_status(priv, &res, &fifo_len, &sw, &bc_sw_val);
		if (fifo_len != 0) {
			priv->bc_last_result = -1;
			hw_bc_send_command(priv, cwdw.cw, cwdw.dw, 0);
		} else {
			ret = -EBUSY;
			break;
		}

		/* wait for operation complete */
		if (!wait_event_interruptible_timeout(priv->wq_bc_event,
				(-1 != priv->bc_last_result), HZ)) {
			/* timeout time was reached */
			DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
				"IOCTL_SEND_MESSAGE: timeout was reached\n");
			ret = -ETIMEDOUT;
			break;
		} else {
			spin_lock_irqsave(&priv->bc_lock, flags);
			ret = priv->bc_last_result;
			cwdw.dw = priv->bc_last_dw;
			cwdw.cw = priv->bc_last_sw;
			spin_unlock_irqrestore(&priv->bc_lock, flags);

			if ((BC_STATUS_RESULT_OK != ret) &&
			    (BC_STATUS_RESULT_NONE != ret)) {
				DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
					"IOCTL_SEND_MESSAGE: "
					"error code = %ld\n",
					ret);
			}

			if (copy_to_user(uarg, (caddr_t)&cwdw,
					 _IOC_SIZE(cmd))) {
				dev_err(priv->dev_bc,
					"IOCTL_SEND_MESSAGE: "
					"copy_to_user failure\n");
				ret = -EFAULT;
			}
			break;
		}
		break;
	}

	case MMRSE_IOCTL_BC_SET_CHANNEL:
	{
		uint32_t res, ch;

		if (copy_from_user((caddr_t)&res, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bc,
				"IOCTL_BC_SET_CHANNEL: "
				"copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}

		ch = hw_bc_set_channel(priv, res);
		DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc,
			"IOCTL_BC_SET_CHANNEL: "
			"try to set active channel %d, now %d\n",
			res, ch);
		if ((1 != ch) && (2 != ch)) {
			ret = -EBUSY;
		}

		if (copy_to_user(uarg, (caddr_t)&ch, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_bc,
				"IOCTL_BC_SET_CHANNEL: copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}

	default:
		dev_err(priv->dev_bc,
			"IOCTL ERROR: invalid command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	} /* switch( cmd ) */

	return ret;
} /* bc_cdev_ioctl */


#ifdef CONFIG_COMPAT

static long bc_compat_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	return bc_cdev_ioctl(filp, cmd, arg);
}

#endif /* CONFIG_COMPAT */


/**
 * open file operation
 * BC devices open
 */
static int bc_cdev_open(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = container_of(inode->i_cdev, mmrse_priv_t, cdev_bc);

	if (!priv)
		return -ENODEV;

	filp->private_data = priv;

	spin_lock(&priv->cdev_open_lock);
	if (1 == priv->bc_device_open) {
		spin_unlock(&priv->cdev_open_lock);
		dev_info(priv->dev_bc,
			 "BC device allready open and busy!\n");
		return -EBUSY;
	}
	priv->bc_device_open = 1;
	spin_unlock(&priv->cdev_open_lock);

	DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc, "BC_CDEV_OPEN\n");

	kobject_get(&priv->dev_bc->kobj);

	return 0;
} /* bc_cdev_open */

/**
 * close file operation
 * BC devices close
 */
static int bc_cdev_release(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;

	if (!priv)
		return -ENODEV;

	DEV_DBG(DBG_MSK_CDEV_BC, priv->dev_bc, "BC_CDEV_CLOSE\n");

	kobject_put(&priv->dev_bc->kobj);

	spin_lock(&priv->cdev_open_lock);
	priv->bc_device_open = 0;
	spin_unlock(&priv->cdev_open_lock);

	filp->private_data = NULL;

	return 0;
} /* bc_cdev_release */


/**
 * BC file operation
 */
const struct file_operations mmrse_bc_dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.mmap		= bc_cdev_mmap,
	.unlocked_ioctl = bc_cdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= bc_compat_ioctl,
#endif
	.open		= bc_cdev_open,
	.release	= bc_cdev_release,
};
