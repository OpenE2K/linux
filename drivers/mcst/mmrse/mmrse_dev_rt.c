/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mmrse_dev_rt.c - MMR/M-SE module device driver
 *
 * Char Device part for Remote Terminal
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
 * Get DMA Latency
 * (saved after each DMA transaction, in PCI (33MHz) clk)
 *
 * @priv:	driver private struct
 *
 * Returns last DMA latency in ns
 */
inline uint64_t mmrse_hw_get_dmalatency_ns(mmrse_priv_t *priv)
{
	uint64_t val;

	val = reg32rd(P_DMA_LATENCY_REG(priv->reg_base));
	val *= 15515;
	val >>= 9; /* ~~ * 30.3 */

	return val;
}

/**
 * Reset RT
 *
 * @priv:	driver private struct
 * @rst:	1 - reset RT, 0 - deactivate terminal
 */
inline void mmrse_hw_rt_reset(mmrse_priv_t *priv, int rst)
{
	if (rst) {
		reg32wr(RT_CONTROL_SET_SOFTRST,
			P_RT_CONTROL_REG(priv->reg_base));
		usleep_range(60, 80); /* reset delay */
	} else {
		reg32wr(RT_STATUS_SET_RTDIS, P_RT_STATUS_REG(priv->reg_base));
	}
}


/** private */

/**
 * Init RT
 *
 * @priv:	driver private struct
 * @ta:		Terminal Address
 * @flags:
 *	RT_FLAG_BC_EN	- Enable Dynamic Bus Control Accept
 *	RT_FLAG_SRVREQ	- Set Service Request Bit in Status Word
 *	RT_FLAG_BUSY	- Set Busy Bit in Status Word
 *	RT_FLAG_TERM	- Set Terminal Flag Bit in Status Word
 *	RT_FLAG_SUBSYS	- Set Subsustem Flag Bit in Status Word
 * @vw:		Vector Word
 */
static inline void hw_rt_init(mmrse_priv_t *priv, uint8_t ta,
			      uint8_t flags, uint16_t vw)
{
	reg32wr(0
		| RT_CONTROL_SET_VW(vw)
		| ((flags & RT_FLAG_BC_EN) ? RT_CONTROL_SET_BUSACPT : 0)
		| RT_CONTROL_SET_RTA(ta)
		| RT_CONTROL_SET_FF(flags)
		| RT_CONTROL_SET_INTMODE_ALL /* All interrupts */
		| RT_CONTROL_SET_INTMODE_DMA, /* and DMA finished */
		P_RT_CONTROL_REG(priv->reg_base));
}

/**
 * Get Status Word and result
 *
 * @priv:	driver private struct
 * @res:	return current Status Word attributes:
 *	RT_STATUS_SW_MSGERR - message error
 *	RT_STATUS_SW_INS - instrumentation
 *	RT_STATUS_SW_SRQ - service request
 *	RT_STATUS_SW_BDCST - broadcast rcvd
 *	RT_STATUS_SW_SUBSYSBSY - busy
 *	RT_STATUS_SW_SUBSYSFL - sub system flag
 *	RT_STATUS_SW_BUS_ACPT - dynamic bus acceptance
 *	RT_STATUS_SW_TERM - terminal flag
 *
 * Return: 0 - no irq, or irq status flags:
 *	RT_STATUS_INTSTAT_DMA - end of DMA transaction
 *	RT_STATUS_INTSTAT_CMD - command received
 *	RT_STATUS_INTSTAT_RX - data received
 *	RT_STATUS_INTSTAT_TX - data transmitted
 */
static inline uint32_t hw_rt_get_status(mmrse_priv_t *priv, uint32_t *res)
{
	uint32_t val = reg32rd(P_RT_STATUS_REG(priv->reg_base));

	*res = RT_STATUS_GET_SW(val);

	return RT_STATUS_GET_INTSTAT_ALL(val);
}

/**
 * Get current state
 *
 * @priv:	driver private struct
 * @chs:	return channels state: 1 - blocked
 *		(chs.bit0 - ch0, chs.bit1 - ch1)
 * @bitw:	return internal BIT word
 *
 * Return: 1 - Terminal Activ, 0 - disabled
 */
static inline int hw_rt_get_state(mmrse_priv_t *priv, uint8_t *chs,
				   uint16_t *bitw)
{
	uint32_t val = reg32rd(P_RT_STATUS_REG(priv->reg_base));

	*chs = RT_STATUS_GET_CHS(val);
	*bitw = RT_STATUS_GET_BITW(val);

	return RT_STATUS_GET_RTACT(val);
}

/**
 * RT Get Command (!FIFO!)
 *
 * @priv:	driver private struct
 * @cw:		return Command Word
 * @dw:		return Data Word in Mode Command with Data Word
 */
static inline void hw_rt_get_command(mmrse_priv_t *priv, uint16_t *cw,
				     uint16_t *dw)
{
	uint32_t val = reg32rd(P_RT_COMMAND_REG(priv->reg_base));
	unsigned long rt_flags;

	spin_lock_irqsave(&priv->rt_lock, rt_flags);
	priv->last_rt_command_reg = val;
	priv->last_rt_command_cnt += 1;
	if (priv->last_rt_command_cnt == 0)
		priv->last_rt_command_cnt = (uint32_t)-1;
	spin_unlock_irqrestore(&priv->rt_lock, rt_flags);

	*cw = RT_COMMAND_GET_CW(val);
	*dw = RT_COMMAND_GET_DW(val);
}

/**
 * RT request DMA transaction
 *
 * @priv:	driver private struct
 * @bufa:	buffer in memory (64 bytes align)
 * @tr:		1 - ram->device, 0 - device->ram
 * @bufn:	buf number (0..31)
 */
#if 0 /* unused */
static inline void hw_rt_req_dma(mmrse_priv_t *priv, uint32_t bufa,
				 long tr, long bufn)
{
	assert((bufa & 0x3F) == 0);

	reg32wr(RT_TASK_SET_DMAADDR(bufa) | RT_TASK_SET_BUFNUM(bufn | (tr<<5)),
		P_RT_TASK_REG(priv->reg_base));
}
#endif

/**
 * RT is DMA finished
 *
 * @priv:	driver private struct
 *
 * Return 0 if DMA finished
 */
#if 0 /* unused */
static inline long hw_rt_is_dma_end(mmrse_priv_t *priv)
{
	uint32_t val = reg32rd(P_RT_TASK_REG(priv->reg_base));

	return (long)val;
}
#endif

/**
 * Init IBuff and OBuff
 *
 * @priv:	driver private struct
 * @init: 1 - init RT, 0 - disable RT
 */
static inline void hw_rt_init_iobufs(mmrse_priv_t *priv, long init)
{
	if (init) {
		/* Clean Valid */
		reg32wr(0xFFFFFFFF, P_RT_IVALID_REG(priv->reg_base));
		/* buffer rewrite disable */
		reg32wr(0, P_RT_IMODE_REG(priv->reg_base));
		/* All interrupts */
		reg32wr(0xFFFFFFFF, P_RT_IMASK_REG(priv->reg_base));

		/* Clean */
		reg32wr(0xFFFFFFFF, P_RT_OFLAG_REG(priv->reg_base));
		/* multi send disabled */
		reg32wr(0, P_RT_OMODE_REG(priv->reg_base));
		/* All interrupts */
		reg32wr(0xFFFFFFFF, P_RT_OMASK_REG(priv->reg_base));
	} else {
		/* Interrupts disable */
		reg32wr(0, P_RT_IMASK_REG(priv->reg_base));
		/* Clean Valid */
		reg32wr(0xFFFFFFFF, P_RT_IVALID_REG(priv->reg_base));
		/* buffer rewrite disable */
		reg32wr(0, P_RT_IMODE_REG(priv->reg_base));

		/* Interrupts disable */
		reg32wr(0, P_RT_OMASK_REG(priv->reg_base));
		/* Clean */
		reg32wr(0xFFFFFFFF, P_RT_OFLAG_REG(priv->reg_base));
		/* multi send disabled */
		reg32wr(0, P_RT_OMODE_REG(priv->reg_base));
	}
}

/**
 * Set IBuf
 * Set rewrite enable/disable and clear IValid flag
 *
 * @priv:	driver private struct
 * @mode:	bitfield: 1 - rewrite enable
 * @mask:	bitfield (31..0 buffers)
 */
static inline void hw_rt_set_ibuf(mmrse_priv_t *priv,
				  uint32_t mode, uint32_t mask)
{
	uint32_t val = reg32rd(P_RT_IMODE_REG(priv->reg_base)) & (~mask);

	reg32wr(val | (mode & mask), P_RT_IMODE_REG(priv->reg_base));
	reg32wr(mask, P_RT_IVALID_REG(priv->reg_base));
}

/**
 * Clear IBuf
 * Clear IValid flag
 *
 * @priv:	driver private struct
 * @mask:	bitfield (31..0 buffers)
 */
static inline void hw_rt_clr_ibuf(mmrse_priv_t *priv, uint32_t mask)
{
	reg32wr(mask, P_RT_IVALID_REG(priv->reg_base));
}

/**
 * Get IBuf
 * Get buffer valid and rewrite flags
 *
 * @priv:	driver private struct
 * @valid:	bitfield: 1 - new data in buffer
 * @rewrite:	bitfield: 1 - dat updated (prev. data lost)
 */
static inline void hw_rt_get_ibuf(mmrse_priv_t *priv, uint32_t *valid,
				  uint32_t *rewrite)
{
	*valid = reg32rd(P_RT_IVALID_REG(priv->reg_base));
	*rewrite = reg32rd(P_RT_IFLAG_REG(priv->reg_base));
}

/**
 * Set OBuf
 *
 * @priv:	driver private struct
 * @valid:	bitfield: 1 - enable buffer, 0 - disable
 * @mode:	bitfield: 1 - multi read enable
 * @mask:	bitfield (31..0 buffers)
 */
static inline void hw_rt_set_obuf(mmrse_priv_t *priv, uint32_t valid,
				  uint32_t mode, uint32_t mask)
{
	uint32_t val = reg32rd(P_RT_OMODE_REG(priv->reg_base)) & (~mask);

	reg32wr(val | (mode & mask), P_RT_OMODE_REG(priv->reg_base));

	reg32wr(valid & mask, P_RT_OFLAG_REG(priv->reg_base)); /* clean */
	reg32wr(valid & mask, P_RT_OVALID_REG(priv->reg_base)); /* enable */
}

/**
 * Get OBuf
 *
 * @priv:	driver private struct
 * @valid:	bitfield: 1 - valid data in buffer
 * @request:	bitfield: 1 - invalid buffer requested by BC
 */
static inline void hw_rt_get_obuf(mmrse_priv_t *priv, uint32_t *valid,
				  uint32_t *request)
{
	*valid = reg32rd(P_RT_OVALID_REG(priv->reg_base));
	*request = reg32rd(P_RT_OFLAG_REG(priv->reg_base));
}

/**
 * RT Interrupt acknowledge
 *
 * @priv:	driver private struct
 * @ack:	interrupt acknowledge flags returned by hw_rt_get_status()
 */
static inline void hw_rt_int_ack(mmrse_priv_t *priv, long ack)
{
	reg32wr(RT_STATUS_SET_INTACK(ack), P_RT_STATUS_REG(priv->reg_base));
}


/**
 * Interrupt handler
 */
void mmrse_rt_irq_handler(mmrse_priv_t *priv)
{
	uint32_t rt_result;
	uint32_t rt_irq;
	uint16_t cw, dw;
	uint64_t dma_lat;

	rt_irq = hw_rt_get_status(priv, &rt_result);
	if (rt_irq) {
		if (rt_irq & RT_STATUS_INTSTAT_DMA) {
			priv->stats.rt_dma++;
			dma_lat = mmrse_hw_get_dmalatency_ns(priv);
			DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
				"IRQ RT DMA: result = 0x%02X, dma_lat=%lld\n",
				rt_result, dma_lat);
		}
		if (rt_irq & RT_STATUS_INTSTAT_CMD) {
			priv->stats.rt_cmd++;
			hw_rt_get_command(priv, &cw, &dw);
			DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
				"IRQ RT CMD: result = 0x%02X, "
				"cw=0x%04X, dw=0x%04X\n",
				rt_result, cw, dw);
		}
		if (rt_irq & RT_STATUS_INTSTAT_RX) {
			priv->stats.rt_rx++;
			DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
				"IRQ RT RX: result = 0x%02X\n", rt_result);
		}
		if (rt_irq & RT_STATUS_INTSTAT_TX) {
			priv->stats.rt_tx++;
			DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
				"IRQ RT TX: result = 0x%02X\n", rt_result);
		}

		/* CMD | RX | TX */
		if ((rt_irq & RT_STATUS_INTSTAT_DMA) != 0) {
			if (rt_result & RT_STATUS_SW_MSGERR) {
				priv->stats.rt_msgerr++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = message error\n");
			}
			if (rt_result & RT_STATUS_SW_INS) {
				priv->stats.rt_instr++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = instrumentation\n");
			}
			if (rt_result & RT_STATUS_SW_SRQ) {
				priv->stats.rt_srq++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = service request\n");
			}
			if (rt_result & RT_STATUS_SW_BDCST) {
				priv->stats.rt_bdcst++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = broadcast rcvd\n");
			}
			if (rt_result & RT_STATUS_SW_SUBSYSBSY) {
				priv->stats.rt_busy++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = busy\n");
			}
			if (rt_result & RT_STATUS_SW_SUBSYSFL) {
				priv->stats.rt_subsys++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = sub system flag\n");
			}
			if (rt_result & RT_STATUS_SW_BUS_ACPT) {
				priv->stats.rt_busacpt++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = "
					"dynamic bus acceptance\n");
			}
			if (rt_result & RT_STATUS_SW_TERM) {
				priv->stats.rt_term++;
				DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
					"IRQ RT: status = terminal flag\n");
			}
		}
		wake_up_interruptible(&priv->wq_rt_event);
		hw_rt_int_ack(priv, rt_irq);
	} else {
		DEV_DBG(DBG_MSK_IRQ_RT, priv->dev_rt,
			"IRQ RT -no-: result = 0x%02X\n", rt_result);
	}
} /* mmrse_rt_irq_handler */


/**
 ******************************************************************************
 * RT file operation part (Char device methods)  /dev/xmmrNt
 ******************************************************************************
 */

/**
 * llseek file operation
 * Set offset to read and write RT data buffers
 */
static loff_t rt_cdev_llseek(struct file *filp, loff_t off, int whence)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	loff_t newpos;

	if (!priv)
		return -ENODEV;

	switch (whence) {
	case SEEK_SET:
		newpos = off;
		break;
	case SEEK_CUR:
		newpos = filp->f_pos + off;
		break;
	case SEEK_END:
		newpos = GET_RT_BUFFS_SIZE + off;
		break;
	default:
		return -EINVAL;
	}

	/* chk newpos in 0..GET_RT_BUFFS_SIZE and align 32*2 bytes */
	if ((newpos < 0) || (newpos > GET_RT_BUFFS_SIZE)) {
		dev_err(priv->dev_rt,
			"LLSEEK ERROR: wrong offset: %lld(0x%llX)\n",
			newpos, newpos);
		return -EINVAL;
	}
	if (newpos & 0x3F) {
		dev_err(priv->dev_rt,
			"LLSEEK ERROR: wrong offset: %lld(0x%llX)\n",
			newpos, newpos);
		return -EINVAL;
	}

	filp->f_pos = newpos;
	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
		"LLSEEK: new offset = %lld(0x%llX) / bufnum %d\n",
		newpos, newpos, (int)GET_RT_BUF_NUM(newpos));

	return newpos;
} /* rt_cdev_llseek */

/**
 * poll file operation
 * Used for RT buffers only.
 *
 * Returns:
 *   -ENODEV
 *   POLLIN | POLLRDNORM - if new data available
 *   POLLOUT | POLLWRNORM - if all data sended
 *   0
 */
static unsigned int rt_cdev_poll(struct file *filp, poll_table *wait)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	uint32_t valid;
	uint32_t rewrite;
	uint32_t request;
	unsigned int mask = 0;

	if (!priv)
		return -ENODEV;

	poll_wait(filp, &priv->wq_rt_event, wait);

	hw_rt_get_ibuf(priv, &valid, &rewrite);
	if (valid)
		mask |= POLLIN | POLLRDNORM; /* readable */

	hw_rt_get_obuf(priv, &valid, &request);
	if (!valid)
		mask |= POLLOUT | POLLWRNORM; /* writable */

	return mask;
} /* rt_cdev_poll */


/**
 * read file operation
 * Read RT data buffers
 *
 * Returns:
 *   -ENODEV
 *   -EAGAIN - no data (if O_NONBLOCK)
 *   -EFAULT - copy_from/to_user failure
 *   -EFBIG - prev data lost (current data readed)
 *   0 - no data
 *   >0 - bytes readed
 */
static ssize_t rt_cdev_read(struct file *filp, char *buf, size_t count,
			    loff_t *ppos)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	size_t len;
	int bn;
	uint32_t valid;
	uint32_t rewrite;
	int i;
	uint16_t dat[GET_RT_BUF_SIZE / 2];

	if (!priv)
		return -ENODEV;

	/* check for newdata */
	bn = GET_RT_BUF_NUM(filp->f_pos);
	bn = (bn < 32) ? 0 : bn - 32;
	do {
		hw_rt_get_ibuf(priv, &valid, &rewrite);
		valid = (valid>>bn) & 1; /* new data */

		if (!valid) {
			DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
				"READ: no valid data on buf %d\n", bn);

			if (filp->f_flags & O_NONBLOCK)
				return -EAGAIN;

			return -EBUSY;
			/* FUTURE: event? */
		}
	} while (!valid);

	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
		"READ: bn=%d valid=0x%X rewrite=0x%X\n", bn, valid, rewrite);

	len = GET_RT_BUF_SIZE;
	len = (count < len) ? count : len;
	/* get real data len? */

	for (i = 0; i < GET_RT_BUF_SIZE >> 2; i++) {
		uint32_t dl = buf32rd(priv->buf_base + filp->f_pos + (i << 2));
		dat[i * 2] = dl & 0xFFFF;
		dat[i * 2 + 1] = dl >> 16;
	}
	if (copy_to_user(buf, dat, len)) {
		dev_err(priv->dev_rt,
			"READ ERROR: copy_to_user failure\n");
		return -EFAULT;
	}
	hw_rt_clr_ibuf(priv, (uint32_t)(1<<bn));

	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
		"READ: readed %zd bytes from subaddress %d\n", len, bn);

	/* *ppos = len; */

	if ((rewrite>>bn) & 1)
		return -EFBIG;	/* prev data lost */

	return len;
} /* rt_cdev_read */

/**
 * write file operation
 * Write RT data buffers
 */
static ssize_t rt_cdev_write(struct file *filp, const char *buf, size_t count,
			     loff_t *ppos)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	size_t len;
	int bn;
	uint32_t valid;
	uint32_t request;
	int i;
	uint16_t dat[GET_RT_BUF_SIZE / 2];

	if (!priv)
		return -ENODEV;

	/* check for empty subaddress */
	bn = GET_RT_BUF_NUM(filp->f_pos);
	hw_rt_get_obuf(priv, &valid, &request);

	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
		 "WRITE: bn=%d valid=0x%X request=0x%X\n", bn, valid, request);

	valid = (valid >> bn) & 1; /* data present */
	/*
	if (valid) {
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;

		return -EBUSY;
	}*/

	/* max to write */
	len = GET_RT_BUF_SIZE;
	len = (count < len) ? count : len;

	if (copy_from_user(dat, (void *)buf, len)) {
		dev_err(priv->dev_rt,
			"WRITE ERROR: copy_from_user failure\n");

		return -EFAULT;
	}
	for (i = 0; i < GET_RT_BUF_SIZE >> 2; i++) {
		uint32_t dl = ((uint32_t)(dat[i * 2 + 1]) << 16) | dat[i * 2];
		buf32wr(dl, priv->buf_base + filp->f_pos + (i << 2));
	}

	/* set obuf */
	hw_rt_set_obuf(priv, 1 << bn, 1 << bn, 0xFFFFFFFF);

	/* *ppos = len; */

	return len;
} /* rt_cdev_write */

/**
 * ioctl file operation
 * RT specific operations
 */
static long rt_cdev_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;
	long ret = 0;
	void __user *uarg = (void __user *) arg;

	if (!priv)
		return -ENODEV;

	if ((_IOC_TYPE(cmd) != MMRSE_IOC_MAGIC)) {
		dev_err(priv->dev_rt,
			"IOCTL ERROR: invalid command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	}

	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
		"CDEV_IOCTL: 0x%X(%d)\n", cmd, cmd);


	switch (cmd) {

	/* RT */
	case MMRSE_IOCTL_RT_INIT:
	{
		mmr_rt_init_t rt_init;
		uint8_t chs;
		uint16_t bitw;
		int res;

		if (copy_from_user((caddr_t)&rt_init, uarg, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_rt,
				"IOCTL_RT_INIT: copy_from_user failure\n");
			ret = -EFAULT;
			break;
		}

		if (rt_init.set | RT_INIT_TFV) {
			DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
				"IOCTL_RT_INIT: ta = %d, flags = 0x%02X, "
				"vw = %d(0x%04X)\n",
				rt_init.ta, rt_init.flags,
				rt_init.vw, rt_init.vw);
			hw_rt_init(priv, rt_init.ta, rt_init.flags, rt_init.vw);
		}
		if (rt_init.set | RT_INIT_IMODE) {
			DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
				"IOCTL_RT_INIT: IMode = 0x%08X\n",
				rt_init.imode);
			/* Enable buffers rewrite bitfield */
			hw_rt_set_ibuf(priv, rt_init.imode, 0xFFFFFFFF);
		}
		if (rt_init.set | RT_INIT_OMODE) {
			DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
				"IOCTL_RT_INIT: OMode = 0x%08X\n",
				rt_init.omode);
			/* Enable multi send bitfield */
			hw_rt_set_obuf(priv, rt_init.omode,
				       rt_init.omode, 0xFFFFFFFF);
		}

		/* read Terminal_Active status & return status */
		res = hw_rt_get_state(priv, &chs, &bitw);
		DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt,
			"IOCTL_RT_INIT: Activ = %d, CHsDis = 0x%1X, "
			"BITw = %d(0x%04X)\n",
			res, chs, bitw, bitw);
		if (!res) {
			ret = -EBUSY;
		}
		break;
	}
	case MMRSE_IOCTL_RT_GET_LAST_CMD:
	{
		mmr_rt_last_cmd_t last_cmd;
		unsigned long flags;

		spin_lock_irqsave(&priv->rt_lock, flags);
		last_cmd.cw = priv->last_rt_command_reg & 0xFFFF;
		last_cmd.dw = priv->last_rt_command_reg >> 16;
		last_cmd.cnt = priv->last_rt_command_cnt;
		priv->last_rt_command_cnt = 0;
		spin_unlock_irqrestore(&priv->rt_lock, flags);

		if (copy_to_user(uarg, (caddr_t)&last_cmd, _IOC_SIZE(cmd))) {
			dev_err(priv->dev_rt,
				"IOCTL_RT_GET_LAST_CMD: "
				"copy_to_user failure\n");
			ret = -EFAULT;
		}
		break;
	}
	default:
		dev_err(priv->dev_rt,
			"IOCTL ERROR: invalid command 0x%X(%d)\n", cmd, cmd);
		return -ENOTTY;
	} /* switch( cmd ) */

	return ret;
} /* rt_cdev_ioctl */


#ifdef CONFIG_COMPAT

static long rt_compat_ioctl(struct file *filp, unsigned int cmd,
			    unsigned long arg)
{
	return rt_cdev_ioctl(filp, cmd, arg);
}

#endif /* CONFIG_COMPAT */


/**
 * open file operation
 * RT devices open
 */
static int rt_cdev_open(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = container_of(inode->i_cdev, mmrse_priv_t, cdev_rt);

	if (!priv)
		return -ENODEV;

	filp->private_data = priv;

	spin_lock(&priv->cdev_open_lock);
	if (1 == priv->rt_device_open) {
		spin_unlock(&priv->cdev_open_lock);
		dev_info(priv->dev_bc,
			 "RT device allready open and busy!\n");
		return -EBUSY;
	}
	priv->rt_device_open = 1;
	spin_unlock(&priv->cdev_open_lock);

	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt, "RT_CDEV_OPEN\n");

	kobject_get(&priv->dev_rt->kobj);

	hw_rt_init_iobufs(priv, 1); /* Enable */

	return 0;
} /* rt_cdev_open */

/**
 * close file operation
 * RT devices close
 */
static int rt_cdev_release(struct inode *inode, struct file *filp)
{
	mmrse_priv_t *priv = (mmrse_priv_t *)filp->private_data;

	if (!priv)
		return -ENODEV;

	hw_rt_init_iobufs(priv, 0); /* Disable */

	DEV_DBG(DBG_MSK_CDEV_RT, priv->dev_rt, "CDEV_CLOSE\n");

	kobject_put(&priv->dev_rt->kobj);

	spin_lock(&priv->cdev_open_lock);
	priv->rt_device_open = 0;
	spin_unlock(&priv->cdev_open_lock);

	filp->private_data = NULL;

	return 0;
} /* rt_cdev_release */

/**
 * RT file operation
 */
const struct file_operations mmrse_rt_dev_fops = {
	.owner		= THIS_MODULE,
	.llseek		= rt_cdev_llseek,
	.read		= rt_cdev_read,
	.write		= rt_cdev_write,
	.poll		= rt_cdev_poll,
	.unlocked_ioctl = rt_cdev_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= rt_compat_ioctl,
#endif
	.open		= rt_cdev_open,
	.release	= rt_cdev_release,
};
