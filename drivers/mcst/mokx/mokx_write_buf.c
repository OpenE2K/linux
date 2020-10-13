#define CLEAR_PD 	pd->dsf = 0; 	\
			pd->int_ac = 0; \
			pd->stat = 0;	\
			pd->msg = 0;

#define WRITE_BUF_DBG 0
#define WRITE_BUF_DEBUG_MSG(x...)\
		if (WRITE_BUF_DBG) DEBUG_MSG(x)
#define WR_DBG WRITE_BUF_DEBUG_MSG
#define	repeate_WRITE 10

int write_buf(int link, rdma_ioc_parm_t *parm, unsigned int f_flags)
{
	rdma_state_link_t *rdma_link;
	rdma_pool_buf_t *w_pool_buf;
	dev_rdma_sem_t *dev_sem;
	struct stat_rdma *pst;
	rdma_buf_t *w_buf; 
	rw_state_p pd;
	size_t size;
	unsigned long flags;
	signed long io_timeout = 0;
	unsigned int sending_msg;
	int ret_time_dwait = 0;
	int num;
	int ret_smsg;
	int ret = 0;
	
	num = parm->acclen;
	size = parm->reqlen;
	rdma_link = &rdma_state->rdma_link[link];
	w_pool_buf = &rdma_link->write_pool;
	w_buf = &w_pool_buf->buf[num];		
	pd = &rdma_link->rw_states_d[WRITER];
	pst = &rdma_link->stat_rdma;
	dev_sem = &pd->dev_rdma_sem;
	dev_sem->time_broadcast = 0;
	WR_DBG("%s: link: %d num buf: %d size: 0x%016lx\n", __FUNCTION__, link, 
	       num, size);
	event_write(link, WRITE_1_EVENT, size, dev_sem->num_obmen);
	raw_spin_lock_irqsave(&dev_sem->lock, flags);
	pd->int_ac = 0;
	/*
	 * Receive's buffer busy
	 */
	if ((!pd->trwd_was) && ( f_flags & O_NONBLOCK )) {
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		parm->err_no = RDMA_E_NULL_BUFFER;
		event_write(link, WRITE_0_EVENT, 0, dev_sem->num_obmen);
		return -EAGAIN;
	}
	if (!pd->trwd_was) {
		/*
		 * Set timeout
		 */
		if (dev_sem->timeout == 0) {
			io_timeout = IO_TIMEOUT;
		} else	{
			io_timeout = dev_sem->timeout * HZ;
		}
		/*
		 * Waiting for the release receive buffer. 
		 * Wake up by MSG_READY_DMA.
		 */
		pd->int_ac = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, io_timeout, link);
		if (dev_sem->irq_count_rdma != 1) {
			ERROR_MSG("%s: link: %d MSG wait_1 bad irq "
					"dev_sem->irq_count_rdma: 0x%08x\n", 
     					__FUNCTION__, link, dev_sem->irq_count_rdma);
			dev_sem->irq_count_rdma = 0;
			if (ev_pr)
				get_event_rdma(1);
		} else {
			dev_sem->irq_count_rdma = 0;
		}
		if (ret_time_dwait < 0) {
			CLEAR_PD
			raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
			WR_DBG("%s: link: %d ret_time_dwait: %d\n", __FUNCTION__, 
			       link, ret_time_dwait);
			event_write(link, WRITE_BAD1_EVENT, 
				    -ret_time_dwait, dev_sem->num_obmen);
			switch (ret_time_dwait) {
			case -1:
				ERROR_MSG("%s: link: %d MSG RDMA_E_WRITE_TIMEOUT num_obmen: 0x%08x\n", 
					  __FUNCTION__, link, dev_sem->num_obmen);
				parm->err_no = RDMA_E_WRITE_TIMEOUT;
				ret = -ETIME;
				read_regs_rdma(link);
				break;
			case -2:
				ERROR_MSG("%s: link: %d MSG RDMA_E_SIGNAL num_obmen: 0x%08x\n", 
					  __FUNCTION__, link, dev_sem->num_obmen);
				parm->err_no = RDMA_E_SIGNAL;
				ret = -EINTR;
				break;
			default:
				ERROR_MSG("%s: link: %d MSG RDMA_E_SPIN num_obmen: 0x%08x\n", 
					  __FUNCTION__, link, dev_sem->num_obmen);
				parm->err_no = RDMA_E_SPIN;
				ret = -EAGAIN;
			}
			if (ev_pr)
				get_event_rdma(1);
			goto exit_err_wr_buf;
		}
	}
	/*
	 * Programming dma (enable send TRWD)
	 */
	if (size > w_buf->size) {
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		ERROR_MSG("%s: link: %d RDMA_E_SIZE size(0x%016lx) > w_buf->size(0x%016lx)\n",
			  __FUNCTION__, link, size, w_buf->size);
		parm->err_no = RDMA_E_SIZE;
		ret = -EMSGSIZE;
		goto exit_err_wr_buf;
	}
	if (size > SMALL_CHANGE) {
		pd->size_trans = (w_pool_buf->tm_mode ? 
			ALIGN(size, (rdma_link->align_buf_tm * PAGE_SIZE)) : allign_dma(size));
	} else {
		pd->size_trans = allign_dma(size);
	}
	WR_DBG("%s: link: %d : pd->size_trans: 0x%08x\n", __FUNCTION__, link, 
	       pd->size_trans);
	/*
	 * Create TRWD
	 */
	sending_msg = MSG_TRWD | size;
	/*
	 * Send TRWD. Подумать когда отправлено, но READY не получено 
	 */
	pd->int_ac = 2;
	if ((ret_smsg = send_msg_check(sending_msg, link, 0, dev_sem, 0)) > 0) {
		event_write(link, WRITE_SNDNGMSG_EVENT, ret_smsg, dev_sem->num_obmen);
		goto wait_env;
	}
	event_write(link, WRITE_SNDMSGBAD_EVENT, ret_smsg, dev_sem->num_obmen);
	//raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
	if (ret_smsg < 0) {
		pd->trwd_was = 0;
		CLEAR_PD
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		ERROR_MSG("%s: link: %d RDMA_E_MSF_WRD error send TRWD: %d\n", 
			  __FUNCTION__, link, ret_smsg);
		parm->err_no = RDMA_E_MSF_WRD;
		ret = -EIO;
		if (ev_pr)
			get_event_rdma(1);
		goto exit_err_wr_buf;
	}
	if (ret_smsg == 0) {
		CLEAR_PD
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		ERROR_MSG("%s: link: %d RDMA_E_TIMER_MAX error send TRWD: %d\n", 
			  __FUNCTION__, link,  ret_smsg);
		parm->err_no = RDMA_E_TIMER_MAX;
		parm->acclen = count_read_sm_max;
		ret = -EIO;
		if (ev_pr)
			get_event_rdma(1);
		goto exit_err_wr_buf;
	}
wait_env:
	dev_sem->num_obmen++;
	pst->send_trwd++;
	
	/*
	 * Wait end dma. Wake up TDC. Таймаут порядка ~2 секунд. Т.к. TRWD 
	 * отправляется только при наличии свободного буфера на приемной 
	 * стороне и обмен проходит без перехода в пользовательский контекст,
	 * то время пробуждения не должно превышать суммы времен двух 
	 * прерываний, времени передачи двух сообщений и времени на передачу 
	 * данных.
	 */
	int timeout_wait_write_dma;
	//timeout_wait_write_dma = TIME_OUT_WAIT_WR + (pd->size_trans >> SHIFT_TO);
	timeout_wait_write_dma = TIME_OUT_WAIT_WR_SEC * HZ;
	ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, (signed long)timeout_wait_write_dma, 
					       link);
	if (dev_sem->irq_count_rdma != 1) {
		ERROR_MSG("%s: link: %d MSG wait_2 bad irq "
			  "dev_sem->irq_count_rdma: 0x%08x\n",
			  __FUNCTION__, link, dev_sem->irq_count_rdma);
		dev_sem->irq_count_rdma = 0;
		if (ev_pr)
			get_event_rdma(1);
	} else {
		dev_sem->irq_count_rdma = 0;
	}
	if (ret_time_dwait < 0) {
		pd->trwd_was = 0; 
		CLEAR_PD
		raw_spin_unlock_irqrestore(&dev_sem->lock, flags);
		event_write(link, WRITE_BAD2_EVENT, -ret_time_dwait,
			    dev_sem->num_obmen);
		switch (ret_time_dwait) {
		case -1:
			ERROR_MSG("%s: link: %d DMA RDMA_E_TIMER_IO num_obmen: 0x%08x\n", 
				  __FUNCTION__, link, dev_sem->num_obmen);
			parm->err_no = RDMA_E_TIMER_IO;
			ret = -ETIME;
			break;
		case -2:
			ERROR_MSG("%s: link: %d DMA RDMA_E_SIGNAL num_obmen: 0x%08x\n", 
				  __FUNCTION__, link, dev_sem->num_obmen);
			parm->err_no = RDMA_E_SIGNAL;
			ret = -EINTR;
			break;
		default:
			ERROR_MSG("%s: link: %d DMA RDMA_E_SPIN num_obmen: 0x%08x\n", 
				  __FUNCTION__, link, dev_sem->num_obmen);
			parm->err_no = RDMA_E_SPIN;
			ret = -EAGAIN;
		}
		if (ev_pr)
			get_event_rdma(1);
		goto exit_err_wr_buf;
	}
	CLEAR_PD
	raw_spin_unlock_irqrestore(&dev_sem->lock, flags);

	WR_DBG("%s: link: %d size: 0x%016lx tdc OK\n", __FUNCTION__, link, size);
	parm->err_no = RDMA_E_SUCCESS;
	ret = size;
exit_err_wr_buf:
	event_write(link, WRITE_0_EVENT, ret, dev_sem->num_obmen);
	//get_event_rdma(1);
	return ret;
}

