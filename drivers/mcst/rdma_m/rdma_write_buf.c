#define CLEAR_PD 	pd->dsf = 0; 	\
			pd->int_ac = 0; \
			pd->stat = 0;	\
			pd->msg = 0;


#ifdef LOOP_MODE	
int prog_loop_dma(int link, size_t size, rdma_ioc_parm_t *parm)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	rdma_addr_struct_t p_xxb, p_xxb_pa;
	dev_rdma_sem_t *dev_sem_rd, *dev_sem_wr;
	rw_state_p pd_rd = NULL, pd_wr = NULL;
	rdma_pool_buf_t *r_pool_buf;
	rdma_pool_buf_t *w_pool_buf;
	rdma_buf_t *r_buf;
	rdma_buf_t *w_buf;
	unsigned long flags_rd, flags_r, flags_wr, flags_w;
	unsigned int tcs_tmp;

	/*
	 * Reader
	 */
	r_pool_buf = &rdma_link->read_pool;
	pd_rd = &rdma_link->rw_states_d[READER];
	p_xxb.addr = (unsigned long)pd_rd;
	dev_sem_rd = &pd_rd->dev_rdma_sem;
	dev_sem_rd->num_obmen++;
	raw_spin_lock_irqsave(&dev_sem_rd->lock, flags_rd);
	if (!pd_rd->state_open_close) {
		if (!pd_rd->first_open) {
			raw_spin_unlock_irqrestore(&dev_sem_rd->lock, flags_rd);
			parm->err_no = RDMA_E_READ_LOOP_NO_OPEN;
			return -EBADF;
		}
	}
	raw_spin_lock_irqsave(&pd_rd->lock_rd, flags_r);
	/*
	 * Search free for read buffer
	 */
	if (list_empty(&r_pool_buf->free_list)) {
		raw_spin_unlock_irqrestore(&pd_rd->lock_rd, flags_r);
		raw_spin_unlock_irqrestore(&dev_sem_rd->lock, flags_rd);
		/*
		 * Not free buf
		 */
		event_loop(link, INTR_TRWD_UNXP_EVENT,
			   r_pool_buf->num_free_buf,
      			   dev_sem_rd->num_obmen);
		parm->err_no = RDMA_E_READ_LOOP_NO_FREE_BUFF;
		return -EFAULT;
	}
	r_buf = list_entry(r_pool_buf->free_list.next,
			   rdma_buf_t, list);
	/*
	 * If file READ close
	 */
	if (!pd_rd->state_open_close) {
		goto r_empty_dma;
	}
	/*
	 * Buf as ready
	 */
	list_move_tail(&r_buf->list, &r_pool_buf->ready_list);
	r_pool_buf->num_free_buf--;
r_empty_dma:
	r_pool_buf->work_buf = r_buf;
	raw_spin_unlock_irqrestore(&pd_rd->lock_rd, flags_r);
	raw_spin_unlock_irqrestore(&dev_sem_rd->lock, flags_rd);
	/*
	 * Programming dma reciver
	 */
	/*size = msg & MSG_USER;*/
	r_buf->real_size = size;
	/*
	 * Check on bad size
	 */
	if (size > r_buf->size) {
		event_loop(link, READ_BADSIZE_EVENT, size,
			   dev_sem_rd->num_obmen);
		event_loop(link, READ_BADSIZE_EVENT, r_buf->size,
			   dev_sem_rd->num_obmen);
		parm->err_no = RDMA_E_READ_LOOP_BAD_SIZE;
		return EMSGSIZE;
	}
	pd_rd->size_trans = (r_pool_buf->tm_mode ? PAGE_ALIGN(size) :
			  (rfsm ? r_buf->size : allign_dma(size)));
	p_xxb_pa.addr = (unsigned long)r_buf->dma_addr;
	if (!HAS_MACHINE_L_SIC) {
		WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_Rx_Rst );
	}
	WRR_rdma(SHIFT_DMA_RSA, link, p_xxb_pa.fields.laddr);
	WRR_rdma(SHIFT_DMA_RBC, link, pd_rd->size_trans);
	if (HAS_MACHINE_L_SIC) {
		WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 );
		WRR_rdma(SHIFT_DMA_HRSA, link, p_xxb_pa.fields.haddr);
		tcs_tmp = RDR_rdma(SHIFT_DMA_TCS, link);
		if (((tcs_tmp & RCode_64) != RCode_64) ||
		     ((tcs_tmp & DMA_TCS_DRCL) != DMA_TCS_DRCL)) {
			WRR_rdma(SHIFT_DMA_TCS, link, tcs_tmp | RCode_64 |
				 DMA_TCS_DRCL);
		}
		WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 | DMA_RCS_RE |
			 (r_pool_buf->tm_mode ? DMA_RCS_RTM : 0) |
			 (r_pool_buf->tm_mode ? 0 : DMA_RCS_RFSM));
	} else {
		WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_RCO | DMA_RCS_RE |
			 (r_pool_buf->tm_mode ? DMA_RCS_RTM : 0) |
			 (r_pool_buf->tm_mode ? 0 : DMA_RCS_RFSM));
	}
	/*
	 * Writer
	 */
	w_pool_buf = &rdma_link->write_pool;
	w_buf = w_pool_buf->work_buf;
	pd_wr = &rdma_link->rw_states_d[WRITER];
	p_xxb.addr = (unsigned long)pd_wr;
	dev_sem_wr = &pd_wr->dev_rdma_sem;
	raw_spin_lock_irqsave(&dev_sem_wr->lock, flags_wr);
	/*
	 * If file WRITE close
	 */
	if (!pd_wr->state_open_close) {
		goto t_empty_dma;
	}
	raw_spin_lock_irqsave(&pd_wr->lock_wr, flags_w);
	if (list_empty(&w_pool_buf->busy_list) || (!w_pool_buf->num_free_buf)) {
		/*
		 * Not ready buf
		 */
		raw_spin_unlock_irqrestore(&pd_wr->lock_wr, flags_w);
		raw_spin_unlock_irqrestore(&dev_sem_wr->lock, flags_wr);
		event_loop(link, INTR_MSG_READY_UNXP_EVENT, 
			   w_pool_buf->num_free_buf, dev_sem_wr->num_obmen);
		if (ev_pr)
			get_event_rdma(0);
		parm->err_no = RDMA_E_WRITE_LOOP_NO_READY_BUF;
		return -EFAULT;
	}
	raw_spin_unlock_irqrestore(&pd_wr->lock_wr, flags_w);
t_empty_dma:
	/*
	 * Programming dma transmiter
	 */
	pd_wr->trwd_was --;
	raw_spin_unlock_irqrestore(&dev_sem_wr->lock, flags_wr);
	p_xxb_pa.addr = (unsigned long)w_buf->dma_addr;
	if (!HAS_MACHINE_L_SIC) {
		WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_Tx_Rst);
	}
	WRR_rdma(SHIFT_DMA_TSA, link, p_xxb_pa.fields.laddr);
	WRR_rdma( SHIFT_DMA_TBC, link, pd_wr->size_trans);
	if (HAS_MACHINE_L_SIC) {
		WRR_rdma(SHIFT_DMA_HTSA, link, p_xxb_pa.fields.haddr);
		WRR_rdma(SHIFT_DMA_TCS, link, RCode_64 | DMA_TCS_DRCL |
			 DMA_TCS_TE | (w_pool_buf->tm_mode ? DMA_TCS_TTM : 0));
	} else {
		WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_TCO | DMA_TCS_DRCL |
			 DMA_TCS_TE | (w_pool_buf->tm_mode ? DMA_TCS_TTM : 0));
	}
	return 0;
}
#endif

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
	raw_spin_lock_irq(&dev_sem->lock);
	pd->int_ac = 0;
	/*
	 * Receive's buffer busy
	 */
	if ((!pd->trwd_was) && ( f_flags & O_NONBLOCK )) {
		raw_spin_unlock_irq(&dev_sem->lock);
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
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, io_timeout,
						       link);
		if (dev_sem->irq_count_rdma != 1) {
			ERROR_MSG("%s: link: %d MSG wait_1 bad irq "
				  "dev_sem->irq_count_rdma: 0x%08x\n",
				  __FUNCTION__, link, dev_sem->irq_count_rdma);
			dev_sem->irq_count_rdma = 0;
		} else {
			dev_sem->irq_count_rdma = 0;
		}
		if (ret_time_dwait < 0) {
			CLEAR_PD
			raw_spin_unlock_irq(&dev_sem->lock);
			WR_DBG("%s: link: %d ret_time_dwait: %d\n",
			       __FUNCTION__, link, ret_time_dwait);
			event_write(link, WRITE_BAD1_EVENT,
				    -ret_time_dwait, dev_sem->num_obmen);
			switch (ret_time_dwait) {
			case -1:
				ERROR_MSG("%s: link: %d "
					  "MSG RDMA_E_WRITE_TIMEOUT "
					  "num_obmen: 0x%08x\n", __FUNCTION__,
					  link, dev_sem->num_obmen);
				parm->err_no = RDMA_E_WRITE_TIMEOUT;
				ret = -ETIME;
				break;
			case -2:
				ERROR_MSG("%s: link: %d MSG RDMA_E_SIGNAL "
					  "num_obmen: 0x%08x\n", __FUNCTION__,
					  link, dev_sem->num_obmen);
				parm->err_no = RDMA_E_SIGNAL;
				ret = -EINTR;
				break;
			default:
				ERROR_MSG("%s: link: %d MSG RDMA_E_SPIN "
					  "num_obmen: 0x%08x\n", __FUNCTION__,
					  link, dev_sem->num_obmen);
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
		raw_spin_unlock_irq(&dev_sem->lock);
		ERROR_MSG("%s: link: %d RDMA_E_SIZE size(0x%016lx) > "
			  "w_buf->size(0x%016lx)\n", __FUNCTION__, link, size,
			  w_buf->size);
		parm->err_no = RDMA_E_SIZE;
		ret = -EMSGSIZE;
		goto exit_err_wr_buf;
	}
	pd->size_trans = (w_pool_buf->tm_mode ? PAGE_ALIGN(size) :
						allign_dma(size));
	WR_DBG("%s: link: %d : pd->size_trans: 0x%08x\n", __FUNCTION__, link,
	       pd->size_trans);
	/*
	 * Create TRWD
	 */
	sending_msg = MSG_TRWD | size;
	/*
	 * Send TRWD. Cleanup: Подумать когда отправлено TRWD,
	 * но READY не получено
	 */
	pd->int_ac = 2;
#ifdef LOOP_MODE
	if (rdma_link->mode_loop == ENABLE_LOOP) {
		raw_spin_unlock_irq(&dev_sem->lock);
		if (ret = prog_loop_dma(link, size, parm) != 0) {
			pd->trwd_was = 0;
			CLEAR_PD
			goto exit_err_wr_buf;
		}
		WR_DBG("%s: loop_link: %d pd->trwd_was: %x pd->int_ac: %x\n",
		       __FUNCTION__, link, pd->trwd_was,  pd->int_ac);
		raw_spin_lock_irq(&dev_sem->lock);
		/*pd->trwd_was--;*/
		goto wait_env;
	}
#endif
	if ((ret_smsg = send_msg_check(sending_msg, link, 0, dev_sem, 0)) > 0) {
		event_write(link, WRITE_SNDNGMSG_EVENT, ret_smsg,
			    dev_sem->num_obmen);
		goto wait_env;
	}
	event_write(link, WRITE_SNDMSGBAD_EVENT, ret_smsg, dev_sem->num_obmen);
	/*raw_spin_unlock_irq(&dev_sem->lock);*/
	if (ret_smsg < 0) {
		pd->trwd_was = 0;
		CLEAR_PD
		raw_spin_unlock_irq(&dev_sem->lock);
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
		raw_spin_unlock_irq(&dev_sem->lock);
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
	/*timeout_wait_write_dma = TIME_OUT_WAIT_WR + (pd->size_trans >> SHIFT_TO);*/
	timeout_wait_write_dma = TIME_OUT_WAIT_WR_SEC * HZ;
	ret_time_dwait = wait_for_irq_rdma_sem(dev_sem,
					(signed long)timeout_wait_write_dma,
					link);
	if (dev_sem->irq_count_rdma != 1) {
		ERROR_MSG("%s: link: %d MSG wait_2 bad irq "
			  "dev_sem->irq_count_rdma: 0x%08x\n",
			  __FUNCTION__, link, dev_sem->irq_count_rdma);
		dev_sem->irq_count_rdma = 0;
	} else {
		dev_sem->irq_count_rdma = 0;
	}
	if (ret_time_dwait < 0) {
		pd->trwd_was = 0;
		CLEAR_PD
		raw_spin_unlock_irq(&dev_sem->lock);
		event_write(link, WRITE_BAD2_EVENT, -ret_time_dwait,
			    dev_sem->num_obmen);
		switch (ret_time_dwait) {
		case -1:
			ERROR_MSG("%s: link: %d DMA RDMA_E_TIMER_IO "
				  "num_obmen: 0x%08x\n", __FUNCTION__, link,
				  dev_sem->num_obmen);
			parm->err_no = RDMA_E_TIMER_IO;
			ret = -ETIME;
			break;
		case -2:
			ERROR_MSG("%s: link: %d DMA RDMA_E_SIGNAL "
				  "num_obmen: 0x%08x\n", __FUNCTION__, link,
				  dev_sem->num_obmen);
			parm->err_no = RDMA_E_SIGNAL;
			ret = -EINTR;
			break;
		default:
			ERROR_MSG("%s: link: %d DMA RDMA_E_SPIN "
				  "num_obmen: 0x%08x\n", __FUNCTION__, link,
				  dev_sem->num_obmen);
			parm->err_no = RDMA_E_SPIN;
			ret = -EAGAIN;
		}
		if (ev_pr)
			get_event_rdma(1);
		goto exit_err_wr_buf;
	}
	CLEAR_PD
	raw_spin_unlock_irq(&dev_sem->lock);

	WR_DBG("%s: link: %d size: 0x%016lx tdc OK\n", __FUNCTION__,
	       link, size);
	parm->err_no = RDMA_E_SUCCESS;
	ret = size;
exit_err_wr_buf:
	event_write(link, WRITE_0_EVENT, ret, dev_sem->num_obmen);
	return ret;
}

