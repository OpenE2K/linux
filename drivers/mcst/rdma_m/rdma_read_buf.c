#define READ_BUF_DBG 0
#define READ_BUF_DEBUG_MSG(x...)\
		if (READ_BUF_DBG) DEBUG_MSG(x)
#define RD_DBG READ_BUF_DEBUG_MSG
int read_buf(int link, rdma_ioc_parm_t *parm, unsigned int f_flags)
{
	rdma_state_link_t *rdma_link;
	rdma_pool_buf_t *r_pool_buf;
	dev_rdma_sem_t *dev_sem;
	struct stat_rdma *pst;
	rw_state_p pd;
	size_t size;
	unsigned long flags_r;
	signed long io_timeout = 0;
	int ret_time_dwait = 0, int_ac;
	int ret = 0;
	
	rdma_link = &rdma_state->rdma_link[link];
	r_pool_buf = &rdma_link->read_pool;
	pd = &rdma_link->rw_states_d[READER];
	pst = &rdma_link->stat_rdma;
	size = parm->reqlen;
	dev_sem = &pd->dev_rdma_sem;
	dev_sem->time_broadcast = 0;
	
	RD_DBG("%s: link: %d size: 0x%016lx\n", __FUNCTION__, link, size);
	dev_sem = &pd->dev_rdma_sem;
	raw_spin_lock_irq(&dev_sem->lock);
	event_read(link, READ_1_EVENT, size, dev_sem->num_obmen);
	pd->int_ac = 0;
	/*
	 * Check size
	 */
	if (size > r_pool_buf->buf_size) {
		raw_spin_unlock_irq(&dev_sem->lock);
		fix_event(link, READ_BADSIZE_EVENT, size, dev_sem->num_obmen);
		fix_event(link, READ_BADSIZE_EVENT, r_pool_buf->buf_size,
			  dev_sem->num_obmen);
		ERROR_MSG("%s: link: %d RDMA_E_SIZE int_ac: %d "
			  "num_obmen: 0x%08x size(0x%016lx) > "
			  "r_pool_buf->buf_size(0x%016lx)\n",
			  __FUNCTION__, link, pd->int_ac, dev_sem->num_obmen,
			  size, r_pool_buf->buf_size);
		parm->err_no = RDMA_E_SIZE;
		parm->acclen = -1;
		ret = -EMSGSIZE;
		goto exit_read_buf;
	}
	/*
	 * If nothing to read
	 */
	raw_spin_lock_irqsave(&pd->lock_rd, flags_r);
	if (list_empty(&r_pool_buf->busy_list)) {
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
	if ( f_flags & O_NONBLOCK ) {
		raw_spin_unlock_irq(&dev_sem->lock);
		parm->err_no = RDMA_E_NULL_BUFFER;
		parm->acclen = -1;
		ret = -EAGAIN;
		goto exit_read_buf;
	} else {
		/*
		 * Set timeout
		 */
		if (dev_sem->timeout == 0) {
			io_timeout = IO_TIMEOUT;
		} else	{
			io_timeout = dev_sem->timeout * HZ;
		}
		/*
		 * Flag on sleep for rdma_cv_broadcast_rdma. Wait RDC.
		 */
		pd->int_ac = 1;
		ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, io_timeout,
						       link);
		if (dev_sem->irq_count_rdma != 1) {
			ERROR_MSG("%s: link: %d MSG Bad irq "
				  "dev_sem->irq_count_rdma: 0x%08x\n",
				  __FUNCTION__, link, dev_sem->irq_count_rdma);
			dev_sem->irq_count_rdma = 0;
		} else {
			dev_sem->irq_count_rdma = 0;
		}
		RD_DBG("%s: link: %d ret_time_dwait: %d\n", __FUNCTION__,
		       link, ret_time_dwait);
		int_ac = pd->int_ac;
		if (ret_time_dwait < 0) {
			pd->int_ac = 0;
			raw_spin_unlock_irq(&dev_sem->lock);
			event_read(link, READ_BAD1_EVENT, ret_time_dwait,
				   dev_sem->num_obmen);
			switch (ret_time_dwait) {
			case -1:
				ERROR_MSG("%s: link: %d "
					  "RDMA_E_READ_TIMEOUT: "
					  "int_ac: %d "
					  "num_obmen: 0x%08x\n",
					  __FUNCTION__, link, int_ac,
					  dev_sem->num_obmen);
					parm->err_no = RDMA_E_READ_TIMEOUT;
					ret = -ETIME;
				break;
			case -2:
				ERROR_MSG("%s: link: %d RDMA_E_SIGNAL: "
					  "int_ac: %d "
					  "num_obmen: 0x%08x\n",
					  __FUNCTION__, link, int_ac,
					  dev_sem->num_obmen);
				parm->err_no = RDMA_E_SIGNAL;
				ret = -EINTR;
				break;
			default:
				ERROR_MSG("%s: link: %d "
					  "RDMA_E_RD_1_ERR: %d\n",
					  __FUNCTION__, link,
					  -ret_time_dwait);
				parm->err_no = RDMA_E_RD_1_ERR;
				ret = -EAGAIN;
			}
			if (ev_pr)
				get_event_rdma(1);
			goto exit_read_buf;
		}
	}
	} else
		raw_spin_unlock_irqrestore(&pd->lock_rd, flags_r);
	pd->int_ac = 0;
	raw_spin_unlock_irq(&dev_sem->lock);
	RD_DBG("%s: link: %d size: 0x%016lx READ OK\n", __FUNCTION__, link,
	       size);
	parm->err_no = RDMA_E_SUCCESS;
	ret = 0;
exit_read_buf:
	event_read(link, READ_00_EVENT, ret, dev_sem->num_obmen);
	return ret;
}
