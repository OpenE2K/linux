int read_buf(rdma_state_inst_t *xsp, const char *buf, int size, int instance,
	      int channel, rdma_ioc_parm_t *parm)
{
	int	size_trans;
	int	size_int;
	int	ret = 0, int_ac, sending_msg;
	int	count_rdr_rbc = 0;
	int	size_rbc = 0, irq_mc;
	dev_rdma_sem_t 	*dev_sem;
	unsigned long	cur_clock, waiting_trwd;
	dma_chan_t	*chd;
	rw_state_p	pd, pm;
	struct stat_rdma	*pst = &stat_rdma;
	int	ret_smsg, evs_trwd, ret_time_dwait;
	int	event_exit_read_buf = 0;
	int	count_wait_rd = 0;
	int	wait_rd_jiff = 0;
	int	io_timeout = 0;
	int	irq_count_rdma;

	dbg_read_buf("(%d %d): START %lx\n",
		     instance, channel, cur_clock);
	cur_clock = (unsigned long)jiffies;
	parm->err_no 	= 0;
	chd = &xsp->dma_chans[channel];
	size_trans = chd->real_size;
	switch (channel) {
	case 0:
	case 1:
	case 2:
	case 3:
		pd = &xsp->rw_states_d[READER];
		mutex_enter(&pd->mu);
		break;
	default:
		ERROR_MSG("read_buf(%d,%d): Unexpected channel\n",
			instance, channel);
		return ERRDMA_BAD_CHANNEL;
	}
	dev_sem = &pd->dev_rdma_sem;
	
	raw_spin_lock_irq(&dev_sem->lock);
	
	pd->ret_GP0 = 0;
	
	/* Enable exit gp0 */	
	if (enable_exit_gp0) {	
		//raw_spin_lock_irq(&dev_sem->lock);
		if (pd->state_GP0 == 1 ) {
			raw_spin_unlock_irq(&dev_sem->lock);
			if (dev_sem->irq_count_rdma) {
				DEBUG_MSG("read_buf(%d,%d): GP0 step 1 "
						" dev_sem->irq_count_rdma: %u\n",
    						  instance, channel, 
   						  dev_sem->irq_count_rdma);
				dev_sem->irq_count_rdma = 0;
			}
			//raw_spin_unlock_irq(&dev_sem->lock);
			//parm->err_no = RDMA_E_GP0_EXIT;
			//ret = ERRDMA_GP0_EXIT;
			pd->ret_GP0++;
			parm->err_no = 0;
			goto exit_read_buf;
		}
		//raw_spin_unlock_irq(&dev_sem->lock);
	} 	

	if (dev_sem->irq_count_rdma) {
		printk("rdma: read_buf(%d,%d): "
			"Unexpected dev_sem->irq_count_rdma: %ld\n",
			instance, channel, dev_sem->irq_count_rdma);
		dev_sem->irq_count_rdma = 0;
	}
	if (pd->int_ac) {
		ERROR_MSG("read_buf(%d,%d): Unexpected pd->int_ac: %d\n",
			instance, channel, pd->int_ac);
		pd->int_ac = 0;
		return ERRDMA_BAD_CHANNEL;
	}
	dev_sem->time_broadcast = 0;
	/* intr channel but p->stat == 0 */
	if (pd->stat) {
		parm->err_no 	= RDMA_E_URGENT;
		parm->acclen 	= pd->stat;
		ERROR_MSG("read_buf(%d,%d): Unexpected p->stat: %d\n",
				instance, channel, pd->stat);
		ret = ERRDMA_BAD_STAT;
		event_exit_read_buf = 1;
		goto exit_read_buf;
	}
	if (parm->reqlen == 0) {
		io_timeout = IO_TIMEOUT;
	} else	{
		if (parm->reqlen < TIME_OUT_WAIT_FS) {
			ret = ERRDMA_BAD_TIMER;
			goto exit_read_buf;
		} else {
			io_timeout = parm->reqlen;
		}
	}
	pd->real_size = chd->real_size;
	size_int = pd->real_size >> 2;
	pd->tm = chd->tm;
	pd->dma = chd->dma;
	pd->prim_buf_addr = chd->prim_buf_addr;
	pd->stat = RDMA_IOC_READ;
	parm->err_no = RDMA_E_SUCCESS;

	dev_sem->num_obmen++;
	event_read(0, READ_1_EVENT, 0, dev_sem->num_obmen);
	//raw_spin_lock_irq(&dev_sem->lock);
	if (pd->trwd_was == 0)
		goto begin_wait;
	pd->trwd_was = 0;
		if (pd->clock_receive_trwd > cur_clock)
			waiting_trwd = ~0L - pd->clock_receive_trwd + cur_clock;
		else
			waiting_trwd = cur_clock - pd->clock_receive_trwd;
	pd->clock_receive_trwd = 0;
	goto TRY_READ;

begin_wait:
	pd->int_ac = 1;
	ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, io_timeout);
	/* Enable exit gp0 */	
	if (enable_exit_gp0) {	
		if (pd->state_GP0 == 1 ) {
			if (dev_sem->irq_count_rdma) {
				DEBUG_MSG("read_buf(%d,%d): GP0_2 Unexpected"
					" dev_sem->irq_count_rdma: %u\n", 
      					instance, channel, 
      					dev_sem->irq_count_rdma);
				dev_sem->irq_count_rdma = 0;
			}
			raw_spin_unlock_irq(&dev_sem->lock);
			//parm->err_no = RDMA_E_GP0_EXIT;
			//ret = ERRDMA_GP0_EXIT;
			pd->ret_GP0++;
			parm->err_no = 0;
			goto exit_read_buf;
		}
	}
	if (ret_time_dwait < 0) {
		irq_count_rdma = dev_sem->irq_count_rdma;
		pd->stat = 0;
		pd->int_ac = 0;
		pd->trwd_was = 0;
		dev_sem->irq_count_rdma = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		printk("rdma: read_buf(%d %d): RDMA_E_TIMER_IO %d\n",
			instance, channel, ret_time_dwait);
		switch (ret_time_dwait) {
		case -1:/* ETIME */
			switch (irq_count_rdma) {
			case 0:
				parm->err_no = RDMA_E_TIMER_IO;
				pst->Rtimeout++;
				ret = ERRDMA_TIMER;
				break;
			default:
				ERROR_MSG("read_buf(%d %d): "
						"RDMA_E_IRQ_COUNT1: %ld "
						"int_ac: %d 0x%x 0x%x\n", 
      						instance, channel, 
	    					dev_sem->irq_count_rdma, 
	  					pd->int_ac, 
						intr_rdc_count[instance], 
      						dev_sem->num_obmen);
				parm->err_no = RDMA_E_IRQ_COUNT1;
				ret = ERRDMA_BAD_IRQ_COUNT;
			}
			break;
		case -2:/* EINTR */
			event_read(0, READ_SIGN1_EVENT, 1, dev_sem->num_obmen);
			parm->err_no = RDMA_E_SIGNAL_READ_1;
			pst->R_signal++;
			ret = ERRDMA_SIGNAL;
			break;
		default:
			parm->err_no = RDMA_E_RD_1_ERR;
			ret = ERRDMA_BAD_WAIT1;
			ERROR_MSG("read_buf(%d %d): RDMA_E_RD_1_ERR: %d\n",
				instance, channel, -ret_time_dwait);
		}
		goto exit_read_buf;
	}
	switch (dev_sem->irq_count_rdma) {
	case 1:
		dev_sem->irq_count_rdma = 0;
		break;
	case 0:
		pd->trwd_was = 0;
		pd->stat = 0;
		pd->int_ac = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		parm->err_no = RDMA_E_TIMER_IO;
		pst->Rtimeout++;
		ret = ERRDMA_TIMER;
		ERROR_MSG("read_buf(%d %d): RDMA_E_TIMER_IO 1 %d\n",
			instance, channel, ret_time_dwait);
		goto exit_read_buf;
	default:
		pd->trwd_was = 0;
		pd->stat = 0;
		dev_sem->irq_count_rdma = 0;
		pd->int_ac = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		ERROR_MSG("read_buf(%d %d): RDMA_E_IRQ_COUNT1: %ld "
				"int_ac: %d 0x%x 0x%x\n",instance, channel, 
    				dev_sem->irq_count_rdma, pd->int_ac,
				intr_rdc_count[instance], dev_sem->num_obmen);
		parm->err_no = RDMA_E_IRQ_COUNT1;
		ret = ERRDMA_BAD_IRQ_COUNT;
		goto exit_read_buf;
	}

	switch (pd->int_ac) {
	case 2:
		goto TRY_READ;
		break;
	default:
		pd->trwd_was = 0;
		pd->stat = 0;
		dev_sem->irq_count_rdma = 0;
		pd->int_ac = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		event_read(0, READ_BAD1_EVENT, pd->int_ac, dev_sem->num_obmen);
		parm->err_no = READ_E_44;
		parm->acclen = pd->int_ac;
		ret = ERRDMA_BAD_INT_AC1;
		ERROR_MSG("read_buf(%d %d): DEFAULT1 int_ac: %d: "
				"num_obmen: 0x%x\n", instance, channel, 
    				pd->int_ac, dev_sem->num_obmen);
		event_exit_read_buf = 8;
		goto exit_read_buf;
	}
TRY_READ:
	pd->size_trb = pd->msg & MSG_USER;
	/* size_trans = allign_dma(pd->size_trb); */
	if (rfsm) 
		size_trans = (chd->real_size);
	else
		size_trans = (chd->tm?chd->real_size:allign_dma(pd->size_trb));
	if (pd->real_size < size_trans) {
		pd->int_ac = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		event_read(0, READ_BADSIZE_EVENT, size_trans, 
			   dev_sem->num_obmen);
		/* read & clear ints */
		evs_trwd = RDR_rdma(SHIFT_ES(instance)) ; 
		if (evs_trwd & ES_MSF_Ev)
			pst->msf_0++;
		parm->err_no = TRWD_E_SIZE;
		ret = ERRDMA_BAD_SIZE;
		ERROR_MSG("read_buf(%d %d): TRWD_E_SIZE\n",
			instance, channel);
		event_exit_read_buf = 2;
		goto exit_read_buf;
	}

	WRR_rdma(SHIFT_DMA_RCS(instance), DMA_RCS_Rx_Rst); 
	WRR_rdma(SHIFT_DMA_RSA(instance), pd->dma);
	WRR_rdma(SHIFT_DMA_RBC(instance), size_trans);
	WRR_rdma(SHIFT_DMA_RCS(instance), DMA_RCS_RCO | DMA_RCS_RE |
			(pd->tm?DMA_RCS_RTM:0) | DMA_RCS_RFSM);
	pd->tm?pst->try_RDMA_tm++:pst->try_RDMA++;
	pd->n_ready++;
	xsp->rw_states_rd = pd;
	pm = &xsp->rw_states_m[1];
	raw_spin_lock(&pm->mu_spin);
	if (pm->stat != 0) {
		raw_spin_unlock(&pm->mu_spin);
		pd->int_ac = 0;
		raw_spin_unlock_irq(&dev_sem->lock);
		event_read(0, READ_PMSTAT_EVENT, pm->stat, dev_sem->num_obmen);
		pst->rd_murg++;
		parm->err_no = RDMA_E_PENDING;
		parm->acclen = pm->stat;
		ERROR_MSG("read_buf(%d %d): err 6 Unexpected "
			"pm->stat: %d\n",
			instance, channel, pm->stat);
		ret = ERRDMA_BAD_STAT_MSG;
		event_exit_read_buf = 33;
		goto exit_read_buf;
	}
	pm->stat = RDMA_IOC_WRITE;
	pm->msg_cs = 0;
	sending_msg = (channel << SHIFT_ABONENT) | MSG_READY | 
			(pd->n_ready & MSG_USER);
	pd->int_ac = 2;
	ret_smsg = send_msg(xsp, sending_msg, instance, 0, dev_sem);
	if (ret_smsg <= 0) {
		pd->int_ac = 0;
		pm->stat = 0;
		raw_spin_unlock(&pm->mu_spin);
		raw_spin_unlock_irq(&dev_sem->lock);
		event_read(0, READ_SNDMSGBAD_EVENT, -ret_smsg, 
			   dev_sem->num_obmen);
		ret = ERRDMA_BAD_SEND_MSG;
		if (ret_smsg < 0) {
			parm->err_no = RDMA_E_MSF_WRD;
			parm->acclen = pm->msg_cs;
			pst->RDMA_MSF_WRD++;
			ERROR_MSG("read_buf(%d %d): RDMA_E_MSF_WRD\n",
				instance, channel);
			event_exit_read_buf = 3;
			goto exit_read_buf;
		}
		if (ret_smsg == 0) {
			parm->err_no = RDMA_E_CRSM_WRD;
			parm->acclen = count_read_sm_max;
			pst->RDMA_CRSM_WRD++;
			ERROR_MSG("read_buf(%d %d): RDMA_E_CRSM_WRD\n",
				instance, channel);
			event_exit_read_buf = 4;
			goto exit_read_buf;
		}
	}
	pm->stat = 0;
	raw_spin_unlock(&pm->mu_spin);
	pst->send_ready++;
	pd->clock_send_ready = cur_clock;

	wait_rd_jiff = TIME_OUT_WAIT_RD + (pd->size_trb>>SHIFT_TO);
	ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, wait_rd_jiff);

	int_ac = pd->int_ac;
	pd->int_ac = 0;
	raw_spin_unlock_irq(&dev_sem->lock);
	if (ret_time_dwait < 0) {
		if (enable_exit_gp0) {	
			if (pd->state_GP0 == 1 ) {
				pd->ret_GP0++;
			}
		}
		switch (ret_time_dwait) {
		case -1:
			event_read(0, READ_BAD_SYNHR_EVENT,
				dev_sem->irq_count_rdma, dev_sem->num_obmen);
			parm->err_no = RDMA_E_BAD_SYNHR;
			pst->bad_synhr++;
			ERROR_MSG("read_buf(%d %d): bad_synhr   : %d "
					"num_obmen: %d cur_clock: 0x%x\n",
					instance, channel, pst->bad_synhr,
      					dev_sem->num_obmen, 
	   				(unsigned int)cur_clock);
			ERROR_MSG("read_buf(%d %d): wait_rd_jiff: %d "
					"num_obmen: %d cur_clock: 0x%x\n",
					instance, channel, wait_rd_jiff, 
     					dev_sem->num_obmen, 
	  				(unsigned int)cur_clock);
			goto BAD_SYNHR;
		case -2:
			event_read(0, READ_SIGN2_EVENT, 1, dev_sem->num_obmen);
			parm->err_no = RDMA_E_SIGNAL_READ_2;
			pd->trwd_was = 0;
			pst->R_signal++;
			pd->stat = 0;
			ret = ERRDMA_SIGNAL;
			ERROR_MSG("read_buf(%d %d): SIGNAL 2\n",
				instance, channel);
			goto exit_read_buf;
		case -3:
			parm->err_no = RDMA_E_SEM;
			ret = ERRDMA_BAD_SPIN;
			ERROR_MSG("read_buf(%d %d): ERR_SEM 1\n",
				instance, channel);
			goto exit_read_buf;
		default:
			parm->err_no = RDMA_E_RD1ERR;
			ret = ERRDMA_RD_BAD_WAIT2;
			ERROR_MSG("read_buf(%d %d): RDMA_E_RD1ERR %d\n",
				instance, channel, -ret_time_dwait);
			goto exit_read_buf;
		}
	}

BAD_SYNHR:
	switch (dev_sem->irq_count_rdma) {
	case 1:
		dev_sem->irq_count_rdma = 0;
		break;
	case 0:
		if (int_ac) {
			WARN_MSG("read_buf(%d %d): ETIME 1 int_ac: %d %d "
					"0x%x 0x%x\n", instance, channel, 
     					int_ac, wait_rd_jiff, 
	  				intr_rdc_count[instance],
        				dev_sem->num_obmen);
			break;
		}
		do {
			size_rbc = RDR_rdma(SHIFT_DMA_RBC(instance));
			WARN_MSG("read_buf(%d %d): BAD_SYNHR RBC: 0x%x "
					"RCS: 0x%x %d\n", instance, channel,
      					size_rbc, 
	   				RDR_rdma(SHIFT_DMA_RCS(instance)),
					count_rdr_rbc);
			if (!size_rbc) {
				goto SYNC_READ;
			}
		} while (count_rdr_rbc++ < MAX_COUNT_RDR_RBC);
		count_rdr_rbc = 0;

		if (count_wait_rd++ < REPEAT_WAIT_RD_MAX)
			WRR_rdma(SHIFT_DMA_RCS(instance), DMA_RCS_Rx_Rst);
		event_read(0, READ_BAD2_EVENT, int_ac, count_wait_rd);
		parm->err_no = RDMA_E_TIMER;
		pst->Rtimeout++;
		pd->stat = 0;
		ret = ERRDMA_RD_MAX_REPEATE;
		ERROR_MSG("read_buf(%d %d): ETIME 2 int_ac: %d\n",
			instance, channel, int_ac);
		goto exit_read_buf;
	default:
		parm->err_no = RDMA_E_IRQ_COUNT2;
		pst->Rtimeout++;
		pd->stat = 0;
		ret = ERRDMA_RD_BAD_IRQ_COUNT1;
		ERROR_MSG("read_buf(%d %d): RDMA_E_IRQ_COUNT2: %ld\n",
			instance, channel, dev_sem->irq_count_rdma);
		goto exit_read_buf;
	}
	switch (int_ac) {
	case 3:
		do {
			size_rbc = RDR_rdma(SHIFT_DMA_RBC(instance));
			irq_mc = RDR_rdma(SHIFT_IRQ_MC(instance));
			if (!size_rbc) {
				goto SYNC_READ;
			}
		} while (count_rdr_rbc++ < MAX_COUNT_RDR_RBC);
		event_read(0, READ_LOSS_EVENT, 0x30000000 | size_rbc,
			   dev_sem->num_obmen);
		ERROR_MSG("read_buf(%d %d): RDMA_E_READ_LOSS "
				"size_rbc: 0x%08x\n", instance, channel, 
    				0x30000000 | size_rbc);
		parm->err_no = RDMA_E_READ_LOSS;
		parm->acclen = int_ac;
		ret = ERRDMA_RD_MAX_COUNT_RDR_RBC;
		event_exit_read_buf = 88;
		goto exit_read_buf;
	case 2:
		size_rbc = RDR_rdma(SHIFT_DMA_RBC(instance));
		irq_mc = RDR_rdma(SHIFT_IRQ_MC(instance));

		event_read(0, READ_LOSS_EVENT, 0x20000000 | size_rbc, 
			   dev_sem->num_obmen);
		ERROR_MSG("read_buf(%d %d): RDMA_E_READ_LOSS "
				"size_rbc: 0x%08x 0x%x 0x%x\n", instance, 
    				channel, 0x20000000 | size_rbc, 
				intr_rdc_count[instance], dev_sem->num_obmen);
		if (!size_rbc) {
			goto SYNC_READ;
		}
		parm->err_no = RDMA_E_READ_LOSS;
		parm->acclen = int_ac;
		ret = ERRDMA_RD_LOSS_RDC_2;
		event_exit_read_buf = 66;
		goto exit_read_buf;

	case 4:
		size_rbc = RDR_rdma(SHIFT_DMA_RBC(instance));
		event_read(0, READ_LOSS_EVENT, 0x40000000 | size_rbc, 
			   dev_sem->num_obmen);
		ERROR_MSG("read_buf(%d %d): RDMA_E_READ_LOSS "
				"size_rbc: 0x%08x 0x%x 0x%x\n", instance, 
    				channel, 0x40000000 | size_rbc, 
				intr_rdc_count[instance], dev_sem->num_obmen);
		parm->err_no = RDMA_E_READ_LOSS;
		parm->acclen = int_ac;
		ret = ERRDMA_RD_LOSS_RDC_4;
		event_exit_read_buf = 55;
		goto exit_read_buf;
	default:
		size_rbc = RDR_rdma(SHIFT_DMA_RBC(instance));
		event_read(0, READ_DEF2_EVENT, 0x50000000 | size_rbc, 
			   dev_sem->num_obmen);
		ERROR_MSG("read_buf(%d %d): DEFAULT 2 int_ac: %d 0x%x 0x%x\n",
				instance, channel, int_ac, 
    				intr_rdc_count[instance], dev_sem->num_obmen);
		parm->err_no = READ_E_44;
		parm->acclen = int_ac;
		ret = ERRDMA_RD_BAD_INT_AC2;
		event_exit_read_buf = 5;
		goto exit_read_buf;
	}

SYNC_READ:
	pd->stat = 0;
	pd->int_ac = 0;
	parm->rwmode = RDR_rdma(SHIFT_DMA_RSA(instance));
	parm->acclen = pd->size_trb;
	ret = parm->acclen;
	parm->msg = pd->int_ac;
exit_read_buf:
	if (enable_exit_gp0) {	
		if (pd->ret_GP0) {
			//parm->err_no = RDMA_E_GP0_EXIT;
			parm->rwmode = RDMA_E_GP0_EXIT;
			ret = ERRDMA_GP0_EXIT;
			pd->ret_GP0 = 0;
		}
	}
	pd->stat = 0;
	pd->int_ac = 0;
	mutex_exit(&pd->mu);
	event_read(pst->rdc_kbyte, READ_00_EVENT, size_rbc, dev_sem->num_obmen);
	return ret;
}
