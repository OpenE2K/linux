#define	repeate_WRITE 10

int write_buf(rdma_state_inst_t *xsp, const char *buf, unsigned int size,
	       int instance, int channel, rdma_ioc_parm_t *parm)
{
	int ret_smsg;
	int ret = 0;
	unsigned int int_ac, dsf;
	int ret_time_dwait = 0;
	unsigned int size_trans;
	int cur_time_TRWD = 0;
	unsigned int sending_msg;
	int repeate_trwd;
	unsigned long flags_mu_spin;
	int io_timeout = 0;
	dev_rdma_sem_t *dev_sem;
	rdma_addr_struct_t p_xxb;
	struct stat_rdma *pst = &xsp->stat_rdma;
	clock_t tick;
	ulong cur_clock_TRWD;
	dma_chan_t *chd;
	rw_state_p pd;
	rw_state_p pm;

	switch (channel) {
	case 0:
	case 1:
	case 2:
	case 3:
		pd = &xsp->rw_states_d[WRITER];
		break;
	default:
		pd = &xsp->rw_states_d[WRITER];
	}
	dev_sem = &pd->dev_rdma_sem;
	dev_sem->time_broadcast = 0;
	if (parm->reqlen == 0) {
		io_timeout = IO_TIMEOUT;	/* 60 x HZ */
	} else	{
		if ((parm->reqlen * HZ) < TIME_OUT_WAIT_FS) {
			return ERRDMA_BAD_TIMER;
		} else {
			io_timeout = parm->reqlen * HZ;
		}
	}
	pst->bg_wr++;
	mutex_enter(&pd->mu);
	if (pd->stat != 0) {
		pst->td_urg++;
		parm->err_no = RDMA_E_URGENT;
		parm->acclen = pd->stat;
		ERROR_MSG("write_buf(%d %d) err 1: Unexpected "
			"pd->stat: %x\n", instance, channel, pd->stat);
		ret = ERRDMA_BAD_STAT;
		goto exit_err_wr_buf;
	}
	pd->stat = RDMA_IOC_WRITE;
	chd = &xsp->dma_chans[channel];
	size_trans = allign_dma(size);
	if (size_trans > chd->real_size) {
		parm->err_no = RDMA_E_SIZE_2;
		pd->stat = 0;
		ERROR_MSG("write_buf(%d %d) err 2: "
				"size_trans(0x%x) > chd->real_size(0x%lx)\n",
			instance, channel, size_trans, chd->real_size);
		ret = ERRDMA_BAD_SIZE;
		goto exit_err_wr_buf;
	}
	pd->real_size = (chd->tm ? chd->real_size : size_trans);
	dbg_write_buf("write_buf(%d %d):real_size: %d 0x%08x size: %d 0x%08x\n",
			instance, channel, (int)pd->real_size, pd->real_size,
			(int)size, size);
	pd->tm = chd->tm;
	pd->dma = chd->dma;
	if (!pd->dma) {
		ERROR_MSG("<1>write_buf(%d %d):pd->dma is NULL\n",
				instance, channel);
		ret = ERRDMA_WR_BAD_DMA;
		goto exit_err_wr_buf;
	}
	pd->fdma = chd->fdma;
	parm->err_no = 0;
	pm = &xsp->rw_states_m[1];
	sending_msg = (channel << SHIFT_ABONENT) | MSG_TRWD | size;
	dbg_write_buf("write_buf(%d %d): xsp: %p pd: %p\n", instance, channel,
		       xsp, pd);
	pd->msg = 0;
	dev_sem->num_obmen++;
	p_xxb.addr = (unsigned long)pd;
	event_write(instance, WRITE_1_EVENT, 0, dev_sem->num_obmen);
	event_write(instance, WRITE_1_EVENT, p_xxb.fields.haddr,
		     p_xxb.fields.laddr);
	cur_clock_TRWD = (unsigned long)jiffies;
	cur_time_TRWD = (int)rdma_gethrtime();
	raw_spin_lock_irq(&dev_sem->lock);
	pd->int_ac = 1;
	dbg_write_buf("write_buf(%d %d): change int_ac on 1(%x) msg: 0x%08x\n", 
		      instance, channel, pd->int_ac, sending_msg);
	repeate_trwd = 0;
	raw_spin_lock_irqsave(&pm->mu_spin, flags_mu_spin);
	if (pm->stat != 0) {
		event_write(instance, WRITE_PMSTAT_EVENT, pm->stat,
			    dev_sem->num_obmen);
		pst->td_murg++;
		parm->err_no = RDMA_E_PENDING;
		parm->acclen = pm->stat;
		ERROR_MSG("write_buf(%d %d): err 6 Unexpected "
			"pm->stat: %x\n", instance, channel, pm->stat);
		raw_spin_unlock_irqrestore(&pm->mu_spin, flags_mu_spin);
		raw_spin_unlock_irq(&dev_sem->lock);
		ret = ERRDMA_BAD_STAT_MSG;
#if GET_EVENT_RDMA_PRINT
		get_event_rdma(1);
#endif
		goto exit_err_wr_buf;
	}
	pm->stat = RDMA_IOC_WRITE;
	if ((ret_smsg = send_msg(xsp, sending_msg, instance, 0, dev_sem)) > 0)
		goto wait_env;
	event_write(instance, WRITE_SNDMSGBAD_EVENT, -ret_smsg,
		     dev_sem->num_obmen);
	pm->stat = 0;
	raw_spin_unlock_irqrestore(&pm->mu_spin, flags_mu_spin);
	raw_spin_unlock_irq(&dev_sem->lock);
	if (ret_smsg < 0) {
		ERROR_MSG("write_buf(%d %d): err 8 %d\n", instance, channel, 
			  ret_smsg);
		parm->err_no = RDMA_E_MSF_WRD;
		parm->acclen = pm->msg_cs;
		ret = ERRDMA_BAD_SEND_MSG;
#if GET_EVENT_RDMA_PRINT
		get_event_rdma(1);
#endif
		goto exit_err_wr_buf;
	}
	if (ret_smsg == 0) {
		ERROR_MSG("write_buf(%d %d): err 9 %d\n", instance, channel,
			  ret_smsg);
		parm->err_no = RDMA_E_CRSM_WRD;
		parm->acclen = count_read_sm_max;
		ret = ERRDMA_BAD_SEND_MSG;
#if GET_EVENT_RDMA_PRINT
		get_event_rdma(1);
#endif
		goto exit_err_wr_buf;
	}
wait_env:
	pst->send_trwd++;
	pm->stat = 0;
	raw_spin_unlock_irqrestore(&pm->mu_spin, flags_mu_spin);
	dbg_write_buf("write_buf(%d %d): try %p:"
			"wait_for_irq_rdma_sem(%p,0x%x)\n", instance, channel,
    			wait_for_irq_rdma_sem, dev_sem, io_timeout);
	ret_time_dwait = wait_for_irq_rdma_sem(dev_sem, (signed long)io_timeout,
					        instance);
	if (dev_sem->irq_count_rdma != 1) {
		event_write(instance, WRITE_IRQ_COUNT_EVENT,
			dev_sem->irq_count_rdma, dev_sem->num_obmen);
		dbg_write_buf("write_buf(%d %d): IO_TIMEOUT "
			      	"dev_sem->irq_count_rdma: %x\n", instance, 
	 			channel, dev_sem->irq_count_rdma);
	}
	dev_sem->irq_count_rdma = 0;
	int_ac = pd->int_ac;
	dsf = pd->dsf;
	pd->int_ac = 0;
	if (ret_time_dwait < 0) {
		event_write(instance, WRITE_BAD1_EVENT, -ret_time_dwait,
			    dev_sem->num_obmen);
		raw_spin_unlock_irq(&dev_sem->lock);
		if (ret_time_dwait == -2) {
			parm->err_no = RDMA_E_SIGNAL;
			pst->T_signal++;
			pd->trwd_was = 0;
			ret = ERRDMA_SIGNAL;
			dbg_write_buf("write_buf(%d %d): SIGNAL 1 "
					"num_obmen: %x\n", instance, channel,
      					dev_sem->num_obmen);
		} else
		if (ret_time_dwait == -1) {
			parm->err_no = RDMA_E_TIMER;
			pst->Ttimeout++;
			ret = ERRDMA_TIMER;
			ERROR_MSG("write_buf(%d %d): ETIME 1 num_obmen: %x\n",
					instance, channel, dev_sem->num_obmen);
		} else
		if (ret_time_dwait == -3) {
			parm->err_no = RDMA_E_SPIN;
			pst->Tspin++;
			ret = ERRDMA_BAD_SPIN;
			ERROR_MSG("write_buf(%d %d): ETIME 2 num_obmen: %x\n",
					instance, channel, dev_sem->num_obmen);
		}
#if GET_EVENT_RDMA_PRINT
		get_event_rdma(1);
#endif
		goto exit_err_wr_buf;
	}
	raw_spin_unlock_irq(&dev_sem->lock);
	switch (int_ac) {
	case 3:
		pst->tdc_3_1++;
		goto SYNC_WRITE1;
	default:
		pst->Ttbc2++;
		parm->acclen = int_ac;
		parm->err_no = RDMA_E_WRITE_2;
		parm->reqlen = RDR_rdma(SHIFT_DMA_TBC, instance);
		ret = ERRDMA_BAD_INT_AC1;
		tick = (unsigned long)jiffies;
		ERROR_MSG("write_buf(%d,%d): default int_ac: %x tbc: "
			"0x%08x tick-cur_clock_TRWD: 0x%08lx\n",
			instance, channel, int_ac, parm->reqlen,
    			tick - cur_clock_TRWD);
#if GET_EVENT_RDMA_PRINT
		get_event_rdma(1);
#endif
		goto exit_err_wr_buf;
	}
SYNC_WRITE1:
	pst->SYNC_WRITE1++;
	if (dsf) {
		event_write(instance, WRITE_DSF_EVENT, pd->dsf, 
			    dev_sem->num_obmen);
		ERROR_MSG("write_buf(%d %d): err 22 dsf: 0x%08x\n",
			instance, channel, pd->dsf);
		parm->err_no = RDMA_ERWRITE;
		parm->acclen = pd->dsf;
		pst->count_dsf_err++;
		ret = ERRDMA_WR_DSF;
		pst->try_TDMA_err++;
# if 1			
#define COUNT_RESET_TCS 100		
#define DELAY_RESET_TCS 10		
		/* Transmitter reset if dsf */	
		int count_reset_tcs;
		for (count_reset_tcs = 0; count_reset_tcs < COUNT_RESET_TCS; 
			count_reset_tcs++) {
			mdelay(DELAY_RESET_TCS);			  
			WRR_rdma(SHIFT_DMA_TCS, instance, 
				DMA_TCS_Tx_Rst);
		}
		WRR_rdma(SHIFT_DMA_TCS, instance, 
		RCode_64 | DMA_TCS_DRCL);
#endif			
#if GET_EVENT_RDMA_PRINT
		get_event_rdma(1);
#endif
		goto exit_err_wr_buf;
	}
	dbg_write_buf("write_buf(%d %d): size: %d tdc OK\n", size, 
		      instance, channel);
	parm->err_no = RDMA_E_SUCCESS;
	ret = size;
exit_err_wr_buf:
	pd->dsf = 0;
	pd->int_ac = 0;
	pd->stat = 0;
	pd->msg = 0;
	mutex_exit(&pd->mu);
	event_write(instance, WRITE_0_EVENT, 0, dev_sem->num_obmen);

	return ret;
}

