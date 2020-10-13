#define CAM_NO 0

extern int irq_mc_0;
nodemask_t	node_online_neighbour_map = NODE_MASK_NONE;
int node_neighbour_num = 0;

void intr_channel(unsigned int es, unsigned int tcs, unsigned int mcs,
		  unsigned int link);

void rdma_interrupt(struct pt_regs *regs)
{
	rdma_addr_struct_t p_xxb;
	unsigned int es, tcs, mcs;
	unsigned int node_neighbour_num_add = 0;
	unsigned int node;
	unsigned int link = RDMA_NODE_IOLINKS, i, inst;
	unsigned int cpu;

#ifdef CONFIG_E90S
	cpu = raw_smp_processor_id();
	unsigned int node_id = e90s_cpu_to_node(cpu);
#else
	cpu = raw_smp_processor_id();
	unsigned int node_id = numa_node_id();
#endif
	/* 
	 * Temporarily until a correct definition of link 
	 */
	for (i = 0; i < link; i++) {
		node = node_id * RDMA_NODE_IOLINKS + i;
		if (HAS_MACHINE_L_SIC) {
			/*_RDMA_for_each_online_rdma(inst)*/
			_RDMA_for_each_rdma(inst)
				if (node == inst)
					goto next;
			continue;
		}
next:
		event_intr(node, RDMA_INTR, START_EVENT, cpu);
		es = RDR_rdma(SHIFT_CS, node);
		es = RDR_rdma(SHIFT_ES, node);
		/*
		 * Started neighbor
		 */
		if (es & ES_RIRM_Ev) {
#if CAM_NO
			WRR_rdma(SHIFT_ES, node, ES_RIRM_Ev);
#endif
			node_neighbour_num_add = 0;
			if (!node_test_and_set(node, node_online_neighbour_map))
				node_neighbour_num_add = 1;
			es &= ~ES_RIRM_Ev;
			if (node_neighbour_num_add)
				node_neighbour_num++;
			p_xxb.addr =
				*((unsigned long *)&node_online_neighbour_map);
			event_intr(node, RDMA_INTR, RIRM_EVENT,
				((node_neighbour_num & 0xf) << 28) |
				 (p_xxb.fields.laddr & 0x0fffffff));
		}
		/*
		 * Neighbor is already acive
		 */
		if (es & ES_RIAM_Ev) {
#if CAM_NO
			WRR_rdma(SHIFT_ES, node, ES_RIAM_Ev);
#endif
			node_neighbour_num_add = 0;
			if (!node_test_and_set(node, node_online_neighbour_map))
				node_neighbour_num_add = 1;
			if (node_neighbour_num_add)
				node_neighbour_num++;
			p_xxb.addr =
				*((unsigned long *)&node_online_neighbour_map);
			event_intr(node, RDMA_INTR, RIAM_EVENT,
				   ((node_neighbour_num & 0xf) << 28) |
				   (p_xxb.fields.laddr & 0x0fffffff));
			es &= ~ES_RIAM_Ev;
		}
		while ((es = RDR_rdma(SHIFT_ES, node)) & irq_mc) {
			tcs = RDR_rdma(SHIFT_DMA_TCS, node);
#if DSF_NO
			WRR_rdma(SHIFT_ES, node, es & ~ES_SM_Ev & ~ES_DSF_Ev);
#else
			WRR_rdma(SHIFT_ES, node, es & ~ES_SM_Ev);
#endif
			mcs = RDR_rdma(SHIFT_MSG_CS, node);
			intr_channel(es, tcs, mcs, node);
		}
		event_intr(node, RDMA_INTR, RETURN_EVENT, 0);
	}
	return;
}

void intr_channel(unsigned int evs, unsigned int tcs, unsigned int mcs,
		  unsigned int link)
{
	rdma_state_link_t *rdma_link = &rdma_state->rdma_link[link];
	struct stat_rdma *pst;
	rdma_addr_struct_t p_xxb, p_xxb_pa;
	dev_rdma_sem_t *dev_sem;
	rw_state_p pd = NULL;
	rdma_pool_buf_t *r_pool_buf;
	rdma_pool_buf_t *w_pool_buf;
	rdma_buf_t *r_buf;
	rdma_buf_t *w_buf;
	unsigned int int_cnt = 0;
	unsigned int sending_msg;
	unsigned int ret_smsg;
	size_t size;

	pst = &rdma_link->stat_rdma;
	event_intr(link, INTR_START_EVENT, evs, tcs);
	pst->rdma_intr++;
	
	/*
	 * GP3 (rezerv)
	 */
	if (evs & ES_RGP3M_Ev) {
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;
		
		if (RDR_rdma(SHIFT_CAM, link)) {
			WRR_rdma(SHIFT_CAM, link, 0);
			pcam = &rdma_link->talive;
			dev_sem = &pcam->dev_rdma_sem;
			raw_spin_lock(&dev_sem->lock);
			if (pcam->stat == 1) {
				pcam->clkr = join_curr_clock();
				pcam->int_cnt = int_cnt;
				rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem,
						link);
			}
			raw_spin_unlock(&dev_sem->lock);
		} else {
			if (state_cam == RDMA_UNSET_CAM) {
				pcam = &rdma_link->talive;
				dev_sem = &pcam->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pcam->stat == 1) {
					pcam->clkr = join_curr_clock();
					pcam->int_cnt = int_cnt;
					rdma_cv_broadcast_rdma(
							&pcam->dev_rdma_sem,
							link);
				}
				raw_spin_unlock(&dev_sem->lock);
			} else {
				WRR_rdma(SHIFT_CAM, link, tr_atl);
				pcam = &rdma_link->ralive;
				dev_sem = &pcam->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pcam->stat == 1)
					rdma_cv_broadcast_rdma(
						&pcam->dev_rdma_sem, link);
				raw_spin_unlock(&dev_sem->lock);
			}
		}
		p_xxb.addr = (unsigned long)pcam;
		event_intr(link, INTR_RGP3M_EVENT, p_xxb.fields.haddr, 
			   p_xxb.fields.laddr);
		event_intr(link, INTR_RGP3M_EVENT, 0, RDR_rdma(SHIFT_CAM, link));
		evs = evs & ~ES_RGP3M_Ev;
	}
	
	/*
	 * GP0 (reset)
	 */
	if (evs & ES_RGP0M_Ev) {
		pst->es_rgp0++;
#if RESET_THREAD_DMA		
		WRR_rdma(SHIFT_IRQ_MC, link, irq_mc_0);
		raw_spin_lock(&rdma_link->rst_thr_lock);
		rdma_link->start_rst_thr = 1;
		raw_spin_unlock(&rdma_link->rst_thr_lock);
		wake_up_process(rdma_link->rst_thr);
#endif		
		event_intr(link, INTR_RGP0M_EVENT, 0, pst->es_rgp0++);
		evs = evs & ~ES_RGP0M_Ev;
	}
	
	/*
	 * CMIE
	 */
	if (evs & ES_CMIE_Ev) {
		pst->es_cmie++;
		event_intr(link, INTR_CMIE_EVENT, 0, pst->es_cmie++);
		evs = evs & ~ES_CMIE_Ev;
	}

	/*
	 * RDC (end dma reciver)
	 */
	if (evs & ES_RDC_Ev) {
		pst->es_rdc++;
		/*
		 * Reset enable dma
		 */
		pst->rcs = RDR_rdma(SHIFT_DMA_RCS, link);
		pst->rbc = RDR_rdma(SHIFT_DMA_RBC, link);
		WRR_rdma(SHIFT_DMA_RCS, link, pst->rcs & (~DMA_RCS_RE));
		pd = &rdma_link->rw_states_d[READER];
		dev_sem = &pd->dev_rdma_sem;
		p_xxb.addr = (unsigned long)pd;
		event_intr(link, INTR_RDC_EVENT, p_xxb.fields.haddr,
			   p_xxb.fields.laddr);
		event_intr(link, INTR_RDC_EVENT, pst->rcs, pst->rbc);
		r_pool_buf = &rdma_link->read_pool;
		raw_spin_lock(&dev_sem->lock);
		/*
		 * If file READ close
		 */
		if (!pd->state_open_close) {
			/*
			 * Create MSG_READY_DMA "not free buf"
			 */
			sending_msg = MSG_READY_DMA | 0x0;
			goto empty_dma_rdc; 
		}
		raw_spin_lock(&pd->lock_rd);
		/*
		 * Find work_buf in ready_list
		 */
		r_buf = list_entry(r_pool_buf->ready_list.next,
				   rdma_buf_t, list);
		if (r_buf == NULL) {
			pd->int_ac = 0;
			raw_spin_unlock(&pd->lock_rd);
			event_intr(link, RDMA_BAD_RDC_EVENT,
				   r_pool_buf->num_free_buf,
				   dev_sem->num_obmen);
			goto ES_RDC_Ev_label;
		}
		r_buf->rfsm_size = pd->size_trans - pst->rbc;
		/*
		 * Work_buf move in busy_list
		 */
		list_move_tail(&r_buf->list, &r_pool_buf->busy_list);
		/*
		 * Create MSG_READY_DMA
		 */
		sending_msg = MSG_READY_DMA | r_pool_buf->num_free_buf;
		raw_spin_unlock(&pd->lock_rd);
/*empty_dma_rdc:*/
		switch (pd->int_ac) {
		case 1:
			/*
			 * Wake up READER
			*/
			rdma_cv_broadcast_rdma(&pd->dev_rdma_sem, link);
			event_intr(link, INTR_SIGN2_READ_EVENT,
				  pd->int_ac, dev_sem->num_obmen);
			pd->int_ac = 0;
			break;
		default:
			break;
		}
empty_dma_rdc:
#ifdef LOOP_MODE
		if (rdma_link->mode_loop == DISABLE_LOOP) {
#endif
		/*
		 * Send READY_DMA
		 */
		if ((ret_smsg = send_msg_check(sending_msg, link, 0,
		     dev_sem, 0)) <= 0) {
			event_intr(link, READ_SNDMSGBAD_EVENT,
				   sending_msg, dev_sem->num_obmen);
			event_intr(link, READ_SNDMSGBAD_EVENT,
				   0xff, raw_smp_processor_id());
		} else {
			event_intr(link, READ_SNDNGMSG_EVENT,
				  sending_msg, dev_sem->num_obmen);
			event_intr(link, READ_SNDNGMSG_EVENT,
				   0xff, raw_smp_processor_id());
		}
#ifdef LOOP_MODE
		} else {
			rdma_pool_buf_t *w_pool_buf;
			rw_state_p pd_wr;
			dev_rdma_sem_t *dev_sem_wr;
			
			w_pool_buf = &rdma_link->write_pool;
			pd_wr = &rdma_link->rw_states_d[WRITER];
			dev_sem_wr = &pd_wr->dev_rdma_sem;

			raw_spin_lock(&dev_sem_wr->lock);
			pd_wr->trwd_was = sending_msg & MSG_USER;
			/*
			 * If hes free buf's reciver
			 */
			if (pd_wr->trwd_was) {
				switch (pd_wr->int_ac) {
				case 1:
					/*
					 * Wake up write
					 */
					rdma_cv_broadcast_rdma(&pd_wr->dev_rdma_sem,
							       link);
					break;
				default:
					break;
				}
			}
			raw_spin_unlock(&dev_sem_wr->lock);
		}
#endif	
ES_RDC_Ev_label:
		raw_spin_unlock(&dev_sem->lock);
		evs = evs & ~ES_RDC_Ev;
	}
	
	/*
	 * TDC (end dma transmiter)
	 */
	if (evs & (ES_TDC_Ev | ES_DSF_Ev)) {
		pst->es_tdc++;
		pd = &rdma_link->rw_states_d[WRITER];
		p_xxb.addr = (unsigned long)pd;
		dev_sem = &pd->dev_rdma_sem;
		if (evs &  ES_DSF_Ev)
			WRR_rdma(SHIFT_IRQ_MC, link, irq_mc_0);
		pst->tcs = RDR_rdma(SHIFT_DMA_TCS, link);
		pst->tbc = RDR_rdma(SHIFT_DMA_TBC, link);
		pst->tsa = RDR_rdma(SHIFT_DMA_TSA, link);
		WRR_rdma(SHIFT_DMA_TCS, link, pst->tcs & (~DMA_TCS_TE));
		pst->tcs = RDR_rdma(SHIFT_DMA_TCS, link);
		if (evs & ES_DSF_Ev) {
			event_intr(link, INTR_DSF_EVENT, pd->int_ac,
				   dev_sem->num_obmen);
			event_intr(link, INTR_DSF_EVENT, pd->int_ac, tcs);
			event_intr(link, INTR_DSF_EVENT, pd->int_ac, pst->tbc);
#if RESET_THREAD_DMA
			/*
			 * Send GP0 (reset)
			 */
			WRR_rdma(SHIFT_IRQ_MC, link, irq_mc_0);
#ifdef LOOP_MODE
			if (rdma_link->mode_loop == DISABLE_LOOP)
#endif
				ret_smsg = send_msg_check(0, link,
						  MSG_CS_SGP0_Msg, 0, 0);
			event_intr(link, INTR_DSF_EVENT, dev_sem->num_obmen,
				  ret_smsg);
			raw_spin_lock(&rdma_link->rst_thr_lock);
			rdma_link->start_rst_thr = 1;
			raw_spin_unlock(&rdma_link->rst_thr_lock);
			wake_up_process(rdma_link->rst_thr);
			/*goto ES_TDC_Ev_label;*/
#endif
			pd->trwd_was = 0;
			goto ES_DSF_Ev_label;
		}
ES_DSF_Ev_label:
		w_pool_buf = &rdma_link->write_pool;
		raw_spin_lock(&dev_sem->lock);
		if (evs &  ES_DSF_Ev)
			pd->trwd_was = 0;
		event_intr(link, INTR_TDC_EVENT, p_xxb.fields.haddr,
			  p_xxb.fields.laddr);
		event_intr(link, INTR_TDC_EVENT, pd->int_ac,
			   dev_sem->num_obmen);
		switch (pd->int_ac) {
		case 2:
			event_intr(link, INTR_SIGN1_WRITE_EVENT,
				  pd->int_ac, dev_sem->num_obmen);
			/*
			 * Wake up WRITER
			 */
			rdma_cv_broadcast_rdma(&pd->dev_rdma_sem, link);
			break;
		default:
			event_intr(link, INTR_TDC_UNXP_EVENT, pd->int_ac,
				  dev_sem->num_obmen);
			break;
		}
		/*pd->trwd_was--;*/
		raw_spin_unlock(&dev_sem->lock);
/*ES_TDC_Ev_label:*/
		evs = evs & (~(ES_TDC_Ev  | ES_DSF_Ev));
	}
	
	/*
	 * RDM (data messages)
	 */
	if (evs & ES_RDM_Ev) {
		int rdmc = (evs & ES_RDMC)>>27;
		int msg;

		pst->es_rdm++;
		if (rdmc == 0)
			rdmc = 32;
		while (rdmc--) {
			msg = RDR_rdma(SHIFT_RDMSG, link);
			pst->rdm++;
			/*
			 * TRWD
			 */
			if ((msg & MSG_OPER) == MSG_TRWD) {
				unsigned int tcs_tmp;
				
				r_pool_buf = &rdma_link->read_pool;
				pd = &rdma_link->rw_states_d[READER];
				p_xxb.addr = (unsigned long)pd;
				dev_sem = &pd->dev_rdma_sem;
				dev_sem->num_obmen++;
				event_intr(link, INTR_TRWD_EVENT,
					  msg, dev_sem->num_obmen);
				event_intr(link, INTR_TRWD_EVENT,
					   p_xxb.fields.haddr,
					   p_xxb.fields.laddr);
				raw_spin_lock(&dev_sem->lock);
				/*
				 * For bad TRWD
				 */
				if (!pd->state_open_close) {
					if (!pd->first_open) {
						raw_spin_unlock(&dev_sem->lock);
						continue;
					}
				}
				raw_spin_lock(&pd->lock_rd);
				/*
				 * Search free for read buffer
				 */
				if (list_empty(&r_pool_buf->free_list)) {
					raw_spin_unlock(&pd->lock_rd);
					raw_spin_unlock(&dev_sem->lock);
					/*
					 * Not free buf
					 */
					event_intr(link, INTR_TRWD_UNXP_EVENT,
						   r_pool_buf->num_free_buf,
						   dev_sem->num_obmen);
					continue;
				}
				r_buf = list_entry(r_pool_buf->free_list.next,
						   rdma_buf_t, list);
				/*
				 * If file READ close
				 */
				if (!pd->state_open_close) {
					goto r_empty_dma;
				}
				/*
				 * Buf as ready
				 */
				list_move_tail(&r_buf->list,
						&r_pool_buf->ready_list);
				r_pool_buf->num_free_buf--;
r_empty_dma:
				r_pool_buf->work_buf = r_buf;
				raw_spin_unlock(&pd->lock_rd);
				raw_spin_unlock(&dev_sem->lock);
				/*
				 * Programming dma reciver
				 */
				size = msg & MSG_USER;
				r_buf->real_size = size;
				/*
				 * Check on bad size
				 */
				if (size > r_buf->size) {
					event_intr(link, READ_BADSIZE_EVENT,
						   size, dev_sem->num_obmen);
					event_intr(link, READ_BADSIZE_EVENT,
						   r_buf->size,
						   dev_sem->num_obmen);
					continue;
				}
				/*pd->size_trans = (r_pool_buf->tm_mode ?
						PAGE_ALIGN(size) : allign_dma(size));*/
				pd->size_trans = (r_pool_buf->tm_mode ?
						PAGE_ALIGN(size) : (rfsm ?
						r_buf->size : allign_dma(size)));
				p_xxb_pa.addr = (unsigned long)r_buf->dma_addr;
				if (!HAS_MACHINE_L_SIC) {
					WRR_rdma(SHIFT_DMA_RCS, link,
						 DMA_RCS_Rx_Rst);
				}
				WRR_rdma(SHIFT_DMA_RSA, link, p_xxb_pa.fields.laddr);
				WRR_rdma(SHIFT_DMA_RBC, link, pd->size_trans);
				if (HAS_MACHINE_L_SIC) {
					WRR_rdma(SHIFT_DMA_RCS, link, WCode_64);
					WRR_rdma(SHIFT_DMA_HRSA, link, 
						 p_xxb_pa.fields.haddr);
					tcs_tmp = RDR_rdma(SHIFT_DMA_TCS, link);
					if (((tcs_tmp & RCode_64) != RCode_64) ||
						((tcs_tmp & DMA_TCS_DRCL) != DMA_TCS_DRCL)) {
						WRR_rdma(SHIFT_DMA_TCS, link, tcs_tmp |
							RCode_64 | DMA_TCS_DRCL);
					}
					WRR_rdma(SHIFT_DMA_RCS, link, WCode_64 |
						DMA_RCS_RE | (r_pool_buf->tm_mode ? DMA_RCS_RTM : 0) |
							     (r_pool_buf->tm_mode ? 0 : DMA_RCS_RFSM));
				} else {
					WRR_rdma(SHIFT_DMA_RCS, link, DMA_RCS_RCO | DMA_RCS_RE |
						(r_pool_buf->tm_mode ? DMA_RCS_RTM : 0) |
						(r_pool_buf->tm_mode ? 0 : DMA_RCS_RFSM));
				}
				/*
				 * Create READY
				 */
				sending_msg = MSG_READY |
						(dev_sem->num_obmen & MSG_USER);
				if ((ret_smsg =
					send_msg_check(sending_msg, link, 0,
						       dev_sem, 0)) <= 0) {
					event_intr(link, READ_SNDMSGBAD_EVENT,
						   sending_msg,
						   dev_sem->num_obmen);
					event_intr(link, READ_SNDMSGBAD_EVENT,
						  0xff, raw_smp_processor_id());
					/*
					 * Cleanup: what to do in case of an error ?
					 */
				} else {
					event_intr(link, READ_SNDNGMSG_EVENT,
						   sending_msg,
						   dev_sem->num_obmen);
					event_intr(link, READ_SNDNGMSG_EVENT,
						   0xff, raw_smp_processor_id());
				}
				continue;
			} else /*
				* READY
				*/
				if ((msg & MSG_OPER) == MSG_READY) {
				w_pool_buf = &rdma_link->write_pool;
				w_buf = w_pool_buf->work_buf;
				pd = &rdma_link->rw_states_d[WRITER];
				p_xxb.addr = (unsigned long)pd;
				dev_sem = &pd->dev_rdma_sem;
				event_intr(link, INTR_READY_EVENT,
					   p_xxb.fields.haddr,
					   p_xxb.fields.laddr);
				event_intr(link, INTR_READY_EVENT,
					   msg, dev_sem->num_obmen);
				raw_spin_lock(&dev_sem->lock);
				/*
				 * If file WRITE close
				 */
				if (!pd->state_open_close) {
					/*raw_spin_unlock(&dev_sem->lock);
					continue;*/
					goto t_empty_dma;
				}
				/*raw_spin_unlock(&dev_sem->lock);*/
				raw_spin_lock(&pd->lock_wr);
				if (list_empty(&w_pool_buf->busy_list) ||
					(!w_pool_buf->num_free_buf)) {
					/*
					 * Not ready buf
					 */
					raw_spin_unlock(&pd->lock_wr);
					raw_spin_unlock(&dev_sem->lock);
					event_intr(link,
						   INTR_MSG_READY_UNXP_EVENT,
						   w_pool_buf->num_free_buf,
       						   dev_sem->num_obmen);
					if (ev_pr)
						get_event_rdma(0);
					continue;
				}
				raw_spin_unlock(&pd->lock_wr);
t_empty_dma:
				/*
		 		 * Programming dma transmiter
				 */
				pd->trwd_was--;
				raw_spin_unlock(&dev_sem->lock);
				p_xxb_pa.addr = (unsigned long)w_buf->dma_addr;
				if (!HAS_MACHINE_L_SIC) {
					WRR_rdma(SHIFT_DMA_TCS, link,
						 DMA_TCS_Tx_Rst);
				}
				WRR_rdma(SHIFT_DMA_TSA, link,
					 p_xxb_pa.fields.laddr);
				WRR_rdma(SHIFT_DMA_TBC, link, pd->size_trans);
				if (HAS_MACHINE_L_SIC) {
					WRR_rdma(SHIFT_DMA_HTSA, link,
						 p_xxb_pa.fields.haddr);
					WRR_rdma(SHIFT_DMA_TCS, link, RCode_64 |
						DMA_TCS_DRCL | DMA_TCS_TE |
						(w_pool_buf->tm_mode ? DMA_TCS_TTM : 0));
				} else {
					WRR_rdma(SHIFT_DMA_TCS, link, DMA_TCS_TCO | DMA_TCS_DRCL | DMA_TCS_TE |
									(w_pool_buf->tm_mode ? DMA_TCS_TTM : 0));
				}
				/* raw_spin_lock(&dev_sem->lock);
				pd->trwd_was--;
				raw_spin_unlock(&dev_sem->lock); */
				continue;
			} else  /*
				 * READY_DMA
				 */
				if ((msg & MSG_OPER) == MSG_READY_DMA) {
				/*
				 * Get free buf reciver
				 */
				w_pool_buf = &rdma_link->write_pool;
				w_buf = w_pool_buf->work_buf;
				pd = &rdma_link->rw_states_d[WRITER];
				dev_sem = &pd->dev_rdma_sem;
				event_intr(link, INTR_READY_DMA_EVENT,
					   pd->int_ac, dev_sem->num_obmen);
				event_intr(link, INTR_READY_DMA_EVENT, msg,
					  dev_sem->num_obmen);
				raw_spin_lock(&dev_sem->lock);
				pd->trwd_was = msg & MSG_USER;
				/*
				 * If hes free buf's reciver
				 */
				if (pd->trwd_was) {
					switch (pd->int_ac) {
					case 1:
						/*
						 * Wake up write
						 */
						rdma_cv_broadcast_rdma(
							&pd->dev_rdma_sem,
							link);
						break;
					default:
						break;
					}
				}
				raw_spin_unlock(&dev_sem->lock);
				continue;
			}
		}
		evs = evs & ~ES_RDM_Ev;
	}
	
	/*
	 * MSF
	 */
	if (evs & ES_MSF_Ev) {
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;

		WRR_rdma(SHIFT_CAM, link, 0);
		WRR_rdma(SHIFT_MSG_CS, link, msg_cs_dmrcl | MSG_CS_Msg_Rst);
		fix_event(link, INTR_MSF_EVENT, 1, 0);
		pcam = &rdma_link->talive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = join_curr_clock();
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem, link);
		}
		raw_spin_unlock(&dev_sem->lock);
		evs = evs & ~ES_MSF_Ev;
	}
#if 1	
	/*
	 * RIAM
	 */
	if (evs & ES_RIAM_Ev) {
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;

		pst->es_riam++;
		fix_event(link, INTR_RIAM_EVENT, 0, pst->es_riam);
		WRR_rdma(SHIFT_CAM, link, tr_atl);
		time_ID_ANS = join_curr_clock();
		pcam = &rdma_link->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = join_curr_clock();
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem, link);
		}
		raw_spin_unlock(&dev_sem->lock);
		evs &= ~ES_RIAM_Ev;
	}
	
	/*
	 * RIRM
	 */
	if (evs & ES_RIRM_Ev) {
		dev_rdma_sem_t *dev_sem;
		rw_state_p pcam;

		pst->es_rirm++;
		fix_event(link, INTR_RIRM_EVENT, 0, pst->es_rirm);
		WRR_rdma(SHIFT_CAM, link, tr_atl);
		time_ID_REQ = join_curr_clock();
		pcam = &rdma_link->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = join_curr_clock();
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem, link);
		}
		raw_spin_unlock(&dev_sem->lock);
		evs &= ~ES_RIRM_Ev;
	}
#endif
	/*
	 * GP1
	 */
	if (evs & ES_RGP1M_Ev) {
		pst->es_rgp1++;
		event_intr(link, INTR_RGP1M_EVENT, 0, pst->es_rgp0++);
		evs &= ~ES_RGP1M_Ev;
	}
	
	/*
	 * GP2
	 */
	if (evs & ES_RGP2M_Ev) {
		pst->es_rgp2++;
		event_intr(link, INTR_RGP2M_EVENT, 0, pst->es_rgp0++);
		evs &= ~ES_RGP2M_Ev;
	}
	
	/*
	 * RLM
	 */
	if (evs & ES_RLM_Ev) {
		pst->es_rlm++;
		evs &= ~ES_RLM_Ev;
	}
	
	/*
	 * RULM
	 */
	if (evs & ES_RULM_Ev) {
		pst->es_rulm++;
		evs &= ~ES_RULM_Ev;
	}
	
	event_intr(link, INTR_EXIT_EVENT, 0, 0);
	return;
}
