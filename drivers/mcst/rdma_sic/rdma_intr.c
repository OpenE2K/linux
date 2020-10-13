#define CAM_NO 0

nodemask_t	node_online_neighbour_map = NODE_MASK_NONE;
EXPORT_SYMBOL(node_online_neighbour_map);

int node_neighbour_num = 0;
void intr_channel(unsigned int es, unsigned int tcs, unsigned int mcs, 
		  unsigned int instance);

void rdma_interrupt(struct pt_regs *regs)
{
	unsigned int es, tcs, mcs;
	unsigned int node_neighbour_num_add = 0;
	rdma_addr_struct_t p_xxb;
	unsigned int node;
	unsigned int link = NODE_NUMIOLINKS, i, inst;
	unsigned int cpu;

#ifdef CONFIG_E90S
	cpu = raw_smp_processor_id();
	unsigned int node_id = e90s_cpu_to_node(cpu);
#else /* E3S */
	cpu = raw_smp_processor_id();
	unsigned int node_id = numa_node_id();
#endif
	/* Temporarily until a correct definition of link */
	for (i = 0; i < link; i++ ) {
		node = node_id * NODE_NUMIOLINKS + i;
		for_each_online_rdma(inst) 
			if ( node == inst ) goto next;
	
		 continue;
next:
 		fix_event(node, RDMA_INTR, START_EVENT, cpu);
		es = RDR_rdma(SHIFT_CS, node);
		es = RDR_rdma(SHIFT_ES, node);
		if (es & ES_RIRM_Ev) {
		/* Started neighbor */
#if CAM_NO
			WRR_rdma(SHIFT_ES, node, ES_RIRM_Ev); /* for CAM  */
#endif
			node_neighbour_num_add = 0;
			if (!node_test_and_set(node, node_online_neighbour_map))
				node_neighbour_num_add = 1;
			es &= ~ES_RIRM_Ev;
			if (node_neighbour_num_add)
				node_neighbour_num++;
			p_xxb.addr =
				*((unsigned long *)&node_online_neighbour_map);
			fix_event(node, RDMA_INTR, RIRM_EVENT,
				((node_neighbour_num & 0xf) << 28) |
				 (p_xxb.fields.laddr & 0x0fffffff));
		}
		if (es & ES_RIAM_Ev) {
		/* Neighbor is already acive */
#if CAM_NO
			WRR_rdma(SHIFT_ES, node, ES_RIAM_Ev); /* for CAM */
#endif
			node_neighbour_num_add = 0;
			if (!node_test_and_set(node, node_online_neighbour_map)) 
				node_neighbour_num_add = 1;
			if (node_neighbour_num_add)
				node_neighbour_num++;
			p_xxb.addr =
				*((unsigned long *)&node_online_neighbour_map);
			fix_event(node, RDMA_INTR, RIAM_EVENT,
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
	        fix_event(node, RDMA_INTR, RETURN_EVENT, 0);
	}
	return;
}

EXPORT_SYMBOL(rdma_interrupt);
void intr_channel(unsigned int evs, unsigned int tcs, unsigned int mcs, 
		  unsigned int instance)
{
	struct stat_rdma	*pst;
	rw_state_p 		pd = NULL;
	rw_state_p 		pm = NULL;
	dev_rdma_sem_t 		*dev_sem;
	ulong			cur_clock;
	register volatile	unsigned int tbc;
	unsigned int		int_cnt = 0;
	rdma_state_inst_t 	*xspi = &rdma_state->rdma_sti[instance];
	rdma_addr_struct_t	p_xxb, p_xxb_pa;

	fix_event(instance, INTR_START_EVENT, evs, tcs);
	pst = &xspi->stat_rdma;
	pst->rdma_intr++;
	
	if (evs & ES_RGP3M_Ev) {
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;
		if (RDR_rdma(SHIFT_CAM, instance)) {
			WRR_rdma(SHIFT_CAM, instance, 0);
			pcam = &xspi->talive;
			dev_sem = &pcam->dev_rdma_sem;
			raw_spin_lock(&dev_sem->lock);
			if (pcam->stat == 1) {
				pcam->clkr = join_curr_clock();
				pcam->int_cnt = int_cnt;
				rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem,
						instance);
			}
			raw_spin_unlock(&dev_sem->lock);
		} else {
			if (state_cam == RDMA_UNSET_CAM) {
				pcam = &xspi->talive;
				dev_sem = &pcam->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pcam->stat == 1) {
					pcam->clkr = join_curr_clock();
					pcam->int_cnt = int_cnt;
					rdma_cv_broadcast_rdma(
							&pcam->dev_rdma_sem,
							instance);
				}
				raw_spin_unlock(&dev_sem->lock);
			} else {
				WRR_rdma(SHIFT_CAM, instance, tr_atl);
				pcam = &xspi->ralive;
				dev_sem = &pcam->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pcam->stat == 1)
					rdma_cv_broadcast_rdma(
						&pcam->dev_rdma_sem,
						instance);
				raw_spin_unlock(&dev_sem->lock);
			}
		}
	}
	cur_clock = (unsigned long)jiffies;
	if (evs & ES_CMIE_Ev) {
		WRR_rdma(SHIFT_MSG_CS, instance, MSG_CS_Msg_Rst);
		fix_event(instance, INTR_CMIE_EVENT, 0, 0);
		pst->es_cmie++;
		return;
	}
	if (evs & ES_RDC_Ev) {
		pst->rcs = RDR_rdma(SHIFT_DMA_RCS, instance);
		pst->rbc = RDR_rdma(SHIFT_DMA_RBC, instance);
		pst->rsa = RDR_rdma(SHIFT_DMA_RSA, instance);
		WRR_rdma(SHIFT_DMA_RCS, instance, pst->rcs & (~DMA_RCS_RE));
		pst->rcs = RDR_rdma(SHIFT_DMA_RCS, instance);
		if (rfsm) {
			WRR_rdma(SHIFT_DMA_RCS, instance, 
				 pst->rcs & (~DMA_RCS_RFSM));
			WRR_rdma(SHIFT_DMA_RBC, instance, CLEAR_RFSM);
		}
		pd = xspi->rw_states_rd;
		p_xxb.addr = (unsigned long)pd;
		fix_event(instance, INTR_RDC_EVENT, p_xxb.fields.haddr,
			  p_xxb.fields.laddr);
		xspi->rw_states_rd = 0;
		if (pd == NULL) {
			fix_event(instance, INTR_RDC_PD_NULL_EVENT,
				  intr_rdc_count[instance], tcs);
			pst->pd_rd++;
			goto ES_RDC_Ev_label;
		}
		dev_sem = &pd->dev_rdma_sem;
		p_xxb.addr = (unsigned long)dev_sem;
		fix_event(instance, INTR_RDC_EVENT, pd->int_ac,
			  intr_rdc_count[instance]);
		fix_event(instance, INTR_RDC_EVENT, p_xxb.fields.haddr,
			  p_xxb.fields.laddr);
		raw_spin_lock(&dev_sem->lock);
		intr_rdc_count[instance]++;
		pd->clock_rdc = cur_clock;
		switch (pd->int_ac) {
		case 2:
			pd->int_ac = 3;
			fix_event(instance, INTR_SIGN2_READ_EVENT,
				 pd->int_ac, dev_sem->num_obmen);
			dev_sem->time_broadcast = join_curr_clock();
			rdma_cv_broadcast_rdma(&pd->dev_rdma_sem, instance);
			break;
		case 0:
		case 1:
		case 3:
		default:
			fix_event(instance, INTR_UNEXP2_READ_EVENT,
				pd->int_ac, dev_sem->num_obmen);
			pst->rdc_unxp++;
			break;
		}
		raw_spin_unlock(&dev_sem->lock);
		pd->rbc = 0;
		pst->es_rdc++;
		rdc_byte += allign_dma(pd->size_trb);
		if (rdc_byte >> 10) {
			pst->rdc_kbyte += (rdc_byte >> 10);
			rdc_byte &= 0x3ff;
		}
ES_RDC_Ev_label:
		evs = evs & ~ES_RDC_Ev;
	}
	if (evs & (ES_TDC_Ev | ES_DSF_Ev)) {
		pst->tcs = RDR_rdma(SHIFT_DMA_TCS, instance);
		pst->tbc = RDR_rdma(SHIFT_DMA_TBC, instance);
		pst->tsa = RDR_rdma(SHIFT_DMA_TSA, instance);
		if (evs & ES_TDC_Ev )
			WRR_rdma(SHIFT_DMA_TCS, instance, pst->tcs & (~DMA_TCS_TE));
		pst->tcs = RDR_rdma(SHIFT_DMA_TCS, instance);
		pd = xspi->rw_states_wr;
		if (pd == NULL) {
			fix_event(instance, INTR_TDC_DSF_PD_NULL_EVENT,
				intr_rdc_count[instance], tcs);
			goto ES_TDC_Ev_label;
		}
		xspi->rw_states_wr = 0;
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		pd->dsf = 0;
		pd->clock_tdc = cur_clock;
		if (evs & ES_DSF_Ev) {
			tbc = RDR_rdma(SHIFT_DMA_TBC, instance);
			pd->dsf = tcs;
# if 0			
			int count_reset_tcs;
			WRR_rdma(SIC_rdma_irq_mc, instance , irq_mc & ~IRQ_DSF);
			for (count_reset_tcs = 0; count_reset_tcs < 10; 
						  count_reset_tcs++) {
				//udelay(10);			  
				WRR_rdma(SHIFT_DMA_TCS, instance, 
					 DMA_TCS_Tx_Rst);
			}
			WRR_rdma(SIC_rdma_irq_mc, instance , irq_mc );
			WRR_rdma(SHIFT_DMA_TCS, instance, 
					 RCode_64 | DMA_TCS_DRCL);
#endif			
			fix_event(instance, INTR_DSF_EVENT, pd->int_ac, tcs);
			fix_event(instance, INTR_DSF_EVENT, pd->int_ac,
				  pst->tbc);
		} else {
			fix_event(instance, INTR_TDC_EVENT, pd->int_ac,
				  dev_sem->num_obmen);
		}
		switch (pd->int_ac) {
		case 2:
			pd->int_ac = 3;
			fix_event(instance, INTR_SIGN1_WRITE_EVENT,
				pd->int_ac, dev_sem->num_obmen);
			rdma_cv_broadcast_rdma(&pd->dev_rdma_sem, instance);
			break;
		case 0:
		case 1:
		case 3:
		default:
			pst->tdc_dsf_unxp++;
			fix_event(instance, INTR_TDC_UNXP_EVENT, pd->int_ac,
				  dev_sem->num_obmen);
			break;
		}
		raw_spin_unlock(&dev_sem->lock);

		if (evs & ES_DSF_Ev) {
			pst->es_dsf++;
			if (tcs &DMA_TCS_DPS_Err)
				pst->dma_tcs_dps_err++;
			else
			if (tcs &DMA_TCS_DPCRC_Err)
				pst->dma_tcs_dpcrc_err++;
			else
			if (tcs &DMA_TCS_DPTO_Err)
				pst->dma_tcs_dpto_err++;
			else
			if (tcs &DMA_TCS_DPID_Err)
				pst->dma_tcs_dpid_err++;
			if (evs & ES_TDC_Ev) {
				pst->es_dsf_tdc++;
			}
		} else {
			pst->es_tdc++;
		}
ES_TDC_Ev_label:
		evs = evs & (~(ES_TDC_Ev  | ES_DSF_Ev));
	}
	if (evs & ES_RDM_Ev) {
		int	rdmc = (evs & ES_RDMC)>>27;
		int	msg;

		pst->es_rdm++;
		if (rdmc == 0)
			rdmc = 32;
		while (rdmc--) {
			msg = RDR_rdma(SHIFT_RDMSG, instance);
			pst->rdm++;

			if ((msg & MSG_OPER) == MSG_READY) {
				pst->rec_ready++;
				switch ((msg & MSG_ABONENT) >> SHIFT_ABONENT) {
				case 0:
				case 1:
				case 2:
				case 3:
					pd = &xspi->rw_states_d[WRITER];
					break;
				default:
					pd = &xspi->rw_states_d[WRITER];
					break;				
				}
				dev_sem = &pd->dev_rdma_sem;
				p_xxb.addr = (unsigned long)pd;
				fix_event(instance, INTR_READY_EVENT,
					pd->int_ac, dev_sem->num_obmen);
				fix_event(instance, INTR_READY_EVENT,
					p_xxb.fields.haddr, p_xxb.fields.laddr);
				raw_spin_lock(&dev_sem->lock);
				switch (pd->int_ac) {
				case 1:
					break;
				case 0:
					raw_spin_unlock(&dev_sem->lock);
					pst->READY_UNXP++;
					continue;
					break;
				case 2:
					raw_spin_unlock(&dev_sem->lock);
					pst->miss_READY_2++;
					continue;
					break;
				case 3:
					raw_spin_unlock(&dev_sem->lock);
					pst->miss_READY_3++;
					continue;
					break;
				default:
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				pd->msg = msg;
				pd->clock_receive_ready = cur_clock;
				pd->int_ac = 2;
				fix_event(instance, INTR_TDMA_EVENT, 
					  pd->real_size, pd->dma);
				xspi->rw_states_wr = pd;
				if (RDR_rdma(SHIFT_DMA_TBC, instance)) {
					pd->int_ac = 5;
					rdma_cv_broadcast_rdma(
							&pd->dev_rdma_sem,
							instance);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				if (RDR_rdma(SHIFT_DMA_TCS, instance) & 
					DMA_TCS_TDMA_On) {
					pd->int_ac = 5;
					rdma_cv_broadcast_rdma(
							&pd->dev_rdma_sem,
							instance);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				if (!pd->dma) {
					pd->int_ac = 5;
					rdma_cv_broadcast_rdma(
							&pd->dev_rdma_sem,
							instance);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				p_xxb_pa.addr = (unsigned long)pd->dma;
				WRR_rdma(SHIFT_DMA_HTSA, instance, 
					 p_xxb_pa.fields.haddr);
				WRR_rdma(SHIFT_DMA_TSA, instance, 
					 p_xxb_pa.fields.laddr);
				if (rfsm) {
#ifdef CONFIG_E2K
					if (IS_MACHINE_E2S) 
						WRR_rdma( SHIFT_DMA_TBC, 
							instance, 
       							pd->real_size);
					else
						WRR_rdma( SHIFT_DMA_TBC, 
							instance, 
				  			PAGE_ALIGN(pd->real_size));
#else
					WRR_rdma( SHIFT_DMA_TBC, instance, 
							PAGE_ALIGN(pd->real_size));
#endif										
				}
				else
					WRR_rdma( SHIFT_DMA_TBC, instance,
						pd->real_size);
				WRR_rdma(SHIFT_DMA_TCS, instance, 
						RCode_64 | DMA_TCS_DRCL |
						DMA_TCS_TE |
			 			(pd->tm?DMA_TCS_TTM:0));
				pst->tcs = RDR_rdma(SHIFT_DMA_TCS, 
						instance);
				pd->tm?pst->try_TDMA_tm++:pst->try_TDMA++;
				raw_spin_unlock(&dev_sem->lock);
				continue;
			} else
			if ((msg & MSG_OPER) == MSG_TRWD) {
				int	chann;

				pst->rec_trwd++;
				switch ((msg & MSG_ABONENT) >> SHIFT_ABONENT) {
				case 0:
				case 1:
				case 2:
				case 3:
					chann = msg & MSG_ABONENT;
					pd = &xspi->rw_states_d[READER];
					break;
				default:
					chann = msg & MSG_ABONENT;		
					pd = &xspi->rw_states_d[READER];	
					break;
					/* for E3S */
				}
				p_xxb.addr = (unsigned long)pd;
				dev_sem = &pd->dev_rdma_sem;
				pd->clock_receive_trwd = cur_clock;
				raw_spin_lock(&dev_sem->lock);
				fix_event(instance, INTR_TRWD_EVENT,
					pd->int_ac, dev_sem->num_obmen);
				fix_event(instance, INTR_TRWD_EVENT,
					p_xxb.fields.haddr, p_xxb.fields.laddr);
				switch (pd->int_ac) {
				case 1:
					pd->int_ac = 2;
					pd->msg = msg;
					fix_event(instance, 
						INTR_SIGN1_READ_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					rdma_cv_broadcast_rdma(
							&pd->dev_rdma_sem,
							instance);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 0:
					pd->trwd_was++;
					pd->msg = msg;
					pst->trwd_was++;
					pst->TRWD_UNXP++;
					fix_event(instance, 
						INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 2:
					pd->trwd_was++;
					pst->trwd_was++;
					pd->msg = msg;
					pst->miss_TRWD_2++;
					fix_event(instance, 
						INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 3:
					pd->trwd_was++;
					pd->msg = msg;
					pst->trwd_was++;
					pst->miss_TRWD_3++;
					fix_event(instance, 
						INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 4:
					pd->trwd_was++;
					pd->msg = msg;
					pst->miss_TRWD_4++;
					fix_event(instance,
						INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				default:
					pd->trwd_was++;
					pd->msg = msg;
					fix_event(instance, 
						INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
			} else { /* if (msg & MSG_TRWD) { */
				pm = &xspi->rw_states_m[0];
				dev_sem = &pm->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pm->stat == RDMA_IOC_DR) {
					fix_event(instance, INTR_RMSG_EVENT, 
							pd->int_ac, 0);
					pm->msg = msg;
					pst->rdm_EXP++;
					rdma_cv_broadcast_rdma(
							&pm->dev_rdma_sem,
							instance);
					raw_spin_unlock(&dev_sem->lock);
				} else {
					fix_event(instance,
						INTR_RMSG_UNXP_EVENT, 
      						pd->int_ac, 0);
					raw_spin_unlock(&dev_sem->lock);
					pst->rdm_UNXP++;
				}
			}
		}
		evs = evs & ~ES_RDM_Ev;
	}
	if (evs & ES_MSF_Ev) {
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		WRR_rdma(SHIFT_CAM, instance, 0);
		WRR_rdma(SHIFT_MSG_CS, instance, msg_cs_dmrcl | MSG_CS_Msg_Rst);
		fix_event(instance, INTR_MSF_EVENT, 1, 0);
		pcam = &xspi->talive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = join_curr_clock();
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem, instance);
		}
		raw_spin_unlock(&dev_sem->lock);
	}
	if (evs & ES_RGP2M_Ev) {
		pst->es_rgp2++;
		evs &= ~ES_RGP2M_Ev;
	}
	if (evs & ES_RGP1M_Ev) {
		pst->es_rgp1++;
		evs &= ~ES_RGP1M_Ev;
	}
	if (evs & ES_RGP0M_Ev) {
		pst->es_rgp0++;
		if (enable_exit_gp0) {
			pd = &xspi->rw_states_d[READER];
			if (pd == NULL) {
				goto GP0_label;
			}
			dev_sem = &pd->dev_rdma_sem;
			fix_event(instance, INTR_GP0_EVENT, pd->int_ac, 
				  pd->state_GP0);
			raw_spin_lock(&dev_sem->lock);
			pd->state_GP0 = 1;
			switch (pd->int_ac) {
			case 1:
				rdma_cv_broadcast_rdma(&pd->dev_rdma_sem,
						instance);
				break;
			case 0:
			case 2:
			case 3:
			default:
				break;
			}
			raw_spin_unlock(&dev_sem->lock);
		}
GP0_label:				
		evs &= ~ES_RGP0M_Ev;
	}
	if (evs & ES_RLM_Ev) {
		pst->es_rlm++;
		evs &= ~ES_RLM_Ev;
	}
	if (evs & ES_RULM_Ev) {
		pst->es_rulm++;
		evs &= ~ES_RULM_Ev;
	}
	if (evs & ES_RIAM_Ev) {
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		WRR_rdma(SHIFT_CAM, instance, tr_atl);
		time_ID_ANS = join_curr_clock();
		pcam = &xspi->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = join_curr_clock();
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem, instance);
		}
		raw_spin_unlock(&dev_sem->lock);
		pst->es_riam++;
		evs &= ~ES_RIAM_Ev;
		fix_event(instance, INTR_RIAM_EVENT, 0, pst->es_riam);
	}
	if (evs & ES_RIRM_Ev) {
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		WRR_rdma(SHIFT_CAM, instance, tr_atl);
		time_ID_REQ = join_curr_clock();
		pcam = &xspi->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = join_curr_clock();
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem, instance);
		}
		raw_spin_unlock(&dev_sem->lock);
		pst->es_rirm++;
		evs 	&= ~ES_RIRM_Ev;
		fix_event(instance, INTR_RIRM_EVENT, 0, pst->es_rirm);
	}
	fix_event(instance, INTR_EXIT_EVENT, 0, 0);
	return;
}
