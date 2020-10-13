void intr_channel(unsigned int evs, unsigned int tcs, unsigned int mcs);

void rdma_interrupt(struct pt_regs *regs)
{
	register volatile	unsigned int 	evs, tcs, mcs;

	evs = RDR_rdma(SHIFT_CS);
	if (evs & CS_SIE) {
		WRR_rdma(SHIFT_CS, evs | CS_SIE);
		event_intr(0, INTR_SIE_EVENT, 0, 0);
		return;
	}
	if (evs & CS_BUS) {
		event_intr(0, INTR_BUS_EVENT, 0, 0);
		return;
	}
	while ((evs = RDR_rdma(SHIFT_ES(0))) & irq_mc) {
		WRR_rdma(SHIFT_ES(0), evs & ~ES_SM_Ev);
		tcs = RDR_rdma(SHIFT_DMA_TCS(0));
		mcs = RDR_rdma(SHIFT_MSG_CS(0));
		intr_channel(evs, tcs, mcs);

	}
//	ack_APIC_irq(); /* remove in apic.c */
	return;
}

void intr_channel(unsigned int evs, unsigned int tcs, unsigned int mcs)
{
	struct stat_rdma	*pst;
	rw_state_p 		pd = NULL;
	rw_state_p 		pm = NULL;
	dev_rdma_sem_t 		*dev_sem;
	ulong			cur_clock;
	register volatile	unsigned int tbc;
	unsigned int		int_cnt;
	rdma_state_inst_t *xspi = &rdma_state->rdma_sti[0];

///	pcibios_read_config_dword(bus_number_rdma, devfn_rdma, 0x40, &int_cnt);
///	event_intr(0, INTR_START_EVENT, evs, int_cnt);
	pst = &stat_rdma;
	pst->rdma_intr++;

	if (evs & ES_RGP3M_Ev) {
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam, pd;
		if (RDR_rdma(SHIFT_CAM(0))) {
			WRR_rdma(SHIFT_CAM(0), 0);
			pcam = &xspi->talive;
			pd = &xspi->rw_states_d[READER];
			pd->trwd_was = 0;
			dev_sem = &pcam->dev_rdma_sem;
			raw_spin_lock(&dev_sem->lock);
			if (pcam->stat == 1) {
				pcam->clkr = E2K_GET_DSREG(clkr);
				pcam->int_cnt = int_cnt;
				rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem);
			}
			raw_spin_unlock(&dev_sem->lock);
		} else {
			if (state_cam == RDMA_UNSET_CAM) {
				pcam = &xspi->talive;
				dev_sem = &pcam->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pcam->stat == 1) {
					pcam->clkr = E2K_GET_DSREG(clkr);
					pcam->int_cnt = int_cnt;
					rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem);
				}
				raw_spin_unlock(&dev_sem->lock);
			} else {
				WRR_rdma(SHIFT_CAM(0), tr_atl);
				pcam = &xspi->ralive;
				dev_sem = &pcam->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pcam->stat == 1)
					rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem);
				raw_spin_unlock(&dev_sem->lock);
			}
		}
	}
	cur_clock = (unsigned long)jiffies;
	if (evs & ES_CMIE_Ev) {
		WRR_rdma(SHIFT_MSG_CS(0), MSG_CS_Msg_Rst);
		event_intr(0, INTR_CMIE_EVENT, 0, 0);
		pst->es_cmie++;
		return;
	}
	if (evs & ES_RDC_Ev) {
		pd = xspi->rw_states_rd;
		xspi->rw_states_rd = 0;
		if (pd == NULL) {
			event_intr(0, INTR_RDC_PD_NULL_EVENT, 
				   intr_rdc_count[0], tcs);
			pst->pd_rd++;
			goto ES_RDC_Ev_label;
		}
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		intr_rdc_count[0]++;
		event_intr(0, INTR_RDC_EVENT, pd->int_ac, intr_rdc_count[0]);
		pd->clock_rdc = cur_clock;
		switch (pd->int_ac) {
		case 2:
			pd->int_ac = 3;
			event_intr(0, INTR_SIGN2_READ_EVENT, 0, 
				   dev_sem->num_obmen);
			dev_sem->time_broadcast = E2K_GET_DSREG(clkr);
			rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
			break;
		case 0:
		case 1:
		case 3:
		default:
			event_intr(0, INTR_UNEXP2_READ_EVENT, pd->int_ac, 
				   dev_sem->num_obmen);
			pst->rdc_unxp++;
			break;
		}
		raw_spin_unlock(&dev_sem->lock);
		if (rfsm)
			WRR_rdma(SHIFT_DMA_RBC(0), 0x0);
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
		pd = xspi->rw_states_wr;
		if (pd == NULL) {
			event_intr(0, INTR_TDC_DSF_PD_NULL_EVENT, 
				   intr_rdc_count[0], tcs);
			goto ES_TDC_Ev_label;
		}
		xspi->rw_states_wr = 0;
		dev_sem = &pd->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		pd->dsf = 0;
		pd->clock_tdc = cur_clock;
		if (evs & ES_DSF_Ev) {
			tbc = RDR_rdma(SHIFT_DMA_TBC(0));
			WRR_rdma(SHIFT_DMA_TCS(0), DMA_TCS_Tx_Rst);
			pd->dsf = tcs;
			event_intr(tbc, INTR_DSF_EVENT, pd->int_ac, tcs);
		} else {
			event_intr(0, INTR_TDC_EVENT, pd->int_ac, 
				   dev_sem->num_obmen);
		}
		switch (pd->int_ac) {
		case 2:
			pd->int_ac = 3;
			event_intr(0, INTR_SIGN1_WRITE_EVENT, pd->int_ac, 
				   dev_sem->num_obmen);
			rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
			break;
		case 0:
		case 1:
		case 3:
		default:
			pst->tdc_dsf_unxp++;
			event_intr(0, INTR_TDC_UNXP_EVENT, pd->int_ac, 
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
		evs = evs & (~(ES_TDC_Ev  |ES_DSF_Ev));
	}
	if (evs & ES_RDM_Ev) {
		int	rdmc = (evs & ES_RDMC)>>27;
		int	msg;

		pst->es_rdm++;
		if (rdmc == 0)
			rdmc = 32;
		while (rdmc--) {
			msg = RDR_rdma(SHIFT_RDMSG(0));
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
					event_intr(0, INTR_MSG_READY_UNXP_EVENT,
							msg, 0);
					continue;
				}
				dev_sem = &pd->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				event_intr(0, INTR_READY_EVENT, pd->int_ac, 
					   dev_sem->num_obmen);
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
				event_intr(0, INTR_TDMA_EVENT, pd->real_size, 
					   pd->dma);
				xspi->rw_states_wr = pd;
				if (RDR_rdma(SHIFT_DMA_TBC(0))) {
					pd->int_ac = 5;
					rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);

					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				if (RDR_rdma(SHIFT_DMA_TCS(0)) & 
						DMA_TCS_TDMA_On) {
					pd->int_ac = 5;
					rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				if (!pd->dma) {
					pd->int_ac = 5;
					rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
				WRR_rdma(SHIFT_DMA_TCS(0), DMA_TCS_Tx_Rst);
				WRR_rdma(SHIFT_DMA_TSA(0), pd->dma);
				WRR_rdma( SHIFT_DMA_TBC(0), pd->real_size);
				WRR_rdma(SHIFT_DMA_TCS(0),
					DMA_TCS_TE | DMA_TCS_TCO |
					(pd->tm?DMA_TCS_TTM:0) | DMA_TCS_DRCL);
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
					event_intr(0, INTR_MSG_TRWD_UNXP_EVENT,
							msg, 0);
					continue;
				}
				dev_sem = &pd->dev_rdma_sem;
				pd->clock_receive_trwd = cur_clock;
				raw_spin_lock(&dev_sem->lock);
				event_intr(0, INTR_TRWD_EVENT, pd->int_ac,
					   dev_sem->num_obmen);
				switch (pd->int_ac) {
				case 1:
					pd->int_ac = 2;
					pd->msg = msg;
					event_intr(0, INTR_SIGN1_READ_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 0:
					pd->trwd_was++;
					pd->msg = msg;
					pst->trwd_was++;
					pst->TRWD_UNXP++;
					event_intr(0, INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 2:
					pd->trwd_was++;
					pst->trwd_was++;
					pd->msg = msg;
					pst->miss_TRWD_2++;
					event_intr(0, INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 3:
					pd->trwd_was++;
					pd->msg = msg;
					pst->trwd_was++;
					pst->miss_TRWD_3++;
					event_intr(0, INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				case 4:
					pd->trwd_was++;
					pd->msg = msg;
					pst->miss_TRWD_4++;
					event_intr(0, INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
					break;
				default:
					pd->trwd_was++;
					pd->msg = msg;
					event_intr(0, INTR_TRWD_UNXP_EVENT,
						pd->int_ac, dev_sem->num_obmen);
					raw_spin_unlock(&dev_sem->lock);
					continue;
				}
			} else { /* if (msg & MSG_TRWD) { */
				pm = &xspi->rw_states_m[0];
				dev_sem = &pm->dev_rdma_sem;
				raw_spin_lock(&dev_sem->lock);
				if (pm->stat == RDMA_IOC_DR) {
					event_intr(0, INTR_RMSG_EVENT, 
							pd->int_ac, 0);
					pm->msg = msg;
					pst->rdm_EXP++;
					rdma_cv_broadcast_rdma(&pm->dev_rdma_sem);
					raw_spin_unlock(&dev_sem->lock);
				} else {
					event_intr(0, INTR_RMSG_UNXP_EVENT, 
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
		rw_state_p	pcam, pd;

		WRR_rdma(SHIFT_CAM(0), 0);
		WRR_rdma(SHIFT_MSG_CS(0), msg_cs_dmrcl | MSG_CS_Msg_Rst);
		event_ioctl(0, INTR_MSF_EVENT, 1, 0);
		pcam = &xspi->talive;
		pd = &xspi->rw_states_d[READER];
		pd->trwd_was = 0;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = E2K_GET_DSREG(clkr);
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem);
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
			raw_spin_lock(&dev_sem->lock);
			pd->state_GP0 = 1;
			switch (pd->int_ac) {
				case 1:
					rdma_cv_broadcast_rdma(&pd->dev_rdma_sem);
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

		WRR_rdma(SHIFT_CAM(0), tr_atl);
		time_ID_ANS = E2K_GET_DSREG(clkr);
		pcam = &xspi->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = E2K_GET_DSREG(clkr);
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem);
		}
		raw_spin_unlock(&dev_sem->lock);
		pst->es_riam++;
		evs &= ~ES_RIAM_Ev;
		event_intr(0, INTR_RIAM_EVENT, 0, pst->es_riam);
	}
	if (evs & ES_RIRM_Ev) {
		dev_rdma_sem_t 	*dev_sem;
		rw_state_p	pcam;

		WRR_rdma(SHIFT_CAM(0), tr_atl);
		time_ID_REQ = E2K_GET_DSREG(clkr);
		pcam = &xspi->ralive;
		dev_sem = &pcam->dev_rdma_sem;
		raw_spin_lock(&dev_sem->lock);
		if (pcam->stat == 1) {
			pcam->clkr = E2K_GET_DSREG(clkr);
			pcam->int_cnt = int_cnt;
			rdma_cv_broadcast_rdma(&pcam->dev_rdma_sem);
		}
		raw_spin_unlock(&dev_sem->lock);
		pst->es_rirm++;
		evs 	&= ~ES_RIRM_Ev;
		event_intr(0, INTR_RIRM_EVENT, 0, pst->es_rirm);
	}
	event_intr(0, INTR_EXIT_EVENT, 0, 0);
	return;
}
