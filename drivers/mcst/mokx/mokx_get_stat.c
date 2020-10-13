
int get_stat_rdma(int fd)
{
	int	ret, rdmps0, rdmps1, rdckbs0, rdckbs1;

	spin_lock_irqsave(&mu_fix_event, flags);
	event_cur = &rdma_event.event[rdma_event.event_cur];
	event_cur->clkr = E2K_GET_DSREG(clkr);
	event_cur->event = event;
	event_cur->channel = channel;
	event_cur->val1 = val1;
	event_cur->val2 = val2;
	rdma_event.event_cur++;
	if (SIZE_EVENT == rdma_event.event_cur)
		rdma_event.event_cur = 0;
	spin_unlock_irqrestore(&mu_fix_event, flags);

	if (stat_rdma[0].cur_clock > cur_clock) {
		/* printf("cur_clock\t\t: %d\n", 
		       stat_rdma[0].cur_clock - cur_clock); */
		time_out = (stat_rdma[0].cur_clock - cur_clock);
	} else {
		/* printf("cur_clock\t\t: %d\n", 
		       stat_rdma[0].cur_clock + (0xffffffff - cur_clock)); */
		time_out = (stat_rdma[0].cur_clock + (0xffffffff - cur_clock));
	}
	if (time_out == 0)
		time_out = 1;
	cur_clock = stat_rdma[0].cur_clock;
	countkbsr++;
	printf("rdma_intr\t\t: %8x\t%d\t%8x\t%d\n",
		stat_rdma[0].rdma_intr, 
  		100 * (stat_rdma[0].rdma_intr - countintr0) / time_out,
		stat_rdma[1].rdma_intr,
   		100 * (stat_rdma[1].rdma_intr - countintr1) / time_out);
	countintr0 = stat_rdma[0].rdma_intr;
	countintr1 = stat_rdma[1].rdma_intr;

/*	
	printf("cs_bm\t\t\t: %8x\t%8x\n",
		stat_rdma[0].cs_bm, stat_rdma[1].cs_bm);
	printf("cs_sie\t\t\t: %8x\t%8x\n",
		stat_rdma[0].cs_sie, stat_rdma[1].cs_sie);
	printf("es_cmie\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_cmie, stat_rdma[1].es_cmie);
*/
	printf("sm_rdm\t: %8x %8x\t%8x %8x\n",
		stat_rdma[0].es_sm, stat_rdma[0].rdm, stat_rdma[1].es_sm,
   		stat_rdma[1].rdm);
	printf("msf\t\t\t: %8x\t%8x\n",
		stat_rdma[0].RDMA_MSF_WRD +
		stat_rdma[1].RDMA_CRSM_WRD,
		stat_rdma[0].RDMA_MSF_WRD +
		stat_rdma[1].RDMA_CRSM_WRD);
	rdmps0 = 100 * (stat_rdma[0].rdm - rdm0)/time_out;
	rdmps1 = 100 * (stat_rdma[1].rdm - rdm1)/time_out;
	printf("rdm_per_sec\t\t: %8d\t%8d\t%8d\n",
		rdmps0, rdmps1, rdmps0+rdmps1);
	rdm0 = stat_rdma[0].rdm;
	rdm1 = stat_rdma[1].rdm;
	printf("rdm_SUM\t\t\t: %8x\t%8x\n",
		stat_rdma[0].TRWD_UNXP +
		stat_rdma[0].rdm_UNXP +
		stat_rdma[0].rdm_EXP
		,
		stat_rdma[1].TRWD_UNXP +
		stat_rdma[1].rdm_UNXP +
		stat_rdma[1].rdm_EXP
		);
	rdckbs0 = 100 * (stat_rdma[0].rdc_kbyte - rdckb0)/time_out;
	rdckbs1 = 100 * (stat_rdma[1].rdc_kbyte - rdckb1)/time_out;
	rdckbsr += rdckbs0 + rdckbs1;
	printf("rdckb_sec\t\t: %8d\t%8d\t%8d\t%8d\n",
		rdckbs0, rdckbs1, rdckbs0+rdckbs1, rdckbsr / countkbsr);
	rdckb0 = stat_rdma[0].rdc_kbyte;
	rdckb1 = stat_rdma[1].rdc_kbyte;
	printf("rdc_kbyte\t\t: %8d\t%8d\n",
		stat_rdma[0].rdc_kbyte, stat_rdma[1].rdc_kbyte);
	printf("nr_tx nr_rx\t: %8d %8d\t%8d %8d\n",
		stat_rdma[0]._nr_tx, stat_rdma[0]._nr_rx,
		stat_rdma[1]._nr_tx, stat_rdma[1]._nr_rx);
	printf("try_RDMA\t\t: %8x %8x\t%8x %8x\n",
		stat_rdma[0].try_RDMA, stat_rdma[0].try_RDMA_tm,
		stat_rdma[1].try_RDMA, stat_rdma[1].try_RDMA_tm);
	printf("try_TDMA\t\t: %8x %8x\t%8x %8x\n",
		stat_rdma[0].try_TDMA, stat_rdma[0].try_TDMA_tm,
		stat_rdma[1].try_TDMA, stat_rdma[1].try_TDMA_tm);
	printf("es_rdc\t\t\t: %8x %8x\t%8x %8x\n",
		stat_rdma[0].es_rdc, stat_rdma[0].bad_synhr,
		stat_rdma[1].es_rdc, stat_rdma[1].bad_synhr);
/*
	printf("wait_r\t\t\t: %8x\t%8x\n",
		stat_rdma[0].wait_r, stat_rdma[1].wait_r);
	printf("wait_rr\t\t\t: %8x\t%8x\n",
		stat_rdma[0].wait_rr, stat_rdma[1].wait_rr);
	printf("pd_rd\t\t\t: %8x\t%8x\n",
		stat_rdma[0].pd_rd, stat_rdma[1].pd_rd);
	printf("bg_wr\t\t\t: %8x\t%8x\n",
		stat_rdma[0].bg_wr, stat_rdma[1].bg_wr);
	printf("rp_wr\t\t\t: %8x\t%8x\n",
		stat_rdma[0].rp_wr, stat_rdma[1].rp_wr);
	printf("rep_wr\t\t\t: %8x\t%8x\n",
		stat_rdma[0].rep_wr, stat_rdma[1].rep_wr);
	printf("wr_1\t\t\t: %8x\t%8x\n",
		stat_rdma[0].wr_1, stat_rdma[1].wr_1);
*/
	printf("rdc_unxp\t\t: %8x\t%8x\n",
		stat_rdma[0].rdc_unxp, stat_rdma[1].rdc_unxp);
	printf("rdc+TRWD_UNXP\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rdc + stat_rdma[0].TRWD_UNXP,
		stat_rdma[1].es_rdc + stat_rdma[1].TRWD_UNXP);
	printf("SYNC_WRITE1\t\t: %8x\t%8x\n",
		stat_rdma[0].SYNC_WRITE1, stat_rdma[1].SYNC_WRITE1);
	printf("SYNC_READ1\t\t: %8x\t%8x\n",
		stat_rdma[0].SYNC_READ1, stat_rdma[1].SYNC_READ1);

	printf("Ttimeout\t\t: %8x\t%8x\n",
		stat_rdma[0].Ttimeout, stat_rdma[1].Ttimeout);
	printf("Rtimeout\t\t: %8x\t%8x\n",
		stat_rdma[0].Rtimeout, stat_rdma[1].Rtimeout);
	printf("trwd_was_timeout\t: %8x\t%8x\n",
		stat_rdma[0].trwd_was_timeout, stat_rdma[1].trwd_was_timeout);

	printf("trwd_was\t\t: %8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].trwd_was,
		stat_rdma[0].TRWD_UNXP +
		stat_rdma[0].miss_TRWD_2 +
		stat_rdma[0].miss_TRWD_3 +
		stat_rdma[0].miss_TRWD_4,
		stat_rdma[1].trwd_was,
		stat_rdma[1].TRWD_UNXP +
		stat_rdma[1].miss_TRWD_2 +
		stat_rdma[1].miss_TRWD_3 +
		stat_rdma[1].miss_TRWD_4);

	printf("try_TDMA_err\t\t: %8x\t%8x\n",
		stat_rdma[0].try_TDMA_err, stat_rdma[1].try_TDMA_err);
	printf("tdc+dsf_tdc\t\t: %8x\t%8x\n",
		stat_rdma[0].es_dsf_tdc+
		stat_rdma[0].es_tdc,
		stat_rdma[1].es_dsf_tdc+
		stat_rdma[1].es_tdc);
	printf("es_tdc\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_tdc, stat_rdma[1].es_tdc);
	printf("es_tdc_unxp\t\t: %8x\t%8x\n",
		stat_rdma[0].es_tdc_unxp, stat_rdma[1].es_tdc_unxp);
	printf("tdc+dsf\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_tdc + stat_rdma[0].es_dsf,
		stat_rdma[1].es_tdc + stat_rdma[1].es_dsf);
	printf("miss\t\t\t: %8x\t%8x\n",
		stat_rdma[0].miss, stat_rdma[1].miss);
	printf("TRWD_UNXP\t\t: %8x\t%8x\n",
		stat_rdma[0].TRWD_UNXP, stat_rdma[1].TRWD_UNXP);
	printf("miss_TRWD_2\t\t: %8x\t%8x\n",
		stat_rdma[0].miss_TRWD_2, stat_rdma[1].miss_TRWD_2);
	printf("miss_TRWD_3\t\t: %8x\t%8x\n",
		stat_rdma[0].miss_TRWD_3, stat_rdma[1].miss_TRWD_3);
	printf("miss_TRWD_4\t\t: %8x\t%8x\n",
		stat_rdma[0].miss_TRWD_4, stat_rdma[1].miss_TRWD_4);
	printf("READY_UNXP\t\t: %8x\t%8x\n",
		stat_rdma[0].READY_UNXP, stat_rdma[1].READY_UNXP);
	printf("miss_READY_2\t\t: %8x\t%8x\n",
		stat_rdma[0].miss_READY_2, stat_rdma[1].miss_READY_2);
	printf("miss_READY_3\t\t: %8x\t%8x\n",
		stat_rdma[0].miss_READY_3, stat_rdma[1].miss_READY_3);
	printf("tdc_3_1 1_1: %8x %8x\t%8x %8x\n",
		stat_rdma[0].tdc_3_1, stat_rdma[0].tdc_1_1,
		stat_rdma[1].tdc_3_1, stat_rdma[1].tdc_1_1);
	printf("Ttbc012: %8x %8x %8x\t%8x %8x %8x\n",
		stat_rdma[0].Ttbc0, stat_rdma[0].Ttbc1, stat_rdma[0].Ttbc2,
		stat_rdma[1].Ttbc0, stat_rdma[1].Ttbc1, stat_rdma[1].Ttbc2);
/*
	printf("tdc_3_2\t\t\t: %8x\t%8x\n",
		stat_rdma[0].tdc_3_2, stat_rdma[1].tdc_3_2);
	printf("nrbc\t\t\t: %8x\t%8x\n",
		stat_rdma[0].nrbc, stat_rdma[1].nrbc);
	printf("rbc1\t\t\t: %8x\t%8x\n",
		stat_rdma[0].rbc1, stat_rdma[1].rbc1);
	printf("RE TE\t\t\t: %8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].rbc1+
		stat_rdma[0].nrbc+
		stat_rdma[0].miss,
		stat_rdma[1].rbc1+
		stat_rdma[1].nrbc+
		stat_rdma[1].miss,
	stat_rdma[0].TE, stat_rdma[1].TE);
*/
	
	printf("TALD\t\t\t: %8x\t%8x\n",
		stat_rdma[0].TALD, stat_rdma[1].TALD);
	printf("TDMA_On\t\t\t: %8x\t%8x\n",
		stat_rdma[0].TDMA_On, stat_rdma[1].TDMA_On);
	printf("TErr\t\t\t: %8x\t%8x\n",
		stat_rdma[0].TErr, stat_rdma[1].TErr);
/*
	printf("mask_mow\t\t: %8x\t%8x\n",
		stat_rdma[0].mask_mow, stat_rdma[1].mask_mow);
	printf("mask_mor\t\t: %8x\t%8x\n",
		stat_rdma[0].mask_mor, stat_rdma[1].mask_mor);
	printf("count_dsf\t\t: %8x\t%8x\n",
		stat_rdma[0].count_dsf, stat_rdma[1].count_dsf);
	printf("count_dsf_err\t\t: %8x\t%8x\n",
		stat_rdma[0].count_dsf_err, stat_rdma[1].count_dsf_err);
	printf("count_timer_tcs\t\t: %8x\t%8x\n",
		stat_rdma[0].count_timer_tcs, stat_rdma[1].count_timer_tcs);
	printf("T_int_ac\t\t: %8x\t%8x\n",
		stat_rdma[0].T_int_ac, stat_rdma[1].T_int_ac);
	printf("T_int_ac_dsf\t\t: %8x\t%8x\n",
		stat_rdma[0].T_int_ac_dsf, stat_rdma[1].T_int_ac_dsf);
	printf("GP0_0\t\t\t: %8x\t%8x\n",
		stat_rdma[0].GP0_0, stat_rdma[1].GP0_0);
*/
	printf("trwd\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].send_trwd, stat_rdma[0].rec_trwd,
		stat_rdma[1].send_trwd, stat_rdma[1].rec_trwd);
	printf("ready\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].send_ready, stat_rdma[0].rec_ready,
		stat_rdma[1].send_ready, stat_rdma[1].rec_ready);
/*
	printf("GP0\t%8x\t%8x\t%8x\t%8x\t\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].GP0_0, stat_rdma[0].GP0_1, stat_rdma[0].GP0_2, 
		stat_rdma[0].GP0_3,
		stat_rdma[1].GP0_0, stat_rdma[1].GP0_1, stat_rdma[1].GP0_2,
	 	stat_rdma[1].GP0_3);
	printf("GP1\t%8x\t%8x\t%8x\t%8x\t\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].GP1_0, stat_rdma[0].GP1_1, stat_rdma[0].GP1_2,
	 	stat_rdma[0].GP1_3,
		stat_rdma[1].GP1_0, stat_rdma[1].GP1_1, stat_rdma[1].GP1_2,
	 	stat_rdma[1].GP1_3);
	printf("GP2\t%8x\t%8x\t%8x\t%8x\t\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].GP2_0, stat_rdma[0].GP2_1, stat_rdma[0].GP2_2,
	 	stat_rdma[0].GP2_3,
		stat_rdma[1].GP2_0, stat_rdma[1].GP2_1, stat_rdma[1].GP2_2,
	 	stat_rdma[1].GP2_3);
	printf("GP3\t%8x\t%8x\t%8x\t%8x\t\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].GP3_0, stat_rdma[0].GP3_1, stat_rdma[0].GP3_2,
	 	stat_rdma[0].GP3_3,
		stat_rdma[1].GP3_0, stat_rdma[1].GP3_1, stat_rdma[1].GP3_2,
	 	stat_rdma[1].GP3_3);
	printf("msf_\t%8x\t%8x\t%8x\t%8x\t\t%8x\t%8x\t%8x\t%8x\n",
		stat_rdma[0].msf_0, stat_rdma[0].msf_2, stat_rdma[0].msf_3,
	 	stat_rdma[0].msf_4,
		stat_rdma[1].msf_0, stat_rdma[1].msf_2, stat_rdma[1].msf_3,
	 	stat_rdma[1].msf_4);
	printf("GP0_2\t\t\t: %8x\t%8x\n",
		stat_rdma[0].GP0_2, stat_rdma[1].GP0_2);
	printf("GP0_3\t\t\t: %8x\t%8x\n",
		stat_rdma[0].GP0_3, stat_rdma[1].GP0_3);
*/
	printf("repwr\t\t\t: %8x\t%8x\n",
		stat_rdma[0].repwr, stat_rdma[1].repwr);
	printf("reprd\t\t\t: %8x\t%8x\n",
		stat_rdma[0].reprd, stat_rdma[1].reprd);
	printf("rep_read\t\t: %8x\t%8x\n",
		stat_rdma[0].rep_read, stat_rdma[1].rep_read);
/*
	printf("repeate_TRWD\t\t: %8x\t%8x\n",
		stat_rdma[0].repeate_TRWD, stat_rdma[1].repeate_TRWD);
	printf("repeate_write\t\t: %8x\t%8x\n",
		stat_rdma[0].repeate_write, stat_rdma[1].repeate_write);
	printf("repeate_intr\t\t: %8x\t%8x\n",
		stat_rdma[0].repeate_intr, stat_rdma[1].repeate_intr);
	printf("R_int_ac\t\t: %8x\t%8x\n",
		stat_rdma[0].R_int_ac, stat_rdma[1].R_int_ac);
	printf("T_signal\t\t: %8x\t%8x\n",
		stat_rdma[0].T_signal, stat_rdma[1].T_signal);
*/
	printf("R_signal\t\t: %8x\t%8x\n",
		stat_rdma[0].R_signal, stat_rdma[1].R_signal);
	printf("T_signal\t\t: %8x\t%8x\n",
		stat_rdma[0].T_signal, stat_rdma[1].T_signal);
	printf("es_dsf\t\t\t: %8x\t%8x\tes_cmie\t: %8x\t%8x\n",
		stat_rdma[0].es_dsf, stat_rdma[1].es_dsf,
		stat_rdma[0].es_cmie, stat_rdma[1].es_cmie);
/*
	printf("es_dsf_unxp\t\t: %8x\t%8x\n",
		stat_rdma[0].es_dsf_unxp, stat_rdma[1].es_dsf_unxp);
	printf("msf\t\t\t: %8x\t%8x\n",
		stat_rdma[0].msf, stat_rdma[1].msf);
	printf("wait_write\t\t: \t%d\t%d\n",
		stat_rdma[0].wait_write, stat_rdma[1].wait_write);
	printf("waited_write\t\t: \t%d\t%d\n",
		stat_rdma[0].waited_write, stat_rdma[1].waited_write);
	printf("wait_read\t\t: \t%d\t%d\n",
		stat_rdma[0].wait_read, stat_rdma[1].wait_read);
	printf("waited_read\t\t: \t%d\t%d\n",
		stat_rdma[0].waited_read, stat_rdma[1].waited_read);
	printf("pr_rd_was\t\t: %8x\t%8x\n",
		stat_rdma[0].pr_rd_was, stat_rdma[1].pr_rd_was);
*/
	printf("dma_tcs_dps_err\t\t: %8x\t%8x\n",
		stat_rdma[0].dma_tcs_dps_err, stat_rdma[1].dma_tcs_dps_err);
	printf("dma_tcs_dpcrc_err\t: %8x\t%8x\n",
		stat_rdma[0].dma_tcs_dpcrc_err, stat_rdma[1].dma_tcs_dpcrc_err);
	printf("dma_tcs_dpto_err\t: %8x\t%8x\n",
		stat_rdma[0].dma_tcs_dpto_err, stat_rdma[1].dma_tcs_dpto_err);
	printf("dma_tcs_dpid_err\t: %8x\t%8x\n",
		stat_rdma[0].dma_tcs_dpid_err, stat_rdma[1].dma_tcs_dpid_err);
/*
	printf("td_urg\t\t\t: %8x\t%8x\n",
		stat_rdma[0].td_urg, stat_rdma[1].td_urg);
	printf("td_murg\t\t\t: %8x\t%8x\n",
		stat_rdma[0].td_murg, stat_rdma[1].td_murg);
*/
	printf("tdc_err\t\t\t: %8x\t%8x\tcs_sie\t: %8x\t%8x\n",
		stat_rdma[0].dma_tcs_dps_err+
		stat_rdma[0].dma_tcs_dpcrc_err+
		stat_rdma[0].dma_tcs_dpto_err+
		stat_rdma[0].dma_tcs_dpid_err,
		stat_rdma[1].dma_tcs_dps_err+
		stat_rdma[1].dma_tcs_dpcrc_err+
		stat_rdma[1].dma_tcs_dpto_err+
		stat_rdma[1].dma_tcs_dpid_err,
		stat_rdma[0].cs_sie, stat_rdma[1].cs_sie);

	printf("dtx_irq_count\t: %8x\t%8x\n",
		stat_rdma[0].dtx_irq_count, stat_rdma[1].dtx_irq_count);
	printf("count_va_to_pa rx tx\t: %8x\t%8x\n",
		stat_rdma[0].count_va_to_pa, stat_rdma[1].count_va_to_pa);
/*
	printf("cs_sie\t\t\t: %8x\t%8x\n",
		stat_rdma[0].cs_sie, stat_rdma[1].cs_sie);
	printf("es_cmie\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_cmie, stat_rdma[1].es_cmie);
	printf("es_dsf_tdc\t\t: %8x\t%8x\n",
		stat_rdma[0].es_dsf_tdc, stat_rdma[1].es_dsf_tdc);
	printf("send_msg_SM_0\t\t: %8x\t%8x\n",
		stat_rdma[0].send_msg_SM_0, stat_rdma[1].send_msg_SM_0);
	printf("send_msg_MSF_0\t\t: %8x\t%8x\n",
		stat_rdma[0].send_msg_MSF_0, stat_rdma[1].send_msg_MSF_0);
	printf("send_msg_DMRCL_0\t: %8x\t%8x\n",
		stat_rdma[0].send_msg_DMRCL_0, stat_rdma[1].send_msg_DMRCL_0);
	printf("send_msg_SD_Msg_0\t: %8x\t%8x\n",
		stat_rdma[0].send_msg_SD_Msg_0, stat_rdma[1].send_msg_SD_Msg_0);
	printf("send_msg_CRMAX\t\t: %8x\t%8x\n",
		stat_rdma[0].send_msg_CRMAX, stat_rdma[1].send_msg_CRMAX);
	printf("es_rlm\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rlm, stat_rdma[1].es_rlm);
	printf("es_rulm\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rulm, stat_rdma[1].es_rulm);
	printf("es_riam\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_riam, stat_rdma[1].es_riam);
	printf("es_rirm\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rirm, stat_rdma[1].es_rirm);
	printf("es_rgp3\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rgp3, stat_rdma[1].es_rgp3);
	printf("es_rgp2\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rgp2, stat_rdma[1].es_rgp2);
	printf("es_rgp1\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rgp1, stat_rdma[1].es_rgp1);
	printf("es_rgp0\t\t\t: %8x\t%8x\n",
		stat_rdma[0].es_rgp0, stat_rdma[1].es_rgp0);
*/
	printf("***********************************************************\n");
	return 0;
}
int main(int argc, char **argv)
{
	int	fd, ret;

	fd = dev_open(argv[1]);
	if (argc == 3) {
		ret = ioctl(fd, RDMA_SET_STAT, &stat_rdma);
		printf("RDMA_SET_STAT: %d %s\n", ret, strerror(errno));
	}
	gettimeofday(&timeval, 0);
	while (1) {
		get_stat_rdma(fd);
		sleep(time_sleep);
		system("clear");
	}
	return 0;
}
