#define	WAIT_RDM	count_wait_rdm = count_wait_rdm_max; \
			while (count_wait_rdm--) { \
				evs = RDR_rdma(SHIFT_ES, instance); \
				if (evs & ES_RDM_Ev) \
					continue; \
				break; \
			} \
			ERROR_MSG("%s: count_wait_rdm: %x\n", __FUNCTION__, \
				count_wait_rdm_max - count_wait_rdm); \
			event_sndmsg(instance, MSG_RST_EVENT, 0, 0); \
			WRR_rdma(SHIFT_MSG_CS, instance, MSG_CS_Msg_Rst); \
			WRR_rdma(SHIFT_MSG_CS, instance, MSG_CS_SIR_Msg); 


#define SEND_MSG_BUF_DBG 0
#define SEND_MSG_BUF_DEBUG_MSG(x...)\
		if (SEND_MSG_BUF_DBG) DEBUG_MSG(x)
#define dbg_send_msg SEND_MSG_BUF_DEBUG_MSG	
int send_msg(rdma_state_link_t *xsp, unsigned int msg,
		unsigned int instance, unsigned int cmd, dev_rdma_sem_t *dev)
{
	struct stat_rdma *pst = &xsp->stat_rdma;
	rw_state_p pm;
	unsigned int evs;
	unsigned int count_read_sm, count_loop_send_msg = 0, count_wait_rdm;
	unsigned int msg_cs;

	pm = &xsp->rw_states_m[1];
repeate_send_msg:
	evs = RDR_rdma(SHIFT_ES, instance);
	if (evs & (ES_SM_Ev | ES_MSF_Ev)) {
		if (evs & ES_MSF_Ev) {
			msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
			dbg_send_msg("%s: unexpected ES_MSF_Ev: MSG_CS: 0x%08x\n", 
				     __FUNCTION__, msg_cs);
			WRR_rdma(SHIFT_ES, instance, ES_MSF_Ev);
		}
		if (evs & ES_SM_Ev) {
			dbg_send_msg("%s: unexpected ES_SM_Ev\n", __FUNCTION__);
			WRR_rdma(SHIFT_ES, instance, ES_SM_Ev);
		}
		evs = RDR_rdma(SHIFT_ES, instance);
		if (evs & (ES_MSF_Ev | ES_SM_Ev)) {
			msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
			WAIT_RDM
			dbg_send_msg("%s: couldn't nulled MSF SM: 0x%08x 0x%08x\n",
				     __FUNCTION__, msg_cs, evs);
			evs = RDR_rdma(SHIFT_ES, instance);
			if (evs & (ES_MSF_Ev | ES_SM_Ev)) {
				msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
				dbg_send_msg("%s: couldn't MSG_CS_Msg_Rst MSF "
						"SM: %08x %08x\n",
      					     __FUNCTION__, msg_cs, evs);
				if (evs & ES_SM_Ev)
					pst->send_msg_SM_0++;
				else
					pst->send_msg_MSF_0++;
				pm->msg_cs = msg_cs;
				if (ev_pr)
					get_event_rdma(1);
				return -count_read_sm_max;
			}
		}
	}
	msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
	if (msg_cs & MCG_CS_SEND_ALL_MSG) {
		dbg_send_msg("%s: unexpected MCG_CS_SEND_ALL_MSG: %08x\n", 
			     __FUNCTION__, msg_cs);
		count_wait_rdm = count_wait_rdm_max;
		WRR_rdma(SHIFT_ES, instance, ES_SM_Ev);
		do {
			msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
			if (msg_cs & MCG_CS_SEND_ALL_MSG) {
				dbg_send_msg("%s: couldn't clear"
					"msg_cs: %08x count_wait_rdm: %x\n",
     					__FUNCTION__, msg_cs, count_wait_rdm);
			} else
				goto check_msf;
		} while (count_wait_rdm--);
		WAIT_RDM
		msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
		if (msg_cs & MCG_CS_SEND_ALL_MSG) {
			dbg_send_msg("%s: couldn't MSG_CS_Msg_Rst"
					"clear MCG_CS_SEND_ALL_MSG: %08x\n", 
     					__FUNCTION__, msg_cs);
			pst->send_msg_SD_Msg_0++;
			pm->msg_cs = msg_cs;
			fix_event(instance, RDMA_SEND_MSG, 
				  SEND_ALL_UNEXPECT_EVENT, pm->msg_cs);
			if (ev_pr)
				get_event_rdma(0);
			return -count_read_sm_max;
		}
	}
check_msf:
	if (msg_cs & MSG_CS_MSF_ALL) {
	dbg_send_msg("%s: unexpected MSG_CS_MSF_ALL: %08x\n", 
		     __FUNCTION__, msg_cs);
		WRR_rdma(SHIFT_ES, instance, ES_MSF_Ev);
		msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
		if (msg_cs & MSG_CS_MSF_ALL) {
			dbg_send_msg("%s: couldn't clear MSG_CS_MSF_ALL: %08x\n",
				     __FUNCTION__, msg_cs);
			WAIT_RDM
			msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
			if (msg_cs & MSG_CS_SD_Msg) {
				dbg_send_msg("%s: couldn't MSG_CS_Msg_Rst clear "
						"MSG_CS_MSF_ALL: %08x\n", 
      						__FUNCTION__, msg_cs);
				pst->send_msg_SD_Msg_0++;
					pm->msg_cs = msg_cs;
				fix_event(instance, RDMA_SEND_MSG, 
					  MSF_ALL_UNEXPECT_EVENT,
					pm->msg_cs);
				if (ev_pr)
					get_event_rdma(0);
				return -count_read_sm_max;
			}
		}
	}
#if	0
	if ((!IS_MACHINE_ES2) && ((msg_cs & MSG_CS_DMRCL) == 0)) {
		dbg_send_msg("%s: unexpected MSG_CS_DMRCL==0\n", __FUNCTION__);
		WRR_rdma(SHIFT_MSG_CS, instance, msg_cs_dmrcl);
		msg_cs = RDR_rdma(SHIFT_MSG_CS, instance);
		if ((msg_cs & MSG_CS_DMRCL) == 0) {
			dbg_send_msg("%s: couldn't set MSG_CS_DMRCL\n", __FUNCTION__);
			pst->send_msg_DMRCL_0++;
			pm->msg_cs = msg_cs;
			fix_event(instance, RDMA_SEND_MSG,DMRCL0_UNEXPECT_EVENT,
				pm->msg_cs);
			if (ev_pr)
				get_event_rdma(0);
			return -count_read_sm_max;
		}
	}
#endif
	count_read_sm = 0;
	if (cmd == 0)
		WRR_rdma(SHIFT_TDMSG, instance, msg); 
	else
		WRR_rdma(SHIFT_MSG_CS, instance, msg_cs_dmrcl | cmd); 
	while (count_read_sm < count_read_sm_max) {
		count_read_sm++;
		evs = RDR_rdma(SHIFT_ES, instance);
		if (evs & ES_MSF_Ev) {
			pm->msg_cs = RDR_rdma(SHIFT_MSG_CS,  instance);
			ERROR_MSG("%s: MSF: msg_cs: 0x%08x"
					"loop: %x\n", __FUNCTION__, 
      					pm->msg_cs, count_loop_send_msg);
			WRR_rdma(SHIFT_ES, instance, (ES_MSF_Ev | ES_SM_Ev));
			pst->msf++;
			count_loop_send_msg++;
			if (count_loop_send_msg > count_loop_send_msg_max) {
				fix_event(instance, RDMA_SEND_MSG, 
					  MSF_COUNT_MAX_UNEXPECT_EVENT,
					pm->msg_cs);
				if (ev_pr)
					get_event_rdma(0);
				return -count_loop_send_msg_max;
			} else {
				goto repeate_send_msg;
			}
		}
		if (evs & ES_SM_Ev) {
			pst->es_sm++;
			dbg_send_msg("%s: instance: %d count_read_sm: %d "
				     "MSG_CS: %x ES: %x TDMSG: %x\n",
				     __FUNCTION__, instance, count_read_sm,
				     RDR_rdma(SHIFT_MSG_CS,  instance),
				     RDR_rdma(SHIFT_ES,  instance),
				     RDR_rdma(SHIFT_TDMSG, instance));
			WRR_rdma(SHIFT_ES, instance, ES_SM_Ev);
			return count_read_sm;
		}
	}
	dbg_send_msg("%s: instance: %d count_read_sm: %d "
			"SHIFT_MSG_CS: %x pst->es_cmie: %x\n", __FUNCTION__, 
   			instance, count_read_sm, RDR_rdma(SHIFT_MSG_CS,  instance),
			pst->es_cmie);
	pst->send_msg_CRMAX++;
	return 0;
}
