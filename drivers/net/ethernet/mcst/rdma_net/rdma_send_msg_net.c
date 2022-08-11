/*
 * Copyright (c) 2011 by MCST.
 * rdma_send_msg_net.h
 * Implementation of networking protocols TCP\IP via rdma
 */

#include "rdma_user_intf_net.h"
#include "rdma_reg_net.h"

int	MCG_CS_SEND_ALL_MSG =
		(MSG_CS_SD_Msg | MSG_CS_SGP0_Msg | MSG_CS_SGP1_Msg | MSG_CS_SGP2_Msg |
		 MSG_CS_SGP3_Msg | MSG_CS_SL_Msg | MSG_CS_SUL_Msg | MSG_CS_SIR_Msg);
int	MSG_CS_MSF_ALL = MSG_CS_DMPS_Err | MSG_CS_MPCRC_Err | MSG_CS_MPTO_Err | MSG_CS_DMPID_Err;
unsigned int	count_loop_send_msg_max = 10;
unsigned int	count_wait_rdm_max = 64;
unsigned long	count_read_sm_max = 80;

#define	WAIT_RDM	count_wait_rdm = count_wait_rdm_max; \
			while (count_wait_rdm--) { \
				evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL); \
				if (evs & ES_RDM_Ev) \
					continue; \
				break; \
			} \
			\
			event_sndmsg(instance, MSG_RST_EVENT, 0, 0); \
			WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_Msg_Rst, (dev_rdma_sem_t *)NULL); \
			WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_SIR_Msg, (dev_rdma_sem_t *)NULL); // 10.11.07

int send_msg(struct rdma_private *rp, unsigned int msg, unsigned int instance, unsigned int cmd)
{
	unsigned int	evs;
	unsigned int	inst;
//	unsigned int	flags;
	unsigned int	count_read_sm, count_loop_send_msg = 0, count_wait_rdm;
	unsigned int	msg_cs;

	struct stat_rdma	*pst;
	spin_snd_msg_rdma_p	*ssmr;

	struct	rdma_event	*re;
	re = &rdma_event;
	unsigned long flags;


	inst = rp->inst;
	pst = &rp->stat_rdma;
	ssmr = &spin_snd_msg_rdma[inst];
	raw_spin_lock_irqsave(&ssmr->lock, flags);

repeate_send_msg:
	evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL);
	if (evs & (ES_SM_Ev | ES_MSF_Ev)) {
		if (evs & ES_MSF_Ev) {
			msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
			dbg_send_msg("<1>rdma: send_msg: unexpected ES_MSF_Ev: MSG_CS: 0x%08x\n",
				msg_cs);
			WRR(rp->regbase, SHIFT_ES, ES_MSF_Ev, (dev_rdma_sem_t *)NULL);
		}
		if (evs & ES_SM_Ev) {
			dbg_send_msg("<1>rdma: send_msg: unexpected ES_SM_Ev\n");
			WRR(rp->regbase, SHIFT_ES, ES_SM_Ev, (dev_rdma_sem_t *)NULL);
		}
		evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL);
		if (evs & (ES_MSF_Ev | ES_SM_Ev)) {
			msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
			WAIT_RDM
			dbg_send_msg("<1>rdma: send_msg: couldn't nulled MSF SM: 0x%08x 0x%08x\n",
				msg_cs, evs);
			evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL);
			if (evs & (ES_MSF_Ev | ES_SM_Ev)) {
				msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
				dbg_send_msg("<1>rdma: send_msg: couldn't MSG_CS_Msg_Rst "
					"MSF SM: %08x %08x\n", msg_cs, evs);
				if (evs & ES_SM_Ev)
					pst->send_msg_SM_0++;
				else
					pst->send_msg_MSF_0++;
				raw_spin_unlock_irqrestore(&ssmr->lock, flags);
				return -count_read_sm_max;
			}
		}
	}
	msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
	if (msg_cs & MCG_CS_SEND_ALL_MSG) {
		dbg_send_msg("<1>rdma: send_msg: unexpected MCG_CS_SEND_ALL_MSG: %08x\n",
			msg_cs);
		count_wait_rdm = count_wait_rdm_max;
		WRR(rp->regbase, SHIFT_ES, ES_SM_Ev, (dev_rdma_sem_t *)NULL);
		do {
			msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
			if (msg_cs & MCG_CS_SEND_ALL_MSG) {
				dbg_send_msg("<1>rdma: send_msg: couldn't clear "
					"msg_cs: %08x count_wait_rdm: %x\n", msg_cs, count_wait_rdm);
			} else
				goto check_msf;
		} while (count_wait_rdm--);
		WAIT_RDM
		msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
		if (msg_cs & MCG_CS_SEND_ALL_MSG) {
			dbg_send_msg("<1>rdma: send_msg: couldn't MSG_CS_Msg_Rst "
				"clear MCG_CS_SEND_ALL_MSG: %08x\n", msg_cs);
			pst->send_msg_SD_Msg_0++;
			raw_spin_unlock_irqrestore(&ssmr->lock, flags);
			return -count_read_sm_max;
		}
	}
check_msf:
	if (msg_cs & MSG_CS_MSF_ALL) {
		dbg_send_msg("<1>rdma: send_msg: unexpected MSG_CS_MSF_ALL: %08x\n",
			msg_cs);
		WRR(rp->regbase, SHIFT_ES, ES_MSF_Ev, (dev_rdma_sem_t *)NULL);
		msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
		if (msg_cs & MSG_CS_MSF_ALL) {
			dbg_send_msg("<1>rdma: send_msg: couldn't clear "
				"MSG_CS_MSF_ALL: %08x\n", msg_cs);
			WAIT_RDM
			msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
			if (msg_cs & MSG_CS_SD_Msg) {
				dbg_send_msg("<1>rdma: send_msg: couldn't "
					"MSG_CS_Msg_Rst clear MSG_CS_MSF_ALL: %08x\n",
					msg_cs);
				pst->send_msg_SD_Msg_0++;
				raw_spin_unlock_irqrestore(&ssmr->lock, flags);
				return -count_read_sm_max;
			}
		}
	}
	if ((msg_cs & MSG_CS_DMRCL) == 0) {
		dbg_send_msg("<1>rdma: send_msg: unexpected MSG_CS_DMRCL == 0\n");
		WRR(rp->regbase, SHIFT_MSG_CS, 0x00001000, (dev_rdma_sem_t *)NULL);
		msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
		if ((msg_cs & MSG_CS_DMRCL) == 0) {
			dbg_send_msg("<1>rdma: send_msg: couldn't set MSG_CS_DMRCL\n");
			pst->send_msg_DMRCL_0++;
			raw_spin_unlock_irqrestore(&ssmr->lock, flags);
			return -count_read_sm_max;
		}
	}

	count_read_sm = 0;

	if (cmd == 0)
		WRR(rp->regbase, SHIFT_TDMSG, msg, (dev_rdma_sem_t *)NULL);
	else
		WRR(rp->regbase, SHIFT_MSG_CS, RDR(rp->regbase,
			SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL) | msg, (dev_rdma_sem_t *)NULL);
	while (count_read_sm < count_read_sm_max) {
		count_read_sm++;
		evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL);
		if (evs & ES_MSF_Ev) {
			msg_cs = RDR(rp->regbase, SHIFT_MSG_CS, (dev_rdma_sem_t *)NULL);
			dbg_error("<1>rdma: send_msg: MSF: msg_cs: 0x%08x loop: %x\n",	msg_cs, count_loop_send_msg);
			WRR(rp->regbase, SHIFT_ES, (ES_MSF_Ev | ES_SM_Ev), (dev_rdma_sem_t *)NULL);
			pst->msf++;
			count_loop_send_msg++;
			if (count_loop_send_msg > count_loop_send_msg_max) {
				raw_spin_unlock_irqrestore(&ssmr->lock, flags);
				return -count_loop_send_msg_max;
			} else
				goto repeate_send_msg;
		}
		if (evs & ES_SM_Ev) {
			WRR(rp->regbase, SHIFT_ES, ES_SM_Ev, (dev_rdma_sem_t *)NULL);
			pst->es_sm++;
			raw_spin_unlock_irqrestore(&ssmr->lock, flags);
			return count_read_sm;
		}
	}
	pst->send_msg_CRMAX++;
	raw_spin_unlock_irqrestore(&ssmr->lock, flags);
	return 0;
}

