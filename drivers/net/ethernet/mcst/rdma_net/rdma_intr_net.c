/*
 * Copyright (c) 2011 by MCST.
 * rdma_intr_net.h
 * Implementation of networking protocols TCP\IP via rdma
 */

#include "rdma_user_intf_net.h"
#include "rdma_reg_net.h"
#ifndef CONFIG_E90
#include "asm/apic.h"
#endif
#include <linux/sched/rt.h>


#ifdef BOTTOM_HALF_RX_ANY_SKB
void put_in_steck(struct rdma_tx_desc *pbtx, struct rdma_private *rp, struct sk_buff	*skb);
#else
void	put_in_steck(struct rdma_tx_desc *pbtx, struct rdma_private *rp);
#endif

void	check_msg(unsigned int msg, struct rdma_private *rp);
u32	who_is_locked_spin_rdma;
unsigned long	wake_jiffies;
unsigned long	stop_jiffies;
unsigned int    tmp_waste;

#ifdef BOTTOM_HALF_RX_ANY_SKB
void bottom_half_rx_any_skb(struct rdma_private *rp);
#endif

#ifdef BOTTOM_HALF_RX_REFILL_SKB
void bottom_half_rx_refill_skb(struct rdma_private *rp);
#endif

/* Wait write memory after interrupt RDC */
#ifdef CHECK_MEMORY_E90S
#define TIME_OUT_MEMORY 400
int check_bad_memory(struct rdma_tx_block *ptx, u32 inst)
{
	struct rdma_tx_desc	*pbtx;

	pbtx = &ptx->btx_ring[ptx->fe];
	ptx->bad_end_buf_csum = 0;	
	do {
		event_mem(inst, START_CHECK_MEM_EVENT, (unsigned int)(rdma_gethrtime() >> 32), (unsigned int) rdma_gethrtime() );
		memcpy(&(ptx->end_buf_csum), (pbtx->vaddr + (pbtx->for_rec_trwd & MSG_USER) - sizeof(unsigned int)), sizeof(unsigned int));
		event_mem(inst, START_CHECK_MEM_EVENT, ptx->end_buf_csum, ptx->rx);
		ptx->bad_end_buf_csum++;
	} while ((ptx->end_buf_csum != ptx->rx) && (ptx->bad_end_buf_csum < TIME_OUT_MEMORY) );
	event_mem(inst, STOP_CHECK_MEM_EVENT, ptx->bad_end_buf_csum, (unsigned int) rdma_gethrtime());
	if (ptx->bad_end_buf_csum >= TIME_OUT_MEMORY) 
		return 1;
	return 0;
}
#endif

#ifndef RDMA_INTR_DBG
#define RDMA_INTR_DBG	0
#endif
#define dbg_rdma_intr	if (RDMA_INTR_DBG) printk

#ifdef CONFIG_E90 /* E90 */
irqreturn_t rdma_intr(int irq, void *dev_instance)
#else /* !E90 */
void rdma_interrupt(struct pt_regs *regs)
#endif /* E90 */
{
#ifdef CONFIG_E90 /* E90 */
	struct net_device 	*dev = dev_instance;
	u32			phaddr;
	u32	 		evs_cs;
#else /* !E90 */
#ifdef CONFIG_E90S /* E90S */
	int			node = e90s_cpu_to_node(raw_smp_processor_id());
//	struct net_device	*dev = (struct net_device *)netdev_addr[node];
	struct net_device	*dev;
#endif /* E90S */
#ifdef CONFIG_E2K /* E3S */
	struct net_device	*dev;
	int			node = numa_node_id();
#endif /* E3S */
//	struct net_device	*dev = (struct net_device *)netdev_addr[node];
	u64			phaddr;
 	u32 			reg;
	unsigned int            link = NODE_NUMIOLINKS, i;
#endif /* E90 */
	struct rdma_private	*rp;
	struct stat_rdma	*pst;
	struct net_device_stats	*p_stats;
	struct rdma_tx_block	*ptx;
	struct rdma_tx_desc	*pbtx;
	struct iphdr 		*ipd;
#ifndef BOTTOM_HALF_RX_ANY_SKB
	u32			size_trans;
#endif
	u32 			evs, _evs;
	u32	 		tcs;
	u32 			inst, inst_link;
	u32			cpu = raw_smp_processor_id();

#ifndef CONFIG_E90
	/* Temporarily until a correct definition of link */
	for (i = 0; i < link; i++ ) {
		node = node * NODE_NUMIOLINKS + i;
		for_each_online_rdma(inst_link)
			if ( node == inst_link ) { 
				dev = (struct net_device *)netdev_addr[node];
				goto next;
			}
		continue;
next:
#endif

	rp = netdev_priv(dev);
	inst = rp->inst;
	evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL) ;
	event_intr_start(inst, INTR_START_EVENT, evs, cpu << 16 | 0);
	if (evs == 0) {
#ifdef CONFIG_E90 /* E90 */
		return IRQ_NONE;
#else
		if ( i < (link -1) ) {
			try_work(rp);
			continue;
		} else {
			try_work(rp);
			goto end_rdma_intr;
		}
#endif
	}
	p_stats = &rp->net_stats;
	pst = &rp->stat_rdma;
	pst->rdma_intr++;
#ifdef CONFIG_E90 
	evs_cs = RDR(e_rega[0], SHIFT_CS, (dev_rdma_sem_t *) NULL);
	if (evs_cs & CS_SIE) {
		dbg_error
		    ("rdma_intr(%x): ERROR slave interface evs: 0x%08x\n",
		     inst, evs_cs);
		prn_reg_rdma(rp->regbase);
		WRR(e_rega[0], SHIFT_CS, evs_cs | CS_SIE, (dev_rdma_sem_t *) NULL);	/* break SIE */
		/* Reset all DMA-operations */
		WRR(rp->regbase, SHIFT_DMA_TCS, DMA_TCS_Tx_Rst, 0);
		event_intr(0, INTR_SIE_EVENT, 0, 0);
		WRR(rp->regbase, SHIFT_DMA_RCS, DMA_RCS_Rx_Rst, 0);
		event_intr(0, INTR_SIE_EVENT, 0, 0);
		WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_Msg_Rst,
		    (dev_rdma_sem_t *) NULL);
		pst->cs_sie++;
		prn_puls(rp);
		return IRQ_HANDLED;
	}
#endif 
	tcs = RDR(rp->regbase, SHIFT_DMA_TCS, (dev_rdma_sem_t *)NULL);
	WRR(rp->regbase, SHIFT_ES, evs & MASK_INTR_NET, (dev_rdma_sem_t *)NULL);
	_evs = ~evs;

	/* Channel Master Interface Error*/
	if (evs & ES_CMIE_Ev) {
		dbg_error("rdma_intr(%x): ERROR master interface evs: 0x%08x\n", inst, evs);
		event_intr(inst, INTR_CMIE_EVENT, 0, 0);
		WRR(rp->regbase, SHIFT_ES, evs | ES_CMIE_Ev, (dev_rdma_sem_t *)NULL);
		/* Reset all DMA-operations */
		WRR(rp->regbase, SHIFT_MSG_CS, MSG_CS_Msg_Rst, (dev_rdma_sem_t *)NULL);
		pst->es_cmie++;
		WRR(rp->regbase, SHIFT_DMA_TCS, DMA_TCS_Tx_Rst, 0);
		WRR(rp->regbase, SHIFT_DMA_RCS, DMA_RCS_Rx_Rst, 0);
#ifndef CONFIG_E90 /* !E90 */
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			/* Setting WCode_64*/
			reg = RDR(rp->regbase, SHIFT_DMA_RCS, 0);
			WRR(rp->regbase, SHIFT_DMA_RCS, reg | WCode_64, 0);
			/* Setting RCode_64 and DMA_TCS_DRCL*/
			reg = RDR(rp->regbase, SHIFT_DMA_TCS, 0);
			WRR(rp->regbase, SHIFT_DMA_TCS, reg | RCode_64 | DMA_TCS_DRCL, 0);
		}
#endif
		prn_puls(rp);
#ifdef CONFIG_E90
		return IRQ_HANDLED;
#else
		return;
#endif		
	}

	/* Received ID_Request_Messages*/
	if (evs & ES_RIRM_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RIRM_Ev evs: 0x%08x\n",inst, evs);
		rp->reset = 1;
		stop_rdma[rp->inst] = 1;
		pst->es_rirm++;
		rp->irmsg = 1;
		clear_es(rp, 1);
		evs = RDR(rp->regbase, SHIFT_ES, (dev_rdma_sem_t *)NULL) ;
		evs &= ~ES_RIRM_Ev;
	}

	/* Receiver DMA Complete Event */
	if (evs & ES_RDC_Ev) {
		event_mem(inst, TIME_RDC_EVENT, 0 , 1); 		
		dbg_rdma_intr("rdma_intr(%x): ES_RDC_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rdc++;
		event_intr(inst, INTR_RDC_EVENT, 0, pst->es_rdc);
#ifdef CONFIG_E90
		phaddr = RDR(rp->regbase, SHIFT_DMA_RSA, (dev_rdma_sem_t *) NULL);
#else
		phaddr = 0x0;
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			phaddr = phaddr |  RDR(rp->regbase, SHIFT_DMA_HRSA, (dev_rdma_sem_t *)NULL);
			phaddr = phaddr << 32;
		}
		phaddr = phaddr | RDR(rp->regbase, SHIFT_DMA_RSA, (dev_rdma_sem_t *)NULL);
#endif 
		WRR(rp->regbase, SHIFT_DMA_RCS, DMA_RCS_Rx_Rst, (dev_rdma_sem_t *)NULL);
#ifndef CONFIG_E90
		/*Setting WCode_64*/
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			reg = RDR(rp->regbase, SHIFT_DMA_RCS, 0);
			WRR(rp->regbase, SHIFT_DMA_RCS, reg | WCode_64, 0);
		}
#endif
#ifdef BOTTOM_HALF_RX_ANY_SKB
		rp->phaddr_r = phaddr;
		raw_spin_lock(&rp->thread_lock);
		rp->start_thread = 1; 
		raw_spin_unlock(&rp->thread_lock);
#endif
#ifndef BOTTOM_HALF_RX_ANY_SKB
		ptx = &rp->rt_block;
		/* Close raw_spin_lock on receiver*/
		raw_spin_lock(&ptx->lock);
		ptx->rx++;
		/* Check the status of  receiver*/
		if (ptx->state_rx != SND_READY) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("rdma_intr(%x): rdc ERR pst->es_rdc: 0x%08x ptx->state_rx: 0x%08x num_obmen(ptx->rx): 0x%08x stop_jiffies: %lx\n",
				inst, pst->es_rdc, ptx->state_rx, ptx->rx, stop_jiffies);
			prn_puls(rp);
			goto ES_RDC_Ev_label;
		}
		pbtx = &ptx->btx_ring[ptx->fe];
		stop_jiffies = 0;
		/* Check the phisical address */
		if (phaddr != pbtx->phaddr) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("rdma_intr(%x): rdc ERR: phaddr(0x%llx) != pbtx->phaddr(0x%llx) num_obmen(ptx->rx): 0x%08x %p\n",
				inst, (u64)phaddr, (u64)pbtx->phaddr, ptx->rx, WHO_CHANN(who.who_snd_ready[inst].chann));
			prn_puls(rp);
			goto ES_RDC_Ev_label;
		}
		/* Check the msg */
		if (!(((pbtx->for_rec_trwd & MSG_ABONENT) == MSG_NET_WR) &&
		      ((pbtx->for_rec_trwd & MSG_OPER) == MSG_TRWD))) {
			raw_spin_unlock(&ptx->lock);
			/* Error in msg */
			dbg_error("rdma_intr(%x): rdc ERR: "
				"pbtx->for_rec_trwd: 0x%08x ptx->fe: 0x%08x ptx->stat_rx: 0x%08x num_obm(ptx->rx): 0x%08x ptx: %p\n",
				inst, pbtx->for_rec_trwd, ptx->fe, ptx->state_rx, ptx->rx, ptx);
			prn_puls(rp);
			goto ES_RDC_Ev_label;
		}
		/* Check WASTE_PACKET sender*/
		if (*(u32 *)pbtx->vaddr == WASTE_PACKET) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("rdma_intr(%x): rdc ERR: rec waste packet "
				"pbtx->for_rec_trwd: 0x%08x ptx->fe: 0x%08x ptx->stat_rx: 0x%08x num_obm(ptx->rx): 0x%08x ptx: %p\n",
				inst, pbtx->for_rec_trwd, ptx->fe, ptx->state_rx, ptx->rx, ptx);
			prn_puls(rp);
			pst->rdc_waste++;
			goto try_send_msg;
		}
		/* Check WASTE_PACKET reciver*/
		if (*(u32 *)pbtx->vaddr == WASTE_PACKET_) {
			while (*(u32 *)pbtx->vaddr == WASTE_PACKET_) {
				tmp_waste = *((u32 *)pbtx->vaddr + 1);
				udelay(1);
			}
		}
#ifdef CHECK_MEMORY_E90S
		/* Wait write memory */
		if (check_bad_memory(ptx, inst)) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("rdma_intr(%x): check mem pbtx->for_rec_trwd: 0x%08x end_buf_csum: 0x%08x ptx->rx: 0x%08x\n", inst, pbtx->for_rec_trwd, ptx->end_buf_csum, ptx->rx);
			prn_puls(rp);
			goto ES_RDC_Ev_label;
		}
#endif
		/* Write to stack the packet*/
		put_in_steck(pbtx, rp);
		p_stats->rx_packets++;
		size_trans = allign_dma(pbtx->for_rec_trwd & MSG_USER);
		p_stats->rx_bytes += size_trans;
		rdc_byte[inst] += size_trans;
		if (rdc_byte[inst] >> 10) {
			pst->rdc_kbyte += rdc_byte[inst] >> 10;
			rdc_byte[inst] = 0;
		}
		*(u32 *)pbtx->vaddr = WASTE_PACKET_;
		pbtx->for_rec_trwd = 0;
#ifdef BOTTOM_HALF_RX_REFILL_SKB 
		ptx->fe = TX_NEXT(ptx->fe); ptx->avail--; pst->tx_avail = ptx->avail;
		pbtx->addr = NULL;
		if ( ptx->avail < 1 ) 	{
			raw_spin_unlock(&ptx->lock);
			raw_spin_lock(&rp->thread_lock);
			rp->start_thread = 1; 
			raw_spin_unlock(&rp->thread_lock);
			wake_up_process(rp->rdma_rx_tsk);
			event_queue(rp->inst, NET_QUEUE_FULL_EVENT, 0, ptx->avail); 
			goto try_send_msg;
		} else {
			ptx->state_rx = 0;
		}
#else
		ptx->state_rx = 0;
#endif
		raw_spin_unlock(&ptx->lock);
try_send_msg:
ES_RDC_Ev_label:
#else
		wake_up_process(rp->rdma_rx_tsk);
#endif 

		evs = evs & ~ES_RDC_Ev;
	}
	/* Received GP0_Message*/
	if (evs & ES_RGP0M_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RGP0M_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rgp0++;
		evs &= ~ES_RGP0M_Ev;
	}

	/* Received GP1_Message*/
	if (evs & ES_RGP1M_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RGP1M_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rgp1++;
	}

	if ((evs & ES_DSF_Ev) && (evs & ES_TDC_Ev)) {
		dbg_error("rdma_intr(%x): DSF && TDC evs: 0x%08x\n", inst, evs);
	}

	/*Data send Failed*/
	if (evs & ES_DSF_Ev) {
		p_stats->collisions++;

#ifdef CONFIG_E90 /* E90 */
		phaddr = RDR(rp->regbase, SHIFT_DMA_TSA, (dev_rdma_sem_t *) NULL);
#else /* !E90 */
		phaddr = 0x0; 
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			phaddr = phaddr | RDR(rp->regbase, SHIFT_DMA_HTSA, (dev_rdma_sem_t *)NULL) ;
			phaddr = phaddr << 32;
		}
		phaddr = phaddr | RDR(rp->regbase, SHIFT_DMA_TSA, (dev_rdma_sem_t *)NULL);
#endif /* E90 */

		dbg_error("rdma_intr(%x): DSF: ph: 0x%llx tcs: 0x%08x\n",
			inst, (u64)phaddr, tcs);
		WRR(rp->regbase, SHIFT_DMA_TCS, DMA_TCS_Tx_Rst, (dev_rdma_sem_t *)NULL);
		pst->es_dsf++;
		if (tcs & DMA_TCS_DPS_Err)
			pst->dma_tcs_dps_err++;
		else
		if (tcs & DMA_TCS_DPCRC_Err)
			pst->dma_tcs_dpcrc_err++;
		else
		if (tcs & DMA_TCS_DPTO_Err)
			pst->dma_tcs_dpto_err++;
		else
		if (tcs & DMA_TCS_DPID_Err)
			pst->dma_tcs_dpid_err++;
		if (evs & ES_TDC_Ev) {
			pst->es_dsf_tdc++;
		}
	}

	/*Transmitter DMA Complete*/
	if (evs & ES_TDC_Ev) {
		event_mem(inst, TIME_TDC_EVENT, 0 , 1); 		
		dbg_rdma_intr("rdma_intr(%x): ES_TDC_Ev evs: 0x%08x\n",inst, evs);
		pst->es_tdc++;
#ifdef CONFIG_E90 /* E90 */
		phaddr = RDR(rp->regbase, SHIFT_DMA_TSA, (dev_rdma_sem_t *) NULL);
#else
		phaddr = 0x0; 
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			phaddr = phaddr | RDR(rp->regbase, SHIFT_DMA_HTSA, (dev_rdma_sem_t *)NULL);
			phaddr = phaddr << 32;
		}
		phaddr = phaddr | RDR(rp->regbase, SHIFT_DMA_TSA, (dev_rdma_sem_t *)NULL);
#endif /* E90 */
		WRR(rp->regbase, SHIFT_DMA_TCS, DMA_TCS_Tx_Rst, (dev_rdma_sem_t *)NULL);
#ifndef CONFIG_E90 /* E90 */
		/* Setting RCode_64*/
		if (HAS_MACHINE_E2K_FULL_SIC) { /*E3S & E90S*/
			reg = RDR(rp->regbase, SHIFT_DMA_TCS, 0);
			WRR(rp->regbase, SHIFT_DMA_TCS, reg | RCode_64 | DMA_TCS_DRCL, 0);
		}
#endif /* E90 */

		ptx = &rp->tx_block;
		raw_spin_lock(&ptx->lock);
//		ptx->tx++;
		if (ptx->state_tx != T_DMA) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("rdma_intr(%x): tdc ERR: ptx->state_tx: 0x%08x num_obm(ptx->tx): 0x%08x ptx: %p\n",
				inst, ptx->state_tx, ptx->tx, ptx);
			prn_puls(rp);
			goto ES_TDC_Ev_label;
		}
		pbtx = &ptx->btx_ring[ptx->fb];
		ipd = (struct iphdr *)(
#ifdef CONFIG_E90 /* E90 */
					(u32)
#else /* !E90 */
					(u64)	
#endif /* E90 */
					pbtx->vaddr + sizeof (struct ethhdr)); 

		event_intr(inst, INTR_TDC_EVENT, 0, 0);

		/* Check the msg */
		if (!(((pbtx->for_snd_trwd & MSG_ABONENT) == MSG_NET_WR) &&
		      ((pbtx->for_snd_trwd & MSG_OPER) == MSG_TRWD))) {
			raw_spin_unlock(&ptx->lock);
			/* Error in  msg */
			dbg_error("rdma_intr(%x): tdc ERR: "
				"pbtx->for_snd_trwd: 0x%08x num_obm(ptx->tx): 0x%08x ptx: %p\n",
				inst, pbtx->for_snd_trwd, ptx->tx, ptx);
			prn_puls(rp);
			goto ES_TDC_Ev_label;
		}
		p_stats->tx_packets++;
		p_stats->tx_bytes += pbtx->for_snd_trwd & MSG_USER;
		ptx->temp_obmen	+= pbtx->for_snd_trwd & MSG_USER;	
		*(u32 *)pbtx->vaddr = WASTE_PACKET;
		ptx->fb = TX_NEXT(ptx->fb); ptx->avail++;
		dev_kfree_skb_irq(pbtx->addr); /* dev_kfree_skb_any(pbtx->addr); */
#ifdef BOTTOM_HALF_RX_REFILL_SKB
		pbtx->skb_in_steck_for_free = 1;
#endif
		if (ptx->avail > TX_RING_SIZE) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("rdma_intr(%x): tdc ERR: ptx->avail: (0x%08x) > TX_RING_SIZE\n",
				inst, ptx->avail);
			prn_puls(rp);
			goto ES_TDC_Ev_label;
		}
		pst->tx_avail = ptx->avail;
		if (netif_queue_stopped(dev))
			if (ptx->avail > TX_RING_SIZE / 2 ) { 
				netif_wake_queue(dev);
				pst->stop_wake_queue = 1;
				pst->wake_queue++;
				wake_jiffies = jiffies;
				ptx->temp_obmen = 0;
				event_queue_net(rp->inst, NET_QUEUE_START_EVENT, ptx->avail, p_stats->tx_bytes);
			}
		pbtx->for_snd_trwd = 0;
		ptx->state_tx = 0;
		ptx->stat_tx_jiffies = jiffies;
		raw_spin_unlock(&ptx->lock);
ES_TDC_Ev_label:;
	}

	/*Receiver DMA Complete*/
	if (evs & ES_RDM_Ev) {
		int	rdmc = (evs & ES_RDMC)>>27;
		int	msg;
		dbg_rdma_intr("rdma_intr(%x): ES_RDM_Ev evs: 0x%08x\n",inst, evs);

		pst->es_rdm++;
		rp->irmsg = 1;

		if (rdmc == 0)
			rdmc = 32;
		while (rdmc--) {	/* rdmc > 1 ? */
			msg = RDR(rp->regbase, SHIFT_RDMSG, (dev_rdma_sem_t *)NULL);
			check_msg(msg, rp);
			pst->rdm++;
		}
		evs = evs & ~ES_RDM_Ev;
	}

	/* Received GP3_Message*/
	if (evs & ES_RGP3M_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RGP3M_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rgp3++;
		evs &= ~ES_RGP3M_Ev;
	}

	/* Received GP2_Message*/
	if (evs & ES_RGP2M_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RGP2M_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rgp2++;
		evs &= ~ES_RGP2M_Ev;
	}

	/* Received Lock_Message*/
	if (evs & ES_RLM_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RLM_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rlm++;
		evs &= ~ES_RLM_Ev;
	}

	/* Received UnLock_Message*/
	if (evs & ES_RULM_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RULM_Ev evs: 0x%08x\n",inst, evs);
		pst->es_rulm++;
		evs &= ~ES_RULM_Ev;
	}

	/* ID_Answer*/
	if (evs & ES_RIAM_Ev) {
		dbg_rdma_intr("rdma_intr(%x): ES_RIAM_Ev evs: 0x%08x\n",inst, evs);
		pst->es_riam++;
		rp->iamsg = 1;
		evs &= ~ES_RIAM_Ev;
	}
#ifndef CONFIG_E90
	try_work(rp);
	}
end_rdma_intr:
#endif
//	try_work(rp);
	event_intr_start(inst, INTR_START_EVENT, evs, cpu << 16 | 1);
#ifdef CONFIG_E90 /* E90*/
	try_work(rp);
	return IRQ_HANDLED;
#else
	return;
#endif /* !E90*/
}

#ifndef CHECK_MSG_DBG
#define CHECK_MSG_DBG	0
#endif
#define dbg_check_msg	if (CHECK_MSG_DBG) printk
void check_msg(unsigned int msg, struct rdma_private *rp)
{
	struct stat_rdma	*pst;
	struct rdma_tx_block	*ptx;
	struct rdma_tx_desc	*pbtx;
	struct net_device_stats *p_stats;
	u32			inst;
	unsigned int		size_trans;
#ifndef CONFIG_E90 
	unsigned int 		reg;
#endif
	inst = rp->inst;
	pst = &rp->stat_rdma;
	p_stats = &rp->net_stats;

	dbg_check_msg("check_msg(%x): start  msg: 0x%08x rp: %p  pst: %p \n", inst, msg, rp, pst);
	rec_msg[inst][fe_rec_msg[inst]] = msg;
	fe_rec_msg[inst] = NEXT_REC_MSG(fe_rec_msg[inst]);

	if ((msg & MSG_OPER) == MSG_TRWD) {
		pst->trwd++;
		ptx = &rp->rt_block;
		raw_spin_lock(&ptx->lock);
		if (ptx->rec_trwd_tx) {
			dbg_error("rdma_intr(%x): WARNING: received TRWD, but ptx->rec_trwd_tx: 0x%08x is not 0\n", inst, ptx->rec_trwd_tx);
		}
		ptx->rec_trwd_tx = msg;
		raw_spin_unlock(&ptx->lock);
	} else
	if ((msg & MSG_OPER) == MSG_READY) {
		pst->ready++;
		ptx = &rp->tx_block;
		raw_spin_lock(&ptx->lock);
		if (ptx->state_tx == 0) {
			raw_spin_unlock(&ptx->lock);
			dbg_error("check_msg(%x): pst->ready: 0x%08x ERR: T_DMA, but rec MSG_READY: 0x%08x\n",
				inst, pst->ready, msg);
			prn_puls(rp);
			goto end_check_msg;
		}
//		size_trans = allign_dma(msg & MSG_USER);
		/* Set T_DMA*/
		ptx->rec_ready++;
		ptx->state_tx = REC_READY;
		ptx->stat_tx_jiffies = jiffies;
		pbtx = &ptx->btx_ring[ptx->fb];
		size_trans = allign_dma(pbtx->for_snd_trwd & MSG_USER);
		if (size_trans != allign_dma(msg & MSG_USER)) {
			raw_spin_unlock(&ptx->lock);
			/*Error size exchange*/
			dbg_error("check_msg(%x): ERR: MSG_READY, but size_trans(0x%08x) != (msg & MSG_USER)(0x%08x) "
				"ptx->snd_trwd: 0x%08x ptx->rec_ready: 0x%08x num_obm(ptx->tx): 0x%08x ptx: %p\n",
				inst, size_trans, (msg & MSG_USER), ptx->snd_trwd, ptx->rec_ready, ptx->tx, ptx);
			prn_puls(rp);
			goto end_check_msg;
		}
		/* size add */
///>>>>>> size add
		if ((pbtx->for_snd_trwd & MSG_USER) < 0x200 )
			size_trans = allign_dma((pbtx->for_snd_trwd & MSG_USER) + 0x200);

		dbg_check_msg("check_msg(%x): try T_DMA: READY: 0x%08x ph: 0x%llx ptx->fb: 0x%08x ptx->snd_trwd: 0x%08x ptx->rec_ready: 0x%08x ptx->tx: 0x%08x ptx: %p\n", inst, msg, (u64)pbtx->phaddr, ptx->fb, ptx->snd_trwd, ptx->rec_ready, ptx->tx, ptx);
		ptx->state_tx = T_DMA;
		ptx->stat_tx_jiffies = jiffies;
		WRR(rp->regbase, SHIFT_DMA_TSA, (unsigned int) pbtx->phaddr, 0);
#ifndef CONFIG_E90 /* !E90*/
		if (HAS_MACHINE_E2K_FULL_SIC)  /*E3S & E90S*/
			WRR(rp->regbase, SHIFT_DMA_HTSA, (unsigned int) (pbtx->phaddr >> 32) , 0);
#endif /* !E90*/
		WRR(rp->regbase, SHIFT_DMA_TBC, size_trans, 0);
		event_mem(inst, TIME_TDC_EVENT, size_trans , 0); 		
#ifdef CONFIG_E90 /* E90*/
		WRR(rp->regbase, SHIFT_DMA_TCS, DMA_TCS_TE | DMA_TCS_TCO | DMA_TCS_DRCL, 0);
#else /* !E90*/
		reg = RDR(rp->regbase, SHIFT_DMA_TCS, (dev_rdma_sem_t *)NULL);
		WRR(rp->regbase, SHIFT_DMA_TCS,reg | DMA_TCS_TE | DMA_TCS_DRCL, 0);
#endif /* E90*/
		pst->try_TDMA++;
		raw_spin_unlock(&ptx->lock);
	} else {
		dbg_error("check_msg(%x): unknown msg: 0x%08x\n", inst, msg);
	}
end_check_msg:
	dbg_check_msg("check_msg(%x): end msg:0x%08x\n", inst, msg);
	return;
}

#ifndef PUT_IN_STECK_DBG
#define PUT_IN_STECK_DBG	0
#endif
#define dbg_put_in_steck	if (PUT_IN_STECK_DBG) printk

#ifndef BOTTOM_HALF_RX_ANY_SKB
void	put_in_steck(struct rdma_tx_desc *pbtx, struct rdma_private *rp)
#else
void put_in_steck(struct rdma_tx_desc *pbtx, struct rdma_private *rp, struct sk_buff	*skb)
#endif
{
#ifndef BOTTOM_HALF_RX_ANY_SKB
	struct sk_buff		*skb;
#endif
	struct stat_rdma	*pst;
	u32			len;
	int			res;
	u32			inst = rp->inst;
	struct rdma_tx_block	*ptx; 		

	dbg_put_in_steck("put_in_steck(%x): start\n", inst);
	if ( pbtx->for_rec_trwd ==  0 )	{
		dbg_error("put_in_steck(%x): pbtx->for_rec_trwd == 0. \n", inst);
		return;
	}
#ifdef CHECK_MEMORY_E90S
	len = (pbtx->for_rec_trwd & MSG_USER) - sizeof(unsigned int);
#else
	len = pbtx->for_rec_trwd & MSG_USER;
#endif
	ptx = &rp->rt_block; 			
	pst = &rp->stat_rdma;
#ifndef BOTTOM_HALF_RX_THREAD_RDMA
	who_locked_free_skb = 1;
	raw_spin_unlock(&ptx->lock);		/// muw raw_spinlock
	skb = dev_alloc_skb(len + 2); 		
	raw_spin_lock(&ptx->lock);   		/// muw raw_spinlock
	who_locked_free_skb = 0;
#else
#ifdef BOTTOM_HALF_RX_REFILL_SKB
	skb = pbtx->addr;
#endif
#endif
	if (skb == NULL) {
		dbg_error("put_in_steck(%x): "
			"Memory squeeze, deferring packet( for len: 0x%08x, try skbs_rdma ).\n", inst, len);
		return;
	}
	skb->dev = rp->dev;
	skb_reserve(skb, 2); 			
	skb_put(skb, len);	
	event_mem(inst, SKB_COPY_EVENT, len , 0);
	skb_copy_to_linear_data(skb, pbtx->vaddr, len);	
	event_mem(inst, SKB_COPY_EVENT, len , 1);
	skb->protocol = eth_type_trans(skb, rp->dev);
	skb->ip_summed = CHECKSUM_UNNECESSARY;
	rp->dev->last_rx = jiffies;
	res = netif_rx(skb);
	switch (res) {
	case NET_RX_SUCCESS:
		break;
/* 
	case NET_RX_CN_LOW:
		pst->net_rx_cn_low++;
		break;
	case NET_RX_CN_MOD:
		pst->net_rx_cn_mod++;
		break;
	case NET_RX_CN_HIGH:
		pst->net_rx_cn_high++;
		break;
*/
	case NET_RX_DROP:
//-		pst->net_rx_cn_drop++;
		rp->dev->stats.rx_dropped++;
		break;
	default:
		dbg_error("puting_in_steck(%x): netif_rx default: res: %d\n", inst, res);
	}
#if AOE_DBG
	printk("tx(%x) ptx->tx: 0x%08x: len 0x%08x\n"
		"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n"
		"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n"
		"%08x.%08x.%08x.%08x.%08x.%08x.%08x.%08x\n",
		inst, ptx->tx, pbtx->for_snd_trwd & MSG_USER,
		*((u32 *)pbtx->vaddr+ 0), *((u32 *)pbtx->vaddr+ 1),
		*((u32 *)pbtx->vaddr+ 2), *((u32 *)pbtx->vaddr+ 3),
		*((u32 *)pbtx->vaddr+ 4), *((u32 *)pbtx->vaddr+ 5),
		*((u32 *)pbtx->vaddr+ 6), *((u32 *)pbtx->vaddr+ 7),
		*((u32 *)pbtx->vaddr+ 8), *((u32 *)pbtx->vaddr+ 9),
		*((u32 *)pbtx->vaddr+10), *((u32 *)pbtx->vaddr+11),
		*((u32 *)pbtx->vaddr+12), *((u32 *)pbtx->vaddr+13),
		*((u32 *)pbtx->vaddr+14), *((u32 *)pbtx->vaddr+15),
		*((u32 *)pbtx->vaddr+16), *((u32 *)pbtx->vaddr+17),
		*((u32 *)pbtx->vaddr+18), *((u32 *)pbtx->vaddr+19),
		*((u32 *)pbtx->vaddr+20), *((u32 *)pbtx->vaddr+21),
		*((u32 *)pbtx->vaddr+22), *((u32 *)pbtx->vaddr+23));
#endif
	dbg_put_in_steck("put_in_steck(%x): netif_rx(): 0x%x\n", inst, res);
	return;
}

#ifndef TRY_SEND_READY_DBG
#define TRY_SEND_READY_DBG	0
#endif
#define dbg_try_send_ready	if (TRY_SEND_READY_DBG) printk
int try_send_ready(struct rdma_private *rp)
{
	struct rdma_tx_block	*ptx;
	struct rdma_tx_desc	*pbtx;
	struct stat_rdma	*pst;
	u32			size_trans;
	u32			sending_msg;
	u32			ret_smsg;
	u32			inst;
#ifndef CONFIG_E90 
	u32	 		reg;
#endif
	unsigned long 		flags;

	inst = rp->inst;
	if (stop_rdma[inst]) {
		return 0;
	}
	ptx = &rp->rt_block;
	raw_spin_lock_irqsave(&ptx->lock, flags);
	event_queue_net(inst, TRY_SEND_READY_EVENT, 0 , ptx->avail);
	dbg_try_send_ready("try_send_ready(%x): start ptx->rec_trwd_tx: 0x%08x ptx->state_rx: 0x%08x\n", inst, ptx->rec_trwd_tx, ptx->state_rx);
	if (ptx->rec_trwd_tx == 0) {
		event_queue_net(inst, TRY_SEND_READY_EVENT, 1 , ptx->avail);
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		return 0;
	}
	/* For second trwd */
	if ((ptx->rec_trwd_tx) && (ptx->state_rx == SND_READY)) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		return 0;
    	}
	pst = &rp->stat_rdma;

	if (PTX_BUFFS_AVAIL != ptx->avail) {
		/* Error!!! Separated counters */ 
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		dbg_error("try_send_ready(%x): ERR: PTX_BUFFS_AVAIL(0x%08x) != ptx->avail(0x%08x) "
			"ptx->fe: 0x%08x ptx->fb: 0x%08x num_obm(ptx->rx): 0x%08x\n",
			inst, PTX_BUFFS_AVAIL, ptx->avail, ptx->fe, ptx->fb, ptx->rx);
		prn_puls(rp);
	}
	if (!ptx->avail) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		dbg_try_send_ready("try_send_ready(%x): ptx->avail(0x%08x) < 2 ptx->fe: 0x%08x ptx->fb: 0x%08x num_obm(ptx->rx): 0x%08x\n",
			inst, ptx->avail, ptx->fe, ptx->fb, ptx->rx);
		return 0;
	}
	/*Shifting for RDC*/
	pbtx = &ptx->btx_ring[ptx->fe];
	/* Must be free*/
	dbg_try_send_ready("try_send_ready(%x): ptx->avail(0x%08x), "
			"but pbtx->for_rec_trwd: 0x%08x ptx->fe: 0x%08x ptx->frx: 0x%08x ptx->state_rx: 0x%08x num_obm(ptx->rx): 0x%08x\n",
			inst, ptx->avail, pbtx->for_rec_trwd, ptx->fe, ptx->frx, ptx->state_rx, ptx->rx);

	if (pbtx->for_rec_trwd) {
		/* Error. Must be free*/
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		dbg_error("try_send_ready(%x): ERR: ptx->avail(0x%08x), "
			"but pbtx->for_rec_trwd: 0x%08x ptx->fe: 0x%08x ptx->frx: 0x%08x ptx->state_rx: 0x%08x num_obm(ptx->rx): 0x%08x\n",
			inst, ptx->avail, pbtx->for_rec_trwd, ptx->fe, ptx->frx, ptx->state_rx, ptx->rx);
		prn_puls(rp);
		return -1;
	}
	pbtx->for_rec_trwd = ptx->rec_trwd_tx;
	ptx->rec_trwd_tx = 0;
	if (!(((pbtx->for_rec_trwd & MSG_ABONENT) == MSG_NET_WR) &&
	      ((pbtx->for_rec_trwd & MSG_OPER) == MSG_TRWD))) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		/* Error in msg */
		dbg_error("try_send_ready(%x): ERR: "
			"pbtx->for_rec_trwd: 0x%08x ptx->fe: 0x%08x ptx->stat_rx: 0x%08x num_obm(ptx->rx): 0x%08x\n",
			inst, pbtx->for_rec_trwd, ptx->fe, ptx->state_rx, ptx->rx);
		prn_puls(rp);
		pbtx->for_rec_trwd = 0;
		return -1;
	}
	size_trans = allign_dma(pbtx->for_rec_trwd & MSG_USER);
	/*Programming's  RDMA */
	sending_msg = (pbtx->for_rec_trwd & ~MSG_ABONENT) | MSG_NET_RD;
	sending_msg = (sending_msg & ~MSG_OPER) | MSG_READY;
	ptx->state_rx = R_DMA;
	WRR(rp->regbase, SHIFT_DMA_RSA, (unsigned int) pbtx->phaddr, (dev_rdma_sem_t *)NULL);
#ifndef CONFIG_E90 /* !E90*/
		if (HAS_MACHINE_E2K_FULL_SIC)  /*E3S & E90S*/
			WRR(rp->regbase, SHIFT_DMA_HRSA, (unsigned int) (pbtx->phaddr >> 32), (dev_rdma_sem_t *)NULL); 
#endif /* !E90*/
///>>>>>> size add
	if ((pbtx->for_rec_trwd & MSG_USER) < 0x200 )
		size_trans = allign_dma((pbtx->for_rec_trwd & MSG_USER) + 0x200);

	WRR(rp->regbase, SHIFT_DMA_RBC, size_trans, (dev_rdma_sem_t *)NULL);
#ifdef CONFIG_E90 /* E90*/
	WRR(rp->regbase, SHIFT_DMA_RCS, DMA_RCS_RCO | DMA_RCS_RE,(dev_rdma_sem_t *) NULL);
#else /* !E90*/
	reg = RDR(rp->regbase, SHIFT_DMA_RCS, (dev_rdma_sem_t *)NULL); 
	WRR(rp->regbase, SHIFT_DMA_RCS, reg | DMA_RCS_RE | DMA_RCS_RCO, (dev_rdma_sem_t *)NULL);
#endif /* E90*/
	/* Send  READY */
	ptx->state_rx = SND_READY;
	ptx->snd_ready++;

	rec_msg[inst][fe_rec_msg[inst]] = sending_msg;
	fe_rec_msg[inst] = NEXT_REC_MSG(fe_rec_msg[inst]);

	ret_smsg = send_msg(rp, sending_msg, inst, 0);
	dbg_try_send_ready("try_send_ready(%x): ptx->snd_ready: 0x%08x sending_msg: 0x%08x ph: 0x%llx ptx->rec_trwd: 0x%08x ptx->snd_ready: 0x%08x ptx->fe: 0x%08x ptx: %p\n", inst,
		ptx->snd_ready, sending_msg, (u64)pbtx->phaddr, ptx->rec_trwd, ptx->snd_ready, ptx->fe, ptx);
	if (ret_smsg <= 0) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		dbg_error("try_send_ready(%x): ERR: ret_smsg: 0x%08x for MSG_READY ptx->rec_trwd: 0x%08x ptx->snd_ready: 0x%08x num_obm(ptx->rx): 0x%08x\n",
			inst, ret_smsg, ptx->rec_trwd, ptx->snd_ready, ptx->rx);
		prn_puls(rp);
		return -1;
	}
	event_queue_net(inst, TRY_SEND_READY_EVENT, 1 , ptx->avail);
	event_mem(inst, TIME_RDC_EVENT, pbtx->for_rec_trwd & MSG_USER , 0);
	raw_spin_unlock_irqrestore(&ptx->lock, flags);
	dbg_try_send_ready("try_send_ready(%x): stop ptx->state_rx: 0x%08x\n", inst, ptx->state_rx);
	return 1;
}

#ifndef TRY_SEND_TRWD_DBG
#define TRY_SEND_TRWD_DBG	0
#endif
#define dbg_try_send_trwd	if (TRY_SEND_TRWD_DBG) printk
int try_send_trwd(struct rdma_private *rp) 
{
	struct rdma_tx_desc	*pbtx;
	struct rdma_tx_block	*ptx;
	struct stat_rdma	*pst;
	u32			sending_msg;
	u32			ret_smsg;
	u32			inst;
	unsigned long		flags;

	inst = rp->inst;
	if (stop_rdma[inst]) {
		return 0;
	}
	ptx = &rp->tx_block;
	pst = &rp->stat_rdma;
	raw_spin_lock_irqsave(&ptx->lock, flags);
	event_queue_net(inst, TRY_SEND_TRWD_EVENT, 0 , ptx->avail);
	dbg_try_send_trwd("try_send_trwd(%x): pbtx->for_snd_trwd "
				"ptx->fe: 0x%08x ptx->fb: 0x%08x ptx->fb: 0x%08x ptx->state_tx 0x%08x \n",
				inst, ptx->fe, ptx->fb, ptx->avail, ptx->state_tx);
	/* set SND_TRWD at send, null at TDC */
	if (ptx->state_tx) {
		event_queue_net(inst, TRY_SEND_TRWD_EVENT, 1 , ptx->avail);
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		return 0;
	}
	pbtx = &ptx->btx_ring[ptx->fb];
  	if (pbtx->for_snd_trwd == 0) {
		if (ptx->fb != ptx->fe) {
		    dbg_error("try_send_trwd(%x): ERR: pbtx->for_snd_trwd == 0, "
		   "but ptx->fe != ptx->fb ptx->fe: 0x%08x ptx->fb: 0x%08x ptx->avail: 0x%08x\n",
		   inst, ptx->fe, ptx->fb, ptx->avail);
	 	   raw_spin_unlock_irqrestore(&ptx->lock, flags);
	 	   prn_puls(rp);
	 	   return -1;
		}
		if (ptx->avail != TX_RING_SIZE) {
		    dbg_error("try_send_trwd(%x): ERR: pbtx->for_snd_trwd == 0, "
		   "but ptx->avail != TX_RING_SIZE ptx->fe: 0x%08x ptx->fb: 0x%08x ptx->avail: 0x%08x\n",
		   inst, ptx->fe, ptx->fb, ptx->avail);
		    raw_spin_unlock_irqrestore(&ptx->lock, flags);
		    prn_puls(rp);
		    return -1;
		}
		event_queue_net(inst, TRY_SEND_TRWD_EVENT, 1 , ptx->avail);
		raw_spin_unlock_irqrestore(&ptx->lock, flags);	
		return 0;
	}
	if (!(((pbtx->for_snd_trwd & MSG_ABONENT) == MSG_NET_WR) &&
	      ((pbtx->for_snd_trwd & MSG_OPER) == MSG_TRWD))) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		dbg_error("try_send_trwd(%x): ERR: pbtx->msg: 0x%08x ptx->fe: 0x%08x ptx->frx: 0x%08x ptx->stat_tx: 0x%08x num_obm(ptx->tx): 0x%08x\n",
			inst, pbtx->for_snd_trwd, ptx->fe, ptx->frx, ptx->state_tx, ptx->tx);
		prn_puls(rp);
		return -1;
	}

	sending_msg = pbtx->for_snd_trwd;
	ptx->state_tx = SND_TRWD;
	ptx->stat_tx_jiffies = jiffies;
	ptx->snd_trwd++;
	rec_msg[inst][fe_rec_msg[inst]] = sending_msg;
	fe_rec_msg[inst] = NEXT_REC_MSG(fe_rec_msg[inst]);
	ret_smsg = send_msg(rp, sending_msg, inst, 0);
	if (ret_smsg <= 0) {
		raw_spin_unlock_irqrestore(&ptx->lock, flags);
		dbg_error("try_send_trwd(%x): ERR: ret_smsg: 0x%08x ptx->snd_trwd: 0x%08x num_obm(ptx->tx): 0x%08x\n",
			inst, ret_smsg, ptx->snd_trwd, ptx->tx);
		prn_puls(rp);
		return -1;
	}
	event_queue_net(inst, TRY_SEND_TRWD_EVENT, 1 , sending_msg);
	raw_spin_unlock_irqrestore(&ptx->lock, flags);
	dbg_try_send_trwd("try_send_trwd(%x): stop ptx->state_tx: 0x%08x\n ", inst, ptx->state_tx);
	return 1;
}

void try_work(struct rdma_private *rp)
{
	try_send_ready(rp);
	try_send_trwd(rp);
}

#ifdef BOTTOM_HALF_RX_ANY_SKB
#ifndef DBG_BOTTOM_HALF_RX_ANY_SKB
#define DBG_BOTTOM_HALF_RX_ANY_SKB 	0
#endif
#define dbg_rx_any_skb	if (DBG_BOTTOM_HALF_RX_ANY_SKB) printk
void bottom_half_rx_any_skb(struct rdma_private *rp)
{
	struct rdma_tx_block	*ptx;
	struct rdma_tx_desc	*pbtx;
	struct stat_rdma	*pst;
	struct net_device_stats	*p_stats = &rp->net_stats;
	struct sk_buff		*skb;
	u32 			inst;
	u32			size_trans;
	unsigned long 		flags;

	dbg_rx_any_skb("bottom_half_rx_any_skb: start \n");

	skb = dev_alloc_skb(SIZE_MTU_DEV + 2);
	ptx = &rp->rt_block;
	raw_spin_lock_irqsave(&ptx->lock, flags);
	ptx->rx++;
	pbtx = &ptx->btx_ring[ptx->fe];
/*
#ifdef CHECK_MEMORY_E90S
	len = (pbtx->for_rec_trwd & MSG_USER) - sizeof(unsigned int);
#else
	len = pbtx->for_rec_trwd & MSG_USER;
#endif
	raw_spin_unlock_irqrestore(&ptx->lock,  flags);
	who_locked_free_skb = 1;
	skb = dev_alloc_skb(len+2);
	who_locked_free_skb = 0;
	raw_spin_lock_irqsave(&ptx->lock, flags);
*/

	inst = rp->inst;
	/* Close raw_spin_lock on receiver*/
	pst = &rp->stat_rdma;
	event_intr(inst, INTR_RDC_EVENT, 0, 0);
	dbg_rx_any_skb("bottom_half_rx_any_skb: rdc(%x) 0x%08x\n", inst, pst->es_rdc);
	/* Check the status of  receiver*/
	if (ptx->state_rx != SND_READY) {
		raw_spin_unlock_irqrestore(&ptx->lock,  flags);
		dbg_error("bottom_half_rx_any_skb(%x 0x%x): rdc ERR: ptx->state_rx: 0x%08x 0x%08x %lx\n",inst, pst->es_rdc, ptx->state_rx, ptx->rx, stop_jiffies);
		prn_puls(rp);
		goto ES_RDC_Ev_label;
	}
	stop_jiffies = 0;
	/* Check the phisical address */
	if (rp->phaddr_r != pbtx->phaddr) {
		raw_spin_unlock_irqrestore(&ptx->lock,  flags);
		dbg_error("bottom_half_rx_any_skb(%x): rdc ERR: phaddr(0x%llx) != pbtx->phaddr(0x%llx) num_obmen: 0x%u %p\n",
			inst, rp->phaddr_r, pbtx->phaddr, ptx->rx, WHO_CHANN(who.who_snd_ready[inst].chann));
			prn_puls(rp);
		goto ES_RDC_Ev_label;
	}
	/* Check the msg */
	if (!(((pbtx->for_rec_trwd & MSG_ABONENT) == MSG_NET_WR) &&
	      ((pbtx->for_rec_trwd & MSG_OPER) == MSG_TRWD))) {
		raw_spin_unlock_irqrestore(&ptx->lock,  flags);
		/* Error in msg */
		dbg_error("bottom_half_rx_any_skb(%x): rdc ERR: "
			"pbtx->msg: 0x%x fe: %x stat_rx: %x num_obm: 0x%x %p\n",
			inst, pbtx->for_rec_trwd, ptx->fe, ptx->state_rx, ptx->rx, ptx);
		prn_puls(rp);
		goto ES_RDC_Ev_label;
	}
	/* Check WASTE_PACKET */
	if (*(u32 *)pbtx->vaddr == WASTE_PACKET) {
		raw_spin_unlock_irqrestore(&ptx->lock,  flags);
		dbg_error("bottom_half_rx_any_skb(%x): rdc ERR: rec waste packet "
			"pbtx->msg: 0x%x fe: %x stat_rx: %x num_obm: 0x%x %p\n",
			inst, pbtx->for_rec_trwd, ptx->fe, ptx->state_rx, ptx->rx, ptx);
		prn_puls(rp);
		pst->rdc_waste++;
		goto ES_RDC_Ev_label;
	}

	if (*(u32 *)pbtx->vaddr == WASTE_PACKET_) {
		dbg_error("bottom_half_rx_any_skb(%x): rdc ERR: rec waste_ packet "
			"pbtx->msg: 0x%x fe: %x stat_rx: %x num_obm: 0x%x %p\n",
			inst, pbtx->for_rec_trwd, ptx->fe, ptx->state_rx, ptx->rx, ptx);
		while (*(u32 *)pbtx->vaddr == WASTE_PACKET_) {
			tmp_waste = *((u32 *)pbtx->vaddr + 1);
			udelay(1);
		}
	}

#ifdef CHECK_MEMORY_E90S
	if (check_bad_memory(ptx, inst)) {
		raw_spin_unlock_irqrestore(&ptx->lock,  flags);
		dbg_error("bottom_half_rx_any_skb: check mem(%x): pbtx->for_rec_trwd: %x end_buf_csum: %x ptx->rx: %x\n", inst, pbtx->for_rec_trwd, ptx->end_buf_csum, ptx->rx);
		prn_puls(rp);
		goto ES_RDC_Ev_label;
	}
#endif
	/* Write to stack the packet*/
	put_in_steck(pbtx, rp, skb);
	p_stats->rx_packets++;
	size_trans = allign_dma(pbtx->for_rec_trwd & MSG_USER);
	p_stats->rx_bytes += size_trans;
	rdc_byte[inst] += size_trans;
	if (rdc_byte[inst] >> 10) {
		pst->rdc_kbyte += rdc_byte[inst] >> 10;
		rdc_byte[inst] = 0;
	}
	*(u32 *)pbtx->vaddr = WASTE_PACKET_;
	raw_spin_lock_irqsave(&rp->thread_lock, flags);
	rp->start_thread = 0; 
	raw_spin_unlock_irqrestore(&rp->thread_lock, flags);
	pbtx->for_rec_trwd = 0;
	ptx->state_rx = 0;
	raw_spin_unlock_irqrestore(&ptx->lock,  flags);
ES_RDC_Ev_label:
	try_work(rp);
	dbg_rx_any_skb("bottom_half_rx_any_skb: stop \n");
}
#endif

#ifdef BOTTOM_HALF_RX_REFILL_SKB
#ifndef DBG_BOTTOM_HALF_RX_REFILL_SKB
#define DBG_BOTTOM_HALF_RX_REFILL_SKB	0
#endif
#define dbg_rx_refill_skb	if (DBG_BOTTOM_HALF_RX_REFILL_SKB) printk

/* Refill ring for rx */
void bottom_half_rx_refill_skb(struct rdma_private *rp)
{
	struct rdma_tx_block	*ptx;
	struct rdma_tx_desc	*pbtx;
	unsigned int		i, max_iter_allocmem = 0;
	unsigned long flags;

	ptx = &rp->rt_block;
        dbg_rx_refill_skb("bottom_half_rx_refill_skb: start dev: %s  rp: %p rp->rt_block: %p ptx->alloc_buf_skb:%x \n", rp->dev->name, &rp, &rp->rt_block, ptx->alloc_buf_rdma);
#define MAX_ITER_ALLOCMEM 4
iter_get_mem:	
	for (i = 0; i < ptx->alloc_buf_rdma; i++) {	//TX_RING_SIZE;
		pbtx = &ptx->btx_ring[i];
		pbtx->for_rec_trwd = 0;
		if (pbtx->addr == NULL )
			pbtx->addr = dev_alloc_skb(SIZE_MTU_DEV + 2);
		if (pbtx->addr == NULL) {
			printk("bottom_half_rx_refill_skb: memory dev_alloc_skb for "
			"ptx->tx_buf[%x]. SIZE_MTU_DEV: %x\n",
			i, SIZE_MTU_DEV);
			ptx->avail = (i + 1 ) - 1;
			goto bad_get_mem;
		}
		*(u32 *)pbtx->vaddr = WASTE_PACKET_;
	}
	ptx->avail = ptx->alloc_buf_rdma;	//TX_RING_SIZE;
bad_get_mem:
	if (( ptx->avail == 0 ) && ( MAX_ITER_ALLOCMEM > max_iter_allocmem++ ))
		goto iter_get_mem; 
	raw_spin_lock_irqsave(&rp->thread_lock, flags);
	rp->start_thread = 0; 
	raw_spin_unlock_irqrestore(&rp->thread_lock, flags);
	ptx->fe = ptx->fb = 0;
	ptx->state_rx = 0;
        dbg_rx_refill_skb("bottom_half_rx_refill_skb: stop dev: %s \n", rp->dev->name);
	event_queue(rp->inst, NET_QUEUE_REFILL_EVENT, 0, ptx->avail); 
	try_work(rp);
}
#endif

#ifdef BOTTOM_HALF_RX_THREAD_RDMA
#ifndef DBG_BOTTOM_HALF_RX_THREAD_RDMA
#define DBG_BOTTOM_HALF_RX_THREAD_RDMA	0
#endif
#define dbg_rx_thread_action	if (DBG_BOTTOM_HALF_RX_THREAD_RDMA) printk
/* Thread rx function */
int rx_thread_action(void *arg)
{
	struct rdma_private 	*rp = (struct rdma_private *) arg;
	struct rdma_tx_block	*ptx;
        struct sched_param param = { .sched_priority = MAX_RT_PRIO/4 };
	unsigned long flags;

        dbg_rx_thread_action("rx_thread_action: start dev: %s rp: %p rp->rt_block: %p\n", rp->dev->name, &rp, &rp->rt_block);
	ptx = &rp->rt_block;
//        sys_sched_setscheduler(current->pid, SCHED_FIFO, &param);
        sched_setscheduler(current, SCHED_FIFO, &param);
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		raw_spin_lock_irqsave(&rp->thread_lock, flags);
		if ( rp->start_thread == 0) { 
			raw_spin_unlock_irqrestore(&rp->thread_lock, flags);
	     		dbg_rx_thread_action("rx_thread_action: rp->start_thread = 0 dev: %s rp->start_thread: %x\n", rp->dev->name, rp->start_thread);
			schedule();
			continue;
		}
		raw_spin_unlock_irqrestore(&rp->thread_lock, flags);
#ifdef BOTTOM_HALF_RX_REFILL_SKB
		bottom_half_rx_refill_skb(rp);
#else
		bottom_half_rx_any_skb(rp);	
#endif
	}
	__set_current_state(TASK_RUNNING);
        dbg_rx_thread_action("rx_thread_action: stop dev: %s\n", rp->dev->name);
	return 0;
}
#endif


