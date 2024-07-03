/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_rxq.c - MXGBE module device driver
 *
 * Rx Queue
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"

#include "mxgbe_rxq.h"


void mxgbe_net_rx_irq_handler(mxgbe_vector_t *vector);


/**
 ******************************************************************************
 * Spec RX HW INIT
 ******************************************************************************
 */

/**
 * Init one line in DSTMAC table
 */
static void mxgbe_rx_init_dstmac(mxgbe_priv_t *priv, int idx, u64 mac)
{
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"set RX_DSTMAC table: idx=%1u, mac=0x%012llX\n", idx, mac);

	mxgbe_wreg32(base, RX_DSTMAC, RX_DSTMAC_SETIDX(idx));
	mxgbe_wreg32(base, RX_DSTMAC,
		     RX_DSTMAC_RECFRAME | RX_DSTMAC_SETMAC(mac >> 24));
	mxgbe_wreg32(base, RX_DSTMAC,
		     RX_DSTMAC_RECFRAME | RX_DSTMAC_SETMAC(mac));
} /* mxgbe_rx_init_dstmac */


/**
 * Init one line in MCASTHASH table
 */
static void mxgbe_rx_init_mcasthash(mxgbe_priv_t *priv, int idx, u16 hash)
{
	void __iomem *base = priv->bar0_base;

	nFDEBUG; /* too big: RX_MCASTHASH_TBLSIZE !!! */

	nDEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"set RX_MCASTHASH table: idx=%3u, hash=0x%04X\n", idx, hash);

	mxgbe_wreg32(base, RX_MCASTHASH, RX_MCASTHASH_SETIDX(idx));
	mxgbe_wreg32(base, RX_MCASTHASH, RX_MCASTHASH_SETHASH(hash));
} /* mxgbe_rx_init_mcasthash */


/**
 * Init one line in VLANFILT table
 */
static void mxgbe_rx_init_vlanfilt(mxgbe_priv_t *priv, int idx, u16 prio)
{
	void __iomem *base = priv->bar0_base;

	nFDEBUG; /* too big: RX_VLANFILT_TBLSIZE !!! */

	nDEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"set RX_VLANFILT table: idx=%3u, prio=0x%04X\n", idx, prio);

	mxgbe_wreg32(base, RX_VLANFILT, RX_VLANFILT_SETIDX(idx));
	mxgbe_wreg32(base, RX_VLANFILT, RX_VLANFILT_SETPRIO(prio));
} /* mxgbe_rx_init_vlanfilt */


/**
 ******************************************************************************
 * INIT
 ******************************************************************************
 */

/**
 * Pre Init RXQ at main
 */
int mxgbe_rxq_alloc_all(mxgbe_priv_t *priv)
{
	int err;
	int qn;
	size_t size;
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	FDEBUG;

	size = Q_SIZE_MIN * sizeof(mxgbe_descr_t);
	size = (size < PAGE_SIZE) ? PAGE_SIZE : size; /* Rx queue size */

	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		/* Alloc RAM for Rx Tail copy */
		DMA_ALLOC_RAM(priv->rxq[qn].tail_size,
			      priv->rxq[qn].tail_addr,
			      priv->rxq[qn].tail_handle,
			      PAGE_SIZE,
			      err_free_alloc,
			      "RX Tail");
		*(u64 *)(priv->rxq[qn].tail_addr) = 1234567891234567890;
		/* Alloc RAM for HW Queue */
		DMA_ALLOC_RAM(priv->rxq[qn].que_size,
			      priv->rxq[qn].que_addr,
			      priv->rxq[qn].que_handle,
			      size,
			      err_free_alloc,
			      "RX Queue");
		priv->rxq[qn].descr_cnt =
			priv->rxq[qn].que_size / sizeof(mxgbe_descr_t);
		priv->rxq[qn].tail = 0;

		DEV_DBG(MXGBE_DBG_MSK_MEM, &priv->pdev->dev,
			"rxq_alloc_all: RX Tail: addr=%p handle=%016llX\n",
			priv->rxq[qn].tail_addr,
			(unsigned long long)priv->rxq[qn].tail_handle);

		DEV_DBG(MXGBE_DBG_MSK_MEM, &priv->pdev->dev,
			"rxq_alloc_all: HW Queue: rxq[%d].descr_cnt=%d  " \
			"que_size=%u\n",
			qn, priv->rxq[qn].descr_cnt,
			(unsigned int)priv->rxq[qn].que_size);
		DEV_DBG(MXGBE_DBG_MSK_MEM, &priv->pdev->dev,
			"rxq_alloc_all: que_addr=%p que_handle=%016llX\n",
			priv->rxq[qn].que_addr,
			(unsigned long long)priv->rxq[qn].que_handle);

		/* Alloc RAM for RX ring */
		priv->rxq[qn].rx_buff = kzalloc_node(sizeof(mxgbe_rx_buff_t) *
						priv->rxq[qn].descr_cnt,
						GFP_KERNEL,
						dev_to_node(&priv->pdev->dev));
		if (!priv->rxq[qn].rx_buff) {
			dev_err(&priv->pdev->dev,
				"ERROR: Cannot allocate memory for RX ring,"
				" aborting\n");
			err = -ENOMEM;
			goto err_free_alloc;
		}
		spin_lock_init(&priv->rxq[qn].tlock);
		spin_lock_init(&priv->rxq[qn].hlock);
	}
	return 0;

err_free_alloc:
	return err;
} /* mxgbe_rxq_alloc_all */


void mxgbe_rxq_free_all(mxgbe_priv_t *priv)
{
	int qn;
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	FDEBUG;

	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		/* Free RAM for RX ring */
		kfree(priv->rxq[qn].rx_buff);

		/* Free RAM for HW Queue */
		DMA_FREE_RAM(priv->rxq[qn].que_size,
			     priv->rxq[qn].que_addr,
			     priv->rxq[qn].que_handle);
		/* Free RAM for Rx Tail copy */
		DMA_FREE_RAM(priv->rxq[qn].tail_size,
			     priv->rxq[qn].tail_addr,
			     priv->rxq[qn].tail_handle);
	}
} /* mxgbe_rxq_free_all */

void mxgbe_rx_multicast_disable(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;
	u32 val;

	val = mxgbe_rreg32(base, RX_CTRL);
	val &= ~(RX_CTRL_RMULTICAST1
		     | RX_CTRL_RMULTICAST0
		     | RX_CTRL_RBROADCAST);
	mxgbe_wreg32(base, RX_CTRL, val);
}

void mxgbe_rx_multicast_enable(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;
	u32 val;

	val = mxgbe_rreg32(base, RX_CTRL);
	val |= (RX_CTRL_RMULTICAST1
		     | RX_CTRL_RMULTICAST0
		     | RX_CTRL_RBROADCAST);
	mxgbe_wreg32(base, RX_CTRL, val);
}

/**
 * First Init RX (ch4.pdf) at start of probe
 */
void mxgbe_rx_init(mxgbe_priv_t *priv)
{
	unsigned int i;
	void __iomem *base = priv->bar0_base;
	u32 offs, bsize;
	u32 val;

	FDEBUG;

	/* clean */
	for (i = 0; i < MXGBE_MAX_REG_PRI; i++) {
		mxgbe_wreg32(base, RX_OFFS_PRI0 + (i << 2), 0);
		mxgbe_wreg32(base, RX_SIZE_PRI0 + (i << 2), 0);
		mxgbe_wreg32(base, RX_MASK_PRI0 + (i << 2),
				   RX_MASK_PRI0_DEF << i);
		mxgbe_wreg32(base, RX_Q_CH0 + (i << 2), RX_Q_CH_DEF);
	}

	/* real init */
	offs = 0;
	bsize = priv->hw_rx_bufsize >> 3; /* /8 */

	mxgbe_wreg32(base, RX_OFFS_PRI0, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI0, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI1, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI1, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI2, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI2, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI3, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI3, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI4, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI4, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI5, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI5, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI6, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI6, bsize);
	offs += bsize;
	mxgbe_wreg32(base, RX_OFFS_PRI7, offs);
	mxgbe_wreg32(base, RX_SIZE_PRI7, bsize);

	mxgbe_wreg32(base, RX_CTRL, 0
		     | RX_CTRL_RWODSTMAC	/* ignore DSTMAC flt */
		     /*| RX_CTRL_TCPRCS */	/* enable MSS (<= 64k) */
		     | RX_CTRL_SET_QPRIO(0)	/* pkt prio w/o Q-taq */
		     | RX_CTRL_CFIDEIST(0)	/* CFI/DEI val (if en) */
		     /*| RX_CTRL_CHKCFIDEI */	/* Q-tag CFI/DEI filt en */
		     | RX_CTRL_PARSETCP		/* enable TCP/UDP parse */
		     | RX_CTRL_PARSEIP		/* enable IP parse */
		     /*| RX_CTRL_RMULTICAST1 */	/* enable rx mcast pkt H[1] */
		     /*| RX_CTRL_RMULTICAST0 */	/* enable rx mcast pkt H[0] */
		     /*| RX_CTRL_RBROADCAST */	/* enable rx bcast pkt */
		     /*| RX_CTRL_RAWMODE */	/* enable RAW mode (!!!) */
		    );
	for (i = 0; i < RX_DSTMAC_TBLSIZE; i++) {
		/* ignore DSTMAC - receive all */
		mxgbe_rx_init_dstmac(priv, i, 0xFFFFFFFFFFFF);
	}
	for (i = 0; i < RX_MCASTHASH_TBLSIZE; i++) {
		/* receive all multicast */
		mxgbe_rx_init_mcasthash(priv, i, 0);
	}
	for (i = 0; i < RX_VLANFILT_TBLSIZE; i++) {
		/* Qtag/VLAN not used */
		mxgbe_rx_init_vlanfilt(priv, i, 0);
	}

	/* Default hash init */
	val = RX_HASH_DIV_DEF;
	mxgbe_wreg32(base, RX_PTP, val); /* IEEE1588 Rx */
	mxgbe_wreg32(base, RX_RAW, val); /* not PTP/IP/TCP/UDP */

	val = 0
		/*| RX_HASH_ENALL*/
		| RX_HASH_ENDPORT
		| RX_HASH_ENSPORT
		| RX_HASH_ENDIP
		| RX_HASH_ENSIP
		| RX_HASH_ENIPP
		/*| RX_HASH_ENVLAN*/
		/*| RX_HASH_ENETHT*/
		/*| RX_HASH_ENSMAC*/
		/*| RX_HASH_ENDMAC*/
		| RX_HASH_ADD(0)	/* == 0..255 */
		| RX_HASH_DIV(priv->num_rx_queues)	/* == 1..256 */
		;
	mxgbe_wreg32(base, RX_IP, val);  /* IP */

	val = 0
		/*| RX_HASH_ENALL*/
		| RX_HASH_ENDPORT
		| RX_HASH_ENSPORT
		| RX_HASH_ENDIP
		| RX_HASH_ENSIP
		| RX_HASH_ENIPP
		/*| RX_HASH_ENVLAN*/
		/*| RX_HASH_ENETHT*/
		/*| RX_HASH_ENSMAC*/
		/*| RX_HASH_ENDMAC*/
		| RX_HASH_ADD(0)	/* == 0..255 */
		| RX_HASH_DIV(priv->num_rx_queues)	/* == 1..256 */
		;
	mxgbe_wreg32(base, RX_TCP, val); /* TCP */

	val = 0
		/*| RX_HASH_ENALL*/
		| RX_HASH_ENDPORT
		| RX_HASH_ENSPORT
		| RX_HASH_ENDIP
		| RX_HASH_ENSIP
		| RX_HASH_ENIPP
		/*| RX_HASH_ENVLAN*/
		/*| RX_HASH_ENETHT*/
		/*| RX_HASH_ENSMAC*/
		/*| RX_HASH_ENDMAC*/
		| RX_HASH_ADD(0)	/* == 0..255 */
		| RX_HASH_DIV(priv->num_rx_queues)	/* == 1..256 */
		;
	mxgbe_wreg32(base, RX_UDP, val); /* UDP */
} /* mxgbe_rx_init */


/**
 * First Init all RXQ at start of probe
 */
int mxgbe_rxq_init_all(mxgbe_priv_t *priv)
{
	int qn;
	u32 val;
	unsigned long timestart;
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	/* clean all */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ), Q_IRQ_CLEARALL);
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_CTRL), 0);
	}

	/* wait for queue stoppped */
	timestart = jiffies;
	do {
		val = 0;
		for (qn = 0, val = 0; qn < priv->num_rx_queues; qn++) {
			val |= mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_CTRL));
		}
		val = Q_CTRL_GET_NOTDONE(val);
		if (val && time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: RX Q_CTRL_NOTDONE == 1\n");
			return -EAGAIN;
		}
	} while (val);


	/* reset all */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_CTRL),
			     Q_CTRL_SET_RESET | Q_CTRL_SET_WRDONEMEM);
	}

	/* wait for queue ready */
	timestart = jiffies;
	do {
		val = 0;
		for (qn = 0, val = 0; qn < priv->num_rx_queues; qn++) {
			val |= mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_CTRL));
		}
		val = Q_CTRL_GET_RESET(val);
		if (val && time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: RX Q_CTRL_RESET == 1\n");
			return -EAGAIN;
		}
	} while (val);


	/* real init */
	for (qn = 0; qn < priv->num_rx_queues; qn++) {
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_CTRL), 0);
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ), Q_IRQ_CLEARALL);
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_EMPTYTHR), 0);
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_RDYTHR), 0);
		mxgbe_wreg64(base, RXQ_REG_ADDR(qn, Q_ADDR),
			     priv->rxq[qn].que_handle);
		mxgbe_wreg64(base, RXQ_REG_ADDR(qn, Q_TAILADDR), 0);
			     /*priv->rxq[qn].tail_handle);*/
		mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_SIZE),
			     priv->rxq[qn].descr_cnt);

		/* Tune Rx IRQ:
		 * use `ethtool -C eth* rx-frames N` to set Q_RDYTHR
		 */
	}

	return 0;
} /* mxgbe_rxq_init_all */


/**
 * Start RXQ[qn] at Open
 */
void mxgbe_rxq_start(mxgbe_priv_t *priv, int qn)
{
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ),
		     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_CTRL),
		     Q_CTRL_SET_HADDR(0) |
		     Q_CTRL_SET_PRIO(priv->rxq[qn].prio) |
		     Q_CTRL_SET_REGHADDR(Q_CTRL_REGHADDR_QCTRL) |
#ifdef USE_LONG_DESCR
		     Q_CTRL_SET_DESCRL |
#endif /* USE_LONG_DESCR */
		     Q_CTRL_SET_AUTOWRB | /* autoclean !!! */
		     /* Q_CTRL_SET_WRDONEMEM | */ /* set in Reset state */
		     /* Q_CTRL_SET_WRTAILMEM | */
		     Q_CTRL_SET_START);

} /* mxgbe_rxq_start */

/**
 * Stop RXQ[qn] at Close
 */
void mxgbe_rxq_stop(mxgbe_priv_t *priv, int qn)
{
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_CTRL), 0);
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ), Q_IRQ_CLEARALL);
} /* mxgbe_rxq_stop */


/**
 ******************************************************************************
 * WORK
 ******************************************************************************
 */

/**
 * Prepare descriptor for Rx
 */
int mxgbe_rxq_request(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
		      u16 head)
{
	u16 new_head;
	mxgbe_descr_t *q_descr;
	void __iomem *base = priv->bar0_base;

	nFDEBUG; /* too big: priv->rxq[qn].descr_cnt !!! */

	q_descr = ((mxgbe_descr_t *)(priv->rxq[qn].que_addr)) + head;
#ifdef USE_LONG_DESCR
	q_descr->vlan.r = cpu_to_le64(descr->vlan.r);
	q_descr->time.r = cpu_to_le64(descr->time.r);
#endif /* USE_LONG_DESCR */
	q_descr->addr.r = cpu_to_le64(descr->addr.r);
	q_descr->ctrl.r = cpu_to_le64(descr->ctrl.r);

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch. */
	wmb();

	INC_RXQ_INDEX(new_head, head, qn);

	DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"rxq_request: qn=%d, head=%u, new_head=%u, tail_hw=??\n",
		qn, head, new_head);

	DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"rxq_request: %016llX %016llX\n",
		descr->ctrl.r, descr->addr.r);

	/* start Rx */
	priv->rxq[qn].head = new_head;
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_HEAD), Q_HEAD_SET_PTR(new_head));

	return 0;
} /* mxgbe_rxq_request */


/**
 * Interrupt handler
 *
 * @irq:	not used (== msix_entries[i].vector == priv->vector[i].irq)
 * @dev_id:	PCI device information struct
 */
irqreturn_t mxgbe_rxq_irq_handler(int irq, void *dev_id)
{
	mxgbe_vector_t *vector;
	mxgbe_priv_t *priv;
	void __iomem *base;
	u32 irqst, irqstn;
	int qn;
	u32 qirq;

	nFDEBUG;

	if (!dev_id)
		return IRQ_NONE;
	vector = (mxgbe_vector_t *)dev_id;
	priv = vector->priv;
	base = priv->bar0_base;
	qn = vector->qn;

	assert(irq == vector->irq);

	/* MSIX_IRQST_* value */
	irqstn = qn >> 5;
	irqst = mxgbe_rreg32(base, MSIX_IRQST_RXBASE + (irqstn << 2));
	if (!(irqst & (1UL << qn))) {
		nDEV_DBG(MXGBE_DBG_MSK_IRQ, &priv->ndev->dev,
			"RX_IRQ #%d - NONE -> qn %d, IRQST%u=0x%08X\n",
			irq, vector->qn, irqstn, irqst);
		return IRQ_NONE;
	}

	nDEV_DBG(MXGBE_DBG_MSK_IRQ, &priv->ndev->dev,
		"RX_IRQ #%d -> qn %d, IRQST%u=0x%08X\n",
		irq, vector->qn, irqstn, irqst);

	nDEV_DBG(MXGBE_DBG_MSK_RX_IRQ, &priv->pdev->dev,
		"RXQ_IRQ on queue %d\n", qn);

	/* Disable IRQ */
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ), Q_IRQ_EN_ALL);

	/* read request flags */
	qirq = mxgbe_rreg32(base, RXQ_REG_ADDR(qn, Q_IRQ));
	qirq &= Q_IRQ_REQ_ALL;

	/* clean request flags */
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ),
		     qirq & (Q_IRQ_REQ_ERROR |
			     Q_IRQ_REQ_EMPTY |
			     Q_IRQ_REQ_WRBACK));
	nDEV_DBG(MXGBE_DBG_MSK_RX_IRQ, &priv->pdev->dev,
		"RXQ_IRQ CLEAN: qn=%d, qirq=%lu\n",
		qn, qirq & Q_IRQ_REQ_ALL);

	if (qirq & Q_IRQ_REQ_ERROR) {
		priv->rx_err_flags[qn].errirq_c += 1;
		nDEV_DBG(MXGBE_DBG_MSK_RX_IRQ, &priv->pdev->dev,
			"RXQ_IRQ_ERROR(%d,0x%08X): qn=%d, qirq=%d\n",
			vector->qn, irqst, qn, qirq);
		/* TODO: cleanup this queue */
	}
	if (qirq & Q_IRQ_REQ_EMPTY) {
		/* OK: Queue size < Q_EMPTYYHR */
		if (!priv->rx_err_flags[qn].queempty_f) {
			priv->rx_err_flags[qn].queempty_f = 1;
			priv->rx_err_flags[qn].queempty_c += 1;
			nDEV_DBG(MXGBE_DBG_MSK_RX_IRQ, &priv->pdev->dev,
				"RXQ_IRQ_EMPTY(%d,0x%08X): qn=%d, qirq=%d\n",
				vector->qn, irqst, qn, qirq);
		}
	}
	if (qirq & Q_IRQ_REQ_WRBACK) {
		nDEV_DBG(MXGBE_DBG_MSK_RX_IRQ, &priv->pdev->dev,
			"RXQ_IRQ_WRBACK(%d,0x%08X): qn=%d, qirq=%d\n",
			vector->qn, irqst, qn, qirq);
		mxgbe_net_rx_irq_handler(vector);
	}

	/* Enable IRQ (napi: w/o Q_IRQ_EN_WRBACK) */
	mxgbe_wreg32(base, RXQ_REG_ADDR(qn, Q_IRQ),
		(Q_IRQ_EN_ERROR | Q_IRQ_EN_EMPTY) | Q_IRQ_ENSETBITS);

	return IRQ_HANDLED;
} /* mxgbe_rxq_irq_handler */


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

#ifdef DEBUG

void mxgbe_rx_dbg_prn_descr_s(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
			      u16 tail_cur)
{
	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"descr addr = %p (HW: 0x%08lX), tail_cur=%u\n",
		descr,
		(unsigned long)priv->rxq[qn].que_handle +
			(tail_cur * sizeof(mxgbe_descr_t)),
		tail_cur);
	if (XX_OWNER_HW == descr->addr.RC.OWNER) {
		DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
			"descr.ctrl.r = %016llX (Receive + CPU)\n" \
			"\tRC.BUFSIZE = %u (0x%X)\n",
			descr->ctrl.r,
			descr->ctrl.RC.BUFSIZE, descr->ctrl.RC.BUFSIZE);
		DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
			"descr.addr.r = %016llX (Receive + CPU)\n" \
			"\tRC.BUFPTR = 0x%016llX\n" \
			"\tRC.OWNER = %u\n",
			descr->addr.r,
			(long long unsigned int)descr->addr.RC.BUFPTR,
			descr->addr.RC.OWNER);
	} else {
		DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
			"descr.ctrl.r = %016llX (Receive + Device)\n" \
			"\tRD.BFERR = %u\n" \
			"\tRD.TOOBIG = %u\n" \
			"\tRD.BUFSIZE = %u (0x%X)\n" \
			"\tRD.L3HDR = %u (0x%X)\n" \
			"\tRD.TYPE = %u (0x%X)\n" \
			"\tRD.L4HDR = %u (0x%X)\n" \
			"\tRD.DATOFFS = %u (0x%X)\n" \
			"\tRD.SIVLAN = %u\n" \
			"\tRD.SOVLAN = %u\n" \
			"\tRD.IPCSUMOK = %u (IPv4)\n" \
			"\tRD.NTCP_UDP = %u\n" \
			"\tRD.L4CSUM = %u\n" \
			"\tRD.L4CSUMOK = %u (L4: TCP|UDP)\n" \
			"\tRD.MERGED = %u\n" \
			"\tRD.FRMSIZE = %u (0x%X)\n",
			descr->ctrl.r,
			descr->ctrl.RD.BFERR,
			descr->ctrl.RD.TOOBIG,
			descr->ctrl.RD.BUFSIZE, descr->ctrl.RD.BUFSIZE,
			descr->ctrl.RD.L3HDR, descr->ctrl.RD.L3HDR,
			descr->ctrl.RD.TYPE, descr->ctrl.RD.TYPE,
			descr->ctrl.RD.L4HDR, descr->ctrl.RD.L4HDR,
			descr->ctrl.RD.DATOFFS, descr->ctrl.RD.DATOFFS,
			descr->ctrl.RD.SIVLAN,
			descr->ctrl.RD.SOVLAN,
			descr->ctrl.RD.IPCSUMOK,
			descr->ctrl.RD.NTCP_UDP,
			descr->ctrl.RD.L4CSUM,
			descr->ctrl.RD.L4CSUMOK,
			descr->ctrl.RD.MERGED,
			descr->ctrl.RD.FRMSIZE, descr->ctrl.RD.FRMSIZE);
		DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
			"descr.addr.r = %016llX (Receive + Device)\n" \
			"\tRD.BUFPTR = 0x%016llX\n" \
			"\tRD.SPLIT = %u\n" \
			"\tRD.OWNER = %u\n",
			descr->addr.r,
			(long long unsigned int)
			descr->addr.RD.BUFPTR,
			descr->addr.RD.SPLIT,
			descr->addr.RD.OWNER);
	}
} /* mxgbe_rx_dbg_prn_descr_s */


void mxgbe_rx_dbg_prn_data(mxgbe_priv_t *priv, char *data, ssize_t size)
{
	int i;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"Received data >>>\n");
	for (i = 0; i < size; i++) {
		pr_debug("%02X ", (unsigned char)data[i]);
	}
	DEV_DBG(MXGBE_DBG_MSK_RX, &priv->pdev->dev,
		"Received data <<<\n");
} /* mxgbe_rx_dbg_prn_data */

#endif /* DEBUG */
