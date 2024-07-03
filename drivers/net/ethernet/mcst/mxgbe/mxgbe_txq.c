/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_txq.c - MXGBE module device driver
 *
 * Tx Queue
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "kcompat.h"

#include "mxgbe_txq.h"


void mxgbe_net_tx_irq_handler(mxgbe_vector_t *vector);


/**
 ******************************************************************************
 * INIT
 ******************************************************************************
 */

/**
 * Pre Init TXQ at main
 */
int mxgbe_txq_alloc_all(mxgbe_priv_t *priv)
{
	int err;
	int qn;
	size_t size;
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	FDEBUG;

	size = Q_SIZE_MIN * sizeof(mxgbe_descr_t);
	size = (size < PAGE_SIZE) ? PAGE_SIZE : size; /* Tx queue size */

	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		/* Alloc RAM for HW Queue */
		DMA_ALLOC_RAM(priv->txq[qn].que_size,
			      priv->txq[qn].que_addr,
			      priv->txq[qn].que_handle,
			      size,
			      err_free_alloc,
			      "TX Queue");
		priv->txq[qn].descr_cnt =
			priv->txq[qn].que_size / sizeof(mxgbe_descr_t);
		priv->txq[qn].tail = 0;

		DEV_DBG(MXGBE_DBG_MSK_MEM, &priv->pdev->dev,
			"txq_alloc_all: HW Queue: txq[%d].descr_cnt=%d  " \
			"que_size=%u\n",
			qn, priv->txq[qn].descr_cnt,
			(unsigned int)priv->txq[qn].que_size);

		DEV_DBG(MXGBE_DBG_MSK_MEM, &priv->pdev->dev,
			"txq_alloc_all: que_addr=%p que_handle=%016llX\n",
			priv->txq[qn].que_addr,
			(unsigned long long)priv->txq[qn].que_handle);

		/* Alloc RAM for TX ring */
		priv->txq[qn].tx_buff = kzalloc_node(sizeof(mxgbe_tx_buff_t) *
						priv->txq[qn].descr_cnt,
						GFP_KERNEL,
						dev_to_node(&pdev->dev));
		if (!priv->txq[qn].tx_buff) {
			dev_err(&pdev->dev,
				"ERROR: Cannot allocate memory for TX ring,"
				" aborting\n");
			err = -ENOMEM;
			goto err_free_alloc;
		}
		spin_lock_init(&priv->txq[qn].tlock);
		spin_lock_init(&priv->txq[qn].hlock);
	}
	return 0;

err_free_alloc:
	return err;
} /* mxgbe_txq_alloc_all */


void mxgbe_txq_free_all(mxgbe_priv_t *priv)
{
	int qn;
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	FDEBUG;

	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		/* Free RAM for TX ring */
		kfree(priv->txq[qn].tx_buff);

		/* Free RAM for HW Queue */
		DMA_FREE_RAM(priv->txq[qn].que_size,
			     priv->txq[qn].que_addr,
			     priv->txq[qn].que_handle);
	}
} /* mxgbe_txq_free_all */


/**
 * First Init TX (ch3.pdf) at start of probe
 */
void mxgbe_tx_init(mxgbe_priv_t *priv)
{
	unsigned int i;
	void __iomem *base = priv->bar0_base;
	u32 offs, bsize;

	FDEBUG;

	/* clean */
	for (i = 0; i < MXGBE_MAX_REG_PRI; i++) {
		mxgbe_wreg32(base, TX_OFFS_PRI0 + (i << 2), 0);
		mxgbe_wreg32(base, TX_SIZE_PRI0 + (i << 2), 0);
		mxgbe_wreg32(base, TX_MASK_PRI0 + (i << 2),
				   TX_MASK_PRI0_DEF << i);
		mxgbe_wreg32(base, TX_Q_CH0 + (i << 2), TX_Q_CH_DEF);
	}

	/* real init */
	offs = 0;
	bsize = priv->hw_tx_bufsize >> 3; /* /8 */

	mxgbe_wreg32(base, TX_OFFS_PRI0, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI0, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI1, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI1, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI2, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI2, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI3, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI3, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI4, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI4, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI5, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI5, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI6, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI6, bsize);
	offs += bsize;
	mxgbe_wreg32(base, TX_OFFS_PRI7, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI7, bsize);
} /* mxgbe_tx_init */


/**
 * First Init all TXQ at start of probe
 */
int mxgbe_txq_init_all(mxgbe_priv_t *priv)
{
	unsigned int qn;
	u32 val;
	unsigned long timestart;
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	/* clean all */
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ), Q_IRQ_CLEARALL);
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_CTRL), 0);
	}

	/* wait for queue stoppped */
	timestart = jiffies;
	do {
		val = 0;
		for (qn = 0, val = 0; qn < priv->num_tx_queues; qn++) {
			val |= mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_CTRL));
		}
		val = Q_CTRL_GET_NOTDONE(val);
		if (val && time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: TX Q_CTRL_NOTDONE == 1\n");
			return -EAGAIN;
		}
	} while (val);


	/* reset all */
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_CTRL),
			     Q_CTRL_SET_RESET | Q_CTRL_SET_WRDONEMEM);
	}

	/* wait for queue ready */
	timestart = jiffies;
	do {
		val = 0;
		for (qn = 0, val = 0; qn < priv->num_tx_queues; qn++) {
			val |= mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_CTRL));
		}
		val = Q_CTRL_GET_RESET(val);
		if (val && time_after(jiffies, timestart + HZ)) {
			dev_err(&priv->pdev->dev,
				"ERROR: TX Q_CTRL_RESET == 1\n");
			return -EAGAIN;
		}
	} while (val);

	/* real init */
	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_CTRL), 0);
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ), Q_IRQ_CLEARALL);
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_EMPTYTHR), 0);
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_RDYTHR), 0);
		mxgbe_wreg64(base, TXQ_REG_ADDR(qn, Q_ADDR),
			     priv->txq[qn].que_handle);
		mxgbe_wreg64(base, TXQ_REG_ADDR(qn, Q_TAILADDR), 0);
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_SIZE),
			     priv->txq[qn].descr_cnt);

		/* Tune Tx IRQ:
		 * use `ethtool -C eth* tx-frames N` to set Q_RDYTHR
		 */
		mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_RDYTHR), 0
			| Q_RDYTHR_SET_TO(500) /* ~1ms */
			| Q_RDYTHR_SET_N(10)
			);
	}

	return 0;
} /* mxgbe_txq_init_all */


/**
 * Last Init TXQ[qn] at end of probe
 */
void mxgbe_txq_start(mxgbe_priv_t *priv, int qn)
{
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ),
		     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);

	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_CTRL),
		     Q_CTRL_SET_HADDR(0) |
		     Q_CTRL_SET_PRIO(priv->txq[qn].prio) |
		     Q_CTRL_SET_REGHADDR(Q_CTRL_REGHADDR_QCTRL) |
#ifdef USE_LONG_DESCR
		     Q_CTRL_SET_DESCRL |
#endif /* USE_LONG_DESCR */
		     Q_CTRL_SET_AUTOWRB | /* autoclean !!! */
		     /* Q_CTRL_SET_WRDONEMEM | */ /* set in Reset state */
		     /* Q_CTRL_SET_WRTAILMEM | */
		     Q_CTRL_SET_START);

	DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
		"txq_start: txq[%d] started\n", qn);
} /* mxgbe_txq_start */


/**
 ******************************************************************************
 * WORK
 ******************************************************************************
 */

int mxgbe_txq_send(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
		   mxgbe_tx_buff_t *tx_buff)
{
	u16 head, tail, new_head;
	mxgbe_descr_t *q_descr;
	void __iomem *base = priv->bar0_base;
	unsigned long flags;

	FDEBUG;

	spin_lock_irqsave(&priv->txq[qn].hlock, flags);

	head = Q_HEAD_GET_PTR(mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_HEAD)));
	INC_TXQ_INDEX(new_head, head, qn);

	tail = READ_ONCE(priv->txq[qn].tail);
	if (tail == new_head) {
		if (!priv->tx_err_flags[qn].quefull_f) {
			priv->tx_err_flags[qn].quefull_f = 1;
			priv->tx_err_flags[qn].quefull_c += 1;
			dev_err(&priv->pdev->dev,
				"txq_send ERROR: queue %d full - "
				"head=%u, tail=%u\n",
				qn, head, tail);
		}
		spin_unlock_irqrestore(&priv->txq[qn].hlock, flags);
		return -EBUSY;
	}
	priv->tx_err_flags[qn].quefull_f = 0;

	q_descr = ((mxgbe_descr_t *)(priv->txq[qn].que_addr)) + head;
#ifdef USE_LONG_DESCR
	q_descr->vlan.r = cpu_to_le64(descr->vlan.r);
	q_descr->time.r = cpu_to_le64(descr->time.r);
#endif /* USE_LONG_DESCR */
	q_descr->addr.r = cpu_to_le64(descr->addr.r);
	q_descr->ctrl.r = cpu_to_le64(descr->ctrl.r);

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch. */
	wmb();

	if (tx_buff) {
		priv->txq[qn].tx_buff[head] = *tx_buff;

		DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
			"txq_send: dma=%llX, skb=%p\n",
			priv->txq[qn].tx_buff[head].dma,
			(void *)priv->txq[qn].tx_buff[head].skb);
	}

	/* start Tx */
	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_HEAD), Q_HEAD_SET_PTR(new_head));

	spin_unlock_irqrestore(&priv->txq[qn].hlock, flags);

	DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
		"txq_send: qn=%d, new_head=%u, tail=%u, descr=%p\n",
		qn, new_head, tail, q_descr);
	DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
		"txq_send: descr: %016llX %016llX\n",
		q_descr->ctrl.r, q_descr->addr.r);

	return 0;
} /* mxgbe_txq_send */


/**
 * Interrupt handler
 *
 * @irq:	not used (== msix_entries[i].vector == priv->vector[i].irq)
 * @dev_id:	PCI device information struct
 */
irqreturn_t mxgbe_txq_irq_handler(int irq, void *dev_id)
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
	irqst = mxgbe_rreg32(base, MSIX_IRQST_TXBASE + (irqstn << 2));
	if (!(irqst & (1UL << qn))) {
		nDEV_DBG(MXGBE_DBG_MSK_IRQ, &priv->ndev->dev,
			"TX_IRQ #%d - NONE -> qn %d, IRQST%u=0x%08X\n",
			irq, vector->qn, irqstn + 8, irqst);
		return IRQ_NONE;
	}

	nDEV_DBG(MXGBE_DBG_MSK_IRQ, &priv->ndev->dev,
		"TX_IRQ #%d -> qn %d, IRQST%u==0x%08X\n",
		irq, vector->qn, irqstn + 8, irqst);

	nDEV_DBG(MXGBE_DBG_MSK_TX_IRQ, &priv->pdev->dev,
		"TXQ_IRQ on queue %d\n", qn);

	/* read request flags */
	qirq = mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_IRQ));
	qirq &= Q_IRQ_REQ_ALL;

	/* clean request flags & Disable IRQ */
	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ),
		     (qirq & (Q_IRQ_REQ_ERROR |
			     Q_IRQ_REQ_EMPTY |
			     Q_IRQ_REQ_WRBACK)) |
		     (Q_IRQ_EN_ALL /*| Q_IRQ_ENSETBITS*/));
	nDEV_DBG(MXGBE_DBG_MSK_TX_IRQ, &priv->pdev->dev,
		"TXQ_IRQ CLEAN: qn=%d, qirq=%lu\n",
		qn, qirq & Q_IRQ_REQ_ALL);

#ifdef DEBUG
	if (qirq & Q_IRQ_REQ_ERROR) {
		nDEV_DBG(MXGBE_DBG_MSK_TX_IRQ, &priv->pdev->dev,
			"TXQ_IRQ_ERROR(%d,0x%08X): qn=%d, qirq=%d\n",
			vector->qn, irqst, qn, qirq);
		/* TODO: cleanup this queue */
	}
#endif /* DEBUG */
#ifdef DEBUG
	if (qirq & Q_IRQ_REQ_EMPTY) {
		nDEV_DBG(MXGBE_DBG_MSK_TX_IRQ, &priv->pdev->dev,
			"TXQ_IRQ_EMPTY(%d,0x%08X): qn=%d, qirq=%d\n",
			vector->qn, irqst, qn, qirq);
		/* OK: Queue size < Q_EMPTYYHR */
	}
#endif /* DEBUG */
	if (qirq & Q_IRQ_REQ_WRBACK) {
		nDEV_DBG(MXGBE_DBG_MSK_TX_IRQ, &priv->pdev->dev,
			"TXQ_IRQ_WRBACK(%d,0x%08X): qn=%d, qirq=%d\n",
			vector->qn, irqst, qn, qirq);
		mxgbe_net_tx_irq_handler(vector);
	}

	/* Enable IRQ (napi: w/o IRQ WRBACK (and EMPTY)) */
	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ), 0
						| Q_IRQ_EN_ERROR
						| Q_IRQ_EN_EMPTY
						| Q_IRQ_ENSETBITS);

	return IRQ_HANDLED;
} /* mxgbe_txq_irq */


/**
 ******************************************************************************
 * DEBUG
 ******************************************************************************
 */

#ifdef DEBUG

void mxgbe_tx_dbg_prn_descr_s(mxgbe_priv_t *priv, mxgbe_descr_t *descr)
{
	FDEBUG;

	if (XX_OWNER_HW == descr->addr.TC.OWNER) {
		DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
			"descr.ctrl.r = %016llX (Transmit + CPU)\n" \
			"\tTC.IPV6 = %u\n" \
			"\tTC.IPCSUM = %u\n" \
			"\tTC.L4CSUM = %u\n" \
			"\tTC.BUFSIZE = %u (0x%X)\n" \
			"\tTC.MSS = %u (0x%X)\n" \
			"\tTC.NTCP_UDP = %u\n" \
			"\tTC.TCPHDR = %u (0x%X)\n" \
			"\tTC.IPHDR = %u (0x%X)\n" \
			"\tTC.L4HDR = %u (0x%X)\n" \
			"\tTC.FRMSIZE = %u (0x%X)\n",
			descr->ctrl.r,
			descr->ctrl.TC.IPV6,
			descr->ctrl.TC.IPCSUM,
			descr->ctrl.TC.L4CSUM,
			descr->ctrl.TC.BUFSIZE, descr->ctrl.TC.BUFSIZE,
			descr->ctrl.TC.MSS, descr->ctrl.TC.MSS,
			descr->ctrl.TC.NTCP_UDP,
			descr->ctrl.TC.TCPHDR, descr->ctrl.TC.TCPHDR,
			descr->ctrl.TC.IPHDR, descr->ctrl.TC.IPHDR,
			descr->ctrl.TC.L4HDR, descr->ctrl.TC.L4HDR,
			descr->ctrl.TC.FRMSIZE, descr->ctrl.TC.FRMSIZE);
		DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
			"descr.addr.r = %016llX (Transmit + CPU)\n" \
			"\tTC.BUFPTR = 0x%016llX\n" \
			"\tTC.SPLIT = %u\n" \
			"\tTC.OWNER = %u\n",
			descr->addr.r,
			(long long unsigned int)descr->addr.TC.BUFPTR,
			descr->addr.TC.SPLIT,
			descr->addr.TC.OWNER);
	} else {
		DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
			"descr.ctrl.r = %016llX (Transmit + Device)\n" \
			"\tTD.BUFSIZE = %u (0x%X)\n" \
			"\tTD.ERRBITS = %u (0x%X)\n",
			descr->ctrl.r,
			descr->ctrl.TD.BUFSIZE, descr->ctrl.TD.BUFSIZE,
			descr->ctrl.TD.ERRBITS, descr->ctrl.TD.ERRBITS);
		DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
			"descr.addr.r = %016llX (Transmit + Device)\n" \
			"\tTD.BUFPTR = 0x%016llX\n" \
			"\tTD.OWNER = %u\n",
			descr->addr.r,
			(long long unsigned int)
			descr->addr.TD.BUFPTR,
			descr->addr.TD.OWNER);
	}
} /* mxgbe_tx_dbg_prn_descr_s */


void mxgbe_tx_dbg_prn_data(mxgbe_priv_t *priv, char *data, ssize_t size)
{
	int i;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
		"Transmit data >>>\n");
	for (i = 0; i < size; i++) {
		pr_debug("%02X ", (unsigned char)data[i]);
	}
	DEV_DBG(MXGBE_DBG_MSK_TX, &priv->pdev->dev,
		"Transmit data <<<\n");
} /* mxgbe_tx_dbg_prn_data */

#endif /* DEBUG */
