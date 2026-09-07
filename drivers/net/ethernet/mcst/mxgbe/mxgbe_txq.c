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
	int node;

	size = priv->tx_ring_count * sizeof(mxgbe_descr_t);
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
		priv->txq[qn].vector = NULL;

		/* Alloc RAM for TX ring */
		node = dev_to_node(&priv->pdev->dev);
		if (node == NUMA_NO_NODE)
			node = 0;
		priv->txq[qn].buff = kzalloc_node(sizeof(mxgbe_buff_t) *
						priv->txq[qn].descr_cnt,
						GFP_KERNEL,
						node);
		if (!priv->txq[qn].buff) {
			dev_err(&pdev->dev,
				"ERROR: Cannot allocate memory for TX ring,"
				" aborting\n");
			err = -ENOMEM;
			goto err_free_alloc;
		}
		spin_lock_init(&priv->txq[qn].tlock);
		spin_lock_init(&priv->txq[qn].hlock);
	}
	priv->tx_ring_count = priv->txq[0].descr_cnt;

	return 0;

err_free_alloc:
	return err;
} /* mxgbe_txq_alloc_all */


void mxgbe_txq_free_all(mxgbe_priv_t *priv)
{
	int qn;
	struct pci_dev *pdev = priv->pdev; /* for DMA_*_RAM macro */

	for (qn = 0; qn < priv->num_tx_queues; qn++) {
		/* Free RAM for TX ring */
		kfree(priv->txq[qn].buff);

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

	/* clean */
	for (i = 0; i < MXGBE_MAX_REG_PRI; i++) {
		mxgbe_wreg32(base, TX_OFFS_PRI0 + (i << 2), 0);
		mxgbe_wreg32(base, TX_SIZE_PRI0 + (i << 2), 0);
		mxgbe_wreg32(base, TX_MASK_PRI0 + (i << 2),
				   TX_MASK_PRI0_DEF << i);
		mxgbe_wreg32(base, TX_Q_CH0 + (i << 2), TX_Q_CH_DEF);
	}

	/* A single tx buffer with 0-th priority */
	offs = 0;
	bsize = priv->hw_tx_bufsize;
	mxgbe_wreg32(base, TX_OFFS_PRI0, offs);
	mxgbe_wreg32(base, TX_SIZE_PRI0, bsize);
	mxgbe_wreg32(base, TX_MASK_PRI0, 0xFF);
	for (i = 1; i < MXGBE_MAX_REG_PRI; i++)
		mxgbe_wreg32(base, TX_MASK_PRI0 + (i << 2), 0x00);
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
			| Q_RDYTHR_SET_TO(priv->tx_coalesce_usecs)
			| Q_RDYTHR_SET_N(priv->tx_coalesced_frames)
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
#ifdef CONFIG_MXGBE_DCA
	u32 dca = 0;

	if (mxgbe_tx_dca_enable)
		dca = Q_CTRL_SET_DESC_TPH |
			  (mxgbe_ro_tx_data ? Q_CTRL_SET_DATARO : 0) |
			  (mxgbe_ro_tx_descr ? Q_CTRL_SET_DESCRRO : 0) |
			  Q_CTRL_SET_ST(priv->txq[qn].vector->numa_node & 0x3F) |
			  Q_CTRL_SET_PH(priv->proc_hint & 0x03);
#endif /* CONFIG_MXGBE_DCA */

	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ),
		     Q_IRQ_EN_ALL | Q_IRQ_ENSETBITS);

	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_CTRL),
#ifdef CONFIG_MXGBE_DCA
			 dca |
#endif /* CONFIG_MXGBE_DCA */
		     Q_CTRL_SET_HADDR(0) |
		     Q_CTRL_SET_PRIO(priv->txq[qn].prio) |
		     Q_CTRL_SET_REGHADDR(Q_CTRL_REGHADDR_QCTRL) |
		     Q_CTRL_SET_DESCRL |
		     Q_CTRL_SET_AUTOWRB | /* autoclean !!! */
		     /* Q_CTRL_SET_WRDONEMEM | */ /* set in Reset state */
		     /* Q_CTRL_SET_WRTAILMEM | */
		     Q_CTRL_SET_START);
} /* mxgbe_txq_start */


/**
 ******************************************************************************
 * WORK
 ******************************************************************************
 */

int mxgbe_txq_send(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
		   mxgbe_buff_t *tx_buff)
{
	u16 head, tail, new_head;
	mxgbe_descr_t *q_descr;
	void __iomem *base = priv->bar0_base;
	unsigned long flags;

	spin_lock_irqsave(&priv->txq[qn].hlock, flags);

	head = Q_HEAD_GET_PTR(mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_HEAD)));
	INC_TXQ_INDEX(new_head, head, qn);

	tail = READ_ONCE(priv->txq[qn].tail);
	if (tail == new_head) {
		if (!priv->tx_err_flags[qn].quefull_f) {
			priv->tx_err_flags[qn].quefull_f = 1;
			priv->tx_err_flags[qn].quefull_c += 1;
		}
		spin_unlock_irqrestore(&priv->txq[qn].hlock, flags);
		return -EBUSY;
	}
	priv->tx_err_flags[qn].quefull_f = 0;

	q_descr = ((mxgbe_descr_t *)(priv->txq[qn].que_addr)) + head;
	q_descr->vlan.r = cpu_to_le64(descr->vlan.ru);
	q_descr->time.r = cpu_to_le64(descr->time.ru);
	q_descr->addr.r = cpu_to_le64(descr->addr.ru);
	q_descr->ctrl.r = cpu_to_le64(descr->ctrl.ru);

	/* Force memory writes to complete before letting h/w
	 * know there are new descriptors to fetch. */
	wmb();

	if (tx_buff)
		priv->txq[qn].buff[head] = *tx_buff;

	/* start Tx */
	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_HEAD), Q_HEAD_SET_PTR(new_head));

	spin_unlock_irqrestore(&priv->txq[qn].hlock, flags);

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
	if (!(irqst & (1UL << qn)))
		return IRQ_NONE;

	/* read request flags */
	qirq = mxgbe_rreg32(base, TXQ_REG_ADDR(qn, Q_IRQ));
	qirq &= Q_IRQ_REQ_ALL;

	/* clean request flags & Disable IRQ */
	mxgbe_wreg32(base, TXQ_REG_ADDR(qn, Q_IRQ),
		     (qirq & (Q_IRQ_REQ_ERROR |
			     Q_IRQ_REQ_EMPTY |
			     Q_IRQ_REQ_WRBACK)) |
		     (Q_IRQ_EN_ALL /*| Q_IRQ_ENSETBITS*/));

	if (qirq & Q_IRQ_REQ_WRBACK)
		mxgbe_net_tx_irq_handler(vector);

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
