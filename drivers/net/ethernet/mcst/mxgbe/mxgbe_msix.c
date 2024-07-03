/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_msix.c - MXGBE module device driver
 *
 * MSIX part
 */

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "mxgbe_txq.h"
#include "mxgbe_rxq.h"
#include "mxgbe_mac.h"

#include "mxgbe_msix.h"


/**
 * ch1.4 - MSI-X
 */

/* MSIX_LUT regiter bits */
#define MSIX_LUT_SETIDX(d)	(0x80000000 | (SET_FIELD((d), 16, 0x3FF)))
#define MSIX_LUT_SETVECT(d)	(SET_FIELD((d), 0, 0x1FF))
/* internal events: */
#define MSIX_RX_IDX_MIN		0	/*   0..255: IRQST_0--7 */
#define MSIX_RX_IDX_NUM		256
#define MSIX_TX_IDX_MIN		256	/* 256..511: IRQST_8--15 */
#define MSIX_TX_IDX_NUM		256
#define MSIX_MAC_IDX_MIN	512	/* 512..543: IRQST_16 */
#define MSIX_MAC_IDX_NUM	32	/* LINK, PAUSE, ERROR, ... */


/*
 * write one recors to MSIX_LUT table
 */
static void msix_lut_set(mxgbe_vector_t *vector, uint16_t idx)
{
	void __iomem *base = vector->priv->bar0_base;

	if (-1 == vector->bidx)
		vector->bidx = idx;

	DEV_DBG(MXGBE_DBG_MSK_IRQ, &vector->priv->pdev->dev,
		"set MSIXLUT: event=%3u(%3u), vect=%3u, irq=%3u, qn=%3u - %s\n",
		idx, vector->bidx, vector->vect, vector->irq, vector->qn,
		vector->name);

	mxgbe_wreg32(base, MSIX_LUT, MSIX_LUT_SETIDX(idx));
	mxgbe_wreg32(base, MSIX_LUT, MSIX_LUT_SETVECT(vector->vect));
} /* msix_lut_set */


/**
 ******************************************************************************
 * INIT
 ******************************************************************************
 */

int mxgbe_msix_prepare(mxgbe_priv_t *priv)
{
	int err;
	int vectors;

	/* init priv->msix_entries */
#ifdef MSIX_COMPACTMODE
#warning not_tested
	/* read one IRQST in irq handler */
	priv->msix_rx_num = (priv->num_rx_queues / 32) +
			  ((priv->num_rx_queues % 32) ? 1 : 0);
	priv->msix_tx_num = (priv->num_tx_queues / 32) +
			  ((priv->num_tx_queues % 32) ? 1 : 0);
	priv->msix_mac_num = MSIX_MAC_IDX_NUM_USE;
#else
	/* don't check IRQST in irq handler */
	priv->msix_rx_num = priv->num_rx_queues;
	priv->msix_tx_num = priv->num_tx_queues;
	priv->msix_mac_num = MSIX_MAC_IDX_NUM_USE;
#endif
	vectors = priv->msix_rx_num + priv->msix_tx_num;
	vectors += priv->msix_mac_num;
	vectors = min_t(int, vectors, MSIX_V_NUM);
	priv->num_msix_entries = vectors;

	dev_dbg(&priv->pdev->dev,
		"msix_prepare: rxn=%d txn=%d macn=%d vectors=%d cpus=%d\n",
		priv->msix_rx_num, priv->msix_tx_num, priv->msix_mac_num,
		vectors, num_online_cpus());

	priv->msix_entries = kzalloc_node(vectors * sizeof(struct msix_entry),
					  GFP_KERNEL,
					  dev_to_node(&priv->pdev->dev));
	if (priv->msix_entries) {
		int i;
		for (i = 0; i < priv->num_msix_entries; i++) {
			priv->msix_entries[i].entry = i;
		}
	} else {
		priv->num_msix_entries = 0;
		dev_err(&priv->pdev->dev,
			"cannot allocate memory for msix, aborting\n");
		return -ENOMEM;
	}

	/* try to register msi-x only! */
	err = pci_enable_msix_range(priv->pdev, priv->msix_entries,
			priv->num_msix_entries, priv->num_msix_entries);
	if (err < 0) {
		dev_err(&priv->pdev->dev,
			"cannot use msix interrupts, reason = %d\n", err);
		goto err_free_msix;
	}
	return 0;

err_free_msix:
	kfree(priv->msix_entries);
	return err;
} /* mxgbe_msix_prepare */

void mxgbe_msix_free(mxgbe_priv_t *priv)
{
	pci_disable_msix(priv->pdev);
	kfree(priv->msix_entries);
} /* mxgbe_msix_free */


/**
 * MSIX Init IRQ table at end of probe
 */
int mxgbe_msix_init(mxgbe_priv_t *priv)
{
	int err;
	unsigned int un;
	int node;
	int nr_cpus;
	int i;

	node = dev_to_node(&priv->pdev->dev);
	nr_cpus = nr_cpus_node(node);

	/* cleanup irq struct */
	for (i = 0; i < priv->num_msix_entries; i++) {
		priv->vector[i].priv = priv;
		priv->vector[i].irq = -1;
		priv->vector[i].bidx = -1;
		/* setup affinity mask and node */
		priv->vector[i].cpu = \
			(i < priv->num_rx_queues) ?
			((node * nr_cpus) + nr_cpus - i - 1) :
			(i < (priv->num_rx_queues + priv->num_tx_queues)) ?
			(i + (node * nr_cpus) - priv->num_rx_queues) :
			(node * nr_cpus);
		if (priv->vector[i].cpu != -1)
			cpumask_set_cpu(priv->vector[i].cpu,
					&priv->vector[i].affinity_mask);
		if (cpu_online(priv->vector[i].cpu))
			priv->vector[i].numa_node =
				cpu_to_node(priv->vector[i].cpu);
	}

	/* request_irq */
	for (i = 0; i < priv->num_msix_entries; i++) {
		if (i < priv->msix_rx_num) {
			snprintf(priv->vector[i].name,
				 sizeof(priv->vector[i].name) - 1,
				 "mxgbe%d:rxq%u@%s",
				 node, i, dev_name(&priv->pdev->dev));
			err = request_irq(priv->msix_entries[i].vector,
					&mxgbe_rxq_irq_handler, 0
						| IRQF_NO_THREAD
						| IRQF_ONESHOT
					, priv->vector[i].name,
					(void *)&priv->vector[i]);
			if (err) {
				dev_err(&priv->pdev->dev,
					"Cannot request rx irq %d, aborting\n",
					priv->msix_entries[i].vector);
				goto err_unregister_irq;
			}
			irq_set_affinity_hint(priv->msix_entries[i].vector,
					      &priv->vector[i].affinity_mask);
		} else if (i < (priv->msix_rx_num + priv->msix_tx_num)) {
			snprintf(priv->vector[i].name,
				 sizeof(priv->vector[i].name) - 1,
				 "mxgbe%d:txq%u@%s",
				 node, i - priv->msix_rx_num,
				 dev_name(&priv->pdev->dev));
			err = request_irq(priv->msix_entries[i].vector,
					&mxgbe_txq_irq_handler, 0
						| IRQF_NO_THREAD
						| IRQF_ONESHOT
					, priv->vector[i].name,
					(void *)&priv->vector[i]);
			if (err) {
				dev_err(&priv->pdev->dev,
					"Cannot request tx irq %d, aborting\n",
					priv->msix_entries[i].vector);
				goto err_unregister_irq;
			}
			irq_set_affinity_hint(priv->msix_entries[i].vector,
					      &priv->vector[i].affinity_mask);
		} else {
			snprintf(priv->vector[i].name,
				 sizeof(priv->vector[i].name) - 1,
				 "mxgbe%d:mac@%s",
				 node, dev_name(&priv->pdev->dev));
			err = request_irq(priv->msix_entries[i].vector,
					&mxgbe_mac_irq_handler, 0
						| IRQF_NO_THREAD
						| IRQF_ONESHOT
					, priv->vector[i].name,
					(void *)&priv->vector[i]);
			if (err) {
				dev_err(&priv->pdev->dev,
					"Cannot request mac irq %d, aborting\n",
					priv->msix_entries[i].vector);
				goto err_unregister_irq;
			}
		}
		priv->vector[i].irq = priv->msix_entries[i].vector;

		DEV_DBG(MXGBE_DBG_MSK_IRQ, &priv->pdev->dev,
			"request_irq: %d - %s (cpu = %d, node = %d)\n",
			priv->msix_entries[i].vector,
			dev_name(&priv->ndev->dev),
			priv->vector[i].cpu,
			priv->vector[i].numa_node);
	}

	/* Init MSIX (ch1.pdf) */
	un = 0;
#ifdef MSIX_COMPACTMODE
#warning not_tested
	/* read one IRQST in irq handler */
	/* init RX irq */
	for (i = 0; i < priv->num_rx_queues; i++) {
		priv->vector[un].qn = i;
		priv->vector[un].vect = un;
		msix_lut_set(&priv->vector[un], MSIX_RX_IDX_MIN + i);
		if (((i + 1) % 32) == 0) {
			un += 1;
		}
	}
	if (((i + 1) % 32) != 0) {
		un += 1;
	}
	/* init TX irq */
	for (i = 0; i < priv->num_tx_queues; i++) {
		priv->vector[un].qn = i;
		priv->vector[un].vect = un;
		msix_lut_set(&priv->vector[un], MSIX_TX_IDX_MIN + i);
		if (((i + 1) % 32) == 0) {
			un += 1;
		}
	}
	if (((i + 1) % 32) != 0) {
		un += 1;
	}
	/* init MAC irq */
	priv->vector[un].qn = 0;
	priv->vector[un].vect = un;
	msix_lut_set(&priv->vector[un], MSIX_IDX_MAC_LINK);
	msix_lut_set(&priv->vector[un], MSIX_IDX_MAC_PAUSE);
	un += 1;
#else
	/* init RX irq */
	for (i = 0; i < priv->num_rx_queues; i++) {
		priv->vector[un].qn = i;
		priv->vector[un].vect = un;
		msix_lut_set(&priv->vector[un], MSIX_RX_IDX_MIN + i);
		un += 1;
	}
	/* init TX irq */
	for (i = 0; i < priv->num_tx_queues; i++) {
		priv->vector[un].qn = i;
		priv->vector[un].vect = un;
		msix_lut_set(&priv->vector[un], MSIX_TX_IDX_MIN + i);
		un += 1;
	}
	/* init MAC irq */
	priv->vector[un].qn = 0;
	priv->vector[un].vect = un;
	msix_lut_set(&priv->vector[un], MSIX_IDX_MAC_LINK);
	msix_lut_set(&priv->vector[un], MSIX_IDX_MAC_PAUSE);
	un += 1;
#endif

	assert(priv->num_msix_entries == un);
	return 0;

err_unregister_irq:
	mxgbe_msix_release(priv);
	return err;
} /* mxgbe_msix_init */

void mxgbe_msix_release(mxgbe_priv_t *priv)
{
	int i;

	for (i = 0; i < priv->num_msix_entries; i++) {
		if (priv->vector[i].irq != -1) {
			irq_set_affinity_hint(priv->msix_entries[i].vector,
					      NULL);
			free_irq(priv->msix_entries[i].vector,
				 (void *)&priv->vector[i]);
		}
	}
} /* mxgbe_msix_release */
