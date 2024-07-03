/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_RXQ_H__
#define MXGBE_RXQ_H__


#define INC_RXQ_INDEX(NI, I, Q) \
do { \
	NI = I + 1; \
	if (NI >= priv->rxq[Q].descr_cnt) \
		NI = NI - priv->rxq[Q].descr_cnt; \
} while (0)


int mxgbe_rxq_alloc_all(mxgbe_priv_t *priv);
void mxgbe_rxq_free_all(mxgbe_priv_t *priv);

void mxgbe_rx_init(mxgbe_priv_t *priv);
int mxgbe_rxq_init_all(mxgbe_priv_t *priv);

void mxgbe_rx_multicast_disable(mxgbe_priv_t *priv);
void mxgbe_rx_multicast_enable(mxgbe_priv_t *priv);

void mxgbe_rxq_start(mxgbe_priv_t *priv, int qn);
void mxgbe_rxq_stop(mxgbe_priv_t *priv, int qn);


int mxgbe_rxq_request(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
		      u16 head);

irqreturn_t mxgbe_rxq_irq_handler(int irq, void *dev_id);


#ifdef DEBUG
void mxgbe_rx_dbg_prn_descr_s(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
			      u16 tail_cur);
void mxgbe_rx_dbg_prn_data(mxgbe_priv_t *priv, char *data, ssize_t size);
#endif /* DEBUG */


#endif /* MXGBE_RXQ_H__ */
