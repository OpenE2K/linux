/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_TXQ_H__
#define MXGBE_TXQ_H__


#define INC_TXQ_INDEX(NI, I, Q) \
do { \
	NI = I + 1; \
	if (NI >= priv->txq[Q].descr_cnt) \
		NI = NI - priv->txq[Q].descr_cnt; \
} while (0)


int mxgbe_txq_alloc_all(mxgbe_priv_t *priv);
void mxgbe_txq_free_all(mxgbe_priv_t *priv);

void mxgbe_tx_init(mxgbe_priv_t *priv);
int mxgbe_txq_init_all(mxgbe_priv_t *priv);


void mxgbe_txq_start(mxgbe_priv_t *priv, int qn);


int mxgbe_txq_send(mxgbe_priv_t *priv, int qn, mxgbe_descr_t *descr,
		   mxgbe_tx_buff_t *tx_buff);

irqreturn_t mxgbe_txq_irq_handler(int irq, void *dev_id);


#ifdef DEBUG
void mxgbe_tx_dbg_prn_descr_s(mxgbe_priv_t *priv, mxgbe_descr_t *descr);
void mxgbe_tx_dbg_prn_data(mxgbe_priv_t *priv, char *data, ssize_t size);
#endif /* DEBUG */


#endif /* MXGBE_TXQ_H__ */
