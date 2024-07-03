/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_MSIX_H__
#define MXGBE_MSIX_H__


int mxgbe_msix_prepare(mxgbe_priv_t *priv);
void mxgbe_msix_free(mxgbe_priv_t *priv);
int mxgbe_msix_init(mxgbe_priv_t *priv);
void mxgbe_msix_release(mxgbe_priv_t *priv);


#endif /* MXGBE_MSIX_H__ */
