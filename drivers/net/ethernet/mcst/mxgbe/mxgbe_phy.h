/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_PHY_H__
#define MXGBE_PHY_H__


void mxgbe_mdio_reset(mxgbe_priv_t *priv);
int mxgbe_mdio_register(mxgbe_priv_t *priv);

int mxgbe_set_pcsphy_mode(struct net_device *ndev);

u16 mxgbe_pcs_read(mxgbe_priv_t *priv, int regnum);
void mxgbe_pcs_write(mxgbe_priv_t *priv, int regnum, u16 value);

#endif /* MXGBE_PHY_H__ */
