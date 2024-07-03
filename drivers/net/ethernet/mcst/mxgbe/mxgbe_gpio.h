/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_GPIO_H__
#define MXGBE_GPIO_H__


void mxgbe_gpio_init(mxgbe_priv_t *priv);
void mxgbe_gpio_phy_reset(mxgbe_priv_t *priv);

int mxgbe_gpio_probe(mxgbe_priv_t *priv);
void mxgbe_gpio_remove(void);


#endif /* MXGBE_GPIO_H__ */
