/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef MXGBE_HW_H__
#define MXGBE_HW_H__


u32 mxgbe_rreg32(void __iomem *base, u32 port);
u64 mxgbe_rreg64c(void __iomem *base, u32 port);
void mxgbe_wreg32(void __iomem *base, u32 port, u32 val);
void mxgbe_wreg64(void __iomem *base, u32 port, u64 val);

int mxgbe_hw_reset(mxgbe_priv_t *priv);
int mxgbe_hw_getinfo(mxgbe_priv_t *priv);
int mxgbe_hw_init(mxgbe_priv_t *priv);
void mxgbe_hw_start(mxgbe_priv_t *priv);


#endif /* MXGBE_HW_H__ */
