/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef ___ASM_L_DMA_DIRECT_H
#define ___ASM_L_DMA_DIRECT_H

static inline dma_addr_t phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	return paddr;
}

static inline phys_addr_t dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	return daddr;
}

#endif /* ___ASM_L_DMA_DIRECT_H */
