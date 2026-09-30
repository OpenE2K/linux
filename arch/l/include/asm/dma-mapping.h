/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef ___ASM_L_DMA_MAPPING_H
#define ___ASM_L_DMA_MAPPING_H

#include <linux/scatterlist.h>
#include <linux/mm.h>

extern const struct dma_map_ops *dma_ops;

static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return dma_ops;
}

#endif /* ___ASM_L_DMA_MAPPING_H */
