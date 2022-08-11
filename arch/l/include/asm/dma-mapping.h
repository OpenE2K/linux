#ifndef ___ASM_L_DMA_MAPPING_H
#define ___ASM_L_DMA_MAPPING_H

#include <linux/scatterlist.h>
#include <linux/mm.h>
#include <linux/dma-debug.h>

/*
 * No easy way to get cache size on all processors
 * so return the maximum possible to be safe.
 */
#define ARCH_DMA_MINALIGN (1 << INTERNODE_CACHE_SHIFT)

extern const struct dma_map_ops *dma_ops;

static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
	return dma_ops;
}

#endif /* ___ASM_L_DMA_MAPPING_H */
