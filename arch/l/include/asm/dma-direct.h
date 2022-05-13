#ifndef ___ASM_L_DMA_DIRECT_H
#define ___ASM_L_DMA_DIRECT_H

static inline bool dma_capable(struct device *dev, dma_addr_t addr, size_t size)
{
	if (!dev) /* caller knows better */
		return true;
	if (!dev->dma_mask)
		return false;
#if defined(CONFIG_E2K) && defined(CONFIG_NUMA)
	if (cpu_has(CPU_HWBUG_CANNOT_DO_DMA_IN_NEIGHBOUR_NODE)) {
		if (page_to_nid(phys_to_page(addr)) !=  dev_to_node(dev))
			return false;
	}
#endif
	return addr + size - 1 <= *dev->dma_mask;
}

static inline dma_addr_t __phys_to_dma(struct device *dev, phys_addr_t paddr)
{
	return paddr;
}

static inline phys_addr_t __dma_to_phys(struct device *dev, dma_addr_t daddr)
{
	return daddr;
}

#endif /* ___ASM_L_DMA_DIRECT_H */
