/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ___ASM_SPARC_DMA_MAPPING_H
#define ___ASM_SPARC_DMA_MAPPING_H

#if	defined(CONFIG_E90) || defined(CONFIG_E90S)
#include <asm-l/dma-mapping.h>
#else /*CONFIG_E90 || CONFIG_E90S*/

#include <asm/cpu_type.h>

extern const struct dma_map_ops *dma_ops;

extern struct bus_type pci_bus_type;

static inline const struct dma_map_ops *get_arch_dma_ops(struct bus_type *bus)
{
#ifdef CONFIG_SPARC_LEON
	if (sparc_cpu_model == sparc_leon)
		return NULL;
#endif
#if defined(CONFIG_SPARC32) && defined(CONFIG_PCI)
	if (bus == &pci_bus_type)
		return NULL;
#endif
	return dma_ops;
}

#define HAVE_ARCH_DMA_SET_MASK 1

static inline int dma_set_mask(struct device *dev, u64 mask)
{
#ifdef CONFIG_PCI
	if (dev->bus == &pci_bus_type) {
		if (!dev->dma_mask || !dma_supported(dev, mask))
			return -EINVAL;
		*dev->dma_mask = mask;
		return 0;
	}
#endif
	return -EINVAL;
}

#include <asm-generic/dma-mapping-common.h>
#endif /*CONFIG_E90 || CONFIG_E90S*/

#endif
