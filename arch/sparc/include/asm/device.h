/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Arch specific extensions to struct device
 */
#ifndef _ASM_SPARC_DEVICE_H
#define _ASM_SPARC_DEVICE_H

#if defined(CONFIG_E90S)

struct dev_archdata {
#ifdef CONFIG_IOMMU_API
	void *iommu;			/* private IOMMU data */
#endif
};

struct pdev_archdata {
};

#define dev_to_link(dev)		0
#define set_dev_link(dev, link)		do { } while (0)

#else	/*CONFIG_E90S*/
#include <asm/openprom.h>

struct device_node;
struct platform_device;

struct dev_archdata {
	void			*iommu;
	void			*stc;
	void			*host_controller;
	struct platform_device	*op;
	int			numa_node;
};

void of_propagate_archdata(struct platform_device *bus);

struct pdev_archdata {
	struct resource		resource[PROMREG_MAX];
	unsigned int		irqs[PROMINTR_MAX];
	int			num_irqs;
};
#endif	/*CONFIG_E90S*/
#endif /* _ASM_SPARC_DEVICE_H */
