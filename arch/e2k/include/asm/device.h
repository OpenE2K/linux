#ifndef _ASM_E2K_DEVICE_H
/*
 * Arch specific extensions to struct device
 *
 * This file is released under the GPLv2
 */
#include <asm/e2k-iommu.h>

struct dev_archdata {
	unsigned int link;
#ifdef CONFIG_IOMMU_API
	void *iommu;			/* private IOMMU data */
	struct e2k_iommu_domain *domain; /* Domain the device is bound to */
	struct kvm *kvm;		 /* Virtual machine, to which device is
					  * passed */
#endif
};

struct pdev_archdata {
};

#define dev_to_link(__dev)		(__dev ? (__dev)->archdata.link : 0)
#define set_dev_link(__dev, __link)	do {						\
						(__dev)->archdata.link = __link;	\
					} while(0)

#endif /* _ASM_E2K_DEVICE_H */
