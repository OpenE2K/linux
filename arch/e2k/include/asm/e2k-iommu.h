#ifndef __ASM_E2K_IOMMU_H
#define __ASM_E2K_IOMMU_H

#include <linux/kvm_host.h>

extern int iommu_panic_off;

extern void e2k_iommu_error_interrupt(struct pt_regs *regs);
extern void e2k_iommu_shutdown(void);
extern void e2k_iommu_set_kvm_device(struct device *dev, struct kvm *kvm);

#endif /* __ASM_E2K_IOMMU_H */
