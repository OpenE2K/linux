#ifndef __ASM_E2K_IOMMU_H
#define __ASM_E2K_IOMMU_H

/*
 * This struct contains device specific data for the IOMMU
 */
struct e2k_iommu_dev_data {
	struct e2k_iommu_domain *domain; /* Domain the device is bound to */
	struct kvm *kvm;		 /* Virtual machine, to which device is
					  * passed */
};

extern int iommu_panic_off;
extern void e2k_iommu_error_interrupt(void);
extern void e2k_iommu_guest_write_ctrl(u32 reg_value);
extern void e2k_iommu_setup_guest_2d_dte(struct kvm *kvm, u64 g_page_table);
extern void e2k_iommu_flush_guest(struct kvm *kvm, u64 command);

#endif /* __ASM_E2K_IOMMU_H */
