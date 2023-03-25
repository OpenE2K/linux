/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This header defines architecture specific interface hypervisor -> guest
 * to know more about the KVM & hypervisor features
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef _ASM_E2K_KVM_HYPERVISOR_H
#define _ASM_E2K_KVM_HYPERVISOR_H

#include <linux/types.h>

#include <asm/glob_regs.h>
#include <asm/kvm/guest.h>

/* KVM and hypervisor features */
/* (see field 'features' of kvm_host_info_t structure at asm/kvm/guest.h) */
#define	KVM_FEAT_HV_CPU_BIT	0	/* Hardware virtualized CPU is ON */
#define	KVM_FEAT_PV_CPU_BIT	1	/* ParaVirtualized CPU is ON */
#define	KVM_FEAT_HW_HCALL_BIT	4	/* HardWare supported HyperCALL is on */
#define	KVM_FEAT_PV_HCALL_BIT	5	/* ParaVirtualized HyperCALLs is on */
#define	KVM_FEAT_HV_MMU_BIT	8	/* Hardware Virtualized MMU is ON */
#define	KVM_FEAT_PV_MMU_BIT	9	/* MMU support is ParaVirtualization */
#define	KVM_FEAT_MMU_SPT_BIT	10	/* MMU support is based on shadow */
					/* paging */
#define	KVM_FEAT_MMU_TDP_BIT	11	/* MMU support is based on TDP */
#define	KVM_FEAT_HV_EPIC_BIT	16	/* Hardware Virtualized EPIC is ON */
#define	KVM_FEAT_PV_APIC_BIT	18	/* ParaVirtualized APIC is ON */
					/* Simulator into hypervisor */
#define	KVM_FEAT_PV_EPIC_BIT	19	/* ParaVirtualized EPIC is ON */
					/* Simulator into hypervisor */

/* bit mask of features to direct test */
#define	KVM_FEAT_HV_CPU_MASK	(1UL << KVM_FEAT_HV_CPU_BIT)
#define	KVM_FEAT_PV_CPU_MASK	(1UL << KVM_FEAT_PV_CPU_BIT)
#define	KVM_FEAT_HW_HCALL_MASK	(1UL << KVM_FEAT_HW_HCALL_BIT)
#define	KVM_FEAT_PV_HCALL_MASK	(1UL << KVM_FEAT_PV_HCALL_BIT)
#define	KVM_FEAT_HV_MMU_MASK	(1UL << KVM_FEAT_HV_MMU_BIT)
#define	KVM_FEAT_PV_MMU_MASK	(1UL << KVM_FEAT_PV_MMU_BIT)
#define	KVM_FEAT_MMU_SPT_MASK	(1UL << KVM_FEAT_MMU_SPT_BIT)
#define	KVM_FEAT_MMU_TDP_MASK	(1UL << KVM_FEAT_MMU_TDP_BIT)
#define	KVM_FEAT_HV_EPIC_MASK	(1UL << KVM_FEAT_HV_EPIC_BIT)
#define	KVM_FEAT_PV_APIC_MASK	(1UL << KVM_FEAT_PV_APIC_BIT)
#define	KVM_FEAT_PV_EPIC_MASK	(1UL << KVM_FEAT_PV_EPIC_BIT)

/*
 * Basic function to access to host info on guest.
 */
#define	GUEST_HOST_INFO_BASE	(offsetof(kvm_vcpu_state_t, host))

static inline kvm_host_info_t *kvm_get_host_info(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return *((kvm_host_info_t **)(vcpu_base + GUEST_HOST_INFO_BASE));
}

static inline unsigned long kvm_hypervisor_features(void)
{
	return kvm_get_host_info()->features;
}
static inline bool kvm_test_hprv_feats_mask(unsigned long feature_mask)
{
	return (kvm_hypervisor_features() & feature_mask) != 0;
}
static inline bool kvm_test_hprv_full_feats_mask(unsigned long feature_mask)
{
	return (kvm_hypervisor_features() & feature_mask) == feature_mask;
}
static inline bool kvm_test_hprv_feats_bit(int feature_bit)
{
	return kvm_test_hprv_feats_mask(1UL << feature_bit);
}

#define	IS_HV_CPU_KVM()		kvm_test_hprv_feats_mask(KVM_FEAT_HV_CPU_MASK)
#define	IS_PV_CPU_KVM()		kvm_test_hprv_feats_mask(KVM_FEAT_PV_CPU_MASK)
#define	IS_HV_MMU_KVM()		kvm_test_hprv_feats_mask(KVM_FEAT_HV_MMU_MASK)
#define	IS_PV_MMU_KVM()		kvm_test_hprv_feats_mask(KVM_FEAT_PV_MMU_MASK)
#define	IS_HV_CPU_PV_MMU_KVM()	\
		kvm_test_hprv_full_feats_mask(KVM_FEAT_HV_CPU_MASK | \
						KVM_FEAT_PV_MMU_MASK)
#define	IS_HV_CPU_HV_MMU_KVM()	\
		kvm_test_hprv_full_feats_mask(KVM_FEAT_HV_CPU_MASK | \
						KVM_FEAT_HV_MMU_MASK)
#define	IS_PV_CPU_PV_MMU_KVM()	\
		kvm_test_hprv_full_feats_mask(KVM_FEAT_PV_CPU_MASK | \
						KVM_FEAT_PV_MMU_MASK)
#define	IS_MMU_SPT()		kvm_test_hprv_feats_mask(KVM_FEAT_MMU_SPT_MASK)
#define	IS_MMU_TDP()		kvm_test_hprv_feats_mask(KVM_FEAT_MMU_TDP_MASK)
#define	IS_HV_MMU_SPT()		(IS_HV_MMU_KVM() && IS_MMU_SPT())
#define	IS_HV_MMU_TDP()		(IS_HV_MMU_KVM() && IS_MMU_TDP())
#define	IS_HV_KVM()		IS_HV_CPU_HV_MMU_KVM()
#define	IS_PV_KVM()		IS_PV_CPU_PV_MMU_KVM()
#define	IS_HW_HCALL_KVM()	kvm_test_hprv_feats_mask(KVM_FEAT_HW_HCALL_MASK)
#define	IS_PV_HCALL_KVM()	kvm_test_hprv_feats_mask(KVM_FEAT_PV_HCALL_MASK)
#define	IS_HV_EPIC_KVM()	kvm_test_hprv_feats_mask(KVM_FEAT_HV_EPIC_MASK)
#define	IS_PV_APIC_KVM()	kvm_test_hprv_feats_mask(KVM_FEAT_PV_APIC_MASK)
#define	IS_PV_EPIC_KVM()	kvm_test_hprv_feats_mask(KVM_FEAT_PV_EPIC_MASK)

static inline unsigned long kvm_hypervisor_inject_interrupt(void)
{
	/*
	 * Not yet fully implemented
	 * The real implementation requires checking for interrupts and only
	 * after that call the host to inject interrupt
	return HYPERVISOR_inject_interrupt();
	 */
	return 0;
}

#endif /* _ASM_E2K_KVM_HYPERVISOR_H */
