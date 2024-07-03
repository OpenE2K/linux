/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Kernel-based Virtual Machine driver for Linux
 *
 * This header defines e2k CPU architecture specific interfaces
 *
 * This work is licensed under the terms of the GNU GPL, version 2.  See
 * the COPYING file in the top-level directory.
 *
 */

#ifndef __E2K_CPU_GUEST_H
#define __E2K_CPU_GUEST_H

#include <linux/types.h>

#include <asm/process.h>
#include <asm/kvm/hypervisor.h>
#include <asm/signal.h>
#include <asm/kvm/guest/cpu.h>

#define	VCPU_DEBUG_MODE_ON	(kvm_get_vcpu_state()->debug_mode_on)

/*
 * Basic functions accessing virtual CPU running state info on guest.
 */
#define	GUEST_RUNSTATE_INFO_BASE	(offsetof(kvm_vcpu_state_t, runstate))

/* own VCPU runstate info: directly accessible through global registers */
static inline kvm_runstate_info_t *kvm_vcpu_runstate_info(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return (kvm_runstate_info_t *)(vcpu_base + GUEST_RUNSTATE_INFO_BASE);
}
/* other VCPU runstate info: accessible through global pointers table */
static inline kvm_runstate_info_t *kvm_the_vcpu_runstate_info(long vcpu_id)
{
	kvm_vcpu_state_t *vcpu_state = kvm_get_the_vcpu_state(vcpu_id);

	return &vcpu_state->runstate;
}

#define	DEBUG_CHECK_VCPU_ID

#ifdef	DEBUG_CHECK_VCPU_ID
static inline void kvm_check_vcpu_id(void)
{
	if (unlikely(raw_smp_processor_id() != KVM_READ_VCPU_ID())) {
		pr_err("%s(): different smp processor id #%d and "
			"VCPU id #%d\n",
			__func__, raw_smp_processor_id(), KVM_READ_VCPU_ID());
		BUG_ON(raw_smp_processor_id() != KVM_READ_VCPU_ID());
	}
}
#else	/* !DEBUG_CHECK_VCPU_ID */
static inline void kvm_check_vcpu_id(void)
{
}
#endif	/* DEBUG_CHECK_VCPU_ID */

/* Host info access */
static inline int kvm_vcpu_host_machine_id(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return host_info->mach_id;
}
static inline int kvm_vcpu_host_cpu_iset(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return host_info->cpu_iset;
}
static inline int kvm_vcpu_host_cpu_rev(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return host_info->cpu_rev;
}
static inline bool kvm_vcpu_host_mmu_support_pt_v6(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return host_info->mmu_support_pt_v6;
}
static inline bool kvm_host_support_hw_hc(void)
{
	return kvm_vcpu_host_support_hw_hc();
}
static inline bool kvm_vcpu_host_is_hv(void)
{
	kvm_host_info_t *host_info;
	unsigned long features, hv_mask;

	host_info = kvm_get_host_info();
	features = host_info->features;
	hv_mask = features & (KVM_FEAT_HV_CPU_MASK | KVM_FEAT_HV_MMU_MASK);

	return hv_mask == (KVM_FEAT_HV_CPU_MASK | KVM_FEAT_HV_MMU_MASK);
}
static inline kvm_time_t *kvm_vcpu_time_info(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return &host_info->time;
}

/*
 * Basic functions to access to local APIC state on guest.
 */
#define	GUEST_LAPIC_STATE_BASE	(offsetof(kvm_vcpu_state_t, lapic))

static inline kvm_apic_state_t *kvm_vcpu_lapic_state(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return (kvm_apic_state_t *)(vcpu_base + GUEST_LAPIC_STATE_BASE);
}
static inline atomic_t *kvm_get_lapic_virqs_num(void)
{
	kvm_apic_state_t *lapic;

	lapic = kvm_vcpu_lapic_state();
	return &lapic->virqs_num;
}

/*
 * Basic functions to access to CEPIC state on guest.
 */
#define	GUEST_CEPIC_STATE_BASE	(offsetof(kvm_vcpu_state_t, cepic))

static inline kvm_epic_state_t *kvm_vcpu_cepic_state(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return (kvm_epic_state_t *)(vcpu_base + GUEST_CEPIC_STATE_BASE);
}
static inline atomic_t *kvm_get_cepic_virqs_num(void)
{
	kvm_epic_state_t *cepic;

	cepic = kvm_vcpu_cepic_state();
	return &cepic->virqs_num;
}

/*
 * Basic functions to access to VIRQs state on guest.
 */
#define	GUEST_VIRQs_STATE_BASE	(offsetof(kvm_vcpu_state_t, virqs))

static inline kvm_virqs_state_t *kvm_vcpu_virqs_state(void)
{
	unsigned long vcpu_base;

	KVM_GET_VCPU_STATE_BASE(vcpu_base);
	return (kvm_virqs_state_t *)(vcpu_base + GUEST_VIRQs_STATE_BASE);
}
static inline atomic_t *kvm_get_timer_virqs_num(void)
{
	kvm_virqs_state_t *virqs;

	virqs = kvm_vcpu_virqs_state();
	return &virqs->timer_virqs_num;
}
static inline atomic_t *kvm_get_hvc_virqs_num(void)
{
	kvm_virqs_state_t *virqs;

	virqs = kvm_vcpu_virqs_state();
	return &virqs->hvc_virqs_num;
}

#endif /* __E2K_CPU_GUEST_H */
