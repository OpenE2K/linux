/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_KVM_GUEST_CPU_H
#define __ASM_KVM_GUEST_CPU_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/kvm/paravirt_sw/guest.h>
#include <asm/kvm/paravirt_sw/hypervisor.h>

#ifdef CONFIG_KVM_GUEST_KERNEL
static inline bool kvm_vcpu_host_support_hw_hc(void)
{
	kvm_host_info_t *host_info;

	host_info = kvm_get_host_info();
	return host_info->support_hw_hc;
}
#endif

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_GUEST_CPU_H */
