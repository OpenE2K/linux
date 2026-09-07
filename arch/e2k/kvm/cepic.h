/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/kvm_host.h>

#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/cepic.h"
#else
static inline int kvm_create_cepic(struct kvm_vcpu *vcpu)
{
	return 0;
}
static inline void kvm_free_cepic(struct kvm_vcpu *vcpu) { }
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

extern u32 kvm_vcpu_to_full_cepic_id(const struct kvm_vcpu *vcpu);
