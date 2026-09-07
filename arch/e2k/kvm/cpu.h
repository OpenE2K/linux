/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_CPU_H
#define __KVM_E2K_CPU_H

#include <linux/kvm_host.h>
#include <asm/cpu_regs.h>
#include <asm/trap_table.h>
#include <asm/kvm/switch.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/trace_kvm.h>

#include "intercepts.h"
#include "process.h"
#include "irq.h"
#include "mmutrace-e2k.h"
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
#include "paravirt_sw/cpu.h"
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#undef	DEBUG_HOST_ACTIVATION_MODE
#undef	DebugHACT
#define	DEBUG_HOST_ACTIVATION_MODE	0	/* KVM host kernel data */
						/* stack activations */
						/* debugging */
#define	DebugHACT(fmt, args...)						\
({									\
	if (DEBUG_HOST_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_ACTIVATION_MODE
#undef	DebugKVMACT
#define	DEBUG_KVM_ACTIVATION_MODE	0	/* KVM guest kernel data stack activations */
#define	DebugKVMACT(fmt, args...)					\
({									\
	if (DEBUG_KVM_ACTIVATION_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})


extern e2k_idr_t kvm_vcpu_get_idr(const struct kvm_vcpu *vcpu);

#ifndef CONFIG_KVM_PARAVIRTUALIZATION
/*
 * Only the state of the hardware virtualization bits is interesting
 */
static inline e2k_core_mode_t read_guest_CORE_MODE_reg(struct kvm_vcpu *vcpu)
{
	return read_SH_CORE_MODE_reg();
}

static inline void
write_guest_CORE_MODE_reg(struct kvm_vcpu *vcpu, e2k_core_mode_t new_reg)
{
	write_SH_CORE_MODE_reg(new_reg);
}

static inline unsigned int guest_trap_init(struct kvm *kvm)
{
	/* Guest will manage his OSEM by himself */
	return 0;
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */

#ifdef CONFIG_KVM_HW_VIRTUALIZATION
extern void kvm_hv_update_guest_stacks_registers(struct kvm_vcpu *vcpu,
						 guest_hw_stack_t *stack_regs);
extern void hv_vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu *vcpu, const struct
						     kvm_hw_cpu_context *hw_ctxt);
extern int kvm_prepare_hv_vcpu_start_stacks(struct kvm_vcpu *vcpu);
extern void init_hv_vcpu_intc_ctxt(struct kvm_vcpu *vcpu);
extern void write_hw_ctxt_to_hv_vcpu_registers(struct kvm_vcpu *vcpu,
					       const struct kvm_hw_cpu_context *hw_ctxt,
					       const struct kvm_sw_cpu_context
					       *sw_ctxt);
extern void kvm_hv_setup_mmu_spt_context(struct kvm_vcpu *vcpu);
extern void init_backup_hw_ctxt(struct kvm_vcpu *vcpu);
#else
static inline void kvm_hv_update_guest_stacks_registers(struct kvm_vcpu *vcpu,
							guest_hw_stack_t *stack_regs)
{
}

static inline void hv_vcpu_write_os_cu_hw_ctxt_to_registers(struct kvm_vcpu
							    *vcpu,
							    const struct kvm_hw_cpu_context
							    *hw_ctxt)
{
}

static inline int kvm_prepare_hv_vcpu_start_stacks(struct kvm_vcpu *vcpu)
{
	return -EOPNOTSUPP;
}

static inline void init_hv_vcpu_intc_ctxt(struct kvm_vcpu *vcpu)
{
}

static inline void write_hw_ctxt_to_hv_vcpu_registers(struct kvm_vcpu *vcpu,
					const struct kvm_hw_cpu_context *hw_ctxt,
					const struct kvm_sw_cpu_context *sw_ctxt)
{
}

static inline void kvm_hv_setup_mmu_spt_context(struct kvm_vcpu *vcpu)
{
}

static inline void init_backup_hw_ctxt(struct kvm_vcpu *vcpu)
{
}
#endif

#endif /* __KVM_E2K_CPU_H */
