/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	__KVM_PIC_H
#define	__KVM_PIC_H

#include "lapic.h"
#include "cepic.h"
#include "ioepic.h"
#include "asm/epic.h"

/*
 * Choose between paravirt LAPIC/IOAPIC and CEPIC/IOEPIC models, based on
 * kvm->arch.is_epic. This variable is set after receiving an EPIC flag from
 * QEMU
 */

static inline bool kvm_is_epic(const struct kvm *kvm)
{
	return kvm->arch.is_epic;
}

static inline bool kvm_vcpu_is_epic(const struct kvm_vcpu *vcpu)
{
	return kvm_is_epic(vcpu->kvm);
}

static inline int kvm_create_local_pic(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		return kvm_create_cepic(vcpu);
	else
		return kvm_create_lapic(vcpu);
}

static inline int kvm_epic_sysrq_deliver(struct kvm_vcpu *vcpu);
static inline int kvm_pic_sysrq_deliver(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		return kvm_epic_sysrq_deliver(vcpu);
	else
		return kvm_apic_sysrq_deliver(vcpu);
}

static inline int kvm_pic_nmi_deliver(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		return kvm_epic_nmi_deliver(vcpu);
	else
		return kvm_apic_nmi_deliver(vcpu);
}

extern void reset_cepic_state(struct kvm_vcpu *vcpu);
extern void reset_lapic_state(struct kvm_vcpu *vcpu);
static inline void reset_pic_state(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		reset_cepic_state(vcpu);
	else
		reset_lapic_state(vcpu);
}

extern int kvm_ioepic_init(struct kvm *kvm);
extern int kvm_ioapic_init(struct kvm *kvm);
static inline int kvm_io_pic_init(struct kvm *kvm)
{
	if (kvm_is_epic(kvm))
		return kvm_ioepic_init(kvm);
	else
		return kvm_ioapic_init(kvm);
}

static inline int kvm_io_pic_set_base(struct kvm *kvm, u64 new_base)
{
	if (kvm_is_epic(kvm))
		return kvm_ioepic_set_base(kvm, new_base);
	return -ENODEV;
}

static inline void kvm_pic_set_vapic_addr(struct kvm_vcpu *vcpu,
						gpa_t vapic_addr)
{
	if (!kvm_vcpu_is_epic(vcpu))
		kvm_lapic_set_vapic_addr(vcpu, vapic_addr);
}

/* Choose between software and hardware EPIC */
extern int kvm_irq_delivery_to_hw_epic(struct kvm *kvm, int src,
		const struct kvm_cepic_irq *irq);
extern int kvm_irq_delivery_to_sw_epic(struct kvm *kvm, int src,
		struct kvm_cepic_irq *irq);
static inline int kvm_irq_delivery_to_epic(struct kvm *kvm, int src,
		struct kvm_cepic_irq *irq)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm->arch.is_hv)
		return kvm_irq_delivery_to_hw_epic(kvm, src, irq);
	else
#endif
		return kvm_irq_delivery_to_sw_epic(kvm, src, irq);
}

extern int kvm_hw_epic_sysrq_deliver(struct kvm_vcpu *vcpu);
static inline int kvm_epic_sysrq_deliver(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (vcpu->kvm->arch.is_hv)
		return kvm_hw_epic_sysrq_deliver(vcpu);
	else
#endif
		return kvm_sw_epic_sysrq_deliver(vcpu);
}

#ifdef CONFIG_KVM_ASYNC_PF
extern int kvm_hw_epic_async_pf_wake_deliver(struct kvm_vcpu *vcpu);
#endif /* CONFIG_KVM_ASYNC_PF */

extern int kvm_set_epic_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_id, int level, bool line_status);
extern int kvm_set_apic_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_id, int level, bool line_status);

static inline int
kvm_set_pic_msi(struct kvm_kernel_irq_routing_entry *e,
	struct kvm *kvm, int irq_id, int level, bool line_status)
{
	if (kvm_is_epic(kvm))
		return kvm_set_epic_msi(e, kvm, irq_id, level, line_status);
	else
		return kvm_set_apic_msi(e, kvm, irq_id, level, line_status);
}

extern void kvm_int_violat_delivery_to_hw_epic(struct kvm *kvm);
extern int kvm_hw_epic_deliver_to_icr(struct kvm_vcpu *vcpu,
	unsigned int vector, u8 dlvm);

extern void kvm_ioapic_release(struct kvm *kvm);
extern void kvm_ioepic_destroy(struct kvm *kvm);
static inline void kvm_iopic_release(struct kvm *kvm)
{
	if (kvm_is_epic(kvm))
		kvm_ioepic_destroy(kvm);
	else
		kvm_ioapic_release(kvm);
}

extern void kvm_free_lapic(struct kvm_vcpu *vcpu);
extern void kvm_free_cepic(struct kvm_vcpu *vcpu);
static inline void kvm_free_local_pic(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		kvm_free_cepic(vcpu);
	else
		kvm_free_lapic(vcpu);
}

extern bool kvm_dy_has_epic_interrupts(const struct kvm_vcpu *vcpu);
extern bool kvm_vcpu_has_epic_interrupts(const struct kvm_vcpu *vcpu);
extern bool kvm_vcpu_has_apic_interrupts(const struct kvm_vcpu *vcpu);
static inline bool kvm_vcpu_has_pic_interrupts(const struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		return kvm_vcpu_has_epic_interrupts(vcpu);
	else
		return kvm_vcpu_has_apic_interrupts(vcpu);
}

extern int kvm_cpu_has_pending_epic_timer(struct kvm_vcpu *vcpu);
extern int kvm_cpu_has_pending_apic_timer(struct kvm_vcpu *vcpu);
static inline int kvm_cpu_has_pending_pic_timer(struct kvm_vcpu *vcpu)
{
	if (kvm_vcpu_is_epic(vcpu))
		return kvm_cpu_has_pending_epic_timer(vcpu);
	else
		return kvm_cpu_has_pending_apic_timer(vcpu);
}

/* Choose between software and hardware LAPIC */
static inline bool kvm_is_hw_apic(const struct kvm *kvm)
{
	return kvm->arch.is_hv;
}

static inline bool kvm_vcpu_is_hw_apic(const struct kvm_vcpu *vcpu)
{
	return kvm_is_hw_apic(vcpu->kvm);
}

extern int kvm_irq_delivery_to_hw_apic(struct kvm *kvm,
		struct kvm_lapic *src, struct kvm_lapic_irq *irq);
extern int kvm_irq_delivery_to_sw_apic(struct kvm *kvm,
		struct kvm_lapic *src, struct kvm_lapic_irq *irq);
static inline int kvm_irq_delivery_to_apic(struct kvm *kvm,
		struct kvm_lapic *src, struct kvm_lapic_irq *irq)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_is_hw_apic(kvm))
		return kvm_irq_delivery_to_hw_apic(kvm, src, irq);
	else
#endif
		return kvm_irq_delivery_to_sw_apic(kvm, src, irq);
}

extern int kvm_get_hw_apic_interrupt(struct kvm_vcpu *vcpu);
extern int kvm_get_sw_apic_interrupt(struct kvm_vcpu *vcpu);
static inline int kvm_get_apic_interrupt(struct kvm_vcpu *vcpu)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(vcpu))
		return kvm_get_hw_apic_interrupt(vcpu);
	else
#endif
		return kvm_get_sw_apic_interrupt(vcpu);
}

extern void hw_apic_set_eoi(struct kvm_lapic *apic);
extern void sw_apic_set_eoi(struct kvm_lapic *apic);
static inline void apic_set_eoi(struct kvm_lapic *apic)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(apic->vcpu))
		hw_apic_set_eoi(apic);
	else
#endif
		sw_apic_set_eoi(apic);
}

extern void start_hw_apic_timer(struct kvm_lapic *apic, u32 apic_tmict);
extern void start_sw_apic_timer(struct kvm_lapic *apic, u32 apic_tmict);
static inline void start_apic_timer(struct kvm_lapic *apic, u32 apic_tmict)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(apic->vcpu))
		start_hw_apic_timer(apic, apic_tmict);
	else
#endif
		start_sw_apic_timer(apic, apic_tmict);
}

extern void hw_apic_write_nm(struct kvm_lapic *apic, u32 val);
static inline void apic_write_nm(struct kvm_lapic *apic, u32 val)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(apic->vcpu))
		hw_apic_write_nm(apic, val);
#endif
}

extern u32 hw_apic_read_nm(struct kvm_lapic *apic);
extern u32 sw_apic_read_nm(struct kvm_lapic *apic);
static inline u32 apic_read_nm(struct kvm_lapic *apic)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(apic->vcpu))
		return hw_apic_read_nm(apic);
	else
#endif
		return sw_apic_read_nm(apic);
}

extern u32 hw_apic_get_tmcct(struct kvm_lapic *apic);
extern u32 sw_apic_get_tmcct(struct kvm_lapic *apic);
static inline u32 apic_get_tmcct(struct kvm_lapic *apic)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(apic->vcpu))
		return hw_apic_get_tmcct(apic);
	else
#endif
		return sw_apic_get_tmcct(apic);
}

extern void hw_apic_write_lvtt(struct kvm_lapic *apic, u32 apic_lvtt);
static inline void apic_write_lvtt(struct kvm_lapic *apic, u32 apic_lvtt)
{
#ifdef CONFIG_KVM_HW_VIRTUALIZATION
	if (kvm_vcpu_is_hw_apic(apic->vcpu))
		return hw_apic_write_lvtt(apic, apic_lvtt);
#endif
}

extern bool kvm_check_lapic_priority(struct kvm_vcpu *vcpu);

#endif	/* __KVM_PIC_H */
