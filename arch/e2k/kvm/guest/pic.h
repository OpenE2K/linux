/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef	__KVM_GUEST_PIC_H
#define	__KVM_GUEST_PIC_H

#include <asm/machdep.h>
#include <asm/l_timer.h>
#include <asm/pic.h>
#include <asm/trap_table.h>

/* Choosing between software LAPIC/CEPIC models and execution with hardware support */

extern irqreturn_t kvm_do_interrupt(struct pt_regs *regs);
extern __init void kvm_time_init_clockevents(void);
extern __init void kvm_time_init_clocksource(void);
extern void kvm_time_shutdown(void);
extern __init int kvm_setup_sw_timer(void);

static inline irqreturn_t guest_do_interrupt_pic(struct pt_regs *regs)
{
	irqreturn_t ret;

	ret = native_do_interrupt(regs);

	if (regs->interrupt_vector == KVM_NMI_APIC_VECTOR) {
		/* NMI IPI on guest implemented as general inteerupt */
		/* with vector KVM_NMI_APIC_VECTOR */
		/* but nmi_call_function_interrupt() has been called */
		/* under NMI disabled, so now enable NMIs */
		exiting_irq();
		KVM_INIT_KERNEL_IRQ_MASK_REG(false,	/* enable IRQs */
					     false	/* disable NMIs */);
	}
	return ret;
}

#ifdef CONFIG_EPIC
extern int pic_get_vector(void);
extern int e2k_virt_get_vector_apic(void);
extern int e2k_virt_get_vector_epic(void);
static inline int e2k_virt_get_vector(void)
{
	if (IS_HV_GM())
		return pic_get_vector();

	if (cpu_has(CPU_FEAT_EPIC)) {
		return e2k_virt_get_vector_epic();
	} else {
		return e2k_virt_get_vector_apic();
	}
}

extern void __init_recv kvm_init_system_handlers_table_apic(void);
extern void __init_recv kvm_init_system_handlers_table_epic(void);
static inline void __init_recv kvm_init_system_handlers_table_pic(void)
{
	if (IS_HV_GM())
		return;

	if (cpu_has(CPU_FEAT_EPIC)) {
		kvm_init_system_handlers_table_epic();
	} else {
		kvm_init_system_handlers_table_apic();
	}
}

extern __init int kvm_setup_boot_lapic_virq(void);
extern __init int kvm_setup_boot_cepic_virq(void);

static inline int __init kvm_setup_boot_local_pic_virq(void)
{
	if (IS_HV_GM())
		return 0;

	if (cpu_has(CPU_FEAT_EPIC)) {
		return kvm_setup_boot_cepic_virq();
	} else {
		return kvm_setup_boot_lapic_virq();
	}
}

extern int kvm_setup_secondary_lapic_virq(unsigned int cpuid);
extern void kvm_setup_local_apic_virq(unsigned int cpuid);
extern void kvm_setup_epic_virq(unsigned int cpuid);
static inline void kvm_setup_local_pic_virq(unsigned int cpuid)
{
	if (IS_HV_GM())
		return;

	if (cpu_has(CPU_FEAT_EPIC)) {
		kvm_setup_epic_virq(cpuid);
	} else {
		kvm_setup_local_apic_virq(cpuid);
	}
}

extern __init void kvm_startup_local_apic_virq(unsigned int cpuid);
extern __init void kvm_startup_epic_virq(unsigned int cpuid);
static inline void kvm_startup_local_pic_virq(unsigned int cpuid)
{
	if (IS_HV_GM())
		return;

	if (cpu_has(CPU_FEAT_EPIC)) {
		kvm_startup_epic_virq(cpuid);
	} else {
		kvm_startup_local_apic_virq(cpuid);
	}
}
#else /* !(CONFIG_EPIC) */
extern int pic_get_vector(void);
extern int e2k_virt_get_vector_apic(void);
static inline int e2k_virt_get_vector(void)
{
	if (IS_HV_GM())
		return pic_get_vector();

	return e2k_virt_get_vector_apic();
}

extern void __init_recv kvm_init_system_handlers_table_apic(void);
static inline void __init_recv kvm_init_system_handlers_table_pic(void)
{
	if (IS_HV_GM())
		return;

	kvm_init_system_handlers_table_apic();
}

extern __init int kvm_setup_boot_lapic_virq(void);
extern __init int kvm_setup_secondary_lapic_virq(unsigned int cpuid);

static inline int __init kvm_setup_boot_local_pic_virq(void)
{
	if (IS_HV_GM())
		return 0;

	return kvm_setup_boot_lapic_virq();
}

extern void kvm_setup_local_apic_virq(unsigned int cpuid);
static inline void kvm_setup_local_pic_virq(unsigned int cpuid)
{
	if (IS_HV_GM())
		return;

	kvm_setup_local_apic_virq(cpuid);
}

extern __init void kvm_startup_local_apic_virq(unsigned int cpuid);
static inline void kvm_startup_local_pic_virq(unsigned int cpuid)
{
	if (IS_HV_GM())
		return;

	kvm_startup_local_apic_virq(cpuid);
}
#endif
#endif	/* __KVM_GUEST_PIC_H */
