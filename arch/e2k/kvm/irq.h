/*
 * irq.h: In-kernel interrupt controller related definitions
 * Copyright (c) 2011, MCST.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms and conditions of the GNU General Public License,
 * version 2, as published by the Free Software Foundation.
 *
 * This program is distributed in the hope it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 */

#ifndef __IRQ_H
#define __IRQ_H

#include <linux/err.h>

#include <asm/kvm/mmu.h>

#include "cpu_defs.h"
#include "pic.h"

#undef	DEBUG_KVM_VIRQs_MODE
#undef	DebugVIRQs
#define	DEBUG_KVM_VIRQs_MODE	0	/* VIRQs debugging */
#define	DebugVIRQs(fmt, args...)					\
({									\
	if (DEBUG_KVM_VIRQs_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* guest kernel thread can have not time to handle previous timer interrupt */
/* so need restart hrtimer on some small addition */
#define	GUEST_RESTART_TIME_NS	1000000	/* 1 mseck addition */

static inline int irqchip_in_kernel(struct kvm *kvm)
{
	return 1;
}

static inline int lapic_in_kernel(struct kvm_vcpu *vcpu)
{
	/* Same as irqchip_in_kernel(vcpu->kvm), but with less
	 * pointer chasing and no unnecessary memory barriers.
	 */
	return vcpu->arch.apic != NULL;
}

/*
 * Basic functions to access to VIRQs state structure on host
 * (see asm/kvm/guest.h)
 */
static inline kvm_virqs_state_t *
kvm_get_guest_virqs_state(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.kmap_vcpu_state->virqs;
}

static inline atomic_t *
kvm_get_guest_timer_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_virqs_state_t *virqs = kvm_get_guest_virqs_state(vcpu);

	return &virqs->timer_virqs_num;
}
static inline atomic_t *
kvm_get_guest_hvc_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_virqs_state_t *virqs = kvm_get_guest_virqs_state(vcpu);

	return &virqs->hvc_virqs_num;
}

static inline atomic_t *
kvm_get_guest_virqs_atomic_counter(struct kvm_vcpu *vcpu, int virq_id)
{
	switch (virq_id) {
	case KVM_VIRQ_TIMER:
		return kvm_get_guest_timer_virqs_num(vcpu);
	case KVM_VIRQ_HVC:
		return kvm_get_guest_hvc_virqs_num(vcpu);
	case KVM_VIRQ_LAPIC:
		return kvm_get_guest_lapic_virqs_num(vcpu);
	case KVM_VIRQ_CEPIC:
		return kvm_get_guest_cepic_virqs_num(vcpu);
	default:
		return ERR_PTR(-EINVAL);
	}
}

extern void kvm_init_clockdev(struct kvm_vcpu *vcpu);
extern void kvm_cancel_clockdev(struct kvm_vcpu *vcpu);

extern void kvm_guest_set_clockevent(struct kvm_vcpu *vcpu,
						unsigned long delta);

extern int kvm_setup_default_irq_routing(struct kvm *kvm);

extern pid_t kvm_guest_intr_handler(struct kvm_vcpu *vcpu, int irq, int virq_id,
					irq_handler_t fn, void *arg);
extern int kvm_guest_intr_thread(int vcpu_id, int irq, int virq_id,
				int gpid_nr, irq_thread_t fn, void *arg);
extern int kvm_guest_free_intr_handler(struct kvm *kvm, int irq, void *arg);
extern int kvm_get_guest_direct_virq(struct kvm_vcpu *vcpu,
				int irq, int virq_id);
extern int kvm_free_guest_direct_virq(struct kvm *kvm, int irq);
extern int kvm_vcpu_interrupt(struct kvm_vcpu *vcpu, int irq);
extern int kvm_vcpu_ioctl_interrupt(struct kvm_vcpu *vcpu, int virq_id);
extern int kvm_guest_wait_for_virq(struct kvm *kvm, int irq, bool in_progress);
extern void kvm_inject_lapic_virq(struct kvm_lapic *apic);
extern void kvm_inject_cepic_virq(struct kvm_cepic *epic);
extern void kvm_inject_nmi(struct kvm_vcpu *vcpu);
extern enum hrtimer_restart kvm_apic_timer_fn(struct hrtimer *data);
extern enum hrtimer_restart kvm_epic_timer_fn(struct hrtimer *data);
extern int kvm_find_pending_virqs(struct kvm_vcpu *vcpu,
					bool inject, bool wakeup);
extern int kvm_dec_vcpu_pending_virq(struct kvm_vcpu *vcpu, int virq_no);

static inline int kvm_wake_up_pending_virqs(struct kvm_vcpu *vcpu)
{
	return kvm_find_pending_virqs(vcpu, false, true);
}
static inline int kvm_get_pending_virqs_num(struct kvm_vcpu *vcpu)
{
	return kvm_find_pending_virqs(vcpu, false, false);
}
static inline bool kvm_is_handling_vcpu_virqs(struct kvm_vcpu *vcpu)
{
	return vcpu->arch.on_virqs_handling;
}
static inline void kvm_set_handling_vcpu_virqs(struct kvm_vcpu *vcpu)
{
	vcpu->arch.on_virqs_handling = true;
}
static inline void kvm_clear_handling_vcpu_virqs(struct kvm_vcpu *vcpu)
{
	vcpu->arch.on_virqs_handling = false;
}
static inline bool kvm_test_hw_stack_bounds_waiting(struct kvm_vcpu *vcpu,
						    thread_info_t *ti)
{
	if (likely(vcpu->arch.is_hv)) {
		return false;
	}
	return test_guest_hw_stack_bounds_waiting(ti,
				exc_proc_stack_bounds_mask |
					exc_chain_stack_bounds_mask);
}

/* kvm->arch.virq_lock should be locked by caller */
static inline bool
kvm_has_virqs_to_guest(struct kvm_vcpu *vcpu)
{
	int virqs_num;
	bool has_pending_virqs;

	virqs_num = kvm_wake_up_pending_virqs(vcpu);
	has_pending_virqs = kvm_test_pending_virqs(vcpu);
	DebugVIRQs("on VCPU #%d, pending flag %d VIRQs number is %d\n",
		vcpu->vcpu_id, has_pending_virqs, virqs_num);
	if (!has_pending_virqs && virqs_num == 0) {
		/* none VIRQs and none pending VIRQs flag */
		/* so nothing to pass */
		return false;
	} else if (!has_pending_virqs && virqs_num != 0) {
		/* there are VIRQs and none pending VIRQs flag */
		/* Do not pass new interrupt because of old interrupt is */
		/* in progress */
		return false;
	} else if (has_pending_virqs && virqs_num == 0) {
		/* none VIRQS and there is pending VIRQs flag */
		/* it can be if host want pass new interrupt, but guest */
		/* is now handling old interrupt and see already new VIRQ */
		/* so do not pass new interrupt, guest should handle old, */
		/* host should clear pending VIRQs flag */
		BUG_ON(!kvm_test_and_clear_pending_virqs(vcpu));
		kvm_clear_virqs_injected(vcpu);
		return false;
	} else if (has_pending_virqs && virqs_num != 0) {
		/* there are VIRQs and there are pending VIRQs flag */
		/* So it need pass new interrupt */
		;
	} else {
		/* unknown and impossible case */
		WARN_ON(true);
	}
	return true;
}

#ifdef	CONFIG_DIRECT_VIRQ_INJECTION
/*
 * Inject 'last wish' to PSR to cauuse trap after return on guest kernel
 * This trap needs to inject one more trap (interrupt on pending VIRQs)
 * to implemet direct ijection of interrupts on guest VCPU thread.
 * FIXME: 'Last with' method is too costly, need implement direct call
 * of guest trap handling, similar to deferred traps.
 */
static __always_inline bool
kvm_test_inject_direct_guest_virqs(struct kvm_vcpu *vcpu,
		struct thread_info *ti, unsigned long upsr, unsigned long psr)
{
	if (!kvm_test_pending_virqs(vcpu) &&
			!kvm_test_hw_stack_bounds_waiting(vcpu, ti))
		return false;
	if (kvm_guest_vcpu_irqs_disabled(vcpu, upsr, psr)) {
		/* guest IRQs is now disabled, so it cannot pass interrupts */
		/* right now, delay while appropriate case */
		return false;
	}
	if (!kvm_vcpu_is_epic(vcpu) && !kvm_check_lapic_priority(vcpu)) {
		/* do not inject an interrupt with a lower priority */
		return false;
	}

	return true;
}
static __always_inline bool
kvm_try_inject_direct_guest_virqs(struct kvm_vcpu *vcpu, struct thread_info *ti,
				 unsigned long upsr, unsigned long psr)
{
	if (!kvm_test_inject_direct_guest_virqs(vcpu, ti, upsr, psr))
		/* there is not VIRQs to inject */
		return false;

	if (kvm_test_virqs_injected(vcpu)) {
		/* already injected */
		return false;
	}

	BUG_ON(vcpu->arch.virq_wish);
	vcpu->arch.virq_wish = true;
	return true;
}
static __always_inline int
kvm_guest_handled_virqs(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.virq_injected)
		/* host did not inject any interrupt */
		return 0;
	vcpu->arch.virq_injected = false;
	return 0;
}
#else	/* ! CONFIG_DIRECT_VIRQ_INJECTION */
static __always_inline bool
kvm_test_inject_direct_guest_virqs(struct kvm_vcpu *vcpu,
		struct thread_info *ti, unsigned long upsr, unsigned long psr)
{
	return false;
}
static __always_inline bool
kvm_try_inject_direct_guest_virqs(struct kvm_vcpu *vcpu,
		struct thread_info *ti, unsigned long upsr, unsigned long psr)
{
	return false;
}
static __always_inline int
kvm_guest_handled_virqs(struct kvm_vcpu *vcpu)
{
	return 0;
}
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

extern void kvm_free_all_VIRQs(struct kvm *kvm);

#endif /* __IRQ_H */

