/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_LAPIC_H
#define __KVM_E2K_LAPIC_H

#include <kvm/iodev.h>
#include "kvm_timer.h"

#include <linux/kvm_host.h>
#include <asm/kvm/guest.h>

#define	MAX_CEPIC_PRIORITY 4
struct kvm_lapic {
	unsigned long base_address;
	struct kvm_io_device dev;
	struct kvm_timer lapic_timer;
	u32 divide_count;
	struct kvm_vcpu *vcpu;
	bool irr_pending;
	struct page *regs_page;
	void *regs;
	gpa_t vapic_addr;
	struct page *vapic_page;
	int virq_no;
	bool virq_is_setup;
	/* APIC v6 (APIC model based on hardware CEPIC support) */
	u32 cepic_vector[MAX_CEPIC_PRIORITY + 1];
};

int kvm_create_lapic(struct kvm_vcpu *vcpu);
void kvm_free_lapic(struct kvm_vcpu *vcpu);

int kvm_apic_has_interrupt(struct kvm_vcpu *vcpu);
int kvm_apic_accept_pic_intr(struct kvm_vcpu *vcpu);
void kvm_lapic_reset(struct kvm_vcpu *vcpu);
extern void kvm_lapic_restart(struct kvm_vcpu *vcpu);
void kvm_lapic_set_base(struct kvm_vcpu *vcpu, u64 value);
u64 kvm_lapic_get_base(struct kvm_vcpu *vcpu);
void kvm_apic_set_version(struct kvm_vcpu *vcpu);

int kvm_apic_match_physical_addr(struct kvm_lapic *apic, u16 dest);
int kvm_apic_match_logical_addr(struct kvm_lapic *apic, u8 mda);
int kvm_apic_set_irq(struct kvm_vcpu *vcpu, struct kvm_lapic_irq *irq);
extern void kvm_lapic_virq_setup(struct kvm_vcpu *vcpu);

u64 kvm_get_apic_base(struct kvm_vcpu *vcpu);
void kvm_set_apic_base(struct kvm_vcpu *vcpu, u64 data);
void kvm_apic_post_state_restore(struct kvm_vcpu *vcpu);
int kvm_lapic_enabled(struct kvm_vcpu *vcpu);
bool kvm_apic_present(struct kvm_vcpu *vcpu);
int kvm_lapic_find_highest_irr(struct kvm_vcpu *vcpu);

void kvm_lapic_set_vapic_addr(struct kvm_vcpu *vcpu, gpa_t vapic_addr);
void kvm_lapic_sync_from_vapic(struct kvm_vcpu *vcpu);
void kvm_lapic_sync_to_vapic(struct kvm_vcpu *vcpu);

int apic_has_pending_timer(struct kvm_vcpu *vcpu);
void kvm_inject_apic_timer_irqs(struct kvm_vcpu *vcpu);
int kvm_apic_sysrq_deliver(struct kvm_vcpu *vcpu);
int kvm_apic_nmi_deliver(struct kvm_vcpu *vcpu);

extern void kvm_print_APIC_field(struct kvm_lapic *apic, int base);
extern void kvm_print_local_APIC(struct kvm_vcpu *vcpu);

/*
 * Basic functions to access to local APIC state structure
 * (see asm/kvm/guest.h) on host.
 */
static inline kvm_apic_state_t *
kvm_get_guest_lapic_state(struct kvm_vcpu *vcpu)
{
	if (unlikely(vcpu == NULL))
		return NULL;
	if (unlikely(vcpu->arch.kmap_vcpu_state == NULL))
		return NULL;
	return &vcpu->arch.kmap_vcpu_state->lapic;
}

static inline atomic_t *
kvm_get_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	return &lapic->virqs_num;
}

static inline int
kvm_read_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	return atomic_read(&lapic->virqs_num);
}
static inline void
kvm_set_guest_lapic_virqs_num(struct kvm_vcpu *vcpu, int count)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	if (unlikely(lapic == NULL))
		return;
	atomic_set(&lapic->virqs_num, count);
}
static inline void
kvm_reset_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_set_guest_lapic_virqs_num(vcpu, 0);
}
static inline void
kvm_inc_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	atomic_inc(&lapic->virqs_num);
}
static inline bool
kvm_inc_and_test_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	return atomic_inc_and_test(&lapic->virqs_num);
}
static inline void
kvm_dec_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	atomic_dec(&lapic->virqs_num);
}
static inline bool
kvm_dec_and_test_guest_lapic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_apic_state_t *lapic = kvm_get_guest_lapic_state(vcpu);

	return atomic_dec_and_test(&lapic->virqs_num);
}

#define	MAX_PENDING_VIRQS	8	/* why 8 ???? */

/* followed define is not in apicdef.h */
#define APIC_SHORT_MASK			0xc0000
#define APIC_DEST_NOSHORT		0x0
#define APIC_DEST_MASK			0x800
#define MAX_APIC_VECTOR			256

#endif	/* __KVM_E2K_LAPIC_H */
