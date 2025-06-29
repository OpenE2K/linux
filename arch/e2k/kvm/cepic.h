/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_CEPIC_H
#define __KVM_E2K_CEPIC_H

#include <kvm/iodev.h>
#include "kvm_timer.h"

#include <linux/kvm_host.h>
#include <asm/kvm/guest.h>

typedef struct kvm_cepic {
	unsigned long base_address;
	struct kvm_io_device dev;
	struct kvm_timer cepic_timer;
	struct kvm_vcpu *vcpu;
	bool irr_pending;
	struct page *regs_page;
	void *regs;
	int virq_no;
	unsigned long cepic_freq;
} kvm_cepic_t;

int kvm_create_cepic(struct kvm_vcpu *vcpu);
void kvm_free_cepic(struct kvm_vcpu *vcpu);

int kvm_epic_has_interrupt(struct kvm_vcpu *vcpu);
int kvm_epic_accept_pic_intr(struct kvm_vcpu *vcpu);
int kvm_get_epic_interrupt(struct kvm_vcpu *vcpu);
void kvm_cepic_reset(struct kvm_vcpu *vcpu);
void kvm_cepic_set_base(struct kvm_vcpu *vcpu, u64 value);
u64 kvm_cepic_get_base(struct kvm_vcpu *vcpu);
void kvm_epic_set_version(struct kvm_vcpu *vcpu);

int kvm_epic_match_physical_addr(struct kvm_cepic *epic, u16 dest);
int kvm_epic_match_logical_addr(struct kvm_cepic *epic, u8 mda);
int kvm_epic_set_irq(struct kvm_vcpu *vcpu, struct kvm_cepic_irq *irq);

u64 kvm_get_epic_base(struct kvm_vcpu *vcpu);
void kvm_set_epic_base(struct kvm_vcpu *vcpu, u64 data);
void kvm_epic_post_state_restore(struct kvm_vcpu *vcpu);
int kvm_cepic_enabled(struct kvm_vcpu *vcpu);
bool kvm_epic_present(struct kvm_vcpu *vcpu);
int kvm_cepic_find_highest_irr(struct kvm_vcpu *vcpu);
int kvm_epic_id(struct kvm_cepic *epic);

int epic_has_pending_timer(struct kvm_vcpu *vcpu);
void kvm_inject_epic_timer_irqs(struct kvm_vcpu *vcpu);
int kvm_sw_epic_sysrq_deliver(struct kvm_vcpu *vcpu);
int kvm_epic_nmi_deliver(struct kvm_vcpu *vcpu);

extern void kvm_print_EPIC_field(struct kvm_cepic *epic, int base);
extern void kvm_print_local_EPIC(struct kvm_vcpu *vcpu);
extern u32 kvm_vcpu_to_full_cepic_id(const struct kvm_vcpu *vcpu);

/* From ioapic.h */
int kvm_epic_match_dest(int cepic_id, int src, int short_hand, int dest);
int kvm_epic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2);

#undef ASSERT
#ifdef DEBUG
#define ASSERT(x)							\
do {									\
	if (!(x)) {							\
		pr_emerg("assertion failed %s: %d: %s\n",	\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else
#define ASSERT(x) do { } while (0)
#endif

/*
 * Basic functions to access to local EPIC state structure
 * (see asm/kvm/guest.h) on host.
 */
static inline kvm_epic_state_t *
kvm_get_guest_cepic_state(struct kvm_vcpu *vcpu)
{
	return &vcpu->arch.kmap_vcpu_state->cepic;
}

static inline atomic_t *
kvm_get_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	return &cepic->virqs_num;
}

static inline int
kvm_read_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	return atomic_read(&cepic->virqs_num);
}
static inline void
kvm_set_guest_cepic_virqs_num(struct kvm_vcpu *vcpu, int count)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	atomic_set(&cepic->virqs_num, count);
}
static inline void
kvm_reset_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_set_guest_cepic_virqs_num(vcpu, 0);
}
static inline void
kvm_inc_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	atomic_inc(&cepic->virqs_num);
}
static inline bool
kvm_inc_and_test_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	return atomic_inc_and_test(&cepic->virqs_num);
}
static inline void
kvm_dec_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	atomic_dec(&cepic->virqs_num);
}
static inline bool
kvm_dec_and_test_guest_cepic_virqs_num(struct kvm_vcpu *vcpu)
{
	kvm_epic_state_t *cepic = kvm_get_guest_cepic_state(vcpu);

	return atomic_dec_and_test(&cepic->virqs_num);
}

#define	MAX_PENDING_VIRQS	8	/* why 8 ???? */

#endif	/* __KVM_E2K_CEPIC_H */
