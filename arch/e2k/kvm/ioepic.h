/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_IO_EPIC_H
#define __KVM_IO_EPIC_H

#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <asm/io_epic.h>
#include <asm/io_epic_regs.h>
#include "cepic.h"

#define IOEPIC_DEFAULT_BASE_ADDRESS	0xfec00000
#define IOEPIC_MEM_LENGTH	0x100000
#define	IOEPIC_NUM_PINS	KVM_IOEPIC_NUM_PINS

struct kvm_ioepic {
	u64 base_address;
	u32 id;
	u32 irr;
	struct IO_EPIC_route_entry redirtbl[IOEPIC_NUM_PINS];
	unsigned long irq_states[IOEPIC_NUM_PINS];
	struct kvm_io_device dev;
	struct kvm *kvm;
	void (*ack_notifier)(void *opaque, int irq);
	struct mutex lock;
};

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

static inline struct kvm_ioepic *ioepic_irqchip(struct kvm *kvm)
{
	return kvm->arch.ioepic;
}

static inline int ioepic_in_kernel(struct kvm *kvm)
{
	int ret;

	ret = (ioepic_irqchip(kvm) != NULL);
	return ret;
}

int kvm_epic_compare_prio(struct kvm_vcpu *vcpu1, struct kvm_vcpu *vcpu2);
void kvm_ioepic_update_eoi(struct kvm *kvm, int vector, int trigger_mode);
int kvm_ioepic_init(struct kvm *kvm);
void kvm_ioepic_destroy(struct kvm *kvm);
int kvm_ioepic_set_base(struct kvm *kvm, unsigned long new_base);
int kvm_ioepic_set_irq(struct kvm_ioepic *ioepic, int irq, int level);
void kvm_ioepic_reset(struct kvm_ioepic *ioepic);
#if 0
int kvm_get_ioepic(struct kvm *kvm, struct kvm_ioepic_state *state);
int kvm_set_ioepic(struct kvm *kvm, struct kvm_ioepic_state *state);
#endif
#endif
