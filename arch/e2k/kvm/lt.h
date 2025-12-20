/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_L_TIMER_H
#define __KVM_L_TIMER_H

#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <asm/io_epic.h>
#include "lt_regs.h"
#include "kvm_timer.h"

#define	DEBUG_LT
#undef ASSERT
#ifdef DEBUG_LT
#define ASSERT(x)							\
do {									\
	if (!(x)) {							\
		pr_emerg("assertion failed %s: %d: %s\n",		\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else	/* ! DEBUG_LT */
#define ASSERT(x) do { } while (0)
#endif	/* DEBUG_LT */

typedef	struct kvm_lt_regs {
	counter_limit_t	  counter_limit;    /* timer counter limit value */
	counter_start_t	  counter_start;    /* start value of counter */
	counter_t	  counter;	    /* timer counter */
	counter_control_t counter_control;  /* timer control register */
	wd_counter_l_t	  wd_counter;	    /* watchdog counter */
	wd_counter_h_t	  wd_prescaler;	    /* watchdog prescaler */
	wd_limit_t	  wd_limit;	    /* watchdog limit */
	power_counter_l_t power_counter_lo; /* power counter low bits */
	power_counter_h_t power_counter_hi; /* power counter high bits */
	wd_control_t	  wd_control;	    /* watchdog control register */
	reset_counter_l_t reset_counter_lo; /* reset counter low bits */
	reset_counter_h_t reset_counter_hi; /* reset counter low bits */

	u32	latched_reset_counter;	/* latched high part of reset counter */
	u32	latched_power_counter;	/* latched high part of power counter */
} kvm_lt_regs_t;

typedef struct kvm_lt {
	u64 base_address;
	kvm_lt_regs_t regs;
	struct kvm_timer sys_timer;
	struct kvm_timer wd_timer;
	struct kvm_timer reset_count;
	struct kvm_timer power_count;
	int sys_timer_irq_id;
	int wd_timer_irq_id;
	u32 ticks_per_sec;	/* cycles (ticks) per 1 sec */
	u32 frequency;		/* frequency of counter increment (Hz) */
				/* standard frequency of system timer */
				/* is 10 Mhz */
	struct kvm_io_device dev;
	struct kvm *kvm;
	struct mutex lock;
} kvm_lt_t;

static inline struct kvm_lt *kvm_get_lt(struct kvm *kvm, int node_id)
{
	ASSERT(node_id < KVM_MAX_EIOHUB_NUM);
	return kvm->arch.lt[node_id];
}

static inline void kvm_set_lt(struct kvm *kvm, int node_id, struct kvm_lt *lt)
{
	ASSERT(node_id < KVM_MAX_EIOHUB_NUM);
	kvm->arch.lt[node_id] = lt;
}

static inline bool kvm_lt_in_kernel(struct kvm *kvm, int node_id)
{
	return kvm_get_lt(kvm, node_id) != NULL;
}
extern int kvm_lt_set_base(struct kvm *kvm, int node_id,
				unsigned long new_base);

extern struct kvm_lt *kvm_create_lt(struct kvm *kvm, int node_id,
					u32 ticks_per_sec, u32 sys_timer_freq);
extern void kvm_free_lt(struct kvm *kvm, int node_id);
extern void kvm_free_all_lt(struct kvm *kvm);

#endif	/* __KVM_L_TIMER_H */
