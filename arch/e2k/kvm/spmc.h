/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_SPMC_H
#define __KVM_SPMC_H

#include <linux/kvm_host.h>
#include <kvm/iodev.h>
#include <asm/io_epic.h>
#include <asm/spmc_regs.h>
#include "kvm_timer.h"

#define	DEBUG_SPMC
#undef ASSERT
#ifdef DEBUG_SPMC
#define ASSERT(x)							\
do {									\
	if (!(x)) {							\
		pr_emerg("assertion failed %s: %d: %s\n",		\
		       __FILE__, __LINE__, #x);				\
		BUG();							\
	}								\
} while (0)
#else	/* ! DEBUG_SPMC */
#define ASSERT(x) do { } while (0)
#endif	/* DEBUG_SPMC */

typedef	struct kvm_spmc_regs {
	spmc_pm_tmr_t		pm_timer;	/* PM timer counter */
	spmc_pm1_sts_t		pm1_status;	/* PM status */
	spmc_pm1_en_t		pm1_enable;	/* PM enables */
	spmc_pm1_cnt_t		pm1_control;	/* PM control */
	spmc_atnsus_cnt_t	atnsus_counter;	/* attention suspend counter */
	spmc_pu_rst_cnt_t	pu_rst_counter;	/* power up reset counter */
} kvm_spmc_regs_t;

typedef struct kvm_spmc {
	u64 base_address;		/* SPMC configuration space base */
					/* address */
	kvm_spmc_regs_t regs;
	struct kvm_timer sci_timer;
	spmc_sleep_state_t s_state;	/* current sleep state */
	spmc_g_state_t g_state;		/* current G state */
	bool sci_state;			/* SCI interrupt state: active or not */
	int sci_timer_irq_id;
	u32 ticks_per_sec;	/* cycles (ticks) per 1 sec */
	u32 frequency;		/* frequency of PM counter increment at herz */
				/* standard frequency of EIOHub SPMC timer */
				/* is 3,579,545 Herz */
	struct kvm_io_device dev;
	struct kvm *kvm;
	struct mutex lock;
} kvm_spmc_t;

static inline bool kvm_spmc_acpi_enable(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_control.sci_en;
}

static inline bool kvm_spmc_sleep_state_enable(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_control.slp_en;
}

static inline spmc_sleep_state_t kvm_spmc_sleep_state(struct kvm_spmc *spmc)
{
	return spmc->regs.pm1_control.slp_typx;
}

static inline bool kvm_sci_timer_enable(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_enable.tmr_en;
}

static inline bool kvm_spmc_ac_power_enable(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_enable.ac_pwr_en;
}

static inline bool kvm_spmc_batton_low_enable(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_enable.batlow_en;
}

static inline bool kvm_spmc_power_batton_enable(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_enable.pwrbtn_en;
}

static inline bool kvm_sci_timer_32(struct kvm_spmc *spmc)
{
	return !!spmc->regs.pm1_enable.tmr_32;
}

static inline bool kvm_sci_timer_24(struct kvm_spmc *spmc)
{
	return !kvm_sci_timer_32(spmc);
}

static inline u32 kvm_get_sci_timer_limit(struct kvm_spmc *spmc)
{
	if (kvm_sci_timer_32(spmc)) {
		/* counter is 32 bits */
		return 1UL << 31;
	} else {
		/* counter is 24 bits */
		return 1UL << 23;
	}
}

static inline u32 kvm_get_sci_timer_limit_mask(struct kvm_spmc *spmc)
{
	if (kvm_sci_timer_32(spmc)) {
		/* counter is 32 bits */
		return ~0UL;
	} else {
		/* counter is 24 bits */
		return (1UL << 24) - 1;
	}
}

static inline u32 kvm_get_sci_timer_max_mask(struct kvm_spmc *spmc)
{
	/* counter is 32 bits */
	return ~0UL;
}

static inline struct kvm_spmc *kvm_get_spmc(struct kvm *kvm, int node_id)
{
	ASSERT(node_id < KVM_MAX_EIOHUB_NUM);
	return kvm->arch.spmc[node_id];
}

static inline void kvm_set_spmc(struct kvm *kvm, int node_id,
				struct kvm_spmc *spmc)
{
	ASSERT(node_id < KVM_MAX_EIOHUB_NUM);
	kvm->arch.spmc[node_id] = spmc;
}

static inline bool kvm_spmc_in_kernel(struct kvm *kvm, int node_id)
{
	return kvm_get_spmc(kvm, node_id) != NULL;
}
extern int kvm_spmc_set_base(struct kvm *kvm, int node_id,
					unsigned long conf_base);

extern struct kvm_spmc *kvm_create_spmc(struct kvm *kvm, int node_id,
					u32 ticks_per_sec, u32 spmc_timer_freq);
extern void kvm_free_spmc(struct kvm *kvm, int node_id);
extern void kvm_free_all_spmc(struct kvm *kvm);

#endif	/* __KVM_SPMC_H */
