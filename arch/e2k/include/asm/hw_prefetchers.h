/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#pragma once

#include <asm/tlb_regs_types.h>
#include <asm/mmu_regs_types.h>


struct e2k_l2_prefetcher {
	u64 state;
};

struct hw_prefetchers_state {
	e2k_tlb_pref_ctrl_t tlb_pref_ctrl;
	e2k_l1_pref_ctrl_t l1_pref_ctrl;
	struct e2k_l2_prefetcher l2_ctrl_ext;
};

/* Disable all hardware prefetchers */
struct hw_prefetchers_state hw_prefetchers_save(void);
void hw_prefetchers_restore(struct hw_prefetchers_state state);

/* Disable TLB prefetcher */
e2k_tlb_pref_ctrl_t tlb_prefetcher_save_v7(void);
static inline e2k_tlb_pref_ctrl_t tlb_prefetcher_save(void)
{
	return (cpu_has(CPU_FEAT_HW_PREFETCHER_TLB))
			? tlb_prefetcher_save_v7()
			: (e2k_tlb_pref_ctrl_t) { .word = 0 };
}

void tlb_prefetcher_restore_v7(e2k_tlb_pref_ctrl_t tlb_pref_ctrl);
static inline void tlb_prefetcher_restore(e2k_tlb_pref_ctrl_t tlb_pref_ctrl)
{
	if (cpu_has(CPU_FEAT_HW_PREFETCHER_TLB))
		tlb_prefetcher_restore_v7(tlb_pref_ctrl);
}

/* Disable L1 prefetcher */
e2k_l1_pref_ctrl_t l1_prefetcher_save_v7(void);
static inline e2k_l1_pref_ctrl_t l1_prefetcher_save(void)
{
	return (cpu_has(CPU_FEAT_HW_PREFETCHER_L1))
			? l1_prefetcher_save_v7()
			: (e2k_l1_pref_ctrl_t) { .word = 0 };
}

void l1_prefetcher_restore_v7(e2k_l1_pref_ctrl_t l1_pref_ctrl);
static inline void l1_prefetcher_restore(e2k_l1_pref_ctrl_t l1_pref_ctrl)
{
	if (cpu_has(CPU_FEAT_HW_PREFETCHER_L1))
		l1_prefetcher_restore_v7(l1_pref_ctrl);
}

/* Enable/disable L2 prefetcher */
struct e2k_l2_prefetcher l2_prefetcher_save(void);
void l2_prefetcher_restore(struct e2k_l2_prefetcher l2_prefetcher);

/* Check current state */
bool l2_prefetcher_enabled(void);

static inline void l2_prefetcher_switch_binco(bool prev_binco, bool next_binco,
		struct e2k_l2_prefetcher *prev, struct e2k_l2_prefetcher *next)
{
	if (likely(!cpu_has(CPU_HWBUG_GENERATIONS_L2_PREF) || prev_binco == next_binco))
		return;

	if (next_binco)
		*next = l2_prefetcher_save();
	else if (prev_binco)
		l2_prefetcher_restore(*prev);
}

/* Switches hardware state with state saved in memory */
void l2_prefetcher_switch(bool *l2_prefetcher_enabled);