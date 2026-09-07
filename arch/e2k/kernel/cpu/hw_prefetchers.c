/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <linux/sched/debug.h>

#include <asm/bug.h>
#include <asm/hw_prefetchers.h>
#include <asm/kvm/hypercall.h>
#include <asm/mmu_regs.h>

static bool use_hypercall __read_mostly;

static int initialize_l2_pref_hypercall(void)
{
	if (IS_HV_GM()) {
		s64 state = HYPERVISOR_l2_prefetcher_save();
		if (state > 0) {
			WARN_ON(HYPERVISOR_l2_prefetcher_restore(state));
			use_hypercall = true;
			return 0;
		}
	}

	use_hypercall = false;
	return 0;
}
pure_initcall(initialize_l2_pref_hypercall);

struct e2k_l2_prefetcher __sched l2_prefetcher_save(void)
{
	if (use_hypercall) {
		s64 state = HYPERVISOR_l2_prefetcher_save();
		/* Have tested already that the hypercall should work */
		if (WARN_ON_ONCE(state < 0))
			state = 0;

		return (struct e2k_l2_prefetcher) { .state = state };
	}

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L2))
		return (struct e2k_l2_prefetcher) { .state = 0 };

	e2k_l2_ctrl_ext_t l2_ctrl_ext = read_L2_CTRL_EXT(0);
	if (l2_ctrl_ext.l2pref_en) {
		unsigned long flags;

		e2k_l2_ctrl_ext_t l2_ctrl_ext_nopref = l2_ctrl_ext;
		l2_ctrl_ext_nopref.l2pref_en = 0;
		raw_all_irq_save(flags);
		write_L2_CTRL_EXT(l2_ctrl_ext_nopref, 0);
		raw_all_irq_restore(flags);
	}

	return (struct e2k_l2_prefetcher) { .state = l2_ctrl_ext.word };
}

void __sched l2_prefetcher_restore(struct e2k_l2_prefetcher l2_prefetcher)
{
	if (use_hypercall) {
		WARN_ON(HYPERVISOR_l2_prefetcher_restore(l2_prefetcher.state));
		return;
	}

	e2k_l2_ctrl_ext_t l2_ctrl_ext = { .word = l2_prefetcher.state };
	if (cpu_has(CPU_FEAT_HW_PREFETCHER_L2) && l2_ctrl_ext.l2pref_en) {
		unsigned long flags;

		raw_all_irq_save(flags);
		write_L2_CTRL_EXT(l2_ctrl_ext, 0);
		raw_all_irq_restore(flags);
	}
}

bool l2_prefetcher_enabled(void)
{
	if (use_hypercall) {
		s64 state = HYPERVISOR_l2_prefetcher_save();
		/* Have tested already that the hypercall should work */
		if (WARN_ON_ONCE(state < 0)) {
			state = 0;
		} else {
			HYPERVISOR_l2_prefetcher_restore(state);
		}
		return state;
	}

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L2))
		return false;

	return read_L2_CTRL_EXT(0).l2pref_en;
}

struct hw_prefetchers_state hw_prefetchers_save(void)
{
	return (struct hw_prefetchers_state) {
		.tlb_pref_ctrl = tlb_prefetcher_save(),
		.l1_pref_ctrl = l1_prefetcher_save(),
		.l2_ctrl_ext = l2_prefetcher_save(),
	};
}

void hw_prefetchers_restore(struct hw_prefetchers_state state)
{
	tlb_prefetcher_restore(state.tlb_pref_ctrl);
	l1_prefetcher_restore(state.l1_pref_ctrl);
	l2_prefetcher_restore(state.l2_ctrl_ext);
}

/**
 * l2_prefetcher_switch - switches hardware state with state saved in memory
 * @l2_prefetcher_enabled: state to switch with
 */
void l2_prefetcher_switch(bool *l2_prefetcher_enabled)
{
	unsigned long flags;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L2))
		return;

	e2k_l2_ctrl_ext_t prev = read_L2_CTRL_EXT(0);
	if (prev.l2pref_en == *l2_prefetcher_enabled)
		return;

	e2k_l2_ctrl_ext_t next = prev;
	next.l2pref_en = *l2_prefetcher_enabled;

	raw_all_irq_save(flags);
	write_L2_CTRL_EXT(next, 0);
	raw_all_irq_restore(flags);

	*l2_prefetcher_enabled = prev.l2pref_en;
}
