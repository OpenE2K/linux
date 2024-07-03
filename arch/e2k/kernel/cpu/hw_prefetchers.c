/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <asm/bug.h>
#include <asm/hw_prefetchers.h>
#include <asm/mmu_regs.h>


static e2k_l2_ctrl_ext_t l2_prefetcher_save(void)
{
	e2k_l2_ctrl_ext_t l2_ctrl_ext;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L2))
		return (e2k_l2_ctrl_ext_t) { .reg = 0 };

	l2_ctrl_ext.reg = read_DCACHE_L2_reg(_E2K_DCACHE_L2_CTRL_EXT_REG, 0);
	if (l2_ctrl_ext.l2pref_en) {
		unsigned long flags;

		e2k_l2_ctrl_ext_t l2_ctrl_ext_nopref = l2_ctrl_ext;
		l2_ctrl_ext_nopref.l2pref_en = 0;
		raw_all_irq_save(flags);
		write_DCACHE_L2_reg(l2_ctrl_ext_nopref.reg,
				    _E2K_DCACHE_L2_CTRL_EXT_REG, 0);
		raw_all_irq_restore(flags);
	}

	return l2_ctrl_ext;
}

static void l2_prefetcher_restore(e2k_l2_ctrl_ext_t l2_ctrl_ext)
{
	unsigned long flags;

	if (!cpu_has(CPU_FEAT_HW_PREFETCHER_L2) || !l2_ctrl_ext.l2pref_en)
		return;

	raw_all_irq_save(flags);
	write_DCACHE_L2_reg(l2_ctrl_ext.reg,
			    _E2K_DCACHE_L2_CTRL_EXT_REG, 0);
	raw_all_irq_restore(flags);
}

struct hw_prefetchers_state hw_prefetchers_save(void)
{
	return (struct hw_prefetchers_state) {
		.l2_pref_ctrl = l2_prefetcher_save(),
	};
}

void hw_prefetchers_restore(struct hw_prefetchers_state state)
{
	l2_prefetcher_restore(state.l2_pref_ctrl);
}