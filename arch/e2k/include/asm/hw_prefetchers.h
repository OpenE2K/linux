/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */
#pragma once

#include <asm/tlb_regs_types.h>
#include <asm/mmu_regs_types.h>

struct hw_prefetchers_state {
	e2k_l2_ctrl_ext_t l2_pref_ctrl;
};

/* Disable all hardware prefetchers */
struct hw_prefetchers_state hw_prefetchers_save(void);
void hw_prefetchers_restore(struct hw_prefetchers_state state);