/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#pragma once

#include <asm/cpu_regs_types_defs.h>

struct jump_buf_e2k {
	e2k_mem_crs_t crs;
	e2k_pcsp_t pcsp;
	e2k_psp_t psp;
	e2k_usd_t usd;
	e2k_sbr_t sbr;
};

extern noinline __attribute__((returns_twice)) int e2k_setjmp(struct jump_buf_e2k *jb);

extern noinline void e2k_longjmp(const struct jump_buf_e2k *jb, int value);
