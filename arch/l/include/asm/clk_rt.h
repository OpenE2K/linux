/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_CLK_RT_H
#define _ASM_L_CLK_RT_H

#define CLK_RT_NO	0
#define CLK_RT_RTC	1
#define CLK_RT_EXT	2
#define CLK_RT_RESUME	3

extern struct clocksource clocksource_clk_rt;

extern int clk_rt_mode;
extern atomic_t num_clk_rt_register;
extern int clk_rt_register(void *);
extern struct clocksource clocksource_clk_rt;
extern struct clocksource lt_cs;
extern struct clocksource *curr_clocksource;
extern u64 read_clk_rt(struct clocksource *cs);

bool clk_rt_enabled(void);

#endif
