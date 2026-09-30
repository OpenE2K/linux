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

typedef union {
	struct {
		u64 hi : 32;
		u64 lo : 32;
	};
	u64 word;
} e90s_rt_tick_t;

typedef union {
	struct {
		u64 npt    : 1;	/* if =0 unpriveleged user may read div */
		u64 soft_ok: 1;
		u64 reserv : 30;
		u64 div    : 32;
	};
	u64 word;
} e90s_rt_div_t;
extern struct clocksource clocksource_clk_rt;
extern struct rtc_device *clk_rtc;

extern int clk_rt_mode;
extern atomic_t num_clk_rt_register;
extern int clk_rt_register(void *);
extern struct clocksource clocksource_clk_rt;
extern struct clocksource lt_cs;
extern struct clocksource *curr_clocksource;
extern u64 read_clk_rt(struct clocksource *cs);
extern int clk_rt_initialized;

bool clk_rt_enabled(void);
bool prepare_rtc_set(void);
void finish_rtc_set(bool);

#endif
