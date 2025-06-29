/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Suspend support specific for e2k.
 */

#include <linux/suspend.h>
#include <linux/sched/clock.h>

#ifdef CONFIG_SCLKR_CLOCKSOURCE
#include <asm/sclkr.h>

static unsigned long long suspended_sched_clock_value;
#endif

void save_processor_state(void)
{
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	if (use_sclk_sched_clock())
		suspended_sched_clock_value = sched_clock();
#endif
}

void restore_processor_state(void)
{
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	if (use_sclk_sched_clock()) {
		atomic64_set(&prev_sclkr.res, 0);
		sclkr_sched_offset = suspended_sched_clock_value - read_sclkr_nosync();
	}
#endif
}
