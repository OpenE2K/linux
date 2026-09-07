/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Suspend support specific for e2k.
 */

#include <linux/suspend.h>

#include <asm/sched_clock.h>
#include <asm/sclkr.h>

void save_processor_state(void)
{
	save_sched_clock_state();
}

void restore_processor_state(void)
{
#ifdef CONFIG_SCLKR_CLOCKSOURCE
	/*
	 * After suspend/hibernate %sclkr is reset to 0, so to avoid
	 * stalling until %sclkr catches up in read_sclkr_noirq()
	 * have to reset the synchronization variable too.
	 */
	atomic64_set(&prev_sclkr.res, 0);
#endif

	restore_sched_clock_state();
}
