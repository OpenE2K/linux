/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Suspend support specific for e2k.
 */

#include <linux/suspend.h>

#include <asm/sched_clock.h>

void save_processor_state(void)
{
	save_sched_clock_state();
}

void restore_processor_state(void)
{
	restore_sched_clock_state();
}
