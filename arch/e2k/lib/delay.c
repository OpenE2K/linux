/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/delay.h>
#include <linux/export.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/timer.h>
#include <asm/sclkr.h>

void notrace __delay(unsigned long cycles)
{
	cycles_t start = get_cycles();

	while (get_cycles() - start < cycles)
		cpu_relax();
}
EXPORT_SYMBOL(__delay);

/* Return -1ULL on error */
static u64 get_usclk_raw(void)
{
	if (likely(use_esclk_sched_clock())) {
		return esclk_sched_clock();
	} else if (likely(use_sclk_sched_clock())) {
		return sclk_sched_clock();
	}

	BUG();
}

void notrace udelay(unsigned long usecs)
{
	if (likely(use_esclk_sched_clock() || use_sclk_sched_clock())) {
		u64 start = get_usclk_raw();
		u64 end = start + usecs * 1000;

		while (get_usclk_raw() < end)
			cpu_relax();

		return;
	}

	/* Fallback in case [e]sclk is not available */
	__delay(usecs * loops_per_jiffy * HZ / USEC_PER_SEC);
}
EXPORT_SYMBOL(udelay);

int native_read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();

	return 0;
}

