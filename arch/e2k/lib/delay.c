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

void __delay(unsigned long cycles)
{
	cycles_t start = get_cycles();

	while (get_cycles() - start < cycles)
		cpu_relax();
}
EXPORT_SYMBOL(__delay);

static void udelay_clkr(u64 usecs)
{
	__delay(usecs * loops_per_jiffy * HZ / USEC_PER_SEC);
}

/* Read sclkr if still available (can be disabled by sclk_unregister_rtc()),
 * return -1ULL otherwise. */
static u64 sclkr_ns(void)
{
	unsigned long flags;
	u64 ns;

	/*
	 * Close interrupts for synchronization (see sched_clock.c:
	 * switching clocks is implemented with IPIs, so any switch
	 * will wait for irq restore below).
	 *
	 * Also sclk_sched_clock() msut be called under all_irq_save().
	 */
	raw_all_irq_save(flags);
	ns = (use_sclk_sched_clock()) ? sclk_sched_clock() : -1ULL;
	raw_all_irq_restore(flags);

	return ns;
}

static void udelay_sclkr(u64 usecs)
{
	u64 now = sclkr_ns();
	if (now == -1ULL)
		return udelay_clkr(usecs);

	u64 left = NSEC_PER_USEC * usecs;

	while (left) {
		u64 next = sclkr_ns();
		if (next == -1ULL)
			return udelay_clkr((left + NSEC_PER_USEC - 1) / NSEC_PER_USEC);

		u64 passed = next - now;
		left = (left > passed) ? left - passed : 0;
		now = next;

		cpu_relax();
	}
}

static void udelay_esclk(u64 usecs)
{
	u64 start = esclk_sched_clock();
	u64 end = start + NSEC_PER_USEC * usecs;

	while (esclk_sched_clock() < end)
		cpu_relax();
}

void udelay(unsigned long usecs)
{
	if (use_esclk_sched_clock())
		return udelay_esclk(usecs);

	if (use_sclk_sched_clock())
		return udelay_sclkr(usecs);

	/* Fallback in case [e]sclk is not available */
	return udelay_clkr(usecs);
}
EXPORT_SYMBOL(udelay);

int native_read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();

	return 0;
}

