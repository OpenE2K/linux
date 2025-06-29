/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/init.h>
#include <linux/tick.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/signal.h>
#include <linux/param.h>
#include <linux/export.h>
#include <linux/profile.h>
#include <linux/clocksource.h>
#include <linux/irq.h>
#include <linux/of_clk.h>

#include <asm/machdep.h>
#include <asm/io.h>
#include <asm/time.h>
#include <asm/timer.h>
#include <asm/timex.h>
#include <asm/process.h>
#include <asm/l_timer.h>
#include <asm/sclkr.h>

#undef	DEBUG_TIMER_MODE
#undef	DebugTM
#define	DEBUG_TIMER_MODE	0	/* timer and time */
#define DebugTM(...)		DebugPrint(DEBUG_TIMER_MODE ,##__VA_ARGS__)

extern ktime_t tick_period;
u64 cpu_clock_psec;	/* number of pikoseconds in one CPU clock */
EXPORT_SYMBOL(cpu_clock_psec);

extern struct clocksource clocksource_jiffies;
void __init arch_clock_setup(void)
{
	arch_clock_init();
}

extern struct machdep machine;

#if defined(CONFIG_SMP)
unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (in_lock_functions(pc)) {
		return get_nested_kernel_IP(regs, 1);
	}

	return pc;
}
EXPORT_SYMBOL(profile_pc);
#endif

void __init native_time_init(void)
{
	of_clk_init(NULL);
	timer_probe();
}

/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	if (likely(use_esclk_sched_clock())) {
		return esclk_sched_clock();
	} else if (likely(use_sclk_sched_clock())) {
		return sclk_sched_clock();
	}

	return (unsigned long long) (jiffies - INITIAL_JIFFIES) * (NSEC_PER_SEC / HZ);
}
