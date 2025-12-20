/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/init.h>
#include <linux/hrtimer.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/signal.h>
#include <linux/param.h>
#include <linux/mc146818rtc.h>
#include <linux/efi.h>
#include <linux/export.h>
#include <linux/profile.h>
#include <linux/dma-mapping.h>
#include <linux/clocksource.h>
#include <linux/irq.h>

#include <asm/machdep.h>
#include <asm/io.h>
#include <asm/mpspec.h>
#include <asm/p2v/boot_smp.h>
#include <asm/time.h>
#include <asm/timer.h>
#include <asm/timex.h>
#include <asm/process.h>
#include <asm/l_timer.h>

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

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	global_clock_event->event_handler(global_clock_event);

	return IRQ_HANDLED;
}

void __init native_time_init(void)
{
	int ret;
	DebugTM("entered\n");

	/* Initialize external timer */
	setup_lt_timer();

	ret = request_irq(0, timer_interrupt,
		IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER, "timer", NULL);
	if (ret) {
		printk("Could not setup IRQ #%02x as timer interrupt, error "
			"%d\n", 0, ret);
		return;
	}

	DebugTM("time_init exited.\n");
}
