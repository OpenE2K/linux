/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/delay.h>
#include <linux/export.h>
#include <linux/time64.h>
#include <asm/processor.h>
#include <asm/delay.h>
#include <asm/timer.h>

void notrace __delay(unsigned long cycles)
{
	cycles_t start = get_cycles();

	while (get_cycles() - start < cycles)
		cpu_relax();
}
EXPORT_SYMBOL(__delay);

void notrace udelay(unsigned long usecs)
{
	__delay(usecs * loops_per_jiffy * HZ / USEC_PER_SEC);
}
EXPORT_SYMBOL(udelay);

int native_read_current_timer(unsigned long *timer_val)
{
	*timer_val = get_cycles();

	return 0;
}

