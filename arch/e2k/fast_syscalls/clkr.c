/*
 * arch/e2k/kernel/clkr.c
 *
 * This file contains implementation of clkr clocksource.
 *
 * Copyright (C) 2011 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

/* includes */
#include <linux/percpu.h>
#include <linux/clocksource.h>
#include <linux/sched.h>

#include <asm/clkr.h>


/* definitions */

/* See comment before __cycles_2_ns() */
#define CYC2NS_SCALE 22
/* CPU frequency must be greater than this to avoid overflows on conversions */
#define CYC2NS_MIN_CPU_FREQ \
		((NSEC_PER_SEC << CYC2NS_SCALE) / ((1UL << 32) - 1UL))

/* Special version for use inside of fast system calls. Limitations:
 * 1) Must be called with disabled interrupts.
 * 2) Must not use data stack.
 * 3) Must not use 'current' and 'current_thread_info()' since
 * corresponding global registers are not set.
 * 4) Must not do any calls. */
__section(".entry.text")
notrace __interrupt
u64 fast_syscall_read_clkr(void)
{
	struct thread_info *const ti = READ_CURRENT_REG();
	u64 before, now;
#ifdef CONFIG_CLKR_OFFSET
	unsigned cpu;
#endif

	before = last_clkr;
	/* Make sure we read 'last_clkr' before CLKR register */
	smp_rmb();
#ifndef CONFIG_CLKR_OFFSET
	now = get_cycles();
#else
	/* Do not access current_thread_info() here since we
	 * do not setup g12 and g13 in fast system calls. */
	cpu = task_cpu(thread_info_task(ti));
	now = get_cycles() + per_cpu(clkr_offset, cpu);
#endif
	if (unlikely(now < before)) {
		/* Time is going backwards. This must be because of
		 * clkr drift (or someone disabling CPUs... in which
		 * case offset should be corrected in resume()). */
#ifdef CONFIG_CLKR_OFFSET
		per_cpu(clkr_offset, cpu) += before - now;
#endif
		now = before;
	} else {
		last_clkr = now;
	}

	return now;
}
