/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

/*
 * This file contains implementation of sched_clock().
 */

#include <linux/clocksource.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/sched/clock.h>

#include <asm/sched_clock.h>
#include <asm/sclkr.h>

/* Use raw spinlock since sched_clock() is a critical low-level functionality,
 * it must not be freezed indefinitely because of some higher priority task. */
static DEFINE_RAW_SPINLOCK(sched_clock_lock);

static DEFINE_PER_CPU(bool, is_freezed);
static u64 freezed_value __read_mostly;

/* Internal offset of sched_clock(), useful for switching between
 * different sources. */
static s64 offset __read_mostly;

static void freeze_fn(void *unused)
{
	unsigned long flags;

	/* Protect against sched_clock() calls */
	all_irq_save(flags);

	/* Freeze sched_clock() */
	u64 old_time = sched_clock();
	__this_cpu_write(is_freezed, true);

	/* And ensure time did not go backwards because of it. */
	for (;;) {
		u64 new_time = READ_ONCE(freezed_value);
		if (old_time <= new_time)
			break;

		if (cmpxchg(&freezed_value, new_time, old_time) == new_time)
			break;
	}

	all_irq_restore(flags);
}

static void unfreeze_fn(void *unused)
{
	unsigned long flags;

	/* Protect against sched_clock() calls */
	all_irq_save(flags);

	/* Unfreeze sched_clock() */
	u64 old_time = sched_clock();
	__this_cpu_write(is_freezed, false);

	/* And ensure time did not go backwards because of it.
	 * Not that `offset` has been updated already. */
	while (sched_clock() < old_time)
		cpu_relax();

	all_irq_restore(flags);
}

/**
 * freeze_sched_clock() - freeze sched_clock() at current time.
 *
 * Call this before switching sched_clock() sources on and off.
 * Use with caution, can cause latency spikes up to dozens of
 * microseconds.
 *
 * Everything must be executed in the same thread (freezing,
 * then source switch, then unfreezing) for E2K_WAIT() to work.
 * The source switch must be fast, possibly just setting a flag.
 */
void freeze_sched_clock(void) __acquires(&sched_clock_lock)
{
	unsigned long flags;

	/* Protect against concurrent freezes */
	raw_spin_lock(&sched_clock_lock);

	all_irq_save(flags);
	freezed_value = sched_clock();
	__this_cpu_write(is_freezed, true);
	all_irq_restore(flags);

	/* Wait for `freezed_value` update so that other CPUs see the new value */
	E2K_WAIT(_st_c|_mt);

	smp_call_function(freeze_fn, NULL, true);
}

/**
 * unfreeze_sched_clock() - paired with freeze sched_clock().
 * @wait: callback to wait for the switching of sched_clock()
 * sources to complete, returns true if ready.
 *
 * Call this after switching sched_clock() sources on and off.
 * Will update per-cpu offset so that sched_clock() value
 * remains continuous.
 */
void unfreeze_sched_clock(void) __releases(&sched_clock_lock)
{
	unsigned long flags;

	all_irq_save(flags);
	__this_cpu_write(is_freezed, false);
	offset += freezed_value - sched_clock();
	all_irq_restore(flags);

	/* Wait for `offset` update and source switch so that other CPUs
	 * see the new value of `offset` and new time in sched_clock(). */
	E2K_WAIT(_st_c|_mt);

	smp_call_function(unfreeze_fn, NULL, true);

	raw_spin_unlock(&sched_clock_lock);
}

/**
 * Scheduler clock - returns current time in nanoseconds.
 *
 * This clock is allowed to have some skew across different CPUs,
 * but on a single CPU it is monitonic and continous.  Functions
 * [un]freeze_sched_clock() can be used to swithc between different
 * time sources.
 */
unsigned long long sched_clock(void)
{
	unsigned long flags;
	u64 ns;

	/* Disable all interrupts to guarantee atomicity
	 * against IPIs from freeze_sched_clock() */
	all_irq_save(flags);
	if (unlikely(__this_cpu_read(is_freezed))) {
		ns = freezed_value;
	} else {
		if (likely(use_sclkr_sched_clock())) {
			/* sched_clock() tolerates small errors across CPUs and we
			 * want it to be as fast as possible, so skip CPUs syncing. */
			ns = read_sclkr_noirq();
		} else {
			ns = (unsigned long long) (jiffies - INITIAL_JIFFIES) * (NSEC_PER_SEC / HZ);
		}

		ns += offset;
	}
	all_irq_restore(flags);

	return ns;
}

static u64 sched_clock_suspend;

void save_sched_clock_state(void)
{
	sched_clock_suspend = sched_clock();
}

void restore_sched_clock_state(void)
{
	offset += sched_clock_suspend - sched_clock();
}