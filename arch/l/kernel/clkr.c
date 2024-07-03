/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of clkr clocksource.
 */

#include <linux/percpu.h>
#include <linux/clocksource.h>
#include <linux/sched.h>
#include <linux/sched/clock.h>


/* See comment before __cycles_2_ns() */
#define CYC2NS_SCALE 22
/* CPU frequency must be greater than this to avoid overflows on conversions */
#define CYC2NS_MIN_CPU_FREQ \
		((NSEC_PER_SEC << CYC2NS_SCALE) / ((1UL << 32) - 1UL))

u64 last_clkr;

static bool clkr_unreliable = true;

/* 
 * Offset of the CPU's clkr. Currently it might be needed in these cases:
 * 1) Different CPUs start at a different time.
 * 2) A processor core has been disabled for some time.
 * 3) Different processor on NUMA use different clock generators.
 */
DEFINE_PER_CPU(u64, clkr_offset) = 0;

/*
 * Used when converting cycles to nanoseconds in sched_clock()
 * with the following formula:
 *   nanoseconds = (cycles * mult) >> CYC2NS_SCALE
 *
 * Since sched_clock() tolerates small errors and all CPUs
 * are running at the same frequency, we use the same 'mult'
 * for all CPUs.
 */
static u64 __read_mostly mult;



/* Until this function comlpetes sched_clock() will always
 * return 0 due to 'mult' being set to 0. */
static int __init e2k_sched_clock_init(void)
{
	u64 freq = cpu_freq_hz;

	/* Set multiplication factor for sched_clock() */
	mult = ((NSEC_PER_SEC << CYC2NS_SCALE) + freq / 2) / freq;
	if (unlikely(mult >= (1UL << 32))) {
		/* Cannot use math with scaling
		 * because of overflows. */
		pr_warn("CPU frequency is too low, sched_clock() "
				"will be a bit imprecise\n");
	}

	return 0;
}
pure_initcall(e2k_sched_clock_init);

/* 
 * Here is the math (NSEC_PER_SEC = 10^9):
 *
 *   nanoseconds = cycles * coeff 
 *   10^9 = cpufreq * coeff
 *   coeff = 10^9 / cpufreq    <===  cpufreq ~= 10^9, so this won't do
 *   coeff = (10^9 * 2^scale) / (cpufreq * 2^scale)
 *   coeff = ((10^9 << scale) / cpufreq) >> scale
 *
 * We want to avoid doing division on the hot path, so we precompute:
 *   mult = (10^9 << scale) / cpufreq
 *   nanoseconds = (cycles * mult) >> scale
 *
 * The rounding error when computing mult is (assuming cpufreq <= 10^9):
 *   error = cpufreq / (2 * 10^9 << scale) <= 1 / (2 ^ (scale + 1))
 * For scale of 22 error will be 10^-7 (0,000012 %).
 *
 * To avoid overflows use special math. Let's denote with cyc_l
 * the left (biggest) 32-bits part of cyc and with cyc_r the
 * right 32-bits part of cyc. We assume that mult can be held in
 * 32-bits integer (this is true for cpufreq >= 976563 Hz if
 * scale equals 22).
 *
 *   ns = cyc * mult >> scale
 *   ns = (cyc_r + (cyc_l << 32)) * mult >> scale
 *   ns = cyc_r * mult >> scale + cyc_l * mult << (32 - scale)
 */
static inline unsigned long long __cycles_2_ns(cycles_t cyc)
{
	const u64 freq = cpu_freq_hz;
	u64 cyc_l, cyc_r, ns;

#ifdef CONFIG_CLKR_OFFSET
	/* Add per-cpu offset */
	cyc += per_cpu(clkr_offset, smp_processor_id());
#endif
	/* Ensure monotonicity (and protect from clkr stops) */
	if (unlikely(cyc < last_clkr))
		cyc = last_clkr;
	/* Do not update last_clkr and offset here as sched_clock()
	 * tolerates small errors and must be as fast as possible. */

	/* Split cyc in two 32-bits parts */
	cyc_l = cyc >> 32;
	cyc_r = cyc & 0xFFFFFFFFUL;

	if (unlikely(mult >= (1UL << 32))) {
		/* Too bad. Can't do the scaled math, but the frequency
		 * should be rather low for this to happen (not greater
		 * than CYC2NS_MIN_CPU_FREQ) so use normal math with 0
		 * scale (slow case which should not happen). */
		ns = (cyc_r * NSEC_PER_SEC + freq/2) / freq +
			(((cyc_l * NSEC_PER_SEC + freq/2) / freq) << 32);
	} else {
		static bool warned;

		/* Compute nanoseconds without 64-bits overflows */
		ns = ((cyc_r * mult) >> CYC2NS_SCALE) +
				((cyc_l * mult) << (32 - CYC2NS_SCALE));

		if (unlikely(freq <= CYC2NS_MIN_CPU_FREQ) && freq && !warned &&
					system_state == SYSTEM_RUNNING) {
			/* Whoops, should not happen since we already
			 * have checked mult. Looks like there is
			 * something wrong with mathematics or our stack. */
			warned = true;

			pr_err("Looks like there is an error in mathematics "
				"in sched_clock() or someone is doing "
				"something very bad!\nfreq = %lld <= "
				"CYC2NS_SCALE = %d, CYC2NS_MIN_CPU_FREQ = %ld,"
				" cpu = %d, mult = %lld, cycles = 0x%lx, "
				"cyc_r = 0x%llx, cyc_l = 0x%llx, offset = %lld\n",
				freq, CYC2NS_SCALE, CYC2NS_MIN_CPU_FREQ,
				smp_processor_id(), mult, cyc, cyc_r, cyc_l,
				per_cpu(clkr_offset, smp_processor_id()));
			WARN_ON(1);
		}
	}

	return ns;
}

#ifndef CONFIG_E90S
/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	unsigned long long ns;
#ifdef CONFIG_CLKR_OFFSET
	unsigned long flags;

	/* Close interrupts to make sure that cpu does not
	 * change after reading cycles. */
	raw_local_irq_save(flags);
#endif
	ns = __cycles_2_ns(get_cycles());
#ifdef CONFIG_CLKR_OFFSET
	raw_local_irq_restore(flags);
#endif
	return ns;
}
#endif

static u64 read_clkr(struct clocksource *cs)
{
	unsigned long flags;
	u64 before, now;

	raw_local_irq_save(flags);
	before = last_clkr;
	/* Make sure we read 'last_clkr' before CLKR register */
#ifdef CONFIG_SPARC64
	__asm__ __volatile__("membar #Sync");
#else
	smp_rmb();
#endif
	now = get_cycles();

#ifdef CONFIG_CLKR_OFFSET
	now += per_cpu(clkr_offset, smp_processor_id());
#endif
	if (unlikely(now < before)) {
#if defined CONFIG_CLKR_SYNCHRONIZATION_WARNING || defined CONFIG_CLKR_OFFSET
		unsigned int cpu = smp_processor_id();
#endif

		/* Time is going backwards. This must be because of
		 * clkr drift (or someone disabling CPUs... in which
		 * case offset should be corrected in resume()). */
#ifdef CONFIG_CLKR_SYNCHRONIZATION_WARNING
		printk(KERN_DEBUG "CLKR on CPU%d is behind: clkr = %llu, "
				  "last read value = %llu\n",
				   cpu, now, before);
# ifdef CONFIG_CLKR_OFFSET
		printk(KERN_DEBUG "offset = %llu\n", per_cpu(clkr_offset, cpu));
# endif
#endif
#ifdef CONFIG_CLKR_OFFSET
		per_cpu(clkr_offset, cpu) += before - now;
#endif
		now = before;
	} else {
		last_clkr = now;
	}
	raw_local_irq_restore(flags);

	return now;
}

static void resume_clkr(struct clocksource *cs)
{
	pr_crit("WARNING: clocksource clkr resume not implemented. "
		"You should probably adjust offset here.\n");
}

static struct clocksource clocksource_clkr = {
	.name		= "clkr",
	.rating		= 100,
	.read		= read_clkr,
	.resume		= resume_clkr,
	.mask		= CLOCKSOURCE_MASK(64),
	.shift		= 22,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static int __init clkr_init(void)
{
	/* Sivuch has multiple motherboards without clock synchronization. */
	if (num_online_nodes() <= 1)
		clkr_unreliable = false;

	if (clkr_unreliable) {
		clear_sched_clock_stable();
		return 0;
	}

#ifdef CONFIG_ARCH_USES_GETTIMEOFFSET
	pr_warn("Warning: clkr clocksource is disabled because "
			"ARCH_USES_GETTIMEOFFSET was enabled in "
			"kernel configuration.\n");
#else
	if (e90s_get_cpu_type() < E90S_CPU_R2000)
		clocksource_register_hz(&clocksource_clkr, cpu_freq_hz);
#endif

	return 0;
}
arch_initcall(clkr_init);
