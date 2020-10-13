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

#include <asm-l/clkr.h>


/* definitions */

/* See comment before __cycles_2_ns() */
#define CYC2NS_SCALE 22
/* CPU frequency must be greater than this to avoid overflows on conversions */
#define CYC2NS_MIN_CPU_FREQ \
		((NSEC_PER_SEC << CYC2NS_SCALE) / ((1UL << 32) - 1UL))

/* globals */

struct clocksource clocksource_clkr;

/* locals */

static cycle_t last_clkr;

#ifdef CONFIG_E2K
static bool clkr_unreliable;

int __init noclkr_setup(char *str)
{
	clkr_unreliable = 1;

	return 1;
}
__setup("noclkr", noclkr_setup);
#endif


/* 
 * Offset of the CPU's clkr. Currently it might be needed in these cases:
 * 1) Different CPUs start at a different time.
 * 2) A processor core has been disabled for some time.
 * 3) Different processor on NUMA use different clock generators.
 */
static DEFINE_PER_CPU(cycle_t, offset) = 0;

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
		pr_warning("CPU frequency is too low, sched_clock() "
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
 *
 * FIXME TODO CLKR overflows in 1170 years on a 500 MHz processor
 * (or in 585 years on 1 Ghz). Not a problem (for now???).
 */
static inline unsigned long long __cycles_2_ns(cycles_t cyc)
{
	const u64 freq = cpu_freq_hz;
	u64 cyc_l, cyc_r, ns;

#ifdef CONFIG_CLKR_OFFSET
	/* Add per-cpu offset */
	cyc += per_cpu(offset, smp_processor_id());
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
				freq, CYC2NS_SCALE, CYC2NS_MIN_CPU_FREQ, smp_processor_id(),
				mult, cyc, cyc_r, cyc_l, per_cpu(offset, smp_processor_id()));
			WARN_ON(1);
		}
	}

	return ns;
}

/*
 * Scheduler clock - returns current time in nanosec units.
 */
unsigned long long sched_clock(void)
{
	unsigned long long ns;
#ifdef CONFIG_CLKR_OFFSET
	unsigned long flags;
#endif

#ifdef CONFIG_E2K
	if (clkr_unreliable)
		return (unsigned long long)(jiffies - INITIAL_JIFFIES)
					* (NSEC_PER_SEC / HZ);
#endif

#ifdef CONFIG_CLKR_OFFSET
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


#ifdef CONFIG_E2K
/* Special version for use inside of fast system calls. Limitations:
 * 1) Must be called with disabled interrupts.
 * 2) Must not use data stack.
 * 3) Must not use 'current' and 'current_thread_info()' since
 * corresponding global registers are not set.
 * 4) Must not do any calls. */
notrace __interrupt
cycle_t fast_syscall_read_clkr(void)
{
	struct thread_info *const ti =
			(struct thread_info *) E2K_GET_DSREG_NV(osr0);
	cycle_t before, now;
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
	cpu = ti->cpu;
	now = get_cycles() + per_cpu(offset, cpu);
#endif
	if (unlikely(now < before)) {
		/* Time is going backwards. This must be because of
		 * clkr drift (or someone disabling CPUs... in which
		 * case offset should be corrected in resume()). */
#ifdef CONFIG_CLKR_OFFSET
		per_cpu(offset, cpu) += before - now;
#endif
		now = before;
	} else {
		last_clkr = now;
	}

	return now;
}
#endif

static cycle_t read_clkr(struct clocksource *cs)
{
	unsigned long flags;
	cycle_t before, now;

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
	now += per_cpu(offset, smp_processor_id());
#endif
	if (unlikely(now < before)) {
		unsigned int cpu = smp_processor_id();

		/* Time is going backwards. This must be because of
		 * clkr drift (or someone disabling CPUs... in which
		 * case offset should be corrected in resume()). */
#ifdef CONFIG_CLKR_SYNCHRONIZATION_WARNING
		printk(KERN_DEBUG "CLKR on CPU%d is behind: clkr = %llu, "
				  "last read value = %llu\n",
				   cpu, now, before);
# ifdef CONFIG_CLKR_OFFSET
		printk(KERN_DEBUG "offset = %llu\n", per_cpu(offset, cpu));
# endif
#endif
#ifdef CONFIG_CLKR_OFFSET
		per_cpu(offset, cpu) += before - now;
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
	clocksource_clkr.cycle_last = 0;
	pr_crit("WARNING: clocksource clkr resume not implemented. "
		"You should probably adjust offset here.\n");
}

struct clocksource clocksource_clkr = {
	.name		= "clkr",
#ifdef CONFIG_E2K
	.rating		= 300,
#else
	.rating		= 100,
#endif
	.read		= read_clkr,
	.resume		= resume_clkr,
	.mask		= CLOCKSOURCE_MASK(64),
	.shift		= 22,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

static int __init clkr_init(void)
{
#ifdef CONFIG_E2K
	u8 mb_type = bootblock_virt->info.bios.mb_type;

	/* SCLKR should be used on systems that support it.
	 * Sivuch has multiple motherboards without clock synchronization. */
	if (machine.iset_ver >= E2K_ISET_V3 ||
			mb_type == MB_TYPE_ES2_RTC_CY14B101P_MULTICLOCK)
		clkr_unreliable = true;

	if (clkr_unreliable)
		return 0;
#endif

	/*
	 * (proc_freq_cycles) * mult / 2^shift  = (1 sec)
	 * mult = (1 << shift) / proc_freq
	 */
	clocksource_clkr.mult = clocksource_hz2mult(
			cpu_freq_hz, clocksource_clkr.shift);

#ifdef CONFIG_ARCH_USES_GETTIMEOFFSET
	pr_warning("Warning: clkr clocksource is disabled because "
			"ARCH_USES_GETTIMEOFFSET was enabled in "
			"kernel configuration.\n");
#else
	clocksource_register(&clocksource_clkr);
#endif

	return 0;
}
arch_initcall(clkr_init);
