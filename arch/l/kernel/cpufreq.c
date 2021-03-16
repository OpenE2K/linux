#include <linux/clocksource.h>
#include <linux/cpufreq.h>
#include <linux/irqflags.h>
#include <linux/smp.h>

#include <asm/timex.h>
#include <asm-l/l_timer.h>

static void measure_cpu_freq_ipi(void *arg)
{
#ifdef CONFIG_E2K
	unsigned long flags;
#endif
	u64 *freq = arg;
	volatile cycles_t cpu_tick_before, cpu_tick_after;
	volatile u32 lt_tick_before, lt_tick_after;

#ifdef CONFIG_E2K
	/* Make sure NMIs do not mess up our calculation */
	raw_all_irq_save(flags);
#endif
	lt_tick_before = lt_read();
	cpu_tick_before = get_cycles();
#ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
#endif

	while (lt_read() - lt_tick_before < CLOCK_TICK_RATE / 1000)
		barrier();

#ifdef CONFIG_E2K
	raw_all_irq_save(flags);
#endif
	lt_tick_after = lt_read();
	cpu_tick_after = get_cycles();
#ifdef CONFIG_E2K
	raw_all_irq_restore(flags);
#endif

	*freq = (cpu_tick_after - cpu_tick_before) * CLOCK_TICK_RATE /
		(lt_tick_after - lt_tick_before);
}

static DEFINE_PER_CPU(u64, cpu_freq);

unsigned long measure_cpu_freq(int cpu)
{
	u64 freq;

	/* First try querying the cpufreq driver */
	freq = 1000 * cpufreq_quick_get(cpu);
	if (freq)
		return freq;

	/* cpufreq is disabled so there is no need to re-measure frequency */
	if ((freq = per_cpu(cpu_freq, cpu)))
		return freq;

	/*
	 * Workaround for paravirtualization: do not call smp_call_function from
	 * e2k_start_secondary: it leads to a WARN_ON(cpu_online && irqs_disabled)
	 */
	if (cpu == smp_processor_id()) {
		measure_cpu_freq_ipi(&freq);
	} else {
		/* If cpufreq failed, then calibrate using lt timer from iohub */
		smp_call_function_single(cpu, measure_cpu_freq_ipi, &freq, true);
	}

	per_cpu(cpu_freq, cpu) = freq;

	return freq;
}
