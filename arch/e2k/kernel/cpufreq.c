#include <linux/hrtimer.h>	/* For tick_cpu_device */
#include <linux/tick.h>		/* For struct tick_device */

#if HZ < 50
#define CPU_FREQ_LOOPS  5
#else
#define CPU_FREQ_LOOPS  (HZ/10)
#endif

static __initdata_recv int cpu_freq_loops[NR_CPUS];
static __initdata_recv u64 cpu_freq_begin[NR_CPUS];
static __initdata_recv u64 cpu_freq_end[NR_CPUS];

/* Temporary interrupt handler. */
static void __init_recv cpu_freq_handler(struct clock_event_device *dev)
{
	u64 tsc = get_cycles();
	int cpu = smp_processor_id();

	pr_debug("cpu%d: Timer interrupt at %llu cycles\n", cpu, tsc);
	switch (cpu_freq_loops[cpu]++) {
	case 0:
	 	cpu_freq_begin[cpu] = tsc;
		break;
	case CPU_FREQ_LOOPS:
		cpu_freq_end[cpu] = tsc;
		break;
	}
}

__init_recv unsigned long measure_cpu_freq(void)
{
	unsigned long flags;
	struct clock_event_device *clock_event;
	void (*real_handler)(struct clock_event_device *dev);
	u64 delta;
	int cpu;

	local_irq_save(flags);

	cpu = smp_processor_id();

	clock_event = per_cpu(tick_cpu_device, cpu).evtdev;

	BUG_ON(!clock_event || !clock_event->event_handler);

	/* The first arriving interrupt can take a while.
	 * If interrupts were disabled before then it can
	 * arrive right before the second interrupt and delay it.
	 * So skip the first two interrupts in our measurements. */
	cpu_freq_loops[cpu] = -2;

	/* Replace the interrupt handler */
	real_handler = clock_event->event_handler;
	clock_event->event_handler = cpu_freq_handler;

	/* Disabling preemption should not be necessary, but just in case... */
	preempt_disable();

	/* Let the interrupts run */
	local_irq_enable();

	while (cpu_freq_loops[cpu] <= CPU_FREQ_LOOPS)
		cpu_relax();

	local_irq_disable();

	preempt_enable();

	/* Restore the real event handler */
	clock_event->event_handler = real_handler;

	local_irq_restore(flags);

	/* Build delta */
	delta = cpu_freq_end[smp_processor_id()] - cpu_freq_begin[smp_processor_id()];

	pr_debug("cpu%d: %llu cycles in %d jiffies, frequency = %llu Hz\n", cpu,
			delta, CPU_FREQ_LOOPS, delta * HZ / CPU_FREQ_LOOPS);

	/* Difference between two ticks is 1/HZ sec (10 ms) */
	return (delta * HZ / CPU_FREQ_LOOPS);
}

