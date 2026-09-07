/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/clockchips.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/irqdomain.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_irq.h>
#include <linux/percpu.h>
#include <linux/cpuhotplug.h>
#include <linux/acpi_pmtmr.h>
#include <linux/seq_file.h>
#include <asm/l_timer.h>

#include "apic.h"
#include "apicdef.h"
#include "apic_local.h"

static unsigned int lapic_timer_frequency = 0;
static int apic_timer_irq;
static struct clock_event_device __percpu *apic_timer_evt;

/*
 * Local APIC timer
 */

/*
 * Clock divisor.
 *
 * APIC clock speed is approximated by two integers: 'mult' and
 * 'shift'. They work as follows:
 *
 * APIC_clocks = (mult * nanoseconds) >> shift
 *
 * Thus the inherent error of this computation is:
 *
 * error = 0.5 / mult = nanoseconds / (2 * (APIC_clocks << shift))
 *
 * Now let's denote the ratio of APIC bus speed to CPU clock speed
 * as X. Then:
 *
 * APIC_clocks = X * nanoseconds
 *
 * nanoseconds = APIC_clocks / X
 *
 * error = APIC_clocks / (2 * X * (APIC_clocks << shift)) =
 *       = APIC_clocks / (2 * X * APIC_clocks * (2^shift)) =
 *       = 1 / (2 * X * (2^shift))
 *
 * Thus increasing X (which is backwards proportional to APIC_DIVISOR)
 * or shift will reduce the approximation error.
 *
 * Reducing APIC_DIVISOR will decrease the max_delta_ns. But when
 * increasing the shift we must make sure that nothing will overflow
 * 64-bits values.
 *
 *   log2(mult * nanoseconds) = log2(APIC_clocks << shift) <= 64
 *
 * (Actually under log2() here and below I mean rounded up
 * logarythm, i.e. the number of bits needed to hold the value).
 * After simple conversion we get:
 *
 *   log2(APIC_clocks) + shift <= 64
 *
 * Maximum value of log2(APIC_clocks) is 32 as TMICT and TMCCT
 * registers are 32-bits long. We want to use the maximum value
 * to allow the system to go idle for a long times, so we get:
 *
 *   shift <= 32
 *
 * So if we increase the shift we will have to decrease APIC_clocks,
 * that is, decrease max_delta_ns.
 *
 * In other words - nothing can be done...
 *
 * Some numbers:
 *
 * APIC clock (MHz) | APIC_DIVISOR | max delta (seconds)
 * -----------------------------------------------------
 *      10 (LMS)    |      16      |      6871
 *      10 (LMS)    |       1      |       429
 *    1000 (E90S)   |      16      |        69
 *    1000 (E90S)   |       1      |         4
 *
 * So it is OK to have divisor of 1
 */
#define APIC_DIVISOR 1
#define TSC_DIVISOR  32

/*
 * This function sets up the local APIC timer, with a timeout of
 * 'clocks' APIC bus clock. During calibration we actually call
 * this function twice on the boot CPU, once with a bogus timeout
 * value, second time for real. The other (noncalibrating) CPUs
 * call this function only once, with the real, calibrated value.
 *
 * We do reads before writes even if unnecessary, to get around the
 * P5 APIC double write bug.
 */
static void __setup_APIC_LVTT(unsigned int clocks, int oneshot, int irqen)
{
	unsigned int lvtt_value, tmp_value;
	struct irq_data *d = irq_get_irq_data(apic_timer_irq);

	lvtt_value = d->hwirq;
	if (!oneshot)
		lvtt_value |= APIC_LVT_TIMER_PERIODIC;

	if (!irqen)
		lvtt_value |= APIC_LVT_MASKED;

	apic_write(APIC_LVTT, lvtt_value);
	apic_printk(APIC_DEBUG, KERN_DEBUG "__setup_APIC_LVTT() APIC_LVTT == 0x%x (w) 0x%x (r)\n",
			lvtt_value, (int) apic_read(APIC_LVTT));

	/*
	 * Do not divide APIC clock.
	 */
	tmp_value = apic_read(APIC_TDCR);
	apic_write(APIC_TDCR,
		(tmp_value & ~APIC_TDR_DIV_TMBASE) | APIC_TDR_DIV_1);
	apic_printk(APIC_DEBUG, KERN_DEBUG "__setup_APIC_LVTT() APIC_TDCR == 0x%x\n",
			(int) apic_read(APIC_TDCR));

	if (!oneshot)
		apic_write(APIC_TMICT, clocks / APIC_DIVISOR);

	apic_printk(APIC_DEBUG, KERN_DEBUG "__setup_APIC_LVTT() APIC_TMICT == %d\n",
			(int) apic_read(APIC_TMICT));
}

/*
 * Program the next event, relative to now
 */
static int lapic_next_event(unsigned long delta,
			    struct clock_event_device *evt)
{
	apic_write(APIC_TMICT, delta);
	return 0;
}

static int lapic_timer_shutdown(struct clock_event_device *evt)
{
	unsigned int v;

	v = apic_read(APIC_LVTT);
	v |= (APIC_LVT_MASKED);
	apic_write(APIC_LVTT, v);
	apic_write(APIC_TMICT, 0);
	return 0;
}

static inline int
lapic_timer_set_periodic_oneshot(struct clock_event_device *evt, bool oneshot)
{
	__setup_APIC_LVTT(lapic_timer_frequency, oneshot, 1);
	return 0;
}

static int lapic_timer_set_periodic(struct clock_event_device *evt)
{
	return lapic_timer_set_periodic_oneshot(evt, false);
}

static int lapic_timer_set_oneshot(struct clock_event_device *evt)
{
	return lapic_timer_set_periodic_oneshot(evt, true);
}

/*
 * Local APIC timer broadcast function
 */
static void lapic_timer_broadcast(const struct cpumask *mask)
{
#ifdef CONFIG_SMP
	struct irq_data *d = irq_get_irq_data(apic_timer_irq);
	default_send_IPI_mask_sequence_phys(mask, d->hwirq);
#endif
}


/*
 * The local apic timer can be used for any function which is CPU local.
 */
static struct clock_event_device lapic_clockevent = {
	.name		= "lapic",
	.features	= CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.shift		= 32,
	.set_state_shutdown	= lapic_timer_shutdown,
	.set_state_periodic	= lapic_timer_set_periodic,
	.set_state_oneshot	= lapic_timer_set_oneshot,
	.set_next_event		= lapic_next_event,
	.broadcast		= lapic_timer_broadcast,
	.rating			= 100,
	.irq			= -1,
};


#ifdef CONFIG_L_WDT
void (*wd_reset_ask)(void) = NULL;
#endif

/*
 * The guts of the apic timer interrupt
 */
void local_apic_timer_interrupt(struct clock_event_device *evt)
{
	int cpu = smp_processor_id();
	if (!evt)
		evt = this_cpu_ptr(apic_timer_evt);
#ifdef CONFIG_L_WDT
	if (wd_reset_ask)
		wd_reset_ask();
#endif

	/*
	 * Normally we should not be here till LAPIC has been initialized but
	 * in some cases like kdump, its possible that there is a pending LAPIC
	 * timer interrupt from previous kernel's context and is delivered in
	 * new kernel the moment interrupts are enabled.
	 *
	 * Interrupts are enabled early and LAPIC is setup much later, hence
	 * its possible that when we get here evt->event_handler is NULL.
	 * Check for event_handler being NULL and discard the interrupt as
	 * spurious.
	 */
	if (!evt->event_handler) {
		pr_warn("Spurious LAPIC timer interrupt on cpu %d\n", cpu);
		/* Switch it off */
		lapic_timer_shutdown(evt);
		return;
	}
	evt->event_handler(evt);
}

#ifdef CONFIG_MCST
#define DELTA_NS	(NSEC_PER_SEC / HZ / 2)
#endif

/*
 * Local APIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesn't support APIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */
static irqreturn_t smp_apic_timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = dev_id;
#ifdef CONFIG_MCST
	int cpu;
	long long cur_time;
	long long next_time;

	cpu = smp_processor_id();
	next_time = per_cpu(next_rt_intr, cpu);
	if (next_time) {
		cur_time = ktime_to_ns(ktime_get());
		if (cur_time > next_time + DELTA_NS) {
			per_cpu(next_rt_intr, cpu) = 0;
		} else if (cur_time > next_time - DELTA_NS &&
				cur_time < next_time + DELTA_NS) {
			/* set 1 -- must do timer later
			 * in do_postpone_tick() */
			per_cpu(next_rt_intr, cpu) = 1;
			/* if do_postpone_tick() will not called: */
			apic_write(APIC_TMICT,
				usecs_2cycles(USEC_PER_SEC / HZ));
			return IRQ_HANDLED;
		}
	}
#endif

	local_apic_timer_interrupt(evt);
	return IRQ_HANDLED;
}

/*
 * In this functions we calibrate APIC bus clocks to the external timer.
 *
 * We want to do the calibration only once since we want to have local timer
 * irqs syncron. CPUs connected by the same APIC bus have the very same bus
 * frequency.
 *
 * This was previously done by reading the PIT/HPET and waiting for a wrap
 * around to find out, that a tick has elapsed. I have a box, where the PIT
 * readout is broken, so it never gets out of the wait loop again. This was
 * also reported by others.
 *
 * Monitoring the jiffies value is inaccurate and the clockevents
 * infrastructure allows us to do a simple substitution of the interrupt
 * handler.
 *
 * The calibration routine also uses the pm_timer when possible, as the PIT
 * happens to run way too slow (factor 2.3 on my VAIO CoreDuo, which goes
 * back to normal later in the boot process).
 */

/* Prototypes can have HZ set to 10, so use at least HZ/5 */
#define LAPIC_CAL_LOOPS		(HZ/5)

static __initdata int lapic_cal_loops = -1;
static __initdata long lapic_cal_t1, lapic_cal_t2;
static __initdata unsigned long long lapic_cal_tsc1, lapic_cal_tsc2;
static __initdata unsigned long lapic_cal_pm1, lapic_cal_pm2;
static __initdata unsigned long lapic_cal_j1, lapic_cal_j2;
static u32 levt_freq;

static void (*real_handler)(struct clock_event_device *dev);
/*
 * Temporary interrupt handler.
 */
static noinline void __init lapic_cal_handler(struct clock_event_device *dev)
{
	unsigned long long tsc = 0;
	long tapic = apic_read(APIC_TMCCT);
	unsigned long pm = acpi_pm_read_early();

	if (paravirt_enabled()) {
		/* real handler should be called too */
		/* restore handler into structure, because of */
		/* tick_handle_periodic() check handler function */
		/* see kernel/time/tick-common.c */
		dev->event_handler = real_handler;
		real_handler(dev);
		dev->event_handler = lapic_cal_handler;
	}

	tsc = get_cycles();

	switch (lapic_cal_loops++) {
	case 0:
		lapic_cal_t1 = tapic;
		lapic_cal_tsc1 = tsc;
		lapic_cal_pm1 = pm;
		lapic_cal_j1 = jiffies;
		break;

	case LAPIC_CAL_LOOPS:
		lapic_cal_t2 = tapic;
		lapic_cal_tsc2 = tsc;
		if (pm < lapic_cal_pm1)
			pm += ACPI_PM_OVRRUN;
		lapic_cal_pm2 = pm;
		lapic_cal_j2 = jiffies;
		break;
	}
}

static int __init calibrate_APIC_clock(void)
{
	long delta, deltatsc;

	if (lapic_timer_frequency)
		return -EALREADY;

	apic_printk(APIC_VERBOSE, "Using local APIC timer interrupts.\n"
		    "calibrating APIC timer ...\n");

	local_irq_disable();

	/*
	 * Setup the APIC counter to maximum. There is no way the lapic
	 * can underflow in the 100ms detection time frame
	 */
	__setup_APIC_LVTT(0xffffffff, 0, 0);

	/* Replace the global interrupt handler */
	real_handler = global_clock_event->event_handler;
	global_clock_event->event_handler = lapic_cal_handler;

	/* Let the interrupts run */
	local_irq_enable();

	while (lapic_cal_loops <= LAPIC_CAL_LOOPS)
		cpu_relax();

	local_irq_disable();

	/* Restore the real event handler */
	global_clock_event->event_handler = real_handler;

	/* Build delta t1-t2 as apic timer counts down */
	delta = lapic_cal_t1 - lapic_cal_t2;
	apic_printk(APIC_VERBOSE, "... lapic delta = %ld\n", delta);

	deltatsc = (long)(lapic_cal_tsc2 - lapic_cal_tsc1);

	lapic_timer_frequency = (delta * APIC_DIVISOR) / LAPIC_CAL_LOOPS;
	levt_freq = delta * HZ / LAPIC_CAL_LOOPS;

	apic_printk(APIC_VERBOSE, "... calibration result: %u\n", lapic_timer_frequency);

	apic_printk(APIC_VERBOSE, "... CPU clock speed is %ld.%04ld MHz.\n",
		    (deltatsc / LAPIC_CAL_LOOPS) / (1000000 / HZ),
		    (deltatsc / LAPIC_CAL_LOOPS) % (1000000 / HZ));

	apic_printk(APIC_VERBOSE, "... host bus clock speed is %u.%04u MHz.\n",
		    lapic_timer_frequency / (1000000 / HZ),
		    lapic_timer_frequency % (1000000 / HZ));

	/*
	 * Do a sanity check on the APIC calibration result
	 */
	if (lapic_timer_frequency < (1000000 / HZ)) {
		local_irq_enable();
		pr_warn("APIC frequency too slow, disabling apic timer\n");
		return -EINVAL;
	}

	local_irq_enable();

	return 0;
}

static int apic_timer_starting_cpu(unsigned int cpu)
{
	struct clock_event_device *evt = this_cpu_ptr(apic_timer_evt);

	WARN_ON(levt_freq == 0 && (!BootStrap(apic_read(APIC_BSP)) ||
				   system_state != SYSTEM_BOOTING));

	if (levt_freq == 0)
		return 0;

	*evt = lapic_clockevent;
	evt->cpumask = cpumask_of(smp_processor_id());

	clockevents_config_and_register(evt, levt_freq, 0xF, 0xFFFFFFFF);
	enable_percpu_irq(apic_timer_irq, 0);
	return 0;
}

static int apic_timer_dying_cpu(unsigned int cpu)
{
	/* Deregisteration is done in tick_cleanup_dead_cpu() */
	disable_percpu_irq(apic_timer_irq);
	return 0;
}

static void __init apic_late_time_init(void)
{
	struct clock_event_device *evt = this_cpu_ptr(apic_timer_evt);

	BUG_ON(!BootStrap(apic_read(APIC_BSP)));

	if (calibrate_APIC_clock())
		return;

	*evt = lapic_clockevent;
	evt->cpumask = cpumask_of(smp_processor_id());

	clockevents_config_and_register(evt, levt_freq, 0xF, 0xFFFFFFFF);
	enable_percpu_irq(apic_timer_irq, 0);
}

void cpuinfo_apic(struct seq_file *m)
{
	/* APIC can be installed into PCI on machine with EPIC
	 * but here we want to report our main PIC. */
	if (!cpu_has(CPU_FEAT_EPIC)) {
		seq_printf(m, " apic=%u", HZ * lapic_timer_frequency);
	}
}

static int __init apic_local_timer_of_register(struct device_node *np)
{
	u32 freq;
	int ret;

	/* Get clock frequency if present */
	if (!of_property_read_u32(np, "clock-frequency", &freq)) {
		lapic_timer_frequency = freq / HZ;
		levt_freq = freq / APIC_DIVISOR;
		apic_printk(APIC_VERBOSE, "Local APIC timer frequency set to %u.%04u MHz from device tree.\n",
				freq / 1000000, freq % 1000000);
	}

	apic_timer_evt = alloc_percpu(struct clock_event_device);
	if (!apic_timer_evt)
		return -ENOMEM;

	ret = irq_of_parse_and_map(np, 0);
	if (WARN(ret <= 0, "%pOF: missing irq: %d\n", np, ret))
		return ret;

	apic_timer_irq = ret;
	ret = request_percpu_irq(apic_timer_irq, smp_apic_timer_interrupt,
				 np->name, apic_timer_evt);
	if (WARN(ret, "%pOF: unable to request irq %d: %d\n",
			np, apic_timer_irq, ret)) {
		return ret;
	}

	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_TIMER_STARTING,
				  "apic-timer:starting",
				  apic_timer_starting_cpu,
				  apic_timer_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return ret;

	/* We have to postpone calibration as irqs are disabled now */
	late_time_init = apic_late_time_init;
	return 0;
}
TIMER_OF_DECLARE(apic_timer, "mcst,apic-timer", apic_local_timer_of_register);
