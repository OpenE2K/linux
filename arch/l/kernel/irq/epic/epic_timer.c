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
#include <asm/l_timer.h>

#include "epic.h"

unsigned long cepic_timer_freq =
			CONFIG_CEPIC_TIMER_FREQUENCY * 1000000;
static int cepic_timer_irq;
static struct clock_event_device __percpu *cepic_timer_evt;


static int cepic_timer_set_periodic(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg_lvtt;
	union cepic_timer_div reg_div;
	struct irq_data *d = irq_get_irq_data(cepic_timer_irq);

	reg_lvtt.raw = 0;
	reg_lvtt.mode = 1;
	reg_lvtt.vect = d->hwirq;
	epic_write_w(CEPIC_TIMER_LVTT, reg_lvtt.raw);

	/* Do not divide EPIC timer frequency */
	reg_div.raw = 0;
	reg_div.divider = CEPIC_TIMER_DIV_1;
	epic_write_w(CEPIC_TIMER_DIV, reg_div.raw);

	epic_write_w(CEPIC_TIMER_INIT, cepic_timer_freq / HZ);

	epic_printk("set EPIC timer to periodic mode on CPU #%d: HZ %d Mhz",
		smp_processor_id(), HZ);

	return 0;
}

static int cepic_timer_set_oneshot(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg_lvtt;
	union cepic_timer_div reg_div;
	struct irq_data *d = irq_get_irq_data(cepic_timer_irq);

	reg_lvtt.raw = 0;
	reg_lvtt.vect = d->hwirq;
	epic_write_w(CEPIC_TIMER_LVTT, reg_lvtt.raw);

	/* Do not divide EPIC timer frequency */
	reg_div.raw = 0;
	reg_div.divider = CEPIC_TIMER_DIV_1;
	epic_write_w(CEPIC_TIMER_DIV, reg_div.raw);

	epic_printk("set EPIC timer to oneshot mode on CPU #%d",
		smp_processor_id());

	return 0;
}

/*
 * Program the next event, relative to now
 */
static int cepic_next_event(unsigned long delta,
			    struct clock_event_device *evt)
{
	epic_write_w(CEPIC_TIMER_INIT, delta);
	return 0;
}

/* Stop generating timer interrupts and mask them */
int cepic_timer_shutdown(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg;

	reg.raw = epic_read_w(CEPIC_TIMER_LVTT);
	reg.mask = 1;
	epic_write_w(CEPIC_TIMER_LVTT, reg.raw);
	epic_write_w(CEPIC_TIMER_INIT, 0);

	return 0;
}

/*
 * The cepic timer can be used for any function which is CPU local.
 * Broadcast is not supported
 */
static struct clock_event_device cepic_clockevent = {
	.name		= "cepic",
	.features	= CLOCK_EVT_FEAT_ONESHOT | CLOCK_EVT_FEAT_PERIODIC,
	.shift		= 32,
	.set_state_shutdown	= cepic_timer_shutdown,
	.set_state_periodic	= cepic_timer_set_periodic,
	.set_state_oneshot	= cepic_timer_set_oneshot,
	.set_next_event		= cepic_next_event,
	.broadcast		= NULL,
	.rating			= 100,
	.irq			= -1,
};

/*
 * The guts of the cepic timer interrupt
 */
void cepic_timer_interrupt(struct clock_event_device *evt)

{
	if (!evt)
		evt = this_cpu_ptr(cepic_timer_evt);
	evt->event_handler(evt);
}

#define DELTA_NS	(NSEC_PER_SEC / HZ / 2)

/*
 * CEPIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesn't support CEPIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */
static irqreturn_t cepic_smp_timer_interrupt(int irq, void *dev_id)
{
	struct clock_event_device *evt = dev_id;
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
			/*
			 * set 1 -- must do timer later
			 * in do_postpone_tick()
			 */
			per_cpu(next_rt_intr, cpu) = 1;
			/* if do_postpone_tick() will not called: */
			epic_write_w(CEPIC_TIMER_INIT,
				usecs_2cycles(USEC_PER_SEC / HZ));
			return IRQ_HANDLED;
		}
	}
	cepic_timer_interrupt(evt);

	return IRQ_HANDLED;
}

static int cepic_timer_starting_cpu(unsigned int cpu)
{
	struct clock_event_device *evt = this_cpu_ptr(cepic_timer_evt);

	memcpy(evt, &cepic_clockevent, sizeof(*evt));
	evt->cpumask = cpumask_of(smp_processor_id());

	clockevents_config_and_register(evt, cepic_timer_freq,
		0xF, 0xFFFFFFFF);
	enable_percpu_irq(cepic_timer_irq, 0);
	return 0;
}

static int cepic_timer_dying_cpu(unsigned int cpu)
{
	disable_percpu_irq(cepic_timer_irq);
	return 0;
}

static int __init cepic_local_timer_of_register(struct device_node *np)
{
	int ret;

	cepic_timer_evt = alloc_percpu(struct clock_event_device);
	if (!cepic_timer_evt)
		return -ENOMEM;

	ret = irq_of_parse_and_map(np, 0);
	if (WARN(ret <= 0, "%pOF: missing irq: %d\n", np, ret))
		return ret;

	cepic_timer_irq = ret;
	ret = request_percpu_irq(cepic_timer_irq, cepic_smp_timer_interrupt,
				 np->name, cepic_timer_evt);
	if (WARN(ret, "%pOF: unable to request irq %d: %d\n",
			np, cepic_timer_irq, ret)) {
		return ret;
	}

	ret = cpuhp_setup_state(CPUHP_AP_IRQ_E2K_TIMER_STARTING,
				  "epic-timer:starting",
				  cepic_timer_starting_cpu,
				  cepic_timer_dying_cpu);

	if (WARN(ret < 0, "%pOF: Failed to setup hotplug state: %d\n", np, ret))
		return ret;

	return 0;
}
TIMER_OF_DECLARE(epic_timer, "mcst,epic-timer", cepic_local_timer_of_register);
