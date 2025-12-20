/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K_SIC timer based/lt functions
 */

#include <linux/clockchips.h>
#include <linux/export.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/io.h>

#include <asm/io_apic.h>
#include <asm/l_timer.h>

#undef  DEBUG_LT_MODE
#undef  DebugLT
#define DEBUG_LT_MODE   0       /* Elbrus timer */
#define	DebugLT(fmt, args...)						\
({									\
	if (DEBUG_LT_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

long lt_clock_rate = 10000000;

lt_regs_t *lt_regs = NULL;

/* Points to the installed clock event device */
struct clock_event_device *global_clock_event;

/*
 * Initialize the LT timer.
 */
static mpc_config_timer_t * __init
find_lt_in_mp_timers(void)
{
	mpc_config_timer_t *mp_timer;
	int tm;

	if (nr_timers == 0) {
		DebugLT("empty MP timers table entry\n");
		return (NULL);
	}
	mp_timer = &mp_timers[0];
	for (tm = 0; tm < nr_timers; tm ++) {
		if (mp_timer->mpc_timertype == MP_LT_TYPE) {
			DebugLT("found Elbrus timer at entry #%d\n", tm);
			return (mp_timer);
		}
		DebugLT("entry #%d is %d type timer is not Elbrus timer\n",
			tm, mp_timer->mpc_timertype);
		mp_timer ++;
	}
	DebugLT("MP timers table has not Elbrus timer\n");
	return (NULL);
}

int __init
get_lt_timer(void)
{
	mpc_config_timer_t *lt;

	if (lt_regs)
		return 0;

	DebugLT("started\n");
	/* check clock override */
	lt = find_lt_in_mp_timers();
	if (lt == NULL) {
		DebugLT("on this machine Elbrus timer is not "
			"found\n");
		return (-ENODEV);
	}
	if (lt->mpc_timeraddr == 0) {
		pr_err("%s(): Elbrus timer registers base address "
			"is not passed\n", __func__);
		return (-ENODEV);
	}
	lt_regs = ioremap(lt->mpc_timeraddr, sizeof (*lt_regs));
	if (lt_regs == NULL) {
		pr_err("%s(): could not map Elbrus timer registers "
			"base address to virtual space\n", __func__);
		return (-ENODEV);
	}
	DebugLT("Elbrus-timers registers 0x%lx mapped to IO virtual "
		"space 0x%px\n", lt->mpc_timeraddr, lt_regs);

	return 0;

}

/*
 * We use invertation clk_state to program timer device. This is historical
 * choise, which is inherited from kernel 2.6.14. We used lt interrupt
 * to move jiffies, lt counter to know the offset and invertional clk_state
 * to differ a condition of overflow.
 *
 * We do not use counter offset anymore, but we continue use this clk_state.
 * It's known as working everythere and good tested. Nobody wants
 * to test direct clk_state on whole zoo of our machines.
 *
 * In invertional clk_state we have following interrupt diagram:
 *                     + #1              + #2
 * 1 ----------        ----------        ----------
 *            |        |        |        |
 * 0          ----------        ----------
 * We have two phase of interrupt counter:
 *	in the first phase limit bit set to 1 and when limit will
 * be reached, then no interrupts will be occured only timer will switch
 * to second phase with limit bit 0
 *	in the second phase limit bit set to 0 and when limit will
 * be reached, then interrupt will ve occured and timer switch to
 * first phase again.
 * So we should set timer to half value of interrupt period (HZ / 2)
 * and programmed IOAPIC pin to receive interrupt on edge from 0 to 1
 */

#define LT_LATCH ((lt_clock_rate + HZ/2) / HZ)	/* For divider */
static int
lt_set_periodic(struct clock_event_device *evt)
{
	DebugLT("started\n");
	/* counter start value is from 1 to limit, so +1 */
	writel(LT_WRITE_COUNTER_VALUE(LT_LATCH / 2 + 1), &lt_regs->counter_limit);
	writel(LT_INVERT_COUNTER_CNTR_LAUNCH, &lt_regs->counter_cntr);
	return 0;
}

static int
lt_shutdown(struct clock_event_device *evt)
{
	unsigned int cntr;

	DebugLT("started\n");
	cntr = readl(&lt_regs->counter_cntr);
	cntr &= ~LT_INVERT_COUNTER_CNTR_LAUNCH;
	writel(cntr, &lt_regs->counter_cntr);
	return 0;
}

/*
 * The profiling and update capabilities are switched off once the local apic is
 * registered. This mechanism replaces the previous #ifdef LOCAL_APIC -
 * !using_apic_timer decisions in do_timer_interrupt_hook()
 */
static struct clock_event_device lt_ce = {
	.name		= "lt",
	.features	= CLOCK_EVT_FEAT_PERIODIC,
	.set_state_periodic	= lt_set_periodic,
	.set_state_shutdown	= lt_shutdown,
	.shift		= 32,
	.irq		= 0,
};

/*
 * Initialize the conversion factor and the min/max deltas of the clock event
 * structure and register the clock event source with the framework.
 */
void __init setup_lt_timer(void)
{
	DebugLT("started\n");
	if (get_lt_timer()) {
		pr_err("%s(): could not get access to Elbrus-timer\n",
			__func__);
		return;
	}

	if (is_prototype()) {
		if (IS_ENABLED(CONFIG_E2K))
			lt_clock_rate = 500000;
	}

	/* cpu_possible_mask() ? */
	lt_ce.cpumask = cpumask_of(smp_processor_id());
	lt_ce.mult = div_sc(lt_clock_rate, NSEC_PER_SEC, lt_ce.shift);
	lt_ce.max_delta_ns = clockevent_delta2ns(0xF423F, &lt_ce);
	lt_ce.min_delta_ns = clockevent_delta2ns(0xF, &lt_ce);

	clockevents_register_device(&lt_ce);
	global_clock_event = &lt_ce;
	DebugLT("clockevents device Elbrus-timer was registered\n");
}

u32 lt_read(void)
{
	if (WARN_ON_ONCE(!lt_regs))
		return 0;

	/*
	 * We read low bytes only. So we don't need any lock
	 * and clocksource's mask is 32 bit.
	 */
	return readl(&lt_regs->reset_counter_lo);
}


static u64 lt_read_cs(struct clocksource *cs)
{
	/*
	 * We read low bytes only. So we don't need any lock
	 * and clocksource's mask is 32 bit.
	 */
	return readl(&lt_regs->reset_counter_lo);
}

struct clocksource lt_cs = {
	.name		= "lt",
	.rating		= 110,
	.read		= lt_read_cs,
	.mask		= CLOCKSOURCE_MASK(32),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
	.mult		= 0,
	.shift		= 20,
};
#if defined(CONFIG_SCLKR_CLOCKSOURCE)
EXPORT_SYMBOL(lt_cs);
#endif

int __init init_lt_clocksource(void)
{
	int ret;

	DebugLT("started\n");

	if (!lt_regs) {
		ret = -ENODEV;
		goto out;
	}

	ret = clocksource_register_hz(&lt_cs, lt_clock_rate);
	if (ret != 0) {
		pr_err("%s(): clocksource registration failed, error %d\n",
			__func__, ret);
	}

out:
	DebugLT("completed with return value %d\n", ret);
	return ret;
}
arch_initcall(init_lt_clocksource);

