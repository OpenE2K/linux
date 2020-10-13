/*
 * lt.c  E2K_SIC timer based/lt functions
 *
 * Copyright (C) 2010,2011,2012,2013,2014 MCST (os@mcst.ru)
 */
#include <linux/clockchips.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>

#include <asm/io_apic.h>
#include <asm/l_timer.h>

#undef  DEBUG_LT_MODE
#undef  DebugLT
#define DEBUG_LT_MODE   0       /* Elbrus timer */
#define DebugLT         if (DEBUG_LT_MODE) printk

#define LT_CLOCK_RATE 10000000

lt_regs_t *lt_regs = NULL;

/* Points to the installed clock event device (PIT on E3M and LT otherwise) */
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
		DebugLT("find_lt_in_mp_timers() empty MP timers table "
			"entry\n");
		return (NULL);
	}
	mp_timer = &mp_timers[0];
	for (tm = 0; tm < nr_timers; tm ++) {
		if (mp_timer->mpc_timertype == MP_LT_TYPE) {
			DebugLT("find_lt_in_mp_timers() found Elbrus timer "
				"at entry #%d\n", tm);
			return (mp_timer);
		}
		DebugLT("find_lt_in_mp_timers() entry #%d is %d type timer "
			"is not Elbrus timer\n",
			tm, mp_timer->mpc_timertype);
		mp_timer ++;
	}
	DebugLT("find_lt_in_mp_timers() MP timers table has not Elbrus "
		"timer\n");
	return (NULL);
}

static int __init
get_lt_timer(void)
{
	mpc_config_timer_t *lt;

	DebugLT("init_lt() started\n");
	/* check clock override */
	if (!L_TIMER_IS_ALLOWED()) {
		DebugLT("init_lt() on this machine Elbrus timer is not "
			"implemented\n");
		return (-ENODEV);
	}
	lt = find_lt_in_mp_timers();
	if (lt == NULL) {
		DebugLT("init_lt() on this machine Elbrus timer is not "
			"found\n");
		return (-ENODEV);
	}
	if (lt->mpc_timeraddr == 0) {
		printk("init_lt() Elbrus timer registers base address "
			"is not passed\n");
		return (-ENODEV);
	}
	lt_regs = ioremap(lt->mpc_timeraddr, sizeof (*lt_regs));
	if (lt_regs == NULL) {
		printk("init_lt() could not map Elbrus timer registers "
			"base address to virtual space\n");
		return (-ENODEV);
	}
	DebugLT("init_lt() L-timers registers 0x%lx mapped to IO virtual "
		"space 0x%p\n", lt->mpc_timeraddr, lt_regs);

	return 0;

}

static void
lt_set_mode(enum clock_event_mode mode, struct clock_event_device *evt)
{
	unsigned int cntr;

	/*
	 * We use invertation mode to program timer device. This is historical
	 * choise, which is inherited from kernel 2.6.14. We used lt interrupt
	 * to move jiffies, lt counter to know the offset and invertional mode
	 * to differ a condition of overflow.
	 *
	 * We do not use counter offset anymore, but we continue use this mode.
	 * It's known as working everythere and good tested. Nobody wants
	 * to test direct mode on whole zoo of our machines.
	 *
	 * In invertional mode we have following interrupt diagram:
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

	switch (mode) {
	case CLOCK_EVT_MODE_PERIODIC:
		/* counter start value is from 1 to limit, so +1 */
		writel(LT_WRITE_COUNTER_VALUE(LATCH / 2 + 1), &lt_regs->counter_limit);
		writel(LT_INVERT_COUNTER_CNTR_LAUNCH, &lt_regs->counter_cntr);
		break;
	case CLOCK_EVT_MODE_UNUSED:
	case CLOCK_EVT_MODE_SHUTDOWN:
		cntr = readl(&lt_regs->counter_cntr);
		cntr &= ~LT_INVERT_COUNTER_CNTR_LAUNCH;
		writel(cntr, &lt_regs->counter_cntr);
		break;
	default:
		pr_warning("lt_set_mode: mode=0x%x is not implemented\n", mode);
		break;
	}
}

/*
 * The profiling and update capabilities are switched off once the local apic is
 * registered. This mechanism replaces the previous #ifdef LOCAL_APIC -
 * !using_apic_timer decisions in do_timer_interrupt_hook()
 */
static struct clock_event_device lt_ce = {
	.name		= "lt",
	.features	= CLOCK_EVT_FEAT_PERIODIC,
	.set_mode	= lt_set_mode,
	.shift		= 32,
	.irq		= 0,
};

/*
 * Initialize the conversion factor and the min/max deltas of the clock event
 * structure and register the clock event source with the framework.
 */
void __init setup_lt_timer(void)
{
	if (get_lt_timer())
		return;

	/* cpu_possible_mask() ? */
	lt_ce.cpumask = cpumask_of(smp_processor_id());
	lt_ce.mult = div_sc(LT_CLOCK_RATE, NSEC_PER_SEC, lt_ce.shift);
	lt_ce.max_delta_ns = clockevent_delta2ns(0xF423F, &lt_ce);
	lt_ce.min_delta_ns = clockevent_delta2ns(0xF, &lt_ce);

	clockevents_register_device(&lt_ce);
	global_clock_event = &lt_ce;
}

static cycle_t lt_read(struct clocksource *cs)
{
	/*
	 * We read low bytes only. So we don't need any lock
	 * and clocksource's mask is 32 bit.
	 */
	return readl(&lt_regs->reset_counter_lo);
}

static struct clocksource lt_cs = {
	.name		= "lt",
	.rating		= 110,
	.read		= lt_read,
	.mask		= CLOCKSOURCE_MASK(32),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
	.mult		= 0,
	.shift		= 20,
};

static int __init init_lt_clocksource(void)
{
#ifdef	__e2k__
	if (!HAS_MACHINE_L_SIC) {
		return -ENODEV;
	}
#endif	/* __e2k__ */

	if (!lt_regs)
		return -ENODEV;

	lt_cs.mult = clocksource_hz2mult(LT_CLOCK_RATE, lt_cs.shift);

	return clocksource_register(&lt_cs);
}
arch_initcall(init_lt_clocksource);

#ifdef CONFIG_MCST_RT
int mcst_rt_lt_start(void)
{
	if (lt_ce.mode != CLOCK_EVT_MODE_UNUSED || !lt_regs)
		return -ENODEV;

	lt_set_mode(CLOCK_EVT_MODE_PERIODIC, &lt_ce);

	return 0;
}
int mcst_rt_lt_stop(void)
{
	if (lt_ce.mode != CLOCK_EVT_MODE_UNUSED || !lt_regs)
		return -ENODEV;

	lt_set_mode(CLOCK_EVT_MODE_SHUTDOWN, &lt_ce);

	return 0;
}
unsigned long lt_get_dintr_time(void)
{
	cycle_t cycles;

	if (!lt_regs)
		return 0;

	cycles = readl(&lt_regs->counter);
	cycles = LT_READ_COUNTER_VALUE(cycles & ~LT_COUNTER_LIMIT_BIT);

	return cycles*(NSEC_PER_SEC/LT_CLOCK_RATE);
}
#endif
