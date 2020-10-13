#include <linux/init.h>
#include <linux/hrtimer.h>
#include <linux/sched.h>
#include <linux/tick.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/interrupt.h>
#include <linux/signal.h>
#include <linux/param.h>
#include <linux/mc146818rtc.h>
#include <linux/efi.h>
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/dma-mapping.h>
#include <linux/clocksource.h>

#include <asm/machdep.h>
#include <asm/io.h>
#include <asm/mpspec.h>
#include <asm/boot_smp.h>
#include <asm/time.h>
#include <asm/timer.h>
#include <asm/timex.h>
#include <asm/process.h>
#include <asm/i8253.h>
#include <asm/l_timer.h>

#undef	DEBUG_TIMER_MODE
#undef	DebugTM
#define	DEBUG_TIMER_MODE	0	/* timer and time */
#define DebugTM(...)		DebugPrint(DEBUG_TIMER_MODE ,##__VA_ARGS__)

extern ktime_t tick_period;

#ifndef	CONFIG_E2K_MACHINE
unsigned int CLOCK_TICK_RATE = CLOCK_TICK_RATE_E3M;
EXPORT_SYMBOL(CLOCK_TICK_RATE);
#endif

int timer_source = MP_PIT_TYPE;

int lt_timer_source(void)
{
	return timer_source == MP_LT_TYPE;
}

extern struct clocksource clocksource_jiffies;
void __init arch_clock_setup(void)
{
	if (machine_id & MACHINE_ID_E2K_IOHUB) {
#ifndef CONFIG_E2K_MACHINE
		CLOCK_TICK_RATE = CLOCK_TICK_RATE_E2K_SIC;
#endif  /* !CONFIG_E2K_MACHINE */
		timer_source = MP_LT_TYPE;
	} else {
#ifndef	CONFIG_E2K_MACHINE
		CLOCK_TICK_RATE = CLOCK_TICK_RATE_E3M;
#endif	/* !CONFIG_E2K_MACHINE */
		timer_source = MP_PIT_TYPE;
	}
}

extern struct machdep machine;

#if defined(CONFIG_SMP)
unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (in_lock_functions(pc)) {
		return get_nested_kernel_IP(regs, 1);
	}

	return pc;
}
EXPORT_SYMBOL(profile_pc);
#endif

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
#ifdef CONFIG_MCST_RT
	unsigned int cpu = smp_processor_id();
	unsigned long val; /* Nanoseconds */

	if (dintr_timer_state == DINTR_TIMER_RUNNING) {
		if (!lt_timer_source()) {
			val = e2k_pit_get_dintr_time();
		} else {
			val = lt_get_dintr_time();
		}

		if (val > per_cpu(dintr_time_max, cpu))
			per_cpu(dintr_time_max, cpu) = val;
		if (val < per_cpu(dintr_time_min, cpu))
			per_cpu(dintr_time_min, cpu) = val;
	}

	if (dintr_timer_state != DINTR_TIMER_WASNT_USE)
		return IRQ_HANDLED;
		
#endif /* CONFIG_MCST_RT */

	global_clock_event->event_handler(global_clock_event);

	return IRQ_HANDLED;
}

static struct irqaction irq0  = {
	.handler = timer_interrupt,
	.flags = IRQF_DISABLED | IRQF_NOBALANCING | IRQF_IRQPOLL | IRQF_TIMER,
	.name = "timer"
};

void __init time_init(void)
{
	int ret;
	DebugTM("entered. LATCH is 0x%x\n", LATCH);

	/* Initialize external timer */
	if (!lt_timer_source())
		setup_pit_timer();
	else
		setup_lt_timer();

	ret = setup_irq(0, &irq0);
	if (ret) {
		printk("Could not setup IRQ #%02x as timer interrupt, error "
			"%d\n", 0, ret);
		return;
	}

	DebugTM("time_init exited.\n");
}

#ifdef CONFIG_MCST_RT
int mcst_rt_timer_start(void)
{
	if (!lt_timer_source()) {
		return mcst_rt_pit_start();
	} else {
		return mcst_rt_lt_start();
	}
}
int mcst_rt_timer_stop(void)
{
	if (!lt_timer_source()) {
		return mcst_rt_pit_stop();
	} else {
		return mcst_rt_lt_stop();
	}
}
#endif

#ifdef	CONFIG_RECOVERY
void time_recovery(void)
{
	struct clock_event_device *clock_event;

	ktime_t now = ktime_get();

	DebugTM("time_recovery() entered. LATCH is 0x%x\n", LATCH);

	/* TODO RECOVERY  we are not using arch-independent
	 * support for control points so we have to avoid using
	 * generic time-recover routines: since all time-handling
	 * data is suspended to the disk as it is, after recovery
	 * only the devices' states will change. We will restore
	 * that state on every CPU's registered device independently
	 * (see also e2k_do_start_secondary() in smpboot.c).
	 *
	 * This probably will not work for oneshot mode.
	 *
	 * Also time is not updated. */

	clock_event = per_cpu(tick_cpu_device, smp_processor_id()).evtdev;

	BUG_ON(!clock_event || !clock_event->event_handler
			|| !clock_event->set_mode);

	pr_alert("Setting clock_event '%s' to mode %d\n",
		clock_event->name, clock_event->mode);
	
	clock_event->set_mode(clock_event->mode, clock_event);
	
	clockevents_program_event(
		clock_event, ktime_add(now, tick_period), true);

	DebugTM("time_recovery() exited.\n");
}
#endif	/* CONFIG_RECOVERY */
