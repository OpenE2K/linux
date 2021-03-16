#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/device.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/bcd.h>
#include <linux/rtc.h>
#include <linux/sched.h>
#include <linux/delay.h>
#include <linux/clockchips.h>
#include <asm/cpudata.h>
#include <asm/timer.h>
#include <asm/l_timer.h>
#include <asm/smp.h>
#include <asm/timex.h>
#include <asm/setup.h>
#include <asm-l/pic.h>

extern int using_apic_timer;

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);

static char clock_override[10] __initdata;

static int __init clock_setup(char* str)
{
	if (str)
		strlcpy(clock_override, str, sizeof(clock_override));
	return 1;
}
__setup("clock=", clock_setup);

#ifdef CONFIG_SMP
unsigned long profile_pc(struct pt_regs *regs)
{
	unsigned long pc = instruction_pointer(regs);

	if (in_lock_functions(pc))
		return regs->u_regs[UREG_RETPC];
	return pc;
}
EXPORT_SYMBOL(profile_pc);
#endif

static irqreturn_t timer_interrupt(int irq, void *dev_id)
{
	global_clock_event->event_handler(global_clock_event);
	return IRQ_HANDLED;
}

static struct irqaction irq0  = {
	.handler = timer_interrupt,
	.flags = IRQF_TIMER,
	.name = "timer",
};

void __init e90s_late_time_init(void)
{
	/*
	 * Now that the external timer is enabled we can
	 * set up the local PIC timer on boot CPU.
	 *
	 * Since setup_boot_pic_clock() will enable interrupts
	 * it should not be called from time_init().
	 */
	setup_boot_pic_clock();

	/* We cannot initialize clock_tick as early as other fields
	 * (other fields are required earlier in the boot process). */
	cpu_data(0).clock_tick = measure_cpu_freq(raw_smp_processor_id());
	cpu_freq_hz = cpu_data(0).clock_tick;
}

void __init time_init(void)
{
	int ret;

	/* Let the user get at STICK too. */
	__asm__ __volatile__(
		"	rd	%%stick, %%g2\n"
		"	andn	%%g2, %0, %%g2\n"
		"	wr	%%g2, 0, %%asr24"
		: /* no outputs */
		: "r" (TICK_PRIV_BIT)
		: "g1", "g2");
	/* Let the user get at TICK too.
	 * If you will set TICK_PRIV_BIT add
	 * 'return ret & ~TICK_PRIV_BIT' in get_cycles() */
	__asm__ __volatile__(
		"	rd	%%tick, %%g2\n"
		"	andn	%%g2, %0, %%g2\n"
		"	wrpr	%%g2, 0, %%tick"
		: /* no outputs */
		: "r" (TICK_PRIV_BIT)
		: "g1", "g2");

	setup_lt_timer();
	
	ret = setup_irq(0, &irq0);
	if (ret) {
		printk("Could not setup IRQ #%02x as timer interrupt, error "
			"%d\n", 0, ret);
		return;
	}

}

#ifdef ARCH_HAS_READ_CURRENT_TIMER
static inline unsigned long long tick_get_tick(void)
{
	unsigned long ret;

	__asm__ __volatile__("rd	%%stick, %0"
			     : "=r" (ret));
	return ret;
}

void __delay(unsigned long loops)
{
	unsigned long bclock, now;

	bclock = tick_get_tick();
	do {
		now = tick_get_tick();
	} while ((now-bclock) < loops);
}
EXPORT_SYMBOL(__delay);


int read_current_timer(unsigned long *timer_val)
{
	*timer_val = tick_get_tick();
	return 0;
}
#else

void __delay(unsigned long loops)
{
	__asm__ __volatile__(
"	b,pt	%%xcc, 1f\n"
"	 cmp	%0, 0\n"
"	.align	32\n"
"1:\n"
"	bne,pt	%%xcc, 1b\n"
"	 subcc	%0, 1, %0\n"
	: "=&r" (loops)
	: "0" (loops)
	: "cc");
}
#endif	/*ARCH_HAS_READ_CURRENT_TIMER*/


void udelay(unsigned long loops)
{
	migrate_disable();
	__delay(loops * (local_cpu_data().clock_tick / USEC_PER_SEC));
	migrate_enable();
}
EXPORT_SYMBOL(udelay);

int update_persistent_clock(struct timespec now)
{
	int ret = -1;
#ifdef	CONFIG_RTC
	/* Everything uses /dev/rtc0 interface. */
	struct rtc_device *rtc = rtc_class_open("rtc0");

	if (rtc) {
		ret = rtc_set_mmss(rtc, now.tv_sec);
		rtc_class_close(rtc);
	}
#endif
	return ret;
}
