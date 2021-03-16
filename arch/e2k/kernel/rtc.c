/*
 * RTC related functions
 */
#include <linux/platform_device.h>
#include <linux/mc146818rtc.h>
#include <linux/acpi.h>
#include <linux/bcd.h>
#include <linux/pnp.h>

#include <asm/p2v/boot_head.h>
#include <asm/machdep_numa.h>
#include <asm/time.h>
#if defined(CONFIG_SCLKR_CLOCKSOURCE)
#include <linux/clocksource.h>
#include <asm/sclkr.h>
#endif

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);

/*
 * In order to set the CMOS clock precisely, set_rtc_mmss has to be
 * called 500 ms after the second nowtime has started, because when
 * nowtime is written into the registers of the CMOS clock, it will
 * jump to the next second precisely 500 ms later. Check the Motorola
 * MC146818A or Dallas DS12887 data sheet for details.
 *
 * BUG: This routine does not handle hour overflow properly; it just
 *      sets the minutes. Usually you'll only notice that after reboot!
 */

static int x86_set_rtc_mmss(unsigned long nowtime)
{
	int retval = 0;
	int real_seconds, real_minutes, cmos_minutes;
	unsigned char save_control, save_freq_select;

	save_control = CMOS_READ(RTC_CONTROL);	/* tell the clock it's being */
						/* set */
	CMOS_WRITE((save_control|RTC_SET), RTC_CONTROL);

	save_freq_select = CMOS_READ(RTC_FREQ_SELECT);	/* stop and reset */
							/* prescaler */
	CMOS_WRITE((save_freq_select|RTC_DIV_RESET2), RTC_FREQ_SELECT);

	cmos_minutes = CMOS_READ(RTC_MINUTES);
	if (!(save_control & RTC_DM_BINARY) || RTC_ALWAYS_BCD)
		cmos_minutes = bcd2bin(cmos_minutes);

	/*
	 * since we're only adjusting minutes and seconds,
	 * don't interfere with hour overflow. This avoids
	 * messing with unknown time zones but requires your
	 * RTC not to be off by more than 15 minutes
	 */
	real_seconds = nowtime % 60;
	real_minutes = nowtime / 60;
	if (((abs(real_minutes - cmos_minutes) + 15)/30) & 1)
		real_minutes += 30;	/* correct for half hour time zone */
	real_minutes %= 60;

	if (abs(real_minutes - cmos_minutes) < 30) {
		if (!(save_control & RTC_DM_BINARY) || RTC_ALWAYS_BCD) {
			real_seconds = bin2bcd(real_seconds);
			real_minutes = bin2bcd(real_minutes);
		}
		CMOS_WRITE(real_seconds, RTC_SECONDS);
		CMOS_WRITE(real_minutes, RTC_MINUTES);
	} else {
		printk(KERN_WARNING
		       "set_rtc_mmss: can't update from %d to %d\n",
		       cmos_minutes, real_minutes);
		retval = -1;
	}

	/* The following flags have to be released exactly in this order,
	 * otherwise the DS12887 (popular MC146818A clone with integrated
	 * battery and quartz) will not reset the oscillator and will not
	 * update precisely 500 ms later. You won't find this mentioned in
	 * the Dallas Semiconductor data sheets, but who believes data
	 * sheets anyway ...                           -- Markus Kuhn
	 */
	CMOS_WRITE(save_control, RTC_CONTROL);
	CMOS_WRITE(save_freq_select, RTC_FREQ_SELECT);

	return retval;
}

static unsigned long x86_get_cmos_time(void)
{
	unsigned int year, mon, day, hour, min, sec;
	int i;

	/* The Linux interpretation of the CMOS clock register contents:
	 * When the Update-In-Progress (UIP) flag goes from 1 to 0, the
	 * RTC registers show the second which has precisely just started.
	 * Let's hope other operating systems interpret the RTC the same way.
	 */
	/* read RTC exactly on falling edge of update flag */
	for (i = 0; i < 1000000; i++)	/* may take up to 1 second... */
		if (CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP)
			break;
	for (i = 0; i < 1000000; i++)	/* must try at least 2.228 ms */
		if (!(CMOS_READ(RTC_FREQ_SELECT) & RTC_UIP))
			break;
	do { /* Isn't this overkill ? UIP above should guarantee consistency */
		sec = CMOS_READ(RTC_SECONDS);
		min = CMOS_READ(RTC_MINUTES);
		hour = CMOS_READ(RTC_HOURS);
		day = CMOS_READ(RTC_DAY_OF_MONTH);
		mon = CMOS_READ(RTC_MONTH);
		year = CMOS_READ(RTC_YEAR);
	} while (sec != CMOS_READ(RTC_SECONDS));
	if (!(CMOS_READ(RTC_CONTROL) & RTC_DM_BINARY) || RTC_ALWAYS_BCD) {
		sec = bcd2bin(sec);
		min = bcd2bin(min);
		hour = bcd2bin(hour);
		day = bcd2bin(day);
		mon = bcd2bin(mon);
		year = bcd2bin(year);
	}
	if ((year += 1900) < 1970)
		year += 100;

	return mktime(year, mon, day, hour, min, sec);
}

/*
 * Everything since E2ó+ uses /dev/rtc0 interface.
 */
static int iohub_rtc_set_mmss(unsigned long nowtime)
{
	struct rtc_device *rtc;
	struct rtc_time tm;
	int ret;

	rtc_time64_to_tm(nowtime, &tm);
	rtc = rtc_class_open("rtc0");
	if (rtc == NULL)
		return -1;

#if defined(CONFIG_SCLKR_CLOCKSOURCE)
	if (strcmp(curr_clocksource->name, "sclkr") == 0 &&
			sclkr_mode == SCLKR_RTC) {
		timekeeping_notify(&lt_cs);
		ret = rtc_set_time(rtc, &tm);
		timekeeping_notify(&clocksource_sclkr);
	} else {
		ret = rtc_set_time(rtc, &tm);
	}
#else
	ret = rtc_set_time(rtc, &tm);
#endif
	rtc_class_close(rtc);

	return ret;
}

static unsigned long iohub_rtc_get_time(void)
{
	struct rtc_time tm;
	struct rtc_device *rtc = rtc_class_open("rtc0");
	unsigned long time;
	int ret;

	rtc = rtc_class_open("rtc0");
	if (!rtc)
		return 0;
	ret = rtc_read_time(rtc, &tm);
	rtc_class_close(rtc);
	if (ret)
		return 0;
	ret = rtc_tm_to_time(&tm, &time);
	if (ret)
		return 0;
	return time;
}

void __init native_clock_init(void)
{
	int nid;

	if (HAS_MACHINE_E2K_IOHUB) {
		for_each_node_has_dup_kernel(nid) {
			the_node_machine(nid)->set_wallclock =
				&iohub_rtc_set_mmss;
			the_node_machine(nid)->get_wallclock =
				&iohub_rtc_get_time;
		}
	} else {
		for_each_node_has_dup_kernel(nid) {
			the_node_machine(nid)->set_wallclock =
				&x86_set_rtc_mmss;
			the_node_machine(nid)->get_wallclock =
				&x86_get_cmos_time;
		}
	}
}

int update_persistent_clock(struct timespec now)
{
	unsigned long flags;
	int ret;

	spin_lock_irqsave(&rtc_lock, flags);
	ret = mach_set_wallclock(now.tv_sec);
	spin_unlock_irqrestore(&rtc_lock, flags);

	return ret;
}

void read_persistent_clock(struct timespec *ts)
{
	unsigned long retval, flags;

	spin_lock_irqsave(&rtc_lock, flags);
	retval = mach_get_wallclock();
	spin_unlock_irqrestore(&rtc_lock, flags);

	ts->tv_sec = retval;
	ts->tv_nsec = 0;
}

static struct resource rtc_resources[] = {
	[0] = {
		.start	= RTC_PORT(0),
		.end	= RTC_PORT(1),
		.flags	= IORESOURCE_IO,
	},
	[1] = {
		.start	= RTC_IRQ,
		.end	= RTC_IRQ,
		.flags	= IORESOURCE_IRQ,
	}
};

static struct platform_device rtc_device = {
	.name		= "rtc_cmos",
	.id		= -1,
	.resource	= rtc_resources,
	.num_resources	= ARRAY_SIZE(rtc_resources),
};

static __init int add_rtc_cmos(void)
{
	/* Everything since E2C+ uses SPI rtc clocks. */
	if (HAS_MACHINE_E2K_IOHUB)
		return 0;

#ifdef CONFIG_PNP
	static const char *ids[] __initconst =
	    { "PNP0b00", "PNP0b01", "PNP0b02", };
	struct pnp_dev *dev;
	struct pnp_id *id;
	int i;

	pnp_for_each_dev(dev) {
		for (id = dev->id; id; id = id->next) {
			for (i = 0; i < ARRAY_SIZE(ids); i++) {
				if (compare_pnp_id(id, ids[i]) != 0)
					return 0;
			}
		}
	}
#endif

	platform_device_register(&rtc_device);
	dev_info(&rtc_device.dev,
		 "registered platform RTC device (no PNP device found)\n");

	return 0;
}
device_initcall(add_rtc_cmos);
