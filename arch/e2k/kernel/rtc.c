/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * RTC related functions
 */
#include <linux/platform_device.h>
#include <linux/mc146818rtc.h>
#include <linux/acpi.h>
#include <linux/bcd.h>
#include <linux/pnp.h>

#include <asm/p2v/boot_head.h>
#include <asm/time.h>
#if defined(CONFIG_SCLKR_CLOCKSOURCE)
#include <linux/clocksource.h>
#include <asm/sclkr.h>
#endif

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);

/*
 * Everything since E2C+ uses /dev/rtc0 interface.
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
		prepare_sclkr_rtc_set();
		ret = rtc_set_time(rtc, &tm);
		finish_sclkr_rtc_set();
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
	int ret;

	rtc = rtc_class_open("rtc0");
	if (!rtc)
		return 0;
	ret = rtc_read_time(rtc, &tm);
	rtc_class_close(rtc);
	if (ret)
		return 0;
	return rtc_tm_to_time64(&tm);
}

void __init native_clock_init(void)
{
	machine.set_wallclock = &iohub_rtc_set_mmss;
	machine.get_wallclock = &iohub_rtc_get_time;
}
