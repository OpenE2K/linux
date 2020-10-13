/*
 * RTC related functions
 */
#include <linux/platform_device.h>
#include <linux/mc146818rtc.h>
#include <linux/acpi.h>
#include <linux/bcd.h>
#include <linux/pnp.h>

#include <asm/time.h>

DEFINE_SPINLOCK(rtc_lock);
EXPORT_SYMBOL(rtc_lock);

int update_persistent_clock(struct timespec now)
{
	unsigned long flags;
	int ret = -1;

	if (HAS_MACHINE_E2K_IOHUB) {
		/* Everything after E3M uses /dev/rtc0 interface. */
		struct rtc_device *rtc = rtc_class_open("rtc0");

		if (rtc) {
			ret = rtc_set_mmss(rtc, now.tv_sec);
			rtc_class_close(rtc);
		}
	} else {
		spin_lock_irqsave(&rtc_lock, flags);
		ret = l_set_persistent_clock(now.tv_sec);
		spin_unlock_irqrestore(&rtc_lock, flags);
	}

	return ret;
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
	/* Everything after E3M uses SPI rtc clocks. */
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
