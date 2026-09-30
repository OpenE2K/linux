/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains support for of sclkr clocksource.
 */

#include <linux/clocksource.h>
#include <linux/kthread.h>
#include <linux/sysctl.h>

#include <asm/bootinfo.h>
#include <asm/sclkr.h>

char proc_sclkr_cmd[SCLKR_CMD_LEN];

enum sclkr_mode __read_mostly sclkr_mode_cmdline = SCLKR_UNINITIALIZED;
enum sclkr_mode __read_mostly sclkr_mode = SCLKR_UNINITIALIZED;
EXPORT_SYMBOL_GPL(sclkr_mode);

static int sclkr_set(const char *name, bool cmdline)
{
	enum sclkr_mode new_sclkr_mode = SCLKR_UNINITIALIZED;

	/* Do not allow disabling sclkr through procfs file, there is
	 * already an arch-independent way for switching clocksources. */
	if (cmdline && !strcmp(name, "no")) {
		new_sclkr_mode = SCLKR_NO;
	} else if (!strcmp(name, "ext")) {
		new_sclkr_mode = SCLKR_EXT;
	} else if (!strcmp(name, "rtc")) {
		new_sclkr_mode = SCLKR_RTC;
	} else if (!cpu_has(CPU_HWBUG_SCLKR_INT_C3) && !strcmp(name, "int")) {
		new_sclkr_mode = SCLKR_INT;
	}
	if (new_sclkr_mode == SCLKR_UNINITIALIZED) {
		pr_err("Possible sclkr modes: ext, rtc%s%s\n",
				cpu_has(CPU_HWBUG_SCLKR_INT_C3) ? "" : ", int",
				cmdline ? ", no" : "");
		return -EINVAL;
	}

	if (cmdline) {
		sclkr_mode_cmdline = new_sclkr_mode;
		return 0;
	} else {
		pr_warn("sclkr is set to %s by echo...>/proc\n", name);
		return sclk_register(new_sclkr_mode);
	}
}

int proc_sclkr(struct ctl_table *ctl, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret;

	if (!write) {
		strlcpy(proc_sclkr_cmd, sclkr_mode_name(sclkr_mode), SCLKR_CMD_LEN);
	}

	ret = proc_dostring(ctl, write, buffer, lenp, ppos);
	if (ret)
		return ret;

	return (write) ? sclkr_set(proc_sclkr_cmd, false) : 0;
}

static int __init sclkr_deviat(char *str)
{
	unsigned long percent;
	int ret;

	ret = kstrtoul(str, 10, &percent);
	if (ret)
		return -EINVAL;

	sclk_set_deviat(percent);
	return 0;
}
__setup("sclkd=", sclkr_deviat);

static int __init sclkr_setup(char *s)
{
	sclkr_set(s, true);
	return 1;
}
__setup("sclkr=", sclkr_setup);
