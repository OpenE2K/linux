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

char sclkr_src[SCLKR_SRC_LEN] = "no"; /* no, ext, rtc, int */
int sclkr_mode = -1;
EXPORT_SYMBOL_GPL(sclkr_mode);

static int sclkr_set(int cmdline)
{
	int ret = 0;
	static struct task_struct *sclkregistask;
	int new_sclkr_mode = -1;

	if (!strcmp(sclkr_src, "no"))
		new_sclkr_mode = SCLKR_NO;
	if (!strcmp(sclkr_src, "ext"))
		new_sclkr_mode = SCLKR_EXT;
	if (!strcmp(sclkr_src, "rtc"))
		new_sclkr_mode = SCLKR_RTC;
	if (!strcmp(sclkr_src, "int"))
		new_sclkr_mode = SCLKR_INT;
	if (new_sclkr_mode < 0) {
		pr_err(KERN_ERR "Possible sclkr modes are:\n"
			"no, ext, rtc, int\n");
		return -EINVAL;
	}
	pr_warn("sclkr is set to %s (mod_no=%d) by %s\n",
		sclkr_src, new_sclkr_mode,
			cmdline ? "cmdline" : "echo...>/proc");
	if (cmdline) {
		sclkr_mode = new_sclkr_mode;
	} else {
		sclkregistask = kthread_run(sclk_register,
			(void *) (long) new_sclkr_mode, "sclkregister");
		if (IS_ERR(sclkregistask)) {
			ret = PTR_ERR(sclkregistask);
			pr_err(KERN_ERR "Failed to start sclk register thread,"
					" error: %d\n", ret);
			return ret;
		}
	}
	return ret;
}
int proc_sclkr(struct ctl_table *ctl, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret;

	ret = proc_dostring(ctl, write, buffer, lenp, ppos);
	if (write) {
		ret = sclkr_set(0);
	}
	return ret;
}
static int __init sclkr_deviat(char *str)
{
	sclk_set_deviat(simple_strtol(str, NULL, 0));
	return 0;
}
__setup("sclkd=", sclkr_deviat);
static int __init sclkr_setup(char *s)
{
	if (!s || (strcmp(s, "no") && strcmp(s, "rtc") &&
			strcmp(s, "ext") && strcmp(s, "int"))) {
		pr_err(KERN_ERR "Possible sclkr cmdline modes are:\n"
			"no, ext, rtc, int\n");
		return -EINVAL;
	}
	strncpy(sclkr_src, s, SCLKR_SRC_LEN);
	sclkr_set(1);
	return 0;
}
__setup("sclkr=", sclkr_setup);

int redpill = 1;	/* enable by defualt */
static int __init redpill_init(char *str)
{
	redpill = simple_strtol(str, NULL, 0);
	return 0;
}
__setup("redpill=", redpill_init);
