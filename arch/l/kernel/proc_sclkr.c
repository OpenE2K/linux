/*
 * arch/l/kernel/proc_sclkr.c
 *
 * This file contains support for of sclkr clocksource.
 *
 * Copyright (C) 2015 Leonid Ananiev (leoan@mcst.ru)
 */

#include <linux/clocksource.h>
#include <linux/kthread.h>
int proc_sclkr(struct ctl_table *ctl, int write,
		void __user *buffer, size_t *lenp,
		loff_t *ppos)
{
	int ret;
	static struct task_struct *sclkregistask;

	ret = proc_dostring(ctl, write, buffer, lenp, ppos);
	if (write) {
		if (!strcmp(sclkr_src, "no")) {
			clocksource_unregister(&clocksource_sclkr);
			return 0;
		}
		sclkregistask = kthread_run(sclk_register, sclkr_src,
			"sclkregister");
		if (IS_ERR(sclkregistask)) {
			ret = PTR_ERR(sclkregistask);
			pr_err(KERN_ERR "Failed to start sclk register thread,"
					"error: %d\n", ret);
			return ret;
		}
	}
	return ret;
}

static int __init sclkr_setup(char *s)
{
	if (!s || strcmp(s, "no") || strcmp(s, "rtc") || strcmp(s, "ext"))
		return -EINVAL;
	strncpy(sclkr_src, s, SCLKR_SRC_LEN);
	return 0;
}
__setup("sclkr=", sclkr_setup);

