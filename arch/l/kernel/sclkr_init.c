/*
 * arch/e2k/kernel/sclkr.c
 *
 * This file contains implementation of sclkr clocksource.
 *
 * Copyright (C) 2011 Pavel V. Panteleev (panteleev_p@mcst.ru)
 */

/* includes */
#include <linux/kthread.h>
#include <linux/clocksource.h>
#include <asm/bootinfo.h>

static int __init sclkr_init(void)
{
	static struct task_struct *sclkregistask;
	int ret;
#ifdef CONFIG_E2K
	/* SCLKR should be used on systems that support it */
	if (machine.iset_ver < E2K_ISET_V3)
#endif
		return 0;

	clocksource_sclkr.mult = (1 << clocksource_sclkr.shift) * 1000;
	if (!strcmp(sclkr_src, "ext")) /* if real external PPS is there */
		sclkregistask = kthread_run(sclk_register, sclkr_src,
			"sclkregister");
		if (IS_ERR(sclkregistask)) {
			ret = PTR_ERR(sclkregistask);
			pr_err(KERN_ERR "Failed to start sclk register thread,"
					"error: %d\n", ret);
			return ret;
		}
		pr_warning("External signal is used for SCLKR.\n");
	/* else we will register it when RTC (fm33256) will supply 1 Hz */
	return 0;
}
arch_initcall(sclkr_init);
