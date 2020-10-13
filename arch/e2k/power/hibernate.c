/*
 * Hibernation support specific for e2k
 *
 * Distribute under GPLv2
 *
 * Copyright (c) 2011 Evgeny M. Kravtsunov <kravtsunov_e@mcst.ru>
 */

#include <linux/suspend.h>
#include <linux/bootmem.h>

int swsusp_arch_suspend(void)
{
	printk("swsusp_arch_suspend() started\n");
	swsusp_save();
	return 0;
}

int swsusp_arch_resume(void)
{
	printk("swsusp_arch_resume() started\n");
	return 0;
}
