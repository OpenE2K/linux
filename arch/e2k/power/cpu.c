/*
 * Suspend support specific for e2k.
 *
 * Distribute under GPLv2
 *
 * Copyright (c) 2011 Evgeny M. Kravtsunov <kravtsunov_e@mcst.ru>
 */

#include <linux/suspend.h>
#include <linux/smp.h>

void save_processor_state(void)
{
	printk("save_processor_state() started\n");
}
EXPORT_SYMBOL(save_processor_state);

void restore_processor_state(void)
{
	printk("restore_processor_state() started\n");
}
EXPORT_SYMBOL(restore_processor_state);
