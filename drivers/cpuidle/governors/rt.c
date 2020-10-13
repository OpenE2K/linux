/*
 * rt.c - the real time cpuidle governor (always selects 0)
 *
 *  Copyright (C) 2013 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 * This code is licenced under the GPL.
 */

#include <linux/kernel.h>
#include <linux/cpuidle.h>
#include <linux/module.h>
#include <linux/moduleparam.h>

/**
 * rt_select_state - selects the next state to enter, it will be 0 :)
 * @dev: the CPU
 */
static int rt_select_state(struct cpuidle_driver *drv,
			   struct cpuidle_device *dev)
{
	return 0;
}

/**
 * rt_enable_device - setup for the governor, do nothing.
 * @dev: the CPU
 */
static int rt_enable_device(struct cpuidle_driver *drv,
			    struct cpuidle_device *dev)
{
	return 0;
}

static struct cpuidle_governor rt_governor = {
	.name =		"rt",
	.rating =	30,
	.enable =	rt_enable_device,
	.select =	rt_select_state,
	.owner =	THIS_MODULE,
};

/**
 * init_rt - initializes the governor
 */
static int __init init_rt(void)
{
	return cpuidle_register_governor(&rt_governor);
}

postcore_initcall(init_rt);
