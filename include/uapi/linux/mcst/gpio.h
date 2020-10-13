/*
 * include/linux/mcst/gpio.h
 *
 * Copyright (C) 2014 MCST
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __MCST_GPIO_H_
#define __MCST_GPIO_H_

#define GPIO_DRV_VER	102
#define	GPIOC				('G' << 8)
#define	GPIO_WAIT_INTR			(GPIOC | 1)
typedef struct gpio_intr_inf {
	int		gpio_drv_ver;
	/* limit time wating for interrupt (mcs) */
	int		timeout_us;
	/* do posppone next tick timer interrupt after indicated nanoseconds */
	int		postpone_tick_ns;
	/* may wait on cpu (mcs) */
	int		may_on_cpu;
	/* expected period of interrupts*/
	long long	period_ns;
	/* number of got interrupts by driver */
	int		num_received_ints;
	/* was waiting on cpu nsecs */
	long long	was_oncpu_ns;
	/* was waiting in sched nsecs */
	long long	was_waiting_ns;
	/* ns timeofday when interrupt was got by driver */
	long long	intr_driver_nsec;
	/* ns timeofday when previous interrupt was got by driver */
	long long	prev_driver_nsec;
	/* ns timeofday when user thread have got cpu */
	long long	woken_nsec;
} gpio_intr_inf_t;

#endif
