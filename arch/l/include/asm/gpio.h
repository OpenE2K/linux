/*
 * arch/l/include/gpio.h
 *
 * Copyright (C) 2012 Evgeny Kravtsunov 
 *
 * AC97-GPIO Controller (part of Elbrus IOHUB).
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __ASM_ARCH_GPIO_H_
#define __ASM_ARCH_GPIO_H_

#include <linux/kernel.h>

/* IOHUB GPIO pins */
#define IOUHB_GPIO_0		0
#define IOHUB_GPIO_1		1
#define IOHUB_GPIO_2		2
#define IOHUB_GPIO_3		3
#define IOHUB_GPIO_4		4
#define IOHUB_GPIO_5		5
#define IOHUB_GPIO_6		6
#define IOHUB_GPIO_7		7
#define IOHUB_GPIO_8		8
#define IOHUB_GPIO_9		9
#define IOHUB_GPIO_10		10
#define IOHUB_GPIO_11		11
#define IOHUB_GPIO_12		12
#define IOHUB_GPIO_13		13
#define IOHUB_GPIO_14		14
#define IOHUB_GPIO_15		15

/* Amount of iohub's own gpios: */
#define ARCH_NR_IOHUB_GPIOS       16
#define ARCH_NR_IOHUB2_GPIOS       32
#define ARCH_MAX_NR_OWN_GPIOS	ARCH_NR_IOHUB2_GPIOS

#if IS_ENABLED(CONFIG_INPUT_LTC2954)
#define LTC2954_IRQ_GPIO_PIN	IOHUB_GPIO_3
#define LTC2954_KILL_GPIO_PIN	IOHUB_GPIO_4
#endif /* CONFIG_INPUT_LTC2954 */

#ifdef CONFIG_GPIOLIB
#include <asm-generic/gpio.h>
#endif /* CONFIG_GPIOLIB */

#endif
