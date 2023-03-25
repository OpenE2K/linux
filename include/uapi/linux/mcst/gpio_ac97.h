/*
 * Copyright (C) 1997, by MCST.
 */

#ifndef	_GPIO_AC97_VAR_H
#define	_GPIO_AC97_VAR_H

/*
 * Definition of relationship between dev_t and interrupt numbers
 * instance, #intr, in/out  <=> minor
 */
#include <linux/ioctl.h>

#define LINES_NUM	8
#define LINES_MASK	((1 << LINES_NUM) - 1)

#define MAGIC_NUMBER 240

#define IOCTL_GPIO_GET_STATUS		_IO( MAGIC_NUMBER, 2)
#define IOCTL_GPIO_SET_STATUS		_IO( MAGIC_NUMBER, 3)
#define IOCTL_GPIO_WAIT_INTERRUPT	_IO( MAGIC_NUMBER, 4)

typedef struct gpio_status {
	unsigned gpio_ctrl;	/* 00 set direction 0-3 -> 4-7 bit register */
	unsigned gpio_data;	/* 04 regiser data   0-7 bit	*/
	unsigned gpio_int_cls;	/* 08 int ctrl			*/
	unsigned gpio_int_lvl;	/* 0c				*/
	unsigned gpio_int_en;	/* 10 interrupt enable		*/
	unsigned gpio_int_sts;
} gpio_status_t;

/*
gpio_ctrl: control register
		1 - corresponding pin is for output, 0 - for input;
		offset 0x0; RW

gpio_data:   data register; contains data to transfer for output, or
		pin status for input;
		offset 0x4; RW (bits for output) / RO (bits for input)

gpio_int_cls: interruption source: 0 - level, 1 - front
		offset 0x8; RW

gpio_int_lvl:	0 - interrupt from low  level or negative front
		1 - interrupt from high level or positive front;
		offset 0xc; RW

gpio_int_en: interrupt enable register
		0 - disabled
		1 - enabled
		offset 0x10; RW

gpio_int_sts: interrupt status register;
		offset 0x14; register RWC (clear on writing 1)
*/

typedef struct wait_int {
	unsigned int pin;	/* line number to wait interrupt from */
	unsigned int timeout;	/* timeout in milliseconds */
	unsigned int disable;	/* disable interrupt on the first arrival */
} wait_int_t;

#ifdef __KERNEL__

#define DEV_NAME		"gpio_as97"
#define GPIO_DSBL_INT		1
/*
 * driver state per instance
 */
typedef struct gpio_state {
	unsigned long start_io;	/*  start of I/O port area */
	unsigned long end_io;	/*    end of I/O port area */
	unsigned long len_io;	/* length of I/O port area */
	struct semaphore mux;	/* open/close mutex        */
	wait_queue_head_t pollhead[LINES_NUM];
	unsigned line_st[LINES_NUM];
	unsigned int major;
	struct pci_dev *dev;	/* pointer to structure with PCI-device data */
	char revision_id;
} gpio_state_t;

#endif				/* __KERNEL__ */

#endif				/* _GPIO_AC97_VAR_H */
