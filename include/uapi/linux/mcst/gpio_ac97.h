
/*
 * Copyright (c) 1997, by MCST.
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
	unsigned gpio_ctrl;	// 00 set direction 0-3 -> 4-7 bit register
	unsigned gpio_data;	// 04 regiser data   0-7 bit
	unsigned gpio_int_cls;	// 08 int ctrl
	unsigned gpio_int_lvl;	// 0с
	unsigned gpio_int_en;	// 10 interrupt enable
	unsigned gpio_int_sts;
} gpio_status_t;

/*
gpio_cotrol: регистр управления
               1 - соответствующий вывод является выходом, 0 - входом,
               относительный адрес 0x0; регистр RW

gpio_data:   регистр данных; для выходов содержит данные, которые надо          
               передать, для входов - состояние пинов;
               относительный адрес 0x4; биты, соответствующие выходам RW,       
             входам - RO

gpio_int_cls: регистр источника прерываний, 0 - уровень, 1 - фронт
               относительный адрес 0x8; регистр RW

gpio_int_lvl: 0 - прерывание от низкого уровня или отрицательного фронта
                1 - прерывание от высокого уровня или положительного
                фронта; относительный адрес 0xС; регистр RW

gpio_int_en: регистр разрешения прерываний
               0 - запрещено
               1 - разрешено
               относительный адрес 0x10; регистр RW

gpio_int_sts: регистр статуса прерываний;
                относительный адрес 0x14; регистр RWC (сбрасывается
                записью единицы)
*/

typedef struct wait_int {
	unsigned pin;		/*номер линии с которой ожидать прерывание */
	unsigned timeout;	/*в микросекундах */
	unsigned disable;	/*запрещать ли прерывание по первому срабатыванию */
} wait_int_t;

#ifdef __KERNEL__

#define DEV_NAME		"gpio_as97"
#define GPIO_DSBL_INT		1
/*
 * driver state per instance
 */
typedef struct gpio_state {
	unsigned long start_io;	/* начало области портов ввода/вывода */
	unsigned long end_io;	/* конец области портов ввода/вывода */
	unsigned long len_io;	/* длина области портов ввода/вывода */
	struct semaphore mux;	/* open/close mutex     */
	wait_queue_head_t pollhead[LINES_NUM];
	unsigned line_st[LINES_NUM];
	unsigned int major;
	struct pci_dev *dev;	/* указатель на структуру с PCI-данными устройства */
	char revision_id;
} gpio_state_t;

#endif				/* __KERNEL__ */

#endif				/* _GPIO_AC97_VAR_H */
