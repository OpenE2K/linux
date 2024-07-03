/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __L_ASM_SPI_H__
#define __L_ASM_SPI_H__

#include <asm-l/iolinkmask.h>
#include <linux/i2c.h>

/* PCI registers definitions for reset */

#define	PCI_RESET_CONTROL		0x60
#define	L_SOFTWARE_RESET_TO_HARD	0x00000004	/* software reset */
							/* to hardware reset */
#define	L_WATCHDOG_RESET_TO_HARD	0x00000008	/* watchdog reset */
							/* to hardware reset */
#define	L_SOFTWARE_RESET_TO_SOFT	0x00000010	/* software reset */
							/* to soft reset */
#define	L_WATCHDOG_RESET_TO_SOFT	0x00000020	/* watchdog reset */
							/* to soft reset */
#define	L_RED_RESET_OUT			0x80000080	/* Led control */
#define	PCI_SOFT_RESET_CONTROL		0x64
#define	L_SOFTWARE_RESET		0x00000001
#define	L_SOFTWARE_RESET_DONE		0x00000002
#define	L_LAST_RESET_INFO		0x000000fc	/* last reset type */
#define L_LAST_RESET_INFO_TYPE_LWDT	0x00000008	/* last reset type - lwdt */
#define	PCI_SOFT_RESET_DURATION		0x68
#define	L_IOHUB_SOFT_RESET_DURATION	0x0000ffff
#define	L_IOHUB2_SOFT_RESET_DURATION	0x00ffffff
#define	L_EIOHUB_SOFT_RESET_DURATION	(250e+6 * 20e-3) /* 20ms at 250 MHz */

/* Common SPI & I2C definitions */

#define I2C_SPI_CNTRL_AREA_SIZE		0x40
#define I2C_SPI_DATA_AREA_SIZE		0x40

#define	I2C_SPI_DEFAULT_IRQ		23

#define I2C_MAX_BUSSES			5
#define I2C_DST_BUSSES			4

#ifdef CONFIG_E2K
extern int iohub_i2c_line_id;
#else
#define iohub_i2c_line_id	0
#endif
#endif /* __L_ASM_SPI_H__ */
