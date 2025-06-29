/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _KVM_L_TIMER_REGS_H
#define _KVM_L_TIMER_REGS_H

#include <linux/types.h>

/*
 * Elbrus System timer Registers
 */

#define COUNTER_LIMIT		0x00
typedef union counter_limit {
	u32	reg;
	struct {			/* as fields	*/
		u32	unused	: 9;	/* [8:0]	*/
		u32	c_l	: 22;	/* [30:9]	*/
		u32	l	: 1;	/* [31]		*/
	};
} counter_limit_t;

#define COUNTER_START_VALUE	0x04
typedef union counter_start {
	u32	reg;
	struct {			/* as fields	*/
		u32	unused	: 9;	/* [8:0]	*/
		u32	c_st_v	: 22;	/* [30:9]	*/
		u32	l	: 1;	/* [31]		*/
	};
} counter_start_t;

#define COUNTER			0x08
typedef union counter {
	u32	reg;
	struct {			/* as fields	*/
		u32	unused	: 9;	/* [8:0]	*/
		u32	c	: 22;	/* [30:9]	*/
		u32	l	: 1;	/* [31]		*/
	};
} counter_t;
#define	MAX_SYS_TIMER_COUNT	0x3fffff	/* [30: 9] : 22 bits */
#define	MIN_SYS_TIMER_COUNT	0x000001

#define COUNTER_CONTROL		0x0c
typedef union counter_control {
	u32	reg;
	struct {			/* as fields */
		u32	s_s	: 1;	/* [0] */
		u32	inv_l	: 1;	/* [1] */
		u32	l_ini	: 1;	/* [2] */
		u32	unused	: 29;	/* [31:3] */
	};
} counter_control_t;

#define WD_COUNTER		0x10
typedef	union wd_counter_l {
	u32	reg;
	struct {			/* as fields */
		u32	wd_c	: 32;	/* [31:0] */
	};
} wd_counter_l_t;

#define WD_PRESCALER		0x14
typedef	union wd_counter_h {
	u32	reg;
	struct {			/* as fields */
		u32	wd_c	: 32;	/* [31:0] */
	};
} wd_counter_h_t;

#define WD_LIMIT		0x18
typedef	union wd_limit {
	u32	reg;
	struct {			/* as fields */
		u32	wd_l	: 32;	/* [31:0] */
	};
} wd_limit_t;

#undef	WD_CONTROL
#define WD_CONTROL		0x1c
typedef union wd_control {
	u32	reg;
	struct {			/* as fields */
		u32	w_m	: 1;	/* [0] */
		u32	w_out_e	: 1;	/* [1] */
		u32	w_evn	: 1;	/* [2] */
		u32	unused	: 29;	/* [31:3] */
	};
} wd_control_t;

#undef	RESET_COUNTER_L
#define RESET_COUNTER_L		0x20
typedef	union reset_counter_l {
	u32	reg;
	struct {			/* as fields */
		u32	rs_c	: 32;	/* [31:0] */
	};
} reset_counter_l_t;

#undef	RESET_COUNTER_H
#define RESET_COUNTER_H		0x24
typedef	union reset_counter_h {
	u32	reg;
	struct {			/* as fields */
		u32	rs_c	: 32;	/* [31:0] */
	};
} reset_counter_h_t;
#define	RESET_COUNTER		RESET_COUNTER_L

#undef	POWER_COUNTER_L
#define POWER_COUNTER_L		0x28
typedef	union power_counter_l {
	u32	reg;
	struct {			/* as fields */
		u32	pw_c	: 32;	/* [31:0] */
	};
} power_counter_l_t;

#undef	POWER_COUNTER_H
#define POWER_COUNTER_H		0x2c
typedef	union power_counter_h {
	u32	reg;
	struct {			/* as fields */
		u32	pw_c	: 32;	/* [31:0] */
	};
} power_counter_h_t;
#define	POWER_COUNTER		POWER_COUNTER_L

#define	LT_MMIO_LENGTH		(POWER_COUNTER_H + 4)

typedef enum lt_irq_map {
	SYS_TIMER_IRQ_ID	=  2,
	WD_TIMER_IRQ_ID		= 20,
} lt_irq_map_t;

#endif	/* _KVM_L_TIMER_REGS_H */
