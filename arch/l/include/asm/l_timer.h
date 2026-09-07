/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _L_ASM_L_TIMER_H
#define _L_ASM_L_TIMER_H

#include <linux/types.h>

/*
 * Elbrus timer
 */

extern struct clock_event_device *global_clock_event;
extern int get_lt_timer(void);
extern u32 lt_read(void);
extern struct clocksource lt_cs;

typedef	struct lt_regs {
	u32	counter_limit;		/* timer counter limit value */
	u32	counter_start;		/* start value of counter */
	u32	counter;		/* timer counter */
	u32	counter_cntr;		/* timer control register */
	u32	wd_counter;		/* watchdog counter */
	u32	wd_prescaler;		/* watchdog prescaler */
	u32	wd_limit;		/* watchdog limit */
	u32	power_counter_lo;	/* power counter low bits */
	u32	power_counter_hi;	/* power counter high bits */
	u32	wd_control;		/* watchdog control register */
	u32	reset_counter_lo;	/* reset counter low bits */
	u32	reset_counter_hi;	/* reset counter low bits */
} lt_regs_t;

typedef	struct lt_regs_eioh {
	u32	counter_limit;		/* timer counter limit value */
	u32	counter_start;		/* start value of counter */
	u32	counter;		/* timer counter */
	u32	counter_cntr;		/* timer control register */
	u32	wd_counter;		/* watchdog counter */
	u32	wd_prescaler;		/* watchdog prescaler */
	u32	wd_limit;		/* watchdog limit */
	u32	wd_control;		/* watchdog control register */
	u32	reset_counter_lo;	/* reset counter low bits */
	u32	reset_counter_hi;	/* reset counter low bits */
	u32	power_counter_lo;	/* power counter low bits */
	u32	power_counter_hi;	/* power counter high bits */
} lt_regs_eioh_t;

extern lt_regs_t *lt_regs;
extern u64 lt_clock_rate;

/* counters registers structure */
#define	LT_COUNTER_SHIFT	9	/* [30: 9] counters value */

#define	LT_WRITE_COUNTER_VALUE(count)	((count) << LT_COUNTER_SHIFT)

/* counter control register structure */
#define	LT_COUNTER_CNTR_START	0x00000001	/* start/stop timer */
#define	LT_COUNTER_CNTR_INVERTL	0x00000002	/* invert limit bit */
#define	LT_COUNTER_CNTR_LINIT	0x00000004	/* Limit bit initial state */
						/* 1 - limit bit set to 1 */

#define	LT_INVERT_COUNTER_CNTR_LAUNCH	\
		(LT_COUNTER_CNTR_START | LT_COUNTER_CNTR_INVERTL | LT_COUNTER_CNTR_LINIT)

#define WD_CLOCK_TICK_RATE 10000000L
#define WD_LIMIT_SHIFT	12
#define WD_SET_COUNTER_VAL(sek)	(WD_CLOCK_TICK_RATE * (sek))

#define	WD_ENABLE	0x2
#define	WD_EVENT	0x4

/* System timer Registers (structure see asm/l_timer_regs.h) */

#define COUNTER_LIMIT		0x00
#define COUNTER_START_VALUE	0x04
#define COUNTER_CONTROL		0x0c
#define WD_LIMIT		0x18
#define POWER_COUNTER_L		0x1c
#define POWER_COUNTER_H		0x20
#define WD_CONTROL		0x24
#define RESET_COUNTER_L		0x28
#define RESET_COUNTER_H		0x2c

#endif	/* _L_ASM_L_TIMER_H */
