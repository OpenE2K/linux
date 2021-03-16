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

/* New timer registers */
#define PIT_COUNTER_LIMIT	0x00
#define PIT_COUNTER_START_VALUE	0x04
#define PIT_COUNTER		0x08
#define PIT_COUNTER_CONTROL	0x0c
#define PIT_WD_COUNTER		0x10
#define PIT_WD_COUNTER_LOW	PIT_WD_COUNTER
#define PIT_WD_COUNTER_HIGH	(PIT_WD_COUNTER_LOW + 0x04)
#define PIT_WD_LIMIT		0x18
#define PIT_POWER_COUNTER	0x1c
#define PIT_POWER_COUNTER_LOW	PIT_POWER_COUNTER
#define PIT_POWER_COUNTER_HIGH	(PIT_POWER_COUNTER_LOW + 0x04)
#define PIT_WD_CONTROL		0x24
#define PIT_RESET_COUNTER	0x28
#define PIT_RESET_COUNTER_LOW	PIT_RESET_COUNTER
#define PIT_RESET_COUNTER_HIGH	(PIT_RESET_COUNTER_LOW + 0x04)

typedef	struct lt_regs {
	u32	counter_limit;	/* timer counter limit value */
	u32	counter_start;	/* start value of counter */
	u32	counter;	/* timer counter */
	u32	counter_cntr;	/* timer control register */
	u32	wd_counter;		/* watchdog counter */
	u32	wd_prescaler;		/* watchdog prescaler */
	u32	wd_limit;		/* watchdog limit */
	u32	power_counter_lo;	/* power counter low bits */
	u32	power_counter_hi;	/* power counter high bits */
	u32	wd_control;		/* watchdog control register */
	u32	reset_counter_lo;	/* reset counter low bits */
	u32	reset_counter_hi;	/* reset counter low bits */
} lt_regs_t;

extern unsigned long long	lt_phys_base;
extern lt_regs_t		*lt_regs;

extern void setup_lt_timer(void);
extern int __init init_lt_clocksource(void);

/* counters registers structure */
#define	LT_COUNTER_SHIFT	9	/* [30: 9] counters value */
#define	LT_COUNTER_LIMIT_SHIFT	31	/* [31] Limit bit */
#define	LT_COUNTER_LIMIT_BIT	(1 << LT_COUNTER_LIMIT_SHIFT)

#define	LT_WRITE_COUNTER_VALUE(count)	((count) << LT_COUNTER_SHIFT)
#define	LT_READ_COUNTER_VALUE(count)	((count) >> LT_COUNTER_SHIFT)
#define	LT_NSEC_PER_COUNTER_INCR	100	/* 10 MHz == 100 nunosec */

/* counter control register structure */
#define	LT_COUNTER_CNTR_START	0x00000001	/* start/stop timer */
#define	LT_COUNTER_CNTR_INVERTL	0x00000002	/* invert limit bit */
#define	LT_COUNTER_CNTR_LINIT	0x00000004	/* Limit bit initial state */
						/* 1 - limit bit set to 1 */

#define	LT_COUNTER_CNTR_LAUNCH	(LT_COUNTER_CNTR_START)
#define	LT_INVERT_COUNTER_CNTR_LAUNCH	(LT_COUNTER_CNTR_LAUNCH | \
						LT_COUNTER_CNTR_INVERTL | \
						LT_COUNTER_CNTR_LINIT)
#define	LT_COUNTER_CNTR_STOP	(0)

#define WD_CLOCK_TICK_RATE 10000000L
#define WD_LATCH(tick_rate) (((tick_rate) + HZ/2) / HZ)
#define WD_LIMIT_SHIFT	12
#define	WD_WRITE_COUNTER_VALUE(count) (count)
#define	WD_READ_COUNTER_VALUE(count) ((count) << WD_LIMIT_SHIFT)
#define WD_SET_COUNTER_VAL(sek)	\
		(WD_WRITE_COUNTER_VALUE(WD_CLOCK_TICK_RATE * (sek)))

#define	WD_INTR_MODE	0x1
#define	WD_ENABLE	0x2
#define	WD_EVENT	0x4

#define WD_COUNTER_BASE	0x10

/* System timer Registers (structure see asm/l_timer_regs.h) */

#define COUNTER_LIMIT		0x00
#define COUNTER_START_VALUE	0x04
#define L_COUNTER		0x08
#define COUNTER_CONTROL		0x0c
#define WD_COUNTER_L		0x10
#define WD_COUNTER_H		0x14
#define WD_LIMIT		0x18
#define POWER_COUNTER_L		0x1c
#define POWER_COUNTER_H		0x20
#define WD_CONTROL		0x24
#define RESET_COUNTER_L		0x28
#define RESET_COUNTER_H		0x2c

#endif	/* _L_ASM_L_TIMER_H */
