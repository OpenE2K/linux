#ifndef _ASM_TIMER_H
#define _ASM_TIMER_H

#include <linux/types.h>
#include <linux/clockchips.h>

#define TICK_SIZE (tick_nsec / 1000)

/* Modifiers for buggy PIT handling */

extern int pit_latch_buggy;

extern int timer_source;
extern int lt_timer_source(void);

#ifdef CONFIG_MCST_RT
#define DINTR_TIMER_UNITS "nsec"
extern int mcst_rt_timer_start(void);
extern int mcst_rt_timer_stop(void);
#endif

#endif
