#ifndef _ASM_TIMER_H
#define _ASM_TIMER_H

#include <linux/types.h>
#include <linux/clockchips.h>

#define TICK_SIZE (tick_nsec / 1000)

extern bool disable_apic_timer;
extern bool disable_epic_timer;

#endif
