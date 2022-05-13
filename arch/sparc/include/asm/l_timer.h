#ifndef _ASM_L_TIMER_H
#define _ASM_L_TIMER_H

#include <asm/l_timer_regs.h>

#ifdef	CONFIG_E90S
#define	L_TIMER_IS_ALLOWED()	1	/* E90S use this timer */
#else
#define	L_TIMER_IS_ALLOWED()	0	/* other sparc64 machine not use */
#endif	/* CONFIG_E90S */

#define	SET_CLOCK_TICK_RATE()	/* clock rate not set dinamicaly */

#include <asm-l/l_timer.h>

#endif	/* _ASM_L_TIMER_H */
