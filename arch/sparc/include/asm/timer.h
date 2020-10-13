#ifndef ___ASM_SPARC_TIMER_H
#define ___ASM_SPARC_TIMER_H

#ifdef CONFIG_MCST_RT

#include <asm-l/l_timer.h>

#define DINTR_TIMER_UNITS "nsec"
static inline int mcst_rt_timer_start(void) { return mcst_rt_lt_start(); }
static inline int mcst_rt_timer_stop(void) { return mcst_rt_lt_stop();}
#else /* CONFIG_MCST_RT */

#if defined(__sparc__) && defined(__arch64__)
#include <asm/timer_64.h>
#else
#include <asm/timer_32.h>
#endif
#endif /* CONFIG_MCST_RT */
#endif
