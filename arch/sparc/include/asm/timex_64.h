/*
 * linux/include/asm/timex.h
 *
 * sparc64 architecture timex specifications
 */
#ifndef _ASMsparc64_TIMEX_H
#define _ASMsparc64_TIMEX_H

#include <asm/timer.h>
#include <asm/cpudata_64.h>

#ifdef CONFIG_E90S

#define CLOCK_TICK_RATE 10000000
/* Getting on the cycle counter on sparc64. */
typedef unsigned long cycles_t;
#define ARCH_HAS_READ_CURRENT_TIMER
#define TICK_PRIV_BIT	(1UL << 63)
static inline cycles_t get_cycles (void)
{
	unsigned long ret;
	__asm__ __volatile__("rd	%%tick, %0"
				: "=r" (ret));
	return ret;

}

extern u32 cpu_freq_hz;
#define	UNSET_CPU_FREQ	((u32)(-1))
static inline cycles_t get_cycles_rate(void)
{
	return (cycles_t)local_cpu_data().clock_tick;
}
static inline long long cycles_2nsec(long long cycles)
{
	return cycles * 1000 / (local_cpu_data().clock_tick / 1000000);
}
static inline long long cycles_2usec(long long cycles)
{
	return cycles * 1000 / (local_cpu_data().clock_tick / 1000);
}
static inline cycles_t usecs_2cycles(long long usecs)
{
	return usecs * (local_cpu_data().clock_tick / 1000) / 1000;
}

#else	/*CONFIG_E90S*/
#define CLOCK_TICK_RATE	1193180 /* Underlying HZ */

/* Getting on the cycle counter on sparc64. */
typedef unsigned long cycles_t;
#define get_cycles()	tick_ops->get_tick()

#define ARCH_HAS_READ_CURRENT_TIMER
#endif	/*CONFIG_E90S*/

#endif
