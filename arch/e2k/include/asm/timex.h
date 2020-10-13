/*
 * linux/include/asm-e2k/timex.h
 *
 * E2K architecture timex specifications
 */
#ifndef _E2K_TIMEX_H_
#define _E2K_TIMEX_H_

#include <asm/e2k_api.h>

/*
 * It's important: ifndef CONFIG_E2K_MACHINE some macr. directly set
 * in linux/jiffies.h
 */

#define CLOCK_TICK_RATE_E3M	1193180
#define CLOCK_TICK_RATE_E2K_SIC	10000000

#ifdef	CONFIG_E2K_MACHINE
#if defined(CONFIG_E2K_E3M_SIM) || defined(CONFIG_E2K_E3M)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E3M	/* Underlying HZ */
#elif defined(CONFIG_E2K_E3M_IOHUB_SIM) || defined(CONFIG_E2K_E3M_IOHUB)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E2K_SIC	/* Underlying HZ */
#elif defined(CONFIG_E2K_E3S_SIM) || defined(CONFIG_E2K_E3S)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E2K_SIC	/* Underlying HZ */
#elif defined(CONFIG_E2K_ES2_DSP_SIM) || defined(CONFIG_E2K_ES2_DSP) || \
	defined(CONFIG_E2K_ES2_RU_SIM) || defined(CONFIG_E2K_ES2_RU)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E2K_SIC	/* Underlying HZ */
#elif defined(CONFIG_E2K_E2S_SIM) || defined(CONFIG_E2K_E2S)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E2K_SIC	/* Underlying HZ */
#elif defined(CONFIG_E2K_E8C_SIM) || defined(CONFIG_E2K_E8C)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E2K_SIC	/* Underlying HZ */
#elif defined(CONFIG_E2K_E8C2_SIM) || defined(CONFIG_E2K_E8C2)
#define CLOCK_TICK_RATE		CLOCK_TICK_RATE_E2K_SIC	/* Underlying HZ */
#else
#    error "E2K MACHINE type does not defined"
#endif
#else	/* ! CONFIG_E2K_MACHINE */
extern unsigned int CLOCK_TICK_RATE;
#endif /* CONFIG_E2K_MACHINE */

extern long pit_time_init(void);
	
typedef unsigned long cycles_t;

#ifdef CONFIG_LATENCY_TIMING
 #define mach_cycles_to_usecs(d) (d)
 #define mach_usecs_to_cycles(d) (d)
#endif

#define ARCH_HAS_READ_CURRENT_TIMER

static inline cycles_t get_cycles(void)
{
	return E2K_GET_DSREG(clkr);
}
#define	UNSET_CPU_FREQ	((u32)(-1))
extern u32 cpu_freq_hz;

static inline long long cycles_2nsec(cycles_t cycles)
{
	return cycles * 1000 / (cpu_freq_hz / 1000000);
}

static inline long long cycles_2usec(cycles_t cycles)
{
	return cycles * 1000 / (cpu_freq_hz / 1000);
}

static inline cycles_t usecs_2cycles(long long usecs)
{
	return usecs * cpu_freq_hz / 1000000;
}

static inline cycles_t get_cycles_rate(void)
{
	return (cycles_t)cpu_freq_hz;
}

#endif /* _E2K_TIMEX_H_ */
