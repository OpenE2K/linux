/*
 * linux/include/asm-e2k/timex.h
 *
 * E2K architecture timex specifications
 */
#ifndef _E2K_TIMEX_H_
#define _E2K_TIMEX_H_

#include <asm/e2k_api.h>

/* Note that this is lt_timer tick rate. */
#define CLOCK_TICK_RATE	(machine.clock_tick_rate)

typedef unsigned long cycles_t;

#define ARCH_HAS_READ_CURRENT_TIMER
static inline cycles_t get_cycles(void)
{
	return NATIVE_READ_CLKR_REG_VALUE();
}
#define	UNSET_CPU_FREQ	((u32)(-1))
extern u32 cpu_freq_hz;
extern u64 cpu_clock_psec;	/* number of pikoseconds in one CPU clock */

static inline long long cycles_2_psec(cycles_t cycles)
{
	return cycles * cpu_clock_psec;
}

static inline long long cycles_2nsec(cycles_t cycles)
{
	return cycles_2_psec(cycles) / 1000;
}

static inline long long cycles_2usec(cycles_t cycles)
{
	return cycles_2_psec(cycles) / 1000000;
}

static inline cycles_t psecs_2_cycles(long long psecs)
{
	return psecs / cpu_clock_psec;
}

static inline cycles_t nsecs_2cycles(long long nsecs)
{
	return psecs_2_cycles(nsecs * 1000);
}

static inline cycles_t usecs_2cycles(long long usecs)
{
	return psecs_2_cycles(usecs * 1000000);
}

static inline cycles_t get_cycles_rate(void)
{
	return (cycles_t)cpu_freq_hz;
}

extern void __init native_time_init(void);
extern int native_read_current_timer(unsigned long *timer_val);

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized guest and host kernel */
#include <asm/paravirt/timex.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/timex.h>
#else	/* native kernel or native kernel with virtualization support */
static inline void time_init(void)
{
	native_time_init();
}
static inline int read_current_timer(unsigned long *timer_val)
{
	return native_read_current_timer(timer_val);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* _E2K_TIMEX_H_ */
