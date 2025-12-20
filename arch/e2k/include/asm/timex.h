/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * linux/include/asm-e2k/timex.h
 *
 * E2K architecture timex specifications
 */
#ifndef _E2K_TIMEX_H_
#define _E2K_TIMEX_H_

#include <linux/init.h>

#include <asm/e2k_api.h>
#include <asm/native_cpu_regs_access.h>

typedef unsigned long cycles_t;

#define ARCH_HAS_READ_CURRENT_TIMER
static inline cycles_t get_cycles(void)
{
	return NATIVE_READ_CLKR_REG_VALUE();
}
#define get_cycles get_cycles

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

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/timex.h>
#else	/* native kernel without or with virtualization support */
static inline void time_init(void)
{
	native_time_init();
}
static inline int read_current_timer(unsigned long *timer_val)
{
	return native_read_current_timer(timer_val);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* _E2K_TIMEX_H_ */
