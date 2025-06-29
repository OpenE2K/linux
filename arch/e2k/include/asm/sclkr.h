/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_SCLKR_H
#define _ASM_E2K_SCLKR_H

#include <linux/clocksource.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/kthread.h>
#include <linux/pci.h>

#include <asm/cpu_regs_access.h>
#include <asm-l/l_timer.h>

#ifdef CONFIG_SCLKR_CLOCKSOURCE
extern u64 fast_syscall_read_sclkr(void);

struct prev_sclkr {
	atomic64_t res;
} ____cacheline_aligned_in_smp;
extern struct prev_sclkr prev_sclkr;

#define SCLKR_NO	0
#define SCLKR_INT	1
#define SCLKR_RTC	2
#define SCLKR_EXT	3

extern struct clocksource clocksource_sclkr;
extern long long sclkr_sched_offset;
extern int sclkr_initialized;


#define SCLKR_SRC_LEN	4
extern char sclkr_src[SCLKR_SRC_LEN];
extern int sclkr_mode;
extern int sclk_register(void *);
extern struct clocksource clocksource_sclkr;
extern int proc_sclkr(struct ctl_table *, int,
		      void __user *, size_t *, loff_t *);
extern void sclk_set_deviat(int dev);
extern u64 read_sclkr_nosync(void);
extern u64 read_sclkr(struct clocksource *cs /*unused */);
extern void prepare_sclkr_rtc_set(void);
extern void finish_sclkr_rtc_set(void);

extern struct clocksource *curr_clocksource;
extern int redpill;
extern int err_sclkr_res;
extern int num_double_pulse;
DECLARE_PER_CPU(int, num_double_pulse);
extern int bad_div_cpu[NR_CPUS];
extern int max_div_cpu, cpu_max_div, min_div_cpu, cpu_min_div;
extern u32 basic_freq_hz;
/* #define DBG_SCLKR */
#ifdef DBG_SCLKR
extern int cpu_err_sclkr, prv_cpu_err_sclkr;
extern int max_err_sclkr_res;
extern int num_err_sclkr;
extern long long err_sclkr_lo;
extern int err_sclkr_div;
#endif

#define xchg_inc_prev_sclkr_res(res) \
	__api_atomic64_fetch_xchg_if_below_or_inc(res, &prev_sclkr.res.counter, RELAXED_MB)

static __always_inline u64 sclkr2ns(u64 sclkr, u32 freq, bool sync)
{
	u64 sclkr_sec, sclkr_lo, res;
	e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();

	if (unlikely(freq < 80000000)) {
		__this_cpu_inc(num_double_pulse);
		sclkr -= (1LL << 32); /* sclkr.hi was increased by false PPS */
		if (machine.native_iset_ver > E2K_ISET_V4)
			write_SCLKR_reg_value(sclkr);
		sclkr += freq; /* sclkr.lo was set to 0 by false PPS */
		freq = basic_freq_hz;
		sclkm1.mdiv = 1;
		sclkm1.div = basic_freq_hz;
		write_SCLKM1_reg(sclkm1);
	}
	sclkr_sec = sclkr >> 32;
	sclkr_lo = ((u32) sclkr < freq) ? (u32) sclkr : (freq - 1);
	res = sclkr_sec * NSEC_PER_SEC + sclkr_lo * NSEC_PER_SEC / freq;

	/* sclkm3 has a summary time when guest was out of cpu */
	if (cpu_has(CPU_FEAT_ISET_V6) && !redpill && sclkm1.sclkm3)
		res -= read_SCLKM3_reg_value();

	if (sync && IS_ENABLED(CONFIG_SMP)) {
		u64 before = xchg_inc_prev_sclkr_res(res);
#ifdef DBG_SCLKR
		if (before > res) {
			if ((before - res) > 0) {
				err_sclkr_res = before - res;
				num_err_sclkr++;
				err_sclkr_lo += sclkr_lo;
				cpu_err_sclkr = raw_smp_processor_id();
				err_sclkr_div = freq;
				if (err_sclkr_res > max_err_sclkr_res)
					max_err_sclkr_res = err_sclkr_res;
			}
			res = before;
		}
		prv_cpu_err_sclkr = raw_smp_processor_id();
#else
		if (before > res) {
			res = before;
		}
#endif	/* DBG_SCLKR */
	}

	return res;
}

static inline bool use_sclk_sched_clock(void)
{
	return !cpu_has(CPU_FEAT_ISET_V7) && likely(sclkr_initialized);
}

static inline unsigned long long sclk_sched_clock(void)
{
	/* sched_clock() tolerates small errors and we want it
	 * to be as fast as possible, so skip syncing across CPUs */
	return sclkr_sched_offset + read_sclkr_nosync();
}
#else
static inline bool use_sclk_sched_clock(void)
{
	return false;
}

static inline unsigned long long sclk_sched_clock(void)
{
	BUG();
}
#endif /* CONFIG_SCLKR_CLOCKSOURCE */


#ifdef CONFIG_ESCLKR_CLOCKSOURCE
extern int esclkr_no;

static inline bool use_esclk_sched_clock(void)
{
	return cpu_has(CPU_FEAT_ISET_V7) && likely(!esclkr_no);
}

/*
 * Scheduler clock - returns current time in nanosec units.
 */
static inline unsigned long long esclk_sched_clock(void)
{
	u64 t_abs = read_T_ABS();

	/* esclkr_clk frequency is 100 MHz but 1 MHz for prototype
	 * but STEP is the same (=10) for same reasons */
	if (is_prototype()) {
		u64 t_off = read_T_OFF();
		return 100 * (t_abs - t_off) + t_off;
	}

	return t_abs;
}
#else
static inline bool use_esclk_sched_clock(void)
{
	return false;
}

static inline unsigned long long esclk_sched_clock(void)
{
	BUG();
}
#endif /* CONFIG_ESCLKR_CLOCKSOURCE */

#endif /* _ASM_E2K_SCLKR_H */
