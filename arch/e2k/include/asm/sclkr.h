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
#include <linux/rtc.h>
#include <linux/seq_file.h>

#include <asm/cpu_regs_access.h>
#include <asm-l/l_timer.h>

#ifdef CONFIG_SCLKR_CLOCKSOURCE
extern u64 fast_syscall_read_sclkr(void);

struct prev_sclkr {
	atomic64_t res;
} ____cacheline_aligned_in_smp;
extern struct prev_sclkr prev_sclkr;

enum sclkr_mode {
	SCLKR_UNINITIALIZED = -1,
	SCLKR_NO = 0,
	SCLKR_INT = 1,
	SCLKR_RTC = 2,
	SCLKR_EXT = 3,
};

static inline const char *sclkr_mode_name(enum sclkr_mode mode)
{
	switch (mode) {
	case SCLKR_INT:
		return "int";
	case SCLKR_RTC:
		return "rtc";
	case SCLKR_EXT:
		return "ext";
	default:
		return "no";
	}
}

extern struct mutex sclkr_lock;

extern struct clocksource clocksource_sclkr;
extern bool sclkr_initialized;
extern unsigned long long unset_sclkr_ext;
extern struct rtc_device *clk_rtc;

#define SCLKR_CMD_LEN	4
extern char proc_sclkr_cmd[SCLKR_CMD_LEN];
extern enum sclkr_mode sclkr_mode_cmdline;
extern enum sclkr_mode sclkr_mode;
extern int sclk_register(enum sclkr_mode);

extern int sclk_register_rtc(void);
extern void sclk_unregister_rtc(void);

extern struct clocksource clocksource_sclkr;
extern int proc_sclkr(struct ctl_table *, int,
		      void __user *, size_t *, loff_t *);
extern void sclk_set_deviat(unsigned long dev);
extern u64 read_sclkr_noirq(void);
extern u64 read_sclkr(struct clocksource *cs /*unused */);

extern struct clocksource *curr_clocksource;
DECLARE_PER_CPU(int, num_double_pulse);
DECLARE_PER_CPU(int, bad_div);
extern u32 basic_freq_hz;
/* #define DBG_SCLKR */
#ifdef DBG_SCLKR
extern int cpu_err_sclkr, prv_cpu_err_sclkr;
extern int err_sclkr_res, max_err_sclkr_res;
extern int num_err_sclkr;
extern long long err_sclkr_lo;
extern int err_sclkr_div;
#endif

#define xchg_inc_prev_sclkr_res(res) \
	__api_atomic64_fetch_xchg_if_below_or_inc(res, &prev_sclkr.res.counter, RELAXED_MB)

static __always_inline u64 sclkr2ns(e2k_sclkr_t sclkr, e2k_sclkm1_t sclkm1)
{
	u64 sclkr_sec, sclkr_lo, res, unset = unset_sclkr_ext;
	u32 freq = sclkm1.div + 1;

	if (unlikely(freq < 3 * basic_freq_hz / 4)) {
		__this_cpu_inc(num_double_pulse);
		__this_cpu_write(bad_div, freq);
		sclkr.hi -= 1; /* was increased by false PPS */
		if (machine.native_iset_ver > E2K_ISET_V4)
			write_SCLKR_reg(sclkr);
		sclkr.lo += freq; /* was set to 0 by false PPS */
		freq = basic_freq_hz;
		sclkm1.mdiv = 1;
		sclkm1.div = basic_freq_hz;
		write_SCLKM1_reg(sclkm1);
	}
	sclkr_sec = sclkr.hi;
	sclkr_lo = (sclkr.lo < freq) ? sclkr.lo : (freq - 1);
	res = sclkr_sec * NSEC_PER_SEC + sclkr_lo * NSEC_PER_SEC / freq;

	if (IS_ENABLED(CONFIG_SMP)) {
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

	/* See comment before prepare_sclkr_rtc_set() */
	if (unlikely(!unset && !IS_HV_GM() &&
		     sclkr_mode > SCLKR_INT && !sclkm1.mode && !sclkm1.sw))
		unset_sclkr_ext = res;

	return res;
}

static inline bool use_sclk_sched_clock(void)
{
	/* Pairs with smp_wmb() in sclk_register() */
	return !cpu_has(CPU_FEAT_ISET_V7) && likely(READ_ONCE(sclkr_initialized));
}

static inline unsigned long long sclk_sched_clock(void)
{
	return read_sclkr_noirq();
}

extern bool sclk_uses_hardware_rtc(void);
extern void cpuinfo_sclk(struct seq_file *);

extern u32 __init sclkr_get_frequency(void);
#else
static inline bool use_sclk_sched_clock(void)
{
	return false;
}

static inline unsigned long long sclk_sched_clock(void)
{
	BUG();
}

static inline bool sclk_uses_hardware_rtc(void)
{
	return false;
}

static inline void cpuinfo_sclk(struct seq_file *m) { }
#endif /* CONFIG_SCLKR_CLOCKSOURCE */

#ifdef CONFIG_ESCLKR_CLOCKSOURCE
extern bool esclk_initialized;

static inline bool use_esclk_sched_clock(void)
{
	return esclk_initialized;
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

extern void cpuinfo_esclk(struct seq_file *);
#else
static inline bool use_esclk_sched_clock(void)
{
	return false;
}

static inline unsigned long long esclk_sched_clock(void)
{
	BUG();
}

static inline void cpuinfo_esclk(struct seq_file *m) { }
#endif /* CONFIG_ESCLKR_CLOCKSOURCE */

static inline void cpuinfo_clk(struct seq_file *m)
{
	cpuinfo_sclk(m);
	cpuinfo_esclk(m);
}

#endif /* _ASM_E2K_SCLKR_H */
