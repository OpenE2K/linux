#ifndef _ASM_E2K_SCLKR_H
#define _ASM_E2K_SCLKR_H

#include <linux/clocksource.h>
#include <linux/types.h>
#include <linux/percpu.h>
#include <linux/sched.h>

#include <asm/cpu_regs.h>
#include <asm-l/l_timer.h>

extern __interrupt u64 fast_syscall_read_sclkr(void);

/* SCLKR/SCLKM1/SCLKM2 implemented only on machine from e2s */
extern unsigned long native_read_SCLKR_reg_value(void);
extern unsigned long native_read_SCLKM1_reg_value(void);
extern unsigned long native_read_SCLKM2_reg_value(void);
extern void native_write_SCLKR_reg_value(unsigned long reg_value);
extern void native_write_SCLKM1_reg_value(unsigned long reg_value);
extern void native_write_SCLKM2_reg_value(unsigned long reg_value);

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
extern u64 raw_read_sclkr(void);
DECLARE_PER_CPU(int, ema_freq);

extern __interrupt u64 fast_syscall_read_sclkr(void);
extern struct clocksource *curr_clocksource;
extern int redpill;

#define xchg_prev_sclkr_res(res) \
	__api_atomic64_fetch_xchg_if_below(res, &prev_sclkr.res.counter, RELAXED_MB)

#define SHF_ALPHA	2
static __always_inline u64 sclkr_to_ns(u64 sclkr, u64 freq)
{
	u64 sclkr_sec, sclkr_lo, res, before;
	e2k_sclkm1_t sclkm1 = READ_SCLKM1_REG();
#ifdef CONFIG_SMP
	struct thread_info *ti = READ_CURRENT_REG();
	struct task_struct *task = (void *) ti
		- offsetof(struct task_struct, thread_info);
	typeof(ema_freq) *pema_freq = per_cpu_ptr(&ema_freq, task->cpu);
#else
	typeof(ema_freq) *pema_freq =
		(typeof(ema_freq) *)per_cpu_ptr(&ema_freq, 0);
#endif
	/* we can not use __this_cpu_read/write(ema_freq) in fast syscall : */

	sclkr_sec = sclkr >> 32;
	sclkr_lo = (u64) (u32) sclkr;

	if (sclkr_lo >= freq)
		sclkr_lo = freq - 1;

	/* Using exponential moving average (ema) of frequency
	 * ema = alpha * cur_freq + (1 - alpha) * ema;
	 * makes got time more smooth but belated frequency is used
	 * shorter:  ema = ema + (cur_freq - ema) * alpha;
	 * alpha = 2 / (period + 1)
	 * if moving average period = 3 alpha = 1/2 or use SHF_ALPHA = 1
	 * if moving average period = 7 alpha = 1/4 or use SHF_ALPHA = 2
	 *
	 * 1 << (SHF_ALPHA - 1) is added for rounding.
	 */
	*pema_freq += (freq - *pema_freq + (1 << (SHF_ALPHA - 1))) >> SHF_ALPHA;
	res = sclkr_sec * NSEC_PER_SEC + sclkr_lo * NSEC_PER_SEC / *pema_freq;

	/* sclkm3 has a summary time when guest was out of cpu */
	if (!redpill && sclkm1.sclkm3)
		res -= READ_SCLKM3_REG();
	before = xchg_prev_sclkr_res(res);
	if (before > res)
		res = before;

	return res;
}

static inline bool use_sclkr_sched_clock(void)
{
	return machine.native_iset_ver >= E2K_ISET_V3 && sclkr_initialized;
}

#endif	/* _ASM_E2K_SCLKR_H */
