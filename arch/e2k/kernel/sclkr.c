/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of sclkr clocksource.
 */

#include <linux/clocksource.h>
#include <linux/cpuidle.h>
#include <linux/delay.h>
#include <linux/freezer.h>
#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/percpu.h>
#include <linux/reboot.h>
#include <linux/sched/clock.h>

#include <asm/pic.h>
#include <asm/nmi.h>
#include <asm/sclkr.h>
#include <asm/sched_clock.h>

#define sclkr_clocksource_register()	\
	clocksource_register_hz(&clocksource_sclkr, NSEC_PER_SEC)

u64 unset_sclkr_ext __read_mostly = 0;
bool sclkr_initialized __read_mostly = 0;
EXPORT_SYMBOL(sclkr_initialized);
static int max_div_cpu = 0, cpu_max_div, min_div_cpu = 0x7fffffff, cpu_min_div;

/*
 * Protects:
 * - sclkr_mode
 * - sclkr_initialized
 * - kthread_rtc_ext
 */
DEFINE_MUTEX(sclkr_lock);

#ifdef DBG_SCLKR
int cpu_err_sclkr, prv_cpu_err_sclkr = 0;
int err_sclkr_res, max_err_sclkr_res = 0;
int num_err_sclkr = 0;
long long err_sclkr_lo = 0;
int err_sclkr_div;
#endif
DEFINE_PER_CPU(int, num_double_pulse) = 0;
DEFINE_PER_CPU(int, bad_div) = 0;

struct rtc_device *clk_rtc;
EXPORT_SYMBOL(clk_rtc);

u32 basic_freq_hz = 1;	/* 1 means there was not call to basic_freq_setup()
				 * and will be used hardware setting */
static int __init basic_freq_setup(char *str)
{
	if (!str)
		return 0;
	basic_freq_hz = simple_strtoul(str, &str, 0);
	return 1;
}
__setup("sclkr_hz=", basic_freq_setup);

u32 __init sclkr_get_frequency(void)
{
	if (is_prototype()) {
		u32 freq = 1000000;
		pr_notice("sclkr: prototype detected, setting frequency to %u hz\n",
			freq);
		return freq;
	} else if (IS_MACHINE_E1CP) {
		/* e1c+ has wrong frequency in sclkm1.div */
		return 100000000;
	} else {
		return read_SCLKM1_reg().div;
	}
}

static int do_watch4sclkr = 0;
static int __init set_watch4sclkr(char *str)
{
	do_watch4sclkr = 1;
	return 1;
}
__setup("watch_sclkr", set_watch4sclkr);

/* Use an aligned structure to make it occupy a whole cache line */
struct prev_sclkr prev_sclkr = { ATOMIC64_INIT(0) };

static unsigned long long max_sclkr_sec_cpu = 0;
static int sclkr_sec_cpu[NR_CPUS];
static void sclkr_read_sec(void *arg)
{
	unsigned long long sclkr_sec;
	int div, cpu = raw_smp_processor_id();
	sclkr_sec = read_SCLKR_reg().hi;
	sclkr_sec_cpu[cpu] = sclkr_sec;
	div = read_SCLKM1_reg().div;
	if (div > max_div_cpu) {
		max_div_cpu = div;
		cpu_max_div = cpu;
	}
	if (div < min_div_cpu) {
		min_div_cpu = div;
		cpu_min_div = cpu;
	}
	if (max_sclkr_sec_cpu < sclkr_sec)
		max_sclkr_sec_cpu = sclkr_sec;
}

/**
 * delay_until_pps_offset - Loop until %sclkr.lo is far enough from pulse per second
 * @offset: this far is enough
 *
 * Returns first successfull %sclkr.lo value.
 */
static u32 delay_until_pps_offset(u32 offset)
{
	u32 sclkr_lo, freq;

	do {
		/* Avoid cpu_relax() since we need precision here */
		barrier();

		freq = read_SCLKM1_reg().div + 1;
		sclkr_lo = read_SCLKR_reg().lo;
	} while (sclkr_lo < offset || sclkr_lo > freq - offset);

	return sclkr_lo;
}

notrace u64 read_sclkr_noirq(void)
{
	u64 res;
	u32 freq;
	e2k_sclkr_t sclkr;
	e2k_sclkm1_t sclkm1;

	sclkr = read_SCLKR_reg();
	sclkm1 = read_SCLKM1_reg();
	freq = sclkm1.div + 1;

#ifdef DBG_SCLKR
	/* freq = (sclkm1.div + 0xff) & 0xffffff00; */
	if (freq > max_div_cpu)
		max_div_cpu = freq;
	else
		freq = max_div_cpu;
#endif
	res = sclkr2ns(sclkr, sclkm1);

	if (unlikely(unset_sclkr_ext)) {
		panic("sclkr ERROR: sclkr_mode is not internal but sclkm1.mode was unset by hardware at %lld.%09lld.\n"
			"There is no PulsePerSecond signal. Do set sclkr=no in cmdline.\n"
			"CPU%02d sclkr=%u.%09ld, freq=%u Hz, sclkm1=0x%llx, sclkr_mode=%d SCLKM2 min %d max %d\n",
			unset_sclkr_ext / NSEC_PER_SEC, unset_sclkr_ext % NSEC_PER_SEC,
			raw_smp_processor_id(),
			sclkr.hi, sclkr.lo * NSEC_PER_SEC / freq, freq,
			AW(sclkm1), sclkr_mode, (read_SCLKM2_reg()).min, (read_SCLKM2_reg()).max);
	}
	if (unlikely(__this_cpu_read(num_double_pulse))) {
		pr_err("CPU %3d SCLKR ERROR: double PPS after %11lld ns bad div= %d fixed by %d num_double_pulse= %d times. sclkr.sec=%u\n",
			raw_smp_processor_id(),
			(long long)__this_cpu_read(bad_div) * NSEC_PER_SEC / basic_freq_hz,
			__this_cpu_read(bad_div), read_SCLKM1_reg().div,
			__this_cpu_read(num_double_pulse), sclkr.hi);
		__this_cpu_write(num_double_pulse, 0);
		__this_cpu_write(bad_div, 0);
	}
#ifdef DBG_SCLKR
	if ((sclkr_sec - print_sec) > 10) {
		sclkr.hi = sclkr_sec;
		pr_err("sclkr2 sec %u err %d max_e %d num_e %d cpu %d prv_cpu %d lo %lld div %d\n",
			sclkr.hi, err_sclkr_res, max_err_sclkr_res,
			num_err_sclkr, cpu_err_sclkr, prv_cpu_err_sclkr,
			err_sclkr_lo / (num_err_sclkr?:1), err_sclkr_div);
		err_sclkr_res = 0;
		err_sclkr_lo = 0;
		num_err_sclkr = 0;
		max_err_sclkr_res = 0;
	}
#endif	/* DBG_SCLKR */
	return res;
}
u64 read_sclkr(struct clocksource *cs)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	u64 ns = read_sclkr_noirq();
	raw_all_irq_restore(flags);

	return ns;
}
EXPORT_SYMBOL(read_sclkr);

static void sclk_set_range(void *sclkm2)
{
	write_SCLKM2_reg(*(e2k_sclkm2_t *) sclkm2);
}

struct clocksource clocksource_sclkr = {
	.name		= "sclkr",
	.rating		= 400,
	.read		= read_sclkr,
	/* For calculation of 2's complement subtraction, find when
	 * %sclkr.hi overflows ((2 ^ 32) * NSEC_PER_SEC) and take the
	 * number of last zero bits. */
	.mask		= CLOCKSOURCE_MASK(41),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};


static void sclkr_set_mode(void *sclkm1_p)
{
	write_SCLKM1_reg(*(e2k_sclkm1_t *) sclkm1_p);
	if (read_SCLKM1_reg().sclkm3) {
		write_SCLKM3_reg_value(0);
	}
}

/* Set allowable deviation of frequency in % */
void sclk_set_deviat(unsigned long dev)
{
	e2k_sclkm2_t range;
	u32 freq, d_freq;

	/* freq >> 7 -- allowable freq error is 0.01 */
	freq = read_SCLKM1_reg().div;
	d_freq = freq * dev / 100;
	range.max = freq + d_freq;
	range.min = (freq > d_freq) ? (freq - d_freq) : 0;
	on_each_cpu(sclk_set_range, &range, 1);
}

/* watch for cogerence of SCLKRs in each cpu */
static long long diff_tod_sclkr = 0;
static int watch4sclkr(void *arg)
{
	struct timespec64 ts;
	u64 sclkr_time;
	long long gtod_time;
	unsigned long flags;

	while (1) {
		local_irq_save(flags);
		ktime_get_real_ts64(&ts);
		sclkr_time = clocksource_sclkr.read(&clocksource_sclkr);
		local_irq_restore(flags);
		gtod_time = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
		if (diff_tod_sclkr == 0)
			diff_tod_sclkr = gtod_time - sclkr_time;
		if (abs(diff_tod_sclkr - (gtod_time - sclkr_time)) > 10000)
			pr_warn("cpu%02u %lld gtod-sclkr= %lld\n",
				raw_smp_processor_id(), ts.tv_sec,
				gtod_time - sclkr_time);
		schedule_timeout_interruptible(600 * HZ);
	}
	return 0;
}

static void check_training_finished(void *arg)
{
	bool *finished = arg;
	e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();
	if (sclkm1.trn || !sclkm1.mode)
		*finished = false;
}

static bool is_training_finished_all_cpus(void)
{
	bool finished = true;
	on_each_cpu(check_training_finished, (void *) &finished, 1);
	return finished;
}

/* Wait for hardware sclkr training completion.
 * Return true if waiting timed out. */
static bool wait_for_cleared_trn(const long max_timeout)
{
	const int single_wait = HZ / 10;
	int waited = 0;
	while (!is_training_finished_all_cpus() && waited < max_timeout) {
		schedule_timeout_uninterruptible(single_wait);
		waited += single_wait;
	}
	return !is_training_finished_all_cpus();
}

static struct task_struct *kthread_rtc_ext;

/* new_sclkr_mode == SCLKR_EXT or SCLKR_RTC */
static int switch_to_rtc_ext_fn(void *arg)
{
	enum sclkr_mode new_sclkr_mode = (enum sclkr_mode) (unsigned long) arg;
	unsigned int sclkr_lo_swch, freq, safe_lo, tolerance;
	e2k_sclkr_t sclkr;
	e2k_sclkm1_t sclkm1;
	e2k_sclkm2_t range;
	struct timespec64 ts;
	const long max_timeout = 3 * HZ;
	bool timedout;
	int cpu, cpu_cur, ret;

	/* Make sure this kthread and suspend/resume do not run simultaneously */
	set_freezable();

	mutex_lock(&sclkr_lock);
	if (sclkr_mode == new_sclkr_mode) {
		ret = 0;
		goto out_unlock;
	}

	/* FIXME add call register_cpu_notifier() for cpu hotplug case */

	/* We want to be far from beginning of internal second.
	 * So different processors will not appear on the different
	 * parties of seconds border while switching to extrnal.
	 *
	 * 15/32 or +-0,47 sec from the seconds borders. */
	freq = basic_freq_hz;
	safe_lo = (freq * 15) >> 5;
	sclkr_lo_swch = delay_until_pps_offset(safe_lo);

	/* Hardware won't clear 'trn' bit if CPU clock is disabled
	 * so we pause cpuidle until sclkr initialization completes. */
	cpuidle_pause_and_lock();

	/* .mode = 1 -- for RTC or external sync */
	sclkm1 = (e2k_sclkm1_t) { .sw = 0, .trn = 1, .mode = 1 };
	on_each_cpu(sclkr_set_mode, &sclkm1, 1);

	timedout = wait_for_cleared_trn(max_timeout);
	sclkm1 = (e2k_sclkm1_t) { .sw = 1, .trn = 0, .mode = 1 };
	on_each_cpu(sclkr_set_mode, &sclkm1, 1);
	cpuidle_resume_and_unlock();

	if (timedout) {
		e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();
		pr_err("There is no pulse per second signal from RTC for %ld seconds, tell your hw vendor.\n"
			"As a temporary workaround you can try setting \"sclkr=no\" in kernel cmdline.\n"
			"If RTC is not ticking then set the time in boot.\n"
			"sclkm1=0x%llx (sw=%d, trn=%d mode=%d mdiv=%d div/freq=%d),\n"
			"sclkm2=0x%llx, basic_freq=%d sclkr_lo_swch=%d\n",
			max_timeout / HZ, AW(sclkm1), sclkm1.sw, sclkm1.trn, sclkm1.mode,
			sclkm1.mdiv, sclkm1.div, AW(read_SCLKM2_reg()), basic_freq_hz,
			sclkr_lo_swch);
		ret = -ENODEV;
		goto out_unlock;
	}

	sclkr = read_SCLKR_reg();
	freq = read_SCLKM1_reg().div;
	ktime_get_real_ts64(&ts);

	cpu_cur = raw_smp_processor_id();
	pr_info("sclkr clocksource registration at cpu %d sclkr=%u.%09lu sec, getnstod =%lld.%09ld\n",
		cpu_cur, sclkr.lo, sclkr.lo * NSEC_PER_SEC / freq, ts.tv_sec, ts.tv_nsec);
	delay_until_pps_offset(safe_lo);
	on_each_cpu(sclkr_read_sec, NULL, 1);
	for_each_online_cpu(cpu) {
		if (sclkr_sec_cpu[cpu] != sclkr_sec_cpu[cpu_cur]) {
			pr_err("sclkr FAIL seconds on cpu%d =%d is differ from cpu%d =%d\n",
				cpu, sclkr_sec_cpu[cpu], cpu_cur,
				sclkr_sec_cpu[cpu_cur]);
			ret = -EINVAL;
			goto out_unlock;
		}
	}
	pr_info("sclkr.div min= %d on cpu %d max= %d on cpu %d diff= %d Hz basic_freq=%d\n",
		min_div_cpu, cpu_min_div, max_div_cpu, cpu_max_div,
		max_div_cpu - min_div_cpu, basic_freq_hz);
	/* freq >> 7 -- allowable freq error is 0.01 */
	tolerance = freq >> 7;
	range.max = freq + tolerance;
	range.min = 0;
	on_each_cpu(sclk_set_range, &range, 1);
	pr_info("sclkm2: min..max %d .. %d (0x%x .. 0x%x) tolerance=%d (0.%06d)\n",
		(read_SCLKM2_reg()).min, (read_SCLKM2_reg()).max,
		(read_SCLKM2_reg()).min, (read_SCLKM2_reg()).max,
		tolerance, tolerance * 1000000 / freq);

	/* Do not register again if we are just switching sclkr mode */
	if (!sclkr_initialized)
		sclkr_clocksource_register();

	freeze_sched_clock();
	sclkr_initialized = true;
	unfreeze_sched_clock();
	sclkr_mode = new_sclkr_mode;

	ret = 0;
out_unlock:
	kthread_rtc_ext = NULL;
	mutex_unlock(&sclkr_lock);
	return ret;
}

static int switch_to_rtc_ext(enum sclkr_mode new_sclkr_mode) __must_hold(sclkr_lock)
{
	kthread_rtc_ext = kthread_run(switch_to_rtc_ext_fn,
			(void *) (unsigned long) new_sclkr_mode, "sclk_register");
	if (IS_ERR(kthread_rtc_ext)) {
		int ret = PTR_ERR(kthread_rtc_ext);
		pr_err("Failed to start sclk_register thread, error: %d\n", ret);
		return ret;
	}

	return 0;
}

static int switch_to_no(void) __must_hold(sclkr_lock)
{
	WARN_ON_ONCE(!sclkr_initialized);

	/* Stop using sclkr for sched_clock() */
	freeze_sched_clock();
	sclkr_initialized = false;
	unfreeze_sched_clock();

	/* Remove sclkr from valid clocksources */
	clocksource_unregister(&clocksource_sclkr);

	sclkr_mode = SCLKR_NO;

	return 0;
}


int sclk_register_rtc(void)
{
	if (sclkr_mode != SCLKR_UNINITIALIZED)
		return 0;

	return sclk_register(SCLKR_RTC);
}
EXPORT_SYMBOL(sclk_register_rtc);

/**
 * sclk_uses_hardware_rtc - check whether sclkr uses actual hardware RTC chip
 * @rtc: RTC device to check, pass NULL for any device
 *
 * Writing into RTC conflicts with sclkr because it shifts
 * pulse-per-second that goes from RTC and into sclkr (which
 * is not mentioned an any datasheets).
 *
 * This returns true if `clk_rtc` is used by sclkr.
 */
bool sclk_uses_hardware_rtc(void) __must_hold(sclkr_lock)
{
	WARN_ON_ONCE(!mutex_is_locked(&sclkr_lock));

	/* Check sched_clock() instead of current clocksource
	 * because user might have disabled using sclkr for
	 * clocksource while sched_clock() will still use it. */
	return !IS_HV_GM() && use_sclk_sched_clock() && sclkr_mode == SCLKR_RTC;
}
EXPORT_SYMBOL(sclk_uses_hardware_rtc);

#ifdef CONFIG_RTC_SYSTOHC
/* Sleep until current `nsec` time reaches `target_nsec` */
static void wait_rtc_sync(unsigned long target_nsec)
{
	struct timespec64 next;

	ktime_get_real_ts64(&next);
	next.tv_sec = 0;
	next.tv_nsec = target_nsec - next.tv_nsec;
	if (next.tv_nsec <= 0)
		next.tv_nsec += NSEC_PER_SEC;
	if (next.tv_nsec >= NSEC_PER_SEC) {
		next.tv_sec++;
		next.tv_nsec -= NSEC_PER_SEC;
	}

	schedule_timeout_uninterruptible(timespec64_to_jiffies(&next));
}

/* Copied from kernel/time/ntp.c */
static inline bool rtc_tv_nsec_ok(unsigned long set_offset_nsec,
				  struct timespec64 *to_set,
				  const struct timespec64 *now)
{
	/* Allowed error in tv_nsec, arbitrarily set to 5 jiffies in ns. */
	const unsigned long TIME_SET_NSEC_FUZZ = TICK_NSEC * 5;
	struct timespec64 delay = {.tv_sec = -1,
				   .tv_nsec = set_offset_nsec};

	*to_set = timespec64_add(*now, delay);

	if (to_set->tv_nsec < TIME_SET_NSEC_FUZZ) {
		to_set->tv_nsec = 0;
		return true;
	}

	if (to_set->tv_nsec > NSEC_PER_SEC - TIME_SET_NSEC_FUZZ) {
		to_set->tv_sec++;
		to_set->tv_nsec = 0;
		return true;
	}
	return false;
}

/* Copied from kernel/time/ntp.c */
static int rtc_set_ntp_time(struct timespec64 now, unsigned long *target_nsec)
{
	struct rtc_device *rtc;
	struct rtc_time tm;
	struct timespec64 to_set;
	int err = -ENODEV;
	bool ok;

	rtc = rtc_class_open(CONFIG_RTC_SYSTOHC_DEVICE);
	if (!rtc)
		goto out_err;

	if (!rtc->ops || !rtc->ops->set_time)
		goto out_close;

	/* Compute the value of tv_nsec we require the caller to supply in
	 * now.tv_nsec.  This is the value such that (now +
	 * set_offset_nsec).tv_nsec == 0.
	 */
	set_normalized_timespec64(&to_set, 0, -rtc->set_offset_nsec);
	*target_nsec = to_set.tv_nsec;

	/* The ntp code must call this with the correct value in tv_nsec, if
	 * it does not we update target_nsec and return EPROTO to make the ntp
	 * code try again later.
	 */
	ok = rtc_tv_nsec_ok(rtc->set_offset_nsec, &to_set, &now);
	if (!ok) {
		err = -EPROTO;
		goto out_close;
	}

	rtc_time64_to_tm(to_set.tv_sec, &tm);

	err = rtc_set_time(rtc, &tm);

out_close:
	rtc_class_close(rtc);
out_err:
	return err;
}

/* Based on sync_rtc_clock() from kernel/time/ntp.c */
static void rtc_sync(void)
{
	int attempts = 3;
	int ret = 0;

	do {
		struct timespec64 adjust, now;
		unsigned long target_nsec;

		ktime_get_real_ts64(&now);

		adjust = now;
		if (persistent_clock_is_local)
			adjust.tv_sec -= (sys_tz.tz_minuteswest * 60);

		ret = rtc_set_ntp_time(adjust, &target_nsec);
		if (ret != -EPROTO)
			break;

		wait_rtc_sync(target_nsec);
	} while (--attempts);

	WARN(!attempts && ret == -EPROTO, "sclkr: could not update RTC");
}

static void sclkr_rtc_systohc(void)
{
	struct rtc_device *systohc_rtc = rtc_class_open(CONFIG_RTC_SYSTOHC_DEVICE);
	if (!systohc_rtc)
		return;

	/* Maybe sclkr used different RTC? */
	if (clk_rtc == systohc_rtc)
		rtc_sync();

	rtc_class_close(systohc_rtc);
}
#else
static void sclkr_rtc_systohc(void) { }
#endif

void sclk_unregister_rtc(void)
{
	bool uses_rtc;

	/* Disable sclkr */
	mutex_lock(&sclkr_lock);
	uses_rtc = sclk_uses_hardware_rtc();
	if (uses_rtc) {
		switch_to_no();
	}
	mutex_unlock(&sclkr_lock);

	if (uses_rtc) {
		/* And update RTC with actual values */
		sclkr_rtc_systohc();
	}
}
EXPORT_SYMBOL(sclk_unregister_rtc);

static int switch_to_int(void) __must_hold(sclkr_lock)
{
	e2k_sclkm1_t sclkm1;
	int cpu;

	if (nr_online_nodes > 1) {
		pr_info("sclkr: internal mode is not intended for NUMA\n");
		return -ENOTSUPP;
	}

	if (cpu_has(CPU_HWBUG_SCLKR_INT_C3)) {
		pr_info("sclkr: internal mode is not supported\n");
		return -ENOTSUPP;
	}

	/* All sclkr in cpu cores in a single processor are synchronous. */
	sclkm1 = read_SCLKM1_reg();
	sclkm1 = (e2k_sclkm1_t) { .sw = 1, .mdiv = 1, .div = basic_freq_hz };
	on_each_cpu(sclkr_set_mode, &sclkm1, 1);
	sclkr_mode = SCLKR_INT;

	/* Do not register again if we are just switching sclkr mode */
	if (!sclkr_initialized)
		sclkr_clocksource_register();

	freeze_sched_clock();
	sclkr_initialized = true;
	unfreeze_sched_clock();

	pr_info("sclk_register set to int mode, %%sclkm1.div=0x%x (%d Mhz)\n",
		read_SCLKM1_reg().div, (read_SCLKM1_reg().div + 1) / 1000000);
	if (do_watch4sclkr) {
		if (num_online_nodes() >= 1) {
			for_each_online_cpu(cpu) {
				struct task_struct *sclkr_w_thread;

				sclkr_w_thread = kthread_create(watch4sclkr,
						NULL, "watch4sclkr/%d", cpu);
				if (WARN_ON(!sclkr_w_thread)) {
					pr_err("kthread_create(watch4sclkr) FAILED\n");
				}
				kthread_bind(sclkr_w_thread, cpu);
				wake_up_process(sclkr_w_thread);
			}
		}
	}
	return 0;
}

static int sclk_enable_guest(enum sclkr_mode new_sclkr_mode)
{
	sclkr_mode = new_sclkr_mode;

	/* Do not register again if we are just switching sclkr mode */
	if (!sclkr_initialized)
		sclkr_clocksource_register();

	freeze_sched_clock();
	sclkr_initialized = true;
	unfreeze_sched_clock();

	return 0;
}

int sclk_register(enum sclkr_mode new_sclkr_mode)
{
	int ret;

	/*
	 * Check sclkr availability
	 */
	struct device_node *np = of_find_compatible_node(NULL, NULL, "mcst,sclkr-timer");
	if (!np)
		return 0;
	of_node_put(np);

#ifdef DEBUG_SCLKR_FREQ
	int cpu;
	for_each_possible_cpu(cpu)
		per_cpu(prev_freq, cpu) = basic_freq_hz;
#endif

	for (;;) {
		mutex_lock(&sclkr_lock);
		if (!kthread_rtc_ext)
			break;
		mutex_unlock(&sclkr_lock);

		schedule_timeout_uninterruptible(1);
	}

	if (sclkr_mode == new_sclkr_mode) {
		ret = 0;
		goto out_unlock;
	}

	/*
	 * Makes no sense trying to switch "int"/"rtc" modes in guest,
	 * it is not supported by hardware.  Just flag sclkr as enabled.
	 */
	if (IS_HV_GM() && new_sclkr_mode != SCLKR_NO) {
		ret = sclk_enable_guest(new_sclkr_mode);
		goto out_unlock;
	}

	switch (new_sclkr_mode) {
	case SCLKR_INT:
		ret = switch_to_int();
		break;
	case SCLKR_RTC:
	case SCLKR_EXT:
		ret = switch_to_rtc_ext(new_sclkr_mode);
		break;
	case SCLKR_NO:
		ret = switch_to_no();
		break;
	default:
		BUG();
	}

out_unlock:
	mutex_unlock(&sclkr_lock);

	return ret;
}

/*
 * Work around problem with writes to hardware RTC by
 * delaying them until system stop.
 */
static int sclkr_reboot(struct notifier_block *nb,
			unsigned long action, void *data)
{
	sclk_unregister_rtc();
	return NOTIFY_DONE;
}

static struct notifier_block sclkr_reboot_notifier = {
	.notifier_call = sclkr_reboot,
	/* Use sclkr for as long as we can.  This guarantees that
	 * kvm_reboot() has finished. */
	.priority = INT_MIN,
};

static int __init sclkr_timer_of_register(struct device_node *np)
{
	u32 freq, cur_freq = read_SCLKM1_reg().div;

	/* Get clock frequency if present */
	if (!of_property_read_u32(np, "clock-frequency", &freq)) {
		basic_freq_hz = freq;
		pr_info("Current sclkr frequency= %u.%04u MHz. Set to %u.%04u MHz from device tree.\n",
				cur_freq / 1000000, cur_freq % 1000000,
				basic_freq_hz / 1000000, basic_freq_hz % 1000000);
	}

	/* Get ready to sync time to RTC chip upon reboot */
	register_reboot_notifier(&sclkr_reboot_notifier);

	/* Can register immediately without waiting for RTC
	 * if "internal" or "no" mode is selected in command line. */
	switch (sclkr_mode_cmdline) {
	case SCLKR_INT:
		sclk_register(SCLKR_INT);
		break;
	case SCLKR_NO:
		sclkr_mode = SCLKR_NO;
		break;
	default:
		break;
	}

	return 0;
}
TIMER_OF_DECLARE(sclkr_timer, "mcst,sclkr-timer", sclkr_timer_of_register);

void cpuinfo_sclk(struct seq_file *m)
{
	if (use_sclk_sched_clock()) {
		seq_printf(m, " sclkr=%u", basic_freq_hz);
	}
}
