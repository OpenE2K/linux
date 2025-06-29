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
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/pci.h>
#include <linux/percpu.h>
#include <linux/rtc.h>
#include <linux/sched/clock.h>

#include <asm/pic.h>
#include <asm/nmi.h>
#include <asm/sclkr.h>

/* #define SET_SCLKR_TIME1970 */

#define SCLKR_LO	0xffffffff

#define sclkr_clocksource_register()	\
	__clocksource_register(&clocksource_sclkr)

long long sclkr_sched_offset __read_mostly = 0;
int err_sclkr_res = 0;
int sclkr_initialized __read_mostly = 0;
static unsigned long long  max_sclkr_sec_cpu = 0;
int max_div_cpu = 0, cpu_max_div, min_div_cpu = 0x7fffffff, cpu_min_div;
static int sclkr_sec_cpu[NR_CPUS];
static DEFINE_MUTEX(sclkr_set_lock); /* for /proc/sclkr_src */
int bad_div_cpu[NR_CPUS];
#ifdef DBG_SCLKR
int cpu_err_sclkr, prv_cpu_err_sclkr = 0;
int max_err_sclkr_res = 0;
int num_err_sclkr = 0;
long long err_sclkr_lo = 0;
int err_sclkr_div;
#endif
DEFINE_PER_CPU(int, num_double_pulse) = 0;

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

static int do_watch4sclkr = 0;
static int __init set_watch4sclkr(char *str)
{
	do_watch4sclkr = 1;
	return 1;
}
__setup("watch_sclkr", set_watch4sclkr);

/* Use an aligned structure to make it occupy a whole cache line */
struct prev_sclkr prev_sclkr = { ATOMIC64_INIT(0) };

static void sclkr_read_sec(void *arg)
{
	unsigned long long sclkr_sec;
	int div, cpu = raw_smp_processor_id();

	sclkr_sec = read_SCLKR_reg_value() >> 32;
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

notrace
static u64 read_sclkr_com(int sync)
{
	u64 sclkr_sec, sclkr, res;
	u32 freq;
	unsigned long flags;
	e2k_sclkm1_t sclkm1;
	int cpu;

	raw_all_irq_save(flags);
	sclkr = read_SCLKR_reg_value();
	sclkm1 = read_SCLKM1_reg();
	freq = sclkm1.div + 1;

#ifdef DBG_SCLKR
	/* freq = (sclkm1.div + 0xff) & 0xffffff00; */
	if (freq > max_div_cpu)
		max_div_cpu = freq;
	else
		freq = max_div_cpu;
#endif
	res = sclkr2ns(sclkr, freq, sync);
	raw_all_irq_restore(flags);
	if (!sync)
		/* Loop if call from sched_clock() and
		   as a consequence possibly from printk() */
		return res;

	if (unlikely(sclkr_mode != SCLKR_INT && !sclkm1.mode ||
		!sclkm1.sw || !freq)) {
		panic("sclkr ERROR: sclkr_mode is not internal but sclkm1.mode was unset (by hardware ?).\n"
		"There is no PulsePerSecond signal. Do set sclkr=no in cmdline.\n"
		"CPU%02d sclkr=.%09lld, freq=%u Hz, sclkm1=0x%llx, sclkr_mode=%d\n",
		raw_smp_processor_id(), (u64) (u32) sclkr, freq,
		AW(sclkm1), sclkr_mode);
	}
	if (unlikely(__this_cpu_read(num_double_pulse))) {
		sclkr_sec = sclkr >> 32;
		pr_err("CPU %3d SCLKR ERROR: double PPS after %11lld ns bad sclkm1.div= %u fixed by %d num_double_pulse= %d times. sclkr.sec=%lld\n",
			raw_smp_processor_id(),
			(long long)freq * NSEC_PER_SEC / basic_freq_hz,
			freq, read_SCLKM1_reg().div,
			__this_cpu_read(num_double_pulse), sclkr_sec);
			__this_cpu_write(num_double_pulse, 0);
		for_each_online_cpu(cpu) {
			if (bad_div_cpu[cpu]) {
				pr_err("CPU %d bad_sclkr_div %d\n",
					cpu,  bad_div_cpu[cpu]);
				bad_div_cpu[cpu] = 0;
			}
		}
	}
#ifdef DBG_SCLKR
		sclkr_sec = sclkr >> 32;
		if ((sclkr_sec - print_sec) > 10) {
			print_sec = sclkr_sec;
			pr_err("sclkr2 sec %lld err %d max_e %d num_e %d cpu %d prv_cpu %d lo %lld div %d\n",
			sclkr_sec, err_sclkr_res, max_err_sclkr_res,
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
	return read_sclkr_com(1);
}
EXPORT_SYMBOL(read_sclkr);

notrace u64 read_sclkr_nosync(void)	/* for sched_clock() only */
{
	return read_sclkr_com(0);
}

static void sclk_set_range(void *range)
{
	write_SCLKM2_reg((e2k_sclkm2_t) { .word = (u64) range });
}
static void susp_sclkr(struct clocksource *clocksource)
{
	pr_warn("DEBUG: clocksource sclkr suspend.\n");
	if (strcmp(curr_clocksource->name, "sclkr") == 0) {
		if (timekeeping_notify(&lt_cs)) {
			pr_warn("susp_sclkr: can't set lt clocksourse\n");
		}
	}
}
static void resume_sclkr(struct clocksource *clocksource)
{
	pr_warn("DEBUG: resume sclkr will be in RTC driver after PPS set\n");
}

#define SCLK_CSOUR_SHFT	20
/*   ns = (cyc * mult) >> shift
 * for sclkr cyc==ns then 1 = (1 * mult) >> shift */
struct clocksource clocksource_sclkr = {
	.name		= "sclkr",
	.rating		= 400,
	.read		= read_sclkr,
	.suspend	= susp_sclkr,
	.resume		= resume_sclkr,
	.mask		= CLOCKSOURCE_MASK(64 - SCLK_CSOUR_SHFT),
	.shift		= SCLK_CSOUR_SHFT,
	.mult		= 1 << SCLK_CSOUR_SHFT,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};


static void sclkr_set_mode(void *arg)
{
	e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();
	write_SCLKM1_reg((e2k_sclkm1_t) { .word = (u64) arg });
	if (sclkm1.sclkm3) {
		write_SCLKM3_reg_value(0);
	}
}

void prepare_sclkr_rtc_set(void)
{
	int sclkr_lo, sclkr_lo_prev;
	e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();
	int freq, safe_lo, safe_lo2;

	if (!sclkm1.mode || sclkr_mode != SCLKR_RTC)
		return;	/* we in sclkr-internal mode already */
	/* We want to be far from PPS. So different processors will
	 * not appear on the different parties of seconds border
	 * while switching to sclkr internal mode.
	 */
	freq = read_SCLKM1_reg().div;
	safe_lo = (freq >> 2) + (freq >> 3);
	safe_lo2 = freq - safe_lo;
	do {
		sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
	} while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2);

	sclkr_mode = SCLKR_INT;
	/* sclkr_initialized should be set after sclkr_sched_offset */
	smp_wmb();
	sclkm1 = (e2k_sclkm1_t) { .sw = 1, .trn = 0, .mdiv = 0, .mode = 0};
	write_SCLKM1_reg(sclkm1); /* set SCLKR_INT mode */
	nmi_on_each_cpu(sclkr_set_mode, (void *) AW(sclkm1), 1, 0);
	if (machine.native_iset_ver > E2K_ISET_V3) {
		/* We want to be close and after to the old PPS while writing
		 * to RTC so that the new PPS and old matches
		 * as much as possible.
		 */
		sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
		do {
			sclkr_lo_prev = sclkr_lo;
			sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
		} while (sclkr_lo < sclkr_lo_prev);
	}

	return;
}
void finish_sclkr_rtc_set(void)
{
	int sclkr_lo;
	e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();
	int freq, safe_lo, safe_lo2;

	if (sclkm1.mode || sclkr_mode != SCLKR_INT)
		return;
	/* We want to be far from PPS. So different processors will
	 * not appear on the different parties of seconds border
	 * while switching to sclkr internal mode.
	 */
	freq = read_SCLKM1_reg().div;
	safe_lo = (freq >> 2) + (freq >> 3);
	safe_lo2 = freq - safe_lo;
	do {
		sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
	} while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2);

	sclkm1 = (e2k_sclkm1_t) { .sw = 1, .trn = 0, .mdiv = 0, .mode = 1};
	write_SCLKM1_reg(sclkm1); /* revert sclkr external mode */
	nmi_on_each_cpu(sclkr_set_mode, (void *) AW(sclkm1), 1, 0);
	sclkr_mode = SCLKR_RTC;
	/* sclkr_initialized should be set after sclkr_sched_offset */
	smp_wmb();
	return;
}
EXPORT_SYMBOL(finish_sclkr_rtc_set);

/* Set allowable deviation of frequency in % */
void sclk_set_deviat(int dev)
{
	unsigned long long range;
	unsigned int freq, d_freq;

	/* freq >> 7 -- allowable freq error is 0.01 */
	freq = read_SCLKM1_reg().div;
	d_freq = freq * 100 / dev;
	range = ((unsigned long long)(freq + d_freq) << 32) | (freq - d_freq);
	sclk_set_range((void *)range);
	smp_call_function(sclk_set_range, (void *)range, 1);
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

static bool wait_for_cleared_trn(const long max_timeout)
{
	const int single_wait = 10;
	int waited = 0;
	while (!is_training_finished_all_cpus() && waited < max_timeout) {
		schedule_timeout_uninterruptible(single_wait);
		waited += single_wait;
	}
	return !is_training_finished_all_cpus();
}

noinline int sclk_register(void *new_sclkr_src_arg)
{
	long new_sclkr_mode = (long)new_sclkr_src_arg;
	unsigned int sclkr_lo, sclkr_lo_swch;
	unsigned int freq, safe_lo, safe_lo2;
	unsigned long long range, sclkr_all;
	e2k_sclkm1_t sclkm1;
	struct task_struct *sclkr_w_thread;
	struct timespec64 ts;
	unsigned long flags;
	int cpu;
	const long max_timeout = 3 * HZ;
	bool timedout;

	/* Make sure this kthread and suspend/resume do not run simultaneously */
	set_freezable();

	if (basic_freq_hz == 1) { /* was not call to basic_freq_setup() */
		if (is_prototype()) {
			basic_freq_hz = 1000000;
			pr_notice("sclkr: PROTOTYPE DETECTED, SETTING FREQUENCY TO %u HZ\n",
				  basic_freq_hz);
		} else if (IS_MACHINE_E1CP) {
			/* e1c+ has wrong frequency in sclkm1.div */
			basic_freq_hz = 100000000;
		} else {
			basic_freq_hz = read_SCLKM1_reg().div;
		}
	}
	sclkm1 = (e2k_sclkm1_t) { .mdiv = 1, .div = basic_freq_hz };
	write_SCLKM1_reg(sclkm1); /* SCLKR_INT */
#ifdef DEBUG_SCLKR_FREQ
	for_each_possible_cpu(cpu)
		per_cpu(prev_freq, cpu) = basic_freq_hz;
#endif
	mutex_lock(&sclkr_set_lock);
	if (new_sclkr_mode == SCLKR_NO) {
		strcpy(sclkr_src, "no");
		sclkr_mode = SCLKR_NO;
		mutex_unlock(&sclkr_set_lock);
		if (timekeeping_notify(&lt_cs))
			pr_warn("can't set lt clocksourse\n");
		return -1;
	}

	/* All sclkr in cpu cores in a single processor are synchronous. */
	/* or  = (bootblock_virt->info.bios.mb_type == MB_TYPE_ES4_PC401); */
	if (new_sclkr_mode == SCLKR_INT) {
		sclkm1 = read_SCLKM1_reg();
		if (sclkm1.mode) {
			/* Work around E16C/E8C Bug 120921 - sclkm1.div renew
			 * is missed while mode is chenged ext->int.
			 * Write in sclkm1.mode when far from second change */
			freq = sclkm1.div + 1;
			safe_lo = (freq >> 2) + (freq >> 3);
			safe_lo2 = freq - safe_lo;
			sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
			while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2) {
				cpu_relax();
				sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
			}
		}
		pr_info("sclkr clocksource registration at internal mode\n");
		sclkm1 = (e2k_sclkm1_t) { .sw = 1, .mdiv = 1,
						.div = basic_freq_hz };
		/* .mode = 0 -- internel */
		on_each_cpu(sclkr_set_mode, (void *) AW(sclkm1), 1);
		strcpy(sclkr_src, "int");
		sclkr_mode = SCLKR_INT;
		sclkr_sched_offset = sched_clock() - read_sclkr(NULL);
		/* sclkr_initialized should be set after sclkr_sched_offset */
		smp_wmb();
		sclkr_initialized = 1;
		sclkr_clocksource_register();
		mutex_unlock(&sclkr_set_lock);
		pr_info("sclk_register set to int mode, %%sclkm1.div=0x%x "
			"(%d Mhz)\n",
			read_SCLKM1_reg().div,
			(read_SCLKM1_reg().div + 1) / 1000000);
		for_each_online_cpu(cpu)
			bad_div_cpu[cpu] = 0;
		if (do_watch4sclkr) {
			if (num_online_nodes() >= 1) {
				for_each_online_cpu(cpu) {
					sclkr_w_thread = kthread_create(watch4sclkr,
							NULL, "watch4sclkr/%d", cpu);
					if (WARN_ON(!sclkr_w_thread)) {
						pr_cont("kthread_create(watch4sclkr) FAILED\n");
					}
					kthread_bind(sclkr_w_thread, cpu);
					wake_up_process(sclkr_w_thread);
				}
			}
		}
		return 0;
	}	/* new_sclkr_mode == SCLKR_INT */

	/* FIXME add call register_cpu_notifier() for cpu hotplug case */

	/* Next for new_sclkr_mode == SCLKR_EXT or SCLKR_RTC */

	all_irq_save(flags);
	freq = basic_freq_hz;
	safe_lo = (freq * 15) >> 5;	/* 15/32 or +-0,47 sec from the seconds borders */
	safe_lo2 = freq - safe_lo;

	/* We want to be far from beginning of internal second.
	 * So different processors will not appear on the different
	 * parties of seconds border while switching to extrnal.
	 */
	sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
	while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2) {
		cpu_relax();
		sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
	}
	sclkr_lo_swch = sclkr_lo;

	all_irq_restore(flags);
	/* .mode = 1 -- for RTC or external sync */
	sclkm1 = (e2k_sclkm1_t) { .sw = 1, .trn = 1, .mode = 1 };

	/* Hardware won't clear 'trn' bit if CPU clock is disabled
	 * so we pause cpuidle until sclkr initialization completes. */
	cpuidle_pause_and_lock();
	on_each_cpu(sclkr_set_mode, (void *)AW(sclkm1), 1);
	/* SCLKR synchronized by RTC is for monotonic time coherent across CPUs
	 * It may leap due to hwclock command */
	if (new_sclkr_mode != SCLKR_RTC) {
		/* freq >> 7 -- allowable freq error is 0.01 */
		range = ((unsigned long long)(freq + (freq >> 7)) << 32) |
						(freq - (freq >> 7));
		sclk_set_range((void *)range);
		smp_call_function(sclk_set_range, (void *)range, 1);
	}
	mutex_unlock(&sclkr_set_lock);

	timedout = wait_for_cleared_trn(max_timeout);
	cpuidle_resume_and_unlock();
	if (timedout)
		goto sclkr_no;

	sclkr_all = read_SCLKR_reg_value();
	sclkr_lo = sclkr_all & SCLKR_LO;
	freq = read_SCLKM1_reg().div;
	ktime_get_real_ts64(&ts);
	pr_info("sclkr clocksource registration at cpu %d sclkr=%lld.%09llu sec, getnstod =%lld.%09ld\n",
		raw_smp_processor_id(), sclkr_all >> 32,
		(unsigned long long)sclkr_lo * NSEC_PER_SEC / freq,
		ts.tv_sec, ts.tv_nsec);
	{
		int cpu, cpu_cur = raw_smp_processor_id();
		while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2) {
			cpu_relax();
			sclkr_lo = read_SCLKR_reg_value() & SCLKR_LO;
		}
		on_each_cpu(sclkr_read_sec, NULL, 1);
		for_each_online_cpu(cpu)
			if (sclkr_sec_cpu[cpu] != sclkr_sec_cpu[cpu_cur]) {
				pr_err("sclkr FAIL seconds on cpu%d =%d is differ from cpu%d =%d\n",
				       cpu, sclkr_sec_cpu[cpu],
				       cpu_cur, sclkr_sec_cpu[cpu_cur]);
				return -1;
			}
	}
	pr_info("sclkr.div min= %d on cpu %d max= %d on cpu %d diff= %d Hz basic_freq=%d\n",
		min_div_cpu, cpu_min_div, max_div_cpu, cpu_max_div,
		max_div_cpu - min_div_cpu, basic_freq_hz);
#ifdef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
	set_sched_clock_stable();
#endif
	mutex_lock(&sclkr_set_lock);
	sclkr_sched_offset = sched_clock() - read_sclkr(NULL);
	/* sclkr_initialized should be set after sclkr_sched_offset */
	smp_wmb();
	sclkr_initialized = 1;
	sclkr_clocksource_register();
	sclkr_mode = new_sclkr_mode;
	if (new_sclkr_mode == SCLKR_RTC)
		strcpy(sclkr_src, "rtc");
	if (new_sclkr_mode == SCLKR_EXT)
		strcpy(sclkr_src, "ext");
	if (new_sclkr_mode == SCLKR_INT)
		strcpy(sclkr_src, "int");
	mutex_unlock(&sclkr_set_lock);
	return 0;
sclkr_no:
	do {
		pr_err("There is no pulse per second signal from RTC during %ld  secs, tell your hw vendor.\n"
		       "As a temporary workaround you can try setting \"sclkr=int nohlt\" in kernel cmdline on a single-socket system\n"
		       "and \"sclkr=no\" on a multi-socket system.\n"
		       "If RTC is not ticking then set the time in boot.\n"
		       "sclkm1=0x%llx (sw=%d, trn=%d mode=%d mdiv=%d div or freq =%d )\n"
		       "sclkm2= 0x%llx safe_lo=%u=%llu%% basic_freq=%d sclkr_lo_swch=%d\n",
		       max_timeout, AW(read_SCLKM1_reg()),
		       read_SCLKM1_reg().sw, read_SCLKM1_reg().trn,
		       read_SCLKM1_reg().mode, read_SCLKM1_reg().mdiv,
		       read_SCLKM1_reg().div, AW(read_SCLKM2_reg()),
		       safe_lo, (long long)safe_lo * 100 / freq,
		       basic_freq_hz, sclkr_lo_swch);
		schedule_timeout_interruptible(MAX_SCHEDULE_TIMEOUT);
	} while (1);
	return -1;
}
EXPORT_SYMBOL(sclk_register);

static int __init sclkr_init(void)
{
	int cpu = raw_smp_processor_id();
	struct task_struct *k;

	if (sclkr_mode == -1 || sclkr_mode == SCLKR_RTC || sclkr_mode == SCLKR_NO)
		return 0;

	k = kthread_create_on_cpu(sclk_register, (void *) SCLKR_INT,
				  cpu, "sclkregister");
	if (IS_ERR(k)) {
		pr_err("Failed to start sclk register thread, error: %ld\n",
		       PTR_ERR(k));
		return PTR_ERR(k);
	}
	wake_up_process(k);

	return 0;
}
arch_initcall(sclkr_init);
