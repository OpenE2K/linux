/*
 * arch/e2k/kernel/sclkr.c
 *
 * This file contains implementation of sclkr clocksource.
 *
 * Copyright (C) MCST 2015 Leonid Ananiev (leoan@mcst.ru)
 */

#include <linux/percpu.h>
#include <linux/clocksource.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/pci.h>
#include <linux/rtc.h>
#include <asm/sclkr.h>
#include <linux/sched/clock.h>

#include <asm/pic.h>

/* #define SET_SCLKR_TIME1970 */
#define SCLKR_CHECKUP	1

#define SCLKR_LO	0xffffffff

/* For kernel 4.9: */
#define READ_SSCLKR_REG()	READ_SCLKR_REG()
#define READ_SSCLKM1_REG()	READ_SCLKM1_REG()
#define READ_SSCLKM2_REG()	READ_SCLKM2_REG()
#define READ_SSCLKM3_REG()	READ_SCLKM3_REG()
#define WRITE_SSCLKR_REG(val)	WRITE_SCLKR_REG(val)
#define WRITE_SSCLKM1_REG(val)	WRITE_SCLKM1_REG(val)
#define WRITE_SSCLKM2_REG(val)	WRITE_SCLKM2_REG(val)
#define WRITE_SSCLKM3_REG(val)	WRITE_SCLKM3_REG(val)
#define READ_SCURRENT_REG()	READ_CURRENT_REG()
#define sclkr_clocksource_register()	\
	__clocksource_register(&clocksource_sclkr)

long long sclkr_sched_offset = 0;
int sclkr_initialized = 0;
#ifdef DEBUG_SCLKR_FREQ
static int rtc_wr_sec = 0;
#endif

static DEFINE_MUTEX(sclkr_set_lock); /* for /proc/sclkr_src */
#ifdef DEBUG_SCLKR_FREQ
static DEFINE_PER_CPU(u64, prev_freq);
static DEFINE_PER_CPU(u64, freq_print) = 0;
#endif

u64 basic_freq_hz = 1;	/* 1 means there was not call to basic_freq_setup()
			 * and will be used hardware setting */
int __init basic_freq_setup(char *str)
{
	if (!str)
		return 0;
	basic_freq_hz = simple_strtoul(str, &str, 0);
#ifdef DEBUG_SCLKR_FREQ
	int cpu;

	for_each_possible_cpu(cpu)
		per_cpu(prev_freq, cpu) = basic_freq_hz;
#endif
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

/* exponential moving average of frequency */
DEFINE_PER_CPU(int, ema_freq);
#define OSCIL_JIT_SHFT	10
notrace
static u64 read_sclkr(struct clocksource *cs)
{
	u64 sclkr_sec, sclkr, freq, res;
	e2k_sclkm1_t sclkm1;
	unsigned long flags;
#ifdef DEBUG_SCLKR_FREQ
	u64 this_prev_freq;

	this_prev_freq = __this_cpu_read(prev_freq);
#endif
	raw_all_irq_save(flags);
	sclkr = READ_SSCLKR_REG();
	sclkm1 = READ_SSCLKM1_REG();
	sclkr_sec = sclkr >> 32;
	freq = sclkm1.div;

	if (unlikely(sclkr_mode != SCLKR_INT && !sclkm1.mode ||
			!sclkm1.sw || !freq)) {
		pr_alert("WARNING: sclkr clocksource error.\n"
			"CPU%02d sclkr= %lld.%09lld sec (raw=.%09lld), freq=%llu Hz, sclkm1=0x%llx sclkr_mode=%d\n"
			"There is no PulsePerSecond signal.\n"
			"Set sclkr=no in cmdline\n",
			raw_smp_processor_id(), sclkr >> 32,
			((u64) (u32) sclkr) * NSEC_PER_SEC / freq,
			(u64) (u32) sclkr, freq, AW(sclkm1), sclkr_mode);
		panic("read_sclkr: ERROR");
	}
#ifdef DEBUG_SCLKR_FREQ
	if (unlikely(abs(this_prev_freq - freq) >
		     (this_prev_freq >> OSCIL_JIT_SHFT))) {
		if (abs(freq - __this_cpu_read(freq_print)) > 2 &&
				/* write to RTC may change PPS phase */
				rtc_wr_sec != sclkr_sec &&
				(rtc_wr_sec + 1) != sclkr_sec) {
			__this_cpu_write(freq_print, freq);
			pr_err("CPU %d SCLKR ERROR freq(div)= %llu prev=%llu rtcwr=%d sec=%lld\n",
				raw_smp_processor_id(), freq, this_prev_freq,
				rtc_wr_sec, sclkr_sec);
		}

		freq = basic_freq_hz;
	}
	__this_cpu_write(prev_freq, freq);
#endif
	res = sclkr_to_ns(sclkr, freq);
	raw_all_irq_restore(flags);
	return res;
}

notrace
u64 raw_read_sclkr(void)
{
	u64 sclkr, freq, res;
	unsigned long flags;
	e2k_sclkm1_t sclkm1;
#ifdef DEBUG_SCLKR_FREQ
	u64 this_prev_freq;

	this_prev_freq = __this_cpu_read(prev_freq);
#endif
	raw_all_irq_save(flags);

	sclkr = READ_SSCLKR_REG();
	sclkm1 = READ_SSCLKM1_REG();
	freq = sclkm1.div;

	if (unlikely(!freq)) {
		raw_all_irq_restore(flags);
		return 0;
	}

#ifdef DEBUG_SCLKR_FREQ
	if (unlikely(abs(this_prev_freq - freq) >
		     (this_prev_freq >> OSCIL_JIT_SHFT)))
		freq = basic_freq_hz;
	__this_cpu_write(prev_freq, freq);
#endif
	res = sclkr_to_ns(sclkr, freq);
	raw_all_irq_restore(flags);
	return res;
}
static void sclk_set_range(void *range)
{
	WRITE_SSCLKM2_REG((unsigned long long) range);
}

static void resume_sclkr(struct clocksource *clocksource)
{
	if (strcmp(curr_clocksource->name, "lt") == 0 &&
			(sclkr_mode == SCLKR_RTC || sclkr_mode == SCLKR_EXT)) {
		if (timekeeping_notify(&clocksource_sclkr)) {
			pr_warn("resume_sclkr: can't set sclkr clocksourse\n");
		}
	}
}

#define SCLK_CSOUR_SHFT	20
/*   ns = (cyc * mult) >> shift
 * for sclkr cyc==ns then 1 = (1 * mult) >> shift */
struct clocksource clocksource_sclkr = {
	.name		= "sclkr",
	.rating		= 400,
	.read		= read_sclkr,
	.resume		= resume_sclkr,
	.mask		= CLOCKSOURCE_MASK(64 - SCLK_CSOUR_SHFT),
	.shift		= SCLK_CSOUR_SHFT,
	.mult		= 1 << SCLK_CSOUR_SHFT,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};


static void sclkr_set_mode(void *arg)
{
	e2k_sclkm1_t sclkm1 = READ_SSCLKM1_REG();
	WRITE_SSCLKM1_REG((e2k_sclkm1_t) (u64) arg);
	if (sclkm1.sclkm3) {
		WRITE_SSCLKM3_REG(0);
	}
}

#ifdef SCLKR_CHECKUP
static int sclkr_sec_cpu[NR_CPUS];
static void sclkr_read_sec(void *arg)
{
	sclkr_sec_cpu[raw_smp_processor_id()] = READ_SSCLKR_REG() >> 32;
}
#endif

/* Set allowable deviation of frequency in % */
void sclk_set_deviat(int dev)
{
	unsigned long long range;
	unsigned int freq, d_freq;

	/* freq >> 7 -- allowable freq error is 0.01 */
	freq = READ_SSCLKM1_REG().div;
	d_freq = freq * 100 / dev;
	range = ((unsigned long long)(freq + d_freq) << 32) |
					(freq - d_freq);
	sclk_set_range((void *)range);
	smp_call_function(sclk_set_range, (void *)range, 1);
}

/* watch for cogerence of SCLKRs in each cpu */
static long long diff_tod_sclkr = 0;
int watch4sclkr(void *arg)
{
	struct timespec ts;
	u64 sclkr_time;
	long long gtod_time;
	unsigned long flags;

	while (1) {
		local_irq_save(flags);
		getnstimeofday(&ts);
		sclkr_time = clocksource_sclkr.read(&clocksource_sclkr);
		local_irq_restore(flags);
		gtod_time = ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
		if (diff_tod_sclkr == 0)
			diff_tod_sclkr = gtod_time - sclkr_time;
		if (abs(diff_tod_sclkr - (gtod_time - sclkr_time)) > 10000)
			pr_warning("cpu%02u %ld gtod-sclkr= %lld\n",
				raw_smp_processor_id(), ts.tv_sec,
				gtod_time - sclkr_time);
		schedule_timeout_interruptible(600 * HZ);
	}
	return 0;
}


noinline int sclk_register(void *new_sclkr_src_arg)
{
	long	new_sclkr_mode = (long)new_sclkr_src_arg;
	unsigned int sclkr_lo, sclkr_lo_prev, sclkr_lo_saved;
	unsigned int freq, freq1, safe_lo, safe_lo2;
	unsigned long long range, sclkr_all;
	e2k_sclkm1_t sclkm1;
	struct task_struct *sclkr_w_thread;
	struct timespec ts;
	unsigned long flags;
	int waiting = 0, cpu;

	if (basic_freq_hz == 1) { /* was not call to basic_freq_setup() */
		if (is_prototype()) {
			basic_freq_hz = 1000000;
			pr_notice("sclkr: PROTOTYPE DETECTED, SETTING FREQUENCY TO %llu HZ\n",
					basic_freq_hz);
		} else if (IS_MACHINE_E1CP) {
			/* e1c+ has wrong frequency in sclkm1.div */
			basic_freq_hz = 100000000;
		} else {
			basic_freq_hz = READ_SSCLKM1_REG().div;
		}
	}
	pr_info("sclk_register old mod %d new %ld basic_fr_hz=%lld m1=%llx\n",
		sclkr_mode, new_sclkr_mode, basic_freq_hz,
		READ_SSCLKM1_REG().word);
	for_each_possible_cpu(cpu)
		per_cpu(ema_freq, cpu) = basic_freq_hz;
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
		sclkm1 = READ_SSCLKM1_REG();
		if (sclkm1.mode) {
			/* Work around E16C/E8C Bug 120921 - sclkm1.div renew
			 * is missed while mode is chenged ext->int.
			 * Write in sclkm1.mode when far from second change */
			freq = sclkm1.div;
			safe_lo = (freq >> 2) + (freq >> 3);
			safe_lo2 = freq - safe_lo;
			sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
			while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2) {
				cpu_relax();
				sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
			}
		}
		pr_info("sclkr clocksource registation at internal mode\n");
		sclkm1 = (e2k_sclkm1_t) { .sw = 1, .mdiv = 1,
						.div = basic_freq_hz };
		/* .mode = 0 -- internel */
		on_each_cpu(sclkr_set_mode, (void *) AW(sclkm1), 1);
		strcpy(sclkr_src, "int");
		sclkr_mode = SCLKR_INT;
		sclkr_sched_offset = sched_clock() - raw_read_sclkr();
		/* sclkr_initialized should be set after sclkr_sched_offset */
		smp_wmb();
		sclkr_initialized = 1;
		sclkr_clocksource_register();
		mutex_unlock(&sclkr_set_lock);
		pr_info("sclk_register set to int mode, %%sclkm1.div=0x%x "
			"(%d Mhz)\n",
			READ_SSCLKM1_REG().div,
			(READ_SSCLKM1_REG().div + 1) / 1000000);
		if (!do_watch4sclkr)
			return 0;
		if (num_online_nodes() >= 1) {
			for_each_online_cpu(cpu) {
				sclkr_w_thread = kthread_create(watch4sclkr,
					NULL, "watch4sclkr/%d", cpu);
				if (WARN_ON(!sclkr_w_thread)) {
					pr_cont("kthread_create(watch4sclkr) "
					"FAILED\n");
				}
				kthread_bind(sclkr_w_thread, cpu);
				wake_up_process(sclkr_w_thread);
			}
		}
		return 0;
	}

	/* FIXME add call register_cpu_notifier() for cpu hotplug case */
	/* We want to be far from beginning of internal second.
	 * So different processors will not appear on the different
	 * parties of seconds border while switching to extrnal.
	 */
	raw_all_irq_save(flags);
	WRITE_SSCLKM2_REG(0xffffffff00000000); /* max range */
	sclkm1 = (e2k_sclkm1_t) { .mdiv = 1, .div = basic_freq_hz };
	WRITE_SSCLKM1_REG(sclkm1); /* SCLKR_INT */
	freq = basic_freq_hz;
	safe_lo = (freq >> 2) + (freq >> 3);	/* 37% reserve */
	safe_lo2 = freq - safe_lo;
	pr_err("sclkr INFO safe_lo=%u %u fr=%u div=%u bas=%llu\n",
		safe_lo, safe_lo2, freq, READ_SSCLKM1_REG().div, basic_freq_hz);

	sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
	while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2) {
		cpu_relax();
		sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
	}
	sclkr_lo_saved = sclkr_lo;

	/* Wait for first external signal of second biginig and look at
	 * sclkm1.div (prvious sclkr_lo) to see how far from external
	 * second bigining the swinching was. */
	sclkm1 = (e2k_sclkm1_t) { .mode = 1 };
	WRITE_SSCLKM1_REG(sclkm1);
	sclkr_lo_prev = sclkr_lo;
	sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
	while (sclkr_lo >= sclkr_lo_prev) {
		cpu_relax();
		sclkr_lo_prev = sclkr_lo;
		sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
	}

	freq1 = READ_SSCLKM1_REG().div;
	if (freq1 <= basic_freq_hz) {
		/* Wait for other cpus as well will increase sclkr seconds
		 * and safe_lo sclkr ticks more */
		if (freq1 > basic_freq_hz - (basic_freq_hz >> 2)) {
			safe_lo = basic_freq_hz >> 1;
			sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
			while (sclkr_lo <= safe_lo) {
				cpu_relax();
				sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
			}
		} else {
			freq = basic_freq_hz;
			safe_lo = freq - (freq >> 3);
			pr_err("sclkr info safe_lo=%u=%llu%% "
				"fr=%u fr1=%u=%llu%%\n",
				safe_lo,
				(long long)safe_lo * 100 / freq, freq,
				freq1, (long long)freq1 * 100 / freq);
			if (safe_lo > (basic_freq_hz << 2)) {
				pr_err("sclkr error safe_lo=%u=%llu%% large "
					"fr=%u fr1=%u=%llu%%\n",
					safe_lo,
					(long long)safe_lo * 100 / freq, freq,
					freq1, (long long)freq1 * 100 / freq);
				goto error_irq_unlock;
			}
			do {
				sclkr_lo_prev = sclkr_lo;
				sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
				if (waiting == 3) {
					pr_err("sclkr info sfl=%llu%% wait=3 "
						"f=%u f1=%llu%% l=%u-%u=%u\n",
						(long long)safe_lo * 100 / freq,
						freq,
						(long long)freq1 * 100 / freq,
						sclkr_lo, sclkr_lo_prev,
						sclkr_lo - sclkr_lo_prev);
				}
				if (waiting++ > basic_freq_hz) {
					pr_err("sclkr error sf_lo=%llu%% wait "
						"f=%u f1=%llu%% l=%u prl=%u\n",
						(long long)safe_lo * 100 / freq,
						freq,
						(long long)freq1 * 100 / freq,
						sclkr_lo, sclkr_lo_prev);
					goto error_irq_unlock;
				}
			} while (sclkr_lo <= safe_lo);
		}
	}
	raw_all_irq_restore(flags);
	/* .mode = 1 -- for RTC or externel sync */
	sclkm1 = (e2k_sclkm1_t) { .sw = 1, .trn = 1, .mode = 1 };
	on_each_cpu(sclkr_set_mode, (void *) AW(sclkm1), 1);
	pr_info("sclkr other CPU registation done sclkr=%lld.%09llu sec,"
		" last sclkr_lo=%d.%d\n",
		READ_SSCLKR_REG() >> 32,
		(unsigned long long)READ_SSCLKR_REG() &
				SCLKR_LO * NSEC_PER_SEC / freq,
		freq1 / 1000000, freq1 % 1000000);
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
	schedule_timeout_interruptible(10 * HZ);
	if (!READ_SSCLKM1_REG().mode) {
		pr_err("Error sclkr. cpu%02d bit 'ext' is cleared by HW.\n",
			raw_smp_processor_id());
		goto sclkr_no;
	}
	if (READ_SSCLKM1_REG().trn) {
		pr_err("Error sclkr. cpu%02d 'training' was not cleared.\n",
			raw_smp_processor_id());
		goto sclkr_no;
	}
	sclkr_all = READ_SSCLKR_REG();
	sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
	freq = READ_SSCLKM1_REG().div;
	getnstimeofday(&ts);
	pr_info("sclkr clocksource registation at cpu %d "
		"sclkr=%lld.%09llu sec, getnstod =%ld.%09ld "
		"fr=%u Hz, ext=%d swOK=%d range= %lld:%lld\n",
		raw_smp_processor_id(), sclkr_all >> 32,
		(unsigned long long)sclkr_lo * NSEC_PER_SEC / freq,
		ts.tv_sec, ts.tv_nsec,
		freq, READ_SSCLKM1_REG().mode, READ_SSCLKM1_REG().sw,
		READ_SSCLKM2_REG() & 0xffffffff,
		READ_SSCLKM2_REG() >> 32);
#ifdef SCLKR_CHECKUP
	{
	int cpu, cpu_cur = raw_smp_processor_id();
	safe_lo = (freq >> 2) + (freq >> 3);	/* 37% reserve */
	safe_lo2 = freq - safe_lo;
	while (sclkr_lo < safe_lo || sclkr_lo > safe_lo2) {
		cpu_relax();
		sclkr_lo = READ_SSCLKR_REG() & SCLKR_LO;
	}
	on_each_cpu(sclkr_read_sec, NULL, 1);
	for_each_online_cpu(cpu)
		if (sclkr_sec_cpu[cpu] != sclkr_sec_cpu[cpu_cur]) {
			pr_err("sclkr FAIL seconds on cpu%d =%d"
				" is differ from cpu%d =%d\n",
				cpu, sclkr_sec_cpu[cpu],
				cpu_cur, sclkr_sec_cpu[cpu_cur]);
			return -1;
		}
	}
#endif
#ifdef CONFIG_HAVE_UNSTABLE_SCHED_CLOCK
	set_sched_clock_stable();
#endif
	mutex_lock(&sclkr_set_lock);
	sclkr_sched_offset = sched_clock() - raw_read_sclkr();
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
error_irq_unlock:
	raw_all_irq_restore(flags);
	mutex_unlock(&sclkr_set_lock);
sclkr_no:
	panic("There is no pulse per second signal from RTC, tell your hw vendor. As a temporary workaround you can try setting \"sclkr=int nohlt\" in kernel cmdline on a single-socket system and \"sclkr=no\" on a multi-socket system.");
}
EXPORT_SYMBOL(sclk_register);

static int __init sclkr_init(void)
{
	int cpu = raw_smp_processor_id();
	struct task_struct *k;

	if (machine.native_iset_ver < E2K_ISET_V3 ||
			sclkr_mode == -1 ||
			sclkr_mode == SCLKR_RTC ||
			sclkr_mode == SCLKR_NO)
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
