/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of clk_rt clocksource.
 */

#if defined(CONFIG_E90S)
#include <linux/percpu.h>
#include <linux/clocksource.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/rtc.h>
#include <linux/sched/clock.h>
#include <linux/rtc.h>
#include <asm/sic_regs.h>
#include <asm-l/clk_rt.h>
#include <asm-l/bootinfo.h>
#define DBG_CLK_RT	0

#define clk_rt_clocksource_register()	\
	__clocksource_register(&clocksource_clk_rt)
#define MASK_32	0xffffffff
#define NPT_MASK	0x8000000000000000LL
#define SOFT_OK_MASK	0x4000000000000000LL

int clk_rt_mode = CLK_RT_RTC;
int clk_rt_initialized = 0;
long long clk_rt_sched_offset = 0;
EXPORT_SYMBOL(clk_rt_mode);
/* for single clk_rt_register thread run if multiple RTC */
atomic_t num_clk_rt_register = ATOMIC_INIT(-1);
EXPORT_SYMBOL(num_clk_rt_register);

struct rtc_device *clk_rtc;
EXPORT_SYMBOL(clk_rtc);

static int __init clk_rt_setup(char *s)
{
	int	error;
	static struct task_struct *reg_task;
	if (!s || (strcmp(s, "no") && strcmp(s, "rtc") &&
			strcmp(s, "ext") && strcmp(s, "int"))) {
		pr_err("Possible clk_rt cmdline modes are:\n"
			"no, ext, rtc, int\n");
		return -EINVAL;
	}

	if (get_cpu_revision() >= 0x10 && s) {
		if (!strcmp(s, "ext")) {
			reg_task = kthread_run(clk_rt_register,
				(void *)CLK_RT_EXT, "clk_rt_register");
			if (IS_ERR(reg_task)) {
				error = PTR_ERR(reg_task);
				pr_err("Failed to start clk_rt register thread, error: %d\n", error);
				return error;
			}
		}
		if (!strcmp(s, "rtc")) {
			clk_rt_mode = CLK_RT_RTC;
		}
		if (!strcmp(s, "no")) {
			clk_rt_mode = CLK_RT_NO;
		}
	}
	return 0;
}
__setup("clk_rt=", clk_rt_setup);
static inline e90s_rt_tick_t read_rt_tick(void)
{
	e90s_rt_tick_t rt_tick; /* RT_TICK ASR 0x1e */
	__asm__ __volatile__ ("rd %%asr30, %0\n\t" : "=r"(rt_tick.word));
	return rt_tick;
};
static inline e90s_rt_div_t read_rt_div(void)
{
	e90s_rt_div_t rt_div; /* RT_DIV ASR 0x1f */
	__asm__ __volatile__ ("rd %%asr31, %0\n\t" : "=r"(rt_div.word));
	return rt_div;
};
static inline void write_rt_tick(e90s_rt_tick_t rt_tick_v)
{
	__asm__ __volatile__("wr	%0, 0, %%asr30"
			     : /* no outputs */
			     : "r" (rt_tick_v.word));
};
static inline void write_rt_div(e90s_rt_div_t rt_div_v)
{
	__asm__ __volatile__("wr	%0, 0, %%asr31"
			     : /* no outputs */
			     : "r" (rt_div_v.word));
};

static inline int get_soft_ok(void)
{
	if (get_cpu_revision() >= 0x12)
		return read_rt_div().soft_ok;
	else
		return !read_rt_div().npt;
}

void set_soft_ok(void *arg)
{
	if (get_cpu_revision() >= 0x12) {
		write_rt_div((e90s_rt_div_t){.div = read_rt_div().div,
			.soft_ok = 1});
	} else {		/* set NPT to zero - clk_rt init is OK */
		write_rt_div((e90s_rt_div_t){.div = read_rt_div().div,
			.npt = 0});
	}
}

void unset_soft_ok(void *arg)
{
	if (get_cpu_revision() >= 0x12) {
		write_rt_div((e90s_rt_div_t){.div = read_rt_div().div,
			.soft_ok = 0});
	} else {
		write_rt_div((e90s_rt_div_t){.div = read_rt_div().div,
			.npt = 1});
	}
}

s64 clk_rt_res_before = 0;

notrace
u64 read_clk_rt(struct clocksource *cs)
{
	e90s_rt_tick_t clk_rt_v;
	long long clk_rt_lo, clk_rt_sec;
	int freq;
	unsigned long flags;
	u64	res = 0;
	s64 old, new;

	raw_local_irq_save(flags);
	clk_rt_v = read_rt_tick();
	clk_rt_lo = clk_rt_v.lo;
	clk_rt_sec = clk_rt_v.hi;
	freq = read_rt_div().div;
	raw_local_irq_restore(flags);
	if (!get_soft_ok()) {
		pr_err_once("ERROR: clocksource clk_rt is not initialised clk_rt_sec=%lld clk_rt_lo=%lld div=%d soft_ok=%d\n",
			clk_rt_sec, clk_rt_lo, read_rt_div().div,
			get_soft_ok());
		return 0;
	}
	res = clk_rt_sec * NSEC_PER_SEC +
		clk_rt_lo * NSEC_PER_SEC / freq;
	old = clk_rt_res_before;
	if (old > res) {
		return old;
	} else {
		clk_rt_res_before = res;
		return res;
	}
}
EXPORT_SYMBOL(read_clk_rt);

static void susp_clk_rt(struct clocksource *clocksource)
{
	pr_warn("DEBUG: clocksource clk_rt suspend.\n");
	if (strcmp(curr_clocksource->name, "clk_rt") == 0) {
		if (timekeeping_notify(&lt_cs)) {
			pr_warn("susp_clk_rt: can't set lt clocksourse\n");
		}
	}
}
static void resume_clk_rt(struct clocksource *clocksource)
{
	pr_crit("DEBUG: clocksource clk_rt resume is not need\n");
}

#define SCLK_CSOUR_SHFT	20
/*   ns = (cyc * mult) >> shift
 * for clk_rt cyc==ns then 1 = (1 * mult) >> shift */
struct clocksource clocksource_clk_rt = {
	.name		= "clk_rt",
	.rating		= 400,
	.read		= read_clk_rt,
	.suspend	= susp_clk_rt,
	.resume		= resume_clk_rt,
	.mask		= CLOCKSOURCE_MASK(64 - SCLK_CSOUR_SHFT),
	.shift		= SCLK_CSOUR_SHFT,
	.mult		= 1 << SCLK_CSOUR_SHFT,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};
EXPORT_SYMBOL(clocksource_clk_rt);

static void clk_rt_wr_seconds(void *arg)
{
	u64 w_clk_rt_sec = (u64) arg;
#if DBG_CLK_RT
	pr_warn("clk_rt bf clk_rt_wr_seconds cpu %d %10lld.%9lld"
			" w_clk_rt_sec %lld %llx\n",
		raw_smp_processor_id(),
		read_rt_tick().hi, read_rt_tick().lo,
			w_clk_rt_sec, w_clk_rt_sec);
#endif
	write_rt_tick((e90s_rt_tick_t){.hi = w_clk_rt_sec});
#if DBG_CLK_RT
	pr_warn("clk_rt af clk_rt_wr_seconds cpu %d %10ld.%9ld\n",
		raw_smp_processor_id(),
		read_rt_tick().hi, read_rt_tick().lo);
#endif
}

/**
 * delay_until_pps_offset - Loop until %clk_rt.lo is far enough from pulse per second
 * @offset: this far is enough
 *
 * Returns first successfull %clk_rt.lo value.
 */
static u32 delay_until_pps_offset(u32 offset, int freq)
{
	long long clk_rt_lo;
	do {
		/* Avoid cpu_relax() since we need precision here */
		barrier();

		clk_rt_lo = read_rt_tick().lo;
	} while (clk_rt_lo < offset || clk_rt_lo > freq - offset);

	return clk_rt_lo;
}

static bool clk_rt_has_bugs(void)
{
	u32 v;
	v = sic_read_node_nbsr_reg(0, NBSR_NODE_CFG_INFO);
	if (v & NBSR_NODE_CFG_INFOR2000P_CfgLockStep)
		return true; /*bug 145528*/

	return false;
}

bool clk_rt_enabled(void)
{
#if DBG_CLK_RT
	pr_warn("clk_rt_enabled e90s_get_cpu_type=%d clk_rt_has_bugs= %d clk_rt_mode= %d num_online_cpus=%d mcst_mb_name=%s\n",
		e90s_get_cpu_type(), clk_rt_has_bugs(), clk_rt_mode,
		num_online_cpus(), mcst_mb_name);
#endif
	/* bug 157387 */
	if (clk_rt_mode == CLK_RT_NO) {
		pr_warn("clk_rt=no -> clocksource clk_rt enabled=false\n");
		return false;
	}
	if (e90s_get_cpu_type() < E90S_CPU_R2000)
		return false;
	if (clk_rt_has_bugs()) {
		pr_warn("clocksource clk_rt enabled=FALSE as clk_rt_has_bugs\n");
		return false;
	}
	return true;
}
EXPORT_SYMBOL(clk_rt_enabled);

noinline int clk_rt_register(void *new_clk_rt_src_arg)
{
	e90s_rt_tick_t clk_rt_v;
	int clk_rt_sec;
	int freq;
	struct timespec ts;
	unsigned long flags;

	/* FIXME add call register_cpu_notifier() for cpu hotplug case */
	/* We want to be far from beginning of next second.
	 */
	if (clk_rt_mode == CLK_RT_RTC) {
		schedule_timeout_interruptible(HZ);
	}
#if DBG_CLK_RT
	pr_warn("clk_rt_register start read_rt_tick= %u.%u div=%u\n",
		read_rt_tick().hi, read_rt_tick().lo, read_rt_div().div);
#endif
	migrate_disable();
	raw_local_irq_save(flags);
	clk_rt_v = read_rt_tick();
	clk_rt_sec = clk_rt_v.hi;
	freq = read_rt_div().div;
	if (clk_rt_sec == 0 || freq == 0) {
		pr_err("CLK_RT: There is no pulse per second signal.\n");
		pr_err("CLK_RT: sec = %d freq = %d\n", clk_rt_sec, freq);
		return 1;
	}
	/* before smp_call_function() wait we are far from PPS */
	delay_until_pps_offset(freq >> 2, freq);
	raw_local_irq_restore(flags);
	migrate_enable();
	while (system_state != SYSTEM_RUNNING) {
#if DBG_CLK_RT
		pr_warn("clk_rt before wr_seconds"
			" cpu=%d rt_tick= %10ld.%9ld"
			" tod %ld system_state=%d\n",
			raw_smp_processor_id(),
			read_rt_tick() >> 32, read_rt_tick() & MASK_32,
			ts.tv_sec, system_state);
#endif
		schedule_timeout_interruptible(3 * HZ);
	}
	getnstimeofday(&ts);
	smp_call_function(clk_rt_wr_seconds, (void *) ts.tv_sec, 1);
	clk_rt_wr_seconds((void *) ts.tv_sec);
	pr_info("clk_rt clocksource registation at cpu %d clk_rt=%d.%09lld sec, getnstod =%ld.%09ld freq=%d Hz\n",
		raw_smp_processor_id(), clk_rt_sec,
		(long long)clk_rt_v.lo * NSEC_PER_SEC / freq,
		ts.tv_sec, ts.tv_nsec, freq);
	/* timeout 2 second after seconds writing into CLK_RT
	   until rt_div will be correct */
	schedule_timeout_interruptible(3 * HZ);
	smp_call_function(set_soft_ok, NULL, 1);
	set_soft_ok(NULL);
	clk_rt_sched_offset = sched_clock() - read_clk_rt(NULL);
	/* clk_rt_initialized should be set after clk_rt_sched_offset */
	smp_wmb();
	clk_rt_initialized = 1;
	clk_rt_clocksource_register();
	return 0;
}
EXPORT_SYMBOL(clk_rt_register);

/* Scheduler clock - returns current time in nanosec units. */
unsigned long long sched_clock(void)
{
	if (likely(clk_rt_initialized)) {
		return clk_rt_sched_offset + read_clk_rt(NULL);
	}
	return (unsigned long long) (jiffies - INITIAL_JIFFIES) * (NSEC_PER_SEC / HZ);
}
#endif /* E90S */
