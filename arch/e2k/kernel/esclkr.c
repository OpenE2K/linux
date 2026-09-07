/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

/*
 * This file contains implementation of esclk clocksource.
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
#include <linux/timex.h>
#include <asm/sic_regs_access.h>
#include <asm/pic.h>
#include <asm/nmi.h>
#include <asm/e2k_api.h>
#include <asm/sclkr.h>
#include <asm/sic_regs.h>

#define ESCLKR_STROB_INTRV	(1LL << 29)
#define STROB_MASK		(ESCLKR_STROB_INTRV - 1)

#define WRITE_ESCLKR_PROC(node, cmd_val)	\
	sic_write_node_nbsr_reg(node, SIC_esclkr, cmd_val);
#define RESET_CMD	0x80000000LL
#define MASTER_CMD	0xc0000000LL

static int redo_esclk_reset = 0;
static int esclkr_no = 0;
bool esclk_initialized __ro_after_init = false;
static unsigned long long esclk_step = 10 << 27;	/* hw default step for esclk_clk 100 MHz */

static int __init esclkr_setup(char *s)
{
	if (!strcmp(s, "no")) {
		esclkr_no = 1;
	}
	return 1;
}
__setup("esclkr=", esclkr_setup);

static u64 read_esclk(struct clocksource *cs)
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

unsigned long long mgb2esclkr(u32 etmr_mgb, int mgb_freq, int prev_strob)
{
	u64 t_abs = read_T_ABS();
	u64 t_off = read_T_OFF();

	return ((t_abs - t_off) & ~STROB_MASK) + t_off +
			etmr_mgb * ESCLKR_STROB_INTRV / mgb_freq -
			prev_strob ? ESCLKR_STROB_INTRV : 0;

}
EXPORT_SYMBOL(mgb2esclkr);

static void cpu_esclk_set_t_off(void *arg)
{
	unsigned long long t_offs_nxt = (unsigned long long) arg;

	pr_info("SET OFFS cpu=%d esclk=%llu t_offs cur %llu t_offs nxt=%llu\n",
		raw_smp_processor_id(), read_T_ABS(),
		read_T_OFF(), t_offs_nxt);
	write_T_OFF(t_offs_nxt); /* since RESET_CMD sets esck_rel=0 */
	/* check if regular strob was in reset period */
	if (read_T_ABS() < t_offs_nxt ||
			read_T_ABS() > (t_offs_nxt + ESCLKR_STROB_INTRV)) {
		pr_info("ERR OFFS cpu=%d esclk=%llu t_offs cur %llu lim =%llu\n",
			raw_smp_processor_id(), read_T_ABS(), read_T_OFF(),
			t_offs_nxt + ESCLKR_STROB_INTRV);
		redo_esclk_reset = 1;
	}
}

/* resume_esclk() is used for init as well as for .resume */
static void resume_esclk(struct clocksource *clocksource)
{
	long long t_abs_nxt;	/* t_abs at next strobe */
	long long t_abs_bfr;	/* t_abs before RESET_CMD */
	long long esclk_rel_lo;		/* T_REL_register[(strob_bit-1):0] */
	long long safe_lo1, safe_lo2;
	int node;

	/* if (num_online_nodes() == 1) return; */
	/* unsafe interval is 15/32 or 47% of ESCLKR_STROB_INTRV */
	safe_lo1 = (ESCLKR_STROB_INTRV * 15) >> 5;
	safe_lo2 = ESCLKR_STROB_INTRV - safe_lo1;
	/* set_freezable();   ?  */

redo:	redo_esclk_reset = 0;
	/* We want to be far from strob while prepare and do RESET_CMD.
	 * So different processors will not appear on the different sides
	 * of the strobe
	 */
	for (;;) {
		esclk_rel_lo = (read_T_ABS() - read_T_OFF()) & STROB_MASK;
		if (esclk_rel_lo > safe_lo1 && esclk_rel_lo < safe_lo2)
			break;
		cpu_relax();
	}
	t_abs_nxt = ((read_T_ABS() - read_T_OFF()) & ~STROB_MASK)
			+ ESCLKR_STROB_INTRV + read_T_OFF();
	t_abs_bfr = read_T_ABS();
	if (!IS_HV_GM()) {
		for_each_online_node(node) {
			/* STEP and RESET should be in different writes */
			WRITE_ESCLKR_PROC(node, esclk_step);
			WRITE_ESCLKR_PROC(node, RESET_CMD);
		}
		do { /* wait for reset done ( reset of  T_REL_register) */
			cpu_relax();
		} while (read_T_ABS() > t_abs_bfr);
	}
	cpuidle_pause_and_lock();
	 /* t_offs_nxt==t_abs_nxt since RESET_CMD sets esck_rel=0 */
	on_each_cpu(cpu_esclk_set_t_off, (void *) t_abs_nxt, 1);
	cpuidle_resume_and_unlock();
	if (redo_esclk_reset) {
		pr_info("redo esclk reset cpu %d T_ABS=%lld.%09llu T_ABS_bfr=%lld.%09llu T_ABS_nxt=%lld.%09llu T_OFFS=%lld\n",
			raw_smp_processor_id(),
			read_T_ABS() / 1000000000, read_T_ABS() % 1000000000,
			t_abs_bfr / 1000000000, t_abs_bfr % 1000000000,
			t_abs_nxt / 1000000000, t_abs_nxt % 1000000000,
			read_T_OFF());
		goto redo;
	}
}

struct clocksource clocksource_esclk = {
	.name		= "esclk",
	.rating		= 400,
	.read		= read_esclk,
	.suspend	= NULL,
	.resume		= resume_esclk,
	.mask		= CLOCKSOURCE_MASK(64),
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};

#define DEBUG_ESCLKR_REGISTER	1

static int __init esclk_timer_of_register(struct device_node *np)
{
	if (IS_HV_GM() && !cpu_has(CPU_FEAT_ISET_V7)) {
		/* Hardware prohibits esclkr on old guests,
		 * see description of intc_rr_cu interception. */
		pr_info("esclk is not supported on old guests\n");
		return 0;
	}

	if (esclkr_no) {
		pr_info("esclk=no is set\n");
		return 0;
	}

	clocksource_register_hz(&clocksource_esclk, NSEC_PER_SEC);
	esclk_initialized = true;
#if DEBUG_ESCLKR_REGISTER
	unsigned long long esclk_abs;
	struct timespec64 ts;

	esclk_abs = read_T_ABS();
	ktime_get_real_ts64(&ts);
	pr_info("esclk clocksource registration done esclk_abs=%lld.%09llu sec, getnstod =%lld.%09ld\n",
		esclk_abs / 1000000000, esclk_abs % 1000000000,
		ts.tv_sec, ts.tv_nsec);
#endif
	return 0;
}
TIMER_OF_DECLARE(esclk_timer, "mcst,esclk-timer", esclk_timer_of_register);

void cpuinfo_esclk(struct seq_file *m)
{
	if (use_esclk_sched_clock()) {
		seq_printf(m, " esclk");
	}
}
