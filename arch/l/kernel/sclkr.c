/*
 * arch/e2k/kernel/sclkr.c
 *
 * This file contains implementation of sclkr clocksource.
 *
 * Copyright (C) 2015 Leonid Ananiev (leoan@mcst.ru)
 */

#include <linux/percpu.h>
#include <linux/clocksource.h>
#include <linux/kthread.h>
#include <asm/bootinfo.h>

#define SCLKR_LO	0xffffffff
#define SCLKM1_DIV	0xffffffff
/* OS may write in SCLKM1_DIV fild */
#define SCLKM1_MDIV	0x100000000LL
/* external mode fiald */
#define SCLKM1_EXT_MODE	0x200000000LL
/* training mode field */
#define SCLKM1_TRN	0x400000000LL
/* software fild is set if sclkr is correct */
#define SCLKM1_SW	0x800000000LL

struct clocksource clocksource_sclkr;
EXPORT_SYMBOL(clocksource_sclkr);

char sclkr_src[SCLKR_SRC_LEN] = "no"; /* no, ext, rtc */

static cycle_t read_sclkr(struct clocksource *cs)
{
	unsigned int sec, freq;
	unsigned long long usec, sclkr_v, sclkm1_v;

	sclkr_v = E2K_GET_DSREG(sclkr);
	sclkm1_v = E2K_GET_DSREG(sclkm1);
	freq = sclkm1_v & SCLKM1_DIV;
	sec = sclkr_v >> 32;
	usec = (unsigned long long)(sclkr_v & SCLKR_LO) * USEC_PER_SEC;
	usec /= freq;
	if ((sclkm1_v & (SCLKM1_EXT_MODE | SCLKM1_SW)) == 0
				&& !sclkr_unstable) {
		sclkr_unstable = 1;
		pr_crit("WARNING: sclkr does not function");
	}
	return sec * USEC_PER_SEC + usec;
}
static void resume_sclkr(struct clocksource *clocksource)
{
	clocksource->cycle_last = 0;
	pr_crit("WARNING: clocksource sclkr resume not implemented. "
		"You should probably adjust offset here.\n");
}

struct clocksource clocksource_sclkr = {
	.name		= "sclkr",
	.rating		= 400,
	.read		= read_sclkr,
	.resume		= resume_sclkr,
	.mask		= CLOCKSOURCE_MASK(64),
	.shift		= 22,
	.flags		= CLOCK_SOURCE_IS_CONTINUOUS,
};
static void sclk_set_extrnal(void *mode_arg)
{
	unsigned long long sclkr_all = E2K_GET_DSREG(sclkr); /* debug */
	unsigned long long old_mod = E2K_GET_DSREG(sclkm1);  /* debug */
	unsigned int freq = E2K_GET_DSREG(sclkm1) & SCLKM1_DIV;
	unsigned long long mode = (unsigned long long) mode_arg;

	E2K_SET_DSREG(sclkm1, mode);
	pr_info("CPU%02d SCLK register %lld.%09lld sec (raw=.%lld),"/* debug */
				"fred=%u Hz, sclkm1=%llx, new_mode=%llx\n",
		raw_smp_processor_id(),
		sclkr_all >> 32,
		(sclkr_all & 0xffffffff) * USEC_PER_SEC / freq,
		sclkr_all & 0xffffffff, freq, old_mod, mode >> 32);
}

static void sclk_set_range(void *range)
{
	E2K_SET_DSREG(sclkm2, (unsigned long long) range);
}

noinline int sclk_register(void *new_sclkr_src)
{
	unsigned int sclkr_lo, sclkr_lo_prev, div_m1;
	unsigned int freq = E2K_GET_DSREG(sclkm1) & SCLKM1_DIV;
	unsigned long long mode, range;
	int retry_n = 0;
#if 0
	int mb_type = bootblock_virt->info.bios.mb_type;
#endif

	if (!strcmp(sclkr_src, "no"))
		return -1;
	strcpy(sclkr_src, new_sclkr_src);
	pr_warning("sclk_register basic_mhz=%d. Check it.\n",
		(freq + 500000) / 1000000);
	/* set min=f/2 and max=2*f */
	range = ((unsigned long long)(freq + (freq >> 1)) << 32) |
					(freq >> 1);
	sclk_set_range((void *)range);
	smp_call_function(sclk_set_range, (void *)range, 1);
	/* We want to be far from beginning of internal second.
	 * So different processors will not appear on the different
	 * parties of seconds border while switching to extrnal.
	 */
retry:
	sclkr_lo = E2K_GET_DSREG(sclkr);
	do {
		sclkr_lo_prev = sclkr_lo;
		sclkr_lo = E2K_GET_DSREG(sclkr);
		if (sclkr_lo_prev == sclkr_lo) {
			pr_err("Error. cpu%02d SCLKR does not run.\n",
				raw_smp_processor_id());
			goto err_sckr;
		}
	} while (sclkr_lo < (freq >> 3) || sclkr_lo > freq - (freq >> 3));
	/* set SCLKM1_SW to indicat that SKLR is correct */
	mode = SCLKM1_SW;
#if 0
	if (mb_type == MB_TYPE_ES4_MBE2S_PC && !strcmp(sclkr_src, "rtc")) {
		/* it is not need in local (from timer fm33256 or cy14b101p)
		 * external mode because of
		 * cores in single CPU are synchronous */
		smp_call_function(sclk_set_extrnal, (void *) mode, 1);
		sclk_set_extrnal((void *) mode);
		return 0;
	}
#endif
	mode |= SCLKM1_EXT_MODE | SCLKM1_TRN;
	smp_call_function(sclk_set_extrnal, (void *) mode, 1);
	sclk_set_extrnal((void *) mode);

	/* Wait for first external signal of second biginig and look at
	 * sclkm1.div (prvious sclkr_lo) to see how far from external
	 * second begining the swinching was. */
	sclkr_lo = E2K_GET_DSREG(sclkr);
	do {
		sclkr_lo_prev = sclkr_lo;
		sclkr_lo = E2K_GET_DSREG(sclkr);
		if (sclkr_lo > freq * 2) {
			pr_err("Error. cpu%02u SCLK: no ext signal.\n",
					raw_smp_processor_id());
			goto err_sckr;
		}
		if (!(E2K_GET_DSREG(sclkm1) & SCLKM1_EXT_MODE)) {
			pr_err("Error. cpu%02u sclkm1 bit 'ext' was cleared."
				"sclkr=%u sclkm1_hi=0x%llx div=%llu\n",
					raw_smp_processor_id(), sclkr_lo,
					E2K_GET_DSREG(sclkm1) >> 32,
					E2K_GET_DSREG(sclkm1) & SCLKM1_DIV);
			goto err_sckr;
		}
	} while (sclkr_lo > sclkr_lo_prev &&
		E2K_GET_DSREG(sclkm1) & SCLKM1_TRN);
	div_m1 = E2K_GET_DSREG(sclkm1) & SCLKM1_DIV;

	pr_info("SCLK register was at %d.%09llu sec, freq=%u Hz, external=%d\n",
		(int)((E2K_GET_DSREG(sclkr) >> 32) - 1),
		(unsigned long long)div_m1 * USEC_PER_SEC / freq, freq,
		!!(E2K_GET_DSREG(sclkm1) & SCLKM1_EXT_MODE));
	if (div_m1 < (freq >> 3) || freq - div_m1 < (freq >> 3)) {
		pr_err("SCLK switchig is too close to seconds border."
			"Retry\n");
		mode = 0;
		smp_call_function(sclk_set_extrnal, (void *) mode, 1);
		sclk_set_extrnal((void *) mode);
		if (retry_n++ < 3) {
			schedule_timeout_interruptible(HZ / 8);
			goto retry;
		}
	}
	schedule_timeout_interruptible(2 * HZ);
	if (E2K_GET_DSREG(sclkm1) & SCLKM1_TRN) {
		pr_err("Error. cpu%02d sclkm1 bit 'trening' was not cleared "
			"by HW.\n",
			raw_smp_processor_id());
			goto err_sckr;
	}
	range = ((unsigned long long)(freq + (freq >> 1)) << 32) |
					(freq >> 1);
	smp_call_function(sclk_set_range, (void *)range, 1);
	sclk_set_range((void *)range);
	clocksource_register(&clocksource_sclkr);
	return 0;
err_sckr:
	mode = 0;
	smp_call_function(sclk_set_extrnal, (void *) mode, 0);
	sclk_set_extrnal((void *) mode);
	strcpy(sclkr_src, "no");
	return -1;
}
EXPORT_SYMBOL(sclk_register);

