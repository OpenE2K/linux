/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of sclkr clocksource.
 */

#include <linux/percpu.h>
#include <linux/clocksource.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/kernel.h>
#include <linux/rtc.h>
#include <asm/sclkr.h>

/* #define SET_SCLKR_TIME1970 */

#define SCLKR_LO	0xffffffff
#define SCLKM1_DIV	0xffffffff
/* OS may write in SCLKM1_DIV field */
#define SCLKM1_MDIV	0x100000000LL
/* external mode field */
#define SCLKM1_EXT	0x200000000LL
/* training mode field will unset by hardware on 2-nd pulse */
#define SCLKM1_TRN	0x400000000LL
/* software field is set if sclkr is correct */
#define SCLKM1_SW_OK	0x800000000LL
#define SCLKR_DFLT_HZ	0x0773593f /* 125 MHz */

notrace __interrupt __section(".entry.text")
u64 fast_syscall_read_sclkr(void)
{
	u64 sclkr;
	u32 freq;
	struct thread_info *const ti = read_CURRENT_reg_value();
	e2k_sclkm1_t sclkm1;
	sclkr = read_SCLKR_reg_value();
	sclkm1 = read_SCLKM1_reg();
	freq = sclkm1.div;

	if (unlikely(sclkr_mode != SCLKR_INT && !sclkm1.mode ||
		     !sclkm1.sw || !freq))
		return 0;
	return sclkr2ns(sclkr, freq, true);
}
