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

/* For kernel 4.9: */
#define READ_SSCLKR_REG()	READ_SCLKR_REG()
#define READ_SSCLKM1_REG()	READ_SCLKM1_REG()
#define READ_SSCLKM3_REG()	READ_SCLKM3_REG()
#define READ_SCURRENT_REG()	READ_CURRENT_REG()

notrace __interrupt __section(".entry.text")
u64 fast_syscall_read_sclkr(void)
{
	u64 sclkr;
	u32 freq;
	struct thread_info *const ti = READ_SCURRENT_REG();
	e2k_sclkm1_t sclkm1;
#ifdef DEBUG_SCLKR_FREQ
	u32 this_prev_freq;
	u32 *prev_freq_ptr;

	prev_freq_ptr = &per_cpu(prev_freq, ti->cpu);
	this_prev_freq = *prev_freq_ptr;
#endif
	sclkr = READ_SSCLKR_REG();
	sclkm1 = READ_SSCLKM1_REG();
	freq = sclkm1.div;

	if (unlikely(sclkr_mode != SCLKR_INT && !sclkm1.mode ||
		     !sclkm1.sw || !freq))
		return 0;
#ifdef DEBUG_SCLKR_FREQ
	if (unlikely(abs(this_prev_freq - freq) >
		     (this_prev_freq >> OSCIL_JIT_SHFT)))
		freq = basic_freq_hz;
	*prev_freq_ptr = freq;
#endif

	return sclkr2ns(sclkr, freq, true);
}
