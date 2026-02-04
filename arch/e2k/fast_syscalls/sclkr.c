/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains implementation of sclkr clocksource for fast system calls.
 */

#include <linux/kernel.h>
#include <asm/sclkr.h>

#define SCLKR_DFLT_HZ	0x0773593f /* 125 MHz */

notrace __interrupt __section(".entry.text")
u64 fast_syscall_read_sclkr(void)
{
	e2k_sclkr_t sclkr = read_SCLKR_reg();
	e2k_sclkm1_t sclkm1 = read_SCLKM1_reg();

	return sclkr2ns(sclkr, sclkm1);
}
