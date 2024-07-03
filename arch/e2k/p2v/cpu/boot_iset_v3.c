/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_v2p.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>

unsigned long boot_rrd_v3(int reg)
{
	return 0;
}

void boot_rwd_v3(int reg, unsigned long value)
{
}

notrace unsigned long boot_native_read_IDR_reg_value()
{
	return NATIVE_READ_IDR_REG_VALUE();
}
