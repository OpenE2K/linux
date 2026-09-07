/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_v2p.h>

#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>

notrace unsigned long boot_native_read_IDR_reg_value(void)
{
	return AW(native_read_IDR_reg());
}
