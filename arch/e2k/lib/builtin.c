/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/irqflags.h>
#include <asm/cpu_regs_access.h>
#include <asm/system.h>

noinline notrace void *__e2k_read_kernel_return_address(int n)
{
	e2k_pcsp_lo_t pcsp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	u64 base;
	s64 cr_ind;
	unsigned long flags, ret;

	raw_all_irq_save(flags);
	NATIVE_FLUSHC;
	pcsp_hi = NATIVE_NV_READ_PCSP_HI_REG();
	pcsp_lo = NATIVE_NV_READ_PCSP_LO_REG();

	base = pcsp_lo.base;
	cr_ind = pcsp_hi.ind - (n + 1) * SZ_OF_CR;
	if ((s64) cr_ind < 0) {
		ret = 0UL;
	} else {
		e2k_mem_crs_t *frame = (e2k_mem_crs_t *) (base + cr_ind);
		ret = frame->cr0_hi.ip << 3;
	}
	raw_all_irq_restore(flags);

	return (void *) ret;
}
