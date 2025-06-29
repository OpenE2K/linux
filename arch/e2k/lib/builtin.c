/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/irqflags.h>
#include <asm/cpu_regs.h>
#include <asm/system.h>

noinline notrace void *__e2k_read_kernel_return_address(int n)
{
	e2k_pcsp_t pcsp;
	u64 base;
	s64 cr_ind;
	unsigned long flags, ret;

	raw_all_irq_save(flags);
	NATIVE_FLUSHC;
	pcsp = native_read_PCSP_reg();

	base = PCSP_BASE(pcsp);
	cr_ind = PCSP_IND(pcsp) - (n + 1) * SZ_OF_CR;
	if ((s64) cr_ind < 0) {
		ret = 0UL;
	} else {
		e2k_mem_crs_t *frame = (e2k_mem_crs_t *) (base + cr_ind);
		ret = get_cr0_ip(frame->cr0);
	}
	raw_all_irq_restore(flags);

	return (void *)ret;
}
