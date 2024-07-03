/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/sched.h>
#include <asm/fpu/api.h>

static DEFINE_PER_CPU(int, nesting);

void kernel_fpu_begin(void)
{
	unsigned long flags;

	preempt_disable();

	raw_all_irq_save(flags);
	int new_nesting = __this_cpu_inc_return(nesting);

	if (likely(new_nesting == 1)) {
		current->thread.sw_regs.fpu.fpcr = READ_FPCR_REG();
		current->thread.sw_regs.fpu.fpsr = READ_FPSR_REG();
		current->thread.sw_regs.fpu.pfpfr = READ_PFPFR_REG();

		INIT_FPU_REGISTERS();
	}
	raw_all_irq_restore(flags);
}
EXPORT_SYMBOL(kernel_fpu_begin);

void kernel_fpu_end(void)
{
	unsigned long flags;

	raw_all_irq_save(flags);
	int new_nesting = __this_cpu_dec_return(nesting);

	if (likely(new_nesting == 0)) {
		WRITE_FPCR_REG(current->thread.sw_regs.fpu.fpcr);
		WRITE_FPSR_REG(current->thread.sw_regs.fpu.fpsr);
		WRITE_PFPFR_REG(current->thread.sw_regs.fpu.pfpfr);
	}
	raw_all_irq_restore(flags);

	preempt_enable();
}
EXPORT_SYMBOL(kernel_fpu_end);
