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
	int new_nesting;

	preempt_disable();

	raw_all_irq_save(flags);
	new_nesting = __this_cpu_inc_return(nesting);

	if (likely(new_nesting == 1)) {
		current->thread.sw_regs.fpu.fpcr = read_FPCR_reg();
		current->thread.sw_regs.fpu.fpsr = read_FPSR_reg();
		current->thread.sw_regs.fpu.pfpfr = read_PFPFR_reg();

		INIT_FPU_REGISTERS();
	}
	raw_all_irq_restore(flags);
}
EXPORT_SYMBOL(kernel_fpu_begin);

void kernel_fpu_end(void)
{
	unsigned long flags;
	int new_nesting;

	raw_all_irq_save(flags);
	new_nesting = __this_cpu_dec_return(nesting);

	if (likely(new_nesting == 0)) {
		write_FPCR_reg(current->thread.sw_regs.fpu.fpcr);
		write_FPSR_reg(current->thread.sw_regs.fpu.fpsr);
		write_PFPFR_reg(current->thread.sw_regs.fpu.pfpfr);
	}
	raw_all_irq_restore(flags);

	preempt_enable();
}
EXPORT_SYMBOL(kernel_fpu_end);
