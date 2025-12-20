/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/glob_regs.h>
#include <asm/ptrace.h>
#include <asm/regs_state.h>
#include <asm/trap_table.h>
#include <asm/debug_print.h>

/*
 * Host kernel is using some additional global registers to support
 * virtualization and guest kernel
 * So it need save/restore these registers
 */

notrace __interrupt
void kvm_guest_save_local_gregs_v5(struct local_gregs *gregs, bool is_signal)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	if (is_signal)
		DO_SAVE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V5(gregs->g);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace __interrupt
void kvm_guest_save_gregs_v5(struct e2k_global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V5(gregs->g);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace __interrupt
void kvm_guest_save_gregs_dirty_bgr_v5(struct e2k_global_regs *gregs)
{
	gregs->bgr = NATIVE_READ_BGR_REG();
	init_BGR_reg(); /* enable whole GRF */
	DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V5(gregs->g);
}

notrace __interrupt
void kvm_guest_restore_gregs_v5(const e2k_global_regs_t *gregs)
{
	init_BGR_reg();  /* enable whole GRF */
	DO_RESTORE_GUEST_GREGS_EXCEPT_KERNEL_V5(gregs->g);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}

notrace __interrupt
void kvm_guest_restore_local_gregs_v5(const local_gregs_t *gregs,
					bool is_signal)
{
	init_BGR_reg();
	if (is_signal)
		DO_RESTORE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V5(gregs);
	NATIVE_WRITE_BGR_REG(gregs->bgr);
}
