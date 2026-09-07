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
#include <asm/kvm/guest/boot.h>


#ifdef CONFIG_KVM_PARAVIRTUALIZATION
/*
 * Host kernel is using some additional global registers to support
 * virtualization and guest kernel
 * So it need save/restore these registers
 */

notrace __interrupt
void kvm_guest_save_local_gregs_v3(local_gregs_t *gregs, bool is_signal)
{
	gregs->bgr = native_read_BGR_reg();
	init_BGR_reg();		/* enable whole GRF */
	if (is_signal)
		DO_SAVE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V3(gregs->g);
	native_write_BGR_reg(gregs->bgr);
}

notrace __interrupt void kvm_guest_save_gregs_v3(e2k_global_regs_t *gregs)
{
	gregs->bgr = native_read_BGR_reg();
	init_BGR_reg();		/* enable whole GRF */
	DO_SAVE_GUEST_GREGS_EXCEPT_KERNEL_V3(gregs->g);
	native_write_BGR_reg(gregs->bgr);
}

notrace __interrupt
void kvm_guest_restore_gregs_v3(const e2k_global_regs_t *gregs)
{
	init_BGR_reg();		/* enable whole GRF */
	DO_RESTORE_GUEST_GREGS_EXCEPT_KERNEL_V3(gregs->g);
	native_write_BGR_reg(gregs->bgr);
}

notrace __interrupt
void kvm_guest_restore_local_gregs_v3(const local_gregs_t *gregs,
					  bool is_signal)
{
	init_BGR_reg();
	if (is_signal)
		DO_RESTORE_GUEST_LOCAL_GREGS_EXCEPT_KERNEL_V3(gregs);
	native_write_BGR_reg(gregs->bgr);
}
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
