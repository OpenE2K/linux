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
#include <asm/kvm/boot.h>

static u64 read_shadow_dreg_unimpl_v3(void)
{
	pr_err("Shadow register is not implemented on the CPU ISET, called from 0x%lx\n",
	     CALLER_ADDR0);
	return 0;
}

static void write_shadow_dreg_unimpl_v3(u64 value)
{
	pr_err("Shadow register is not implemented on the CPU ISET, called from 0x%lx\n",
	     CALLER_ADDR0);
}

void kvm_host_machine_setup_regs_v3(host_machdep_t *machine)
{
	machine->read_VIRT_CTRL_MU = &read_shadow_dreg_unimpl_v3;
	machine->write_VIRT_CTRL_MU = &write_shadow_dreg_unimpl_v3;
	machine->read_GID = &read_shadow_dreg_unimpl_v3;
	machine->write_GID = &write_shadow_dreg_unimpl_v3;
	machine->read_GP_VPTB = &read_shadow_dreg_unimpl_v3;
	machine->write_GP_VPTB = &write_shadow_dreg_unimpl_v3;
	machine->read_GP_PPTB = &read_shadow_dreg_unimpl_v3;
	machine->write_GP_PPTB = &write_shadow_dreg_unimpl_v3;
	machine->read_SH_OS_PPTB = &read_shadow_dreg_unimpl_v3;
	machine->write_SH_OS_PPTB = &write_shadow_dreg_unimpl_v3;
	machine->read_SH_OS_VPTB = &read_shadow_dreg_unimpl_v3;
	machine->write_SH_OS_VPTB = &write_shadow_dreg_unimpl_v3;
	machine->read_SH_OS_VAB = &read_shadow_dreg_unimpl_v3;
	machine->write_SH_OS_VAB = &write_shadow_dreg_unimpl_v3;
	machine->read_G_W_IMASK_MMU_CR = &read_shadow_dreg_unimpl_v3;
	machine->write_G_W_IMASK_MMU_CR = &write_shadow_dreg_unimpl_v3;
	machine->read_SH_PID = &read_shadow_dreg_unimpl_v3;
	machine->write_SH_PID = &write_shadow_dreg_unimpl_v3;
	machine->read_SH_MMU_CR = &read_shadow_dreg_unimpl_v3;
	machine->write_SH_MMU_CR = &write_shadow_dreg_unimpl_v3;
}

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
