#pragma once

#include <asm/sic_regs_access.h>
#include <asm/p2v/boot_smp.h>

static __always_inline void boot_wait_for_flush_v5_L3(unsigned char *node_nbsr)
{
	l3_ctrl_t l3_ctrl;

	/* waiting for flush completion */
	do {
		boot_cpu_relax();
		l3_ctrl.E2K_L3_CTRL_reg =
			boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_ctrl);
	} while (l3_ctrl.E2K_L3_CTRL_fl != 0);
}

static __always_inline void boot_wait_for_flush_v4_L3(unsigned char *node_nbsr)
{
	l3_reg_t l3_diag;

	/* waiting for flush completion */
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b0_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b1_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b2_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b3_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b4_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b5_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b6_diag_dw);
	l3_diag = boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_b7_diag_dw);

	__E2K_WAIT_ALL;
}

static __always_inline void boot_native_flush_L3(int iset_ver,
		unsigned char *node_nbsr)
{
	l3_ctrl_t l3_ctrl;

	if (iset_ver < E2K_ISET_V4)
		/* cache L3 is absent */
		return;

	/* set bit of L3 control register to flash L3 */
	l3_ctrl.E2K_L3_CTRL_reg =
		boot_do_sic_read_node_nbsr_reg(node_nbsr, SIC_l3_ctrl);
	l3_ctrl.E2K_L3_CTRL_fl = 1;
	boot_do_sic_write_node_nbsr_reg(node_nbsr, SIC_l3_ctrl,
					l3_ctrl.E2K_L3_CTRL_reg);

	/* waiting for flush completion */
	if (iset_ver > E2K_ISET_V4)
		boot_wait_for_flush_v5_L3(node_nbsr);
	else
		boot_wait_for_flush_v4_L3(node_nbsr);
}

