/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_v2p.h>

#include <linux/kernel.h>
#include <asm/cpu_regs.h>
#include <asm/e2k.h>
#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_console.h>

#undef  BOOT_DEBUG_SIC_MODE
#undef  BootDebugSIC
#define	BOOT_DEBUG_SIC_MODE	0	/* SIC mapping & init */
#define	BootDebugSIC(fmt, args...)					\
		({ if (BOOT_DEBUG_SIC_MODE)				\
			dump_printk(fmt, ##args); })

unsigned int boot_get_e2k_machine_id(void)
{
	e2k_idr_t idr;
	unsigned int mdl;
	unsigned int mach_id;

	idr = boot_read_IDR_reg();
	mdl = idr.IDR_mdl;
	BootDebugSIC("boot_get_e2k_machine_id() CPU model is %d, IDR 0x%llx\n",
		mdl, idr.IDR_reg);
	if (mdl == IDR_E2S_MDL) {
		mach_id = MACHINE_ID_E2S;
	} else if (mdl == IDR_E8C_MDL) {
		mach_id = MACHINE_ID_E8C;
	} else if (mdl == IDR_E1CP_MDL) {
		mach_id = MACHINE_ID_E1CP;
	} else if (mdl == IDR_E8C2_MDL) {
		mach_id = MACHINE_ID_E8C2;
	} else if (mdl == IDR_E12C_MDL) {
		mach_id = MACHINE_ID_E12C;
	} else if (mdl == IDR_E16C_MDL) {
		mach_id = MACHINE_ID_E16C;
	} else if (mdl == IDR_E2C3_MDL) {
		mach_id = MACHINE_ID_E2C3;
	} else if (mdl == IDR_E48C_MDL) {
		mach_id = MACHINE_ID_E48C;
	} else if (mdl == IDR_E8V7_MDL) {
		mach_id = MACHINE_ID_E8V7;
	} else {
		BootDebugSIC("Undefined CPU model number %d\n", mdl);
		return MACHINE_ID_NONE;
	}

	return mach_id;
}

void boot_e2k_sic_setup_arch(void)
{
	if (BOOT_HAS_MACHINE_E2K_FULL_SIC) {
		boot_machine.io_area_base = E2K_FULL_SIC_IO_AREA_PHYS_BASE;
		boot_machine.io_area_size = E2K_FULL_SIC_IO_AREA_SIZE;
	} else if (BOOT_HAS_MACHINE_E2K_LEGACY_SIC) {
		boot_machine.io_area_base =
			E2K_LEGACY_SIC_IO_AREA_PHYS_BASE;
		boot_machine.io_area_size = E2K_LEGACY_SIC_IO_AREA_SIZE;
	} else {
		do_boot_printk("boot_e2k_sic_setup_arch(): this machine does not have SIC\n");
	}
	boot_machine.native_rev = boot_read_IDR_reg().IDR_rev;
}

