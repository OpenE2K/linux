/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_api.h>
#include <asm/mmu_regs.h>

unsigned long boot_rrd_v6(int reg)
{
	switch (reg) {
	case E2K_REG_HCEM:
		return READ_HCEM_REG();
	case E2K_REG_HCEB:
		return READ_HCEB_REG();
	case E2K_REG_OSCUTD:
		return NATIVE_READ_OSCUTD_REG_VALUE();
	case E2K_REG_OSCUIR:
		return NATIVE_READ_OSCUIR_REG_VALUE();
	}

	return 0;
}

void boot_rwd_v6(int reg, unsigned long value)
{
	switch (reg) {
	case E2K_REG_HCEM:
		WRITE_HCEM_REG(value);
		return;
	case E2K_REG_HCEB:
		WRITE_HCEB_REG(value);
		return;
	case E2K_REG_OSCUTD:
		NATIVE_WRITE_OSCUTD_REG_VALUE(value);
		return;
	case E2K_REG_OSCUIR:
		NATIVE_WRITE_OSCUIR_REG_VALUE(value);
		return;
	}
}

unsigned long light_hw_hypercall(unsigned long nr,
				unsigned long arg1, unsigned long arg2,
				unsigned long arg3, unsigned long arg4,
				unsigned long arg5, unsigned long arg6)
{
	unsigned long ret;

	ret = E2K_HCALL(LINUX_HCALL_LIGHT_TRAPNUM, nr, 6,
			arg1, arg2, arg3, arg4, arg5, arg6);
	return ret;
}

unsigned long generic_hw_hypercall(unsigned long nr,
	unsigned long arg1, unsigned long arg2, unsigned long arg3,
	unsigned long arg4, unsigned long arg5, unsigned long arg6,
	unsigned long arg7)
{
	unsigned long ret;

	ret = E2K_HCALL(LINUX_HCALL_GENERIC_TRAPNUM, nr, 7,
			arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	return ret;
}

unsigned long boot_native_read_MMU_OS_PPTB_reg_value(void)
{
	return BOOT_NATIVE_READ_MMU_OS_PPTB_REG_VALUE();
}
void boot_native_write_MMU_OS_PPTB_reg_value(unsigned long value)
{
	BOOT_NATIVE_WRITE_MMU_OS_PPTB_REG_VALUE(value);
}

unsigned long boot_native_read_MMU_OS_VPTB_reg_value(void)
{
	return BOOT_NATIVE_READ_MMU_OS_VPTB_REG_VALUE();
}
void boot_native_write_MMU_OS_VPTB_reg_value(unsigned long value)
{
	BOOT_NATIVE_WRITE_MMU_OS_VPTB_REG_VALUE(value);
}

unsigned long boot_native_read_MMU_OS_VAB_reg_value(void)
{
	return BOOT_NATIVE_READ_MMU_OS_VAB_REG_VALUE();
}
void boot_native_write_MMU_OS_VAB_reg_value(unsigned long value)
{
	BOOT_NATIVE_WRITE_MMU_OS_VAB_REG_VALUE(value);
}
