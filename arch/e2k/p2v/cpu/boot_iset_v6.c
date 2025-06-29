/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_api.h>
#include <asm/mmu_regs.h>
#include <asm/kvm/hypercall.h>

unsigned long boot_rrd_v6(int reg)
{
	switch (reg) {
	case E2K_REG_HCEM:
		return native_read_HCEM_reg_value();
	case E2K_REG_HCEB:
		return native_read_HCEB_reg_value();
	case E2K_REG_OSCUTD:
		return AW(native_read_OSCUTD_reg());
	case E2K_REG_OSCUIR:
		return AW(native_read_OSCUIR_reg());
	}

	return 0;
}

void boot_rwd_v6(int reg, unsigned long value)
{
	switch (reg) {
	case E2K_REG_HCEM:
		native_write_HCEM_reg_value(value);
		return;
	case E2K_REG_HCEB:
		native_write_HCEB_reg_value(value);
		return;
	case E2K_REG_OSCUTD:
		native_write_OSCUTD_reg(TOS(e2k_cutd_t, value));
		return;
	case E2K_REG_OSCUIR:
		native_write_OSCUIR_reg(TOS(e2k_cuir_t, value));
		return;
	}
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

#ifdef CONFIG_KVM_GUEST_HW_HCALL
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
	e2k_upsr_t upsr_before, upsr_after;

	upsr_before = native_read_UPSR_reg();
	ret = E2K_HCALL(LINUX_HCALL_GENERIC_TRAPNUM, nr, 7,
			arg1, arg2, arg3, arg4, arg5, arg6, arg7);
	upsr_after = native_read_UPSR_reg();
	WARN_ON_ONCE(upsr_before.word != upsr_after.word);
	return ret;
}
#endif
