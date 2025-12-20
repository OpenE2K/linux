/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/kvm/cpu_hv_regs_access.h>
#include <asm/kvm/mmu_hv_regs_access.h>
#include <asm/machdep.h>

u32 read_SH_CORE_MODE_v6(void)
{
	return READ_SH_CORE_MODE_REG_VALUE();
}
static void write_SH_CORE_MODE_v6(u32 value)
{
	WRITE_SH_CORE_MODE_REG_VALUE(value);
}
static u64 read_SH_PSHTP_v6(void)
{
	return READ_SH_PSHTP_REG_VALUE();
}
static void write_SH_PSHTP_v6(u64 value)
{
	WRITE_SH_PSHTP_REG_VALUE(value);
}
u32 read_SH_PCSHTP_v6(void)
{
	return READ_SH_PCSHTP_REG_SVALUE();
}
static void write_SH_PCSHTP_v6(u32 value)
{
	WRITE_SH_PCSHTP_REG_SVALUE(value);
}
static u64 read_SH_WD_v6(void)
{
	return READ_SH_WD_REG_VALUE();
}
static void write_SH_WD_v6(u64 value)
{
	WRITE_SH_WD_REG_VALUE(value);
}

static u64 read_SH_OSR0_v6(void)
{
	return READ_SH_OSR0_REG_VALUE();
}
static void write_SH_OSR0_v6(u64 value)
{
	WRITE_SH_OSR0_REG_VALUE(value);
}

static u64 read_VIRT_CTRL_MU_v6(void)
{
	return READ_VIRT_CTRL_MU_REG().word;
}
static void write_VIRT_CTRL_MU_v6(u64 value)
{
	WRITE_VIRT_CTRL_MU_REG_VALUE(value);
}

static u64 read_GID_v6(void)
{
	return READ_GID_REG_VALUE();
}
static void write_GID_v6(u64 value)
{
	WRITE_GID_REG_VALUE(value);
}

static u64 read_GP_VPTB_v6(void)
{
	return READ_GP_VPTB_REG_VALUE();
}
static void write_GP_VPTB_v6(u64 value)
{
	WRITE_GP_VPTB_REG_VALUE(value);
}

static u64 read_GP_PPTB_v6(void)
{
	return READ_GP_PPTB_REG_VALUE();
}
static void write_GP_PPTB_v6(u64 value)
{
	WRITE_GP_PPTB_REG_VALUE(value);
}

static u64 read_SH_OS_PPTB_v6(void)
{
	return READ_SH_OS_PPTB_REG_VALUE();
}
static void write_SH_OS_PPTB_v6(u64 value)
{
	WRITE_SH_OS_PPTB_REG_VALUE(value);
}

static u64 read_SH_OS_VPTB_v6(void)
{
	return READ_SH_OS_VPTB_REG_VALUE();
}
static void write_SH_OS_VPTB_v6(u64 value)
{
	WRITE_SH_OS_VPTB_REG_VALUE(value);
}

static u64 read_SH_OS_VAB_v6(void)
{
	return READ_SH_OS_VAB_REG_VALUE();
}
static void write_SH_OS_VAB_v6(u64 value)
{
	WRITE_SH_OS_VAB_REG_VALUE(value);
}

static u64 read_G_W_IMASK_MMU_CR_v6(void)
{
	return READ_G_W_IMASK_MMU_CR_REG_VALUE();
}
static void write_G_W_IMASK_MMU_CR_v6(u64 value)
{
	WRITE_G_W_IMASK_MMU_CR_REG_VALUE(value);
}

static u64 read_SH_PID_v6(void)
{
	return READ_SH_PID_REG_VALUE();
}
static void write_SH_PID_v6(u64 value)
{
	WRITE_SH_PID_REG_VALUE(value);
}

static u64 read_SH_MMU_CR_v6(void)
{
	return READ_SH_MMU_CR_REG_VALUE();
}
static void write_SH_MMU_CR_v6(u64 value)
{
	WRITE_SH_MMU_CR_REG_VALUE(value);
}

void kvm_host_machine_setup_regs_v6(host_machdep_t *machine)
{
	machine->read_SH_CORE_MODE = &read_SH_CORE_MODE_v6;
	machine->write_SH_CORE_MODE = &write_SH_CORE_MODE_v6;
	machine->read_SH_PSHTP = &read_SH_PSHTP_v6;
	machine->write_SH_PSHTP = &write_SH_PSHTP_v6;
	machine->read_SH_PCSHTP = &read_SH_PCSHTP_v6;
	machine->write_SH_PCSHTP = &write_SH_PCSHTP_v6;
	machine->read_SH_WD = &read_SH_WD_v6;
	machine->write_SH_WD = &write_SH_WD_v6;
	machine->read_SH_OSR0 = &read_SH_OSR0_v6;
	machine->write_SH_OSR0 = &write_SH_OSR0_v6;
	machine->read_VIRT_CTRL_MU = &read_VIRT_CTRL_MU_v6;
	machine->write_VIRT_CTRL_MU = &write_VIRT_CTRL_MU_v6;
	machine->read_GID = &read_GID_v6;
	machine->write_GID = &write_GID_v6;
	machine->read_GP_VPTB = &read_GP_VPTB_v6;
	machine->write_GP_VPTB = &write_GP_VPTB_v6;
	machine->read_GP_PPTB = &read_GP_PPTB_v6;
	machine->write_GP_PPTB = &write_GP_PPTB_v6;
	machine->read_SH_OS_PPTB = &read_SH_OS_PPTB_v6;
	machine->write_SH_OS_PPTB = &write_SH_OS_PPTB_v6;
	machine->read_SH_OS_VPTB = &read_SH_OS_VPTB_v6;
	machine->write_SH_OS_VPTB = &write_SH_OS_VPTB_v6;
	machine->read_SH_OS_VAB = &read_SH_OS_VAB_v6;
	machine->write_SH_OS_VAB = &write_SH_OS_VAB_v6;
	machine->read_G_W_IMASK_MMU_CR = &read_G_W_IMASK_MMU_CR_v6;
	machine->write_G_W_IMASK_MMU_CR = &write_G_W_IMASK_MMU_CR_v6;
	machine->read_SH_PID = &read_SH_PID_v6;
	machine->write_SH_PID = &write_SH_PID_v6;
	machine->read_SH_MMU_CR = &read_SH_MMU_CR_v6;
	machine->write_SH_MMU_CR = &write_SH_MMU_CR_v6;
}
