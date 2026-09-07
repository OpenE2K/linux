/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define BUILD_CPUHAS_INITIALIZERS
#include <linux/init.h>
#include <asm/cpu_features.h>
#include <asm/cpu_regs.h>
#include <asm/errno.h>
#include <asm/machdep.h>

machdep_t machine = { 0 };

unsigned long cpu_features[(NR_CPU_FEATURES + 63) / 64];

static int cpu_to_iset(int cpu)
{
	int iset = -EINVAL;

	switch (cpu) {
	case IDR_E2S_MDL:
		iset = ELBRUS_2S_ISET;
		break;
	case IDR_E8C_MDL:
		iset = ELBRUS_8C_ISET;
		break;
	case IDR_E1CP_MDL:
		iset = ELBRUS_1CP_ISET;
		break;
	case IDR_E8C2_MDL:
		iset = ELBRUS_8C2_ISET;
		break;
	case IDR_E12C_MDL:
		iset = ELBRUS_12C_ISET;
		break;
	case IDR_E16C_MDL:
		iset = ELBRUS_16C_ISET;
		break;
	case IDR_E2C3_MDL:
		iset = ELBRUS_2C3_ISET;
		break;
	case IDR_E8V7_MDL:
		iset = ELBRUS_8V7_ISET;
		break;
	}

	return iset;
}

__visible int machdep_setup_features(int cpu, int revision)
{
	int iset_ver = cpu_to_iset(cpu);
	cpuhas_initcall_t *fn, *start, *end;
	bool is_hardware_guest;
	unsigned long image_start, load_offset;

	if (iset_ver < 0)
		return iset_ver;

	if (IS_ENABLED(CONFIG_KVM_GUEST_KERNEL))
		is_hardware_guest = false;
	else
		is_hardware_guest = native_read_CORE_MODE_reg().gmi;

	image_start = read_OSCUD_reg().Base;
	load_offset = image_start - 0x10000;

	start = (cpuhas_initcall_t *) __cpuhas_initcalls;
	end = (cpuhas_initcall_t *) __cpuhas_initcalls_end;
	for (fn = start; fn < end; fn++)
		((cpuhas_initcall_t) ((void *) *fn + load_offset))(cpu, revision,
				iset_ver, cpu, is_hardware_guest, cpu_features);

	return 0;
}
