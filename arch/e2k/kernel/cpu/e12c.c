/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_head.h>
#include <asm/e2k_sic.h>
#include <asm/pic.h>
#include <asm/processor.h>

#include <asm-l/hw_irq.h>

static e2k_addr_t e12c_get_nsr_area_phys_base(void)
{
	return E12C_NSR_AREA_PHYS_BASE;
}

static void __init_recv
e12c_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	strncpy(cpu_info->vendor, ELBRUS_CPU_VENDOR, 16);
	cpu_info->family = ELBRUS_12C_ISET;
	cpu_info->model  = IDR.IDR_mdl;
	cpu_info->revision = IDR.IDR_rev;
}

static void __init
e12c_setup_arch(void)
{
	machine.setup_cpu_info = e12c_setup_cpu_info;
}

void __init
e12c_setup_machine(void)
{
	machine.setup_arch = e12c_setup_arch;
	machine.arch_reset = NULL;
	machine.arch_halt = NULL;
	machine.get_irq_vector = pic_get_vector;
	machine.get_nsr_area_phys_base = e12c_get_nsr_area_phys_base;
	machine.setup_apic_vector_handlers = NULL;
}
