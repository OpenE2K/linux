/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_head.h>
#include <asm/e2k_sic.h>
#include <asm/hb_regs.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>

#include <asm-l/hw_irq.h>

static void e1cp_setup_apic_vector_handlers(void)
{
}

static void __init_recv
e1cp_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	strncpy(cpu_info->vendor, ELBRUS_CPU_VENDOR, 16);
	cpu_info->family = ELBRUS_1CP_ISET;
	cpu_info->model = IDR.mdl;
	cpu_info->revision = IDR.rev;
}

static void __init
e1cp_setup_arch(void)
{
	machine.setup_cpu_info = e1cp_setup_cpu_info;
}

void __init
e1cp_setup_machine(void)
{
	machine.setup_arch = e1cp_setup_arch;
	machine.arch_reset = NULL;
	machine.arch_halt = NULL;
	machine.get_irq_vector = pic_get_vector;
	machine.get_nsr_area_phys_base = early_get_legacy_nbsr_base;
	machine.setup_apic_vector_handlers = e1cp_setup_apic_vector_handlers;
}
