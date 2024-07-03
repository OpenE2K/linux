/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_sic.h>
#include <asm/p2v/boot_head.h>

void boot_e8v7_setup_arch(void)
{
	boot_e2k_sic_setup_arch();

	boot_machine.native_iset_ver = ELBRUS_8V7_ISET;
	boot_machine.mmu_pt_v6 = IS_ENABLED(CONFIG_MMU_PT_V6);
	boot_machine.mmu_separate_pt = IS_ENABLED(CONFIG_MMU_SEP_VIRT_SPACE);
	boot_machine.L3_enable = true;
	boot_machine.max_nr_node_cpus = E8V7_MAX_NR_NODE_CPUS;
	boot_machine.nr_node_cpus = E8V7_NR_NODE_CPUS;
	boot_machine.node_iolinks = E8V7_NODE_IOLINKS;
	boot_machine.pcicfg_area_phys_base = E8V7_PCICFG_AREA_PHYS_BASE;
	boot_machine.pcicfg_area_size = E8V7_PCICFG_AREA_SIZE;
	boot_machine.nsr_area_phys_base = E8V7_NSR_AREA_PHYS_BASE;
	boot_machine.sic_mc_size = E8V7_SIC_MC_SIZE;
	boot_machine.sic_mc_count = E8V7_SIC_MC_COUNT;
	boot_machine.sic_mc1_ecc = 0;	/* no MC1_ECC reg */
	boot_machine.sic_io_str1 = 0;	/* no IO_STR1 reg */
	boot_machine.qnr1_offset = E8V7_QNR1_OFFSET;
}

