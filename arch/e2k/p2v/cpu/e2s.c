#include <asm/e2k_sic.h>
#include <asm/p2v/boot_head.h>
#include <asm/sic_regs.h>

void boot_e2s_setup_arch(void)
{
	boot_e2k_sic_setup_arch();

	if (!boot_machine.cmdline_iset_ver)
		boot_machine.native_iset_ver = ELBRUS_2S_ISET;
	boot_machine.mmu_pt_v6 = false;
	boot_machine.mmu_separate_pt = false;
	boot_machine.max_nr_node_cpus = E2S_MAX_NR_NODE_CPUS;
	boot_machine.nr_node_cpus = E2S_NR_NODE_CPUS;
	boot_machine.node_iolinks = E2S_NODE_IOLINKS;
	boot_machine.pcicfg_area_phys_base = E2S_PCICFG_AREA_PHYS_BASE;
	boot_machine.pcicfg_area_size = E2S_PCICFG_AREA_SIZE;
	boot_machine.nsr_area_phys_base = E2S_NSR_AREA_PHYS_BASE;
	boot_machine.sic_mc_size = E2S_SIC_MC_SIZE;
	boot_machine.sic_mc_count = E2S_SIC_MC_COUNT;
	boot_machine.sic_mc1_ecc = SIC_mc1_ecc;
	boot_machine.sic_io_str1 = SIC_io_str_hi;
}

