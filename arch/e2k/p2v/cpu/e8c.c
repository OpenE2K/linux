#include <asm/e2k_sic.h>
#include <asm/p2v/boot_head.h>

void boot_e8c_setup_arch(void)
{
	boot_e2k_sic_setup_arch();

	if (!boot_machine.cmdline_iset_ver)
		boot_machine.native_iset_ver = ELBRUS_8C_ISET;
	boot_machine.mmu_pt_v6 = false;
	boot_machine.mmu_separate_pt = false;
	boot_machine.L3_enable = true;
	boot_machine.max_nr_node_cpus = E8C_MAX_NR_NODE_CPUS;
	boot_machine.nr_node_cpus = E8C_NR_NODE_CPUS;
	boot_machine.node_iolinks = E8C_NODE_IOLINKS;
	boot_machine.pcicfg_area_phys_base = E8C_PCICFG_AREA_PHYS_BASE;
	boot_machine.pcicfg_area_size = E8C_PCICFG_AREA_SIZE;
	boot_machine.nsr_area_phys_base = E8C_NSR_AREA_PHYS_BASE;
	boot_machine.nbsr_area_offset = E8C_NBSR_AREA_OFFSET;
	boot_machine.nbsr_area_size = E8C_NBSR_AREA_SIZE;
	boot_machine.copsr_area_phys_base = E8C_COPSR_AREA_PHYS_BASE;
	boot_machine.copsr_area_size = E8C_COPSR_AREA_SIZE;
	boot_machine.mlt_size = E8C_MLT_SIZE;
	boot_machine.tlb_lines_bits_num = E8C_TLB_LINES_BITS_NUM;
	boot_machine.tlb_addr_line_num = E8C_TLB_ADDR_LINE_NUM;
	boot_machine.tlb_addr_line_num2 = E8C_TLB_ADDR_LINE_NUM2;
	boot_machine.tlb_addr_line_num_shift2 = E8C_TLB_ADDR_LINE_NUM_SHIFT2;
	boot_machine.tlb_addr_set_num = E8C_TLB_ADDR_SET_NUM;
	boot_machine.tlb_addr_set_num_shift = E8C_TLB_ADDR_SET_NUM_SHIFT;
	boot_machine.sic_mc_size = E8C_SIC_MC_SIZE;
	boot_machine.sic_mc_count = E8C_SIC_MC_COUNT;
	boot_machine.sic_mc1_ecc = E8C_SIC_MC1_ECC;
	boot_machine.sic_io_str1 = 0;
}

