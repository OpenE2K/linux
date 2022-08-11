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
	boot_machine.nbsr_area_offset = E2S_NBSR_AREA_OFFSET;
	boot_machine.nbsr_area_size = E2S_NBSR_AREA_SIZE;
	boot_machine.copsr_area_phys_base = E2S_COPSR_AREA_PHYS_BASE;
	boot_machine.copsr_area_size = E2S_COPSR_AREA_SIZE;
	boot_machine.mlt_size = E2S_MLT_SIZE;
	boot_machine.tlb_lines_bits_num = E2S_TLB_LINES_BITS_NUM;
	boot_machine.tlb_addr_line_num = E2S_TLB_ADDR_LINE_NUM;
	boot_machine.tlb_addr_line_num2 = E2S_TLB_ADDR_LINE_NUM2;
	boot_machine.tlb_addr_line_num_shift2 = E2S_TLB_ADDR_LINE_NUM_SHIFT2;
	boot_machine.tlb_addr_set_num = E2S_TLB_ADDR_SET_NUM;
	boot_machine.tlb_addr_set_num_shift = E2S_TLB_ADDR_SET_NUM_SHIFT;
	boot_machine.sic_mc_size = E2S_SIC_MC_SIZE;
	boot_machine.sic_mc_count = E2S_SIC_MC_COUNT;
	boot_machine.sic_mc1_ecc = E2S_SIC_MC1_ECC;
	boot_machine.sic_io_str1 = SIC_io_str_hi;
}

