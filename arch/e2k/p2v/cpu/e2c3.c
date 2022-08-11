#include <asm/e2k_sic.h>
#include <asm/p2v/boot_head.h>

void boot_e2c3_setup_arch(void)
{
	boot_e2k_sic_setup_arch();

	if (!boot_machine.cmdline_iset_ver)
		boot_machine.native_iset_ver = ELBRUS_2C3_ISET;
#ifdef	CONFIG_MMU_PT_V6
	boot_machine.mmu_pt_v6 = true;
#else
	boot_machine.mmu_pt_v6 = false;
#endif
#ifdef CONFIG_MMU_SEP_VIRT_SPACE
	boot_machine.mmu_separate_pt = true;
#else
	boot_machine.mmu_separate_pt = false;
#endif
	boot_machine.L3_enable = false;	/* no cache L3 */
	boot_machine.max_nr_node_cpus = E2C3_MAX_NR_NODE_CPUS;
	boot_machine.nr_node_cpus = E2C3_NR_NODE_CPUS;
	boot_machine.node_iolinks = E2C3_NODE_IOLINKS;
	boot_machine.pcicfg_area_phys_base = E2C3_PCICFG_AREA_PHYS_BASE;
	boot_machine.pcicfg_area_size = E2C3_PCICFG_AREA_SIZE;
	boot_machine.nsr_area_phys_base = E2C3_NSR_AREA_PHYS_BASE;
	boot_machine.nbsr_area_offset = E2C3_NBSR_AREA_OFFSET;
	boot_machine.nbsr_area_size = E2C3_NBSR_AREA_SIZE;
	boot_machine.copsr_area_phys_base = E2C3_COPSR_AREA_PHYS_BASE;
	boot_machine.copsr_area_size = E2C3_COPSR_AREA_SIZE;
	boot_machine.mlt_size = E2C3_MLT_SIZE;
	boot_machine.tlb_lines_bits_num = E2C3_TLB_LINES_BITS_NUM;
	boot_machine.tlb_addr_line_num = E2C3_TLB_ADDR_LINE_NUM;
	boot_machine.tlb_addr_line_num2 = E2C3_TLB_ADDR_LINE_NUM2;
	boot_machine.tlb_addr_line_num_shift2 = E2C3_TLB_ADDR_LINE_NUM_SHIFT2;
	boot_machine.tlb_addr_set_num = E2C3_TLB_ADDR_SET_NUM;
	boot_machine.tlb_addr_set_num_shift = E2C3_TLB_ADDR_SET_NUM_SHIFT;
	boot_machine.sic_mc_size = E2C3_SIC_MC_SIZE;
	boot_machine.sic_mc_count = E2C3_SIC_MC_COUNT;
	boot_machine.sic_mc1_ecc = 0;	/* no MC1_ECC reg */
	boot_machine.sic_io_str1 = 0;	/* no IO_STR1 reg */
}

