#include <asm/e2k_sic.h>
#include <asm/p2v/boot_head.h>

void boot_e12c_setup_arch(void)
{
	boot_e2k_sic_setup_arch();

	if (!boot_machine.cmdline_iset_ver)
		boot_machine.native_iset_ver = ELBRUS_12C_ISET;
#ifdef	CONFIG_MMU_PT_V6
	boot_machine.mmu_pt_v6 = true;
#else	/* ! CONFIG_MMU_PT_V6 */
	boot_machine.mmu_pt_v6 = false;
#endif	/* CONFIG_MMU_PT_V6 */
#ifdef CONFIG_MMU_SEP_VIRT_SPACE
	boot_machine.mmu_separate_pt = true;
#else
	boot_machine.mmu_separate_pt = false;
#endif
	boot_machine.L3_enable = true;
	boot_machine.max_nr_node_cpus = E12C_MAX_NR_NODE_CPUS;
	boot_machine.nr_node_cpus = E12C_NR_NODE_CPUS;
	boot_machine.node_iolinks = E12C_NODE_IOLINKS;
	boot_machine.pcicfg_area_phys_base = E12C_PCICFG_AREA_PHYS_BASE;
	boot_machine.pcicfg_area_size = E12C_PCICFG_AREA_SIZE;
	boot_machine.nsr_area_phys_base = E12C_NSR_AREA_PHYS_BASE;
	boot_machine.nbsr_area_offset = E12C_NBSR_AREA_OFFSET;
	boot_machine.nbsr_area_size = E12C_NBSR_AREA_SIZE;
	boot_machine.copsr_area_phys_base = E12C_COPSR_AREA_PHYS_BASE;
	boot_machine.copsr_area_size = E12C_COPSR_AREA_SIZE;
	boot_machine.mlt_size = E12C_MLT_SIZE;
	boot_machine.tlb_lines_bits_num = E12C_TLB_LINES_BITS_NUM;
	boot_machine.tlb_addr_line_num = E12C_TLB_ADDR_LINE_NUM;
	boot_machine.tlb_addr_line_num2 = E12C_TLB_ADDR_LINE_NUM2;
	boot_machine.tlb_addr_line_num_shift2 = E12C_TLB_ADDR_LINE_NUM_SHIFT2;
	boot_machine.tlb_addr_set_num = E12C_TLB_ADDR_SET_NUM;
	boot_machine.tlb_addr_set_num_shift = E12C_TLB_ADDR_SET_NUM_SHIFT;
	boot_machine.sic_mc_size = 0;
	boot_machine.sic_mc_count = E12C_SIC_MC_COUNT;
	boot_machine.sic_mc1_ecc = E12C_SIC_MC1_ECC;
	boot_machine.sic_io_str1 = 0;
	boot_machine.clock_tick_rate = E12C_CLOCK_TICK_RATE;
}

