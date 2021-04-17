#include <asm/p2v/boot_head.h>
#include <asm/e2k_sic.h>
#include <asm/machdep_numa.h>
#include <asm/pic.h>

static e2k_addr_t e2c3_get_nsr_area_phys_base(void)
{
	return E2C3_NSR_AREA_PHYS_BASE;
}

static void __init_recv
e2c3_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	strncpy(cpu_info->vendor, E2C3_CPU_VENDOR, 16);
	cpu_info->family = E2C3_CPU_FAMILY;
	cpu_info->model  = IDR.IDR_mdl;
	cpu_info->revision = IDR.IDR_rev;
}

static void __init
e2c3_setup_arch(void)
{
	int nid;

	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->setup_cpu_info = e2c3_setup_cpu_info;
	}
}

void __init
e2c3_setup_machine(void)
{
	int nid;

	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->setup_arch = e2c3_setup_arch;
		the_node_machine(nid)->arch_reset = NULL;
		the_node_machine(nid)->arch_halt = NULL;
		the_node_machine(nid)->get_irq_vector = pic_get_vector;
		the_node_machine(nid)->get_nsr_area_phys_base =
				e2c3_get_nsr_area_phys_base;
		the_node_machine(nid)->setup_apic_vector_handlers = NULL;
	}
}
