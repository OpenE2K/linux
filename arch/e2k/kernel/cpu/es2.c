#include <asm/p2v/boot_head.h>
#include <asm/e2k_sic.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>
#include <asm/machdep_numa.h>

#include <asm-l/hw_irq.h>

static e2k_addr_t es2_get_nsr_area_phys_base(void)
{
	return ES2_NSR_AREA_PHYS_BASE;
}

static void es2_setup_apic_vector_handlers(void)
{
#if defined(CONFIG_ELDSP) || defined(CONFIG_ELDSP_MODULE)
	setup_PIC_vector_handler(LVT3_INTERRUPT_VECTOR, eldsp_interrupt, 1,
		"eldsp_interrupt");
#endif
}

static void __init_recv
es2_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	strncpy(cpu_info->vendor, ELBRUS_CPU_VENDOR, 16);
	cpu_info->family = ELBRUS_S_ISET;
	cpu_info->model  = IDR.IDR_mdl;
	cpu_info->revision = IDR.IDR_rev;
}

static void __init
es2_setup_arch(void)
{
	int nid;

	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->setup_cpu_info = es2_setup_cpu_info;
	}
}

void __init
es2_setup_machine(void)
{
	int nid;

	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->setup_arch = es2_setup_arch;
		the_node_machine(nid)->arch_reset = NULL;
		the_node_machine(nid)->arch_halt = NULL;
		the_node_machine(nid)->get_irq_vector = apic_get_vector;
		the_node_machine(nid)->get_nsr_area_phys_base =
				es2_get_nsr_area_phys_base;
		the_node_machine(nid)->setup_apic_vector_handlers =
				es2_setup_apic_vector_handlers;
	}
}
