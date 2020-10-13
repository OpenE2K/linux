/*
 * LMS simulator's hardware implementation dependant procedures.
 */

#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/e1cp_lms.h>
#include <asm/e2k_sic.h>
#include <asm/machdep.h>
#include <asm/mas.h>
#include <asm/boot_head.h>
#include <asm/iset.h>

void __init
boot_e1cp_lms_setup_arch(void)
{
	boot_e2k_sic_setup_arch();
	boot_machine.iset_ver = ELBRUS_1CP_ISET;
}

static void
e1cp_lms_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	strncpy(cpu_info->vendor, E1CP_LMS_CPU_VENDOR, 16);
	cpu_info->family = E1CP_LMS_CPU_FAMILY;
	cpu_info->model  = IDR.IDR_mdl;
	cpu_info->revision = IDR.IDR_rev;
	cpu_info->L1_size = E1CP_LMS_L1_CACHE_SIZE;
	cpu_info->L1_bytes = E1CP_LMS_L1_CACHE_BYTES;
	cpu_info->L2_size = E1CP_LMS_L2_CACHE_SIZE;
	cpu_info->L2_bytes = IDR_WBL_TO_BYTES(IDR.IDR_wbl);
}

void __init
e1cp_lms_setup_arch(void)
{
	int nid;

	e2k_setup_arch();
	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->setup_cpu_info = e1cp_lms_setup_cpu_info;
	}
}

void __init
e1cp_lms_setup_machine(void)
{
	int nid;

	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->iset = &iset_e1cp;
		the_node_machine(nid)->setup_arch = e1cp_lms_setup_arch;
		the_node_machine(nid)->arch_reset = NULL;
		the_node_machine(nid)->arch_halt = NULL;
		the_node_machine(nid)->get_irq_vector = e2k_sic_get_vector;
	}
}
