/*
 * LMS simulator's hardware implementation dependant procedures.
 */

#include <asm/apic.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/lms.h>
#include <asm/e3m.h>
#include <asm/iolinkmask.h>
#include <asm/machdep.h>
#include <asm/mas.h>
#include <asm/boot_head.h>
#include <asm/io.h>
#include <asm/console.h>

void __init
boot_e3m_lms_setup_arch(void)
{
	boot_machine.x86_io_area_base = E3M_X86_IO_AREA_PHYS_BASE;
	boot_machine.rev = E3M_LMS_CPU_REVISION;
	boot_machine.iset_ver = ELBRUS_ISET;
}

static void
e3m_lms_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	strncpy(cpu_info->vendor, E3M_LMS_CPU_VENDOR, 16);
	cpu_info->family = E3M_LMS_CPU_FAMILY;
	cpu_info->model  = E3M_LMS_CPU_MODEL;
	cpu_info->revision = E3M_LMS_CPU_REVISION;
	cpu_info->L1_size = E3M_LMS_L1_CACHE_SIZE;
	cpu_info->L1_bytes = E3M_LMS_L1_CACHE_BYTES;
	cpu_info->L2_size = E3M_LMS_L2_CACHE_SIZE;
	cpu_info->L2_bytes = E3M_LMS_L2_CACHE_BYTES;
}

/*
 * If kernel was loaded by binary compilator (flash image on lms)
 * it set protection bits in North Bridge
 * Clear all protection bits in IO chip
 */
#define	E3M_BINCO_PROT_R0	0xfff8000000UL
#define	E3M_BINCO_PROT_R1	0xfff8000004UL
#define	E3M_BINCO_PROT_R2	0xfff8000008UL
#define	E3M_BINCO_PROT_R3	0xfff800000cUL
#define	E3M_BINCO_PROT_R4	0xfff8000010UL
#define	E3M_BINCO_PROT_R5	0xfff8000014UL
#define	E3M_BINCO_PROT_R6	0xfff8000018UL
#define	E3M_BINCO_PROT_R7	0xfff800001cUL

extern void inline
e3m_lms_clear_binco_prot(void)
{
	/* Clear all binary compiler protection maps */
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R0, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R1, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R2, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R3, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R4, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R5, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R6, 0, MAS_IOADDR);
	E2K_WRITE_MAS_W(E3M_BINCO_PROT_R7, 0, MAS_IOADDR);
}

static void
e3m_reset_machine(void)
{
	outb(6, 0xcf9);
}

static void
e3m_halt_machine(void)
{
	printk("Hardware support to power off is not until supported by "
		"kernel, so use manual mode\n");
}

#ifdef CONFIG_IOHUB_DOMAINS
/*
 * This e3m machine has not IO link and is connect to PIIX4 controller
 * through North breadge, so it has only one IO bus and PCI domain # 0
 */
void __init
e3m_lms_create_io_config(void)
{
	char src_buffer[80];
	char *buffer = src_buffer;

	iolinks_num = 1;
	iohub_set(0, iolink_iohub_map);
	iohub_set(0, iolink_online_iohub_map);
	iolink_iohub_num = 1;
	iolink_online_iohub_num = 1;
	buffer += iolinkmask_scnprintf(buffer, 80, iolink_online_iohub_map);
	buffer[0] = '\0';
}
#endif /* CONFIG_IOHUB_DOMAINS */

void __init
e3m_lms_setup_arch(void)
{
	int nid;

	e2k_setup_arch();
	for_each_node_has_dup_kernel(nid) {
		the_node_machine(nid)->iset		= NULL;
		the_node_machine(nid)->setup_arch	= e3m_lms_setup_arch;
		the_node_machine(nid)->setup_cpu_info	=
						e3m_lms_setup_cpu_info;
		the_node_machine(nid)->arch_reset	= e3m_reset_machine;
		the_node_machine(nid)->arch_halt	= e3m_halt_machine;
		the_node_machine(nid)->get_irq_vector	= e3m_get_vector;
	}

#ifdef CONFIG_IOHUB_DOMAINS
	e3m_lms_create_io_config();
#endif /* CONFIG_IOHUB_DOMAINS */
	e3m_lms_clear_binco_prot();
}
