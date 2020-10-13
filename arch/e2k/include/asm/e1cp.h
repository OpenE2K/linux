#ifndef _ASM_E1CP_H_
#define _ASM_E1CP_H_

#include <linux/init.h>
#include <asm/e3s.h>

#define	E1CP_CPU_VENDOR		E3S_CPU_VENDOR
#define	E1CP_CPU_FAMILY		E3S_CPU_FAMILY

extern void __init boot_e1cp_setup_arch(void);
extern void __init e1cp_setup_machine_rev(void);
extern void __init e1cp_setup_arch(void);
extern void __init e1cp_setup_machine(void);

/*
 * Machine (based on e1c+ processor) topology:
 * e1c+ is one core CPU + graphical processor to support 3D, so
 * - is not NUMA system
 * - is not SMP system
 */

#define	e1cp_cpu_to_node(cpu)		(0)
#define	e1cp_node_to_cpumask(node, main_cpu_mask)	\
		(main_cpu_mask)
#define	e1cp_node_to_first_cpu(node, main_cpu_mask)	\
		(0)	/* only single CPU #0 */

#define	boot_e1cp_cpu_to_node(cpu)	e1cp_cpu_to_node(cpu)
#define	boot_e1cp_node_to_cpumask(node, boot_main_cpu_mask)		\
					(boot_main_cpu_mask)

/*
 * IO links, IO controllers, PCI CFG topology
 */
#define	E1CP_MAX_NODE_IOLINKS	1	/* CPU can has one IO link */
					/* (with two physical channels) */
					/* connected to IOHUB or RDMA */
#define	E1CP_MAX_NUMIOLINKS	(E1CP_MAX_NODE_IOLINKS * 1)

#define	E1CP_NODE_IOLINKS	E1CP_MAX_NODE_IOLINKS

#define e1cp_domain_pci_conf_base(domain) (E1CP_PCICFG_AREA_PHYS_BASE)

#endif /* _ASM_E1CP_H_ */
