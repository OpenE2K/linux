#ifndef _ASM_E3S_H_
#define _ASM_E3S_H_

#include <linux/init.h>
#include <asm/mas.h>

#define	E3S_CPU_VENDOR		"Elbrus-MCST"
#define	E3S_CPU_FAMILY		4
#define	E3S_CPU_MODEL		IDR_E3S_MDL

extern void __init boot_e3s_setup_arch(void);
extern void __init e3s_setup_machine_rev(void);
extern void __init e3s_setup_arch(void);
extern void __init e3s_setup_machine(void);

/*
 * Machine (based on e3s processor) topology:
 * e3s is NUMA system on distributed memory and can have as few nodes.
 * Each node has only one CPU and some memory (faster to access)
 * Node number is the same as CPU number.
 * Some nodes (CPUS) can be without memory
 */

#define	E3S_NR_NODE_CPUS		1	/* 1 CPU on each node */
#define	e3s_cpu_to_node(cpu)		(cpu / E3S_NR_NODE_CPUS)
#define	e3s_node_to_cpumask(node, __main_cpu_mask)		\
({								\
	cpumask_t cpu_mask;					\
	cpumask_t node_cpu_mask = CPU_MASK_NONE;		\
	cpumask_t main_cpu_mask = __main_cpu_mask;		\
	cpumask_set_cpu(node, &node_cpu_mask);			\
	cpus_and(cpu_mask, node_cpu_mask, main_cpu_mask);	\
	cpu_mask;						\
})
#define	e3s_node_to_first_cpu(node, __main_cpu_mask)			\
({									\
	cpumask_t node_cpumask;						\
	node_cpumask = e3s_node_to_cpumask(node, __main_cpu_mask);	\
	first_cpu(node_cpumask);					\
})

#define	boot_e3s_cpu_to_node(cpu)	e3s_cpu_to_node(cpu)
#define	boot_e3s_node_to_cpumask(node, boot_main_cpu_mask)		\
		e3s_node_to_cpumask(node, boot_main_cpu_mask)

/*
 * IO links, IO controllers, PCI topology
 */
#define	E3S_MAX_NODE_IOLINKS	1	/* each node can has only one IO link */
					/* connected to IOHUB or RDMA */
#define	E3S_MAX_NUMIOLINKS		(E3S_MAX_NODE_IOLINKS * MAX_NUMNODES)

#define	E3S_NODE_IOLINKS		E3S_MAX_NODE_IOLINKS

#define e3s_domain_pci_conf_base(domain) (E3S_NSR_AREA_PHYS_BASE + \
		E3S_NSR_AREA_SIZE * ((unsigned long) domain) + \
		E3S_PCICFG_AREA_OFFSET)


#endif /* _ASM_E3S_H_ */
