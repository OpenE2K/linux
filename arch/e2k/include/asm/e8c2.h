#ifndef _ASM_E8C2_H_
#define _ASM_E8C2_H_

#include <linux/init.h>
#include <asm/e3s.h>

#define	E8C2_CPU_VENDOR		E3S_CPU_VENDOR
#define	E8C2_CPU_FAMILY		E3S_CPU_FAMILY

extern void __init boot_e8c2_setup_arch(void);
extern void __init e8c2_setup_arch(void);
extern void __init e8c2_setup_machine(void);

/*
 * Machine (based on e8c2 processor) topology:
 * e8c2 is NUMA system on distributed memory and can have as few nodes.
 * Each node can have some memory (faster to access) and  max 8 CPU (core)
 * Node number is the same as chip-processor number
 * Some nodes (CPUS) can be without memory
 * LAPIC cluster number is the same as node number
 */

#define	E8C2_MAX_NR_NODE_CPUS		16	/* max number of posible */
						/* cores on a processor chip */
#define	E8C2_NR_NODE_CPUS		8	/* only 8 cores can be */
						/* enable on on real chip */
#define	e8c2_cpu_to_node(cpu)		((cpu) / E8C2_MAX_NR_NODE_CPUS)
#define	e8c2_node_to_cpumask(node, main_cpu_mask)			\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	__cpus_setall(&cpumask, E8C2_NR_NODE_CPUS);			\
	cpus_shift_left(node_cpumask, cpumask,				\
					node * E8C2_MAX_NR_NODE_CPUS);	\
	cpus_and(cpumask, node_cpumask, main_cpu_mask);			\
	cpumask;							\
})
#define	e8c2_node_to_first_cpu(node, main_cpu_mask)			\
({									\
	cpumask_t node_cpumask;						\
	node_cpumask = e8c2_node_to_cpumask(node, main_cpu_mask);	\
	first_cpu(node_cpumask);					\
})

#define	boot_e8c2_cpu_to_node(cpu)	e8c2_cpu_to_node(cpu)
#define	boot_e8c2_node_to_cpumask(node, boot_main_cpu_mask)		\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	__cpus_setall(&cpumask, E8C2_NR_NODE_CPUS);			\
	cpus_shift_left(node_cpumask, cpumask,				\
					node * E8C2_MAX_NR_NODE_CPUS);	\
	cpus_and(cpumask, node_cpumask, boot_main_cpu_mask);		\
	cpumask;							\
})

/*
 * IO links, IO controllers, PCI CFG topology
 */
#define	E8C2_MAX_NODE_IOLINKS	1	/* each node can has one IO link */
					/* (with two physical channels) */
					/* connected to IOHUB or RDMA */
#define	E8C2_MAX_NUMIOLINKS	(E8C2_MAX_NODE_IOLINKS * MAX_NUMNODES)

#define	E8C2_NODE_IOLINKS	E8C2_MAX_NODE_IOLINKS

#define e8c2_domain_pci_conf_base(domain) (E8C2_PCICFG_AREA_PHYS_BASE + \
		E8C2_PCICFG_AREA_SIZE * ((unsigned long) domain))

#endif /* _ASM_E8C2_H_ */
