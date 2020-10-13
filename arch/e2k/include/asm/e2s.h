#ifndef _ASM_E2S_H_
#define _ASM_E2S_H_

#include <linux/init.h>
#include <asm/e3s.h>

#define	E2S_CPU_VENDOR		E3S_CPU_VENDOR
#define	E2S_CPU_FAMILY		E3S_CPU_FAMILY

extern void __init boot_e2s_setup_arch(void);
extern void __init e2s_setup_machine_rev(void);
extern void __init e2s_setup_arch(void);
extern void __init e2s_setup_machine(void);

/*
 * Machine (based on e2s processor) topology:
 * e2s is NUMA system on distributed memory and can have as few nodes.
 * Each node can have some memory (faster to access) and  max 4 CPU (core)
 * Node number is the same as chip-processor number
 * Some nodes (CPUS) can be without memory
 * LAPIC cluster number is the same as node number
 */

#define	E2S_MAX_NR_NODE_CPUS		4	/* max number of posible */
						/* cores on a processor chip */
#define	E2S_NR_NODE_CPUS		E2S_MAX_NR_NODE_CPUS
						/* all 4 cores can be */
						/* enable on on real chip */
#define	e2s_cpu_to_node(cpu)		((cpu) / E2S_MAX_NR_NODE_CPUS)
#define	e2s_node_to_cpumask(node, main_cpu_mask)			\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	__cpus_setall(&cpumask, E2S_NR_NODE_CPUS);			\
	cpus_shift_left(node_cpumask, cpumask,				\
					node * E2S_MAX_NR_NODE_CPUS);	\
	cpus_and(cpumask, node_cpumask, main_cpu_mask);			\
	cpumask;							\
})
#define	e2s_node_to_first_cpu(node, main_cpu_mask)			\
({									\
	cpumask_t node_cpumask;						\
	node_cpumask= e2s_node_to_cpumask(node, main_cpu_mask);		\
	first_cpu(node_cpumask);					\
})

#define	boot_e2s_cpu_to_node(cpu)	e2s_cpu_to_node(cpu)
#define	boot_e2s_node_to_cpumask(node, boot_main_cpu_mask)		\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	__cpus_setall(&cpumask, E2S_NR_NODE_CPUS);			\
	cpus_shift_left(node_cpumask, cpumask,				\
					node * E2S_MAX_NR_NODE_CPUS);	\
	cpus_and(cpumask, node_cpumask, boot_main_cpu_mask);		\
	cpumask;							\
})

/*
 * IO links, IO controllers, PCI CFG topology
 */
#define	E2S_MAX_NODE_IOLINKS	1	/* each node can has two IO links */
					/* connected to IOHUB or RDMA */
#define	E2S_MAX_NUMIOLINKS	(E2S_MAX_NODE_IOLINKS * MAX_NUMNODES)

#define	E2S_NODE_IOLINKS	E2S_MAX_NODE_IOLINKS

#define e2s_domain_pci_conf_base(domain) (E2S_PCICFG_AREA_PHYS_BASE + \
		E2S_PCICFG_AREA_SIZE * ((unsigned long) domain))

#endif /* _ASM_E2S_H_ */
