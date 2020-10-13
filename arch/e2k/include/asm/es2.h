#ifndef _ASM_ES2_H_
#define _ASM_ES2_H_

#include <linux/init.h>
#include <asm/e3s.h>

#define	ES2_CPU_VENDOR		E3S_CPU_VENDOR
#define	ES2_CPU_FAMILY		E3S_CPU_FAMILY

extern void __init boot_es2_setup_arch(void);
extern void __init es2_setup_machine_rev(void);
extern void __init es2_setup_arch(void);
extern void __init es2_setup_machine(void);

/*
 * Machine (based on es2 processor) topology:
 * es2 is NUMA system on distributed memory and can have as few nodes.
 * Each node can have some memory (faster to access) and  max 4 CPU (core),
 * but real processor chip has only two core (2 other should consider
 * as always disabled). So online CPU numbers will be 0, 1, 4, 5, 8, 9 ...
 * Node number is the same as chip-processor number
 * Some nodes (CPUS) can be without memory
 * LAPIC cluster number is the same as node number
 */

#define	ES2_MAX_NR_NODE_CPUS		4	/* max number of posible */
						/* cores on a processor chip */
#define	ES2_NR_NODE_CPUS		2	/* only 2 cores can be */
						/* enable on on real chip */
#define	es2_cpu_to_node(cpu)		((cpu) / ES2_MAX_NR_NODE_CPUS)
#define	es2_node_to_cpumask(node, main_cpu_mask)			\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	__cpus_setall(&cpumask, ES2_NR_NODE_CPUS);			\
	cpus_shift_left(node_cpumask, cpumask,				\
					node * ES2_MAX_NR_NODE_CPUS);	\
	cpus_and(cpumask, node_cpumask, main_cpu_mask);			\
	cpumask;							\
})
#define	es2_node_to_first_cpu(node, main_cpu_mask)			\
({									\
	cpumask_t node_cpumask;						\
	node_cpumask= es2_node_to_cpumask(node, main_cpu_mask);		\
	first_cpu(node_cpumask);					\
})

#define	boot_es2_cpu_to_node(cpu)	es2_cpu_to_node(cpu)
#define	boot_es2_node_to_cpumask(node, boot_main_cpu_mask)		\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	__cpus_setall(&cpumask, ES2_NR_NODE_CPUS);			\
	cpus_shift_left(node_cpumask, cpumask,				\
					node * ES2_MAX_NR_NODE_CPUS);	\
	cpus_and(cpumask, node_cpumask, boot_main_cpu_mask);		\
	cpumask;							\
})

/*
 * IO links and IO controllers topology
 */
#define		ES2_MAX_NODE_IOLINKS	2	/* each node can has two IO links */
						/* connected to IOHUB or RDMA */
#define		ES2_MAX_NUMIOLINKS	(ES2_MAX_NODE_IOLINKS * MAX_NUMNODES)
#define		ES2_NODE_IOLINKS	ES2_MAX_NODE_IOLINKS

#define es2_domain_pci_conf_base(domain) (ES2_PCICFG_AREA_PHYS_BASE + \
		ES2_PCICFG_AREA_SIZE * ((unsigned long) domain))

#endif /* _ASM_ES2_H_ */
