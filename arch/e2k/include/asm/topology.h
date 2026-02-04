/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_TOPOLOGY_H_
#define _E2K_TOPOLOGY_H_

#include <linux/cpumask.h>
#include <asm/numa.h>
#include <asm/percpu.h>

/* Max CPUS needs to allocate static array of structures */
#define MAX_NR_CPUS		CONFIG_NR_CPUS

/*
 * IO links/controllers/buses topology:
 * each node of e2k machines can have from 1 to MAX_NODE_IOLINKS IO links
 * which can be connected to IOHUB or RDMA
 * Real possible number of IO links on node is described by following
 * macroses for every type of machines
 */

#define	MAX_NODE_IOLINKS	E2K_MAX_NODE_IOLINKS
#define	E2K_NODE_IOLINKS	(machine.node_iolinks)
#define MACH_NODE_NUMIOLINKS	E2K_NODE_IOLINKS

/*
 * IOLINK can be represented by global domain number (unique at system and
 * corresponds to bit number at iolinkmask_t bit map structure)
 * and as pair: node # and local link number on the node.
 * It needs convert from one presentation to other
 */

#define	node_iolink_to_domain(node, link)			\
		((node) * (E2K_NODE_IOLINKS) + (link))
#define	node_iohub_to_domain(node, link)			\
		node_iolink_to_domain((node), (link))
#define	node_rdma_to_domain(node, link)				\
		node_iolink_to_domain((node), (link))
#define	iolink_domain_to_node(domain)				\
		((domain) / (E2K_NODE_IOLINKS))
#define	iolink_domain_to_link(domain)				\
		((domain) % (E2K_NODE_IOLINKS))
#define	iohub_domain_to_node(domain)	iolink_domain_to_node(domain)
#define	iohub_domain_to_link(domain)	iolink_domain_to_link(domain)

#define	for_each_iolink_of_node(link)				\
		for ((link) = 0; (link) < E2K_NODE_IOLINKS; (link) ++)

#define	mach_early_iohub_online(node, link)			\
		e2k_early_iohub_online((node), (link))
#define	mach_early_sic_init()

extern int cpuid_to_cpu(int cpuid);

#ifdef CONFIG_L_LOCAL_APIC
DECLARE_EARLY_PER_CPU_READ_MOSTLY(u16, cpu_to_picid);
#define cpu_to_cpuid(cpu)	early_per_cpu(cpu_to_picid, cpu)
#else
/*
 * That case wouldn't work, we should delete CONFIG_L_LOCAL_APIC in future
 */
#define cpu_to_cpuid(cpu)	BUILD_BUG()
#endif

#ifdef CONFIG_NUMA
extern s16 __apicid_to_node[NR_CPUS];

extern int is_duplicated_code(unsigned long ip);
extern int is_duplicated_address(unsigned long addr);

# define topology_physical_package_id(cpu)	cpu_to_node(cpu)

#define cpumask_of_pcibus(bus)	(pcibus_to_node(bus) == -1 ?		\
				 cpu_all_mask :				\
				 cpumask_of_node(pcibus_to_node(bus)))

#else /* ! CONFIG_NUMA */

static inline int is_duplicated_address(unsigned long addr) { return false; }
static inline int is_duplicated_code(unsigned long ip) { return false; }
# define topology_physical_package_id(cpu)	0
#endif	/* CONFIG_NUMA */

#define for_each_node_has_dup_kernel(node) \
		for_each_node_mm_pgdmask((node), &init_mm)

#define topology_core_id(cpu)		(cpu)
#define topology_core_cpumask(cpu)	cpumask_of_node(cpu_to_node(cpu))

#include <asm-generic/topology.h>

static inline void arch_fix_phys_package_id(int num, u32 slot)
{
}

extern const struct cpumask *cpu_coregroup_mask(int cpu);

#endif /* _E2K_TOPOLOGY_H_ */
