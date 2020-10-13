#ifndef _ASM_SPARC64_TOPOLOGY_E90S_H
#define _ASM_SPARC64_TOPOLOGY_E90S_H

#include <asm/iolinkmask.h>
#include <asm/cpudata.h>
/*
 * IO links/controllers/buses topology:
 * each node of e90s machines can have from 1 to MAX_NODE_IOLINKS IO links
 * which can be connected to IOHUB or RDMA
 */
#define	MAX_NODE_IOLINKS	MACH_NODE_NUMIOLINKS
/*
 * IOLINK can be represented by global domain number (unique at system and
 * corresponds to bit number at iolinkmask_t bit map structure)
 * and as pair: node # and local link number on the node.
 * It needs convert from one presentation to other
 * Supporing of many IOHUBs not yet implemented on sprac arch
 */

#define	node_iolink_to_domain(node, link)			\
	((node) * (MACH_NODE_NUMIOLINKS) + (link))
#define	node_iohub_to_domain(node, link) node_iolink_to_domain((node), (link))
#define	node_rdma_to_domain(node, link) node_iolink_to_domain((node), (link))
#define	iolink_domain_to_node(domain)				\
	((domain) / (MACH_NODE_NUMIOLINKS))
#define	iolink_domain_to_link(domain)				\
	((domain) % (MACH_NODE_NUMIOLINKS))
#define	iohub_domain_to_node(domain)	iolink_domain_to_node(domain)
#define	iohub_domain_to_link(domain)	iolink_domain_to_link(domain)
#define	rdma_domain_to_node(domain)	iolink_domain_to_node(domain)
#define	rdma_domain_to_link(domain)	iolink_domain_to_link(domain)

#define pcibus_to_link(bus)	__pcibus_to_link(bus)

#define	mach_early_iohub_online(node, link)	\
		e90s_early_iohub_online((node), (link))

#ifdef CONFIG_NUMA

#include <asm/mmzone.h>

static inline int cpu_to_node(int cpu)
{
	return numa_cpu_lookup_table[cpu];
}

#define parent_node(node)	(node)

#define cpumask_of_node(node) ((node) == -1 ?				\
			       cpu_all_mask :				\
			       &numa_cpumask_lookup_table[node])

struct pci_bus;
#ifdef CONFIG_PCI
extern int pcibus_to_node(struct pci_bus *pbus);
#else
static inline int pcibus_to_node(struct pci_bus *pbus)
{
	return -1;
}
#endif

#define cpumask_of_pcibus(bus)	\
	(pcibus_to_node(bus) == -1 ? \
	 cpu_all_mask : \
	 cpumask_of_node(pcibus_to_node(bus)))

#define SD_NODE_INIT (struct sched_domain) {		\
	.min_interval		= 8,			\
	.max_interval		= 32,			\
	.busy_factor		= 32,			\
	.imbalance_pct		= 125,			\
	.cache_nice_tries	= 2,			\
	.busy_idx		= 3,			\
	.idle_idx		= 2,			\
	.newidle_idx		= 0, 			\
	.wake_idx		= 0,			\
	.forkexec_idx		= 0,			\
	.flags			= SD_LOAD_BALANCE	\
				| SD_BALANCE_FORK	\
				| SD_BALANCE_EXEC	\
				| SD_SERIALIZE,		\
	.last_balance		= jiffies,		\
	.balance_interval	= 1,			\
}

#else /* CONFIG_NUMA */

#include <asm-generic/topology.h>

#endif /* !(CONFIG_NUMA) */

#ifdef CONFIG_SMP
#define topology_physical_package_id(cpu)	(cpu_data(cpu).proc_id)
#define topology_core_id(cpu)			(cpu_data(cpu).core_id)
#define topology_core_cpumask(cpu)		(&cpu_core_map[cpu])
#define topology_thread_cpumask(cpu)		(&per_cpu(cpu_sibling_map, cpu))
#define mc_capable()				(sparc64_multi_core)
#define smt_capable()				(sparc64_multi_core)
#endif /* CONFIG_SMP */

static inline void arch_fix_phys_package_id(int num, u32 slot)
{
}

extern cpumask_t cpu_core_map[NR_CPUS];
static inline const struct cpumask *cpu_coregroup_mask(int cpu)
{
        return &cpu_core_map[cpu];
}

#endif /* _ASM_SPARC64_TOPOLOGY_E90S_H */
