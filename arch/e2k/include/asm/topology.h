#ifndef _E2K_TOPOLOGY_H_
#define _E2K_TOPOLOGY_H_

#include <linux/numa.h>
#ifdef	CONFIG_NUMA
#include <linux/cpumask.h>
#endif	/* CONFIG_NUMA */
#include <asm/smp.h>
#include <asm/e2k.h>
#include <asm/e3m.h>
#include <asm/e3m_iohub.h>
#include <asm/e3s.h>
#include <asm/es2.h>
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/e1cp.h>

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

#define	E2S_CPUs_NODE_IOLINKS						\
		((IS_MACHINE_E2S) ?					\
			(E2S_NODE_IOLINKS)				\
			:						\
			((IS_MACHINE_E8C) ?				\
				(E8C_NODE_IOLINKS)			\
				:					\
				((IS_MACHINE_E1CP) ?			\
					(E1CP_NODE_IOLINKS)		\
					:				\
					((IS_MACHINE_E8C2) ?		\
						(E8C2_NODE_IOLINKS)	\
						:			\
						({BUG(); -1; })))))
#define	E2K_NODE_IOLINKS						\
	((IS_MACHINE_E3M) ?						\
		(E3M_NODE_IOLINKS)					\
		:							\
		((IS_MACHINE_E3M_IOHUB) ?				\
			(E3M_IOHUB_NODE_IOLINKS)			\
			:						\
			((IS_MACHINE_E3S) ?				\
				(E3S_NODE_IOLINKS)			\
				:					\
				((IS_MACHINE_ES2) ?			\
					(ES2_NODE_IOLINKS)		\
					:				\
					(E2S_CPUs_NODE_IOLINKS)))))
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
#define	rdma_domain_to_node(domain)	iolink_domain_to_node(domain)
#define	rdma_domain_to_link(domain)	iolink_domain_to_link(domain)

#define		for_each_iolink_of_node(link)				\
		for ((link) = 0; (link) < E2K_NODE_IOLINKS; (link) ++)

#define pcibus_to_node(bus)	__pcibus_to_node(bus)
#define pcibus_to_link(bus)	__pcibus_to_link(bus)
#define pcibus_to_cpumask(bus)	node_to_cpumask(pcibus_to_node(bus))

#define	mach_early_iohub_online(node, link)				\
		e2k_early_iohub_online((node), (link))
#define	mach_early_sic_init()

#ifdef CONFIG_NUMA
extern int __cpu_to_node[NR_CPUS];
#define	cpu_to_node(cpu)	__cpu_to_node[cpu]

#define numa_node_id()	(cpu_to_node(raw_smp_processor_id()))

#define __node_to_cpumask(node, cpu_mask)			\
({								\
	cpumask_t ret;						\
								\
	if (IS_MACHINE_E3M)					\
		ret = e3m_node_to_cpumask(node, cpu_mask);	\
	else if (IS_MACHINE_E3S)				\
		ret = e3s_node_to_cpumask(node, cpu_mask);	\
	else if (IS_MACHINE_ES2)				\
		ret = es2_node_to_cpumask(node, cpu_mask);	\
	else if (IS_MACHINE_E2S)				\
		ret = e2s_node_to_cpumask(node, cpu_mask);	\
	else if (IS_MACHINE_E8C)				\
		ret = e8c_node_to_cpumask(node, cpu_mask);	\
	else if (IS_MACHINE_E1CP)				\
		ret = e1cp_node_to_cpumask(node, cpu_mask);	\
	else							\
		ret = e8c2_node_to_cpumask(node, cpu_mask);	\
								\
	ret;							\
})

#define node_to_cpumask(node)					\
		__node_to_cpumask(node, *cpu_online_mask)
#define node_to_present_cpumask(node)				\
		__node_to_cpumask(node, *cpu_present_mask)

#define __node_to_first_cpu(node, cpu_mask)			\
({								\
	u32 ret;						\
								\
	if (IS_MACHINE_E3M)					\
		ret = e3m_node_to_first_cpu(node, cpu_mask);	\
	else if (IS_MACHINE_E3S)				\
		ret = e3s_node_to_first_cpu(node, cpu_mask);	\
	else if (IS_MACHINE_ES2)				\
		ret = es2_node_to_first_cpu(node, cpu_mask);	\
	else if (IS_MACHINE_E2S)				\
		ret = e2s_node_to_first_cpu(node, cpu_mask);	\
	else if (IS_MACHINE_E8C)				\
		ret = e8c_node_to_first_cpu(node, cpu_mask);	\
	else if (IS_MACHINE_E1CP)				\
		ret = e1cp_node_to_first_cpu(node, cpu_mask);	\
	else							\
		ret = e8c2_node_to_first_cpu(node, cpu_mask);	\
								\
	ret;							\
})

#define node_to_first_cpu(node)					\
		__node_to_first_cpu(node, *cpu_online_mask)
#define node_to_first_present_cpu(node)				\
		__node_to_first_cpu(node, *cpu_present_mask)

#define node_has_online_mem(nid) (nodes_phys_mem[nid].pfns_num != 0)

/*
 * Returns the number of the node containing Node 'node'. This
 * architecture is flat, so it is a pretty simple function!
 */
#define parent_node(node) (node)

#define cpumask_of_pcibus(bus)	(pcibus_to_node(bus) == NUMA_NO_NODE ?	\
				 cpu_online_mask :			\
				 cpumask_of_node(pcibus_to_node(bus)))

/* Mappings between node number and cpus on that node. */
extern struct cpumask node_to_cpumask_map[MAX_NUMNODES];

/* Returns a pointer to the cpumask of CPUs on Node 'node'. */
static inline const struct cpumask *cpumask_of_node(int node)
{
	return &node_to_cpumask_map[node];
}
extern void setup_node_to_cpumask_map(void);

/* sched_domains SD_NODE_INIT for NUMA machines */
#define SD_NODE_INIT (struct sched_domain) {		\
	.min_interval		= 8,					\
	.max_interval		= 32,					\
	.busy_factor		= 32,					\
	.imbalance_pct		= 125,					\
	.cache_nice_tries	= 2,					\
	.busy_idx		= 3,					\
	.idle_idx		= 2,					\
	.newidle_idx		= 0,					\
	.wake_idx		= 0,					\
	.forkexec_idx		= 0,					\
									\
	.flags			= 1*SD_LOAD_BALANCE			\
				| 1*SD_BALANCE_NEWIDLE			\
				| 1*SD_BALANCE_EXEC			\
				| 1*SD_BALANCE_FORK			\
				| 0*SD_BALANCE_WAKE			\
				| 1*SD_WAKE_AFFINE			\
				| 0*SD_PREFER_LOCAL			\
				| 0*SD_SHARE_CPUPOWER			\
				| 0*SD_POWERSAVINGS_BALANCE		\
				| 0*SD_SHARE_PKG_RESOURCES		\
				| 1*SD_SERIALIZE			\
				| 0*SD_PREFER_SIBLING			\
				,					\
	.last_balance		= jiffies,				\
	.balance_interval	= 1,					\
}

extern nodemask_t __nodedata node_has_dup_kernel_map;
extern atomic_t __nodedata node_has_dup_kernel_num;
extern int __nodedata all_nodes_dup_kernel_nid[/*MAX_NUMNODES*/];
extern struct mm_struct __nodedata *all_nodes_init_mm[/*MAX_NUMNODES*/];
#define	node_dup_kernel_nid(nid)	(all_nodes_dup_kernel_nid[nid])
#define	node_init_mm(nid)		(all_nodes_init_mm[nid])
#define	THERE_IS_DUP_KERNEL		atomic_read(&node_has_dup_kernel_num)
#define	DUP_KERNEL_NUM						\
		(atomic_read(&node_has_dup_kernel_num) + 1)
#else /* ! CONFIG_NUMA */

#define	THERE_IS_DUP_KERNEL		0
#define numa_node_id()	0


static inline int early_cpu_to_node(int cpu)
{
	return 0;
}

#define	node_has_dup_kernel_map		nodemask_of_node(0)
#define	node_has_dup_kernel_num		0
#define	node_dup_kernel_nid(nid)	0
#define	node_init_mm(nid)		(&init_mm)
#define THERE_IS_DUP_KERNEL		0

#define node_to_first_present_cpu(node)	0

#define node_to_present_cpumask(node) (*cpu_present_mask)

#define node_to_possible_cpumask(node)		cpumask_of_cpu(0)
#endif	/* CONFIG_NUMA */

#include <asm-generic/topology.h>

static inline void arch_fix_phys_package_id(int num, u32 slot)
{
}

static inline int is_duplicated_code(unsigned long ip)
{
	return ip >= (unsigned long) _stext && ip < (unsigned long) _etext;
}

#endif /* _E2K_TOPOLOGY_H_ */
