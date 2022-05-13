#ifndef _E2K_TOPOLOGY_H_
#define _E2K_TOPOLOGY_H_

#include <linux/numa.h>
#ifdef	CONFIG_NUMA
#include <linux/cpumask.h>
#endif	/* CONFIG_NUMA */
#include <asm/smp.h>
#include <asm/e2k.h>
#include <asm/e2s.h>
#include <asm/e8c.h>
#include <asm/e1cp.h>
#include <asm/e16c.h>
#include <asm/e12c.h>
#include <asm/e2c3.h>
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

#define pcibus_to_node(bus)	__pcibus_to_node(bus)
#define pcibus_to_link(bus)	__pcibus_to_link(bus)

#define	mach_early_iohub_online(node, link)			\
		e2k_early_iohub_online((node), (link))
#define	mach_early_sic_init()

extern int __init_recv cpuid_to_cpu(int cpuid);

#ifdef CONFIG_L_LOCAL_APIC
DECLARE_EARLY_PER_CPU_READ_MOSTLY(u16, x86_cpu_to_apicid);
#define cpu_to_cpuid(cpu)	early_per_cpu(x86_cpu_to_apicid, cpu)
#else
/*
 * That case wouldn't work, we should delete CONFIG_L_LOCAL_APIC in future
 */
#define cpu_to_cpuid(cpu)	BUILD_BUG()
#endif

#ifdef CONFIG_NUMA
extern void __init numa_init(void);

extern s16 __apicid_to_node[NR_CPUS];

extern int __nodedata __cpu_to_node[NR_CPUS];
#define	cpu_to_node(cpu)	__cpu_to_node[cpu]

extern cpumask_t __nodedata __node_to_cpu_mask[MAX_NUMNODES];
#define	node_to_cpu_mask(node)	__node_to_cpu_mask[node]

#define numa_node_id()		(cpu_to_node(raw_smp_processor_id()))

#define __node_to_cpumask_and(node, cpu_mask)			\
({								\
	cpumask_t cpumask = node_to_cpu_mask(node);		\
	cpumask_and(&cpumask, &cpumask,	&cpu_mask);		\
	cpumask;						\
})

#define node_to_cpumask(node)					\
		__node_to_cpumask_and(node, *cpu_online_mask)
#define node_to_present_cpumask(node)				\
		__node_to_cpumask_and(node, *cpu_present_mask)

#define __node_to_first_cpu(node, cpu_mask)			\
({								\
	cpumask_t node_cpumask;					\
	node_cpumask = __node_to_cpumask_and(node, cpu_mask);	\
	cpumask_first((const struct cpumask *)&node_cpumask);	\
})

#define node_to_first_cpu(node)					\
		__node_to_first_cpu(node, *cpu_online_mask)
#define node_to_first_present_cpu(node)				\
		__node_to_first_cpu(node, *cpu_present_mask)

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

extern nodemask_t __nodedata node_has_dup_kernel_map;
extern atomic_t __nodedata node_has_dup_kernel_num;
extern int __nodedata all_nodes_dup_kernel_nid[/*MAX_NUMNODES*/];

#define	node_dup_kernel_nid(nid)	(all_nodes_dup_kernel_nid[nid])
#define	THERE_IS_DUP_KERNEL		atomic_read(&node_has_dup_kernel_num)
#define	DUP_KERNEL_NUM						\
		(atomic_read(&node_has_dup_kernel_num) + 1)

#define topology_physical_package_id(cpu)	cpu_to_node(cpu)
#else /* ! CONFIG_NUMA */

#define numa_node_id()				0

static inline void numa_init(void) { }

#define	node_has_dup_kernel_map			nodemask_of_node(0)
#define	node_has_dup_kernel_num			0
#define	node_dup_kernel_nid(nid)		0
#define THERE_IS_DUP_KERNEL			0

#define node_to_first_cpu(node)			0
#define node_to_first_present_cpu(node)		0
#define node_to_present_cpumask(node)		(*cpu_present_mask)
#define node_to_possible_cpumask(node)		cpumask_of_cpu(0)

#define topology_physical_package_id(cpu)	0
#endif	/* CONFIG_NUMA */

#define node_has_online_mem(nid) (nodes_phys_mem[nid].pfns_num != 0)

#define topology_core_id(cpu)		(cpu)
#define topology_core_cpumask(cpu)	cpumask_of_node(cpu_to_node(cpu))

#include <asm-generic/topology.h>

static inline void arch_fix_phys_package_id(int num, u32 slot)
{
}

static inline int is_duplicated_code(unsigned long ip)
{
	return ip >= (unsigned long) _stext && ip < (unsigned long) _etext;
}
extern const struct cpumask *cpu_coregroup_mask(int cpu);
#endif /* _E2K_TOPOLOGY_H_ */
