/*
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 *
 * This file contains NUMA specific variables and functions which can
 * be split away from DISCONTIGMEM and are used on NUMA machines with
 * contiguous memory.
 * 		2002/08/07 Erich Focht <efocht@ess.nec.de>
 * Populate cpu entries in sysfs for non-numa systems as well
 *  	Intel Corporation - Ashok Raj
 * Port to E2K
 * 	MCST - 2009/11/18 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 */

#include <linux/cpu.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/node.h>
#include <linux/init.h>
#include <linux/nodemask.h>
#include <linux/topology.h>
#include <asm/apic.h>
#include <asm/cpu.h>


#undef	DEBUG_TOPOLOGY_MODE
#undef	DebugT
#define	DEBUG_TOPOLOGY_MODE	0	/* topology */
#define	DebugT			if (DEBUG_TOPOLOGY_MODE) printk


#ifdef CONFIG_NUMA
static struct node *sysfs_nodes;
#endif

static struct cpu *sysfs_cpus;


int __ref arch_register_cpu(int num)
{
#ifdef CONFIG_HOTPLUG_CPU
	sysfs_cpus[num].hotpluggable = 1;
#endif

	return register_cpu(&sysfs_cpus[num], num);
}

#ifdef CONFIG_HOTPLUG_CPU
EXPORT_SYMBOL(arch_register_cpu);

void arch_unregister_cpu(int num)
{
	return unregister_cpu(&sysfs_cpus[num]);
}
EXPORT_SYMBOL(arch_unregister_cpu);
#endif

/* maps the cpu to the sched domain representing multi-core */
const struct cpumask *cpu_coregroup_mask(int cpu)
{
	return cpumask_of_node(cpu_to_node(cpu));
}

static int __init topology_init(void)
{
	int i, err = 0;

#ifdef CONFIG_NUMA
	sysfs_nodes = kmalloc(sizeof(struct node) * MAX_NUMNODES, GFP_KERNEL);
	if (!sysfs_nodes) {
		err = -ENOMEM;
		goto out;
	}
	memset(sysfs_nodes, 0, sizeof(struct node) * MAX_NUMNODES);

	for_each_online_node(i)
		if ((err = register_one_node(i)))
			goto out;
#endif

	sysfs_cpus = kmalloc(sizeof(sysfs_cpus[0]) * NR_CPUS, GFP_KERNEL);
	if (!sysfs_cpus) {
		err = -ENOMEM;
		goto out;
	}
	memset(sysfs_cpus, 0, sizeof(sysfs_cpus[0]) * NR_CPUS);

	for_each_possible_cpu(i)
		if ((err = arch_register_cpu(i)))
			goto out;

out:
	return err;
}
subsys_initcall(topology_init);

int __init_recv cpuid_to_cpu(int cpuid)
{
	int cpu = 0;

	for (; cpu < NR_CPUS; cpu++)
		if (cpu_to_cpuid(cpu) == cpuid)
			return cpu;

	BUG();
}

#ifdef CONFIG_NUMA
s16 __apicid_to_node[NR_CPUS] = {
	[0 ... NR_CPUS-1] = NUMA_NO_NODE
};

int __nodedata __cpu_to_node[NR_CPUS];
EXPORT_SYMBOL(__cpu_to_node);

cpumask_t __nodedata __node_to_cpu_mask[MAX_NUMNODES];

static int __init numa_cpu_node(int cpu)
{
	int apicid = early_per_cpu(x86_cpu_to_apicid, cpu);

	BUG_ON(apicid == BAD_APICID);
	BUG_ON(__apicid_to_node[apicid] == NUMA_NO_NODE);

	return __apicid_to_node[apicid];
}

static void __init cpu_to_node_init(void)
{
	int cpu, node;

	for_each_possible_cpu(cpu) {
		__cpu_to_node[cpu] = numa_cpu_node(cpu);
		DebugT("__cpu_to_node[%d]=%d\n", cpu, __cpu_to_node[cpu]);
	}

	for_each_node_has_dup_kernel(node) {
		int *nid_cpu_to_node  = __va(vpa_to_pa(
						node_kernel_va_to_pa(
							node, __cpu_to_node)));

		memcpy(nid_cpu_to_node, __cpu_to_node, sizeof(__cpu_to_node));
	}
}

static void __init node_to_cpu_mask_init(void)
{
	int cpu, node;

	for_each_node(node)
		cpumask_clear(&__node_to_cpu_mask[node]);

	for_each_possible_cpu(cpu) {
		node = __cpu_to_node[cpu];
		cpumask_set_cpu(cpu, &__node_to_cpu_mask[node]);
		DebugT("__node_to_cpu_mask[%d]=0x%lx\n",
			node, __node_to_cpu_mask[node].bits[0]);
	}

	for_each_node_has_dup_kernel(node) {
		cpumask_t *nid_node_to_cpu_mask;

		nid_node_to_cpu_mask =
			__va(vpa_to_pa(node_kernel_va_to_pa(
						node, __node_to_cpu_mask)));

		memcpy(nid_node_to_cpu_mask, __node_to_cpu_mask,
			sizeof(__node_to_cpu_mask));
	}
}

static void __init update_numa_possible_map(void)
{
	int cpu;

	nodes_clear(node_possible_map);
	for_each_possible_cpu(cpu)
		node_set(__cpu_to_node[cpu], node_possible_map);
}

void __init numa_init(void)
{
	cpu_to_node_init();
	node_to_cpu_mask_init();
	update_numa_possible_map();
}
#endif
