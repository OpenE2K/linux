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
#include <linux/node.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/nodemask.h>
#include <linux/topology.h>
#include <asm/cpu.h>

#ifdef CONFIG_NUMA
int __nodedata __cpu_to_node[NR_CPUS];
EXPORT_SYMBOL(__cpu_to_node);
static struct node *sysfs_nodes;
#endif
static struct e2k_cpu *sysfs_cpus;


int __ref arch_register_cpu(int num)
{

#ifdef CONFIG_ACPI
	/*
	 * If CPEI cannot be re-targetted, and this is
	 * CPEI target, then dont create the control file
	 */

	/*
	 * Probably we'll add acpi one day. We must not
	 * forget about acpi hook here. See ia64 implementation
	 * as example. Emkr.
	 */
#endif

#ifdef CONFIG_HOTPLUG_CPU
	sysfs_cpus[num].cpu.hotpluggable = 1;
#endif /* CONFIG_HOTPLUG_CPU */

	return register_cpu(&sysfs_cpus[num].cpu, num);
}

#ifdef CONFIG_HOTPLUG_CPU

void arch_unregister_cpu(int num)
{
	return unregister_cpu(&sysfs_cpus[num].cpu);
}
EXPORT_SYMBOL(arch_register_cpu);
EXPORT_SYMBOL(arch_unregister_cpu);
#endif /*CONFIG_HOTPLUG_CPU*/


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
	sysfs_cpus = kmalloc(sizeof(struct e2k_cpu) * NR_CPUS, GFP_KERNEL);
	if (!sysfs_cpus) {
		err = -ENOMEM;
		goto out;
	}
	memset(sysfs_cpus, 0, sizeof(struct e2k_cpu) * NR_CPUS);

	for_each_present_cpu(i)
		if((err = arch_register_cpu(i)))
			goto out;
out:
	return err;
}

__initcall(topology_init);
