/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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
#include <linux/memblock.h>
#include <linux/nodemask.h>
#include <linux/slab.h>
#include <linux/topology.h>
#include <asm/apic.h>
#include <asm/cpu.h>
#include <asm/mmu_context.h>

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
	int i, err;

	for_each_online_node(i)
		if ((err = register_one_node(i)))
			return err;

	sysfs_cpus = kmalloc(sizeof(sysfs_cpus[0]) * NR_CPUS, GFP_KERNEL);
	if (!sysfs_cpus)
		return -ENOMEM;
	memset(sysfs_cpus, 0, sizeof(sysfs_cpus[0]) * NR_CPUS);

	for_each_possible_cpu(i) {
		if ((err = arch_register_cpu(i)))
			return err;
	}

	return 0;
}
subsys_initcall(topology_init);

int cpuid_to_cpu(int cpuid)
{
	int cpu = 0;

	for (; cpu < NR_CPUS; cpu++)
		if (cpu_to_cpuid(cpu) == cpuid)
			return cpu;

	BUG();
}

#ifdef CONFIG_NUMA
/*
 * Which logical CPUs are on which nodes
 */
cpumask_var_t node_to_cpumask_map[MAX_NUMNODES] __read_mostly;
EXPORT_SYMBOL(node_to_cpumask_map);

void numa_update_cpu(unsigned int cpu, bool remove)
{
	int nid = cpu_to_node(cpu);

	if (nid == NUMA_NO_NODE)
		return;

	if (remove)
		cpumask_clear_cpu(cpu, node_to_cpumask_map[nid]);
	else
		cpumask_set_cpu(cpu, node_to_cpumask_map[nid]);
}


s16 __apicid_to_node[NR_CPUS] = {
	[0 ... NR_CPUS-1] = NUMA_NO_NODE
};

/*
 * This version of cpu_to_node() will work earlier but is much slower
 */
int early_cpu_to_node(int cpu)
{
	int apicid = cpu_to_cpuid(cpu);

	BUG_ON(apicid == BAD_APICID);
	BUG_ON(__apicid_to_node[apicid] == NUMA_NO_NODE);

	return __apicid_to_node[apicid];
}

static void __init update_numa_possible_map(void)
{
	int cpu;

	nodes_clear(node_possible_map);
	for_each_possible_cpu(cpu)
		node_set(early_cpu_to_node(cpu), node_possible_map);
}

/*
 * Allocate node_to_cpumask_map based on node_online_map
 * Requires cpu_online_mask to be valid.
 */
static void __init create_node_to_cpumask_map(void)
{
	int node;

	/* setup nr_node_ids if not done yet */
	if (nr_node_ids == MAX_NUMNODES)
		setup_nr_node_ids();

	/* allocate and clear the mapping */
	for (node = 0; node < nr_node_ids; node++) {
		alloc_bootmem_cpumask_var(&node_to_cpumask_map[node]);
		cpumask_clear(node_to_cpumask_map[node]);
	}
}

void __init numa_init(void)
{
	update_numa_possible_map();

	create_node_to_cpumask_map();
}

static void zero_page_duplicate(void)
{
	int node;

	/* Duplicate zero page */
	kernel_image_duplicate_page_range(empty_zero_page,
			sizeof(empty_zero_page), false);

	/* Initialize pointers to zero page */
	for_each_node_state(node, N_MEMORY) {
		phys_addr_t pa;

		pa = node_kernel_address_to_phys(node,
				(unsigned long) empty_zero_page);
		BUG_ON(IS_ERR_VALUE(pa));

		zero_page_nid_to_pfn[node] = PHYS_PFN(pa);
		zero_page_nid_to_page[node] = phys_to_page(pa);
	}

	/* Nodes without memory will use zero pages from other nodes */
	for_each_node(node) {
		if (node_state(node, N_MEMORY))
			continue;

		zero_page_nid_to_pfn[node] =
				zero_page_nid_to_pfn[first_memory_node];
		zero_page_nid_to_page[node] =
				zero_page_nid_to_page[first_memory_node];
	}
}

static void __init update_os_pptb(void *unused)
{
	u64 os_pptb = __pa(mm_node_pgd(&init_mm, numa_node_id()));
	WRITE_MMU_OS_PPTB(os_pptb);
	local_flush_tlb_all();
}

static int __init duplicate_kernel_image(void)
{
	unsigned long start_pfn, end_pfn;
	int i;

	/* These are the same areas as in boot_map_kernel_image() */
	kernel_image_duplicate_page_range(_stext,
			_etext - _stext, false);
	kernel_image_duplicate_page_range(__start_rodata_notes,
			__end_rodata_notes - __start_rodata_notes, false);
	kernel_image_duplicate_page_range(__special_data_begin,
			__special_data_end - __special_data_begin, true);
	kernel_image_duplicate_page_range(__node_data_start,
			__node_data_end - __node_data_start, false);
	kernel_image_duplicate_page_range(__common_data_begin,
			__common_data_end - __common_data_begin, true);
	kernel_image_duplicate_page_range(__init_text_begin,
			__init_text_end - __init_text_begin, false);
	kernel_image_duplicate_page_range(__init_data_begin,
			__init_data_end - __init_data_begin, true);

	for_each_mem_pfn_range(i, MAX_NUMNODES, &start_pfn, &end_pfn, NULL) {
		unsigned long start, end;

		/* Duplicate PAGE_OFFSET mapping */
		start = (unsigned long) pfn_to_virt(start_pfn);
		end = (unsigned long) pfn_to_virt(end_pfn);
		kernel_image_duplicate_page_range((void *) start, end - start, true);

		/* Duplicate sparse vmemmap mapping */
		start = (unsigned long) pfn_to_page(start_pfn);
		end = (unsigned long) pfn_to_page(end_pfn);
		start = round_down(start, PAGE_SIZE);
		end = round_up(end, PAGE_SIZE);
		kernel_image_duplicate_page_range((void *) start, end - start, true);
	}

	zero_page_duplicate();

	/* If we have a separate register for OS page tables
	 * then initialize it with a pointer to closest NUMA node. */
	if (MMU_IS_SEPARATE_PT())
		on_each_cpu(update_os_pptb, NULL, false);

	return 0;
}
arch_initcall(duplicate_kernel_image);

int is_duplicated_address(unsigned long addr)
{
	/* Code is not yet duplicated this early in the boot process */
	if (system_state == SYSTEM_BOOTING)
		return 0;

	return addr >= (unsigned long) _stext &&
				addr < (unsigned long) _etext ||
			addr >= (unsigned long) __start_rodata_notes &&
				addr < (unsigned long) __end_rodata_notes ||
			addr >= (unsigned long) __special_data_begin &&
				addr < (unsigned long) __special_data_end ||
			addr >= (unsigned long) __node_data_start &&
				addr < (unsigned long) __node_data_end ||
			addr >= (unsigned long) __common_data_begin &&
				addr < (unsigned long) __common_data_end ||
			addr >= (unsigned long) __init_text_begin &&
				addr < (unsigned long) __init_text_end ||
			addr >= (unsigned long) __init_data_begin &&
				addr < (unsigned long) __init_data_end ||
			addr >= PAGE_OFFSET && addr < PAGE_OFFSET + MAX_PM_SIZE ||
			addr >= VMEMMAP_START && addr < VMEMMAP_END;
}
#endif
