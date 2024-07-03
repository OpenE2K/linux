/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * SMP mode of boot-time initialization helpers
 */

#include <asm/p2v/boot_head.h>
#include <asm/p2v/boot_smp.h>
#include <asm/p2v/boot_console.h>
#include <asm/processor.h>

#undef	DEBUG_BOOT_SMP_MODE
#undef	boot_printk
#define	DEBUG_BOOT_SMP_MODE	0	/* Boot SMP process */
#define	boot_printk		if (DEBUG_BOOT_SMP_MODE) do_boot_printk

cpu_sync_count_t __cacheline_aligned_in_smp num_arrived = {.pad = 0};

/* error occured while boot-time initialization */
atomic_t  boot_error_flag = ATOMIC_INIT(0);

int cpu_to_sync_num = NR_CPUS;

void __boot_sync_all_processors(atomic_t *num_arrived)
{
	int phys_cpu_num = boot_cpu_to_sync_num;
	int current_num_arrived, max_num_arrived;

	current_num_arrived = boot_atomic_inc_return(num_arrived);

	max_num_arrived = current_num_arrived / phys_cpu_num;
	max_num_arrived += (current_num_arrived % phys_cpu_num) ? 1 : 0;
	max_num_arrived *= phys_cpu_num;

	while (boot_atomic_read(num_arrived) < max_num_arrived)
		boot_cpu_relax();
}

void __init_sync_all_processors(atomic_t *num_arrived, int cpus_to_sync)
{
	int current_num_arrived, max_num_arrived;

	current_num_arrived = atomic_inc_return(num_arrived);

	max_num_arrived = current_num_arrived / cpus_to_sync;
	max_num_arrived += (current_num_arrived % cpus_to_sync) ? 1 : 0;
	max_num_arrived *= cpus_to_sync;

	while (atomic_read(num_arrived) < max_num_arrived)
		cpu_relax();
}

/*
 * Setup CPU configuration for boot-time initialization,
 * passed by BIOS thru bootblock structure
 */

int __init_recv
boot_bios_smp_cpu_config(boot_info_t *bootblock)
{
	int		phys_cpu_num;

	phys_cpu_num = bootblock->num_of_cpus;

	if (phys_cpu_num <= 0) {
		BOOT_WARNING("Boot info structure passed by BIOS does not "
			"specify number of live physical CPUs\n");
	} else if (phys_cpu_num > NR_CPUS) {
		BOOT_WARNING("Boot info structure passed by BIOS specifies "
			"bad number of live physical CPUs %d\n",
			phys_cpu_num);
		phys_cpu_num = 0;
	}
	boot_phys_cpu_present_num = phys_cpu_num;
	boot_cpu_to_sync_num = phys_cpu_num;
	return (phys_cpu_num);
}

static inline int __init_recv
boot_romloader_smp_cpu_config(boot_info_t *bootblock)
{
	return boot_bios_smp_cpu_config(bootblock);
}

int __init_recv
boot_native_smp_cpu_config(boot_info_t *bootblock)
{
	int phys_cpu_num = 0;

	if (bootblock->signature == BOOTBLOCK_ROMLOADER_SIGNATURE)
		phys_cpu_num = boot_romloader_smp_cpu_config(bootblock);
	else if (bootblock->signature == BOOTBLOCK_BOOT_SIGNATURE)
		phys_cpu_num = boot_bios_smp_cpu_config(bootblock);
	else
		BOOT_BUG("Unknown type of Boot information structure");

	return phys_cpu_num;
}

void __init_recv
boot_bios_smp_node_config(boot_info_t *bootblock)
{
	int 		boot_nodes_num = bootblock->num_of_nodes;
	unsigned long	boot_nodes_map = bootblock->nodes_map;
	int		nodes_num;
	unsigned long	node_mask;

	if (boot_nodes_num == 0) {
		boot_nodes_num = 1;	/* pure SMP or old boot loader */
					/* without nodes support */
		boot_nodes_map = 0x1UL;	/* only node #0 */
	} else if (boot_nodes_num > L_MAX_MEM_NUMNODES) {
		BOOT_WARNING("Too many nodes : max number can be %d, other %d will be ignored",
			L_MAX_MEM_NUMNODES,
			boot_nodes_num - L_MAX_MEM_NUMNODES);
		boot_nodes_num = L_MAX_MEM_NUMNODES;
	}
	node_mask = 0x1UL;
	nodes_num = 0;
	while (node_mask) {
		if (boot_nodes_map & node_mask)
			nodes_num ++;
		if (nodes_num > L_MAX_MEM_NUMNODES) {
			BOOT_WARNING("Too many nodes in node map : max number can be %d, map 0x%lx,  following  0x%lx will be ignored",
				L_MAX_MEM_NUMNODES, boot_nodes_map,
				boot_nodes_map & ~(node_mask - 1));
			boot_nodes_map &= (node_mask - 1);
			nodes_num = L_MAX_MEM_NUMNODES;
			break;
		}
		node_mask <<= 1;
	}
	if (nodes_num != boot_nodes_num) {
		BOOT_WARNING("Number of nodes passed by boot loader %d is not the same as nodes in the passed %d (map 0x%lx",
			boot_nodes_num, nodes_num, boot_nodes_map);
	}
	
	boot_phys_nodes_num = nodes_num;
	boot_phys_nodes_map = boot_nodes_map;
}

static inline void __init_recv
boot_romloader_smp_node_config(boot_info_t *bootblock)
{
	boot_bios_smp_node_config(bootblock);
}

void __init_recv
boot_native_smp_node_config(boot_info_t *bootblock)
{
	if (bootblock->signature == BOOTBLOCK_ROMLOADER_SIGNATURE)
		boot_romloader_smp_node_config(bootblock);
	else if (bootblock->signature == BOOTBLOCK_BOOT_SIGNATURE)
		boot_bios_smp_node_config(bootblock);
	else
		BOOT_BUG("Unknown type of Boot information structure");
}

/*
 * Setup CPU configuration for boot-time initialization
 * Needed info passed by loader/BIOS thru bootinfo structure
 */

void __init
boot_setup_smp_cpu_config(boot_info_t *boot_info)
{
	int		phys_cpu_num = -1;

	phys_cpu_num = boot_smp_cpu_config(boot_info);
	boot_smp_node_config(boot_info);
	if (phys_cpu_num <= 0) {
		BOOT_WARNING("Boot info structure (passed by loader/BIOS) "
			"does not specify number of live physical CPUs\n");
		phys_cpu_num = boot_smp_processors_num();
		BOOT_WARNING("The number of live physical CPUs will be %d "
			"(all CPU(s) started boot process)\n",
			phys_cpu_num);
		boot_phys_cpu_present_num = phys_cpu_num;
		boot_cpu_to_sync_num = phys_cpu_num;
	} else if (phys_cpu_num > NR_CPUS) {
		BOOT_BUG("Number of live physical CPUs (passed thru boot info "
			"structure) is %d > %d (NR_CPUS - max allowed number "
			"of CPUs)\n",
			phys_cpu_num, NR_CPUS);
	} else if (boot_smp_processors_num() > phys_cpu_num) {
		BOOT_BUG("Number of live physical CPUs (passed thru boot info "
			"structure) is %d < %d (number of CPU(s) started boot "
			"process\n",
			phys_cpu_num, boot_smp_processors_num());
	}
	boot_printk("Number of live physical CPU(s) is set to %d\n",
		phys_cpu_num);
}

#ifdef	CONFIG_RECOVERY
/*
 * Setup CPU configuration for boot-time recovery of the system
 */

void boot_recover_smp_cpu_config(boot_info_t *boot_info)
{
	cpumask_t	*cpu_mask;
	int		phys_cpu_num = -1;
	int		new_phys_cpu_num = -1;

	boot_printk("boot_recover_smp_cpu_config() started with %d live physical CPU(s)\n",
		boot_phys_cpu_present_num);

	phys_cpu_num = boot_phys_cpu_present_num;
	new_phys_cpu_num = boot_smp_cpu_config(boot_info);

	/* From all global cpu masks (cpu_present_mask, cpu_online_mask,
	 * cpu_active_mask, cpu_possible_mask) only online mask is used
	 * for synchronization when recovering, so do not clear any other
	 * masks here. */
	cpu_mask = boot_vp_to_pp(&boot_get_vo_value(__cpu_online_mask));
	cpumask_clear(cpu_mask);

	if (new_phys_cpu_num <= 0) {
		BOOT_WARNING("Boot info structure (passed by loader/BIOS) does not specify number of live physical CPUs\n");
		new_phys_cpu_num = boot_smp_processors_num();

		BOOT_WARNING("The number of live physical CPUs will be %d (all CPU(s) started recovery process)\n",
			new_phys_cpu_num);

		boot_phys_cpu_present_num = new_phys_cpu_num;
		boot_cpu_to_sync_num = new_phys_cpu_num;
	} else if (new_phys_cpu_num > NR_CPUS) {
		BOOT_BUG("Number of live physical CPUs (passed thru boot info structure) is %d > %d (NR_CPUS - max allowed number of CPUs)\n",
			new_phys_cpu_num, NR_CPUS);
	} else if (boot_smp_processors_num() > new_phys_cpu_num) {
		BOOT_BUG("Number of live physical CPUs (passed thru boot info structure) is %d < %d (number of CPU(s) started recovery process\n",
			new_phys_cpu_num, boot_smp_processors_num());
	}

	if (phys_cpu_num != new_phys_cpu_num)
		BOOT_BUG("Number of live physical CPUs started recovery process (%d) is not the same as were interrupted at the control point (%d)\n",
			new_phys_cpu_num, phys_cpu_num);

	boot_printk("Number of live physical CPU(s) is %d\n",
		phys_cpu_num);
}
#endif	/* CONFIG_RECOVERY */
