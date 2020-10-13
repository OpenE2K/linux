/* $Id: boot_smp.c,v 1.14 2009/09/09 09:54:41 monahov_d Exp $
 *
 * Control of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */
#include <linux/init.h>
#include <linux/sched.h>
#include <stdarg.h>

#include <asm/types.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/boot_smp.h>
#include <asm/boot_bitops.h>
#include <asm/errors_hndl.h>
#include <asm/console.h>
#include <asm/current.h>
#include <asm/atomic.h>
#include <asm/smp.h>

#include <asm/e2k_debug.h>
#include <asm/console.h>
#include <asm/bootinfo.h>

#undef	DEBUG_BOOT_SMP_MODE
#undef	boot_printk
#undef	DebugBSMP
#define	DEBUG_BOOT_SMP_MODE	0	/* Boot SMP process */
#define	boot_printk		if (DEBUG_BOOT_SMP_MODE) do_boot_printk
#define	DebugBSMP		if (DEBUG_BOOT_SMP_MODE) printk

#ifdef	CONFIG_SMP

/* current number CPUs in synchronization function */
static atomic_t	 boot_sync_cpucount = ATOMIC_INIT(0);

/* error occured while boot-time initialization */
atomic_t  boot_error_flag = ATOMIC_INIT(0);

/* bit map of CPUs in synchronization function */
static unsigned long 	sync_cpu_map = 0UL;
#define	boot_sync_cpu_map	boot_get_vo_value(sync_cpu_map)

/* current point (number) of synchronization */
static atomic_t  boot_sync_point_num = ATOMIC_INIT(0);

#define	boot_read_sync_point() \
		boot_atomic_read(&boot_sync_point_num)
#define	boot_inc_sync_point() \
		boot_atomic_inc(&boot_sync_point_num)

static inline int
#ifndef	CONFIG_RECOVERY
__init
#endif	/* ! (CONFIG_RECOVERY) */
do_boot_sync_all_processors(int error_flag, long waiting_time)
{
	int	cpuid = boot_smp_processor_id();
	int	phys_cpu_num = boot_phys_cpu_present_num;
	int	sync_ok = 0;
	long	iter;
	int	loop = 0;
	int	cpu_num = -1;
	atomic_t *sync_cpucount_p;
	atomic_t *error_flag_p;

	boot_printk("boot_sync_all_processors() started : CPU #%d, "
		"synchronization point #%d\n",
		cpuid, boot_read_sync_point());
	if (boot_test_and_set_bit(cpuid, boot_vp_to_pp(&sync_cpu_map))) {
		BOOT_BUG_POINT("boot_sync_all_processors()");
		BOOT_BUG("CPU #%d already reached the synchronization "
			"point %d\n",
			cpuid, boot_read_sync_point());
	}
	if (error_flag != BOOT_NO_ERROR_FLAG) {
		boot_printk("boot_sync_all_processors() : CPU #%d "
			"started with error flag\n",
			cpuid);
		boot_set_event(&boot_error_flag);
	} else {
		boot_mb();
		cpu_num = boot_atomic_inc_return(&boot_sync_cpucount);
		if (cpu_num > phys_cpu_num) {
			BOOT_BUG_POINT("boot_sync_all_processors()");
			BOOT_BUG("CPU #%d : number of CPUs registered in "
				"the synchronization point %d is %d > than "
				"physical CPU present number %d\n",
				cpuid, boot_read_sync_point(),
				cpu_num, phys_cpu_num);
		}
	}
	sync_cpucount_p = boot_vp_to_pp(&boot_sync_cpucount);
	error_flag_p = boot_vp_to_pp(&boot_error_flag);
	boot_printk("boot_sync_all_processors() : CPU #%d "
		"current CPU sync counter is %d, phys CPU number is %d, "
		"error flag %d\n",
		cpuid, atomic_read(sync_cpucount_p), phys_cpu_num,
		atomic_read(error_flag_p));
	while (1) {
		for (iter = 0; iter < waiting_time; iter ++) {
			for (loop = 0; loop < BOOT_WAITING_FOR_SYNC_LOOPS;
								loop ++) {
				error_flag = atomic_read(error_flag_p);
				cpu_num = atomic_read(sync_cpucount_p);
				if (IS_BOOT_STRAP_CPU()) {
					if (cpu_num >= phys_cpu_num ||
								error_flag) {
						sync_ok = 1;
						break;
					}
				} else {
					if (cpu_num == 0 || error_flag) {
						sync_ok = 1;
						break;
					}
				}
				boot_mb();
			}
			boot_mb();
			if (sync_ok) break;
			boot_printk("boot_sync_all_processors() : CPU #%d "
				"synchronization was not reached in the "
				"iteration #%ld\n", cpuid, iter);
		}
		if (!sync_ok) {
			BOOT_WARNING_POINT("boot_sync_all_processors()");
			BOOT_WARNING("CPU #%d : synchronization was not "
				"completed : only %d CPU(s) from %d reached "
				"synchronization point %d\n",
				cpuid, boot_atomic_read(&boot_sync_cpucount),
				phys_cpu_num, boot_read_sync_point());
		} else {
			break;
		}
	}
	boot_printk("boot_sync_all_processors() : CPU #%d "
		"synchronization was reached in the loop #%d of iteration "
		"#%ld\n",
		cpuid, loop, iter);
	if (boot_read_event(&boot_error_flag)) {
		BOOT_BUG_POINT("boot_sync_all_processors()");
		BOOT_BUG("CPU #%d detected BOOT ERROR FLAG at the "
			"synchronization point %d\n",
			cpuid, boot_read_sync_point());
	} else if (sync_ok & IS_BOOT_STRAP_CPU()) {
		if (cpu_num != phys_cpu_num) {
			BOOT_BUG_POINT("boot_sync_all_processors()");
			BOOT_BUG("CPU #%d : number of CPUs registered in "
				"the synchronization point %d is %d != "
				"physical CPU present number %d\n",
				cpuid, boot_read_sync_point(),
				cpu_num, phys_cpu_num);
		} else if (cpu_num != boot_smp_processors_num()) {
			BOOT_BUG_POINT("boot_sync_all_processors()");
			BOOT_BUG("CPU #%d : number of CPUs registered in "
				"the synchronization point %d is %d != "
				"number of CPUs started boot process %d\n",
				cpuid, boot_read_sync_point(),
				cpu_num, boot_smp_processors_num());
		}
	}
	if (IS_BOOT_STRAP_CPU()) {
		boot_sync_cpu_map = 0UL;
		boot_inc_sync_point();
		boot_mb();
		boot_atomic_set(&boot_sync_cpucount, 0);
		boot_printk("boot_sync_all_processors() : bootstrap CPU #%d "
			"completed synchronization\n",
			cpuid);
	} else {
		boot_printk("boot_sync_all_processors() : application CPU #%d "
			"completed synchronization\n",
			cpuid);
	}
	return boot_read_event(&boot_error_flag);
}

int __init_recv
boot_sync_all_processors(int error_flag)
{
	return (do_boot_sync_all_processors(error_flag,
						BOOT_WAITING_FOR_SYNC_ITER));
}

int __init_recv
boot_timed_sync_all_processors(int error_flag, long waiting_time)
{
	return (do_boot_sync_all_processors(error_flag, waiting_time));
}

/*
 * Setup CPU configuration for boot-time initialization,
 * passed by BIOS thru bootblock structure
 */

static int __init_recv
boot_biosx86_smp_cpu_config(boot_info_t *bootblock)
{
	int		phys_cpu_num;

	phys_cpu_num = bootblock->num_of_cpus;

	if (phys_cpu_num <= 0) {
		BOOT_WARNING_POINT("boot_biosx86_smp_cpu_config()");
		BOOT_WARNING("Boot info structure passed by BIOS "
			"does not specify number of live physical CPUs\n");
	} else if (phys_cpu_num > NR_CPUS) {
		BOOT_WARNING_POINT("boot_biosx86_smp_cpu_config()");
		BOOT_WARNING("Boot info structure passed by BIOS "
			"specifies bad number of live physical CPUs %d\n",
			phys_cpu_num);
		phys_cpu_num = 0;
	}
	boot_phys_cpu_present_num = phys_cpu_num;
	return (phys_cpu_num);
}

static inline int __init_recv
boot_romloader_smp_cpu_config(boot_info_t *bootblock)
{
	return (boot_biosx86_smp_cpu_config(bootblock));
}

static void __init_recv
boot_biosx86_smp_node_config(boot_info_t *bootblock)
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
		BOOT_WARNING_POINT("boot_biosx86_smp_node_config");
		BOOT_WARNING("Too many nodes : max number "
			"can be %d, other %d will be ignored",
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
			BOOT_WARNING_POINT("boot_biosx86_smp_node_config");
			BOOT_WARNING("Too many nodes in node map : max number "
				"can be %d, map 0x%lx,  following  0x%lx "
				"will be ignored",
				L_MAX_MEM_NUMNODES, boot_nodes_map,
				boot_nodes_map & ~(node_mask - 1));
			boot_nodes_map &= (node_mask - 1);
			nodes_num = L_MAX_MEM_NUMNODES;
			break;
		}
		node_mask <<= 1;
	}
	if (nodes_num != boot_nodes_num) {
		BOOT_WARNING_POINT("boot_biosx86_smp_node_config");
		BOOT_WARNING("Number of nodes passed by boot loader %d "
			"is not the same as nodes in the passed %d (map 0x%lx",
			boot_nodes_num, nodes_num, boot_nodes_map);
	}
	
	boot_phys_nodes_num = nodes_num;
	boot_phys_nodes_map = boot_nodes_map;
}

static inline void __init_recv
boot_romloader_smp_node_config(boot_info_t *bootblock)
{
	boot_biosx86_smp_node_config(bootblock);
}

/*
 * Setup CPU configuration for boot-time initialization
 * Needed info passed by loader/BIOS thru bootinfo structure
 */

void __init
boot_setup_smp_cpu_config(void)
{
	boot_info_t	*bootblock;
	int		phys_cpu_num = -1;

	bootblock = &boot_bootblock_phys->info;
	if (bootblock->signature == ROMLOADER_SIGNATURE) {
		phys_cpu_num = boot_romloader_smp_cpu_config(bootblock);
		boot_romloader_smp_node_config(bootblock);
	} else if (bootblock->signature == X86BOOT_SIGNATURE) {
		phys_cpu_num = boot_biosx86_smp_cpu_config(bootblock);
		boot_biosx86_smp_node_config(bootblock);
	} else {
		BOOT_BUG_POINT("boot_setup_smp_cpu_config()");
		BOOT_BUG("Unknown type of Boot information structure");
	}
	if (phys_cpu_num <= 0) {
		BOOT_WARNING_POINT("boot_setup_smp_cpu_config()");
		BOOT_WARNING("Boot info structure (passed by loader/BIOS) "
			"does not specify number of live physical CPUs\n");
		phys_cpu_num = boot_smp_processors_num();
		BOOT_WARNING("The number of live physical CPUs will be %d "
			"(all CPU(s) started boot process)\n",
			phys_cpu_num);
		boot_phys_cpu_present_num = phys_cpu_num;
	} else if (phys_cpu_num > NR_CPUS) {
		BOOT_BUG_POINT("boot_setup_smp_cpu_config()");
		BOOT_BUG("Number of live physical CPUs (passed thru boot info "
			"structure) is %d > %d (NR_CPUS - max allowed number "
			"of CPUs)\n",
			phys_cpu_num, NR_CPUS);
	} else if (boot_smp_processors_num() > phys_cpu_num) {
		BOOT_BUG_POINT("boot_setup_smp_cpu_config()");
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

void
boot_recover_smp_cpu_config(void)
{
	boot_info_t	*bootblock;
	cpumask_t	*cpu_mask;
	int		phys_cpu_num = -1;
	int		new_phys_cpu_num = -1;

	boot_printk("boot_recover_smp_cpu_config() started with %d live "
		"physical CPU(s)\n",
		boot_phys_cpu_present_num);
	phys_cpu_num = boot_phys_cpu_present_num;
	bootblock = &boot_bootblock_phys->info;
	if (bootblock->signature == ROMLOADER_SIGNATURE) {
		new_phys_cpu_num = boot_romloader_smp_cpu_config(bootblock);
	} else if (bootblock->signature == X86BOOT_SIGNATURE) {
		new_phys_cpu_num = boot_biosx86_smp_cpu_config(bootblock);
	} else {
		BOOT_BUG_POINT("boot_recover_smp_cpu_config()");
		BOOT_BUG("Unknown type of Boot information structure");
	}

	/* From all global cpu masks (cpu_present_mask, cpu_online_mask,
	 * cpu_active_mask, cpu_possible_mask) only online mask is used
	 * for synchronization when recovering, so do not clear any other
	 * masks here. */
	cpu_mask = boot_vp_to_pp(boot_get_vo_value(cpu_online_mask));
	cpus_clear(*cpu_mask);
	if (new_phys_cpu_num <= 0) {
		BOOT_WARNING_POINT("boot_recover_smp_cpu_config()");
		BOOT_WARNING("Boot info structure (passed by loader/BIOS) "
			"does not specify number of live physical CPUs\n");
		new_phys_cpu_num = boot_smp_processors_num();
		BOOT_WARNING("The number of live physical CPUs will be %d "
			"(all CPU(s) started recovery process)\n",
			new_phys_cpu_num);
		boot_phys_cpu_present_num = new_phys_cpu_num;
	} else if (new_phys_cpu_num > NR_CPUS) {
		BOOT_BUG_POINT("boot_recover_smp_cpu_config()");
		BOOT_BUG("Number of live physical CPUs (passed thru boot info "
			"structure) is %d > %d (NR_CPUS - max allowed number "
			"of CPUs)\n",
			new_phys_cpu_num, NR_CPUS);
	} else if (boot_smp_processors_num() > new_phys_cpu_num) {
		BOOT_BUG_POINT("boot_recover_smp_cpu_config()");
		BOOT_BUG("Number of live physical CPUs (passed thru boot info "
			"structure) is %d < %d (number of CPU(s) started "
			"recovery process\n",
			new_phys_cpu_num, boot_smp_processors_num());
	}
	if (phys_cpu_num != new_phys_cpu_num) {
		BOOT_BUG_POINT("boot_recover_smp_cpu_config()");
		BOOT_BUG("Number of live physical CPUs started recovery "
			"process (%d) is not the same as were interrupted at "
			"the control point (%d)\n",
			new_phys_cpu_num, phys_cpu_num);
	}
	boot_printk("Number of live physical CPU(s) is %d\n",
		phys_cpu_num);
}
#endif	/* CONFIG_RECOVERY */

#endif	/* CONFIG_SMP */
