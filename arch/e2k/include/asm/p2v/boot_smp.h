/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Heading of SMP boot-time initialization.
 */

#ifndef	_E2K_P2V_BOOT_SMP_H
#define	_E2K_P2V_BOOT_SMP_H

#include <linux/init.h>

#include <linux/types.h>
#include <linux/smp.h>
#include <asm/cpu_regs_types.h>
#include <asm/head.h>
#include <asm/atomic.h>
#include <asm/thread_info.h>
#include <asm/topology.h>
#include <asm/p2v/boot_bitops.h>
#include <asm/p2v/boot_spinlock.h>

#ifndef __ASSEMBLY__

/*
 * Atomic operations for boot-time initialization
 */

#define	boot_mb()	mb()

#define	boot_atomic_read(value_p) \
		atomic_read((atomic_t *)boot_vp_to_pp(value_p))
#define	boot_atomic_set(value_p, count) \
		atomic_set((atomic_t *)boot_vp_to_pp(value_p), count)
#define	boot_atomic_inc(value_p) \
		atomic_inc((atomic_t *)boot_vp_to_pp(value_p))
#define	boot_atomic_dec(value_p) \
		atomic_dec((atomic_t *)boot_vp_to_pp(value_p))
#define	boot_atomic_inc_return(value_p) \
		atomic_inc_return((atomic_t *)boot_vp_to_pp(value_p))

/*
 * Current CPU logical # and total number of active CPUs
 */
extern atomic_t	boot_cpucount;
#define	boot_smp_get_processor_id()				\
({								\
	int cpu_id = boot_early_pic_read_id();			\
	boot_atomic_inc(&boot_cpucount);			\
	cpu_id;							\
})
#define	boot_smp_processors_num()	boot_atomic_read(&boot_cpucount)
#define	init_smp_processors_num()	atomic_read(&boot_cpucount)
#define	boot_reset_smp_processors_num()	boot_atomic_set(&boot_cpucount, 0)
#define	init_reset_smp_processors_num()	atomic_set(&boot_cpucount, 0)
#define	boot_set_smp_processors_num(num) boot_atomic_set(&boot_cpucount, num)
#define	init_set_smp_processors_num(num) atomic_set(&boot_cpucount, num)

/*
 * Special system register 'OSR0' is used to hold logical processor number
 * while boot-time initialization.
 * Later this register will be used to hold pointer to 'current' task structure
 */

#define	boot_smp_set_processor_id(cpuid)	\
		boot_set_current_thread_info(cpuid)
#define	boot_smp_processor_id()						\
({									\
	long cpuid = (long)boot_current_thread_info();			\
									\
	if (cpuid >= BOOT_TASK_SIZE)					\
		cpuid = raw_smp_processor_id();				\
	cpuid;								\
})

#ifdef CONFIG_SMP
#define	BOOT_IS_BSP(__bsp)	(__bsp)
#define	INIT_IS_BSP(__bsp)	(__bsp)
#else	/* ! CONFIG_SMP */
#define	BOOT_IS_BSP(__bsp)	true
#define	INIT_IS_BSP(__bsp)	true
#endif	/* CONFIG_SMP */

/*
 * Simple spin lock operations for SMP boot-time initialization
 */
#define boot_spin_trylock(lock)	arch_boot_spin_trylock(boot_vp_to_pp(lock))
#define boot_spin_lock(lock)	arch_boot_spin_lock(boot_vp_to_pp(lock))
#define boot_spin_unlock(lock)	arch_boot_spin_unlock(boot_vp_to_pp(lock))
#define init_spin_trylock(lock)	arch_boot_spin_trylock(lock)
#define init_spin_lock(lock)	arch_boot_spin_lock(lock)
#define init_spin_unlock(lock)	arch_boot_spin_unlock(lock)

/*
 * Simple event maintenance for boot-time initialization
 */
#define boot_set_event(event_p) boot_atomic_set(event_p, 1)
#define boot_wait_for_event(event_p)					\
({									\
	atomic_t *error_flag_p = boot_vp_to_pp(&boot_error_flag);	\
	while (!boot_atomic_read(event_p)) {				\
		if (unlikely(atomic_read(error_flag_p))) {		\
			BOOT_BUG("detected BOOT ERROR FLAG while "	\
				"wait for event\n");			\
		}							\
		boot_mb();						\
	}								\
})

#define boot_set_boot_event(boot_event_p) atomic_set(boot_event_p, 1)
#define boot_wait_for_boot_event(boot_event_p, error_flag_p)		\
({									\
	while (!atomic_read(boot_event_p)) {				\
		if (unlikely(atomic_read(error_flag_p))) {		\
			BOOT_BUG("detected BOOT ERROR FLAG while "	\
				"wait for event\n");			\
		}							\
		boot_mb();						\
	}								\
})

/*
 * Physical number and map of live CPUs passed by loader/BIOS through
 * bootinfo structure
 */

extern int	phys_cpu_present_num;	/* number of present CPUs */
					/* (passed by BIOS thru */
					/* MP table) */
extern int	cpu_to_sync_num;	/* real number of CPUs to make */
					/* sinchronization */

#define	boot_set_phys_cpu(cpuid, mask)	physid_set(cpuid, mask)
#define	boot_test_phys_cpu(cpuid, mask)	physid_isset(cpuid, mask)

#define	boot_phys_cpu_present_map_p	boot_vp_to_pp(&phys_cpu_present_map)

#define	boot_set_phys_cpu_present(cpu)	\
		boot_set_phys_cpu(cpu, *boot_phys_cpu_present_map_p)
#define boot_phys_cpu_present(cpu)	\
		boot_test_phys_cpu(cpu, *boot_phys_cpu_present_map_p)

#define	boot_phys_cpu_present_num	boot_get_vo_value(phys_cpu_present_num)
#ifdef CONFIG_SMP
# define boot_cpu_to_sync_num		boot_get_vo_value(cpu_to_sync_num)
#else
# define boot_cpu_to_sync_num		0
#endif

#ifdef	CONFIG_NUMA
#define boot_physid_to_cpu_mask(physid_mask_p)				\
({									\
	cpumask_t cpu_mask;						\
	bitmap_copy(cpumask_bits(&cpu_mask), physid_mask_p->bits,	\
			nr_cpumask_bits);				\
	cpu_mask;							\
})

#define boot_node_to_cpumask(node)					\
({									\
	cpumask_t cpumask;						\
	cpumask_t node_cpumask;						\
	cpumask_t boot_main_cpu_mask = boot_physid_to_cpu_mask(		\
			boot_phys_cpu_present_map_p);			\
	bitmap_fill(cpumask_bits(&cpumask), boot_machine.nr_node_cpus);	\
	cpumask_shift_left(&node_cpumask, (const cpumask_t *)&cpumask,	\
			node * boot_machine.max_nr_node_cpus);		\
	cpumask_and(&cpumask, &node_cpumask, &boot_main_cpu_mask);	\
	cpumask;							\
})

#define boot___apicid_to_node	boot_get_vo_value(__apicid_to_node)

#define boot_numa_node_id_initialized() (boot_machine.max_nr_node_cpus != 0)
#define boot_cpu_to_node(cpu)	((cpu) / boot_machine.max_nr_node_cpus)
#define	boot_numa_node_id()	boot_cpu_to_node(boot_smp_processor_id())
#define	BOOT_BS_NODE_ID		(0)
#define	BOOT_IS_BS_NODE		(boot_numa_node_id() == BOOT_BS_NODE_ID)

#define	boot_node_is_online(node)	\
		(boot_phys_nodes_map & (1 << (node))) 
#define boot_node_has_online_mem(nid)	\
		(boot_nodes_phys_mem[nid].pfns_num != 0)

#define	boot_for_each_node_has_online_mem(node)				\
		for ((node) = 0,					\
				({while ((node) < MAX_NUMNODES &&	\
					!boot_node_has_online_mem(node))\
					(node) ++;});			\
			(node) < MAX_NUMNODES;				\
			({ (node) ++; while ((node) < MAX_NUMNODES &&	\
					!boot_node_has_online_mem(node))\
					(node) ++;}))

#define boot_for_each_cpu(cpu, mask)				\
	for ((cpu) = -1;				\
		(cpu) = cpumask_next((cpu), (mask)),	\
		(cpu) < NR_CPUS;)

#define	boot_for_each_online_cpu_of_node(node, cpu, cpu_mask)		\
		cpu_mask = boot_node_to_cpumask(node);			\
		boot_for_each_cpu(cpu, &cpu_mask)

/*
 * Next variables, arrays, structures have own copy on each nodes
 */

/* number of nodes which have duplicated kernel image and own page tables */
extern atomic_t num_nodes_dup_kernel;

#define init_cpu_to_node(cpu)	((cpu) / machine.max_nr_node_cpus)
#define	init_numa_node_id()	init_cpu_to_node(boot_early_pic_read_id())
#else	/* ! CONFIG_NUMA */
#define boot_numa_node_id_initialized() true
#define	BOOT_IS_BS_NODE		1
#define	boot_numa_node_id()	0
#define boot_node_has_online_mem(nid)	1

#define	init_numa_node_id()	0
#endif	/* CONFIG_NUMA */

extern void boot_setup_smp_cpu_config(boot_info_t *boot_info);

/*
 * Flag of error occured while boot-time initialization
 */

extern atomic_t  boot_error_flag;

/*
 * Synchronize all active processors at the specified point while boot-time
 * initialization
 */

#define	BOOT_NO_ERROR_FLAG		0

#ifdef	CONFIG_VIRTUALIZATION
#include <asm/kvm/guest/boot.h>	/* to redefine synchronization times */
#endif	/* CONFIG_VIRTUALIZATION */

/*
 * number of iterations of waiting for completion of synchronization
 */
#ifndef	BOOT_WAITING_FOR_SYNC_ITER
#define	BOOT_WAITING_FOR_SYNC_ITER	(1000 * NR_CPUS)
#endif	/* ! BOOT_WAITING_FOR_SYNC_ITER */

/*
 * number of loops in each iteration of waiting for
 * synchronization completion
 */

#ifndef	BOOT_WAITING_FOR_SYNC_LOOPS
#if defined(CONFIG_MEMLIMIT) && defined(CONFIG_EXT_MEMLIMIT)
#define	BOOT_WAITING_FOR_SYNC_LOOPS	(NR_CPUS * 64 *	\
					(CONFIG_MEMLIMIT+CONFIG_EXT_MEMLIMIT))
#else
#define	BOOT_WAITING_FOR_SYNC_LOOPS	(NR_CPUS * 16000)
#endif
#endif	/* ! BOOT_WAITING_FOR_SYNC_LOOPS */

#ifdef CONFIG_SMP
typedef union cpu_sync_count {
	atomic_t num_arrived;
	u64	 pad;
} cpu_sync_count_t;

extern void __boot_sync_all_processors(atomic_t *num_arrived);
extern void __init_sync_all_processors(atomic_t *num_arrived, int cpus_to_sync);

extern cpu_sync_count_t __cacheline_aligned_in_smp num_arrived;
# define boot_sync_all_processors() \
do { \
	__boot_sync_all_processors(&num_arrived.num_arrived); \
} while (0)

/* number of CPUs arrived to sync while boot-time init completion */
extern cpu_sync_count_t __cacheline_aligned_in_smp init_num_arrived;
# define init_sync_all_processors(cpus) \
do { \
	__init_sync_all_processors(&init_num_arrived.num_arrived, cpus); \
} while (0)
#else
# define boot_sync_all_processors()	do { } while (0)
# define init_sync_all_processors(cpus)	do { } while (0)
#endif

extern int boot_native_smp_cpu_config(boot_info_t *bootblock);
extern int boot_bios_smp_cpu_config(boot_info_t *bootblock);
extern void boot_native_smp_node_config(boot_info_t *bootblock);
extern void boot_bios_smp_node_config(boot_info_t *bootblock);

static inline void boot_native_cpu_relax(void)
{
	E2K_NOP(7);
}

#ifdef CONFIG_RECOVERY
extern void boot_recover_smp_cpu_config(boot_info_t *boot_info);
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/boot.h>
#else	/* native kernel */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
static inline e2k_size_t __init
boot_smp_cpu_config(boot_info_t *bootblock)
{
	return boot_native_smp_cpu_config(bootblock);
}
static inline void __init
boot_smp_node_config(boot_info_t *bootblock)
{
	boot_native_smp_node_config(bootblock);
}
static inline void
boot_cpu_relax(void)
{
	boot_native_cpu_relax();
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* !(__ASSEMBLY__) */
#endif /* !(_E2K_P2V_BOOT_SMP_H) */
