/* $Id: boot_smp.h,v 1.11 2008/06/11 20:02:07 atic Exp $
 *
 * Heading of SMP boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_BOOT_SMP_H
#define	_E2K_BOOT_SMP_H

#include <linux/init.h>

#include <asm/types.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/atomic.h>
#include <asm/boot_bitops.h>
#include <asm/smp.h>
#ifdef	CONFIG_SMP
#include <asm/spinlock.h>
#endif	/* CONFIG_SMP */

#ifndef __ASSEMBLY__

//#ifdef	CONFIG_SMP

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

#define	IS_BOOT_STRAP_CPU()	(BootStrap(arch_apic_read(APIC_BSP)))

extern atomic_t	boot_cpucount;
#define	boot_smp_get_processor_id()				\
({								\
	boot_atomic_inc(&boot_cpucount);			\
	READ_APIC_ID();						\
})
#define	boot_smp_processors_num() \
		boot_atomic_read(&boot_cpucount)
#define	init_smp_processors_num() \
		atomic_read(&boot_cpucount)
#define	boot_reset_smp_processors_num() \
		boot_atomic_set(&boot_cpucount, 0)
#define	init_reset_smp_processors_num() \
		atomic_set(&boot_cpucount, 0)
#define	boot_set_smp_processors_num(num) \
		boot_atomic_set(&boot_cpucount, num)
#define	init_set_smp_processors_num(num) \
		atomic_set(&boot_cpucount, num)

/*
 * Special system register 'OSR0' is used to hold logical processor number
 * while boot-time initialization.
 * Later this register will be used to hold pointer to 'current' task structure
 */
	
#define	boot_smp_set_processor_id(cpuid) (E2K_SET_DSREG_NV(osr0, (long)cpuid))
#define	boot_smp_processor_id()	\
		(((e2k_addr_t)current_thread_info() >= TASK_SIZE) ? \
			raw_smp_processor_id() : ((long)E2K_GET_DSREG_NV(osr0)))
#define	init_smp_processor_id() \
		(((e2k_addr_t)current_thread_info() >= TASK_SIZE) ? \
			raw_smp_processor_id() : ((long)E2K_GET_DSREG_NV(osr0)))

/*
 * Simple spin lock operations for SMP boot-time initialization
 */

#ifdef CONFIG_SMP
# define boot_spin_trylock(lock_p)	arch_spin_trylock \
		(boot_vp_to_pp(&((struct raw_spinlock *) lock_p)->raw_lock))
# define boot_spin_lock(lock_p)		arch_spin_lock \
		(boot_vp_to_pp(&((struct raw_spinlock *) lock_p)->raw_lock))
# define boot_spin_unlock(lock_p)	arch_spin_unlock \
		(boot_vp_to_pp(&((struct raw_spinlock *) lock_p)->raw_lock))
#else
# define boot_spin_trylock(lock_p)
# define boot_spin_lock(lock_p)
# define boot_spin_unlock(lock_p)
#endif /* CONFIG_SMP */

#define boot_spin_lock_irqsave(lock_p, flags) \
({ \
	raw_local_irq_save(flags); \
	boot_spin_lock(lock_p); \
})

#define boot_spin_unlock_irqrestore(lock_p, flags) \
({ \
	boot_spin_unlock(lock_p); \
	raw_local_irq_restore(flags); \
})


/*
 * Simple spin lock operations for the CPU node boot-time initialization
 */

#define	boot_node_spin_trylock(lock_p)	\
		boot_spin_trylock(&lock_p[boot_numa_node_id()])
#define	boot_node_spin_lock(lock_p)	\
		boot_spin_lock(&lock_p[boot_numa_node_id()])
#define	boot_node_spin_unlock(lock_p)	\
		boot_spin_unlock(&lock_p[boot_numa_node_id()])

#define	boot_dup_node_spin_trylock(lock_p)	\
		boot_spin_trylock(&lock_p[boot_my_node_dup_kernel_nid])
#define	boot_dup_node_spin_lock(lock_p)		\
		boot_spin_lock(&lock_p[boot_my_node_dup_kernel_nid])
#define	boot_dup_node_spin_unlock(lock_p)	\
		boot_spin_unlock(&lock_p[boot_my_node_dup_kernel_nid])

/*
 * Simple event maintenance for boot-time initialization
 */

#define	boot_wait_for_event(event_p) \
		while (!boot_atomic_read(event_p)) { boot_mb(); }
#define	boot_read_event(event_p) \
		boot_atomic_read(event_p)
#define	boot_set_event(event_p) \
		boot_atomic_set(event_p, 1)
#define	boot_reset_event(event_p) \
		boot_atomic_set(event_p, 0)

/*
 * Physical number and map of live CPUs passed by loader/BIOS through
 * bootinfo structure
 */

extern int		phys_cpu_present_num;	/* number of present CPUs */
						/* (passed by BIOS thru */
						/* MP table) */

#define	boot_set_cpu(cpu, mask)		set_bit(cpu, (mask).bits)
#define	boot_set_phys_cpu(cpuid, mask)	physid_set(cpuid, mask)

#define	boot_get_cpu_possible_map_p					\
({									\
	const struct cpumask *cpu_mask_p;				\
	cpu_mask_p = boot_get_vo_value(cpu_possible_mask);		\
	boot_vp_to_pp(cpu_mask_p);					\
})
#define	boot_cpu_possible_map_p						\
({									\
	cpumask_t *cpu_map_p = boot_get_cpu_possible_map_p;		\
	(cpu_map_p);							\
})
#define	boot_set_cpu_possible(cpu)					\
({									\
	boot_set_cpu(cpu, *boot_cpu_possible_map_p);			\
})
#define	boot_cpu_possible(cpu)		\
		cpu_isset((cpu), *(boot_cpu_possible_map_p))

#define	boot_get_cpu_present_map_p					\
({									\
	const struct cpumask *cpu_mask_p;				\
	cpu_mask_p = boot_get_vo_value(cpu_present_mask);		\
	boot_vp_to_pp(cpu_mask_p);					\
})
#define	boot_cpu_present_map_p						\
({									\
	cpumask_t *cpu_map_p = boot_get_cpu_present_map_p;		\
	(cpu_map_p);							\
})
#define	boot_phys_cpu_present_map	boot_get_vo_value(phys_cpu_present_map)
#define	boot_phys_cpu_present_num	boot_get_vo_value(phys_cpu_present_num)
#define	boot_set_cpu_present(cpu)					\
({									\
		boot_set_phys_cpu(cpu, boot_phys_cpu_present_map);	\
		boot_set_cpu(cpu, *boot_cpu_present_map_p);		\
})

#ifdef	CONFIG_NUMA

#define boot___cpu_to_node		boot_get_vo_value(__cpu_to_node)

#define boot_cpu_to_node(cpu)				\
({							\
	int ret;					\
	if (BOOT_IS_MACHINE_E3M)			\
		ret = boot_e3m_cpu_to_node(cpu);	\
	else if (BOOT_IS_MACHINE_E3S)			\
		ret = boot_e3s_cpu_to_node(cpu);	\
	else if (BOOT_IS_MACHINE_ES2)			\
		ret = boot_es2_cpu_to_node(cpu);	\
	else if (BOOT_IS_MACHINE_E2S)			\
		ret = boot_e2s_cpu_to_node(cpu);	\
	else if (BOOT_IS_MACHINE_E8C)			\
		ret = boot_e8c_cpu_to_node(cpu);	\
	else if (BOOT_IS_MACHINE_E1CP)			\
		ret = boot_e1cp_cpu_to_node(cpu);	\
	else						\
		ret = boot_e8c2_cpu_to_node(cpu);	\
	ret;						\
})
#define boot_node_to_cpumask(node)					   \
({									   \
	cpumask_t boot_main_cpu_mask = *boot_cpu_present_map_p, ret;	   \
	if (BOOT_IS_MACHINE_E3M)					   \
		ret = boot_e3m_node_to_cpumask(node, boot_main_cpu_mask);  \
	else if (BOOT_IS_MACHINE_E3S)					   \
		ret = boot_e3s_node_to_cpumask(node, boot_main_cpu_mask);  \
	else if (BOOT_IS_MACHINE_ES2)					   \
		ret = boot_es2_node_to_cpumask(node, boot_main_cpu_mask);  \
	else if (BOOT_IS_MACHINE_E2S)					   \
		ret = boot_e2s_node_to_cpumask(node, boot_main_cpu_mask);  \
	else if (BOOT_IS_MACHINE_E8C)					   \
		ret = boot_e8c_node_to_cpumask(node, boot_main_cpu_mask);  \
	else if (BOOT_IS_MACHINE_E1CP)					   \
		ret = boot_e1cp_node_to_cpumask(node, boot_main_cpu_mask); \
	else								   \
		ret = boot_e8c2_node_to_cpumask(node, boot_main_cpu_mask); \
	ret;								   \
})
#define	BOOT_BS_NODE_ID		(0)
#define	boot_numa_node_id()	boot_cpu_to_node(boot_smp_processor_id())
#define	BOOT_IS_BS_NODE		(boot_numa_node_id() == BOOT_BS_NODE_ID)
#define	boot_node_is_online(node)	\
		(boot_phys_nodes_map & (1 << (node))) 
#define boot_node_has_online_mem(nid)	\
		(boot_nodes_phys_mem[nid].pfns_num != 0)
#define	boot_early_node_has_dup_kernel_from(node_from)			\
({									\
	int node = (node_from);						\
	while (node < MAX_NUMNODES &&					\
		!BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(node)) {		\
		node ++;						\
	}								\
	node;								\
})
#define	boot_early_next_node_has_dup_kernel(node_prev)			\
		boot_early_node_has_dup_kernel_from((node_prev) + 1)
#define	boot_node_has_dup_kernel_from(node_from)			\
({									\
	int node = (node_from);						\
	while (node < MAX_NUMNODES &&					\
		!boot_the_node_has_dup_kernel(boot_numa_node_id(),	\
							node)) {	\
		node ++;						\
	}								\
	node;								\
})
#define	boot_next_node_has_dup_kernel(node_prev)			\
({									\
	int node_from = (node_prev) + 1;				\
	boot_node_has_dup_kernel_from(node_from);			\
})
#define	boot_node_has_not_dup_kernel_from(node_from)			\
({									\
	int node = (node_from);						\
	while (node < MAX_NUMNODES && (!boot_node_is_online(node) ||	\
		boot_the_node_has_dup_kernel(boot_numa_node_id(),	\
							node))) {	\
		node ++;						\
	}								\
	node;								\
})
#define	boot_next_node_has_not_dup_kernel(node_prev)			\
({									\
	int node_from = (node_prev) + 1;				\
	boot_node_has_not_dup_kernel_from(node_from);			\
})
/*
 * Get a next node which has own duplicated kernel image
 * We start from the follow node and search in direct of increasing
 * node number. If there is not more nodes, we start new search from
 * node #1 and only at last we take node #0 so same algorithm is used
 * while building zone lists on each node (see mm/page_alloc.c)
 */
#define	boot_early_get_next_node_has_dup_kernel(node_prev)		\
({									\
	int node_next = boot_early_next_node_has_dup_kernel(node_prev);	\
	if (node_next >= MAX_NUMNODES) {				\
		node_next = boot_early_next_node_has_dup_kernel(0);	\
		if (node_next >= MAX_NUMNODES) {			\
			node_next = 0;	/* BS node */			\
		}							\
	}								\
	node_next;							\
})

#define	boot_for_each_node_has_online_mem(node)				\
		for ((node) = 0,					\
				({while ((node) < MAX_NUMNODES &&	\
					!boot_node_has_online_mem(node))\
					(node) ++;});			\
			(node) < MAX_NUMNODES;				\
			({ (node) ++; while ((node) < MAX_NUMNODES &&	\
					!boot_node_has_online_mem(node))\
					(node) ++;}))

#define	boot_for_each_node_has_dup_kernel(node)				\
		for ((node) = boot_node_has_dup_kernel_from(0);		\
			(node) < MAX_NUMNODES;				\
			(node) = boot_next_node_has_dup_kernel(node))

#define	boot_for_each_node_has_not_dup_kernel(node)			\
		for ((node) = boot_node_has_not_dup_kernel_from(0);	\
			(node) < MAX_NUMNODES;				\
			(node) = boot_next_node_has_not_dup_kernel(node))

#define	boot_for_each_online_cpu_of_node(node, cpu, cpu_mask)		\
		cpu_mask = boot_node_to_cpumask(node);			\
		for_each_cpu_mask(cpu, cpu_mask)

/*
 * Next variables, arrays, structures have own copy on each nodes
 */
/* map of nodes which have duplicated kernel image and own page tables */
#define	boot_the_node_has_dup_kernel_map(nid)				\
		boot_the_node_get_vo_value(nid, node_has_dup_kernel_map)
#define	boot_node_has_dup_kernel_map					\
		boot_the_node_has_dup_kernel_map(boot_numa_node_id())
#define	boot_the_node_has_dup_kernel(nid_where, nid_which)		\
		boot_test_bit(nid_which,				\
			boot_the_node_vp_to_pp(nid_where,		\
				&(node_has_dup_kernel_map)))
#define	boot_node_has_dup_kernel()					\
		boot_the_node_has_dup_kernel(boot_numa_node_id(),	\
						boot_numa_node_id())
#define	boot_the_node_set_has_dup_kernel(nid_where, nid_which)		\
		boot_set_bit(nid_which,					\
			boot_the_node_vp_to_pp(nid_where,		\
				&(node_has_dup_kernel_map)))
#define	boot_node_set_has_dup_kernel					\
		boot_the_node_set_has_dup_kernel(boot_numa_node_id(),	\
						boot_numa_node_id())

/* number of nodes which have duplicated kernel image and own page tables */
#define	boot_node_has_dup_kernel_num					\
		boot_get_vo_value(node_has_dup_kernel_num)
#define	boot_the_node_has_dup_kernel_num(nid)				\
		boot_the_node_get_vo_value(nid, node_has_dup_kernel_num)
#define	BOOT_THERE_IS_DUP_KERNEL					\
		boot_atomic_read(&boot_node_has_dup_kernel_num)
#define	BOOT_DUP_KERNEL_NUM						\
		(boot_atomic_read(&boot_node_has_dup_kernel_num) + 1)

/* array of node ID on which this node has kernel image and use page table */
/* if the node has own copy of the kernel then node ID is own ID */
/* if the node has not own copy of image and page table then node ID is */
/* ID of node on which it use kernel image and page table (now in this case */
/* node ID of BS NODE) */
#define	boot_the_node_dup_kernel_nid(nid)				\
		((int *)(boot_the_node_vp_to_pp(nid,			\
						all_nodes_dup_kernel_nid)))
#define	boot_dup_kernel_nid						\
		boot_the_node_dup_kernel_nid(boot_numa_node_id())
#define	boot_node_dup_kernel_nid(node)					\
		(boot_dup_kernel_nid[node])
#define	boot_my_node_dup_kernel_nid					\
		boot_node_dup_kernel_nid(boot_numa_node_id())

/* array of pointers to pg_dir (root page table) on each node */
#define	boot_the_node_pg_dir(nid)					\
		((pgd_t **)(boot_the_node_vp_to_pp(nid,			\
						all_nodes_pg_dir)))
#define	boot_node_pg_dir						\
		boot_the_node_pg_dir(boot_numa_node_id())
#else	/* ! CONFIG_NUMA */
#define	BOOT_IS_BS_NODE		1
#define	boot_numa_node_id()	0
#define	boot_for_each_node_has_dup_kernel(node)				\
		for ((node) = 0, (node) < 1; (node) ++)
#endif	/* CONFIG_NUMA */
extern void __init	boot_setup_smp_cpu_config(void);

/*
 * Flag of error occured while boot-time initialization
 */

extern atomic_t  boot_error_flag;

/*
 * Synchronize all active processors at the specified point while boot-time
 * initialization
 */

#define	BOOT_NO_ERROR_FLAG		0
#define	BOOT_FAIL_ERROR_FLAG		1

/*
 * number of iterations of waiting for completion of synchronization
 */
#define	BOOT_WAITING_FOR_SYNC_ITER	(1000 * NR_CPUS)

/*
 * number of loops in each iteration of waiting for
 * synchronization completion
 */

#if defined(CONFIG_MEMLIMIT) && defined(CONFIG_EXT_MEMLIMIT)
#define	BOOT_WAITING_FOR_SYNC_LOOPS	(NR_CPUS * 64 *	\
					(CONFIG_MEMLIMIT+CONFIG_EXT_MEMLIMIT))
#else
#define	BOOT_WAITING_FOR_SYNC_LOOPS	(NR_CPUS * 16000)
#endif

extern int __init_recv boot_sync_all_processors(int error_flag);
extern int __init_recv boot_timed_sync_all_processors(int error_flag,
							long waiting_time);

#ifdef	CONFIG_RECOVERY
extern void	boot_recover_smp_cpu_config(void);
#endif	/* CONFIG_RECOVERY */

//#endif	/* CONFIG_SMP */

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_BOOT_SMP_H) */
