/* $Id: boot_smp.h,v 1.11 2008/06/11 20:02:07 atic Exp $
 *
 * Heading of SMP boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_P2V_BOOT_SMP_H
#define	_E2K_P2V_BOOT_SMP_H

#include <linux/init.h>

#include <linux/types.h>
#include <linux/smp.h>
#include <asm/cpu_regs_types.h>
#include <asm/head.h>
#include <asm/atomic.h>
#include <asm/p2v/boot_bitops.h>

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
 * Simple IRQ save/restore operations for SMP boot-time initialization
 */

#define boot_raw_local_irq_restore(x)		BOOT_UPSR_RESTORE(x)
#define boot_raw_local_irq_disable()		BOOT_UPSR_ALL_CLI()
#define boot_raw_local_save_flags(x)		BOOT_UPSR_SAVE(x)
#define boot_raw_irqs_disabled_flags(x)		__raw_irqs_disabled_flags(x)
#define boot_raw_local_irq_enable()		BOOT_UPSR_ALL_STI()
#define boot_raw_local_irq_save(x)		BOOT_UPSR_ALL_SAVE_AND_CLI(x)

/*
 * Simple spin lock operations for SMP boot-time initialization
 */

#ifdef CONFIG_SMP

# include <asm/p2v/boot_spinlock.h>

# define boot_spin_trylock(lock) arch_boot_spin_trylock(boot_vp_to_pp(lock)
# define boot_spin_lock(lock) arch_boot_spin_lock(boot_vp_to_pp(lock))
# define boot_spin_unlock(lock) arch_boot_spin_unlock(boot_vp_to_pp(lock))
# define init_spin_trylock(lock) arch_boot_spin_trylock(lock)
# define init_spin_lock(lock) arch_boot_spin_lock(lock)
# define init_spin_unlock(lock) arch_boot_spin_unlock(lock)
#else	/* ! CONFIG_SMP */
# define boot_spin_trylock(lock_p)
# define boot_spin_lock(lock_p)
# define boot_spin_unlock(lock_p)
# define init_spin_trylock(lock_p)
# define init_spin_lock(lock_p)
# define init_spin_unlock(lock_p)
#endif /* CONFIG_SMP */

#define boot_spin_lock_irqsave(lock_p, flags) \
({ \
	boot_raw_local_irq_save(flags); \
	boot_spin_lock(lock_p); \
})

#define boot_spin_unlock_irqrestore(lock_p, flags) \
({ \
	boot_spin_unlock(lock_p); \
	boot_raw_local_irq_restore(flags); \
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

#define	init_dup_node_spin_trylock(lock_p)	\
		init_spin_trylock(&lock_p[init_my_node_dup_kernel_nid])
#define	init_dup_node_spin_lock(lock_p)		\
		init_spin_lock(&lock_p[init_my_node_dup_kernel_nid])
#define	init_dup_node_spin_unlock(lock_p)	\
		init_spin_unlock(&lock_p[init_my_node_dup_kernel_nid])

/*
 * Simple event maintenance for boot-time initialization
 */

#define	boot_wait_for_event(event_p)					\
({									\
	atomic_t *error_flag_p = boot_vp_to_pp(&boot_error_flag);	\
	while (!boot_atomic_read(event_p)) {				\
		if (unlikely(atomic_read(error_flag_p))) {		\
			BOOT_BUG_POINT(__func__);			\
			BOOT_BUG("detected BOOT ERROR FLAG while "	\
				"wait for event\n");			\
		}							\
		boot_mb();						\
	}								\
})
#define	boot_read_event(event_p) \
		boot_atomic_read(event_p)
#define	boot_set_event(event_p) \
		boot_atomic_set(event_p, 1)
#define	boot_reset_event(event_p) \
		boot_atomic_set(event_p, 0)
#define	boot_wait_for_boot_event(boot_event_p, error_flag_p)		\
({									\
	while (!atomic_read(boot_event_p)) {				\
		if (unlikely(atomic_read(error_flag_p))) {		\
			BOOT_BUG_POINT(__func__);			\
			BOOT_BUG("detected BOOT ERROR FLAG while "	\
				"wait for event\n");			\
		}							\
		boot_mb();						\
	}								\
})
#define	boot_read_boot_event(boot_event_p)	atomic_read(boot_event_p)
#define	boot_set_boot_event(boot_event_p)	atomic_set(boot_event_p, 1)
#define	boot_reset_boot_event(boot_event_p)	atomic_set(boot_event_p, 0)

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
#define	boot_cpu_to_sync_num		boot_get_vo_value(cpu_to_sync_num)

#ifdef	CONFIG_NUMA
extern atomic_t early_node_has_dup_kernel_num;

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

#define boot_cpu_to_node(cpu)	((cpu) / boot_machine.max_nr_node_cpus)
#define	boot_numa_node_id()	boot_cpu_to_node(boot_smp_processor_id())
#define	BOOT_BS_NODE_ID		(0)
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
/* map of nodes which have duplicated kernel image and own page tables */
#define	boot_the_node_has_dup_kernel_map(nid)				\
		boot_the_node_get_vo_value(nid, node_has_dup_kernel_map)
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

/* number of nodes which have duplicated kernel image and own page tables */
#define	boot_early_node_has_dup_kernel_num				\
		boot_get_vo_value(early_node_has_dup_kernel_num)
#define	boot_the_node_has_dup_kernel_num(nid)				\
		boot_the_node_get_vo_value(nid, node_has_dup_kernel_num)
#define	BOOT_EARLY_THERE_IS_DUP_KERNEL					\
		boot_atomic_read(&boot_early_node_has_dup_kernel_num)
#define	BOOT_EARLY_DUP_KERNEL_NUM					\
		(boot_atomic_read(&boot_early_node_has_dup_kernel_num) + 1)
#define	BOOT_THE_NODE_THERE_IS_DUP_KERNEL(nid)				\
		boot_atomic_read(&boot_the_node_has_dup_kernel_num(nid))
#define	BOOT_THE_NODE_DUP_KERNEL_NUM(nid)				\
		(boot_atomic_read(&boot_the_node_has_dup_kernel_num(nid)) + 1)
#define	BOOT_NODE_THERE_IS_DUP_KERNEL()				\
		BOOT_THE_NODE_THERE_IS_DUP_KERNEL(boot_numa_node_id())
#define	BOOT_NODE_DUP_KERNEL_NUM()				\
		BOOT_THE_NODE_DUP_KERNEL_NUM(boot_numa_node_id())

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
#define	init_my_node_dup_kernel_nid					\
		node_dup_kernel_nid(init_numa_node_id())

/* array of pointers to pg_dir (root page table) on each node */
#define	boot_the_node_pg_dir(nid)					\
		((pgd_t **)(boot_the_node_vp_to_pp(nid,			\
						all_nodes_pg_dir)))
#define	boot_node_pg_dir						\
		boot_the_node_pg_dir(boot_numa_node_id())

#define init_cpu_to_node(cpu)	((cpu) / machine.max_nr_node_cpus)
#define	init_numa_node_id()	init_cpu_to_node(boot_early_pic_read_id())
#else	/* ! CONFIG_NUMA */
#define	BOOT_IS_BS_NODE		1
#define	boot_numa_node_id()	0
#define	boot_for_each_node_has_dup_kernel(node)				\
		for ((node) = 0, (node) < 1; (node) ++)
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
extern int boot_biosx86_smp_cpu_config(boot_info_t *bootblock);
extern void boot_native_smp_node_config(boot_info_t *bootblock);
extern void boot_biosx86_smp_node_config(boot_info_t *bootblock);

static inline void boot_native_cpu_relax(void)
{
	/* nothing to do */
}

#ifdef CONFIG_RECOVERY
extern void boot_recover_smp_cpu_config(boot_info_t *boot_info);
#endif	/* CONFIG_RECOVERY */

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/boot.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops */
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
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* !(__ASSEMBLY__) */
#endif /* !(_E2K_P2V_BOOT_SMP_H) */
