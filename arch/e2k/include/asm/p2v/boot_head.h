/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Heading of boot-time initialization.
 */

#ifndef	_E2K_P2V_BOOT_HEAD_H
#define	_E2K_P2V_BOOT_HEAD_H

#include <linux/init.h>
#include <linux/numa.h>

#include <asm/p2v/boot_v2p.h>
#include <asm/types.h>
#include <asm/cpu_regs_access.h>
#include <asm/e2k.h>
#include <asm/head.h>
#include <asm/p2v/boot_smp.h>
#include <asm/bootinfo.h>

#ifndef __ASSEMBLY__

#ifndef	CONFIG_SMP
extern unsigned char	boot_init_started;	/* boot-time initialization */
						/* has been started */
extern unsigned char	_va_support_on;		/* virtual addressing support */
						/* has turned on */
#define	boot_boot_init_started		boot_get_vo_value(boot_init_started)
#define	boot_va_support_on		boot_get_vo_value(_va_support_on)
#define	va_support_on			_va_support_on
#else
extern unsigned char		boot_init_started[NR_CPUS];
						/* boot-time initialization */
						/* has been started */
extern unsigned char		_va_support_on[NR_CPUS];
						/* virtual addressing support */
						/* has turned on */
#define	boot_boot_init_started \
		(boot_vp_to_pp((unsigned char *)boot_init_started)) \
						[boot_smp_processor_id()]
#define	boot_va_support_on \
		(boot_vp_to_pp((unsigned char *)_va_support_on)) \
						[boot_smp_processor_id()]
#define	va_support_on		_va_support_on[boot_smp_processor_id()]
#endif	/* CONFIG_SMP */

extern	bootblock_struct_t *bootblock_phys;	/* bootblock structure */
						/* physical pointer */
extern	bootblock_struct_t *bootblock_virt;	/* bootblock structure */
						/* virtual pointer */
#define	boot_bootblock_phys	boot_get_vo_value(bootblock_phys)
#define	boot_bootblock_virt	boot_get_vo_value(bootblock_virt)
#define	boot_cpu_model_mismatch	boot_get_vo_value(cpu_model_mismatch)

#ifdef	CONFIG_E2K_MACHINE
# define boot_native_machine_id	(native_machine_id)
#else
# if defined(CONFIG_E2S) || defined(CONFIG_E8C) || defined(CONFIG_E1CP) || \
	defined(CONFIG_E8C2) || defined(CONFIG_E12C) || defined(CONFIG_E16C) || \
	defined(CONFIG_E2C3) || defined(CONFIG_E48C) || defined(CONFIG_E8V7)
#  define boot_native_machine_id	(native_machine_id)
# else
#  define boot_native_machine_id	boot_get_vo_value(native_machine_id)
# endif
#endif

extern e2k_addr_t start_of_phys_memory;	/* start address of physical memory */
extern e2k_addr_t end_of_phys_memory;	/* end address + 1 of physical memory */
extern e2k_size_t pages_of_phys_memory;	/* number of pages of physical memory */

#define	boot_start_of_phys_memory	boot_get_vo_value(start_of_phys_memory)
#define	boot_end_of_phys_memory		boot_get_vo_value(end_of_phys_memory)
#define	boot_pages_of_phys_memory	boot_get_vo_value(pages_of_phys_memory)

extern int		phys_nodes_num;		/* total number of online */
						/* nodes */
extern unsigned long 	phys_nodes_map;		/* map of all online nodes */
extern int		phys_mem_nodes_num;	/* number of online nodes */
						/* only with memory */
extern unsigned long	phys_mem_nodes_map;	/* map of online nodes */
						/* only with memory */
#define	boot_phys_nodes_num		boot_get_vo_value(phys_nodes_num)
#define	boot_phys_nodes_map		boot_get_vo_value(phys_nodes_map)
#define	boot_phys_mem_nodes_num		boot_get_vo_value(phys_mem_nodes_num)
#define	boot_phys_mem_nodes_map		boot_get_vo_value(phys_mem_nodes_map)

struct node_lock_single {
	boot_spinlock_t lock;
	bool done;
} ____cacheline_aligned_in_smp;
struct node_lock {
	struct node_lock_single nodes[MAX_NUMNODES];
};
#define BOOT_NODE_LOCK_INIT { \
	.nodes[0 ... MAX_NUMNODES - 1].lock = __BOOT_SPIN_LOCK_UNLOCKED, \
	.nodes[0 ... MAX_NUMNODES - 1].done = false \
}

static inline bool __boot_node_lock(int node, struct node_lock *node_lock)
{
	struct node_lock *boot_node_lock = boot_vp_to_pp(node_lock);
	bool done;

	boot_spin_lock(&boot_node_lock->nodes[node].lock);
	done = boot_node_lock->nodes[node].done;
	if (done)
		boot_spin_unlock(&boot_node_lock->nodes[node].lock);

	return done;
}

static inline void __boot_node_unlock(int node, struct node_lock *node_lock)
{
	struct node_lock *boot_node_lock = boot_vp_to_pp(node_lock);

	boot_node_lock->nodes[node].done = true;
	boot_spin_unlock(&boot_node_lock->nodes[node].lock);
}

#define boot_node_lock(node_lock) __boot_node_lock(boot_numa_node_id(), (node_lock))
#define boot_node_unlock(node_lock) __boot_node_unlock(boot_numa_node_id(), (node_lock))

#define BOOT_DEFINE_NODE_LOCK(name) \
	struct node_lock name = BOOT_NODE_LOCK_INIT

/*
 * Native/guest VM indicator
 */
#define	BOOT_IS_HV_GM()		(boot_machine.gmi)

#define	BOOT_IS_IRQ_MASK_GLOBAL()	boot_cpu_has(CPU_FEAT_GLOBAL_IRQ_MASK)

/*
 * Kernel Compilation units table
 */
extern const e2k_cute_t		kernel_CUT[MAX_KERNEL_CODES_UNITS];
#define boot_kernel_CUT		boot_va_to_pa((void *) kernel_CUT)

/*
 * Control process of boot-time initialization.
 */

extern void boot_native_setup_machine_id(bootblock_struct_t *bootblock);
extern void boot_startup(bool bsp, bootblock_struct_t *bootblock);
extern void boot_native_clear_bss(void);
extern void __init boot_native_check_bootblock(bool bsp,
				bootblock_struct_t *bootblock);
extern void boot_setup_iset_features(struct machdep *machine);
extern void boot_common_setup_arch_mmu(struct machdep *machine,
						pt_struct_t *pt_struct);
extern void init_native_terminate_boot_init(bool bsp, int cpuid);
extern void init_start_kernel_init(bool bsp, int cpuid);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/boot.h>
#else	/* native kernel */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
static inline void boot_setup_machine_id(bootblock_struct_t *bootblock)
{
	boot_native_setup_machine_id(bootblock);
}
static inline  void boot_clear_bss(void)
{
	boot_native_clear_bss();
}
static inline void __init
boot_check_bootblock(bool bsp, bootblock_struct_t *bootblock)
{
	boot_native_check_bootblock(bsp, bootblock);
}

static inline  void init_terminate_boot_init(bool bsp, int cpuid)
{
	init_native_terminate_boot_init(bsp, cpuid);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_P2V_BOOT_HEAD_H) */
