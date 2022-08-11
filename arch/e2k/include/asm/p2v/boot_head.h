/* $Id: boot_head.h,v 1.21 2009/06/29 11:53:53 atic Exp $
 *
 * Heading of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_P2V_BOOT_HEAD_H
#define	_E2K_P2V_BOOT_HEAD_H

#include <linux/init.h>

#include <asm/p2v/boot_v2p.h>
#include <asm/types.h>
#include <asm/cpu_regs_access.h>
#include <asm/e2k.h>
#include <asm/head.h>
#include <asm/p2v/boot_smp.h>
#include <asm/bootinfo.h>
#include <asm/numnodes.h>

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

#ifdef	CONFIG_E2K_MACHINE
# define boot_native_machine_id	(native_machine_id)
#else
# if defined(CONFIG_ES2) || defined(CONFIG_E2S) || \
	defined(CONFIG_E8C) || defined(CONFIG_E1CP) || \
	defined(CONFIG_E8C2) || defined(CONFIG_E12C) || \
	defined(CONFIG_E16C) || defined(CONFIG_E2C3)
#  define boot_native_machine_id	(native_machine_id)
# else
#  define boot_native_machine_id	boot_get_vo_value(native_machine_id)
# endif

# ifdef CONFIG_NUMA
#  define boot_the_node_machine_id(nid)	\
		boot_the_node_get_vo_value(nid, machine_id)
#  define boot_node_machine_id		\
		boot_the_node_machine_id(boot_numa_node_id())
# endif
#endif

#define	boot_machine			(boot_get_vo_value(machine))

#ifdef	CONFIG_NUMA
#define	boot_the_node_machine(nid)	\
		((machdep_t *)boot_the_node_vp_to_pp(nid, &machine))
#define	boot_node_machine(nid)	\
		boot_the_node_machine(boot_numa_node_id())
#else	/* ! CONFIG_NUMA */
#define	boot_the_node_machine(nid)	\
		((machdep_t *)boot_vp_to_pp(&machine))
#define	boot_node_machine(nid)		\
		boot_the_node_machine(0)
#endif	/* CONFIG_NUMA */

extern e2k_addr_t start_of_phys_memory;	/* start address of physical memory */
extern e2k_addr_t end_of_phys_memory;	/* end address + 1 of physical memory */
extern e2k_size_t pages_of_phys_memory;	/* number of pages of physical memory */
extern e2k_addr_t kernel_image_size;	/* size of full kernel image in the */
					/* memory ("text" + "data" + "bss") */
#define	boot_start_of_phys_memory	boot_get_vo_value(start_of_phys_memory)
#define	boot_end_of_phys_memory		boot_get_vo_value(end_of_phys_memory)
#define	boot_pages_of_phys_memory	boot_get_vo_value(pages_of_phys_memory)
#define	boot_kernel_image_size		boot_get_vo_value(kernel_image_size)

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

#ifdef	CONFIG_NUMA
extern e2k_addr_t node_kernel_phys_base[MAX_NUMNODES];
#define	boot_node_kernel_phys_base(node_id)				\
		boot_get_vo_value(node_kernel_phys_base[(node_id)])
#define	boot_kernel_phys_base						\
		boot_node_kernel_phys_base(boot_numa_node_id())
#define	init_node_kernel_phys_base(node_id)				\
		(node_kernel_phys_base[(node_id)])
#define	BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(node_id)			\
		((unsigned long)(boot_node_kernel_phys_base(node_id)) != \
			(unsigned long)-1)
#define	BOOT_EARLY_NODE_HAS_DUP_KERNEL()				\
		BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(boot_numa_node_id())

#define	BOOT_TEST_AND_SET_NODE_LOCK(node_lock, node_done)		\
({									\
	int was_done;							\
	boot_node_spin_lock((node_lock));				\
	was_done = (node_done);						\
	if ((was_done)) {						\
		boot_node_spin_unlock((node_lock));			\
	}								\
	was_done;							\
})
#define	BOOT_NODE_UNLOCK(node_lock, node_done)				\
({									\
	(node_done) = 1;						\
	boot_node_spin_unlock((node_lock));				\
})
#else	/* ! CONFIG_NUMA */
extern e2k_addr_t kernel_phys_base;	/* physical address of kernel Image */
					/* begining */
#define BOOT_IS_BSP_ID			(boot_smp_processor_id() == 0)
#define	boot_kernel_phys_base		boot_get_vo_value(kernel_phys_base)
#define	BOOT_TEST_AND_SET_NODE_LOCK(node_lock, node_done) (!BOOT_IS_BSP_ID)
#define	BOOT_NODE_UNLOCK(node_lock, node_done)
#endif	/* CONFIG_NUMA */

/*
 * MMU Trap Cellar
 */
#ifndef	CONFIG_SMP
extern	unsigned long		kernel_trap_cellar[MMU_TRAP_CELLAR_MAX_SIZE];

#define	KERNEL_TRAP_CELLAR	kernel_trap_cellar

#define	boot_kernel_trap_cellar	boot_vp_to_pp((u64 *)kernel_trap_cellar)
#define	boot_trap_cellar	boot_kernel_trap_cellar
#define	BOOT_KERNEL_TRAP_CELLAR	boot_kernel_trap_cellar
#else	/* CONFIG_SMP */
extern	unsigned long		kernel_trap_cellar;

/*
 * Don't use hard_smp_processor_id() here to avoid function call in
 * NATIVE_SAVE_TRAP_CELLAR().
 */
#define	KERNEL_TRAP_CELLAR	\
		((&kernel_trap_cellar) + MMU_TRAP_CELLAR_MAX_SIZE * \
		 cpu_to_cpuid(raw_smp_processor_id()))

#define	boot_trap_cellar	\
		boot_vp_to_pp((u64 *)(&kernel_trap_cellar) + \
			MMU_TRAP_CELLAR_MAX_SIZE * boot_smp_processor_id())
#define	boot_kernel_trap_cellar	\
		boot_node_vp_to_pp((u64 *)(&kernel_trap_cellar) + \
			MMU_TRAP_CELLAR_MAX_SIZE * boot_smp_processor_id())
#define	BOOT_KERNEL_TRAP_CELLAR	\
		((&kernel_trap_cellar) + \
		 MMU_TRAP_CELLAR_MAX_SIZE * boot_smp_processor_id())
#endif	/* ! CONFIG_SMP */

/*
 * Native/guest VM indicator
 */
#define	BOOT_IS_HV_GM()		(boot_machine.gmi)

/*
 * Kernel Compilation units table
 */
extern	e2k_cute_t		kernel_CUT[MAX_KERNEL_CODES_UNITS];
#define	boot_kernel_CUT		boot_node_vp_to_pp((e2k_cute_t *)kernel_CUT)

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

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/boot.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops */
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
#endif	/* CONFIG_PARAVIRT_GUEST */

/*
 * Convert virtual address of kernel item to the consistent physical address,
 * while booting process is continued into virtual memory space.
 */

#ifndef	CONFIG_NUMA
#define	kernel_va_to_pa(virt_addr)	\
		((e2k_addr_t)(virt_addr) - KERNEL_BASE + kernel_phys_base)
#else	/* CONFIG_NUMA */
#define	kernel_va_to_pa(virt_addr)	\
		node_kernel_va_to_pa(numa_node_id(), virt_addr)
#endif	/* ! CONFIG_NUMA */

/*
 * Convert virtual address of kernel item to the consistent physical address 
 * on the given node, while booting process is continued into virtual memory 
 * space.
 */

#ifndef CONFIG_NUMA
#define node_kernel_va_to_pa(node_id, virt_addr)			\
	((e2k_addr_t)(virt_addr) - KERNEL_BASE + kernel_phys_base)
#else /* CONFIG_NUMA */
#define node_kernel_va_to_pa(node_id, virt_addr)			\
({									\
	unsigned long virt_offset = (e2k_addr_t)(virt_addr) -		\
							KERNEL_BASE;	\
	unsigned long kernel_base;					\
	if ((e2k_addr_t)(virt_addr) >= (e2k_addr_t)__node_data_end) {	\
		kernel_base = node_kernel_phys_base[BOOT_BS_NODE_ID];	\
	} else if (node_has_dup_kernel(node_id)) {			\
		kernel_base = node_kernel_phys_base[node_id];		\
	} else {							\
		kernel_base = node_kernel_phys_base[			\
					node_dup_kernel_nid(node_id)]; 	\
	}								\
	kernel_base + virt_offset;					\
})
#endif /* ! CONFIG_NUMA */

#ifdef	CONFIG_NUMA
/*
 * The next macroses should be used for NUMA mode to convert addresses on
 * the current node 
 */
static	inline	void *
boot_node_kernel_va_to_pa(int node_id, void *virt_pnt)
{
	unsigned long node_base;

	node_base = boot_node_kernel_phys_base(node_id);
	if (node_base == (unsigned long)-1) {
		node_base = boot_node_kernel_phys_base(BOOT_BS_NODE_ID);
	}
	return boot_kernel_va_to_pa(virt_pnt, node_base);
}
#define	boot_the_node_vp_to_pp(node_id, virt_pnt)			\
		boot_node_kernel_va_to_pa((node_id), (void *)(virt_pnt))
#define	boot_the_node_get_vo_value(node_id, virt_value_name)		\
		*(typeof ( virt_value_name)*)				\
				boot_the_node_vp_to_pp((node_id),	\
						&(virt_value_name))
#define	boot_the_node_get_vo_name(node_id, virt_value_name)		\
		*(typeof ( virt_value_name)*)				\
				boot_the_node_vp_to_pp((node_id),	\
						&(virt_value_name))
#define	boot_node_vp_to_pp(virt_pnt)					\
		boot_the_node_vp_to_pp(boot_numa_node_id(), virt_pnt)
#define	boot_node_get_vo_value(virt_value_name)				\
		boot_the_node_get_vo_value(boot_numa_node_id(),		\
						virt_value_name)
#define	boot_node_get_vo_name(virt_value_name)				\
		boot_the_node_get_vo_name(boot_numa_node_id(),		\
						virt_value_name)
#else	/* ! CONFIG_NUMA */
#define	boot_node_vp_to_pp(virt_pnt)	boot_vp_to_pp(virt_pnt)
#define	boot_node_get_vo_value(virt_value_name)				\
		boot_get_vo_value(virt_value_name)
#define	boot_node_get_vo_name(virt_value_name)				\
		boot_node_get_vo_name(virt_value_name)
#endif	/* CONFIG_NUMA */

#endif /* !(__ASSEMBLY__) */

#endif /* !(_E2K_P2V_BOOT_HEAD_H) */
