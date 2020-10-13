/* $Id: boot_head.h,v 1.21 2009/06/29 11:53:53 atic Exp $
 *
 * Heading of boot-time initialization.
 *
 * Copyright (C) 2001 Salavat Guiliazov <atic@mcst.ru>
 */

#ifndef	_E2K_BOOT_HEAD_H
#define	_E2K_BOOT_HEAD_H

#include <linux/init.h>
#include <linux/kernel_stat.h>

#include <asm/types.h>
#include <asm/cpu_regs_access.h>
#include <asm/e2k.h>
#include <asm/head.h>
#include <asm/boot_smp.h>
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
extern struct task_struct	*init_tasks[];
extern unsigned char		boot_init_started[NR_CPUS];
						/* boot-time initialization */
						/* has been started */
extern unsigned char		_va_support_on[NR_CPUS];
						/* virtual addressing support */
						/* has turned on */
#define	boot_boot_init_started \
		((unsigned char *)boot_vp_to_pp(boot_init_started)) \
						[boot_smp_processor_id()]
#define	boot_va_support_on \
		((unsigned char *)boot_vp_to_pp(_va_support_on)) \
						[boot_smp_processor_id()]
#define	va_support_on			_va_support_on[boot_smp_processor_id()]
#endif	/* CONFIG_SMP */

extern	bootblock_struct_t *bootblock_phys;	/* bootblock structure */
						/* physical pointer */
extern	bootblock_struct_t *bootblock_virt;	/* bootblock structure */
						/* virtual pointer */
#define	boot_bootblock_phys		\
		((bootblock_struct_t *)boot_get_vo_value(bootblock_phys))
/* To avoid compiler  error (18 version) */
#define	boot_bootblock_virt_write		\
		boot_get_vo_value(bootblock_virt)
#define	boot_bootblock_phys_write		\
		boot_get_vo_value(bootblock_phys)

#define	boot_bootblock_virt		\
		((bootblock_struct_t *)boot_get_vo_value(bootblock_virt))
#ifdef	CONFIG_E2K_MACHINE
#define	boot_machine_id			(machine_id)
#define	boot_virt_machine_id		(machine_id)
#else	/* ! CONFIG_E2K_MACHINE */

 #if	defined(CONFIG_E3M)
  #define	boot_machine_id		(machine_id)
  #define	boot_virt_machine_id	(machine_id)
 #elif	defined(CONFIG_E3S)
  #define	boot_machine_id		(machine_id)
  #define	boot_virt_machine_id	(machine_id)
 #elif	defined(CONFIG_ES2)
  #define	boot_machine_id		(machine_id)
  #define	boot_virt_machine_id	(machine_id)
 #elif	defined(CONFIG_E2S)
  #define	boot_machine_id		(machine_id)
  #define	boot_virt_machine_id	(machine_id)
 #elif	defined(CONFIG_E8C)
  #define	boot_machine_id		(machine_id)
  #define	boot_virt_machine_id	(machine_id)
 #elif	defined(CONFIG_E1CP)
  #define	boot_machine_id		(machine_id)
  #define	boot_virt_machine_id	(machine_id)
 #else
  #define	boot_machine_id		boot_get_vo_value(machine_id)
  #define	boot_virt_machine_id	boot_get_vo_value(virt_machine_id)
 #endif

#ifdef	CONFIG_NUMA
#define	boot_the_node_machine_id(nid)	\
		boot_the_node_get_vo_value(nid, machine_id)
#define	boot_node_machine_id		\
		boot_the_node_machine_id(boot_numa_node_id())
#endif	/* CONFIG_NUMA */
#endif	/* CONFIG_E2K_MACHINE */
#define	boot_machine			((machdep_t)boot_get_vo_value(machine))
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
#define	init_kernel_phys_base						\
		init_node_kernel_phys_base(numa_node_id())

#define	BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(node_id)			\
		((unsigned long)(boot_node_kernel_phys_base(node_id)) != \
			(unsigned long)-1)
#define	BOOT_EARLY_NODE_HAS_DUP_KERNEL()					\
		BOOT_EARLY_THE_NODE_HAS_DUP_KERNEL(boot_numa_node_id())

#define	BOOT_TEST_AND_SET_NODE_LOCK(node_lock, node_done)		\
({									\
	int was_done;					\
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
#define BOOT_IS_BSP			(boot_smp_processor_id() == 0)
#define	boot_kernel_phys_base		boot_get_vo_value(kernel_phys_base)
#define	init_kernel_phys_base		(kernel_phys_base)
#define	BOOT_TEST_AND_SET_NODE_LOCK(node_lock, node_done) (!BOOT_IS_BSP)
#define	BOOT_NODE_UNLOCK(node_lock, node_done)
#endif	/* CONFIG_NUMA */

/*
 * MMU Trap Cellar
 */
#ifndef	CONFIG_SMP
extern	unsigned long		kernel_trap_cellar[MMU_TRAP_CELLAR_MAX_SIZE];
#define	boot_kernel_trap_cellar	boot_vp_to_pp(kernel_trap_cellar)
#define	boot_trap_cellar	boot_kernel_trap_cellar
#define	KERNEL_TRAP_CELLAR	kernel_trap_cellar
#else
extern	unsigned long		kernel_trap_cellar;
#define	boot_trap_cellar	\
		boot_vp_to_pp((u64 *)(&kernel_trap_cellar) + \
			MMU_TRAP_CELLAR_MAX_SIZE * boot_smp_processor_id())
#define	boot_kernel_trap_cellar	\
		boot_node_vp_to_pp((u64 *)(&kernel_trap_cellar) + \
			MMU_TRAP_CELLAR_MAX_SIZE * boot_smp_processor_id())
#define	KERNEL_TRAP_CELLAR	((&kernel_trap_cellar) + \
			MMU_TRAP_CELLAR_MAX_SIZE * raw_smp_processor_id())
#define	BOOT_KERNEL_TRAP_CELLAR	((&kernel_trap_cellar) + \
			MMU_TRAP_CELLAR_MAX_SIZE * boot_smp_processor_id())
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_KERNEL_CODE_CONTEXT
/*
 * Kernel Compilation units table
 */
 
extern	e2k_cute_t		kernel_CUT[MAX_KERNEL_CODES_UNITS];
#define	boot_CUT		boot_vp_to_pp(kernel_CUT)
#define	boot_kernel_CUT		boot_node_vp_to_pp(kernel_CUT)
#endif	/* CONFIG_KERNEL_CODE_CONTEXT */



/*
 * Control process of boot-time initialization.
 */

extern void	boot_init(bootblock_struct_t *bootblock);

/*
 * Convert virtual address of pointer of global or static variable, array,
 * structure, string or other item of linux image to the consistent physical
 * address of one, while booting process is in the progress and virtual memory
 * support is not yet ready.
 * Linker loads Linux image to a virtual space and all enumerated above items
 * have virtual addresses into the image. BIOS loader loads image to the
 * some existing area of physical memory, virtual addressing is off and direct
 * access to the items is impossible.
 * Loader should write pointer of image text segment location in the physical
 * memory to the 'OSCUD' register:
 *			OSCUD.OSCUD_base
 *			OSCUD.OSCUD_size
 * and pointer of image data & bss segments location in the physical memory
 * to the 'OSGD' register:
 *			OSGD.OSGD_base
 *			OSGD.OSGD_size
 * These areas can intersect.
 * If some item of the image (see above) is located into the text, data or
 * bss segment, then to access it on absolute address (pointer) you should
 * call this function to convert absolute virtual address to real physical
 * address.
 *
 * Example:
 *
 *	char	boot_buf[81];
 *	int	boot_buf_size = 80;
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		char	*buf = (char *)boot_va_to_pa((void *)boot_buf);
 *		int	buf_size = *((int *)boot_va_to_pa(
 *						(e2k_addr_t)&boot_buf_size));
 *	.......
 *	}
 *
 * NOTE !!!!! It is rather to use the macroses defined below to access image
 * objects instead of this function. The mocroses have more convenient
 * interfaces
 */

static	inline	void *
boot_kernel_va_to_pa(void *virt_pnt, unsigned long kernel_base)
{
	if (READ_OSCUD_LO_REG().OSCUD_lo_base >= PAGE_OFFSET)
		return virt_pnt;
	else if ((e2k_addr_t)virt_pnt >= KERNEL_BASE)
		return (void *)(kernel_base +
					((e2k_addr_t)virt_pnt - KERNEL_BASE));
	else
		return virt_pnt;
}

static	inline	void *
boot_va_to_pa(void *virt_pnt)
{
	return boot_kernel_va_to_pa(virt_pnt,
					READ_OSCUD_LO_REG().OSCUD_lo_base);
}

/*
 * Convert pointer of global or static variable, array, structure, string or
 * other item of linux image, which is located into the virtual linux text,
 * data or bss segment to the consistent pointer with physical address of
 * object, while booting process is in the progress and virtual memory
 * support is not yet ready.
 * See comments above ('boot_va_to_pa()' function declaration).
 *
 * Example of usage:
 *
 *	char	boot_buf[81];
 *	
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		char	*buf = boot_vp_to_pp(boot_buf);
 *
 *	.......
 *	}
 */

#define	boot_vp_to_pp(virt_pnt)		boot_va_to_pa((void *)(virt_pnt))

/*
 * Get value of object (variable, array, structure, string or other item of
 * linux image) which is located into the virtual linux text, data or bss
 * segment, while booting process is in the progress and virtual memory support
 * is not yet ready.
 * See comments above ('boot_va_to_pa()' function declaration).
 *
 * Example of usage:
 *
 *	static	long	*boot_long_p;
 *		int	boot_buf_size = 80;
 *	
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		int	buf_size = boot_get_vo_value(boot_buf_size);
 *		long	*long_p = boot_get_vo_value(boot_long_p);
 *
 *		long_p[0] = buf_size;
 *	.......
 *	}
 */

#define	boot_get_vo_value(virt_value_name) \
		(*(typeof ( virt_value_name)*)boot_vp_to_pp(&virt_value_name))

/*
 * Get name of object (variable, array, structure, string or other item of
 * linux image) which is located into the virtual linux text, data or bss
 * segment, while booting process is in the progress and virtual memory support
 * is not yet ready. This name can be used to assign a value to the object.
 * See comments above ('boot_va_to_pa()' function declaration).
 *
 * Example of usage:
 *
 *	static	int	boot_memory_size;
 *	
 *	.......
 *	void
 *	xxx_func()
 *	{
 *		int	total_memory_size = 0;
 *
 *	.......
 *		boot_get_vo_name(boot_memory_size) = total_memory_size;
 *	.......
 *	}
 */

#define	boot_get_vo_name(virt_value_name) \
		*(typeof ( virt_value_name)*)boot_vp_to_pp(&virt_value_name)

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

#endif /* !(_E2K_BOOT_HEAD_H) */
