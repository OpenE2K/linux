/* $Id: boot_phys.h,v 1.5 2009/06/29 11:53:06 atic Exp $
 *
 * Simple boot-time physical memory accounting and allocator.
 * Discontiguous memory supports on physical memory banks level.
 */
#ifndef _E2K_BOOT_PHYS_H
#define _E2K_BOOT_PHYS_H

#include <linux/init.h>
#include <linux/numa.h>
#include <asm/types.h>
#include <asm/e2k.h>
#include <asm/page.h>
#include <asm/pgtable.h>

/*
 * The structure 'boot_phys_bank_t' is the same as common kernel structure
 * 'e2k_phys_bank_t' (see 'page.h' header). This structure is physical memory
 * bank specifier and is used to hold the boot-time physical memory
 * configuration of the machine.
 * The array 'boot_phys_banks[]' contains base addresses and sizes of all
 * physical memory banks.
 * To reduce the boot-time map size, the boot map represents only needed
 * to boot tasks first 'BOOT_MAX_PHYS_MEM_SIZE' bytes of real physical memory
 * configuration. Creation of full physical memory map can be completed later,
 * when virtual memory support will be ready.
 */

typedef	e2k_mem_map_t	boot_mem_map_t;		/* The same as common map */
						/* item : double-word */
						/* (64 bits == 64 pages) */
typedef e2k_phys_bank_t	boot_phys_bank_t;	/* the same as common */
						/* memory bank structure */
typedef node_phys_mem_t	boot_phys_mem_t;	/* The same as common */
						/* structure */

#define	boot_phys_mem	nodes_phys_mem	/* The same as common banks */
					/* array */

#ifndef	CONFIG_NUMA
#define	BOOT_MAX_CPU_PHYS_MEM_SIZE	(16UL * (1024 * 1024)) /* 16 Mbytes */
/* some memory reserved by BIOS */
#define	BOOT_MAX_BIOS_PHYS_MEM_SIZE	(16UL * (1024 * 1024)) /* 16 Mbytes */

#ifndef	CONFIG_RECOVERY
#define BOOT_MAX_PHYS_MEM_SIZE	(BOOT_MAX_CPU_PHYS_MEM_SIZE * NR_CPUS)
#else	/* CONFIG_RECOVERY */
#define BOOT_MAX_PHYS_MEM_SIZE	(BOOT_MAX_CPU_PHYS_MEM_SIZE * NR_CPUS + \
						BOOT_MAX_BIOS_PHYS_MEM_SIZE)
#endif	/* ! CONFIG_RECOVERY */

#else	/* CONFIG_NUMA */
#define	BOOT_MAX_CPU_PHYS_MEM_SIZE	(16 * (1024 * 1024)) /* 16 Mbytes */
/* some memory reserved by BIOS */
#define	BOOT_MAX_BIOS_PHYS_MEM_SIZE	(16 * (1024 * 1024)) /* 16 Mbytes */

#ifndef	CONFIG_RECOVERY
#define BOOT_MAX_NODE_MEM_SIZE	(BOOT_MAX_CPU_PHYS_MEM_SIZE * MAX_NODE_CPUS)
#else	/* CONFIG_RECOVERY */
#define BOOT_MAX_NODE_MEM_SIZE	(BOOT_MAX_CPU_PHYS_MEM_SIZE * MAX_NODE_CPUS + \
						BOOT_MAX_BIOS_PHYS_MEM_SIZE)
#endif	/* ! CONFIG_RECOVERY */
typedef	struct boot_node_mem_map {
	boot_mem_map_t bitmap[(1UL * BOOT_MAX_NODE_MEM_SIZE *
				L_MAX_NODE_PHYS_BANKS / PAGE_SIZE +
				(sizeof(boot_mem_map_t) * 8 - 1)) /
				(sizeof(boot_mem_map_t) * 8) +
				L_MAX_NODE_PHYS_BANKS];
} boot_node_mem_map_t;

#endif	/* ! CONFIG_NUMA */


/*
 * Forwards of functions to allocate boot-time physical memory
 */

extern e2k_size_t __init boot_create_physmem_maps(void);

extern int 
#ifndef CONFIG_RECOVERY
__init
#endif
_boot_reserve_physmem(e2k_addr_t phys_addr,
			e2k_size_t mem_size, e2k_size_t page_size,
			int ignore_busy);
#define	boot_reserve_physmem(phys_addr, mem_size) \
		_boot_reserve_physmem((phys_addr), (mem_size), PAGE_SIZE, 0)
#define	boot_reserve_large_physpages(phys_addr, mem_size) \
		_boot_reserve_physmem((phys_addr), (mem_size), \
			BOOT_E2K_LARGE_PAGE_SIZE, 0)

extern void __init_recv
_boot_free_physmem(e2k_addr_t phys_addr,
			e2k_size_t mem_size, e2k_size_t page_size);
#define	boot_free_physmem(phys_addr, mem_size) \
		_boot_free_physmem((phys_addr), (mem_size), PAGE_SIZE)
#define	boot_free_large_physpages(phys_addr, mem_size) \
		_boot_free_physmem((phys_addr), (mem_size), \
					BOOT_E2K_LARGE_PAGE_SIZE)

extern void * __init_recv
boot_alloc_node_mem(int node_id, e2k_size_t mem_size, e2k_size_t align,
			e2k_size_t page_size, int only_on_the_node, int try);
#ifndef	CONFIG_NUMA
#define boot_alloc_phys_mem(mem_size, align)				\
		boot_alloc_node_mem(0, (mem_size), (align),		\
					PAGE_SIZE, 0, 0)
#define boot_alloc_large_phys_pages(mem_size, align)			\
		boot_alloc_node_mem(0, (mem_size), (align),		\
					BOOT_E2K_LARGE_PAGE_SIZE, 0, 0)
#else	/* CONFIG_NUMA */
#define boot_node_alloc_physmem(node_id, mem_size, align)		\
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
					PAGE_SIZE, 0, 0)
#define boot_node_alloc_large_physpages(node_id, mem_size, align)	\
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
					BOOT_E2K_LARGE_PAGE_SIZE, 0, 0)
#define boot_the_node_alloc_physmem(node_id, mem_size, align)		\
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
					PAGE_SIZE, 1, 0)
#define boot_the_node_alloc_large_physpages(node_id, mem_size, align)	\
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
					BOOT_E2K_LARGE_PAGE_SIZE, 1, 0)
#define boot_alloc_phys_mem(mem_size, align)				\
		boot_node_alloc_physmem(boot_numa_node_id(),		\
					(mem_size), (align))
#define boot_alloc_large_phys_pages(mem_size, align)			\
		boot_node_alloc_large_physpages(boot_numa_node_id(),	\
					(mem_size), (align))
#define boot_the_node_try_alloc_physmem(node_id, mem_size, align)	\
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
					PAGE_SIZE, 1, 1)
#define boot_the_node_try_alloc_large_physpages(node_id, mem_size, align) \
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
					BOOT_E2K_LARGE_PAGE_SIZE, 1, 1)
#define boot_the_node_try_alloc_pages(node_id, mem_size, page_size)	\
		boot_alloc_node_mem((node_id), (mem_size), (page_size),	\
					page_size, 1, 1)
#endif	/* ! CONFIG_NUMA */

extern e2k_size_t __init register_free_bootmem(void);

extern int __init boot_map_physmem(e2k_addr_t phys_base_addr,
			e2k_size_t mem_size, e2k_addr_t virt_base_addr,
			pgprot_t prot_flags, e2k_size_t page_size);

#endif /* _E2K_BOOT_PHYS_H */
