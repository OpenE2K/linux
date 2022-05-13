/* $Id: boot_phys.h,v 1.5 2009/06/29 11:53:06 atic Exp $
 *
 * Simple boot-time physical memory accounting and allocator.
 * Discontiguous memory supports on physical memory banks level.
 */

#ifndef _E2K_P2V_BOOT_PHYS_H
#define _E2K_P2V_BOOT_PHYS_H

#include <linux/types.h>
#include <linux/init.h>
#include <linux/numa.h>

#include <asm/types.h>
#include <asm/e2k.h>
#include <asm/page.h>

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

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM

# define LOW_MEMORY_ENABLED_DEFAULT	true

extern bool low_memory_enabled;
# define boot_low_memory_enabled	boot_get_vo_value(low_memory_enabled)
# define LOW_MEMORY_ENABLED()		low_memory_enabled
# define BOOT_LOW_MEMORY_ENABLED()	boot_low_memory_enabled
# define BOOT_SET_LOW_MEMORY_ENABLED()	(BOOT_LOW_MEMORY_ENABLED() = true)
# define BOOT_LOW_MEMORY_DISABLED()	!boot_low_memory_enabled
# define BOOT_SET_LOW_MEMORY_DISABLED()	(BOOT_LOW_MEMORY_ENABLED() = false)

extern void * __init_recv boot_pa_to_high_pa(void *lo_pa,
					     boot_info_t *boot_info);
extern bool __init boot_has_lo_bank_remap_to_hi(boot_phys_bank_t *phys_bank,
						boot_info_t *bootblock);
extern void __init boot_remap_low_memory(bool bsp, boot_info_t *boot_info);

#else	/* ! CONFIG_ONLY_HIGH_PHYS_MEM */

# define LOW_MEMORY_ENABLED()		true
# define BOOT_LOW_MEMORY_ENABLED()	true
# define BOOT_SET_LOW_MEMORY_ENABLED()
# define BOOT_SET_LOW_MEMORY_DISABLED()

static inline __init_recv void *
boot_pa_to_high_pa(void *lo_pa, boot_info_t *boot_info)
{
	/* nothing convertion of physical addresses is need */
	return lo_pa;
}
static inline __init bool
boot_has_lo_bank_remap_to_hi(boot_phys_bank_t *phys_bank,
					boot_info_t *bootblock)
{
	return false;
}

static inline __init void
boot_reserve_low_memory(boot_info_t *boot_info)
{
	/* low physical memory can be used in full measure, */
	/* so it does not need to reserve preliminarily some areas */
}

static inline __init void
boot_remap_low_memory(bool bsp, boot_info_t *boot_info)
{
	/* low and high memory can be used */
	/* so nothing remapping from one to other need */
}
#endif	/* CONFIG_ONLY_HIGH_PHYS_MEM */

static inline __init void *
boot_pa_end_to_high(void *lo_pa_end, boot_info_t *boot_info)
{
	/* end address of bank can be start address of next, */
	/* so transform end address to last address into a bank */
	return boot_pa_to_high_pa(lo_pa_end - 1, boot_info) + 1;
}

/*
 * Forwards of functions to allocate boot-time physical memory
 */

extern e2k_size_t boot_do_create_physmem_maps(boot_info_t *bootblock,
						bool create);
static inline __init e2k_size_t
boot_create_physmem_maps(boot_info_t *bootblock)
{
	return boot_do_create_physmem_maps(bootblock, true);
}
static inline __init e2k_size_t
boot_update_physmem_maps(boot_info_t *bootblock)
{
	return boot_do_create_physmem_maps(bootblock, false);
}
extern short __init_recv boot_init_new_phys_bank(int node,
				node_phys_mem_t *node_mem,
				e2k_addr_t bank_start, e2k_size_t bank_size);
extern short __init boot_create_new_phys_bank(int node,
			node_phys_mem_t *node_mem,
			e2k_addr_t bank_start, e2k_size_t bank_size);
extern void __init_recv  boot_add_new_phys_bank(int node,
				node_phys_mem_t *node_mem,
				e2k_phys_bank_t *new_phys_bank,
				short new_bank_ind);
extern short __init_recv  boot_delete_phys_bank_part(int node_id,
				node_phys_mem_t *node_mem,
				short bank, e2k_phys_bank_t *phys_bank,
				e2k_addr_t from_addr, e2k_addr_t to_addr);
extern short __init boot_create_phys_bank_part(int node_id,
			node_phys_mem_t *node_mem,
			short bank, e2k_phys_bank_t *phys_bank,
			e2k_addr_t from_addr, e2k_addr_t to_addr);

/* reserved memory flags (see following function arguments) */
#define	BOOT_NOT_IGNORE_BUSY_BANK	0x0000	/* area cannot intersect with */
						/* any other areas while */
						/* is reserving */
#define BOOT_IGNORE_BUSY_BANK		0x0001	/* area can intersect with */
						/* other such areas while */
						/* is reserving */
#define BOOT_IGNORE_BANK_NOT_FOUND	0x0002	/* area can point to pages */
						/* outside of present banks */
#define	BOOT_CAN_BE_INTERSECTIONS	0x0004	/* area can intersect with */
						/* other such areas after */
						/* was reserved */
#define	BOOT_DELETE_PHYS_MEM		0x0008	/* delete area from available */
						/* physical memory */
#define	BOOT_ONLY_LOW_PHYS_MEM		0x0010	/* area can be always only */
						/* at low memory ( < 2**32) */
#define	BOOT_IGNORE_AT_HIGH_PHYS_MEM	0x0020	/* it does not need remap */
						/* area from low to high */
						/* physical memory */
#define	BOOT_EXCLUDE_AT_HIGH_PHYS_MEM	0x0040	/* area should be mapped */
						/* only at low memory */
						/* and excluded from high */
						/* physical memory */
#define	BOOT_RESERVED_TO_FREE_PHYS_MEM	0x0080	/* area is reserved to free */
						/* while bootmem freeing */
#define	BOOT_ONLY_HIGH_PHYS_MEM		0x0100	/* area should be always */
						/* only at high memory */
#define	BOOT_FIRST_HIGH_PHYS_MEM	0x0200	/* area should be preferably */
						/* at high memory */
#define	BOOT_ONLY_ON_NODE_ALLOC_MEM	0x1000	/* allocate memory only on */
						/* the specified node */
#define	BOOT_IS_TRY_ALLOC_MEM		0x2000	/* it is try to allocate, */
						/* so miss is not BUG */
#define	BOOT_MERGEABLE_ALLOC_MEM	0x4000	/* allocated area can be */
						/* merged with other areas */
						/* if memory type is equal */

extern bool __init_recv boot_has_node_low_memory(int node,
						 boot_info_t *bootblock);
extern bool __init boot_has_node_high_memory(int node, boot_info_t *bootblock);
extern bool __init_recv boot_has_high_memory(boot_info_t *bootblock);

extern int boot_reserve_physmem(e2k_addr_t virt_phys_addr,
			e2k_size_t mem_size, busy_mem_type_t mem_type,
			unsigned short flags);
extern int boot_delete_physmem(e2k_addr_t virt_phys_addr,
			e2k_size_t mem_size);
extern void __init boot_rereserve_bank_area(int node_id,
			boot_phys_mem_t *node_mem,
			short bank, short new_bank,
			short area, e2k_busy_mem_t *busy_area);
extern void *boot_alloc_node_mem(int node_id, e2k_size_t mem_size,
			e2k_size_t align, e2k_size_t page_size,
			busy_mem_type_t mem_type, unsigned short flags);

#ifndef	CONFIG_NUMA
#define boot_alloc_phys_mem(mem_size, align, type)			\
		boot_alloc_node_mem(0, (mem_size), (align),		\
			PAGE_SIZE, (type),				\
			BOOT_NOT_IGNORE_BUSY_BANK |			\
				BOOT_MERGEABLE_ALLOC_MEM |		\
				BOOT_FIRST_HIGH_PHYS_MEM)
#define boot_node_alloc_physmem(node_id, mem_size, align, type)		\
		boot_alloc_phys_mem(mem_size, align, type)

#else	/* CONFIG_NUMA */
#define boot_node_alloc_physmem(node_id, mem_size, align, type)		\
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
			PAGE_SIZE, (type),				\
			BOOT_NOT_IGNORE_BUSY_BANK |			\
				BOOT_MERGEABLE_ALLOC_MEM |		\
				BOOT_FIRST_HIGH_PHYS_MEM)
#define boot_node_alloc_large_physpages(node_id, mem_size, align, type, flags) \
		boot_alloc_node_mem((node_id), (mem_size), (align),	\
			BOOT_E2K_LARGE_PAGE_SIZE, (type), (flags))
#define boot_alloc_phys_mem(mem_size, align, type)			\
		boot_node_alloc_physmem(boot_numa_node_id(),		\
			(mem_size), (align), (type))
#endif	/* ! CONFIG_NUMA */

#define	boot_node_try_alloc_low_mem(mem_size, align, page_size, type)	\
		boot_alloc_node_mem(boot_numa_node_id(), (mem_size),	\
			(align), (page_size), (type),			\
			BOOT_NOT_IGNORE_BUSY_BANK |			\
				BOOT_ONLY_ON_NODE_ALLOC_MEM |		\
				BOOT_ONLY_LOW_PHYS_MEM |		\
				BOOT_EXCLUDE_AT_HIGH_PHYS_MEM |		\
				BOOT_RESERVED_TO_FREE_PHYS_MEM |	\
				BOOT_IS_TRY_ALLOC_MEM)

#define boot_the_node_try_alloc_pages(node_id, mem_size, page_size, type) \
		boot_alloc_node_mem((node_id), (mem_size), (page_size),	\
			(page_size), (type),				\
			BOOT_NOT_IGNORE_BUSY_BANK |			\
				BOOT_ONLY_ON_NODE_ALLOC_MEM |		\
				BOOT_FIRST_HIGH_PHYS_MEM |		\
				BOOT_MERGEABLE_ALLOC_MEM |		\
				BOOT_IS_TRY_ALLOC_MEM)

extern long boot_map_physmem(pgprot_t prot_flags, e2k_size_t max_page_size);
extern void boot_expand_phys_banks_reserved_areas(void);

#endif /* _E2K_P2V_BOOT_PHYS_H */
