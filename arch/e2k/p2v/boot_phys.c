/* $Id: boot_phys.c,v 1.17 2009/06/29 10:39:10 atic Exp $
 *
 * Simple boot-time physical memory accounting and memory allocator.
 * Discontiguous memory supports on memory banks level.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/string.h>
#include <linux/bootmem.h>
#include <linux/mm.h>

#include <asm/string.h>
#include <asm/page.h>
#include <asm/boot_bitops.h>
#include <asm/boot_head.h>
#include <asm/boot_phys.h>
#include <asm/boot_map.h>
#include <asm/atomic.h>
#ifdef	CONFIG_RECOVERY
#include <asm/boot_recovery.h>
#endif	/* CONFIG_RECOVERY */

#include <asm/console.h>

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#undef	DebugB
#define	DEBUG_BOOT_MODE		0	/* Boot process */
#define	boot_printk		if (DEBUG_BOOT_MODE) do_boot_printk
#define	DebugB			if (DEBUG_BOOT_MODE) printk
#define	DEBUG_BANK_MODE		0	/* Reserve bank of memory */
#define	DebugBANK		if (DEBUG_BANK_MODE) do_boot_printk

#undef	DEBUG_PHYS_MAP_MODE
#undef	DebugMAP
#define	DEBUG_PHYS_MAP_MODE	0	/* Physical memory mapping */
#define	DebugMAP		if (DEBUG_PHYS_MAP_MODE) do_boot_printk

#undef	DEBUG_MAP_PHYS_MEM_MODE
#undef	DebugMP
#define	DEBUG_MAP_PHYS_MEM_MODE	0	/* Physical memory mapping */
#define	DebugMP		if (DEBUG_MAP_PHYS_MEM_MODE) do_boot_printk

#undef	DEBUG_MEM_ALLOC_MODE
#undef	DebugAM
#define	DEBUG_MEM_ALLOC_MODE	0	/* Physical memory allocation */
#define	DebugAM			if (DEBUG_MEM_ALLOC_MODE) do_boot_printk

/*
 * The array 'boot_mem_bitmaps[]' is a buffer for boot maps of physical memory
 * banks. The size of array is restricted by memory needed to boot tasks only.
 * This size is constant described by '#define BOOT_MAX_PHYS_MEM_SIZE'.
 * It is needed to allocate the boot bitmap array statically into the kernel
 * image. Creation of full physical memory map can be completed later,
 * when virtual memory support will be ready.
 */

#ifndef	CONFIG_NUMA
static boot_mem_map_t __initdata_recv
		boot_mem_bitmaps[
			(BOOT_MAX_PHYS_MEM_SIZE * L_MAX_NODE_PHYS_BANKS /
			PAGE_SIZE + (sizeof(boot_mem_map_t) * 8 - 1)) /
			(sizeof(boot_mem_map_t) * 8) +
			L_MAX_MEM_NUMNODES * L_MAX_NODE_PHYS_BANKS];
#else	/* CONFIG_NUMA */
static boot_node_mem_map_t __initdata_recv boot_mem_bitmaps[MAX_NUMNODES];
#endif	/* ! CONFIG_NUMA */

e2k_addr_t	start_of_phys_memory;	/* start address of physical memory */
e2k_addr_t	end_of_phys_memory;	/* end address + 1 of physical memory */
e2k_size_t	pages_of_phys_memory;	/* number of pages of physical memory */
e2k_addr_t	kernel_image_size;	/* size of full kernel image in the */
					/* memory ("text" + "data" + "bss") */
#ifdef	CONFIG_RECOVERY
/*
 * Full physical memory descriptors.
 * In this case start_of_phys_memory, end_of_phys_memory, pages_of_phys_memory
 * describe only current control point memory boundaries
 */
e2k_addr_t	start_of_full_memory;	/* real start address of full */
					/* physical memory */
e2k_addr_t	end_of_full_memory;	/* real end address + 1 of full */
					/* physical memory */
e2k_size_t	pages_of_full_memory;	/* real number of pages of full */
					/* physical memory */
#endif	/* CONFIG_RECOVERY */

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
static DEFINE_RAW_SPINLOCK(boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
static raw_spinlock_t __initdata_recv
			boot_node_phys_mem_lock[MAX_NUMNODES] = {
				[ 0 ... (MAX_NUMNODES-1) ] =
					__RAW_SPIN_LOCK_UNLOCKED(
						boot_node_phys_mem_lock)
			};
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */

static	e2k_size_t __init boot_create_physmem_bank_map(
				boot_phys_bank_t *phys_bank,
				e2k_size_t max_map_size);
static	boot_phys_bank_t * __init_recv
boot_find_bank_of_addr(e2k_addr_t phys_addr, int *node_id, int *bank_index);
static	long __init_recv
boot_reserve_bank_physmem(int node_id, boot_phys_bank_t *phys_bank,
			e2k_addr_t phys_addr, long pages_num, int ignore_busy);
static	long __init_recv
boot_free_bank_physmem(int node_id, boot_phys_bank_t *phys_bank,
			e2k_addr_t phys_addr, long pages_num);
static	long __init_recv
boot_map_bank_physmem(boot_phys_bank_t *phys_bank,
			e2k_addr_t phys_addr, long pages_num,
			e2k_addr_t virt_addr, pgprot_t prot_flags,
			e2k_size_t page_size);
static	long __init_recv
boot_reserve_bank_area(int node_id, boot_phys_bank_t *phys_bank,
			e2k_size_t start_page, long pages_num,
			int ignore_busy);
static	void __init boot_order_bank_areas(boot_phys_bank_t *phys_bank);

/*
 * Create pages bitmaps of physical memory banks.
 */

e2k_size_t __init
boot_create_physmem_maps(void)
{
	boot_phys_mem_t		*all_phys_banks = NULL;
	boot_phys_bank_t	*phys_bank = NULL;
	boot_mem_map_t		*mem_bitmap_v = NULL;
	int			nodes_num;
	int			cur_nodes_num = 0;
	e2k_size_t		pages_num = 0;
	e2k_size_t		bank_map_size;
	e2k_size_t		total_map_size = 0;
	e2k_size_t		max_map_size;
	e2k_addr_t		top_addr;
	int			node;
	int			bank;

	all_phys_banks = boot_vp_to_pp(boot_phys_mem);
#ifndef	CONFIG_NUMA
	max_map_size = BOOT_MAX_PHYS_MEM_SIZE / PAGE_SIZE;
	mem_bitmap_v = boot_mem_bitmaps;
#endif	/* ! CONFIG_NUMA */
	boot_start_of_phys_memory = 0xffffffffffffffffUL;
	boot_end_of_phys_memory = 0x0000000000000000UL;

	nodes_num = boot_phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
#ifdef	CONFIG_NUMA
		max_map_size = BOOT_MAX_NODE_MEM_SIZE / PAGE_SIZE;
		mem_bitmap_v = boot_mem_bitmaps[node].bitmap;
#endif	/* CONFIG_NUMA */
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		phys_bank = all_phys_banks[node].banks;
		if (phys_bank->pages_num == 0)
			continue;	/* node has not memory */
		DebugMAP("boot_create_physmem_maps() node #%d: phys banks "
			"addr 0x%lx, max map size 0x%lx pages, bitmap array "
			"addr 0x%lx\n",
			node, phys_bank, max_map_size, mem_bitmap_v);
		cur_nodes_num ++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (phys_bank->pages_num == 0)
				break;	/* no more banks on node */
			if (phys_bank->base_addr < boot_start_of_phys_memory)
				boot_start_of_phys_memory =
					phys_bank->base_addr;
			top_addr = phys_bank->base_addr +
					phys_bank->pages_num * PAGE_SIZE;
			if (boot_end_of_phys_memory < top_addr)
				boot_end_of_phys_memory = top_addr;
			pages_num += phys_bank->pages_num;
			DebugMAP("boot_create_physmem_maps() bank #%d: from "
				"addr 0x%lx to 0x%lx, phys memory start 0x%lx "
				"end 0x%lx\n",
				bank, phys_bank->base_addr, top_addr,
				boot_start_of_phys_memory,
				boot_end_of_phys_memory);
			phys_bank->mem_bitmap = mem_bitmap_v;
			bank_map_size = boot_create_physmem_bank_map(phys_bank,
								max_map_size);
			DebugMAP("boot_create_physmem_maps() bank #%d: "
				"mapped 0x%lx pages, bitmap addr from 0x%lx\n",
				bank, bank_map_size, mem_bitmap_v);
			total_map_size += bank_map_size;
			mem_bitmap_v = &mem_bitmap_v[(bank_map_size +
					(sizeof(boot_mem_map_t) * 8 - 1)) /
					(sizeof(boot_mem_map_t) * 8)];
			phys_bank ++;
		}
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
	}
	boot_pages_of_phys_memory = pages_num;
	DebugMAP("boot_create_physmem_maps() finished: total phys memory "
		"pages number is 0x%lx, maped pages number is first 0x%lx "
		"pages on %d nodes\n",
		pages_num, total_map_size, nodes_num);
	return total_map_size;
}

/*
 * Create pages bitmaps of physical memory banks.
 */

static	e2k_size_t __init boot_create_physmem_bank_map(
				boot_phys_bank_t *phys_bank,
				e2k_size_t max_map_size)
{
	register e2k_addr_t	base_addr = phys_bank->base_addr;
	register e2k_size_t	bitmap_size = phys_bank->pages_num;
	register boot_mem_map_t	*mem_bitmap = NULL;

	boot_printk("boot_create_physmem_bank_map() started: bank base phys "
		"addr = 0x%lx, pages in the bank = 0x%lx, current max map size "
		"= 0x%lx pages\n",
		base_addr, bitmap_size, max_map_size);
	if ((base_addr & ~(PAGE_MASK)) != 0) {
		BOOT_BUG_POINT("boot_create_physmem_bank_map");
		BOOT_BUG("Base address 0x%lx of physical memory bank is not "
			"page aligned", (e2k_addr_t)base_addr);
	}

	if (bitmap_size > max_map_size)
		bitmap_size = max_map_size;
	phys_bank->bitmap_size = bitmap_size;
	atomic_set(&phys_bank->free_pages_num, bitmap_size);
	phys_bank->first_free_page = 0;
	phys_bank->busy_areas_num = 0;
	if (bitmap_size == 0) {
		phys_bank -> mem_bitmap = NULL;
		return 0;
	}

	/*
	 * Initially all pages are free - boot_mem_init() has to
	 * register occupied or reserved RAM areas explicitly.
	 */

	mem_bitmap = boot_vp_to_pp(phys_bank -> mem_bitmap);
	(void) memset((void *)mem_bitmap, 0x00, (bitmap_size + (8-1)) / 8);

	boot_printk("boot_create_physmem_bank_map() finished: bank memory "
		"bitmap addr = 0x%lx, bank maped pages number is 0x%lx\n",
		mem_bitmap, bitmap_size);

	return bitmap_size;
}

#ifdef	CONFIG_RECOVERY

/*
 * Scan all banks of full memory to determine boundaries of
 * full physical memory
 */

void __init
boot_scan_full_physmem(void)
{
	boot_phys_mem_t		*all_phys_banks = NULL;
	boot_phys_bank_t	*phys_bank = NULL;
	e2k_size_t		pages_num = 0;
	e2k_addr_t		top_addr;
	int			bank;
	int			node;
	int			cur_node;
	int			nodes_num;

	all_phys_banks = boot_vp_to_pp(full_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;
	boot_start_of_full_memory = 0xffffffffffffffffUL;
	boot_end_of_full_memory = 0x0000000000000000UL;
	boot_printk("boot_scan_full_physmem() started: full phys banks addr "
		"0x%lx\n", all_phys_banks);

	for (node = 0, cur_node = 0; node < L_MAX_MEM_NUMNODES &&
			cur_node < nodes_num ; node ++) {
		phys_bank = all_phys_banks[node].banks;
		if (phys_bank->pages_num == 0)
			continue;       /* node has not memory */
		cur_node++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (phys_bank -> pages_num == 0)
				break;  /* no more banks on node */

			if (phys_bank->base_addr < boot_start_of_full_memory)
				boot_start_of_full_memory =
					phys_bank->base_addr;
			top_addr = phys_bank->base_addr +
				phys_bank->pages_num * PAGE_SIZE;

			if (boot_end_of_full_memory < top_addr)
				boot_end_of_full_memory = top_addr;
			pages_num += phys_bank->pages_num;
			phys_bank++;
		}
	}
	boot_pages_of_full_memory += pages_num;
	boot_printk("boot_scan_full_physmem() finished: total phys memory "
		"pages number is 0x%lx\n", pages_num);
}
#endif	/* CONFIG_RECOVERY */

/*
 * Reserve a particular physical memory range. This range marks as
 * unallocatable.
 * Usable RAM might be used for boot-time allocations -
 * or it might get added to the free page pool later on.
 * The function returns 0 on reservation success and 1, if all or some part
 * of reserved memory range is already occupied and 'ignore_busy' is not set.
 */

int __init_recv
_boot_reserve_physmem(e2k_addr_t phys_addr, e2k_size_t mem_size,
		e2k_size_t page_size, int ignore_busy)
{
	e2k_addr_t		base_addr;
	e2k_addr_t		end_addr = phys_addr + mem_size;
	boot_phys_bank_t	*phys_bank = NULL;
	long			pages_num;
	long			bank_pages_num;
	int			error_flag = 0;

	boot_printk("_boot_reserve_physmem() started: mem addr 0x%lx "
		"size 0x%lx\n",
		phys_addr, mem_size);
	if (mem_size == 0) {
		BOOT_BUG_POINT("_boot_reserve_physmem");
		BOOT_BUG("Reserved memory area size %ld is empty", mem_size);
	}

	boot_printk("_boot_reserve_physmem() page size 0x%lx\n",
		page_size);
	if (page_size == 0) {
		BOOT_BUG_POINT("_boot_reserve_physmem");
		BOOT_BUG("The page size to round up %ld is empty", page_size);
	}

	/*
	 * Round up according to argument 'page_size', partially reserved
	 * pages are considered fully reserved.
	 */

	base_addr = phys_addr & ~(page_size - 1UL);
	end_addr = (end_addr + (page_size-1)) & ~(page_size - 1UL);
	pages_num = (end_addr - base_addr) / PAGE_SIZE;

	/*
	 * The memory range can occupy a few contiguous physical banks.
	 * The pages bits set in all of these banks
	 */

	boot_printk("_boot_reserve_physmem() will start cycle on pages\n");
	while (pages_num > 0) {
		int node_id;

		boot_printk("_boot_reserve_physmem() will start "
				"boot_find_bank_of_addr()\n");
		phys_bank = boot_find_bank_of_addr(base_addr, &node_id, NULL);
		boot_printk("_boot_reserve_physmem() "
				"boot_find_bank_of_addr() returned 0x%lx\n",
				phys_bank);
		if (phys_bank == NULL) {
#ifndef	CONFIG_RECOVERY
			BOOT_BUG_POINT("_boot_reserve_physmem");
			BOOT_BUG("Could not find the physical memory bank "
				"including reserved address 0x%lx", base_addr);
#else
			boot_printk("Could not find the physical memory bank "
				"including reserved address 0x%lx", base_addr);
			base_addr += PAGE_SIZE;
			pages_num -= 1;
			boot_printk("_boot_reserve_physmem go to the next "
				"page of reserved area with address 0x%lx",
				base_addr);
			continue;
#endif	/* ! (CONFIG_RECOVERY) */
		}
		boot_printk("_boot_reserve_physmem() will start "
				"boot_reserve_bank_physmem()\n");
		bank_pages_num = boot_reserve_bank_physmem(node_id, phys_bank,
					base_addr, pages_num, ignore_busy);
		boot_printk("_boot_reserve_physmem() "
				"boot_reserve_bank_physmem() returned bank "
				"pages num 0x%lx\n",
				bank_pages_num);
		if (bank_pages_num <= 0) {
			error_flag = 1;
			if (bank_pages_num == 0)
				break;
			bank_pages_num = -bank_pages_num;
		}
		pages_num -= bank_pages_num;
		base_addr += (bank_pages_num * PAGE_SIZE);
	}
	return (error_flag);
}

/*
 * Free a particular physical memory range. This range will be allocatable.
 * It might be used for boot-time allocations or it might get added to the
 * free page pool later on.
 */
void __init_recv
_boot_free_physmem(e2k_addr_t phys_addr, e2k_size_t mem_size,
		e2k_size_t page_size)
{
	e2k_addr_t		base_addr;
	e2k_addr_t		end_addr = phys_addr + mem_size;
	boot_phys_bank_t	*phys_bank = NULL;
	long			pages_num;
	long			bank_pages_num;

	if (mem_size == 0) {
		BOOT_BUG_POINT("_boot_free_physmem");
		BOOT_BUG("Reserved memory area size %ld is empty", mem_size);
	}

	if (page_size == 0) {
		BOOT_BUG_POINT("_boot_free_physmem");
		BOOT_BUG("The page size to round down %ld is empty", page_size);
	}

	/*
	 * Round up the beginning of the address and round down end of usable
	 * memory according to argument 'page_size', partially free pages are
	 * considered reserved.
	 */

	base_addr = (phys_addr + (page_size-1)) & ~(page_size - 1UL);
	end_addr = end_addr & ~(page_size - 1UL);
	pages_num = (end_addr - base_addr) / PAGE_SIZE;

	/*
	 * The released memory range can occupy a few contiguous physical banks.
	 * The pages bits clear in all of these banks
	 */

	while (pages_num > 0) {
		int node_id;
		phys_bank = boot_find_bank_of_addr(base_addr, &node_id, NULL);
		if (phys_bank == NULL) {
			BOOT_BUG_POINT("_boot_free_physmem");
			BOOT_BUG("Could not find the physical memory bank "
				"including released address 0x%lx", base_addr);
		}
		bank_pages_num = boot_free_bank_physmem(node_id, phys_bank, 
					base_addr, pages_num);
		pages_num -= bank_pages_num;
		base_addr += (bank_pages_num * PAGE_SIZE);
	}
}

/*
 * Find a bank including the physical address.
 * Function returns the physical pointer of the bank description structure or
 * NULL, if memory bank did not found.
 */
static	boot_phys_bank_t * __init_recv
boot_find_bank_of_addr(e2k_addr_t phys_addr, int *node_id, int *bank_index)
{
	boot_phys_mem_t		*all_phys_banks = NULL;
	boot_phys_bank_t	*phys_bank = NULL;
	int			nodes_num;
	int			cur_nodes_num = 0;
	int			node;
	int			bank;

	all_phys_banks = boot_vp_to_pp(boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		phys_bank = all_phys_banks[node].banks;
		if (phys_bank->pages_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num ++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			if (phys_bank -> pages_num == 0)
				break;	/* no more banks on node */
			if (phys_addr >= phys_bank -> base_addr &&
				phys_addr < phys_bank -> base_addr +
					phys_bank -> pages_num * PAGE_SIZE) {
				if (bank_index != NULL)
					*bank_index = bank;
				if (node_id != NULL)
					*node_id = node;
				return (phys_bank);
			}
			phys_bank ++;
		}
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
	}
	if (bank_index != NULL)
		*bank_index = -1;
	if (node_id != NULL)
		*node_id = -1;;
	return ((boot_phys_bank_t *)NULL);	
}

/*
 * Reserve the physical memory pages of the bank.
 * This pages mark as unallocatable.
 * The function returns the number of reserved pages in the bank
 * or negative number of reserved pages, if any reserved page is already
 * occupied.
 */
static	long __init_recv
boot_reserve_bank_physmem(int node_id, boot_phys_bank_t *phys_bank,
			e2k_addr_t phys_addr, long pages_num, int ignore_busy)
{
	register boot_mem_map_t	*mem_bitmap = NULL;
	register e2k_size_t	start_page;
	register long		page;
	register long		pages;
	register int		busy_flag = 0;

	DebugBANK("boot_reserve_bank_physmem() started for addr 0x%lx and "
		"page(s) 0x%lx\n",
		phys_addr, pages_num);
	if (phys_addr < phys_bank -> base_addr ||
		phys_addr >= phys_bank -> base_addr +
				phys_bank -> pages_num * PAGE_SIZE) {
		BOOT_BUG_POINT("boot_reserve_bank_physmem");
		BOOT_BUG("The address 0x%lx is not in the range of the "
			"physical memory bank addresses 0x%lx : 0x%lx",
			phys_addr, phys_bank -> base_addr,
			phys_bank -> base_addr + 
				phys_bank -> pages_num * PAGE_SIZE);
	}
	mem_bitmap = boot_vp_to_pp(phys_bank -> mem_bitmap);
	DebugBANK("boot_reserve_bank_physmem() mem bitmap is 0x%lx\n",
		mem_bitmap);
	start_page = (phys_addr - phys_bank -> base_addr) / PAGE_SIZE;
	DebugBANK("boot_reserve_bank_physmem() start page is 0x%lx\n",
		start_page);
	for (page = 0; page < pages_num; page ++) {
		if (page + start_page >= phys_bank -> pages_num) {
			return ((busy_flag) ? (long)-page : (long)page);
		}
		if (page + start_page >= phys_bank -> bitmap_size) {
			DebugBANK("The reserved address area from 0x%lx to "
				"0x%lx out of range of mapped pages\n",
				phys_addr + page * PAGE_SIZE,
				phys_addr + pages_num * PAGE_SIZE);
			pages = boot_reserve_bank_area(node_id, phys_bank,
					start_page + page, pages_num - page,
					ignore_busy);
			if (pages <= 0)
				return ((long)(pages - page));
			else if (busy_flag)
				return ((long)(-page - pages));
			else
				return ((long)(page + pages));
		}
		if (boot_test_and_set_bit(page + start_page, mem_bitmap)) {
			if (!ignore_busy) {
				BOOT_WARNING_POINT("boot_reserve_bank_physmem");
				BOOT_WARNING("The address 0x%lx reserved twice",
					phys_addr + page * PAGE_SIZE);
				busy_flag = 1;
			}
		} else {
			atomic_dec(&phys_bank -> free_pages_num);
			cmpxchg(&phys_bank -> first_free_page,
				page + start_page, page + start_page + 1);
		}
		boot_printk("boot_reserve_bank_physmem() reserved bank page "
			"# 0x%lx phys addr 0x%lx\n",
			page + start_page, phys_addr + page * PAGE_SIZE);
	}
	DebugBANK("boot_reserve_bank_physmem() reserved 0x%lx page(s) "
		"in the bank\n",
		page);
	return ((busy_flag) ? (long)-page : (long)page);
}

static	long __init_recv
boot_free_bank_area(int node_id, boot_phys_bank_t *phys_bank,
			e2k_size_t start_page, long pages_num)
{
	register e2k_busy_mem_t	*busy_area = NULL;
	register e2k_addr_t	start_addr;
	register e2k_size_t	end_page;
	register e2k_size_t	ex_start_page = 0;
	register long		ex_pages_num = 0;
	register long		pages;
	register int		area;
	register int		first_hole = -1;
	register char		ex_found = 0; 

	boot_printk("boot_free_bank_area() started: start page # 0x%lx "
		"number of pages 0x%lx\n",
		start_page, pages_num);
	start_addr = phys_bank->base_addr + start_page * PAGE_SIZE;
	pages = phys_bank->pages_num - start_page;
	if (pages_num < pages)
		pages = pages_num;
	end_page = start_page + pages;
	boot_printk("boot_free_bank_area() will free area from addr "
		"0x%lx to addr 0x%lx\n",
		start_addr, start_addr + pages * PAGE_SIZE);

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_lock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
	boot_spin_lock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */

	for (area = 0; area < phys_bank->busy_areas_num; area ++) {
		busy_area = &phys_bank->busy_areas[area];
		if (busy_area->pages_num == 0) {
			if (first_hole < 0)
				first_hole = area;
			if (ex_found)
				break;
			continue;
		}
		if (start_page >= busy_area->start_page + busy_area->pages_num)
			continue;
		if (end_page <= busy_area->start_page)
			continue;
		if ((start_page <= busy_area->start_page) && (end_page >= 
			busy_area->start_page + busy_area->pages_num)) {
			busy_area->pages_num = 0;
			continue;
		}
		if ((start_page <= busy_area->start_page) && (end_page <
			busy_area->start_page + busy_area->pages_num)) {
			busy_area->pages_num -= end_page - busy_area->start_page;
			busy_area->start_page = end_page;
			continue;
		}
		if ((start_page > busy_area->start_page) && (end_page >=
			busy_area->start_page + busy_area->pages_num)) {
			busy_area->pages_num = 
				start_page - busy_area->start_page;
			continue;
		}
		busy_area->pages_num = start_page - busy_area->start_page;
		ex_start_page = end_page;
		ex_pages_num = busy_area->start_page + busy_area->pages_num -
			end_page;
		ex_found = 1;
		if (first_hole >= 0)
			break;
	}

	if (ex_found) {
		if (first_hole >= 0) {
			busy_area = &phys_bank->busy_areas[first_hole];
			busy_area->start_page = ex_start_page;
			busy_area->pages_num = ex_pages_num;
		}
		else {
			boot_printk("boot_free_bank_area() could not free "
				"area from addr 0x%lx to addr 0x%lx, "
				"because there are no free busy_areas "
				"entries\n",
				start_addr, start_addr + pages * PAGE_SIZE);
			return 0;
		}
	}

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
	boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	
	return pages;
}

/*
 * Reserve the physical memory area in the bank.
 * This pages od area mark as unallocatable.
 * The function returns the number of reserved pages in the bank
 * or negative number of reserved pages, if any reserved page is already
 * occupied.
 */
static	long __init_recv
boot_reserve_bank_area(int node_id, boot_phys_bank_t *phys_bank,
			e2k_size_t start_page, long pages_num, int ignore_busy)
{
	register e2k_busy_mem_t	*busy_area = NULL;
	register e2k_addr_t	start_addr;
	register e2k_size_t	end_page;
	register long		pages;
	register int		area;
	register int		first_hole = -1;
	register int		busy_flag = 0;
	register int		area_changed = 0;
	register int		adjacent_areas = 0;

	boot_printk("boot_reserve_bank_area() started: start page # 0x%lx "
		"number of pages 0x%lx\n",
		start_page, pages_num);
	start_addr = phys_bank->base_addr +  start_page * PAGE_SIZE;
	pages = phys_bank->pages_num - start_page;
	if (pages_num < pages)
		pages = pages_num;
	end_page = start_page + pages;
		
	boot_printk("boot_reserve_bank_area() will reserve area from addr "
		"0x%lx to addr 0x%lx\n",
		start_addr, start_addr + pages * PAGE_SIZE);
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_lock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
	boot_spin_lock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	for (area = 0; area < phys_bank->busy_areas_num; area ++) {
		busy_area = &phys_bank->busy_areas[area];
		if (busy_area->pages_num == 0) {
			if (first_hole < 0)
				first_hole = area;
			continue;
		}
		if (start_page > busy_area->start_page + busy_area->pages_num)
			continue;
		else if (start_page == busy_area->start_page +
							busy_area->pages_num)
			adjacent_areas = 1;
		if (end_page < busy_area->start_page)
			continue;
		else if (end_page == busy_area->start_page)
			adjacent_areas = 1;
		if (!ignore_busy && !adjacent_areas) {
			BOOT_WARNING_POINT("boot_reserve_bank_area");
			BOOT_WARNING("The area from 0x%lx to 0x%lx or some "
				"its part is reserved twice",
				start_addr, start_addr + pages * PAGE_SIZE);
			busy_flag = 1;
		}
		if (start_page < busy_area->start_page) {
			boot_printk("The reserved area #%d start page will be "
				"moved from 0x%lx to 0x%lx\n",
				area, busy_area->start_page, start_page);
			busy_area->pages_num += (busy_area->start_page -
								start_page);
			busy_area->start_page = start_page;
			boot_printk("The reserved area #%d new size is "
				"0x%lx pages\n",
				area, busy_area->pages_num);
			area_changed = 1;
		}
		if (end_page > busy_area->start_page + busy_area->pages_num) {
			boot_printk("The reserved area #%d finish page will be "
				"moved from 0x%lx to 0x%lx\n",
				area,
				busy_area->start_page + busy_area->pages_num,
				end_page);
			busy_area->pages_num += (end_page -
						(busy_area->start_page +
							busy_area->pages_num));
			boot_printk("The reserved area new size is "
				"0x%lx pages\n",
				busy_area->pages_num);
			area_changed = 1;
		}
		if (area_changed) {
			start_page = busy_area->start_page;
			pages_num = busy_area->pages_num;
			busy_area->pages_num = 0;
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
			boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			boot_printk("The area #%d will be reserved again as "
				"area from 0x%lx page and size 0x%lx\n",
				area, start_page, pages_num);
			(void) boot_reserve_bank_area(node_id, phys_bank,
					start_page, pages_num, ignore_busy);
		} else {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
			boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			boot_printk("The area from addr 0x%lx to addr 0x%lx "
				"is included into the area #%d\n",
				start_addr, start_addr + pages * PAGE_SIZE,
				area);
		}
		return ((busy_flag) ? (long)-pages : (long)pages);
	}
	if (first_hole < 0) {
		first_hole = phys_bank->busy_areas_num;
		if (first_hole >= E2K_MAX_PRERESERVED_AREAS) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
			boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("boot_reserve_bank_area");
			BOOT_BUG("Too many prereserved areas in the bank "
				"(> %d)",
				E2K_MAX_PRERESERVED_AREAS);
			return (0);
		}
		phys_bank->busy_areas_num ++;
	}
	busy_area = &phys_bank->busy_areas[first_hole];
	busy_area->start_page = start_page;
	busy_area->pages_num = pages;
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
	boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	boot_printk("The new reserved area #%d from 0x%lx to 0x%lx "
		"was added to the list of occupied areas\n",
		first_hole, 
		start_addr, start_addr + pages * PAGE_SIZE);

	return ((busy_flag) ? (long)-pages : (long)pages);
}

/*
 * Order the physical memory areas in the bank on increase of addresses
 */
static	void __init boot_order_bank_areas(boot_phys_bank_t *phys_bank)
{
	register e2k_busy_mem_t	*busy_areai = NULL;
	register e2k_busy_mem_t	*busy_areaj = NULL;
	register e2k_size_t	start_page;
	register e2k_size_t	end_page;
	register int		i;
	register int		j;

	DebugB("boot_order_bank_areas() started\n");
	for (i = 0; i < phys_bank->busy_areas_num; i ++) {
		busy_areai = &phys_bank->busy_areas[i];
		if (busy_areai->pages_num == 0)
			continue;
		start_page = busy_areai->start_page;
		end_page = start_page + busy_areai->pages_num;
		DebugB("The reserved area #%d from page 0x%lx to 0x%lx "
			"will be ordered\n",
			i, start_page, end_page);
		for (j = i + 1; j < phys_bank->busy_areas_num; j ++) {
			busy_areaj = &phys_bank->busy_areas[j];
			if (busy_areaj->pages_num == 0)
				continue;
			if (start_page < busy_areaj->start_page) {
				if (end_page > busy_areaj->start_page) {
					INIT_BUG_POINT("boot_order_bank_areas");
					INIT_BUG("The area #%d end page 0x%lx "
						"> start page 0x%lx of area "
						"#%d",
						i, end_page,
						busy_areaj->start_page, j);
				}
				continue;
			}
			if (start_page < busy_areaj->start_page +
						busy_areaj->pages_num) {
				INIT_BUG_POINT("boot_order_bank_areas");
				INIT_BUG("The area #%d start page 0x%lx < end "
					"page 0x%lx of area #%d",
					i, start_page,
					busy_areaj->start_page +
						busy_areaj->pages_num,
					j);
			}
			DebugB("The reserved area #%d with start page "
				"0x%lx is exchanged with area #%d "
				"with start page 0x%lx\n",
				i, start_page,
				j, busy_areaj->start_page);
			busy_areai->start_page = busy_areaj->start_page;
			busy_areai->pages_num = busy_areaj->pages_num;
			busy_areaj->start_page = start_page;
			busy_areaj->pages_num = end_page - start_page;
			start_page = busy_areai->start_page;
			end_page = start_page + busy_areai->pages_num;
		}
	}
}

/*
 * Free the physical memory pages of the bank.
 * This pages mark as allocatable.
 * The function returns the number of released pages in the bank
 */
static	long  __init_recv
boot_free_bank_physmem(int node_id, boot_phys_bank_t *phys_bank,
			e2k_addr_t phys_addr, long pages_num)
{
	register boot_mem_map_t	*mem_bitmap = NULL;
	register e2k_size_t	start_page;
	register long		page;
	register long 		pages;
	register e2k_size_t	first_free_page;

	DebugBANK("boot_free_bank_physmem() started for addr 0x%lx and "
		"0x%lx page(s)\n",
		phys_addr, pages_num);
	if (phys_addr < phys_bank -> base_addr ||
		phys_addr >= phys_bank -> base_addr +
				phys_bank -> pages_num * PAGE_SIZE) {
		BOOT_BUG_POINT("boot_free_bank_physmem");
		BOOT_BUG("The address 0x%lx is not in the range of the "
			"physical memory bank addresses 0x%lx : 0x%lx",
			phys_addr, phys_bank -> base_addr,
			phys_bank -> base_addr + 
				phys_bank -> pages_num * PAGE_SIZE);
	}
	mem_bitmap = boot_vp_to_pp(phys_bank -> mem_bitmap);
	start_page = (phys_addr - phys_bank -> base_addr) / PAGE_SIZE;
	for (page = 0; page < pages_num; page ++) {
		if (page + start_page >= phys_bank -> pages_num) {
			return ((long)page);
		}
		if (page + start_page >= phys_bank -> bitmap_size) {
			DebugBANK("The released address area from 0x%lx to "
				"0x%lx out of range of mapped pages\n",
				phys_addr + page * PAGE_SIZE,
				phys_addr + pages_num * PAGE_SIZE);
			pages = boot_free_bank_area(node_id, phys_bank, 
					start_page + page, pages_num - page);
			return (pages + page);
		}
		if (!boot_test_and_clear_bit(page + start_page, mem_bitmap)) {
			BOOT_WARNING_POINT("boot_free_bank_physmem");
			BOOT_WARNING("The address 0x%lx released twice",
				phys_addr + page * PAGE_SIZE);
		} else {
			atomic_inc(&phys_bank -> free_pages_num);
			first_free_page = phys_bank -> first_free_page;
			if (page + start_page < first_free_page)
				cmpxchg(&phys_bank -> first_free_page,
					first_free_page, page + start_page);
		}
		boot_printk("boot_free_bank_physmem() has released page # "
			"0x%lx in the bank, (released addr is 0x%lx)\n",
			page + start_page, phys_addr + page * PAGE_SIZE);
	}
	boot_printk("boot_free_bank_physmem() has released 0x%lx page(s) "
		"in the bank\n",
		page);
	return ((long)page);	
}

/*
 * Allocate memory area into the free physical memory space on the node.
 * Start address of allocation should have the alignment 'align' and
 * The memory area is allocated in terms of pages with size 'page_size'.
 * Partially occupied pages (in terms of 'page_size') are considered fully
 * reserved and can not be used for other memory request.
 *
 * Alignment 'align' and 'page_size' has to be a power of 2 value.
 *
 * Function returns base address of allocated memory or (void *)-1, if
 * allocation failed or no memory on the node
 */
static void *  __init_recv
boot_alloc_node_physmem(int node_id, e2k_size_t mem_size, e2k_size_t align,
			e2k_size_t page_size)
{
	boot_phys_mem_t		*all_phys_banks = NULL;
	boot_phys_bank_t	*phys_bank = NULL;
	boot_mem_map_t		*mem_bitmap = NULL;
	e2k_size_t		max_align;
	int			bank;
	long			pages_num;
	long			mem_pages;
	e2k_size_t		start_page;
	long			page;
	unsigned char		start_found;
	e2k_addr_t		start_addr = -1;
	int			ret;

	DebugAM("boot_alloc_node_physmem() node #%d: mem size 0x%lx\n",
		node_id, mem_size);
	if (mem_size == 0) {
		BOOT_BUG_POINT("_boot_alloc_physmem");
		BOOT_BUG("Allocated memory area size %ld is empty", mem_size);
		return ((void *)-1);
	}

	DebugAM("boot_alloc_node_physmem() page size 0x%lx\n", page_size);
	if (page_size == 0) {
		BOOT_BUG_POINT("boot_alloc_node_physmem");
		BOOT_BUG("The page size to round up %ld is empty", page_size);
		return ((void *)-1);
	}

	if (align > page_size)
		max_align = align;
	else
		max_align = page_size;
	DebugAM("boot_alloc_node_physmem() max align 0x%lx\n", max_align);
	mem_pages = (mem_size + (page_size-1)) / page_size;
	mem_pages *= (page_size / PAGE_SIZE);
	DebugAM("boot_alloc_node_physmem() mem pages 0x%lx\n", mem_pages);

	/*
	 * Scan the node physical memory banks and search an area of contiguous
	 * free pages, which satisfies to conditions of start address alignment,
	 * needed page size alignment and requested memory size.
	 * The allocated memory range can occupy a few contiguous physical
	 * banks.
	 */

	all_phys_banks = boot_vp_to_pp(boot_phys_mem);

	pages_num = mem_pages;
	start_found = 0;
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_lock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
	boot_spin_lock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	phys_bank = all_phys_banks[node_id].banks;
	if (phys_bank->pages_num == 0) {
		goto no_memory;	/* node has not memory */
	}
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
		phys_bank = &all_phys_banks[node_id].banks[bank];
		DebugAM("boot_alloc_node_physmem() current bank #%d is "
			"0x%lx\n", bank, phys_bank);
		DebugAM("boot_alloc_node_physmem() bank pages num is 0x%lx\n",
			phys_bank->pages_num);
		if (phys_bank->pages_num == 0)
			break;	/* no more memory on node */
		DebugAM("boot_alloc_node_physmem() bank free pages "
			"num is 0x%lx\n",
			(long)atomic_read(&phys_bank->free_pages_num));
		if (atomic_read(&phys_bank->free_pages_num) == 0) {
			start_found = 0;
			pages_num = mem_pages;
			continue;
		}
		mem_bitmap = boot_vp_to_pp(phys_bank->mem_bitmap);
		DebugAM("boot_alloc_node_physmem() mem bitmap is "
			"0x%lx\n", mem_bitmap);
		if (start_found) {
			start_page = 0;
		} else {
			start_page = phys_bank->first_free_page;
		}
		DebugAM("boot_alloc_node_physmem() start page is "
			"0x%lx\n", start_page);

		/*
		 * Scan all free pages of physical memory bank and
		 * search a suitable area of contiguous free pages.
		 */

		DebugAM("boot_alloc_node_physmem() will start cycle "
			"on pages\n");
		for (page = start_page;
			page < phys_bank->bitmap_size;
				page++) {
			if (boot_test_bit(page, mem_bitmap)) {
				start_found = 0;
				pages_num = mem_pages;
				cmpxchg(&phys_bank->first_free_page,
					page, page + 1);
				continue;
			}
			if (start_found) {
				pages_num --;
				if (pages_num == 0)
					break;
				continue;
			}
			start_addr = phys_bank->base_addr +
						page * PAGE_SIZE;
			if ((start_addr & (max_align - 1)) != 0) {
				continue;
			}
			start_found = 1;
			pages_num --;
			if (pages_num == 0)
				break;
		}
		if (start_found && pages_num == 0)
			break;
		else if (!start_found)
			continue;
		if (phys_bank -> pages_num > phys_bank -> bitmap_size) {
			/*
			 * There is a hole between a maped pages of two
			 * adjacent banks
			 */
			start_found = 0;
			pages_num = mem_pages;
			continue;
		}
	}

	if (!start_found || pages_num != 0 ) {
no_memory:
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
		boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
		boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
		DebugAM("boot_alloc_node_physmem() node #%d: could not find "
			"free memory enough to allocate area: size 0x%lx "
			"align 0x%lx page size 0x%lx\n",
			node_id, mem_size, align, page_size);
		return ((void *)-1);
	}

	/*
	 * Reserve the area now:
	 */

	ret = _boot_reserve_physmem(start_addr, mem_size, page_size, 0);
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_unlock(&boot_phys_mem_lock);
#else	/* CONFIG_NUMA */
	boot_spin_unlock(&boot_node_phys_mem_lock[node_id]);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	if (ret != 0) {
		BOOT_BUG_POINT("boot_alloc_node_physmem");
		BOOT_BUG("Could not reserve allocated free memory "
			"area: node #%d size %ld align 0x%lx page size 0x%lx",
			node_id, mem_size, align, page_size);
		return ((void *)-1);
	}

	return((void *)start_addr);
}

void * __init_recv
boot_alloc_node_mem(int node_id, e2k_size_t mem_size, e2k_size_t align,
			e2k_size_t page_size, int only_on_the_node, int try)
{
	node_phys_mem_t *all_nodes_mem = NULL;
	void	*node_mem;
	int	cur_node = node_id;
	int	node;
	int	nodes_num;
	int	cur_nodes_num = 0;
	int	cur_try;

	DebugAM("boot_alloc_node_mem() node #%d: mem size 0x%lx %s\n",
		node_id, mem_size,
		(only_on_the_node) ? "only on this node"
					: "may be on other node");
	nodes_num = boot_phys_mem_nodes_num;
	all_nodes_mem = boot_vp_to_pp(boot_phys_mem);
	for (cur_try = 0; cur_try < 3; cur_try ++) {
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= nodes_num)
			goto next_try;	/* no more nodes with memory */
		if (all_nodes_mem[cur_node].pfns_num == 0) {
			if (only_on_the_node)
				break;
			goto next_node;	/* node has not memory */
		}
		node_mem = boot_alloc_node_physmem(cur_node, mem_size, align,
							page_size);
		if (node_mem != (void *)-1) {
			if (cur_node != node_id) {
				BOOT_WARNING_POINT("boot_alloc_node_mem");
				BOOT_WARNING("Could allocate area on node #%d  "
					"insteed of #%d, addr 0x%lx size 0x%lx "
					"align 0x%lx page size 0x%lx",
					cur_node, node_id, node_mem,
					mem_size, align, page_size);
			}
			DebugAM("boot_alloc_node_mem() node #%d: allocated "
				"on node #%d from 0x%p, size 0x%lx %s\n",
				node_id, cur_node, node_mem, mem_size);
			return (node_mem);
		}
		if (only_on_the_node)
			break;
		cur_nodes_num ++;
next_node:
		cur_node ++;
		if (cur_node >= L_MAX_MEM_NUMNODES) {
			/*
			 * If there is not more nodes, we start new search
			 * from node #1 and only at last we take node #0
			 * so same algorithm is used while building zone lists
			 * on each node (see mm/page_alloc.c)
			 */
next_try:
			if (cur_try == 0) {
				cur_node = 1;
				cur_nodes_num = 1;
				break;
			} else if (cur_try == 1) {
				cur_node = 0;
				cur_nodes_num = 0;
				break;
			}
		}
	}
		if (only_on_the_node)
			break;
	}
	if (!try) {
		BOOT_BUG_POINT("boot_alloc_node_mem");
		BOOT_BUG("Could not find free memory enough to allocate area: "
			"node #%d (%s) size %ld align 0x%lx page size 0x%lx",
			node_id,
			(only_on_the_node) ? "only on this node"
						: "and on other node",
			mem_size, align, page_size);
	}
	return ((void *)-1);
}

/*
 * Register the available free physical memory with the allocator.
 * ("linux/mm/bootmap')
 *
 * Function returns number of registered free pages
 */
#ifndef CONFIG_DISCONTIGMEM
#define do_free_bootmem(start, size)	free_bootmem((start), (size))
#else
#define do_free_bootmem(start, size)	\
		free_bootmem_node(NODE_DATA(node), (start), (size))
#endif /* ! CONFIG_DISCONTIGMEM */

e2k_size_t __init register_free_bootmem()
{
	boot_phys_bank_t	*phys_bank = NULL;
	e2k_busy_mem_t		*busy_area = NULL;
	e2k_size_t		size;
	e2k_addr_t		start_addr = -1;
	e2k_size_t		free_pages_num = 0;
	e2k_size_t		start_page;
	unsigned long		fz;
	unsigned long		fs;
	long			pages_num;
	int			nodes_num;
	int			cur_nodes_num = 0;
	int			node = 0;
	int			bank;
	int			area;

#ifdef CONFIG_DEBUG_PAGEALLOC
	/*
	 * Free reserved some memory from the begining of physical memory
	 * This memory was mapped to small pages (from physical
	 * memory start to start of X86 low IO memory area)
	 * Freed memory will be used to split first large pages
	 */

	if (start_of_phys_memory < E2K_X86_LOW_IO_AREA_PHYS_BASE) {
		do_free_bootmem(start_of_phys_memory,
					DEBUG_PAGEALLOC_AREA_SIZE);
		DebugB("register_free_bootmem() free the begining of physical memory to debug PAGEALLOC from 0x%lx to 0x%lx\n",
			start_of_phys_memory, 32 * PAGE_SIZE);
	}

#endif /* CONFIG_DEBUG_PAGEALLOC */
	nodes_num = boot_phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		phys_bank = boot_phys_mem[node].banks;
		if (phys_bank->pages_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num++;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
			phys_bank = &boot_phys_mem[node].banks[bank];
			if (phys_bank->pages_num == 0)
				break;	/* no more nodes with memory */

			if (phys_bank->bitmap_size == 0 &&
				phys_bank->busy_areas_num == 0) {
				/*
				 * The bank is fully free
				 */
				start_addr = phys_bank->base_addr;
				size = phys_bank->pages_num * PAGE_SIZE;
				do_free_bootmem(start_addr, size);
				free_pages_num += phys_bank->pages_num;
				DebugB("register_free_bootmem() free memory from 0x%lx to 0x%lx\n",
					start_addr, start_addr + size);
				continue;
			}

			/*
			 * Scan all free pages of physical memory bank and
			 * collect the areas of contiguous free pages.
			 */
			fs = 0;
			while ((fz = find_next_zero_bit(
						phys_bank->mem_bitmap,
						phys_bank->bitmap_size,
						fs)) < phys_bank->bitmap_size) {
				fs = find_next_bit(phys_bank->mem_bitmap,
					phys_bank->bitmap_size, fz);
				start_addr = phys_bank->base_addr +
							fz * PAGE_SIZE;
				size = (fs - fz) * PAGE_SIZE;
				do_free_bootmem(start_addr, size);
				DebugB("register_free_bootmem() free memory from 0x%lx to 0x%lx\n",
					start_addr, start_addr + size);
			}

			if (phys_bank->pages_num > phys_bank->bitmap_size) {
				/*
				 * There are some number of not maped pages
				 * in the bank.
				 * These pages should be registered as free
				 * memory
				 */
				start_page = phys_bank->bitmap_size;
				start_addr = phys_bank->base_addr +
						start_page * PAGE_SIZE;
				boot_order_bank_areas(phys_bank);
				for (area = 0;
					area < phys_bank->busy_areas_num; 
						area++) {
					busy_area =
						&phys_bank->busy_areas[area];
					if (busy_area->pages_num == 0)
						continue;
					pages_num = busy_area->start_page -
								start_page;
					size = pages_num * PAGE_SIZE;
					if (size != 0) {
						do_free_bootmem(start_addr,
									size);
						free_pages_num += pages_num;
						DebugB("register_free_bootmem() freeing memory from 0x%lx to 0x%lx\n",
							start_addr,
							start_addr + size);
					}
					start_page = busy_area->start_page +
							busy_area->pages_num;
					start_addr = phys_bank->base_addr +
							start_page * PAGE_SIZE;
				}
				if (start_page < phys_bank->pages_num) {
					pages_num = phys_bank->pages_num -
								start_page;
					size = pages_num * PAGE_SIZE;
					do_free_bootmem(start_addr, size);
					free_pages_num += pages_num;
					DebugB("register_free_bootmem() freeing memory from 0x%lx to 0x%lx\n",
						start_addr, start_addr + size);
				}
			}
		}
		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
	}
	DebugB("register_free_bootmem() total number of realised "
		"memory pages is 0x%lx\n",
		free_pages_num);
	return free_pages_num;
}

/*
 * Map the physical memory range (or all physical memory) into virtual space
 *
 * Function returns number of mapped physical pages
 */
int __init
boot_map_physmem(e2k_addr_t phys_base_addr, e2k_size_t mem_size,
	e2k_addr_t virt_base_addr, pgprot_t prot_flags, e2k_size_t page_size)
{
	boot_phys_mem_t		*all_phys_banks = NULL;
	boot_phys_mem_t		*node_mem;
	e2k_addr_t		phys_addr = phys_base_addr;
	e2k_size_t		size = mem_size;
	e2k_addr_t		end_addr;
	e2k_addr_t		virt_addr = virt_base_addr;
	e2k_size_t		offset;
	boot_phys_bank_t	*phys_bank = NULL;
	long			pages_num;
	long			bank_pages_num;
	int			mapped_pages = 0;
	int			start_node;
	int			start_bank;
	int			node;
	int			bank;

	DebugMP("boot_map_physmem() started to map physical memory from 0x%lx "
		"size 0x%lx to virtual from 0x%lx\n",
		phys_base_addr, mem_size, virt_base_addr);
	all_phys_banks = boot_vp_to_pp(boot_phys_mem);
	if (phys_base_addr == (e2k_addr_t)-1) {
		phys_addr = boot_start_of_phys_memory;
	}
	if (mem_size == 0 || mem_size == (e2k_size_t)-1) {
		size = boot_pages_of_phys_memory * PAGE_SIZE -
				(phys_addr - boot_start_of_phys_memory);
	}
	end_addr = phys_addr + size;

	/*
	 * Round up according to argument 'page_size', partially mapped
	 * pages are considered fully mapped.
	 */

	phys_addr = PAGE_ALIGN_UP(phys_addr);
	end_addr = PAGE_ALIGN_DOWN(end_addr);
	pages_num = (end_addr - phys_addr) / PAGE_SIZE;
	virt_addr = PAGE_ALIGN_UP(virt_addr);
	DebugMP("boot_map_physmem() will map physical memory from 0x%lx "
		"to 0x%lx, pages num 0x%lx\n",
		phys_addr, end_addr, pages_num);

	/*
	 * The memory range can occupy a few serial physical banks.
	 * The pages are mapped in all of those banks
	 */

	phys_bank = boot_find_bank_of_addr(phys_addr, &start_node, &start_bank);
	if (phys_bank == NULL) {
		BOOT_BUG_POINT("boot_map_physmem");
		BOOT_BUG("Could not find the physical memory bank "
			"including mapped address 0x%lx", phys_addr);
	}
	bank_pages_num = boot_map_bank_physmem(phys_bank, phys_addr,
				pages_num, virt_addr, prot_flags, page_size);
	DebugMP("boot_map_physmem() mapped 0x%lx pages start node %d "
		"start bank %d\n",
		bank_pages_num, start_node, start_bank);
	mapped_pages += bank_pages_num;
	pages_num -= bank_pages_num;
	if (pages_num <= 0) {
		return mapped_pages;
	}
	phys_addr += (bank_pages_num * PAGE_SIZE);
	virt_addr += (bank_pages_num * PAGE_SIZE);
	start_bank ++;
	DebugMP("boot_map_physmem() will map physical memory from 0x%lx "
		"to virtual 0x%lx, start bank %d\n",
		phys_addr, virt_addr, start_bank);

	for (node = start_node; node < L_MAX_MEM_NUMNODES; node ++) {
		node_mem = &all_phys_banks[node];
		if (node_mem->banks[0].pages_num == 0)
			continue;	/* node has not memory */
		for (bank = start_bank;
			bank < L_MAX_NODE_PHYS_BANKS;
				bank ++) {
			phys_bank = &node_mem->banks[bank];
			if (phys_bank->pages_num == 0)
				break;	/* no more banks on node */
			offset = phys_bank->base_addr - phys_addr;
			if (offset != 0) {
				phys_addr += offset;
				virt_addr += offset;
			}
			bank_pages_num = boot_map_bank_physmem(phys_bank,
						phys_addr, pages_num,
						virt_addr, prot_flags,
						page_size);
			DebugMP("boot_map_physmem() mapped 0x%lx pages on bank "
				"%d node %d start addr 0x%lx\n",
				bank_pages_num, bank, node, phys_addr);
			mapped_pages += bank_pages_num;
			pages_num -= bank_pages_num;
			if (pages_num <= 0)
				break;
			phys_addr += (bank_pages_num * PAGE_SIZE);
			virt_addr += (bank_pages_num * PAGE_SIZE);
			DebugMP("boot_map_physmem() will map physical memory "
				"from 0x%lx to virtual 0x%lx, rest pages "
				"0x%lx\n",
				phys_addr, virt_addr, pages_num);
		}
		if (pages_num <= 0)
			break;
		start_bank = 0;
	}
	if (pages_num > 0) {
		BOOT_BUG_POINT("boot_map_physmem");
		BOOT_BUG("Could not map all needed physical memory pages "
			"only 0x%lx pages instead of 0x%lx", mapped_pages,
			mapped_pages + pages_num);
	}
	return mapped_pages;
}

/*
 * Map the physical memory pages of the bank into the virtual pages
 * The function returns the number of mapped pages in the bank
 */
static	long __init_recv
boot_map_bank_physmem(boot_phys_bank_t *phys_bank,
	e2k_addr_t phys_addr, long pages_num,
	e2k_addr_t virt_addr, pgprot_t prot_flags, e2k_size_t page_size)
{
	e2k_size_t	start_page;
	long		bank_pages_num;
	int		ret;
	e2k_addr_t	map_phys_addr;
	e2k_addr_t	map_virt_addr;
	e2k_size_t	map_size;

	if (phys_addr < phys_bank -> base_addr ||
		phys_addr >= phys_bank -> base_addr +
				phys_bank -> pages_num * PAGE_SIZE) {
		BOOT_BUG_POINT("boot_map_bank_physmem");
		BOOT_BUG("The address 0x%lx is not in the range of the "
			"physical memory bank addresses 0x%lx : 0x%lx",
			phys_addr, phys_bank -> base_addr,
			phys_bank -> pages_num * PAGE_SIZE);
	}
	start_page = (phys_addr - phys_bank -> base_addr) / PAGE_SIZE;
	bank_pages_num = phys_bank -> pages_num - start_page;
	if (bank_pages_num > pages_num)
		bank_pages_num = pages_num;
	map_phys_addr = _PAGE_ALIGN_UP(phys_addr, page_size);
	map_virt_addr = _PAGE_ALIGN_UP(virt_addr, page_size);
	map_size = bank_pages_num * PAGE_SIZE + (phys_addr - map_phys_addr);
	ret = boot_map_phys_area(map_phys_addr, map_size, map_virt_addr,
		prot_flags, page_size,
		(map_phys_addr != phys_addr));	/* ignore or not if mapping */
						/* virtual area is busy */
	if (ret <= 0) {
		BOOT_BUG_POINT("boot_map_bank_physmem");
		BOOT_BUG("Could not map physical memory area: "
			"base addr 0x%lx size 0x%lx page size 0x%x to "
			"virtual addr 0x%lx",
			phys_addr, bank_pages_num * PAGE_SIZE, page_size,
			virt_addr);
		return (-1);
	}
	return (bank_pages_num);
}
