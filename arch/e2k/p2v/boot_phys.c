/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Simple boot-time physical memory accounting and memory allocator.
 * Discontiguous memory supports on memory banks level.
 */

#include <asm/p2v/boot_v2p.h>

#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_map.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_console.h>
#include <asm/boot_profiling.h>
#include <asm/mmu_types.h>
#include <asm/l-iommu.h>

#include "boot_string.h"

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#undef	DebugB
#define	DEBUG_BOOT_MODE		0	/* Boot process */
#define	boot_printk		if (DEBUG_BOOT_MODE) do_boot_printk
#define	DebugB			if (DEBUG_BOOT_MODE) printk

#undef	DEBUG_PHYS_BANK_MODE
#undef	DebugBank
#define	DEBUG_PHYS_BANK_MODE	0	/* Reserve bank of memory */
#define	DebugBank		if (DEBUG_PHYS_BANK_MODE) do_boot_printk

#undef	DEBUG_DELETE_MEM_MODE
#undef	DebugDEL
#define	DEBUG_DELETE_MEM_MODE	0	/* Delete area of memory bank */
#define	DebugDEL		if (DEBUG_DELETE_MEM_MODE) do_boot_printk

#undef	DEBUG_PHYS_MAP_MODE
#undef	DebugMAP
#define	DEBUG_PHYS_MAP_MODE	0	/* Physical memory map */
#define	DebugMAP		if (DEBUG_PHYS_MAP_MODE) do_boot_printk

#undef	DEBUG_MAP_PHYS_MEM_MODE
#undef	DebugMP
#define	DEBUG_MAP_PHYS_MEM_MODE	0	/* Physical memory mapping to virtual */
#define	DebugMP			if (DEBUG_MAP_PHYS_MEM_MODE) do_boot_printk

#undef	DEBUG_REMAP_LOW_MEM_MODE
#undef	DebugRML
#define	DEBUG_REMAP_LOW_MEM_MODE 0	/* Low physical memory remapping */
#define	DebugRML		if (DEBUG_REMAP_LOW_MEM_MODE) do_boot_printk

#undef	DEBUG_REMAP_SUM_MODE
#undef	DebugRMLT
#define	DEBUG_REMAP_SUM_MODE	0	/* Sum of low memory remapping */
#define	DebugRMLT		if (DEBUG_REMAP_SUM_MODE) do_boot_printk

#undef	DEBUG_MEM_ALLOC_MODE
#undef	DebugAM
#define	DEBUG_MEM_ALLOC_MODE	0	/* Physical memory allocation */
#define	DebugAM			if (DEBUG_MEM_ALLOC_MODE) do_boot_printk

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* Boot NUMA */
#define	DebugNUMA		if (DEBUG_NUMA_MODE) do_boot_printk

e2k_addr_t	start_of_phys_memory;	/* start address of physical memory */
e2k_addr_t	end_of_phys_memory;	/* end address + 1 of physical memory */
e2k_size_t	pages_of_phys_memory;	/* number of pages of physical memory */

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
static boot_spinlock_t boot_phys_mem_lock = __BOOT_SPIN_LOCK_UNLOCKED;
#define	boot_the_node_spin_lock(node, lock)	boot_spin_lock(&(lock))
#define	boot_the_node_spin_unlock(node, lock)	boot_spin_unlock(&(lock))
#else	/* CONFIG_NUMA */
static boot_spinlock_t __initdata_recv boot_phys_mem_lock[MAX_NUMNODES] = {
	[0 ... (MAX_NUMNODES-1)] = __BOOT_SPIN_LOCK_UNLOCKED
};
#define	boot_the_node_spin_lock(node, lock)	\
		boot_spin_lock(&((lock)[node]))
#define	boot_the_node_spin_unlock(node, lock)	\
		boot_spin_unlock(&((lock)[node]))
#endif	/* ! CONFIG_NUMA */
#else	/* ! CONFIG_SMP */
#define	boot_phys_mem_lock
#define	boot_the_node_spin_lock(node, lock)
#define	boot_the_node_spin_unlock(node, lock)
#endif	/* CONFIG_SMP */

__init
void boot_expand_phys_banks_reserved_areas(void)
{
	boot_phys_mem_t	*all_nodes_mem = NULL;
	int		nodes_num;
	int		cur_nodes_num = 0;
	int		node;
	int		bank;

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		node_phys_mem_t *node_mem = &all_nodes_mem[node];
		boot_phys_bank_t *node_banks;
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;		/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */

		node_banks = node_mem->banks;
		cur_nodes_num++;

		for (bank = node_mem->first_bank;
				bank >= 0;
					bank = phys_bank->next) {
			e2k_addr_t area_base;

			phys_bank = &node_banks[bank];

			if (phys_bank->pages_num == 0)
				BOOT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);

			area_base = (e2k_addr_t)boot_alloc_phys_mem(
					BOOT_RESERVED_AREAS_SIZE, PAGE_SIZE,
					boot_time_data_mem_type);
			boot_memcpy((void *)area_base, phys_bank->busy_areas,
				sizeof(phys_bank->busy_areas_prereserved));
			DebugBank("Node #%d bank #%d busy_areas array at "
				"address 0x%lx and size 0x%lx moved to 0x%lx "
				"and expanded to 0x%lx bytes\n",
				node, bank, phys_bank->busy_areas,
				sizeof(phys_bank->busy_areas_prereserved),
				area_base, BOOT_RESERVED_AREAS_SIZE);
			phys_bank->busy_areas = (e2k_busy_mem_t *)area_base;
		}
	}
}

/*
 * Create pages maps of physical memory banks.
 */
e2k_size_t __init
boot_do_create_physmem_maps(boot_info_t *boot_info, bool create)
{
	boot_phys_mem_t	*all_nodes_mem = NULL;
	int		nodes_num;
	int		cur_nodes_num = 0;
	e2k_size_t	pages_num = 0;
	e2k_addr_t	top_addr;
	int		node;
	short		bank;

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	boot_start_of_phys_memory = 0xffffffffffffffffUL;
	boot_end_of_phys_memory = 0x0000000000000000UL;

	nodes_num = boot_phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		node_phys_mem_t *node_mem = &all_nodes_mem[node];
		boot_phys_bank_t *node_banks;
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		node_banks = node_mem->banks;
		DebugMAP("Node #%d: physical memory banks number %d\n",
			node, node_mem->banks_num);
		cur_nodes_num ++;
		for (bank = node_mem->first_bank;
				bank >= 0;
					bank = phys_bank->next) {
			phys_bank = &node_banks[bank];
			if (phys_bank->pages_num == 0) {
				/* bank in the list has not pages */
				BOOT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);
			}
			if (phys_bank->base_addr < boot_start_of_phys_memory)
				boot_start_of_phys_memory =
					phys_bank->base_addr;
			top_addr = phys_bank->base_addr +
					phys_bank->pages_num * PAGE_SIZE;
			if (boot_end_of_phys_memory < top_addr)
				boot_end_of_phys_memory = top_addr;
			pages_num += phys_bank->pages_num;
			if (create && is_addr_from_low_memory(top_addr -1)) {
				/* it is low memory bank */
				phys_bank->maybe_remapped_to_hi =
					boot_has_lo_bank_remap_to_hi(phys_bank,
								boot_info);
			}
			DebugMAP("Node %d bank #%d: from addr 0x%lx to 0x%lx, "
				"phys memory start 0x%lx end 0x%lx\n",
				node, bank, phys_bank->base_addr, top_addr,
				boot_start_of_phys_memory,
				boot_end_of_phys_memory);
		}
	}
	boot_pages_of_phys_memory = pages_num;
	DebugMAP("Total phys memory pages number is 0x%lx on %d node(s), "
		"start from 0x%lx to end 0x%lx\n",
		pages_num, nodes_num,
		boot_start_of_phys_memory, boot_end_of_phys_memory);
	return pages_num;
}

/* lock should be taken by caller */
static inline void __init_recv
boot_delete_busy_area(int node, e2k_phys_bank_t *phys_bank,
	e2k_busy_mem_t *busy_area, short area_id, e2k_busy_mem_t *prev_area)
{
	if (prev_area == NULL) {
		/* area should be at head of the list */
		if (phys_bank->first_area != area_id) {
			BOOT_BUG("Node #%d busy area #%d from 0x%lx to 0x%lx "
				"should be at head, but head point to area #%d",
				node, area_id,
				phys_bank->base_addr +
					(busy_area->start_page << PAGE_SHIFT),
				phys_bank->base_addr +
					(busy_area->start_page +
						busy_area->pages_num) <<
								PAGE_SHIFT);
		}
		phys_bank->first_area = busy_area->next;
	} else {
		/* previous area should point to the deleted area */
		if (prev_area->next != area_id) {
			BOOT_BUG("Node #%d busy area #%d from 0x%lx to 0x%lx "
				"should be pointed by previous area, "
				"but it point to area #%d",
				node, area_id,
				phys_bank->base_addr +
					(busy_area->start_page << PAGE_SHIFT),
				phys_bank->base_addr +
					(busy_area->start_page +
						busy_area->pages_num) <<
								PAGE_SHIFT,
				prev_area->next);
		}
		prev_area->next = busy_area->next;
	}
	phys_bank->busy_areas_num--;
	/* busy area is now free, so increment number of free pages at bank */
	atomic64_add(busy_area->pages_num, &phys_bank->free_pages_num);
	busy_area->next = -1;
	busy_area->pages_num = 0;
}

/* lock should be taken by caller */
static inline short __init
boot_get_free_busy_area(int node, e2k_phys_bank_t *phys_bank)
{
	e2k_busy_mem_t	*busy_areas;
	short area;

	busy_areas = phys_bank->busy_areas;
	for (area = 0; area < E2K_MAX_PRERESERVED_AREAS; area++) {
		e2k_busy_mem_t *cur_busy_area = &busy_areas[area];

		if (cur_busy_area->pages_num == 0)
			/* found empty entry at table */
			return area;
	}
	if (phys_bank->busy_areas_num >= E2K_MAX_PRERESERVED_AREAS) {
		BOOT_WARNING("Node #%d number of busy areas %d exceeds "
			"permissible limit %d",
			node, phys_bank->busy_areas_num,
			E2K_MAX_PRERESERVED_AREAS);
		return -1;
	}
	BOOT_BUG("Node #%d number of busy areas is only %d from %d, "
		"but could not find empty entry at table",
		node, phys_bank->busy_areas_num, E2K_MAX_PRERESERVED_AREAS);
	return -1;
}

static	bool __init_recv
boot_try_merge_bank_area(int node_id, boot_phys_bank_t *phys_bank,
		e2k_busy_mem_t	*prev_busy_area,
		e2k_size_t start_page, long pages_num,
		busy_mem_type_t mem_type, unsigned short flags)
{
	if (!(flags & BOOT_MERGEABLE_ALLOC_MEM))
		return false;	/* new area is not mergeable */

	if (prev_busy_area == NULL) {
		BOOT_BUG("Node #%d new reserved area from 0x%lx to 0x%lx "
			"cannot be merged with empty previous area\n",
			node_id,
			phys_bank->base_addr + (start_page << PAGE_SHIFT),
			phys_bank->base_addr + (start_page << PAGE_SHIFT) +
				(pages_num << PAGE_SHIFT));
	}
	if (!(prev_busy_area->flags & BOOT_MERGEABLE_ALLOC_MEM))
		return false;	/* previous area is not mergeable */
	if (mem_type != prev_busy_area->type)
		return false;	/* areas with different memory type */
				/* cannot be merged */

	if (pages_num > phys_bank->pages_num - start_page)
		return false;	/* merged area cannot intersect */
				/* bank boundaries */
	if (start_page != prev_busy_area->start_page +
					prev_busy_area->pages_num) {
		BOOT_BUG("Node #%d new merged area start 0x%lx is not "
			"adjacent to the end 0x%lx of previous area\n",
			node_id,
			phys_bank->base_addr + (start_page << PAGE_SHIFT),
			phys_bank->base_addr +
				((prev_busy_area->start_page +
					prev_busy_area->pages_num) <<
								PAGE_SHIFT));
	}

	prev_busy_area->pages_num += pages_num;
	DebugAM("Node #%d new area from 0x%lx to 0x%lx was merged and "
		"total area is now from 0x%lx to 0x%lx\n",
		node_id,
		phys_bank->base_addr + (start_page << PAGE_SHIFT),
		phys_bank->base_addr + ((start_page + pages_num) << PAGE_SHIFT),
		phys_bank->base_addr +
			(prev_busy_area->start_page << PAGE_SHIFT),
		phys_bank->base_addr +
			((prev_busy_area->start_page +
				prev_busy_area->pages_num) << PAGE_SHIFT));

	return true;	/* new area is successfully merged */
}

static void __init_recv
boot_move_bank_busy_areas_part(int node_id, boot_phys_mem_t *node_mem,
		short old_bank, short new_bank,
		e2k_addr_t start_addr, e2k_addr_t end_addr,
		unsigned short flags)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *phys_bank;
	e2k_busy_mem_t *busy_area;
	short area, next_area;

	node_banks = node_mem->banks;
	phys_bank = &node_banks[old_bank];

	/* loop on busy areas of old memory bank to move them */
	/* to created new memory bank */
	for (area = phys_bank->first_area; area >= 0; area = next_area) {
		e2k_size_t start, end;

		busy_area = &phys_bank->busy_areas[area];
		if (busy_area->pages_num == 0) {
			BOOT_BUG("Node #%d old bank #%d empty physical memory "
				"busy area #%d cannot be in the list",
				node_id, old_bank, area);
		}
		start = busy_area->start_page;
		end = start + busy_area->pages_num;
		DebugRML("Node #%d old bank #%d current busy area #%d "
			"from 0x%lx to 0x%lx\n",
			node_id, old_bank, area,
			start_addr + (start << PAGE_SHIFT),
			start_addr + (end << PAGE_SHIFT));
		if (start_addr + (start << PAGE_SHIFT) >= end_addr)
			/* the area is out of moving range, so complete */
			break;
		if (start_addr + (end << PAGE_SHIFT) > end_addr) {
			BOOT_BUG("Node #%d old bank #%d busy area #%d "
				"from 0x%lx to 0x%lx is partially out of "
				"moving range from 0x%lx to 0x%lx\n",
				node_id, old_bank, area,
				start_addr + (start << PAGE_SHIFT),
				start_addr + (end << PAGE_SHIFT),
				start_addr, end_addr);
		}

		/* moving of busy area should delete it from list of areas */
		/* so save reference to next entry of the list before */
		next_area = busy_area->next;

		if (start >= phys_bank->pages_num ||
				end > phys_bank->pages_num) {
			BOOT_BUG("Node #%d old bank #%d area #%d start 0x%lx "
				"or end 0x%lx is out of bank size 0x%lx\n",
				node_id, old_bank, area, start, end,
				phys_bank->pages_num);
		}
		if ((flags & BOOT_EXCLUDE_AT_HIGH_PHYS_MEM) &&
				(busy_area->flags &
					BOOT_EXCLUDE_AT_HIGH_PHYS_MEM)) {
			BOOT_BUG("Node #%d old bank #%d area #%d flags %04x: "
				"cannot be remapped to high memory range\n",
				node_id, old_bank, area, busy_area->flags);
		}
		if ((flags & BOOT_IGNORE_AT_HIGH_PHYS_MEM) &&
				(busy_area->flags &
					BOOT_IGNORE_AT_HIGH_PHYS_MEM)) {
			DebugRML("Node #%d old bank #%d busy area #%d "
				"can not be remapped\n",
				node_id, old_bank, area);
			/* delete busy area from old memory range */
			boot_delete_busy_area(node_id, phys_bank,
				busy_area, area,
				NULL);	/* rereserved area should be at head */
					/* of old bank */
			continue;
		}

		boot_rereserve_bank_area(node_id, node_mem,
				old_bank, new_bank, area, busy_area);
	}
}

/* should return source old bank index, which can be updated while moving */
/* but now number should not be changed */
/* parameter 'delete_size' is size of additional area which should be deleted */
/* from bank memory truncated end */
static short __init_recv
boot_move_node_bank_part(int node_id, boot_phys_mem_t *node_mem, short old_bank,
		e2k_addr_t start_addr, e2k_addr_t end_addr,
		e2k_addr_t delete_size)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *old_phys_bank, *new_phys_bank;
	short new_bank, bank;

	node_banks = node_mem->banks;
	old_phys_bank = &node_banks[old_bank];

	new_bank = boot_init_new_phys_bank(node_id, node_mem,
				start_addr, end_addr - start_addr);
	if (new_bank < 0) {
		boot_printk("Node #%d: could not create new bank "
			"from 0x%lx to 0x%lx to move old bank #%d",
			node_id, start_addr, end_addr, old_bank);
		return old_bank;
	}
	new_phys_bank = &node_banks[new_bank];
	DebugRML("Node #%d: created new bank #%d from 0x%lx to 0x%lx "
		"to remap old bank #%d\n",
		node_id, new_bank, start_addr, end_addr, old_bank);

	boot_move_bank_busy_areas_part(node_id, node_mem, old_bank, new_bank,
			start_addr, end_addr, 0);

	/* now old bank (or part of bank) can be deleted */
	bank = boot_delete_phys_bank_part(node_id, node_mem,
			old_bank, old_phys_bank, start_addr,
			end_addr + delete_size);

	boot_add_new_phys_bank(node_id, node_mem, new_phys_bank, new_bank);

	return bank;
}

static long __init_recv
boot_delete_bank_area(int node_id, boot_phys_mem_t *node_mem,
		short bank, boot_phys_bank_t *phys_bank,
		e2k_addr_t area_start, e2k_size_t area_pages)
{
	e2k_addr_t bank_start, bank_end, new_end;
	e2k_addr_t area_end;
	e2k_size_t area_size;
	short new_bank;

	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	area_size = (area_pages << PAGE_SHIFT);
	area_end = area_start + area_size;

	DebugDEL("Node #%d bank #%d from 0x%lx to 0x%lx, should delete "
		"memory area from 0x%lx to 0x%lx\n",
		node_id, bank, bank_start, bank_end, area_start, area_end);

	new_end = area_start;
	if (new_end > bank_start) {
		new_bank = boot_move_node_bank_part(node_id, node_mem,
					bank, bank_start, new_end, area_size);
	} else if (new_end == bank_start) {
		/* deleted area from start of bank, truncate bank */
		new_bank = boot_delete_phys_bank_part(node_id, node_mem,
				bank, phys_bank, bank_start, area_size);
	} else {
		BOOT_BUG("Node #%d bank #%d from 0x%lx to 0x%lx does not "
			"contain memory area to delete from 0x%lx\n",
			node_id, bank, bank_start, bank_end, new_end);
	}
	if (new_bank < 0) {
		/* deleted area was right in the end of bank */
		/* the old bank was deleted and fully moved to new */
		DebugDEL("Node #%d bank #%d area from 0x%lx to 0x%lx "
			"was deleted from end, new bank end 0x%lx\n",
			node_id, bank, bank_start, bank_end, new_end);
		return area_pages;
	}
	if (new_bank != bank) {
		BOOT_BUG("Node #%d old bank #%d cannot be changed, but "
			"after partially moveing to high range "
			"the bank index is updated to #%d",
			node_id, bank, new_bank);
	}
	/* source bank can be updated after moveing of part */
	/* of the old bank, so recalculate its parameters */
	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	if (bank_start != area_end) {
		BOOT_BUG("Node #%d bank #%d new base address 0x%lx should "
			"start from end of deleted area 0x%lx",
			node_id, bank, bank_start, area_end);
	}

	DebugDEL("Node #%d bank #%d new base from 0x%lx to 0x%lx "
		"after delete area from 0x%lx to 0x%lx\n",
		node_id, bank, bank_start, bank_end, area_start, area_end);

	return area_pages;
}

/*
 * Reserve the physical memory area in the bank.
 * This pages od area mark as unallocatable.
 * The function returns the number of reserved pages in the bank
 * or negative number of reserved pages, if any reserved page is already
 * occupied.
 */
static long __init_recv
boot_reserve_bank_area(int node_id, boot_phys_mem_t *node_mem,
		short bank, boot_phys_bank_t *phys_bank,
		e2k_size_t start_page, long pages_num,
		busy_mem_type_t mem_type, unsigned short flags)
{
	e2k_busy_mem_t	*busy_area;
	e2k_busy_mem_t	*prev_busy_area;
	e2k_addr_t	start_addr;
	e2k_size_t	end_page;
	long		pages;
	short		area;
	bool		busy_flag;
	bool		area_changed;
	bool		mergeable;

	DebugBank("boot_reserve_bank_area() started: start page # 0x%lx "
		"number of pages 0x%lx\n",
		start_page, pages_num);

	start_addr = phys_bank->base_addr +  (start_page << PAGE_SHIFT);
	pages = phys_bank->pages_num - start_page;
	if (pages_num < pages)
		pages = pages_num;
	end_page = start_page + pages;

	if ((flags & BOOT_IGNORE_AT_HIGH_PHYS_MEM) &&
				!phys_bank->maybe_remapped_to_hi)
		flags |= BOOT_DELETE_PHYS_MEM;
	if (flags & BOOT_DELETE_PHYS_MEM) {
		DebugBank("Node #%d bank #%d: will delete area from "
			"base 0x%lx to end 0x%lx\n",
			node_id, bank, start_addr,
			start_addr + ((end_page - start_page) << PAGE_SHIFT));
	} else {
		DebugBank("Node #%d bank #%d: will reserve area from "
			"base 0x%lx to end 0x%lx\n",
			node_id, bank, start_addr,
			start_addr + ((end_page - start_page) << PAGE_SHIFT));
	}

again:
	busy_flag = false;
	area_changed = false;
	mergeable = false;
	prev_busy_area = NULL;

	for (area = phys_bank->first_area;
		area >= 0;
			prev_busy_area = busy_area, area = busy_area->next) {
		busy_area = &phys_bank->busy_areas[area];

		if (busy_area->pages_num == 0) {
			BOOT_BUG("Node #%d empty physical memory busy area #%d "
				"cannot be in the list",
				node_id, area);
			continue;
		}
		if (start_page > busy_area->start_page + busy_area->pages_num)
			continue;
		if (start_page == busy_area->start_page +
						busy_area->pages_num) {
			/* new area should be added after current busy area, */
			/* but can be intersections with next area,  */
			/* so it need consider this case */
			mergeable = true; /* can be merged with current */
			continue;
		}
		if (end_page < busy_area->start_page)
			/* cannot be intersections with residuary areas */
			/* at the tail, need add as new area after previous */
			break;
		if (end_page == busy_area->start_page)
			/* cannot be other intersections with residuary areas */
			/* at the tail, need add as new area after previous */
			break;
		mergeable = false; /* there is intersections */
		if (!(flags & BOOT_IGNORE_BUSY_BANK)) {
			BOOT_WARNING("The area from 0x%lx to 0x%lx or some "
				"its part is reserved twice",
				start_addr, start_addr + pages * PAGE_SIZE);
			busy_flag = true;
		}
		if (flags & BOOT_DELETE_PHYS_MEM) {
			/* area should be deleted and cannot intersect other */
			BOOT_BUG("Deleted area from 0x%lx to 0x%lx or some "
				"its part intersects other busy area(s)",
				start_addr, start_addr + pages * PAGE_SIZE);
			break;
		}
		if (!(busy_area->flags &  BOOT_CAN_BE_INTERSECTIONS)) {
			BOOT_WARNING("The area from 0x%lx to 0x%lx "
				"intersects with area from 0x%lx to 0x%lx "
				"CANNOT INTERSECT",
				start_addr, start_addr + pages * PAGE_SIZE,
				busy_area->start_page << PAGE_SHIFT,
				(busy_area->start_page +
					busy_area->pages_num) << PAGE_SHIFT);
			flags &= ~BOOT_CAN_BE_INTERSECTIONS;
		}
		if ((busy_area->flags & BOOT_ONLY_LOW_PHYS_MEM) !=
					(flags & BOOT_ONLY_LOW_PHYS_MEM)) {
			BOOT_WARNING("The area from 0x%lx to 0x%lx %s "
				"intersects with area from 0x%lx to 0x%lx %s",
				start_addr, start_addr + pages * PAGE_SIZE,
				(flags & BOOT_ONLY_LOW_PHYS_MEM) ?
					"ONLY LOW MEM" : "ANY MEM",
				busy_area->start_page << PAGE_SHIFT,
				(busy_area->start_page +
					busy_area->pages_num) << PAGE_SHIFT,
				(busy_area->flags & BOOT_ONLY_LOW_PHYS_MEM) ?
					"ONLY LOW MEM" : "ANY MEM");
			flags |= BOOT_ONLY_LOW_PHYS_MEM;
		}
		if ((busy_area->flags & BOOT_IGNORE_AT_HIGH_PHYS_MEM) !=
				(flags & BOOT_IGNORE_AT_HIGH_PHYS_MEM)) {
			BOOT_WARNING("The area from 0x%lx to 0x%lx %s "
				"intersects with area from 0x%lx to 0x%lx %s",
				start_addr, start_addr + pages * PAGE_SIZE,
				(flags & BOOT_IGNORE_AT_HIGH_PHYS_MEM) ?
					"NEED NOT REMAP TO HIGH MEM" :
						"CAN REMAP TO HIGH MEM",
				busy_area->start_page << PAGE_SHIFT,
				(busy_area->start_page +
					busy_area->pages_num) << PAGE_SHIFT,
				(busy_area->flags &
						BOOT_IGNORE_AT_HIGH_PHYS_MEM) ?
					"NEED NOT REMAP TO HIGH MEM" :
						"CAN REMAP TO HIGH MEM");
			flags |= BOOT_IGNORE_AT_HIGH_PHYS_MEM;
		}
		if (mem_type != busy_area->type) {
			BOOT_WARNING("The area from 0x%lx to 0x%lx type %d "
				"intersects with area from 0x%lx to 0x%lx "
				"type %d",
				start_addr, start_addr + pages * PAGE_SIZE,
				mem_type,
				busy_area->start_page << PAGE_SHIFT,
				(busy_area->start_page +
					busy_area->pages_num) << PAGE_SHIFT,
				busy_area->type);
			/* keep memory type of source busy area */
			mem_type = busy_area->type;
		}
		if (start_page < busy_area->start_page) {
			DebugBank("The reserved area #%d start page will be "
				"moved from 0x%lx to 0x%lx\n",
				area, busy_area->start_page, start_page);
			busy_area->pages_num += (busy_area->start_page -
								start_page);
			busy_area->start_page = start_page;
			DebugBank("The reserved area #%d new size is "
				"0x%lx pages\n",
				area, busy_area->pages_num);
			area_changed = true;
		}
		if (end_page > busy_area->start_page + busy_area->pages_num) {
			DebugBank("The reserved area #%d finish page will be "
				"moved from 0x%lx to 0x%lx\n",
				area,
				busy_area->start_page + busy_area->pages_num,
				end_page);
			busy_area->pages_num += (end_page -
						(busy_area->start_page +
							busy_area->pages_num));
			DebugBank("The reserved area new size is "
				"0x%lx pages\n",
				busy_area->pages_num);
			area_changed = true;
		}
		if (area_changed) {
			start_page = busy_area->start_page;
			pages_num = busy_area->pages_num;
			boot_delete_busy_area(node_id, phys_bank,
					busy_area, area, prev_busy_area);
			DebugBank("The reserved area #%d will be deleted as it"
				" is included into new area from 0x%lx page"
				" and size 0x%lx\n",
				area, start_page, pages_num);
			goto again;
		} else {
			/* probably area memory type or flags were changed, */
			/* update its */
			busy_area->type = mem_type;
			busy_area->flags = flags;
			DebugBank("The area from addr 0x%lx to addr 0x%lx "
				"is included into the area #%d\n",
				start_addr, start_addr + pages * PAGE_SIZE,
				area);
		}
		return (busy_flag) ? (long)-pages : (long)pages;
	}
	if (flags & BOOT_DELETE_PHYS_MEM) {
		return boot_delete_bank_area(node_id, node_mem,
				bank, phys_bank, start_addr, pages);
	}
	if (mergeable) {
		/* probably new area can be merged with previous */
		if (boot_try_merge_bank_area(node_id, phys_bank, prev_busy_area,
				start_page, pages, mem_type, flags))
			/* yes, area has been merged */
			return pages;
	}
	area = boot_get_free_busy_area(node_id, phys_bank);
	if (unlikely(area < 0)) {
		BOOT_BUG("Node #%d: cannot prereserve busy area from 0x%lx "
			"to 0x%lx, no empty entries in the tabale",
			node_id, start_addr, start_addr + pages * PAGE_SIZE);
		return 0;
	}
	busy_area = &phys_bank->busy_areas[area];
	busy_area->start_page = start_page;
	busy_area->pages_num = pages;
	busy_area->type = mem_type;
	busy_area->flags = flags;
	if (prev_busy_area == NULL) {
		/* add new area to head of the list */
		busy_area->next = phys_bank->first_area;
		phys_bank->first_area = area;
	} else {
		/* add new area after previous at the list */
		busy_area->next = prev_busy_area->next;
		prev_busy_area->next = area;
	}
	phys_bank->busy_areas_num++;
	DebugBank("The node #%d new reserved area #%d from 0x%lx to 0x%lx "
		"was added to the list of occupied areas\n",
		node_id, area,
		start_addr, start_addr + pages * PAGE_SIZE);

	return (busy_flag) ? (long)-pages : (long)pages;
}

/*
 * Reserve the physical memory pages of the bank.
 * This pages mark as unallocatable.
 * The function returns the number of reserved pages in the bank
 * or negative number of reserved pages, if any reserved page is already
 * occupied.
 */
static long __init_recv
boot_reserve_bank_physmem(int node_id, boot_phys_mem_t *node_mem,
		short bank, boot_phys_bank_t *phys_bank,
		e2k_addr_t phys_addr, long pages_num,
		busy_mem_type_t mem_type, unsigned short flags)
{
	e2k_size_t	start_page, end_page;
	long		pages;

	DebugBank("boot_reserve_bank_physmem() started for addr 0x%lx and "
		"page(s) 0x%lx\n",
		phys_addr, pages_num);
	if (phys_addr < phys_bank->base_addr ||
		phys_addr >= phys_bank->base_addr +
				phys_bank->pages_num * PAGE_SIZE) {
		BOOT_BUG("The address 0x%lx is not in the range of "
			"the physical memory bank addresses 0x%lx : 0x%lx",
			phys_addr, phys_bank->base_addr,
			phys_bank->base_addr +
				phys_bank->pages_num * PAGE_SIZE);
	}
	start_page = (phys_addr - phys_bank->base_addr) / PAGE_SIZE;
	end_page = start_page + pages_num;
	if (end_page > phys_bank->pages_num) {
		end_page = phys_bank->pages_num;
		pages_num = end_page - start_page;
	}
	DebugBank("boot_reserve_bank_physmem() start pages from 0x%lx "
		"to 0x%lx, number 0x%lx\n",
		start_page, end_page, pages_num);
	pages = boot_reserve_bank_area(node_id, node_mem, bank, phys_bank,
			start_page, pages_num, mem_type, flags);
	DebugBank("boot_reserve_bank_physmem() reserved 0x%lx page(s) "
		"in the bank\n",
		pages);
	if (pages <= 0)
		return pages;

	atomic64_sub(pages, &phys_bank->free_pages_num);
	return pages;
}

/*
 * Find a bank including the physical address.
 * Function returns the physical pointer of the bank description structure or
 * NULL, if memory bank did not found.
 */
static	boot_phys_bank_t * __init_recv
boot_find_bank_of_addr(e2k_addr_t phys_addr, int *node_id, short *bank_index)
{
	boot_phys_mem_t	*all_nodes_mem = NULL;
	int		nodes_num;
	int		cur_nodes_num = 0;
	int		node;
	int		bank;

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		node_phys_mem_t *node_mem = &all_nodes_mem[node];
		boot_phys_bank_t *node_banks;
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		node_banks = node_mem->banks;
		cur_nodes_num++;
		boot_the_node_spin_lock(node, boot_phys_mem_lock);
		for (bank = node_mem->first_bank;
				bank >= 0;
					bank = phys_bank->next) {

			phys_bank = &node_banks[bank];
			if (phys_bank->pages_num == 0) {
				/* bank in the list has not pages */
				boot_the_node_spin_unlock(node,
						boot_phys_mem_lock);
				BOOT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);
			}
			if (phys_addr >= phys_bank->base_addr &&
				phys_addr < phys_bank->base_addr +
					phys_bank->pages_num * PAGE_SIZE) {
				if (bank_index != NULL)
					*bank_index = bank;
				if (node_id != NULL)
					*node_id = node;
				boot_the_node_spin_unlock(node,
						boot_phys_mem_lock);
				return phys_bank;
			}
		}
		boot_the_node_spin_unlock(node, boot_phys_mem_lock);
	}
	if (bank_index != NULL)
		*bank_index = -1;
	if (node_id != NULL)
		*node_id = -1;
	return (boot_phys_bank_t *)NULL;
}

/*
 * Reserve/delete a particular physical memory range. This range marks as
 * unallocatable.
 * Usable RAM might be used for boot-time allocations -
 * or it might get added to the free page pool later on.
 * The function returns 0 on reservation success and 1, if all or some part
 * of reserved memory range is already occupied and 'ignore_busy' is not set.
 */

void __init_recv boot_reserve_physmem(const char *name,
		e2k_addr_t virt_phys_addr, e2k_size_t mem_size,
		busy_mem_type_t mem_type, unsigned short flags)
{
	e2k_addr_t	phys_addr;
	e2k_addr_t	base_addr;
	e2k_addr_t	end_addr;
	boot_phys_mem_t	*all_nodes_mem = NULL;
	boot_phys_bank_t *phys_bank = NULL;
	long		pages_num;
	long		bank_pages_num;
	int		error_flag = 0;

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	phys_addr = boot_vpa_to_pa(virt_phys_addr);
	end_addr = phys_addr + mem_size;
	DebugBank("boot_reserve_physmem() started: mem addr 0x%lx  size 0x%lx\n",
		phys_addr, mem_size);
	if (mem_size == 0)
		BOOT_BUG("Reserved memory area size %ld is empty", mem_size);

	/*
	 * Round up according to PAGE_SIZE, partially reserved pages are
	 * considered fully reserved.
	 */

	base_addr = round_down(phys_addr, PAGE_SIZE);
	end_addr = round_up(end_addr, PAGE_SIZE);
	pages_num = (end_addr - base_addr) >> PAGE_SHIFT;

	/*
	 * The memory range can occupy a few contiguous physical banks.
	 * The pages bits set in all of these banks
	 */
	while (pages_num > 0) {
		node_phys_mem_t *node_mem;
		int node_id;
		short bank;

		phys_bank = boot_find_bank_of_addr(base_addr, &node_id, &bank);
		if (phys_bank == NULL) {
			DebugBank("boot_reserve_physmem() bank including "
				"address 0x%lx was not found\n",
				base_addr);
			if (flags & BOOT_IGNORE_BANK_NOT_FOUND)
				return;
			/* Some guest areas can be allocated by QEMU/host */
			/* into special address space to emulate hardware */
			if (!boot_paravirt_enabled()) {
				BOOT_BUG("Could not find the physical memory "
					"bank including reserved address 0x%lx",
					base_addr);
			}
			base_addr += PAGE_SIZE;
			pages_num -= 1;
			DebugBank("boot_reserve_physmem go to the next "
				"page of reserved area with address 0x%lx",
				base_addr);
			continue;
		}
		node_mem = &all_nodes_mem[node_id];
		boot_the_node_spin_lock(node_id, boot_phys_mem_lock);
		bank_pages_num = boot_reserve_bank_physmem(node_id, node_mem,
					bank, phys_bank,
					base_addr, pages_num,
					mem_type, flags);
		boot_the_node_spin_unlock(node_id, boot_phys_mem_lock);
		DebugBank("boot_reserve_physmem() "
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
		base_addr += (bank_pages_num << PAGE_SHIFT);
	}

	BOOT_BUG_ON(error_flag, "Could not reserve '%s' area: base addr 0x%lx size 0x%lx",
			name, virt_phys_addr, mem_size);

	boot_printk("The kernel '%s' segment:  base 0x%lx size 0x%lx\n",
			name, virt_phys_addr, mem_size);
}

void __init_recv boot_delete_physmem(const char *name,
		e2k_addr_t virt_phys_addr, e2k_size_t mem_size)
{
	unsigned short flags;

	if (BOOT_LOW_MEMORY_ENABLED()) {
		/* the area should be deleted really */
		flags = BOOT_DELETE_PHYS_MEM |
				BOOT_NOT_IGNORE_BUSY_BANK |
				BOOT_IGNORE_BANK_NOT_FOUND;
	} else {
		/* the area will be deleted while low memory will be remmaped */
		/* to high, where hardware does not strip out any areas */
		flags = BOOT_ONLY_LOW_PHYS_MEM |
				BOOT_IGNORE_AT_HIGH_PHYS_MEM |
				BOOT_NOT_IGNORE_BUSY_BANK |
				BOOT_IGNORE_BANK_NOT_FOUND;
	}
	boot_reserve_physmem(name, virt_phys_addr, mem_size,
			hw_stripped_mem_type, flags);
}

void __init_recv boot_rereserve_bank_area(int node_id,
			boot_phys_mem_t *node_mem, short bank,
			short new_bank, short area, e2k_busy_mem_t *busy_area)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *phys_bank, *new_phys_bank;
	long pages;

	node_banks = node_mem->banks;
	phys_bank = &node_banks[bank];
	new_phys_bank = &node_banks[new_bank];

	/* copy busy area from low bank to high memory range */
	pages = boot_reserve_bank_area(node_id, node_mem,
			new_bank, new_phys_bank,
			busy_area->start_page, busy_area->pages_num,
			busy_area->type, busy_area->flags);
	if (pages != busy_area->pages_num) {
		BOOT_BUG("Node #%d bank #%d: could not rereserve area #%d "
			"from 0x%lx 0x%lx pages at new bank #%d\n",
			node_id, bank, area,
			busy_area->start_page, busy_area->pages_num,
			new_bank);
	}

	/* delete busy area from low memory range */
	boot_delete_busy_area(node_id, phys_bank, busy_area, area,
		NULL);	/* rereserved area should be at head of low bank */
}

/*
 * Need try use only high memory range addresses of physical memory
 * But in some case it is better to do it dinamicaly, so there is boot-time
 * parameter to force enabling of low memory range
 */
#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM
bool low_memory_enabled = LOW_MEMORY_ENABLED_DEFAULT;
#endif

static int __init boot_low_memory_setup(char *cmd)
{
	if (!BOOT_NATIVE_IS_MACHINE_E1CP)
		BOOT_SET_LOW_MEMORY_DISABLED();
	return 0;
}
boot_param("lowmem_disable", boot_low_memory_setup);

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM

/*
 * IOMMU on/off setup
 *
 * Based on l_iommu_setup() from arch/l/kernel/iommu.c to determine
 * 'Will be IOMMMU turned ON or OFF' on early stage and need or not reserve
 * DMA bounce buffers while boot-time initialization.
 * Real option parsing will be done by common function l_iommu_setup()
 */
static bool iommu_win_supported = true;
#define boot_iommu_win_supported	boot_get_vo_value(iommu_win_supported)

static int __init boot_iommu_win_setup(char *cmd)
{
	if (!boot_strcmp(cmd, "noprefetch")) {
		/* unused while boot-time */
		return 2;
	} else {
		e2k_size_t iommu_win_size = boot_simple_strtoul(cmd, &cmd, 0);

		if (*cmd == 'K' || *cmd == 'k')
			iommu_win_size <<= 10;
		else if (*cmd == 'M' || *cmd == 'm')
			iommu_win_size <<= 20;

		iommu_win_size &= ~PAGE_MASK;

		if (iommu_win_size == 0) {
			boot_iommu_win_supported = false;
			boot_printk("IOMMU will be turned OFF\n");
		} else {
			boot_iommu_win_supported = true;
			boot_printk("IOMMU window limit set to 0x%lx\n",
				iommu_win_size);
		}
	}
	return 2;
}
boot_param("iommu", boot_iommu_win_setup);

static void __init
boot_reserve_dma_low_memory(boot_info_t *boot_info)
{
	static __initdata BOOT_DEFINE_NODE_LOCK(low_mem_reserved_lock);
	e2k_size_t area_size;
	e2k_size_t min_size;
	e2k_size_t max_size;
	e2k_size_t large_page_size;
	void *dma_low_mem = NULL;

	/* reserve DMA bounce buffers, if it need */
	if (boot_l_iommu_supported() && boot_iommu_win_supported &&
			!boot_cpu_has(CPU_HWBUG_IOMMU))
		/* IOMMU will be ON, nothing DMA bounce buffers need */
		return;

	/* IOMMU cannot be used, DMA bounce buffers will be need */
	if (!boot_has_node_low_memory(boot_numa_node_id(), boot_info)) {
		BOOT_WARNING("Node has not low memory to reserve "
			"DMA bounce buffers area");
		return;
	}

	if (boot_node_lock(&low_mem_reserved_lock)) {
		DebugNUMA("boot_reserve_dma_low_memory() DMA bounce buffers "
			"was already reserved on node\n");
		return;
	}

	large_page_size = BOOT_E2K_LARGE_PAGE_SIZE;
	area_size = L_SWIOTLB_DEFAULT_SIZE;
	min_size = L_SWIOTLB_MIN_SIZE;
	area_size = ALIGN_TO_MASK(area_size, large_page_size);
	min_size = ALIGN_TO_MASK(min_size, large_page_size);
	max_size = area_size;
	while (area_size >= min_size) {
		dma_low_mem = boot_node_try_alloc_low_mem(area_size,
					large_page_size, large_page_size,
					dma32_mem_type);
		if (dma_low_mem != (void *)-1)
			break;
		area_size = area_size >> 1;
	}
	if (dma_low_mem == (void *)-1) {
		BOOT_WARNING("Could not allocate low memory to reserve "
			"DMA bounce buffers area");
	} else if (area_size < max_size) {
		BOOT_WARNING("Could allocate only 0x%lx Mb from 0x%lx Mb of "
			"low memory to reserve DMA bounce buffers area",
			area_size >> 20, max_size >> 20);
	} else {
		DebugMAP("Allocated 0x%lx Mb of low memory from 0x%lx "
			"to reserve DMA bounce buffers area\n",
			area_size >> 20, (e2k_addr_t)dma_low_mem);
	}

	boot_node_unlock(&low_mem_reserved_lock);
}

static void __init
boot_reserve_netdev_dma_memory(bool bsp, boot_info_t *boot_info)
{
	e2k_size_t area_size;
	e2k_size_t large_page_size;
	void *netdev_low_mem = NULL;

	/* FIXME TODO: drivers of l_e1000 & sunlance ethernet cards need */
	/* direct allocation DMA low memory */

	if (!BOOT_IS_BSP(bsp))
		return;

	if (!boot_has_node_low_memory(boot_numa_node_id(), boot_info)) {
		BOOT_WARNING("Node has not low memory to reserve "
			"DMA memory for ethernet l_e1000 & sunlance "
			"net devices");
		return;
	}

	large_page_size = BOOT_E2K_LARGE_PAGE_SIZE;
	area_size = 1 * large_page_size;	/* one huge page */
	netdev_low_mem = boot_node_try_alloc_low_mem(area_size,
					large_page_size, large_page_size,
					dma32_mem_type);
	if (netdev_low_mem == (void *)-1) {
		BOOT_WARNING("Could not allocate low memory to reserve "
			"DMA net devices structures");
	} else {
		DebugMAP("Allocated 0x%lx Mb of low memory from 0x%lx "
			"to reserve DMA net devices structures\n",
			area_size >> 20, (e2k_addr_t)netdev_low_mem);
	}
}

/*
 * In some cases memory areas should be allocated only at low addresses
 * range (below 2**32). For example DMA bounce buffers.
 * All such areas should be preliminarily reserved here while boot-time
 * initialization and will be realised while bootmem registration and freeing.
 */
static void __init
boot_reserve_low_memory(bool bsp, boot_info_t *boot_info)
{
	/* reserve DMA bounce buffers, if it need */
	boot_reserve_dma_low_memory(boot_info);

	/* FIXME TODO: reserve for DMA net devices structures */
	boot_reserve_netdev_dma_memory(bsp, boot_info);
}

/* should return source low bank index, which can be updated while remapping */
/* but now number should not be changed */
static short __init
boot_remap_node_low_bank_area(boot_info_t *boot_info, int node_id,
		boot_phys_mem_t *node_mem, short lo_bank,
		e2k_addr_t start_lo_addr, e2k_addr_t end_lo_addr)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *lo_phys_bank, *hi_phys_bank;
	e2k_addr_t start_hi_addr, end_hi_addr;
	short hi_bank, new_bank;

	node_banks = node_mem->banks;
	lo_phys_bank = &node_banks[lo_bank];

	start_hi_addr = (e2k_addr_t)boot_pa_to_high_pa((void *)start_lo_addr,
							boot_info);
	end_hi_addr = (e2k_addr_t)boot_pa_end_to_high((void *)end_lo_addr,
							boot_info);
	if (start_hi_addr == start_lo_addr || end_hi_addr == end_lo_addr) {
		if (boot_has_node_high_memory(node_id, boot_info)) {
			BOOT_WARNING("Could not convert addresses of low bank "
				"from 0x%lx to 0x%lx to remap to high memory "
				"range",
				start_hi_addr, end_hi_addr);
		}
		return lo_bank;
	}
	hi_bank = boot_init_new_phys_bank(node_id, node_mem,
				start_hi_addr, end_hi_addr - start_hi_addr);
	if (hi_bank < 0) {
		boot_printk("Node #%d: could not create high bank "
			"from 0x%lx to 0x%lx to remap low bank #%d",
			node_id, start_hi_addr, end_hi_addr, lo_bank);
		return lo_bank;
	}
	hi_phys_bank = &node_banks[hi_bank];
	DebugRML("Node #%d: created high bank #%d from 0x%lx to 0x%lx "
		"to remap low bank #%d\n",
		node_id, hi_bank, start_hi_addr, end_hi_addr, lo_bank);

	boot_move_bank_busy_areas_part(node_id, node_mem, lo_bank, hi_bank,
			start_lo_addr, end_lo_addr,
			BOOT_EXCLUDE_AT_HIGH_PHYS_MEM |
				BOOT_IGNORE_AT_HIGH_PHYS_MEM);

	/* now low bank (or part of bank) can be deleted */
	new_bank = boot_delete_phys_bank_part(node_id, node_mem,
			lo_bank, lo_phys_bank, start_lo_addr, end_lo_addr);

	boot_add_new_phys_bank(node_id, node_mem, hi_phys_bank, hi_bank);

	return new_bank;
}

/* should return source low bank index, which can be updated while remapping */
/* but now number should not be changed */
static short __init
boot_unremap_node_low_bank_area(int node_id, boot_phys_mem_t *node_mem,
		short bank, boot_phys_bank_t *phys_bank)
{
	e2k_busy_mem_t *busy_area;
	e2k_addr_t bank_start, bank_end;
	e2k_addr_t start_addr, end_addr;
	e2k_addr_t prev_area_end;
	short area;

	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	start_addr = -1;
	end_addr = start_addr;
	prev_area_end = -1;
	for (area = phys_bank->first_area; area >= 0; area = busy_area->next) {
		e2k_size_t area_start, area_end;

		/* loop on busy areas to find max bank contigous area */
		/* which cannot be remapped as high bank of memory */
		busy_area = &phys_bank->busy_areas[area];
		if (busy_area->pages_num == 0) {
			BOOT_BUG("Node #%d bank #%d empty physical memory "
				"busy area #%d cannot be in the list",
				node_id, bank, area);
			break;
		}
		area_start = busy_area->start_page;
		area_end = area_start + busy_area->pages_num;
		DebugRML("Node #%d bank #%d current busy area #%d "
			"from 0x%lx to 0x%lx\n",
			node_id, bank, area,
			bank_start + (area_start << PAGE_SHIFT),
			bank_start + (area_end << PAGE_SHIFT));
		if (area_start >= phys_bank->pages_num ||
				area_end > phys_bank->pages_num) {
			BOOT_BUG("Node #%d low bank #%d area #%d from 0x%lx "
				"to 0x%lx is out of bank from 0x%lx to 0x%lx\n",
				node_id, bank, area,
				bank_start + (area_start << PAGE_SHIFT),
				bank_start + (area_end << PAGE_SHIFT),
				bank_start, bank_end);
		}
		if (prev_area_end == -1) {
			prev_area_end = area_end;
		} else if (area_start != prev_area_end) {
			/* continuity is broken */
			DebugRML("Node #%d bank #%d area #%d continuity is "
				"broken: area start 0x%lx is not previous "
				"area end 0x%lx\n",
				node_id, bank, area,
				bank_start + (area_start << PAGE_SHIFT),
				bank_start + (prev_area_end << PAGE_SHIFT));
			break;
		}
		if (!(busy_area->flags & BOOT_EXCLUDE_AT_HIGH_PHYS_MEM))
			/* area can be remapped to high range */
			/* so it is end of areas which cannot be remapped */
			break;

		/* it is area which cannot be remapped, so account it */
		if (start_addr == -1)
			start_addr = bank_start + (area_start << PAGE_SHIFT);
		end_addr = bank_start + (area_end << PAGE_SHIFT);
		prev_area_end = area_end;
	}
	if (start_addr == -1 || start_addr == end_addr) {
		DebugRML("Node #%d low bank #%d : could not find any not "
			"remapped area\n",
			node_id, bank);
		return bank;
	}
	if (start_addr != bank_start) {
		BOOT_BUG("Node #%d low bank #%d not remapped areas starts "
			"from 0x%lx, but should starts from bank base 0x%lx\n",
			node_id, bank, start_addr, bank_start);
	}

	DebugRML("Node #%d bank #%d will create new bank "
		"from 0x%lx to 0x%lx\n",
		node_id, bank, start_addr, end_addr);
	return boot_create_phys_bank_part(node_id, node_mem,
				bank, phys_bank, start_addr, end_addr);
}

/* should return source low bank index, which can be updated while remapping */
/* but now number should not be changed */
static short __init
boot_remap_node_low_bank_mem(boot_info_t *boot_info, int node_id,
				short bank, boot_phys_mem_t *node_mem)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *phys_bank;
	e2k_busy_mem_t *busy_area;
	e2k_addr_t bank_start, bank_end;
	e2k_addr_t start_addr, end_addr;
	short new_bank;
	short area, next_area;

	node_banks = node_mem->banks;
	phys_bank = &node_banks[bank];

	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	start_addr = bank_start;
	end_addr = start_addr;
	for (area = phys_bank->first_area; area >= 0; area = next_area) {
		e2k_size_t area_start, area_end;

		/* loop on busy areas to find max bank contigous area */
		/* which can be remapped as high bank of memory */
		busy_area = &phys_bank->busy_areas[area];
		if (busy_area->pages_num == 0) {
			BOOT_BUG("Node #%d bank #%d empty physical memory "
				"busy area #%d cannot be in the list",
				node_id, bank, area);
			continue;
		}
		area_start = busy_area->start_page;
		area_end = area_start + busy_area->pages_num;
		DebugRML("Node #%d bank #%d current busy area #%d "
			"from 0x%lx to 0x%lx\n",
			node_id, bank, area,
			bank_start + (area_start << PAGE_SHIFT),
			bank_start + (area_end << PAGE_SHIFT));
		next_area = busy_area->next;
		if (!(busy_area->flags & BOOT_EXCLUDE_AT_HIGH_PHYS_MEM))
			/* area can be remapped to high range */
			/* so continue loop and search end of max area */
			continue;
		if (!phys_bank->maybe_remapped_to_hi)
			/* area cannot be remapped to high range, but */
			/* high range to remap is absent, so area should */
			/* stay at low bank */
			continue;

		/* found low busy area which cannot be remapped to high */
		/* so its start is end of current max bank contigous area */
		DebugRML("Node #%d bank #%d area #%d need not be remapped "
			"to high\n",
			node_id, bank, area);
		end_addr = bank_start + (area_start << PAGE_SHIFT);
		if (end_addr > start_addr) {
			new_bank = boot_remap_node_low_bank_area(boot_info,
					node_id, node_mem,
					bank, start_addr, end_addr);
			if (new_bank != bank) {
				BOOT_BUG("Node #%d low bank #%d cannot be "
					"changed, but after partially "
					"remapping to high range the bank "
					"index is updated to #%d\n",
					node_id, bank, new_bank);
			}
			/* source bank can be updated after remapping of part */
			/* of the low bank, so recalculate its parameters */
			bank_start = phys_bank->base_addr;
			bank_end = bank_start +
					(phys_bank->pages_num << PAGE_SHIFT);
		}
		/* now bank starts from area which cannot be remapped */
		/* from low memory to high, create new bank for such areas */
		new_bank = boot_unremap_node_low_bank_area(node_id,
						node_mem, bank, phys_bank);
		if (new_bank < 0)
			/* uremapped areas were right in the end of bank */
			/* the bank was deleted, so bank fully remapped */
			return new_bank;
		if (new_bank != bank) {
			BOOT_BUG("Node #%d low bank #%d cannot be changed, "
				"but after creation of unremapping bank "
				"the bank index is updated to #%d\n",
				node_id, bank, new_bank);
		}
		/* source bank can be updated after creation of unremapping */
		/* the low bank, so recalculate its parameters */
		bank_start = phys_bank->base_addr;
		bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
		next_area = phys_bank->first_area;
		start_addr = bank_start;
		end_addr = start_addr;
	}
	if (start_addr >= bank_end)
		/* nothing pages at the end of bank */
		return bank;
	end_addr = bank_end;
	DebugRML("Node #%d bank #%d free area from 0x%lx to 0x%lx "
		"at the end of bank\n",
		node_id, bank, start_addr, end_addr);
	new_bank = boot_remap_node_low_bank_area(boot_info, node_id,
				node_mem, bank, start_addr, end_addr);
	if (new_bank >= 0) {
		if (boot_has_node_high_memory(node_id, boot_info)) {
			BOOT_WARNING("Node #%d low bank #%d should be deleted, "
				"but after full remapping to high range "
				"bank there is #%d\n",
				node_id, bank, new_bank);
		}
	}
	return new_bank;
}
static void __init
boot_remap_node_low_memory(boot_info_t *boot_info, int node_id,
				boot_phys_mem_t *node_mem)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *phys_bank;
	short bank, next_bank, new_bank;

	boot_the_node_spin_lock(node_id, boot_phys_mem_lock);
	node_banks = node_mem->banks;
	for (bank = node_mem->first_bank; bank >= 0; bank = next_bank) {
		e2k_addr_t bank_start;

		phys_bank = &node_banks[bank];
		if (phys_bank->pages_num == 0) {
			/* bank in the list has not pages */
			BOOT_BUG("Node #%d bank #%d at the list has not "
				"memory pages",
				node_id, bank);
			break;
		}
		bank_start = phys_bank->base_addr;
		if (is_addr_from_high_memory(bank_start))
			/* bank is from high memory, no more banks from low */
			break;
		DebugRMLT("Node #%d bank #%d from 0x%lx to 0x%lx will be "
			"remapped to high memory\n",
			node_id, bank, bank_start,
			bank_start + (phys_bank->pages_num << PAGE_SHIFT));

		/* the bank can be deleted, so remember next bank # */
		next_bank = phys_bank->next;
		new_bank = boot_remap_node_low_bank_mem(boot_info, node_id,
							bank, node_mem);
		if (new_bank < 0) {
			/* the bank was deleted, so bank fully remapped */
		} else if (new_bank != bank) {
			BOOT_BUG("Node #%d low bank #%d cannot be changed, "
				"but after creation of unremapping bank "
				"the bank index is updated to #%d\n",
				node_id, bank, new_bank);
		}
	}
	boot_the_node_spin_unlock(node_id, boot_phys_mem_lock);
}
static void __init
boot_remap_low_to_high_memory(boot_info_t *boot_info)
{
	static __initdata BOOT_DEFINE_NODE_LOCK(low_mem_remapped_lock);
	boot_phys_mem_t *all_nodes_mem;
	boot_phys_mem_t *node_mem;
	int node_id;

	if (boot_node_lock(&low_mem_remapped_lock)) {
		DebugNUMA("boot_remap_low_to_high_memory() low memory "
			"was already remapped on node\n");
		return;
	}

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);

	node_id = boot_numa_node_id();
	node_mem = &all_nodes_mem[node_id];
	if (node_mem->pfns_num != 0)
		boot_remap_node_low_memory(boot_info, node_id, node_mem);

	boot_node_unlock(&low_mem_remapped_lock);
}

static	e2k_busy_mem_t * __init_recv
boot_find_node_buse_area_of_addr(e2k_addr_t phys_addr,
		int node_id, node_phys_mem_t *node_mem)
{
	boot_phys_bank_t *node_banks;
	boot_phys_bank_t *phys_bank;
	e2k_busy_mem_t *busy_area;
	short bank;

	node_banks = node_mem->banks;

	for (bank = node_mem->first_bank; bank >= 0; bank = phys_bank->next) {
		e2k_addr_t bank_start;
		short area;

		phys_bank = &node_banks[bank];
		if (phys_bank->pages_num == 0) {
			/* bank in the list has not pages */
			BOOT_BUG("Node #%d bank #%d at the list has not "
				"memory pages\n",
				node_id, bank);
		}
		bank_start = phys_bank->base_addr;
		for (area = phys_bank->first_area;
				area >= 0;
					area = busy_area->next) {
			e2k_size_t start, end;

			busy_area = &phys_bank->busy_areas[area];
			if (busy_area->pages_num == 0) {
				BOOT_BUG("Node #%d low bank #%d empty physical "
					"memory busy area #%d cannot be in "
					"the list",
					node_id, bank, area);
			}
			start = bank_start + (busy_area->start_page <<
								PAGE_SHIFT);
			end = start + (busy_area->pages_num << PAGE_SHIFT);
			DebugRML("Node #%d low bank #%d current busy area #%d "
				"from 0x%lx to 0x%lx\n",
				node_id, bank, area, start, end);
			if (phys_addr >= start && phys_addr < end)
				return busy_area;
		}
	}
	return NULL;	/* area is not found */
}

static	e2k_busy_mem_t * __init_recv
boot_find_busy_area_of_addr(e2k_addr_t phys_addr)
{
	boot_phys_mem_t	*all_nodes_mem = NULL;
	e2k_busy_mem_t	*area;
	int		nodes_num;
	int		cur_nodes_num = 0;
	int		node;

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		node_phys_mem_t *node_mem = &all_nodes_mem[node];

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num++;
		boot_the_node_spin_lock(node, boot_phys_mem_lock);
		area = boot_find_node_buse_area_of_addr(phys_addr,
							node, node_mem);
		boot_the_node_spin_unlock(node, boot_phys_mem_lock);
		if (area != NULL)
			return area;	/* area is found */
	}
	return NULL;	/* area is not found */
}

static e2k_addr_t __init
boot_get_remapped_area_addr(boot_info_t *boot_info,
		e2k_addr_t old_addr, busy_mem_type_t mem_type)
{
	e2k_addr_t new_addr;
	e2k_busy_mem_t *area;

	/* area could be remapped from low to high memory */
	/* so new address should be from high memory */

	if (is_addr_from_high_memory(old_addr)) {
		/* address is already from high memory */
		new_addr = old_addr;
	} else {
		new_addr = (e2k_addr_t)boot_pa_to_high_pa((void *)old_addr,
								boot_info);
	}
	area = boot_find_busy_area_of_addr(new_addr);
	if (unlikely(area == NULL)) {
		BOOT_BUG("Could not find remapped from low to high busy area, "
			"low address 0x%lx, high 0x%lx\n",
			old_addr, new_addr);
	}
	if (area->type != mem_type) {
		BOOT_WARNING("Memory type %d of remapped from low 0x%lx to "
			"high 0x%lx area is not the same as source area "
			"type %d\n",
			area->type, old_addr, new_addr, mem_type);
	}
	return new_addr;
}

static void __init
boot_update_kernel_image_addr(bool bsp, boot_info_t *boot_info)
{
	e2k_addr_t old_addr, new_addr;

	if (BOOT_IS_BSP(bsp)) {
		/* kernel image 'text' segment */
		old_addr = boot_text_phys_base;
		new_addr = boot_get_remapped_area_addr(boot_info,
					old_addr, kernel_image_mem_type);
		if (new_addr != old_addr) {
			boot_text_phys_base = new_addr;
			DebugRMLT("kernel 'text' segment was remapped from "
				"low memory 0x%lx to high 0x%lx\n",
				old_addr, new_addr);
		} else {
			DebugRMLT("kernel 'text' segment could not remap from "
				"low memory 0x%lx to high\n",
				old_addr);
		}

		/* kernel image 'data/bss' segment */
		old_addr = boot_data_phys_base;
		new_addr = boot_get_remapped_area_addr(boot_info,
					old_addr, kernel_image_mem_type);
		if (new_addr != old_addr) {
			boot_data_phys_base = new_addr;
			DebugRMLT("kernel 'data/bss' segment was remapped from "
				"low memory 0x%lx to high 0x%lx\n",
				old_addr, new_addr);
		} else {
			DebugRMLT("kernel 'data/bss' segment could not remap "
				"from low memory 0x%lx to high\n",
				old_addr);
		}
	}
}

static void __init
boot_update_bootblock_addr(bool bsp, boot_info_t *boot_info)
{
	e2k_addr_t old_addr, new_addr;
#ifdef	CONFIG_L_IO_APIC
	struct intel_mp_floating *mpf;
#endif	/* CONFIG_L_IO_APIC */

	if (BOOT_IS_BSP(bsp)) {
		/* kernel <-> boot loader BOOTINFO area */
		old_addr = boot_bootinfo_phys_base;
		new_addr = boot_get_remapped_area_addr(boot_info,
					old_addr, boot_loader_mem_type);
		if (new_addr != old_addr) {
			boot_bootinfo_phys_base = new_addr;
			boot_bootblock_virt =
				(bootblock_struct_t *)
					__boot_va(boot_vpa_to_pa(new_addr));
			DebugRMLT("kernel <-> boot loader info was remapped "
				"from low memory 0x%lx to high 0x%lx (0x%lx)\n",
				old_addr, new_addr, boot_bootblock_virt);
		} else {
			DebugRMLT("kernel <-> boot loader info could not remap "
				"from low memory 0x%lx to high\n",
				old_addr);
		}

#ifdef CONFIG_BLK_DEV_INITRD
		/* initial ramdisk INITRD */
		if (boot_info->ramdisk_size != 0) {
			old_addr = boot_initrd_phys_base;
			new_addr = boot_get_remapped_area_addr(boot_info,
						old_addr, boot_loader_mem_type);
			if (new_addr != old_addr) {
				boot_initrd_phys_base = new_addr;
				DebugRMLT("initial ramdisk INITRD was remapped "
					"from low memory 0x%lx to high 0x%lx\n",
					old_addr, new_addr);
			} else {
				DebugRMLT("initial ramdisk INITRD could not "
					"remap from low memory 0x%lx to high\n",
					old_addr);
			}
		}
#endif	/* CONFIG_BLK_DEV_INITRD */

#ifdef	CONFIG_L_IO_APIC
		if (boot_info->mp_table_base == (e2k_addr_t)0UL)
			/* nothing additional tables */
			return;

		mpf = (struct intel_mp_floating *)boot_info->mp_table_base;

		/* additional MP tables */
		old_addr = boot_info->mp_table_base;
		new_addr = boot_get_remapped_area_addr(boot_info,
					old_addr, boot_loader_mem_type);
		if (new_addr != old_addr) {
			boot_info->mp_table_base = new_addr;
			boot_mpf_phys_base = new_addr;
			DebugRMLT("MP floating table was remapped "
				"from low memory 0x%lx to high 0x%lx\n",
				old_addr, new_addr);
		} else {
			DebugRMLT("MP floating table could not remap "
				"from low memory 0x%lx to high\n",
				old_addr);
		}

		/* MP configuration tables */
		if (mpf->mpf_physptr == (e2k_addr_t)0UL)
			return;

		old_addr = mpf->mpf_physptr;
		new_addr = boot_get_remapped_area_addr(boot_info,
					old_addr, boot_loader_mem_type);
		if (new_addr != old_addr) {
			mpf->mpf_checksum = 0;
			mpf->mpf_physptr = new_addr;
			boot_mpc_phys_base = new_addr;
			/* recalculate structure sum */
			mpf->mpf_checksum =
				boot_mpf_do_checksum((unsigned char *)mpf,
							sizeof(*mpf));
			DebugRMLT("MP configuration table was remapped "
				"from low memory 0x%lx to high 0x%lx\n",
				old_addr, new_addr);
		} else {
			DebugRMLT("MP configuration table could not remap "
				"from low memory 0x%lx to high\n",
				old_addr);
		}
#endif	/* CONFIG_L_IO_APIC */
	}
}

static void __init
boot_update_boot_memory_addr(bool bsp, boot_info_t *boot_info)
{
	e2k_addr_t old_addr, new_addr;

	if (BOOT_IS_BSP(bsp)) {
		int bank;

		/* boot loader busy areas */
		for (bank = 0; bank < boot_info->num_of_busy; bank++) {
			bank_info_t *busy_area;
			busy_area = &boot_info->busy[bank];
			old_addr = busy_area->address;
			new_addr = boot_get_remapped_area_addr(boot_info,
						old_addr, boot_loader_mem_type);
			if (new_addr != old_addr) {
				busy_area->address = new_addr;
				DebugRMLT("memory area occupied by boot loader "
					"was remapped from low memory 0x%lx "
					"to high 0x%lx\n",
					old_addr, new_addr);
			} else {
				DebugRMLT("memory area occupied by boot loader "
					"could not remap from low memory 0x%lx "
					"to high\n",
					old_addr);
			}
		}
	}
}

static void __init
boot_update_stacks_addr(boot_info_t *boot_info)
{
	e2k_addr_t old_addr, new_addr;

	/* kernel procedure stack */
	old_addr = boot_boot_ps_phys_base;
	new_addr = boot_get_remapped_area_addr(boot_info,
				old_addr, boot_loader_mem_type);
	if (new_addr != old_addr) {
		boot_boot_ps_phys_base = new_addr;
		DebugRMLT("kernel procedure stack was remapped from "
			"low memory 0x%lx to high 0x%lx\n",
			old_addr, new_addr);
	} else {
		DebugRMLT("kernel procedure stack could not remap "
			"from low memory 0x%lx to high\n",
			old_addr);
	}

	/* kernel procedure chain stack */
	old_addr = boot_boot_pcs_phys_base;
	new_addr = boot_get_remapped_area_addr(boot_info,
				old_addr, boot_loader_mem_type);
	if (new_addr != old_addr) {
		boot_boot_pcs_phys_base = new_addr;
		DebugRMLT("kernel procedure chain stack was remapped from "
			"low memory 0x%lx to high 0x%lx\n",
			old_addr, new_addr);
	} else {
		DebugRMLT("kernel procedure chain stack could not remap "
			"from low memory 0x%lx to high\n",
			old_addr);
	}

	/* kernel local data stack */
	old_addr = boot_boot_stack_phys_base;
	new_addr = boot_get_remapped_area_addr(boot_info,
				old_addr, boot_loader_mem_type);
	if (new_addr != old_addr) {
		boot_boot_stack_phys_base = new_addr;
		DebugRMLT("kernel local data stack was remapped from "
			"low memory 0x%lx to high 0x%lx\n",
			old_addr, new_addr);
	} else {
		DebugRMLT("kernel local data stack could not remap "
			"from low memory 0x%lx to high\n",
			old_addr);
	}
}

static void __init
boot_update_reserved_areas_addr(bool bsp, boot_info_t *boot_info)
{
	/* Update kernel image 'text/data/bss' segments */
	boot_update_kernel_image_addr(bsp, boot_info);

	/* Update memory of boot-time local data & hardware stacks */
	boot_update_stacks_addr(boot_info);

	/* Update boot information records */
	boot_update_bootblock_addr(bsp, boot_info);

	/* Update pointers to memory used by BOOT (e2k boot-loader) */
	boot_update_boot_memory_addr(bsp, boot_info);
}

void __init boot_remap_low_memory(bool bsp, boot_info_t *boot_info)
{
	if (BOOT_LOW_MEMORY_ENABLED()) {
		boot_printk("Remapping low memory to high is disabled\n");
		return;
	}

	/*
	 * Preliminarily reserve low memory, if it need
	 */
	boot_reserve_low_memory(bsp, boot_info);

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete reserving of
	 * used low memory.
	 * After synchronization can start remapping of low memory to high
	 */
	boot_sync_all_processors();

	/*
	 * Remap all low memory to high memory range on all nodes
	 */
	boot_remap_low_to_high_memory(boot_info);

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete remapping of
	 * used low memory to high adrresses memory range.
	 * After synchronization need be updated common info about
	 * present physical memory
	 */
	boot_sync_all_processors();

	/* update common info about present physical memory */
	if (BOOT_IS_BSP(bsp))
		boot_update_physmem_maps(boot_info);

	/* update addresses of remapped kernel boot-time data, structures, */
	/* images, tables and other allocated & reserved areas */
	boot_update_reserved_areas_addr(bsp, boot_info);
}
#endif	/* CONFIG_ONLY_HIGH_PHYS_MEM */

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
boot_alloc_node_physmem(int node_id, e2k_size_t mem_size,
			e2k_size_t align, e2k_size_t page_size,
			busy_mem_type_t mem_type, unsigned short flags)
{
	boot_phys_mem_t		*all_nodes_mem;
	boot_phys_mem_t		*node_mem;
	boot_phys_bank_t	*node_banks;
	boot_phys_bank_t	*phys_bank = NULL;
	e2k_size_t		max_align;
	short			bank;
	long			mem_pages;
	e2k_size_t		start_page;
	bool			start_found;
	e2k_addr_t		start_addr = -1;
	long			bank_pages_num;

	DebugAM("boot_alloc_node_physmem() node #%d: mem size 0x%lx\n",
		node_id, mem_size);
	if (mem_size == 0)
		BOOT_BUG("Allocated memory area size %ld is empty", mem_size);

	DebugAM("boot_alloc_node_physmem() page size 0x%lx\n", page_size);
	if (page_size == 0)
		BOOT_BUG("The page size to round up %ld is empty", page_size);

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

	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);

	start_found = false;
	boot_the_node_spin_lock(node_id, boot_phys_mem_lock);
	node_mem = &all_nodes_mem[node_id];
	if (node_mem->pfns_num == 0) {
		goto no_memory;	/* node has not memory */
	}
	node_banks = node_mem->banks;
	for (bank = node_mem->first_bank; bank >= 0; bank = phys_bank->next) {
		e2k_addr_t bank_start;
		e2k_busy_mem_t *busy_area;
		short area;

		phys_bank = &node_banks[bank];
		bank_start = phys_bank->base_addr;
		DebugAM("boot_alloc_node_physmem() current bank #%d is "
			"from 0x%lx to 0x%lx\n",
			bank, bank_start,
			bank_start + (phys_bank->pages_num << PAGE_SHIFT));
		if (phys_bank->pages_num == 0) {
			/* bank in the list has not pages */
			BOOT_BUG("Node #%d bank #%d at the list "
				"has not memory pages",
				node_id, bank);
			break;
		}
		if ((flags & BOOT_ONLY_LOW_PHYS_MEM) &&
				is_addr_from_high_memory(bank_start)) {
			DebugAM("boot_alloc_node_physmem() bank is from high "
				"memory 0x%lx, need only low\n",
				bank_start);
			continue;
		}
		if ((flags & (BOOT_ONLY_HIGH_PHYS_MEM |
					BOOT_FIRST_HIGH_PHYS_MEM)) &&
			is_addr_from_low_memory(bank_start +
				(phys_bank->pages_num << PAGE_SHIFT) - 1)) {
			DebugAM("boot_alloc_node_physmem() bank is from low "
				"memory 0x%lx, need only or first high\n",
				bank_start);
			continue;
		}
		DebugAM("boot_alloc_node_physmem() node #%d bank #%d "
			"free pages num is 0x%lx\n",
			node_id, bank,
			atomic64_read(&phys_bank->free_pages_num));
		if (atomic64_read(&phys_bank->free_pages_num) == 0) {
			DebugAM("boot_alloc_node_physmem() node #%d bank #%d "
				"has not free pages\n",
				node_id, bank);
			continue;
		}

		/*
		 * Scan all busy areas of physical memory bank and
		 * search a suitable hole of contiguous free pages.
		 */
		start_addr = phys_bank->base_addr;
		start_addr = ALIGN_TO_SIZE(start_addr, max_align);
		start_page = (start_addr - phys_bank->base_addr) >> PAGE_SHIFT;
		if (start_page + mem_pages > phys_bank->pages_num) {
			DebugAM("boot_alloc_node_physmem() node #%d bank #%d "
				"has not enough memory from 0x%lx to 0x%lx\n",
				node_id, bank, start_addr,
				start_addr + (mem_pages << PAGE_SHIFT));
			continue;
		}
		for (area = phys_bank->first_area;
				area >= 0;
					area = busy_area->next) {
			e2k_size_t area_start, area_end;

			busy_area = &phys_bank->busy_areas[area];
			if (busy_area->pages_num == 0) {
				BOOT_BUG("Node #%d bank #%d empty physical "
					"memory busy area #%d cannot be "
					"in the list",
					node_id, bank, area);
				continue;
			}
			area_start = busy_area->start_page;
			area_end = area_start + busy_area->pages_num;
			DebugAM("boot_alloc_node_physmem() node #%d bank #%d "
				"busy area #%d from 0x%lx to 0x%lx\n",
				node_id, bank, area,
				bank_start + (area_start << PAGE_SHIFT),
				bank_start + (area_end << PAGE_SHIFT));
			if (start_page < area_start &&
					area_start - start_page >= mem_pages) {
				/* suitable free area is found */
				start_found = true;
				DebugAM("boot_alloc_node_physmem() node #%d "
					"bank #%d area #%d found free hole "
					"from 0x%lx to 0x%lx\n",
					node_id, bank, area, start_addr,
					start_addr + (mem_pages << PAGE_SHIFT));
				break;
			}
			if (start_page < area_start ||
					start_page < area_end) {
				/* hole is too small or start into already */
				/* busy area, shift start address outside */
				/* the end of current area and goto next */
				start_page = area_end;
				start_addr = bank_start +
						(start_page << PAGE_SHIFT);
				start_addr = ALIGN_TO_SIZE(start_addr,
								max_align);
				start_page = (start_addr -
						bank_start) >> PAGE_SHIFT;
				DebugAM("boot_alloc_node_physmem() node #%d "
					"bank #%d area #%d shift start of "
					"search to 0x%lx\n",
					node_id, bank, area, start_addr);
				if (start_page + mem_pages >
						phys_bank->pages_num) {
					DebugAM("boot_alloc_node_physmem() "
						"node #%d bank #%d "
						"has not enough memory "
						"from 0x%lx to 0x%lx\n",
						node_id, bank, start_addr,
						start_addr +(mem_pages <<
								PAGE_SHIFT));
					break;
				}
				continue;
			}
			/* start address above current area, goto next */
		}

		if (start_found)
			break;

		if (start_page + mem_pages <= phys_bank->pages_num) {
			/* suitable free hole is found at bank end */
			start_found = true;
			DebugAM("boot_alloc_node_physmem() node #%d "
				"bank #%d found free hole from 0x%lx "
				"to 0x%lx at bank end\n",
				node_id, bank, start_addr,
				start_addr + (mem_pages << PAGE_SHIFT));
			break;
		}
		DebugAM("boot_alloc_node_physmem() node #%d bank #%d "
			"has not enough memory from 0x%lx to 0x%lx\n",
			node_id, bank, start_addr,
			start_addr + (mem_pages << PAGE_SHIFT));
	}

	if (!start_found) {
no_memory:
		boot_the_node_spin_unlock(node_id, boot_phys_mem_lock);
		DebugAM("boot_alloc_node_physmem() node #%d: could not find "
			"free memory enough to allocate area: size 0x%lx "
			"align 0x%lx page size 0x%lx\n",
			node_id, mem_size, align, page_size);
		return ((void *)-1);
	}

	/* Reserve the area now */
	bank_pages_num = boot_reserve_bank_physmem(node_id, node_mem,
					bank, phys_bank,
					start_addr, mem_pages,
					mem_type, flags);

	boot_the_node_spin_unlock(node_id, boot_phys_mem_lock);

	if (bank_pages_num <= 0) {
		BOOT_BUG("Could not reserve allocated free memory area: "
			"node #%d size %ld align 0x%lx page size 0x%lx",
			node_id, mem_size, align, page_size);
		return ((void *)-1);
	}

	/* VCPUs are starting with virtual memory support ON, so all */
	/* guest "physical addresses" (gpa) should be virtual (vpa) */
	/* i.e. PAGE_OFFSET + gpa */
	start_addr = boot_pa_to_vpa(start_addr);

	return((void *)start_addr);
}

void * __init_recv
boot_alloc_node_mem(int node_id, e2k_size_t mem_size,
			e2k_size_t align, e2k_size_t page_size,
			busy_mem_type_t mem_type, unsigned short flags)
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
		(flags & BOOT_ONLY_ON_NODE_ALLOC_MEM) ?
			"only on this node" : "may be on other node");
	nodes_num = boot_phys_mem_nodes_num;
	all_nodes_mem = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	for (cur_try = 0; cur_try < 3; cur_try ++) {
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= nodes_num)
			goto next_try;	/* no more nodes with memory */
		if (all_nodes_mem[cur_node].pfns_num == 0) {
			if (flags & BOOT_ONLY_ON_NODE_ALLOC_MEM)
				break;
			goto next_node;	/* node has not memory */
		}
node_next_try:
		node_mem = boot_alloc_node_physmem(cur_node, mem_size, align,
					page_size, mem_type, flags);
		if (node_mem != (void *)-1) {
			if (cur_node != node_id) {
				BOOT_WARNING("Could allocate area on node #%d "
					"insteed of #%d, addr 0x%lx size 0x%lx "
					"align 0x%lx page size 0x%lx",
					cur_node, node_id, node_mem,
					mem_size, align, page_size);
			}
			DebugAM("boot_alloc_node_mem() node #%d: allocated "
				"on node #%d from 0x%px, size 0x%lx\n",
				node_id, cur_node, node_mem, mem_size);
			return (node_mem);
		}
		if (flags & BOOT_ONLY_ON_NODE_ALLOC_MEM) {
			if (flags & BOOT_FIRST_HIGH_PHYS_MEM) {
				DebugAM("boot_alloc_node_mem() node #%d: could "
					"not allocate high memory as first, "
					"try allocate any only on node\n",
					node_id);
				flags &= ~BOOT_FIRST_HIGH_PHYS_MEM;
				goto node_next_try;
			}
			break;
		}
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
		if (flags & BOOT_ONLY_ON_NODE_ALLOC_MEM)
			break;
		if (flags & BOOT_FIRST_HIGH_PHYS_MEM) {
			DebugAM("boot_alloc_node_mem() node #%d: could not "
				"allocate high memory as first, try "
				"allocate any on any node\n",
				node_id);
			flags &= ~BOOT_FIRST_HIGH_PHYS_MEM;
			cur_node = node_id;
			cur_nodes_num = 0;
		}
	}
	if (!(flags & BOOT_IS_TRY_ALLOC_MEM)) {
		BOOT_BUG("Could not find free memory enough to allocate area: "
			"node #%d (%s) size %ld align 0x%lx page size 0x%lx",
			node_id,
			(flags & BOOT_ONLY_ON_NODE_ALLOC_MEM) ?
				"only on this node" : "and on other node",
			mem_size, align, page_size);
	}
	return ((void *)-1);
}

/*
 * Map the physical memory pages of the banks into the virtual pages
 * The function returns the number of mapped pages in the bank
 */
static	long __init_recv
boot_map_physmem_area(e2k_addr_t phys_start, e2k_addr_t phys_end,
		pgprot_t prot_flags, e2k_size_t max_page_size,
		pt_struct_t *pt_struct, int start_level)
{
	pt_level_t	*pt_level;
	e2k_addr_t	level_start;
	e2k_addr_t	level_end;
	e2k_size_t	page_size;
	e2k_addr_t	map_virt_addr;
	e2k_size_t	map_size;
	int		level;
	long		pages = 0;
	long		ret;

	/* loop on all page table levels from possible max to min level, */
	/* it allows to map physical memory to virtual pages of max sizes */
	for (level = start_level; level > 0; level--) {
		pt_level = &pt_struct->levels[level];
		if (!pt_level->is_huge && !pt_level->is_pte)
			/* level cannot point to physical pages */
			/* (can be as pte) */
			continue;
		page_size = pt_level->page_size;
		if (max_page_size != 0 && page_size > max_page_size)
			/* it is not level with specified page size */
			continue;

		level_start = _PAGE_ALIGN_DOWN(phys_start, page_size);
		level_end = _PAGE_ALIGN_UP(phys_end, page_size);
		if (level_start >= level_end)
			continue;	/* too big page size to map */

		/* this lavel and page size is suitable to map */
		break;
	}
	if (unlikely(level <= 0)) {
		BOOT_BUG("Could not find page table level to map physical "
			"memory from addr 0x%lx to 0x%lx, specified max page "
			"size 0x%lx",
			phys_start, phys_end, max_page_size);
		return -EINVAL;
	}

	if (level_start != phys_start) {
		/* there is area at beginning which can be mapped */
		/* only a smaller pages */
		pages += boot_map_physmem_area(phys_start, level_start,
				prot_flags, max_page_size,
				pt_struct, level - 1);
	}

	map_virt_addr = (e2k_addr_t)__boot_va(level_start);
	map_size = level_end - level_start;
	ret = boot_do_map_phys_area(level_start, map_size, map_virt_addr,
			prot_flags, pt_level,
			false,	/* ignore mapping virtual area is busy ? */
			false);	/* populate map on host ? */
	if (unlikely(ret <= 0)) {
		BOOT_BUG("Could not map physical memory from addr 0x%lx "
			"to 0x%lx, page size 0x%lx",
			level_start, level_end, page_size);
		return ret;
	}
	pages += (ret * (page_size >> PAGE_SHIFT));
	DebugMP("Map physical memory from addr 0x%lx to 0x%lx to virtual space "
		"base 0x%lx, 0x%lx pages of size 0x%lx\n",
		level_start, level_end, map_virt_addr, ret, page_size);

	if (level_end != phys_end) {
		/* there is area at ending which can be mapped */
		/* only a smaller pages */
		pages += boot_map_physmem_area(level_end, phys_end,
				prot_flags, max_page_size,
				pt_struct, level - 1);
	}

	return pages;
}
static	long __init_recv
boot_map_banks_physmem(e2k_addr_t phys_start, e2k_addr_t phys_end,
		pgprot_t prot_flags, e2k_size_t max_page_size)
{
	pt_struct_t *pt_struct = boot_pgtable_struct_p;

	DebugMP("will map physical area from 0x%lx to 0x%lx\n",
		phys_start, phys_end);
	return boot_map_physmem_area(phys_start, phys_end,
			prot_flags, max_page_size, pt_struct,
			pt_struct->levels_num);
}

e2k_addr_t __init
boot_get_adjacent_phys_bank_addr(int start_node, short start_bank,
			e2k_addr_t start_addr,
			bool lowest	/* if false then highest */)
{
	boot_phys_mem_t	*all_phys_banks = NULL;
	int		my_node_id = boot_numa_node_id();
	int		nodes_num;
	int		cur_nodes_num = 0;
	e2k_addr_t	bank_base;
	e2k_addr_t	bank_end;
	e2k_addr_t	new_start;
	e2k_addr_t	phys_addr;
	int		nodes;
	int		node;
	short		bank;

	all_phys_banks = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;
	node = start_node;
	for (nodes = 0; nodes < L_MAX_MEM_NUMNODES; nodes++) {
		boot_phys_mem_t	*node_mem = &all_phys_banks[node];
		boot_phys_bank_t *node_banks;
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			goto next_node;	/* node has not memory */
		node_banks = node_mem->banks;
		if (node == start_node)
			bank = node_banks[start_bank].next;
		else
			bank = node_mem->first_bank;
		cur_nodes_num++;
		for (; bank >= 0; bank = phys_bank->next) {
			phys_bank = &node_banks[bank];
			if (phys_bank->pages_num == 0) {
				/* bank in the list has not pages */
				BOOT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);
			}
			DebugMP("Node #%d bank #%d: from 0x%lx to 0x%lx\n",
				node, bank, phys_bank->base_addr,
				phys_bank->base_addr +
					(phys_bank->pages_num << PAGE_SHIFT));
			if (phys_bank->mapped[my_node_id]) {
				/* bank already mapped */
				DebugMP("Node #%d bank #%d: already mapped\n",
					node, bank);
				continue;
			}
			bank_base = phys_bank->base_addr;
			bank_end = bank_base +
					(phys_bank->pages_num << PAGE_SHIFT);
			if (start_addr > bank_base && start_addr < bank_end) {
				BOOT_BUG("Node #%d bank #%d: start addr 0x%lx "
					"is into bank range deom 0x%lx "
					"to 0x%lx",
					node, bank, start_addr,
					bank_base, bank_end);
			}
			if (lowest)
				/* contiguity should be to end */
				phys_addr = bank_end;
			else
				/* contiguity should be to begin */
				phys_addr = bank_base;
			if (phys_addr == start_addr) {
				if (lowest)
					new_start = bank_base;
				else
					new_start = bank_end;
				phys_bank->mapped[my_node_id] = true;
				DebugMP("Node #%d bank #%d: there is "
					"contiguity from %s, contigous bank %s "
					"is now 0x%lx\n",
					node, bank,
					(lowest) ? "end" : "start",
					(lowest) ? "start" : "end",
					new_start);
				return boot_get_adjacent_phys_bank_addr(
						node, bank, new_start, lowest);
			}
			if (start_addr < phys_addr)
				/* all other banks higher and cannot have */
				/* contiguity from start or end */
				break;
		}
next_node:
		node++;
		if (node >= L_MAX_MEM_NUMNODES)
			node = 0;
	}
	DebugMP("Node #%d bank #%d: there is not more contiguity from %s, so "
		"contigous bank %s stay the same 0x%lx\n",
		start_node, start_bank,
		(lowest) ? "end" : "start", (lowest) ? "start" : "end",
		start_addr);
	return start_addr;
}
static inline e2k_addr_t __init
boot_get_lowest_phys_bank_base(int start_node, short start_bank,
			e2k_addr_t start_addr)
{
	return boot_get_adjacent_phys_bank_addr(start_node, start_bank,
						start_addr,
						true	/* lowest ? */);
}
static inline e2k_addr_t __init
boot_get_highest_phys_bank_end(int start_node, short start_bank,
			e2k_addr_t start_addr)
{
	return boot_get_adjacent_phys_bank_addr(start_node, start_bank,
						start_addr,
						false	/* lowest ? */);
}

/*
 * Map all physical memory into virtual space
 *
 * Function returns number of mapped physical pages
 */
long __init
boot_map_physmem(pgprot_t prot_flags, e2k_size_t max_page_size)
{
	boot_phys_mem_t	*all_phys_banks = NULL;
	int		my_node_id = boot_numa_node_id();
	int		nodes_num;
	int		cur_nodes_num = 0;
	e2k_addr_t	bank_base;
	e2k_addr_t	bank_end;
	e2k_addr_t	phys_addr;
	e2k_addr_t	phys_end;
	long		pages_num;
	long		mapped_pages = 0;
	long		all_pages_num = boot_pages_of_phys_memory;
	int		node;
	short		bank;

	all_phys_banks = boot_vp_to_pp((boot_phys_mem_t *)boot_phys_mem);
	nodes_num = boot_phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		boot_phys_mem_t	*node_mem = &all_phys_banks[node];
		boot_phys_bank_t *node_banks;
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		node_banks = node_mem->banks;
		DebugMP("Node #%d: physical memory banks number %d\n",
			node, node_mem->banks_num);
		cur_nodes_num++;
		for (bank = node_mem->first_bank;
				bank >= 0;
					bank = phys_bank->next) {
			phys_bank = &node_banks[bank];
			if (phys_bank->pages_num == 0) {
				/* bank in the list has not pages */
				BOOT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);
			}
			if (phys_bank->mapped[my_node_id])
				/* bank alread mapped */
				continue;
			bank_base = phys_bank->base_addr;
			bank_end = bank_base +
					(phys_bank->pages_num << PAGE_SHIFT);
			phys_bank->mapped[my_node_id] = true;
			DebugMP("Node #%d bank #%d from base 0x%lx to 0x%lx "
				"try expand continuously from start and end\n",
				node, bank, bank_base, bank_end);
			if (bank_base > boot_start_of_phys_memory)
				phys_addr = boot_get_lowest_phys_bank_base(
							node, bank, bank_base);
			else
				phys_addr = bank_base;
			if (phys_addr != bank_base) {
				DebugMP("Node #%d bank #%d base bank "
					"addr 0x%lx was decrement to 0x%lx\n",
					node, bank, bank_base, phys_addr);
			} else {
				DebugMP("Node #%d bank #%d base bank "
					"addr 0x%lx was not changed\n",
					node, bank, phys_addr);
			}
			if (bank_end < boot_end_of_phys_memory)
				phys_end = boot_get_highest_phys_bank_end(
							node, bank, bank_end);
			else
				phys_end = bank_end;
			if (phys_end != bank_end) {
				DebugMP("Node #%d bank #%d end bank "
					"addr 0x%lx was increment to 0x%lx\n",
					node, bank, bank_end, phys_end);
			} else {
				DebugMP("Node #%d bank #%d end bank "
					"addr 0x%lx was not changed\n",
					node, bank, phys_end);
			}
			pages_num = boot_map_banks_physmem(phys_addr, phys_end,
						prot_flags, max_page_size);
			DebugMP("Node #%d bank #%d: physical memory from 0x%lx "
				"to 0x%lx mapped to 0x%lx pages\n",
				node, bank, phys_addr, phys_end, pages_num);
			mapped_pages += pages_num;
			if (mapped_pages >= all_pages_num)
				break;
		}
		if (mapped_pages >= all_pages_num)
			break;
	}
	if (mapped_pages != all_pages_num) {
		BOOT_BUG("Could not map all needed physical memory pages "
			"only 0x%lx pages instead of 0x%lx",
			mapped_pages, all_pages_num);
	}
	return mapped_pages;
}
