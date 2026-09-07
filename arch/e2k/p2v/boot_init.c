/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Boot-time initialization of Virtual memory support.
 * Switch from boot execution on physical memory to continuation of boot
 * on virtual memory
 */

#define DEBUG_CPU_REGS 0

#include <asm/p2v/boot_v2p.h>

#include <asm/p2v/io.h>
#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_map.h>
#include <asm/p2v/boot_cacheflush.h>
#include <asm/p2v/boot_console.h>
#include <asm/p2v/boot_param.h>
#include <asm/p2v/boot_mmu_context.h>
#include <asm/boot_recovery.h>
#include <asm/errors_hndl.h>
#include <asm/e2k_debug.h>
#include <asm/mmu_context.h>
#include <asm/process.h>
#include <asm/regs_state.h>
#include <asm/sic_regs_access.h>
#include <asm/vga.h>

#include "boot_string.h"

#undef	DEBUG_BOOT_MODE
#undef	boot_printk
#define	DEBUG_BOOT_MODE		0	/* Boot process */
#define	boot_printk		if (DEBUG_BOOT_MODE) do_boot_printk

#undef	DEBUG_LO_TO_HI_MODE
#undef	DebugLoHi
#define	DEBUG_LO_TO_HI_MODE	0	/* Convertion low to high address */
#define	DebugLoHi		if (DEBUG_LO_TO_HI_MODE) do_boot_printk

#undef	DEBUG_PHYS_BANK_MODE
#undef	DebugBank
#define	DEBUG_PHYS_BANK_MODE	0	/* Physical memory bank management */
#define	DebugBank		if (DEBUG_PHYS_BANK_MODE) do_boot_printk

/*
 * Array of 'BOOT_MAX_MEM_NUMNODES' of 'BOOT_MAX_MEM_NUMNODES' structures
 * is statically allocated into the kernel image.
 * The array of structures is used to hold the
 * physical memory configuration of the machine. This is filled in
 * 'boot_probe_memory()' and is later used by 'boot_mem_init()' to setup
 * boot-time memory map and by 'mem_init()' to set up 'mem_map[]'.
 */

node_phys_mem_t nodes_phys_mem[L_MAX_MEM_NUMNODES];
EXPORT_SYMBOL(nodes_phys_mem);

#ifdef	PA_TO_HIGH_DINAMICALY
/* is enabled/disabled usage only of high partition of physical memory */
/* and conversion addresses from low memory to high */
bool pa_to_high_disabled = false;	/* default is enabled */
#endif /* PA_TO_HIGH_DINAMICALY */

/*
 * The next structure contains list of descriptors of the memory areas
 * used by boot-time initialization.
 * All the used memory areas enumerate in this structure. If a some new
 * area will be used, then it should be added to the list of already known ones.
 */

bootmem_areas_t kernel_bootmem;

static atomic_t boot_physmem_maps_ready = ATOMIC_INIT(0);
#ifdef CONFIG_SMP
static atomic_t __initdata_recv boot_pv_ops_switched = ATOMIC_INIT(0);
#endif

/*
 * FIXME: Nodes number is limited by bits in unsigned long size - 64
 */
int phys_nodes_num;
unsigned long phys_nodes_map;
unsigned long phys_mem_nodes_map;

static __init void boot_reserve_bootinfo_areas(boot_info_t *boot_info);

static e2k_size_t mem_limit = -1UL;
#define boot_mem_limit	boot_get_vo_value(mem_limit)

static int __init boot_mem_set(char *cmd)
{
	boot_mem_limit = boot_simple_strtoul(cmd, &cmd, 0);

	if (*cmd == 'K' || *cmd == 'k')
		boot_mem_limit <<= 10;
	else if (*cmd == 'M' || *cmd == 'm')
		boot_mem_limit <<= 20;
	else if (*cmd == 'G' || *cmd == 'g')
		boot_mem_limit <<= 30;

	boot_mem_limit &= PAGE_MASK;

	boot_printk("Physical memory limit set to 0x%lx\n", boot_mem_limit);

	return 0;
}
__boot_setup("mem", boot_mem_set);

static e2k_size_t node_mem_limit = -1UL;
#define boot_node_mem_limit	boot_get_vo_value(node_mem_limit)

static int __init boot_node_mem_set(char *cmd)
{
	boot_node_mem_limit = boot_simple_strtoul(cmd, &cmd, 0);

	if (*cmd == 'K' || *cmd == 'k')
		boot_node_mem_limit <<= 10;
	else if (*cmd == 'M' || *cmd == 'm')
		boot_node_mem_limit <<= 20;

	boot_node_mem_limit &= PAGE_MASK;

	boot_printk("Node physical memory limit set to 0x%lx\n",
		    boot_node_mem_limit);

	return 0;
}
__boot_setup("nodemem", boot_node_mem_set);


/*
 * bootblock.banks_ex is extended area for all nodes. Firstly, we fill
 * node_phys_mem.banks from bootblock.nodes_mem.banks, which presents for each
 * node. If there are more than L_MAX_NODE_PHYS_BANKS_FUSTY phys banks for a
 * node, we continue to fill node_phys_mem.banks from bootblock.banks_ex,
 * which is one for all nodes. Last element in bootblock.banks_ex for a
 * node, which uses it, should be with size = 0. If a node has only
 * L_MAX_NODE_PHYS_BANKS_FUSTY phys banks, there should be element with size = 0
 * in bootblock.banks_ex for this node.
 *
 *	    node_phys_mem.banks		  bootblock.nodes_mem.banks
 *         __________________________________________
 *  ______|_____________________________   __________|____________
 * |__________________|_________________| |_______________________|
 *                             |
 * L_MAX_NODE_PHYS_BANKS_FUSTY |           bootblock.banks_ex
 * <------------------>        |_____________________
 *                                         __________|____________
 *				          |_______________________|
 * L_MAX_NODE_PHYS_BANKS
 * <----------------------------------->
 */

struct bank_iterator {
	int node;
	size_t index;
	size_t ex_index;
};

static inline struct bank_iterator bootblock_bank_iter_init(int node, const boot_info_t *bootblock)
{
	int cur_node = 0;
	size_t i;

	for (i = 0; i < ARRAY_SIZE(bootblock->banks_ex); i++) {
		if (cur_node == node)
			break;

		/* Zero-sized banks separate nodes */
		if (bootblock->banks_ex[i].size == 0)
			cur_node += 1;
	}

	return (struct bank_iterator) {
		.node = node,
		.index = 0,
		.ex_index = i,
	};
}

static inline bank_info_t *bootblock_bank_iter_next(struct bank_iterator *iter,
		boot_info_t *bootblock)
{
	/* First go over usual per-node banks */
	if (iter->index < ARRAY_SIZE(bootblock->nodes_mem[iter->node].banks)) {
		bank_info_t *bank = &bootblock->nodes_mem[iter->node].banks[iter->index];
		if (bank->size) {
			iter->index += 1;
			return bank;
		}
	} else if (iter->ex_index < ARRAY_SIZE(bootblock->banks_ex)) {
		/* Then go over `banks_ex` where all nodes are mixed
		 * together and entries with size==0 are used as
		 * separators.  Note that `banks_ex` can be used
		 * only after filling `nodes_mem.banks`. */
		bank_info_t *bank = &bootblock->banks_ex[iter->ex_index];
		if (bank->size) {
			iter->ex_index += 1;
			return bank;
		}
	}

	return NULL;
}

/**
 * for_each_node_bank - iterate over all banks of node from bootblock
 * @bank: pointer to bank_info_t will be returned here
 * @iter: temporary of `struct bank_iterator` type
 * @node: consider only banks from this node
 * @bootblock: bios_info_t pointer
 */
#define for_each_node_bank(bank, iter, node, bootblock) \
	for ((iter) = bootblock_bank_iter_init((node), (bootblock)), \
			(bank) = bootblock_bank_iter_next(&(iter), (bootblock)); \
			(bank) != NULL; \
			(bank) = bootblock_bank_iter_next(&(iter), (bootblock)))


static bank_info_t * __init_recv boot_get_first_node_bank(boot_info_t *bootblock, int node)
{
	struct bank_iterator iter;
	bank_info_t *bank;

	for_each_node_bank(bank, iter, node, bootblock) {
		/* Return with first found bank */
		break;
	}

	return bank;
}

bool __init boot_has_node_low_memory(int node, boot_info_t *bootblock)
{
	struct bank_iterator iter;
	bank_info_t *bank;

	for_each_node_bank(bank, iter, node, bootblock) {
		if (is_addr_from_low_memory(bank->address + bank->size - 1))
			/* found low memory bank */
			return true;
	}
	return false;
}

bool __init_recv boot_has_node_high_memory(int node, boot_info_t *bootblock)
{
	struct bank_iterator iter;
	bank_info_t *bank;

	for_each_node_bank(bank, iter, node, bootblock) {
		if (is_addr_from_high_memory(bank->address))
			/* found high memory bank */
			return true;
	}
	return false;
}

bool __init_recv boot_has_high_memory(boot_info_t *bootblock)
{
	int node;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		bank_info_t *node_bank;

		node_bank = boot_get_first_node_bank(bootblock, node);
		if (node_bank == NULL)
			continue;	/* node has not memory */
		if (boot_has_node_high_memory(node, bootblock))
			return true;
	}
	return false;
}

static short __init_recv
boot_get_free_phys_bank(int node, node_phys_mem_t *node_mem)
{
	e2k_phys_bank_t *phys_banks;
	short bank;

	phys_banks = node_mem->banks;
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank++) {
		e2k_phys_bank_t *cur_phys_bank = &phys_banks[bank];

		if (cur_phys_bank->pages_num == 0)
			/* found empty entry at table */
			return bank;
	}
	if (node_mem->banks_num >= L_MAX_NODE_PHYS_BANKS) {
		BOOT_WARNING("Node #%d number of phys banks %d\n"
			     " exceeds permissible limit\n",
			node, node_mem->banks_num);
		return -1;
	}
	BOOT_BUG("Node #%d number of phys banks is only %d from %d,\n"
		 " but could not find empty entry at table\n",
		 node, node_mem->banks_num, L_MAX_NODE_PHYS_BANKS);
	return -1;
}

static short __init_recv
boot_find_node_phys_bank(int node, node_phys_mem_t *node_mem, short bank)
{
	e2k_phys_bank_t *cur_phys_bank;
	short prev_bank_ind = -1;
	short cur_bank_ind;

	for (cur_bank_ind = node_mem->first_bank;
	     cur_bank_ind >= 0; cur_bank_ind = cur_phys_bank->next) {
		if (cur_bank_ind == bank)
			break;
		prev_bank_ind = cur_bank_ind;
		cur_phys_bank = &node_mem->banks[cur_bank_ind];
	}
	if (cur_bank_ind != bank) {
		BOOT_BUG("Node #%d: could not find bank #%d at the list of node banks\n",
			node, bank);
	}
	return prev_bank_ind;
}

void __init_recv boot_add_new_phys_bank(int node, node_phys_mem_t *node_mem,
					e2k_phys_bank_t *new_phys_bank,
					short new_bank_ind)
{
	e2k_phys_bank_t *phys_banks;
	e2k_phys_bank_t *cur_phys_bank;
	short prev_bank_ind;
	short cur_bank_ind;
	e2k_addr_t new_bank_start;
	e2k_addr_t new_bank_end;
	e2k_size_t new_bank_size;
	e2k_addr_t node_start;
	e2k_addr_t node_end;

	if (node_mem->banks_num == 0 && node_mem->first_bank >= 0 ||
	    node_mem->banks_num != 0 && node_mem->first_bank < 0) {
		BOOT_BUG("No physical banks on node #%d,\n"
			 " but list of banks is not empty or vice versa",
			node);
	}
	if (node_mem->banks_num >= L_MAX_NODE_PHYS_BANKS) {
		BOOT_BUG("Node #%d number of phys banks %d exceeds permissible limit, ignored",
			 node, node_mem->banks_num);
		return;
	}

	new_bank_start = new_phys_bank->base_addr;
	new_bank_size = new_phys_bank->pages_num << PAGE_SHIFT;
	if (new_bank_size == 0) {
		BOOT_BUG("Node #%d empty physical memory bank #%d cannot be added",
			node, new_bank_ind);
		return;
	}
	new_bank_end = new_bank_start + new_bank_size;
	DebugBank("Node #%d : should be added new bank #%d from 0x%lx to 0x%lx\n",
		  node, new_bank_ind, new_bank_start, new_bank_end);

	prev_bank_ind = -1;
	phys_banks = node_mem->banks;
	for (cur_bank_ind = node_mem->first_bank;
	     cur_bank_ind >= 0; cur_bank_ind = cur_phys_bank->next) {
		e2k_addr_t cur_bank_start;

		cur_phys_bank = &phys_banks[cur_bank_ind];
		cur_bank_start = cur_phys_bank->base_addr;
		if (cur_phys_bank->pages_num == 0) {
			BOOT_BUG("Node #%d: empty physical memory bank #%d\n"
				 " cannot be at the node list",
				 node, cur_bank_ind);
			return;
		}
		DebugBank("Node #%d bank cur #%d prev #%d from 0x%lx new end 0x%lx\n",
			  node, cur_bank_ind, prev_bank_ind,
			  cur_bank_start, new_bank_end);
		if (new_bank_end <= cur_bank_start)
			/* new bank should be added before current */
			break;
		prev_bank_ind = cur_bank_ind;
	}

	if (node_mem->banks_num > 0) {
		node_start = node_mem->start_pfn << PAGE_SHIFT;
		node_end = node_start + (node_mem->pfns_num << PAGE_SHIFT);
	} else {
		node_start = -1UL;
		node_end = 0;
	}
	DebugBank("Node #%d : before add bunk #%d\n"
		  "start 0x%lx end 0x%lx pfns 0x%lx, banks %d\n",
		  node, new_bank_ind, node_start, node_end,
		  node_mem->pfns_num, node_mem->banks_num);
	if (prev_bank_ind < 0) {
		/* new bank should be first entry in the list */

		if (node_mem->first_bank < 0) {
			/* it is first bank on the node */
			if (new_bank_start > node_start) {
				BOOT_BUG("Node #%d : added bank #%d is first on node,\n"
					 " so its start 0x%lx should be below node start 0x%lx\n",
					 node, new_bank_ind,
					 new_bank_start, node_start);
			}
			if (new_bank_end < node_end) {
				BOOT_BUG("Node #%d : added bank #%d is first on node\n"
					 "its end 0x%lx should be above node end 0x%lx\n",
					 node, new_bank_ind,
					 new_bank_end, node_end);
			}
			node_mem->start_pfn = new_bank_start >> PAGE_SHIFT;
			node_mem->pfns_num = new_phys_bank->pages_num;
			node_start = new_bank_start;
			node_end = new_bank_end;
			DebugBank("Node #%d : added bank #%d is first on node,\n"
				  " node is now from 0x%lx to 0x%lx pfns 0x%lx\n",
				  node, new_bank_ind, node_start, node_end,
				  node_mem->pfns_num);
		} else {
			/* it is not last on the node, correcr only node */
			/* start and size */
			e2k_phys_bank_t *next_phys_bank;

			if (new_bank_end >= node_end) {
				BOOT_BUG("Node #%d added bank #%d should be at head of banks,\n"
					 " but bank end 0x%lx is above of node end 0x%lx\n",
					 node, new_bank_ind,
					 new_bank_end, node_end);
			}
			next_phys_bank = &node_mem->banks[node_mem->first_bank];
			node_mem->start_pfn = new_bank_start >> PAGE_SHIFT;
			node_mem->pfns_num += (next_phys_bank->base_addr - new_bank_start) >>
								PAGE_SHIFT;
			node_start = new_bank_start;
			DebugBank("Node #%d : added bunk #%d is at the head of node,\n"
				  " next bank #%d, node start 0x%lx end 0x%lx pfns 0x%lx\n",
				  node, new_bank_ind, node_mem->first_bank,
				  node_start, node_end, node_mem->pfns_num);
		}
		/* insert bank at the node list of all banks */
		new_phys_bank->next = node_mem->first_bank;
		node_mem->first_bank = new_bank_ind;
	} else {
		/* add new bank in the list after previous */
		e2k_phys_bank_t *prev_phys_bank;

		prev_phys_bank = &phys_banks[prev_bank_ind];

		if (node_start >= new_bank_start) {
			BOOT_BUG("Node #%d : added bank #%d from 0x%lx\n"
				 " below node start address 0x%lx\n",
				 node, new_bank_ind, new_bank_start,
				 node_start);
		}
		if (prev_phys_bank->next < 0) {
			/* added bank will be last bank on the node, */
			/* correct node end or size */
			if (node_end >= new_bank_end) {
				BOOT_BUG("Node #%d : added bank #%d wiil be last on node,\n"
					 "its end 0x%lx should be above node end 0x%lx\n",
					 node, new_bank_ind,
					 new_bank_end, node_end);
			}
			node_mem->pfns_num +=
			    ((new_bank_end - node_end) >> PAGE_SHIFT);
			node_end = new_bank_end;
			DebugBank("Node #%d : added bunk #%d is last on node, previous bank #%d\n"
				  " node start 0x%lx end 0x%lx pfns 0x%lx\n",
				  node, new_bank_ind, prev_bank_ind,
				  node_start, node_end, node_mem->pfns_num);
		} else {
			/* added bank is into midle of banks list, */
			/* so node start and end should not change */
			if (node_end <= new_bank_end) {
				BOOT_BUG("Node #%d : added bank #%d is not last on node\n"
					 "its end 0x%lx should be below node end 0x%lx\n",
					 node, new_bank_ind,
					 new_bank_end, node_end);
			}
			DebugBank("Node #%d : added bunk #%d is at midle of bank list\n"
				  " previous bank #%d , next %d,\n"
				  " node start 0x%lx end 0x%lx pfns 0x%lx\n",
				  node, new_bank_ind, prev_bank_ind,
				  prev_phys_bank->next,
				  node_start, node_end, node_mem->pfns_num);
		}
		/* insert new bank at midle of the node list of banjs */
		new_phys_bank->next = prev_phys_bank->next;
		prev_phys_bank->next = new_bank_ind;
	}
	node_mem->banks_num++;
}

/* node bank management lock should be taken by caller */
short __init_recv boot_init_new_phys_bank(int node, node_phys_mem_t *node_mem,
					  e2k_addr_t bank_start,
					  e2k_size_t bank_size)
{
	e2k_phys_bank_t *new_phys_bank;
	short new_bank_ind;

	new_bank_ind = boot_get_free_phys_bank(node, node_mem);
	if (new_bank_ind < 0) {
		BOOT_WARNING("Node #%d: could not find empty bank entry to add one more bank",
			     node);
		return new_bank_ind;
	}
	new_phys_bank = &node_mem->banks[new_bank_ind];
	new_phys_bank->base_addr = bank_start;
	new_phys_bank->pages_num = bank_size >> PAGE_SHIFT;
	atomic64_set(&new_phys_bank->free_pages_num, new_phys_bank->pages_num);
	new_phys_bank->busy_areas = boot_vp_to_pp((e2k_busy_mem_t *)
						  new_phys_bank->busy_areas_prereserved);
	new_phys_bank->busy_areas_num = 0;
	new_phys_bank->first_area = -1;

	return new_bank_ind;
}

/* node bank management lock should be taken by caller */
short __init boot_create_new_phys_bank(int node, node_phys_mem_t *node_mem,
				       e2k_addr_t bank_start,
				       e2k_size_t bank_size)
{
	e2k_phys_bank_t *new_phys_bank;
	short new_bank_ind;

	new_bank_ind = boot_init_new_phys_bank(node, node_mem,
					       bank_start, bank_size);
	if (new_bank_ind < 0)
		/* could not find new empty bank */
		return new_bank_ind;
	new_phys_bank = &node_mem->banks[new_bank_ind];

	boot_add_new_phys_bank(node, node_mem, new_phys_bank, new_bank_ind);

	if (bank_start < boot_start_of_phys_memory)
		boot_start_of_phys_memory = bank_start;
	if (boot_end_of_phys_memory < bank_start + bank_size)
		boot_end_of_phys_memory = bank_start + bank_size;

	return new_bank_ind;
}

/* node bank management lock should be taken by caller */
/* should return source bank index in the list of node banks */
/* after deleting the bank from list its index should be -1 */
/* as flag of free entry */
static inline short __init_recv
boot_delete_phys_bank(int node_id, node_phys_mem_t *node_mem,
		      short bank, e2k_phys_bank_t *phys_bank)
{
	e2k_addr_t bank_start, bank_end;
	e2k_addr_t node_start_pfn, node_end_pfn;
	e2k_addr_t node_start, node_end;
	short prev_bank_ind;

	if (phys_bank->busy_areas_num != 0) {
		BOOT_BUG("Node #%d bank #%d: could not be deleted\n"
			 " because of is not empty (%d entries) list of busy areas\n",
			 node_id, bank, phys_bank->busy_areas_num);
	}

	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	DebugBank("node #%d bank #%d from 0x%lx to 0x%lx:\n"
		  "should be deleted fully\n",
		node_id, bank, bank_start, bank_end);

	/* delete bank from list of all node banks */
	prev_bank_ind = boot_find_node_phys_bank(node_id, node_mem, bank);
	node_start_pfn = node_mem->start_pfn;
	node_end_pfn = node_start_pfn + node_mem->pfns_num;
	node_start = node_start_pfn << PAGE_SHIFT;
	node_end = node_end_pfn << PAGE_SHIFT;

	DebugBank("Node #%d : before delete bank #%d is from 0x%lx to 0x%lx, pfns 0x%lx, banks num %d\n",
		  node_id, bank, node_start, node_end,
		  node_mem->pfns_num, node_mem->banks_num);

	if (prev_bank_ind < 0) {
		/* the deleted bank or part is at the head of the list */
		if (node_mem->first_bank != bank) {
			BOOT_BUG("Node #%d: head of list of node banks points to bank #%d, but should point to #%d\n",
				 node_id, node_mem->first_bank, bank);
		}
		if (node_start != bank_start) {
			BOOT_BUG("Node #%d : deleted bank #%d from 0x%lx should start from node start 0x%lx\n",
				 node_id, bank, bank_start, node_start);
		}
		if (phys_bank->next < 0) {
			/* it is last bank on the node */
			if (node_end != bank_end) {
				BOOT_BUG("Node #%d : deleted bank #%d is last on node, so its end 0x%lx should be equal to node end 0x%lx\n",
					 node_id, bank, bank_end, node_end);
			}
			node_mem->pfns_num = 0;
			node_start = -1UL;
			node_end = 0;
		} else {
			/* it is not last on the node, correcr start and end */
			/* to next banks */
			e2k_phys_bank_t *next_phys_bank;

			next_phys_bank = &node_mem->banks[phys_bank->next];
			node_mem->start_pfn = next_phys_bank->base_addr >> PAGE_SHIFT;
			node_mem->pfns_num -=
				((next_phys_bank->base_addr - node_start) >> PAGE_SHIFT);
			node_start = next_phys_bank->base_addr;
			DebugBank("Node #%d : deleted bunk #%d is at the head of node, new head is now bank #%d, node start 0x%lx end 0x%lx pfns 0x%lx\n",
				  node_id, bank, phys_bank->next,
				  node_start, node_end, node_mem->pfns_num);
		}
		node_mem->first_bank = phys_bank->next;
	} else {
		/* the deleted bank is after current bank */
		e2k_phys_bank_t *prev_phys_bank;

		prev_phys_bank = &node_mem->banks[prev_bank_ind];
		if (node_mem->first_bank == bank) {
			BOOT_BUG("Node #%d: head of list of node banks points to bank #%d, but should point to other\n",
				 node_id, node_mem->first_bank);
		}
		if (node_start >= bank_start) {
			BOOT_BUG("Node #%d : deleted bank #%d from 0x%lx below node start address 0x%lx\n",
				 node_id, bank, bank_start, node_start);
		}
		if (phys_bank->next < 0) {
			/* deleted bank is last bank on the node, */
			/* correct node end to previous bank */
			if (node_end != bank_end) {
				BOOT_BUG("Node #%d : deleted bank #%d is last on node, so its end 0x%lx should be equal to node end 0x%lx\n",
					 node_id, bank, bank_end, node_end);
			}
			node_mem->pfns_num = ((prev_phys_bank->base_addr -
			      node_start) >> PAGE_SHIFT) + prev_phys_bank->pages_num;
			node_end = prev_phys_bank->base_addr +
			    (prev_phys_bank->pages_num << PAGE_SHIFT);
			DebugBank("Node #%d : deleted bunk #%d is last on node, new last is now bank #%d, node start 0x%lx end 0x%lx pfns 0x%lx\n",
				  node_id, bank, prev_bank_ind,
				  node_start, node_end, node_mem->pfns_num);
		} else {
			/* deleted area is into midle of banks list, */
			/* so node start and end should not change */
			if (node_end <= bank_end) {
				BOOT_BUG("Node #%d : deleted bank #%d is not last on node, so its end 0x%lx should be below node end 0x%lx\n",
					 node_id, bank, bank_end, node_end);
			}
			DebugBank("Node #%d : deleted bunk #%d is at midle of bank list, previous bank #%d , next %d, node start 0x%lx end 0x%lx pfns 0x%lx\n",
				  node_id, bank, prev_bank_ind, phys_bank->next,
				  node_start, node_end, node_mem->pfns_num);
		}
		prev_phys_bank->next = phys_bank->next;
	}
	node_mem->banks_num--;
	phys_bank->next = -1;
	phys_bank->pages_num = 0;

	DebugBank("Node #%d : after delete bank #%d is from 0x%lx to 0x%lx, pfns 0x%lx, banks num %d\n",
		  node_id, bank, node_start, node_end,
		  node_mem->pfns_num, node_mem->banks_num);

	return -1;		/* the bank is deleted from list */
}

/* should return source low bank index, which can be updated while truncating */
/* but now number should not be changed */
short __init_recv boot_delete_phys_bank_part(int node_id,
					     node_phys_mem_t *node_mem,
					     short bank,
					     e2k_phys_bank_t *phys_bank,
					     e2k_addr_t from_addr,
					     e2k_addr_t to_addr)
{
	e2k_addr_t bank_start, bank_end;
	e2k_addr_t node_start, node_end;
	e2k_size_t pages_del;
	e2k_busy_mem_t *busy_area;
	short prev_bank_ind;
	short area;

	if (from_addr >= to_addr) {
		BOOT_BUG("Node #%d bank #%d: area to truncate from 0x%lx is above or equal to 0x%lx\n",
			 node_id, bank, from_addr, to_addr);
	}
	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	if (from_addr != bank_start) {
		BOOT_BUG("Node #%d bank #%d: area to truncate from 0x%lx to 0x%lx is not started from bank base 0x%lx\n",
			 node_id, bank, from_addr, to_addr, bank_start);
	}
	pages_del = (to_addr - from_addr) >> PAGE_SHIFT;
	if (pages_del > phys_bank->pages_num) {
		BOOT_BUG("Node #%d bank #%d: area to truncate from 0x%lx to 0x%lx is out of bank from 0x%lx to 0x%lx\n",
			 node_id, bank, from_addr, to_addr,
			 bank_start, bank_end);
	}
	if (pages_del == phys_bank->pages_num)
		/* bank should be deleted fully */
		return boot_delete_phys_bank(node_id,
					     node_mem, bank, phys_bank);

	DebugBank("node #%d bank #%d from 0x%lx to 0x%lx: should be truncated partially from 0x%lx to 0x%lx\n",
		  node_id, bank, bank_start, bank_end, from_addr, to_addr);

	/* loop on busy areas of bank to update start page of the area */
	/* because of bank base address change */
	for (area = phys_bank->first_area; area >= 0; area = busy_area->next) {
		busy_area = &phys_bank->busy_areas[area];
		DebugBank("Node #%d bank #%d busy area #%d from 0x%lx to 0x%lx\n",
			  node_id, bank, area,
			  bank_start + (busy_area->start_page << PAGE_SHIFT),
			  bank_start + ((busy_area->start_page +
					 busy_area->pages_num) << PAGE_SHIFT));
		if (busy_area->pages_num == 0) {
			BOOT_BUG("Node #%d bank #%d : empty physical memory usy area #%d cannot be in the list",
				 node_id, bank, area);
			continue;
		}
		if (busy_area->start_page < pages_del) {
			BOOT_BUG("Node #%d bank #%d busy area #%d from 0x%lx to 0x%lx cannot intersect truncated part from 0x%lx to 0x%lx\n",
				 node_id, bank, area,
				 bank_start + (busy_area->start_page << PAGE_SHIFT),
				 bank_start + ((busy_area->start_page +
							busy_area->pages_num) << PAGE_SHIFT),
				 from_addr, to_addr);
			continue;
		}
		busy_area->start_page -= pages_del;
		DebugBank("Node #%d bank #%d updated busy area #%d is now from 0x%lx to 0x%lx\n",
			  node_id, bank, area,
			  to_addr + (busy_area->start_page << PAGE_SHIFT),
			  to_addr + ((busy_area->start_page +
				      busy_area->pages_num) << PAGE_SHIFT));
	}

	/* now truncate begining part of bank and correct bank & node */
	/* start, end or size */
	prev_bank_ind = boot_find_node_phys_bank(node_id, node_mem, bank);
	node_start = node_mem->start_pfn << PAGE_SHIFT;
	node_end = (node_mem->start_pfn + node_mem->pfns_num) << PAGE_SHIFT;
	if (prev_bank_ind < 0) {
		/* the truncated bank is at the head of the list */
		if (node_mem->first_bank != bank) {
			BOOT_BUG("Node #%d: head of list of node banks points to bank #%d, but should point to #%d\n",
				 node_id, node_mem->first_bank, bank);
		}
		if (node_start != bank_start) {
			BOOT_BUG("Node #%d : truncated bank #%d from 0x%lx should start from node start 0x%lx\n",
				 node_id, bank, bank_start, node_start);
		}
		if (phys_bank->next < 0) {
			/* it is last bank on the node */
			if (node_end != bank_end) {
				BOOT_BUG("Node #%d : truncated bank #%d is last on node, so its end 0x%lx should be equal to node end 0x%lx\n",
					 node_id, bank, bank_end, node_end);
			}
		}
		/* correcr start & size of node on truncated size */
		/* to point to new bank start and tructated pages number */
		node_mem->start_pfn += pages_del;
		node_mem->pfns_num -= pages_del;
		node_start = to_addr;
	} else {
		/* the truncated bank is after current bank */
		/* so truncated pages transform to hole and node start & end */
		/* are not changed */
		if (node_mem->first_bank == bank) {
			BOOT_BUG("Node #%d: head of list of node banks points to bank #%d, but should point to other\n",
				 node_id, node_mem->first_bank);
		}
		if (node_start >= bank_start) {
			BOOT_BUG("Node #%d : truncated bank #%d from 0x%lx below node start address 0x%lx\n",
				 node_id, bank, bank_start, node_start);
		}
		if (phys_bank->next < 0) {
			/* truncated bank is last bank on the node */
			if (node_end != bank_end) {
				BOOT_BUG("Node #%d : truncated bank #%d is last on node, so its end 0x%lx should be equal to node end 0x%lx\n",
					 node_id, bank, bank_end, node_end);
			}
		} else {
			/* truncated area is into midle of banks list, */
			if (node_end <= bank_end) {
				BOOT_BUG("Node #%d : truncated bank #%d is not last on node, so its end 0x%lx should be below node end 0x%lx\n",
					 node_id, bank, bank_end, node_end);
			}
		}
	}

	/* correct bank base address and size on truncated pages */
	/* truncated area can not be reserved, so number of free pages */
	/* should be decremented on truncated pages number */
	phys_bank->base_addr = to_addr;
	phys_bank->pages_num -= pages_del;
	atomic64_sub(pages_del, &phys_bank->free_pages_num);

	DebugBank("node #%d truncated bank #%d is now from 0x%lx to 0x%lx, free pages 0x%lx\n",
		  node_id, bank, phys_bank->base_addr,
		  phys_bank->base_addr + (phys_bank->pages_num << PAGE_SHIFT),
		  atomic64_read(&phys_bank->free_pages_num));

	DebugBank("Node #%d : after truncating bank #%d is from 0x%lx to 0x%lx, pfns with holes 0x%lx\n",
		  node_id, bank, node_start, node_end, node_mem->pfns_num);

	return bank;
}

/* should return source low bank index, which can be updated while creation */
/* but now number should not be changed */
short __init boot_create_phys_bank_part(int node_id, node_phys_mem_t *node_mem,
					short bank, e2k_phys_bank_t *phys_bank,
					e2k_addr_t from_addr,
					e2k_addr_t to_addr)
{
	boot_phys_bank_t *node_banks;
	e2k_phys_bank_t *new_phys_bank;
	e2k_addr_t bank_start, bank_end;
	e2k_size_t pages;
	e2k_busy_mem_t *busy_area;
	short new_bank, old_bank;
	short area, next_area;

	if (from_addr >= to_addr) {
		BOOT_BUG("Node #%d bank #%d: area to create from 0x%lx is above or equal to 0x%lx\n",
			 node_id, bank, from_addr, to_addr);
	}
	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	if (from_addr != bank_start) {
		BOOT_BUG("Node #%d bank #%d: area to create from 0x%lx to 0x%lx is not started from bank base 0x%lx\n",
			 node_id, bank, from_addr, to_addr, bank_start);
	}
	pages = (to_addr - from_addr) >> PAGE_SHIFT;
	if (pages > phys_bank->pages_num) {
		BOOT_BUG("Node #%d bank #%d: area to create from 0x%lx to 0x%lx is out of bank from 0x%lx to 0x%lx\n",
			 node_id, bank, from_addr, to_addr,
			 bank_start, bank_end);
	}
	if (pages == phys_bank->pages_num)
		/* new bank should be created from source bank fully */
		/* and source bank will be empty, so it does not need */
		/* devide source bank on two part, create real new bank, */
		/* the source bank is now as new, the old source bank */
		/* is now empty and as deleted */
		return -1;	/* no longer source bank */

	new_bank = boot_init_new_phys_bank(node_id, node_mem,
					   from_addr, to_addr - from_addr);
	if (new_bank < 0) {
		BOOT_WARNING("Node #%d: could not create new bank from 0x%lx to 0x%lx for unremapped area of bank #%d",
			     node_id, from_addr, to_addr, bank);
		return new_bank;
	}
	node_banks = node_mem->banks;
	new_phys_bank = &node_banks[new_bank];
	DebugBank("Node #%d: created new bank #%d from 0x%lx to 0x%lx for unremapped area of bank #%d\n",
		  node_id, new_bank, from_addr, to_addr, bank);

	/* loop on unremapable areas of memory bank to remap them */
	/* to created new memory bank */
	for (area = phys_bank->first_area; area >= 0; area = next_area) {
		e2k_size_t start, end;

		busy_area = &phys_bank->busy_areas[area];
		if (busy_area->pages_num == 0) {
			BOOT_BUG("Node #%d low bank #%d empty physical memory busy area #%d cannot be in the list",
				 node_id, bank, area);
		}
		start = busy_area->start_page;
		end = start + busy_area->pages_num;
		if (from_addr + (start << PAGE_SHIFT) >= to_addr) {
			DebugBank("Node #%d bank #%d current area #%d from 0x%lx to 0x%lx is out of unremable range\n",
				  node_id, bank, area,
				  from_addr + (start << PAGE_SHIFT),
				  from_addr + (end << PAGE_SHIFT));
			break;
		}
		DebugBank("Node #%d bank #%d current unremapable area #%d from 0x%lx to 0x%lx\n",
			  node_id, bank, area,
			  from_addr + (start << PAGE_SHIFT),
			  from_addr + (end << PAGE_SHIFT));

		/* remapping of some area should delete it from list of areas */
		/* so save reference to next entry of the list before */
		next_area = busy_area->next;

		if (start >= phys_bank->pages_num || end > phys_bank->pages_num) {
			BOOT_BUG("Node #%d bank #%d area #%d start 0x%lx or end 0x%lx is out of bank size 0x%lx\n",
				 node_id, bank, area, start, end,
				 phys_bank->pages_num);
		}

		boot_rereserve_bank_area(node_id, node_mem,
					 bank, new_bank, area, busy_area);
	}

	/* now old bank (or part of bank) can be deleted */
	old_bank = boot_delete_phys_bank_part(node_id, node_mem,
					      bank, phys_bank, from_addr,
					      to_addr);
	if (old_bank < 0) {
		BOOT_BUG("Node #%d low bank #%d could not be empty after delete its part from 0x%lx to 0x%lx\n",
			 node_id, bank, from_addr, to_addr);
	}

	/* insert new bank of unremapable low memory at the list */
	boot_add_new_phys_bank(node_id, node_mem, new_phys_bank, new_bank);

	return old_bank;
}

static int __init boot_bios_probe_node_memory(boot_info_t *bootblock, int node,
			node_phys_mem_t *node_mem, e2k_size_t *phys_memory_size)
{
	bank_info_t *bank_info;
	struct bank_iterator iter;
	e2k_phys_bank_t *phys_banks = node_mem->banks;
	e2k_size_t node_memory_size = 0;
	int bank_num = 0;

	node_mem->first_bank = -1;	/* initial state: empty list */

	for_each_node_bank(bank_info, iter, node, bootblock) {
		e2k_size_t bank_size;
		e2k_addr_t bank_start;
		e2k_phys_bank_t *new_phys_bank;
		short new_bank_ind;

		if (*phys_memory_size + node_memory_size >= boot_mem_limit) {
			BOOT_WARNING("Node #%d: total memory size 0x%lx exceeds permissible limit 0x%lx, ignored",
				     node, *phys_memory_size + node_memory_size,
				     boot_mem_limit);
			continue;
		}
		if (node_memory_size >= boot_node_mem_limit) {
			BOOT_WARNING("Node #%d bank memory size 0x%lx exceeds permissible node limit 0x%lx, ignored",
				     node, node_memory_size, boot_node_mem_limit);
			continue;
		}

		bank_start = bank_info->address;
		bank_size = bank_info->size;

		if (!PAGE_ALIGNED(bank_start) || !PAGE_ALIGNED(bank_size)) {
			BOOT_BUG("Node #%d: phys bank 0x%lx+0x%lx is not page aligned",
				node, bank_start, bank_size);
		}

		if (*phys_memory_size + node_memory_size + bank_size > boot_mem_limit) {
			bank_size = boot_mem_limit - (*phys_memory_size + node_memory_size);
			boot_printk("Node #%d: phys bank size is reduced to 0x%lx bytes\n",
				node, bank_size);
		}

		if (node_memory_size + bank_size > boot_node_mem_limit) {
			bank_size = boot_node_mem_limit - node_memory_size;
			boot_printk("Node #%d: phys bank size is reduced to 0x%lx bytes\n",
				node, bank_size);
		}

		new_bank_ind = boot_create_new_phys_bank(node, node_mem,
							 bank_start, bank_size);
		if (new_bank_ind < 0) {
			BOOT_WARNING("Node #%d: could not find empty bank entry to add one more physical memory bank",
				     node);
			break;
		}
		new_phys_bank = &phys_banks[new_bank_ind];
		bank_num++;
		node_memory_size += bank_size;
		boot_printk("Node #%d: phys bank (list index %d) address 0x%lx, size 0x%lx pages (0x%lx bytes)\n",
			    node, new_bank_ind,
			    new_phys_bank->base_addr, new_phys_bank->pages_num,
			    new_phys_bank->pages_num * PAGE_SIZE);
	}

	*phys_memory_size += node_memory_size;

	return bank_num;
}

/*
 * Probe physical memory configuration of the machine and fill the array of
 * structures of physical memory banks 'e2k_phys_bank'.
 * It is better to merge contiguous memory banks for allocation goals.
 * Base address of a bank should be page aligned.
 */
void __init boot_bios_probe_memory(node_phys_mem_t *nodes_phys_mem, boot_info_t *bootblock)
{
	unsigned long nodes_map = 0;
	unsigned long node_mask;
	int bank_num = 0;
	int node;
	e2k_size_t phys_memory_size = 0;

#ifndef	CONFIG_SMP
	boot_phys_nodes_num = 1;
	boot_phys_nodes_map = 0x1;
#endif /* CONFIG_SMP */

	for (node_mask = 0x1UL, node = 0; node < L_MAX_MEM_NUMNODES; node_mask <<= 1, node++) {
		node_phys_mem_t *node_mem = &nodes_phys_mem[node];
		bank_info_t *node_bank;

		if (phys_memory_size >= boot_mem_limit)
			break;

		node_bank = boot_get_first_node_bank(bootblock, node);
		if (node_bank == NULL)
			goto next_node;	/* node has not memory */

		if (!(boot_phys_nodes_map & node_mask) && BOOT_HAS_MACHINE_L_SIC) {
			BOOT_WARNING("Node #%d is not online but has not empty memory bank address 0x%lx, size 0x%lx, ignored",
				     node, node_bank->address,
				     node_bank->size);
			goto next_node;
		}
		if ((!BOOT_HAS_MACHINE_E2K_FULL_SIC) && node != 0) {
			BOOT_WARNING("Machine can have only one node #0, but memory node #%d has not empty phys bank address 0x%lx, size 0x%lx, ignored",
				     node, node_bank->address, node_bank->size);
			goto next_node;
		}

		nodes_map |= node_mask;

		bank_num += boot_bios_probe_node_memory(bootblock, node, node_mem,
					&phys_memory_size);

next_node:
		boot_printk("Node #%d: banks num %d, first bank index %d start pfn 0x%lx, size 0x%lx pfns, current phys memory total size is %d MiB\n",
			node, node_mem->banks_num, node_mem->first_bank,
			node_mem->start_pfn, node_mem->pfns_num,
			phys_memory_size / (1024 * 1024));
	}

	if (boot_mem_limit != -1UL && boot_node_mem_limit != -1UL &&
		bootblock->num_of_banks != 0 && bootblock->num_of_banks != bank_num) {
		BOOT_WARNING("Number of banks of physical memory passed by boot loader %d is not the same as banks at boot_info structure %d",
			bootblock->num_of_banks, bank_num);
	}
	if (nodes_map == 0) {
		BOOT_BUG("Empty online nodes map passed by boot loader at boot_info structure");
	}
	if (boot_phys_nodes_map && ((boot_phys_nodes_map & nodes_map) != nodes_map)) {
		BOOT_BUG("Calculated map of nodes with memory 0x%lx contains node(s) out of total nodes map 0x%lx",
			 nodes_map, boot_phys_nodes_map);
	}
	if (boot_phys_nodes_map & ~((1 << L_MAX_MEM_NUMNODES) - 1)) {
		BOOT_WARNING("Probably some nodes 0x%lx out of memory max nodes range 0x%lx contain memory, but cannot be accounted",
			     boot_phys_nodes_map,
			     (1 << L_MAX_MEM_NUMNODES) - 1);
	}

	boot_phys_mem_nodes_map = nodes_map;
	boot_totalram_real_pages = phys_memory_size / PAGE_SIZE;
	boot_printk("Phys memory total size is %d Mgb\n",
		    phys_memory_size / (1024 * 1024));
}

void __init boot_native_loader_probe_memory(node_phys_mem_t *nodes_phys_mem,
				boot_info_t *bootblock)
{
	if (bootblock->signature != BOOTBLOCK_ROMLOADER_SIGNATURE &&
	    bootblock->signature != BOOTBLOCK_BOOT_SIGNATURE) {
		BOOT_BUG("Unknown type of Boot information structure");
	}

	boot_bios_probe_memory(nodes_phys_mem, bootblock);
}

static void __init boot_probe_memory(boot_info_t *boot_info)
{
	node_phys_mem_t *all_phys_banks = NULL;

	all_phys_banks = boot_vp_to_pp((node_phys_mem_t *) nodes_phys_mem);
	boot_fast_memset(all_phys_banks, 0x00, sizeof(*all_phys_banks));

	boot_loader_probe_memory(all_phys_banks, boot_info);
}

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM

static bank_info_t * __init_recv boot_find_low_pa_bank(
		e2k_addr_t lo_pa, boot_info_t *bootblock, int node)
{
	struct bank_iterator iter;
	bank_info_t *bank;

	for_each_node_bank(bank, iter, node, bootblock) {
		u64 bank_start = bank->address;
		u64 bank_end = bank_start + bank->size;

		/* Check for low address bank */
		if (lo_pa >= bank_start && lo_pa < bank_end)
			return bank;
	}

	return NULL;
}

static bank_info_t * __init_recv boot_find_high_pa_bank(bank_info_t *low_bank,
		bool above, boot_info_t *bootblock, int node)
{
	u64 low_start = low_bank->address;
	u64 low_end = low_start + low_bank->size;
	struct bank_iterator iter;
	bank_info_t *bank;

	for_each_node_bank(bank, iter, node, bootblock) {
		u64 bank_start = bank->address;
		u64 bank_end = bank_start + bank->size;

		if (is_addr_from_low_memory(bank_end - 1))
			/* it is low memory bank, ignore */
			continue;

		/* Check for high address bank */
		if (above) {
			/* contiguity should be from low end to high start */
			if (bank_start == (low_end | (bank_start & ~LOW_PHYS_MEM_MASK)))
				return bank;
		} else {
			/* contiguity should be from high end to low start */
			if (bank_end == (low_start | (bank_end & ~LOW_PHYS_MEM_MASK)))
				return bank;
		}
	}

	return NULL;
}

static inline bank_info_t * __init_recv boot_find_above_high_pa_bank(
		bank_info_t *low_bank, boot_info_t *bootblock, int node)
{
	return boot_find_high_pa_bank(low_bank, true /* i.e. above */,
				      bootblock, node);
}

static inline bank_info_t * __init_recv boot_find_below_high_pa_bank(
		bank_info_t *low_bank, boot_info_t *bootblock, int node)
{
	return boot_find_high_pa_bank(low_bank, false /* i.e. below */,
				      bootblock, node);
}

static e2k_addr_t __init_recv
boot_node_pa_to_high_pa(e2k_addr_t pa, boot_info_t *bootblock)
{
	bank_info_t *lo_bank_info = NULL;
	bank_info_t *below_hi_bank_info;
	bank_info_t *above_hi_bank_info;
	e2k_addr_t lo_pa_offset;
	e2k_addr_t hi_pa;
	int node;

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		bank_info_t *node_bank;

		node_bank = boot_get_first_node_bank(bootblock, node);
		if (node_bank == NULL)
			continue;	/* node has not memory */

		lo_bank_info = boot_find_low_pa_bank(pa, bootblock, node);
		if (lo_bank_info != NULL)
			/* low address bank is found */
			break;
	}
	if (lo_bank_info == NULL)
		/* could not find low memory bank for source low address */
		return -1;
	lo_pa_offset = pa - lo_bank_info->address;

	below_hi_bank_info = boot_find_below_high_pa_bank(lo_bank_info,
							  bootblock, node);
	above_hi_bank_info = boot_find_above_high_pa_bank(lo_bank_info, bootblock, node);
	if (below_hi_bank_info == NULL && above_hi_bank_info == NULL) {
		/* could not find high memory bank from which low area */
		/* was cut out */
		return -1;
	}
	if (below_hi_bank_info == NULL) {
		/* low area was cut out from the very beginning of high bank */
		hi_pa = above_hi_bank_info->address - lo_bank_info->size + lo_pa_offset;
		if ((hi_pa - lo_pa_offset) + lo_bank_info->size +
		    above_hi_bank_info->size !=
		    above_hi_bank_info->address + above_hi_bank_info->size) {
			BOOT_WARNING("high address calculated from begining "
				     "of the above area 0x%lx + low area size 0x%lx "
				     "+ high area size is not equal to address "
				     "of bank end 0x%lx\n",
				     hi_pa - lo_pa_offset, lo_bank_info->size,
				     above_hi_bank_info->size,
				     above_hi_bank_info->address +
				     above_hi_bank_info->size);
			return -1;
		}
		return hi_pa;
	}
	if (above_hi_bank_info == NULL) {
		/* low area was cut out from the very ending of high bank */
		hi_pa = below_hi_bank_info->address + below_hi_bank_info->size + lo_pa_offset;
		if ((hi_pa - lo_pa_offset) + lo_bank_info->size !=
		    below_hi_bank_info->address + below_hi_bank_info->size + lo_bank_info->size) {
			BOOT_WARNING("high address calculated from ending "
				     "of the below area 0x%lx + low area size 0x%lx "
				     "is not equal to address "
				     "of bank merged end 0x%lx\n",
				     hi_pa - lo_pa_offset, lo_bank_info->size,
				     below_hi_bank_info->address + below_hi_bank_info->size +
					lo_bank_info->size);
			return -1;
		}
		return hi_pa;
	}
	if (below_hi_bank_info == above_hi_bank_info) {
		/* below and above banks are the same bank, */
		/* it can be if start of low area is aligned to the bank end */
		/* so low area was cut out from the beginning of the bank */
		hi_pa = above_hi_bank_info->address - lo_bank_info->size +
		    lo_pa_offset;
		if ((hi_pa - lo_pa_offset) + lo_bank_info->size +
		    above_hi_bank_info->size !=
		    above_hi_bank_info->address + above_hi_bank_info->size) {
			BOOT_WARNING("high address calculated from begining "
				     "of the same area 0x%lx + low area size 0x%lx "
				     "+ high area size is not equal to address "
				     "of bank end 0x%lx\n",
				     hi_pa - lo_pa_offset, lo_bank_info->size,
				     above_hi_bank_info->size,
				     above_hi_bank_info->address + above_hi_bank_info->size);
			return -1;
		}
		return hi_pa;
	}

	/* low area was cut out from the middle of high bank */
	/* (from ending of below and to beginning of above) */
	hi_pa = below_hi_bank_info->address + below_hi_bank_info->size +
	    lo_pa_offset;
	if (hi_pa != above_hi_bank_info->address -
	    lo_bank_info->size + lo_pa_offset) {
		BOOT_WARNING("high address calculated from ending of below "
			     "area 0x%lx is not equal 0x%lx : address calculated "
			     "from beginning of above area\n",
			     hi_pa,
			     above_hi_bank_info->address - lo_bank_info->size + lo_pa_offset);
		return -1;
	}
	return hi_pa;
}

void *__init_recv boot_pa_to_high_pa(void *pa, boot_info_t * bootblock)
{
	e2k_addr_t lo_pa = (e2k_addr_t) pa;
	e2k_addr_t hi_pa;

	if (likely(is_addr_from_high_memory(lo_pa))) {
		/* address is already from high area */
		DebugLoHi("physical address 0x%lx is already from high "
			  "addresses range\n", lo_pa);
		return pa;
	}
	if (BOOT_LOW_MEMORY_ENABLED()) {
		/* conversion is disabled. return source address */
		DebugLoHi("physical address 0x%lx conversion is disabled\n",
			  lo_pa);
		return pa;
	}
	hi_pa = boot_node_pa_to_high_pa(lo_pa, bootblock);
	if (hi_pa == (e2k_addr_t) - 1) {
		if (boot_has_high_memory(bootblock)) {
			BOOT_WARNING("could not convert low physical "
				     "address 0x%lx to equivalent from high range",
				     lo_pa);
		}
		return pa;
	} else {
		DebugLoHi("low physical address 0x%lx is converted "
			  "to 0x%lx from  high addresses range\n",
			  lo_pa, hi_pa);
	}
	return (void *)hi_pa;
}

bool __init boot_has_lo_bank_remap_to_hi(boot_phys_bank_t * phys_bank,
					 boot_info_t * boot_info)
{
	e2k_addr_t bank_start, bank_end;
	e2k_addr_t bank_start_hi, bank_end_hi;

	bank_start = phys_bank->base_addr;
	bank_end = bank_start + (phys_bank->pages_num << PAGE_SHIFT);
	bank_start_hi = (e2k_addr_t) boot_pa_to_high_pa((void *)bank_start, boot_info);
	bank_end_hi = (e2k_addr_t) boot_pa_end_to_high((void *)bank_end, boot_info);
	if (bank_start_hi == bank_start || bank_end_hi == bank_end)
		return false;
	return true;
}

#endif /* CONFIG_ONLY_HIGH_PHYS_MEM */

e2k_size_t __init boot_native_get_bootblock_size(const boot_info_t *bblock)
{
	switch (bblock->signature) {
	case BOOTBLOCK_ROMLOADER_SIGNATURE:
	case BOOTBLOCK_BOOT_SIGNATURE:
		return sizeof(bootblock_struct_t);
		break;
	default:
		BOOT_BUG("Unknown type of Boot information structure");
	}
}

static void __init boot_reserve_0_phys_page(bool bsp, boot_info_t * boot_info)
{
	e2k_addr_t area_base;
	e2k_size_t area_size;

	if (BOOT_IS_BSP(bsp)) {
		area_base = 0;
		area_size = PAGE_SIZE;

		if (!boot_is_kdump_kernel())
			boot_reserve_physmem("0-page", area_base, area_size,
				     hw_reserved_mem_type,
				     BOOT_NOT_IGNORE_BUSY_BANK |
				     BOOT_IGNORE_BANK_NOT_FOUND |
				     BOOT_CAN_BE_INTERSECTIONS);
		boot_fast_memset((void *)0, 0x00, PAGE_SIZE);
		boot_printk("The 0-page reserved area: "
			    "base addr 0x%lx size 0x%lx page size 0x%x\n",
			    area_base, area_size, PAGE_SIZE);
	}
}

/*
 * Reserve kernel image 'text/data/bss' segments.
 */
void __init boot_reserve_kernel_image(bool bsp, boot_info_t * boot_info)
{
	e2k_addr_t base;
	e2k_size_t size, delta;

	if (!BOOT_IS_BSP(bsp))
		return;

	delta = (unsigned long)boot_va_to_pa(_start) - (unsigned long)_start;

	base = (unsigned long)_stext + delta;
	size = (unsigned long)(_etext - _stext);
	boot_reserve_physmem(".text", base, size, kernel_image_mem_type,
			     BOOT_NOT_IGNORE_BUSY_BANK);
	boot_text_phys_base = base;
	boot_text_size = size;

	base = (unsigned long)__start_rodata_notes + delta;
	size = (unsigned long)(__end_rodata_notes - __start_rodata_notes);
	boot_reserve_physmem(".rodata/.notes", base, size,
			     kernel_image_mem_type, BOOT_NOT_IGNORE_BUSY_BANK);

	base = (unsigned long)__special_data_begin + delta;
	size = (unsigned long)(__special_data_end - __special_data_begin);
	boot_reserve_physmem(".nodedata/.ro_after_init", base, size,
			     kernel_image_mem_type, BOOT_NOT_IGNORE_BUSY_BANK);

	base = (unsigned long)__common_data_begin + delta;
	size = (unsigned long)(__common_data_end - __common_data_begin);
	boot_reserve_physmem(".data/.bss", base, size, kernel_image_mem_type,
			     BOOT_NOT_IGNORE_BUSY_BANK);
	boot_data_phys_base = base;
	boot_data_size = size;

	base = (unsigned long)__init_begin + delta;
	size = (unsigned long)(__init_end - __init_begin);
	boot_reserve_physmem(".init", base, size, kernel_image_mem_type,
			     BOOT_NOT_IGNORE_BUSY_BANK);
}

void __init boot_reserve_stacks(boot_info_t * boot_info)
{
	e2k_addr_t area_base;
	e2k_size_t area_size;
	e2k_psp_t PSP;
	e2k_pcsp_t PCSP;
	e2k_usbr_t USBR;
	e2k_usd_t USD;

	/*
	 * Reserve memory of boot-time hardware procedures stack (PS).
	 * 'PSP' register-pointer describes this area.
	 */
	PSP = boot_read_PSP_reg();
	area_base = PSP_BASE(PSP);
	area_size = PSP_SIZE(PSP);
	boot_reserve_physmem("procedure stack", area_base, area_size,
			     boot_loader_mem_type, BOOT_CAN_BE_INTERSECTIONS);
	boot_boot_ps_phys_base = area_base;
	boot_boot_ps_size = area_size;

	/*
	 * Reserve memory of boot-time hardware procedure chain stack (PCS).
	 * 'PCSP' register-pointer describes this area.
	 */
	PCSP = boot_read_PCSP_reg();
	area_base = PCSP_BASE(PCSP);
	area_size = PCSP_SIZE(PCSP);
	boot_reserve_physmem("chain stack", area_base, area_size,
			     boot_loader_mem_type, BOOT_CAN_BE_INTERSECTIONS);
	boot_boot_pcs_phys_base = area_base;
	boot_boot_pcs_size = area_size;

	/*
	 * Reserve memory of boot-time kernel stack (user stack) (US).
	 * 'SBR + USD' registers describe this area.
	 */
	USBR = boot_read_USBR_reg();
	USD = boot_read_USD_reg();
	boot_printk("The kernel boot-time data stack: USBR_base 0x%lx USD_base 0x%lx USD_size 0x%llx\n",
	     USBR.base, USD_PTR(USD), USD_IND(USD));
	area_base = USD_BASE(USD);
	area_size = USBR.base - area_base;
	boot_reserve_physmem("data stack", area_base, area_size,
			     boot_loader_mem_type, BOOT_CAN_BE_INTERSECTIONS);
	boot_boot_stack_phys_base = area_base;
	boot_boot_stack_phys_offset = USD_IND(USD);
	boot_boot_stack_size = area_size;
}

static void __init boot_reserve_low_io_mem(bool bsp)
{
	/*
	 * Reserve memory of low VGAMEM area.
	 */
	if (BOOT_IS_BSP(bsp)) {
		e2k_addr_t area_base = VGA_VRAM_PHYS_BASE;	/* VGA ... */
		e2k_size_t area_size = VGA_VRAM_SIZE;
		boot_delete_physmem("Deleted low VGAMEM", area_base, area_size);
	}
}

/*
 * Reserve boot information records.
 */
void __init boot_reserve_bootblock(bool bsp, boot_info_t *boot_info)
{
	unsigned long area_base;
	size_t area_size;

	if (!BOOT_IS_BSP(bsp))
		return;

	area_base = (unsigned long) boot_info;
	area_size = boot_get_bootblock_size(boot_info);
	boot_reserve_physmem("bootblock", area_base, area_size,
			     boot_loader_mem_type, BOOT_CAN_BE_INTERSECTIONS);

	boot_printk("The BOOTINFO reserved area: base addr 0x%lx size 0x%lx page size 0x%x\n",
	     area_base, area_size, E2K_BOOTINFO_PAGE_SIZE);

	/*
	 * Reserve the needed areas from boot information records.
	 */
	boot_reserve_bootinfo_areas(boot_info);
}

/*
 * Reserve memory used by BOOT (e2k boot-loader)
 */
static void __init boot_reserve_boot_memory(bool bsp, boot_info_t * boot_info)
{
	e2k_addr_t area_base;
	e2k_size_t area_size;
	int bank;

	if (!BOOT_IS_BSP(bsp))
		return;

	for (bank = 0; bank < boot_info->num_of_busy; bank++) {
		bank_info_t *busy_area;
		busy_area = &boot_info->busy[bank];
		area_base = busy_area->address;
		area_size = busy_area->size;
		boot_reserve_physmem("BIOS data", area_base, area_size,
				     boot_loader_mem_type,
				     BOOT_IGNORE_BUSY_BANK |
				     BOOT_CAN_BE_INTERSECTIONS |
				     BOOT_IGNORE_BANK_NOT_FOUND);
	}
}

/*
 * Reserve the memory used by boot-time initialization.
 * All the used memory areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */
void __init boot_native_reserve_all_bootmem(bool bsp, boot_info_t * boot_info)
{
	/*
	 * Reserve 0 phys page area for software fix of hardware bug:
	 * "page miss" for semi-speculative load for invalid address instead of
	 * diagnostic value because of "illegal page".
	 */
	boot_reserve_0_phys_page(bsp, boot_info);

	/*
	 * Reserve kernel image 'text/data/bss' segments.
	 * 'OSCUD' & 'OSGD' register-pointers describe these areas.
	 * 'text' and 'data/bss' segments can intersect or one can include
	 * other.
	 */
	boot_reserve_kernel_image(bsp, boot_info);

	/*
	 * Reserve memory of boot-time stacks.
	 */
	boot_reserve_stacks(boot_info);

	/*
	 * Reserve memory of PC reserved area (640K - 1M).
	 */
	boot_reserve_low_io_mem(bsp);

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete reservation of
	 * memory used by themselves.
	 * Now boot loader busy area can be reserved, but only after
	 * this synchronization, because this area might include all
	 * other already reserved areas (bug 101002)
	 */
	boot_sync_all_processors();

	/*
	 * Reserve boot information records.
	 */
	boot_reserve_bootblock(bsp, boot_info);

	/*
	 * Reserve memory used by BOOT (e2k boot-loader)
	 */
	boot_reserve_boot_memory(bsp, boot_info);
}

/*
 * Reserve the needed memory from MP - tables
 */

static void __init boot_reserve_mp_table(boot_info_t * bblock)
{
	e2k_addr_t area_base;
	e2k_size_t area_size;
	struct intel_mp_floating *mpf;

	if (!bblock->mp_table_base)
		return;

	/*
	 * MP floating specification table
	 */
	area_base = bblock->mp_table_base;
	area_size = E2K_MPT_PAGE_SIZE;
	boot_reserve_physmem("MP floating table", area_base, area_size,
			     boot_loader_mem_type,
			     BOOT_IGNORE_BUSY_BANK | BOOT_CAN_BE_INTERSECTIONS);

	mpf = (struct intel_mp_floating *)bblock->mp_table_base;
	if (DEBUG_BOOT_MODE) {
		int i;
		for (i = 0; i < sizeof(struct intel_mp_floating) / 8; i++) {
			do_boot_printk("mpf[%d] = 0x%lx\n", i,
				       ((u64 *) mpf)[i]);
		}
	}

	/*
	 * MP configuration table
	 */
	if (mpf->mpf_physptr) {
		boot_reserve_physmem("MP configuration table",
				mpf->mpf_physptr, E2K_MPT_PAGE_SIZE,
				boot_loader_mem_type,
				BOOT_IGNORE_BUSY_BANK | BOOT_CAN_BE_INTERSECTIONS);
	} else {
		boot_printk("The MP configuration table: is absent\n");
	}
}

/*
 * Reserve the needed memory from boot-info used by boot-time initialization.
 * All the used memory areas from boot info enumerate below.
 * If a some new area will be used, then it should be added to the list
 * of already known ones.
 */

static void __init boot_reserve_bootinfo_areas(boot_info_t * boot_info)
{
	e2k_addr_t area_base;
	e2k_size_t area_size;

#ifdef CONFIG_BLK_DEV_INITRD
	/*
	 * Reserve memory of initial ramdisk (initrd).
	 */
	area_base = boot_info->ramdisk_base;	/* INITRD_BASE and INITRD_SIZE */
	area_size = boot_info->ramdisk_size;	/* come from Loader */
	if (area_size) {
		boot_reserve_physmem("initrd", area_base, area_size,
				     boot_loader_mem_type,
				     BOOT_CAN_BE_INTERSECTIONS);
		boot_initrd_phys_base = area_base;
		boot_initrd_size = area_size;
		boot_printk("The initial ramdisk area: "
			    "base addr 0x%lx size 0x%lx page size 0x%x\n",
			    area_base, area_size, E2K_INITRD_PAGE_SIZE);
	} else {
		boot_printk("Initial ramdisk is empty\n");
	}
#endif /* CONFIG_BLK_DEV_INITRD */

	/*
	 * Reserve MP configuration table
	 */
	if (boot_info->mp_table_base != (e2k_addr_t) 0UL)
		boot_reserve_mp_table(boot_info);

	/*
	 * kexec puts new cmdline not in boot reserved area, so this area should be reserved for
	 * proper work of print_boot_info().
	 */
	area_base = boot_info->kernel_args_string_pnt;
	area_size = boot_strlen((const char *)area_base) + 1;
	if (area_base)
		boot_reserve_physmem("kernel_args_string_pnt", area_base, area_size,
			boot_loader_mem_type, BOOT_CAN_BE_INTERSECTIONS);
}

static int __init boot_is_pfn_valid(e2k_size_t pfn)
{
	unsigned long *nodes_map = &boot_phys_mem_nodes_map;
	node_phys_mem_t *all_nodes_mem = NULL;
	int node;
	short bank;

	all_nodes_mem = boot_vp_to_pp((node_phys_mem_t *) boot_phys_mem);
	for_each_set_bit(node, nodes_map, L_MAX_MEM_NUMNODES) {
		node_phys_mem_t *node_mem = &all_nodes_mem[node];
		boot_phys_bank_t *node_banks;

		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		node_banks = node_mem->banks;
		bank = node_mem->first_bank;
		while (bank >= 0) {
			boot_phys_bank_t *phys_bank = &node_banks[bank];
			e2k_addr_t bank_pfn;

			if (phys_bank->pages_num == 0) {
				/* bank in the list has not pages */
				BOOT_BUG("Node #%d bank #%d at the list has not memory pages",
					node, bank);
			}
			bank_pfn = phys_bank->base_addr >> PAGE_SHIFT;
			if (pfn >= bank_pfn &&
			    pfn < bank_pfn + phys_bank->pages_num)
				return 1;
			bank = phys_bank->next;
		}
	}
	return 0;
}

/*
 * Map into the virtual space all physical areas used by kernel while
 * boot-time initialization and needed later.
 * All the mapped areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */

/*
 * Map the kernel image 'text/data/bss' segments.
 * 'text' and 'data/bss' segments can intersect or one can include
 * other.
 */
void __init boot_map_kernel_image(bool populate_on_host)
{
	e2k_addr_t virt_base;
	e2k_size_t size, delta, size_huge;

	/* Kernel image duplication on NUMA is done later
	 * (see duplicate_kernel_image()) */

	delta = (unsigned long)boot_va_to_pa(_start) - (unsigned long)_start;

	virt_base = (unsigned long)_stext;
	size = (unsigned long)(_etext - _stext);
	if (boot_cpu_has(CPU_HWBUG_ITLB_LARGE_PAGES)) {
		size_huge = min(16 * E2K_LARGE_PAGE_SIZE,
				round_down(size, E2K_LARGE_PAGE_SIZE));
	} else {
		size_huge = round_down(size, E2K_LARGE_PAGE_SIZE);
	}
	boot_map_phys_area(".text", virt_base + delta,
			size_huge, virt_base,
			   PAGE_KERNEL_TEXT, BOOT_E2K_KERNEL_PAGE_SIZE,
			   false, populate_on_host);
	if (size != size_huge) {
		boot_map_phys_area(".text", virt_base + delta + size_huge,
				size - size_huge, virt_base + size_huge,
				PAGE_KERNEL_TEXT, E2K_SMALL_PAGE_SIZE,
				false, populate_on_host);
	}
	boot_text_virt_base = virt_base;

	virt_base = (unsigned long)__start_rodata_notes;
	size = (unsigned long)(__end_rodata_notes - __start_rodata_notes);
	boot_map_phys_area(".rodata/.notes", virt_base + delta, size, virt_base,
			   PAGE_KERNEL_RO, BOOT_E2K_KERNEL_PAGE_SIZE,
			   false, populate_on_host);

	virt_base = (unsigned long)__special_data_begin;
	size = (unsigned long)(__special_data_end - __special_data_begin);
	boot_map_phys_area(".nodedata/.ro_after_init", virt_base + delta, size,
			   virt_base, PAGE_KERNEL_DATA, PAGE_SIZE, false,
			   populate_on_host);

	virt_base = (unsigned long)__common_data_begin;
	size = (unsigned long)(__common_data_end - __common_data_begin);
	boot_map_phys_area(".data/.bss", virt_base + delta, size, virt_base,
			   PAGE_KERNEL_DATA, BOOT_E2K_KERNEL_PAGE_SIZE,
			   false, populate_on_host);

	virt_base = (unsigned long)__init_text_begin;
	size = (unsigned long)(__init_text_end - __init_text_begin);
	boot_map_phys_area(".init.text", virt_base + delta, size, virt_base,
			   PAGE_KERNEL_TEXT, PAGE_SIZE, false,
			   populate_on_host);

	virt_base = (unsigned long)__init_data_begin;
	size = (unsigned long)(__init_data_end - __init_data_begin);
	boot_map_phys_area(".init.data", virt_base + delta, size, virt_base,
			   PAGE_KERNEL_DATA, PAGE_SIZE, false,
			   populate_on_host);

	boot_printk
	    ("The kernel full image: is mapped from base addr 0x%lx size 0x%lx\n",
	     KERNEL_BASE, KERNEL_END - KERNEL_BASE);
}

void __init boot_map_kernel_boot_stacks(void)
{
	e2k_addr_t area_phys_base;
	e2k_addr_t area_offset;
	e2k_addr_t area_virt_base;

	/*
	 * Map the kernel boot-time hardware procedures stack (PS).
	 * The first PS maps to virtual space from the very begining
	 * of the area, dedicated for hardware kernel stacks.
	 * The following stacks are allocated from end of the previous stack.
	 */
	area_phys_base = boot_boot_ps_phys_base;
	area_virt_base = (e2k_addr_t) __boot_va(boot_vpa_to_pa(area_phys_base));
	boot_boot_ps_virt_base = area_virt_base;
	boot_printk("The kernel boot-time procedure stack: %d pages from 0x%lx\n",
	     boot_boot_ps_size / PAGE_SIZE, boot_boot_ps_virt_base);

	/*
	 * Map the kernel boot-time hardware procedure chain stack (PCS).
	 * PCS maps to virtual space right after PS
	 */
	area_phys_base = boot_boot_pcs_phys_base;
	area_virt_base = (e2k_addr_t) __boot_va(boot_vpa_to_pa(area_phys_base));
	boot_boot_pcs_virt_base = area_virt_base;
	boot_printk("The kernel boot-time chain stack: %d pages from 0x%lx\n",
		    boot_boot_pcs_size / PAGE_SIZE, boot_boot_pcs_virt_base);

	/*
	 * Map the kernel boot-time data stack (user stack) (US).
	 * The first stack maps to virtual space from the very begining
	 * of the area, dedicated for all data kernel stacks.
	 * The following stacks are allocated from end of the previous stack.
	 */
	area_phys_base = boot_boot_stack_phys_base;
	area_offset = boot_boot_stack_phys_offset;
	area_virt_base = (e2k_addr_t) __boot_va(boot_vpa_to_pa(area_phys_base));
	boot_boot_stack_virt_base = area_virt_base;
	boot_boot_stack_virt_offset = area_offset;
	boot_printk("The kernel boot-time data stack: %d pages from 0x%lx\n",
		    boot_boot_stack_size / PAGE_SIZE,
		    boot_boot_stack_virt_base);
}

void __init boot_map_all_phys_memory(void)
{
	long ret;

	/*
	 * Map the available physical memory into virtual space to direct
	 * access to physical memory using kernel pa <-> va translations
	 * All physical memory pages are mapped to virtual space starting
	 * from 'PAGE_OFFSET'
	 */
	boot_printk("The physical memory start address 0x%lx, end 0x%lx\n",
		    boot_start_of_phys_memory, boot_end_of_phys_memory);
	ret = boot_map_physmem(PAGE_MAPPED_PHYS_MEM,
			       IS_ENABLED(CONFIG_DEBUG_PAGEALLOC) ? PAGE_SIZE :
			       0 /* any max possible page size */ );
	BOOT_BUG_ON(ret <= 0, "Mapping all phys. memory failed with %ld", ret);
	boot_printk("All physical memory is mapped to %d virtual pages from base offset 0x%lx\n",
	     ret, (e2k_addr_t) __boot_va(boot_start_of_phys_memory));
}

static void __init boot_map_low_io_memory(void)
{
	e2k_addr_t area_phys_base, area_virt_base;

	/*
	 * Map the low VGAMEM.
	 */
	area_phys_base = VGA_VRAM_PHYS_BASE;
	area_virt_base = (e2k_addr_t) __boot_va(area_phys_base);
	boot_map_phys_area("low VGAMEM", area_phys_base,
			   VGA_VRAM_SIZE, area_virt_base,
			   boot_cpu_has(CPU_FEAT_WC_LEGACY_VGA) ? PAGE_IO_MAP_WC : PAGE_IO_MAP,
			   E2K_SMALL_PAGE_SIZE,
			   false, /* do not ignore if data mapping virtual  area is busy */
			   false);	/* populate map on host? */
}

static void __init boot_map_high_io_memory(void)
{
	static __initdata BOOT_DEFINE_NODE_LOCK(hwbug_lock);
	unsigned long first_base;
	e2k_addr_t area_phys_base;
	e2k_size_t area_size;
	e2k_addr_t area_virt_base;
	int node;

	/*
	 * Map the PCI/IO ports area to allow IO operations on system console.
	 */
	area_phys_base = boot_machine.io_area_base;
	if (BOOT_HAS_MACHINE_E2K_FULL_SIC)
		area_size = E2K_FULL_SIC_IO_AREA_SIZE;
	else if (BOOT_HAS_MACHINE_E2K_LEGACY_SIC)
		area_size = E2K_LEGACY_SIC_IO_AREA_SIZE;
	else
		BOOT_BUG("Unknown I/O ports area size");
	area_virt_base = E2K_IO_AREA_BASE;
	boot_map_phys_area("PCI I/O ports", area_phys_base, area_size,
			   area_virt_base, PAGE_IO_MAP, BOOT_E2K_IO_PAGE_SIZE,
			   false, /* do not ignore if data mapping virtual  area is busy */
			   false);	/* populate map on host? */

	if (!boot_node_lock(&hwbug_lock)) {
		if (!boot_node_has_online_mem(boot_numa_node_id()))
			goto no_hwbug_mapping;

		/*
		 * Only 4 nodes on e8c with the problem
		 * Allocate and map 8 * 4 = 32 pages on every node.
		 * Then every core will have its own 4 pages: one on every node.
		 */
		first_base = -1UL;
		for (node = 0; node < 4; node++) {
			if (!BOOT_IS_MACHINE_E8C || node >= MAX_NUMNODES ||
			    !boot_node_has_online_mem(node)) {
				if (first_base == -1UL) {
					first_base = (u64) boot_alloc_phys_mem(8 * PAGE_SIZE,
									      PAGE_SIZE,
									      hw_reserved_mem_type);
				}
				area_phys_base = first_base;
			} else {
				area_phys_base =
				    (u64) boot_node_alloc_physmem(node,
								  8 * PAGE_SIZE,
								  PAGE_SIZE,
								  hw_reserved_mem_type);
				if (first_base == -1UL)
					first_base = area_phys_base;
			}
			if (area_phys_base == -1UL)
				BOOT_BUG
				    ("Failed to allocate memory for hwbug workaround\n");

			area_virt_base = node * 8 * PAGE_SIZE +
			    NATIVE_HWBUG_WRITE_MEMORY_BARRIER_ADDRESS;

			boot_map_phys_area("hwbug workaround", area_phys_base,
					   8 * PAGE_SIZE, area_virt_base, PAGE_USER_RO_ACCESSED,
					   PAGE_SIZE, true,	/* ignory busy mapping ? */
					   false);	/* populate map on host ? */
		}

no_hwbug_mapping:
		boot_node_unlock(&hwbug_lock);
	}
}

void __init boot_native_map_all_bootmem(bool bsp, boot_info_t * boot_info)
{
	if (BOOT_IS_BSP(bsp)) {
		/*
		 * Map the kernel image 'text/data/bss' segments.
		 */
		boot_map_kernel_image(false);

		/*
		 * Map all available physical memory
		 */
		boot_map_all_phys_memory();

		/*
		 * Map the low VGAMEM.
		 */
		boot_map_low_io_memory();

		/*
		 * Map all needed physical areas from boot-info.
		 */
		boot_map_all_bootinfo_areas(boot_info);

		/*
		 * Map the PCI/IO ports area to allow IO operations on system console.
		 */
		boot_map_high_io_memory();
	}

	/*
	 * Map the kernel stacks
	 */
	boot_map_kernel_boot_stacks();
}

/*
 * Map into the virtual space all needed physical areas from boot-info.
 * All the mapped areas enumerate below. If a some new area will be used,
 * then it should be added to the list of already known ones.
 */
void __init boot_map_all_bootinfo_areas(boot_info_t *boot_info)
{
	e2k_addr_t area_pfn;

	/*
	 * Check the bootinfo structure.
	 */
	area_pfn = boot_vpa_to_pa((unsigned long) boot_info) >> PAGE_SHIFT;
	BOOT_BUG_ON(!boot_is_pfn_valid(area_pfn), "bootinfo not in RAM");
	boot_bootblock_virt = (bootblock_struct_t *)
			__boot_va(boot_vpa_to_pa((unsigned long) boot_bootblock_phys));

#ifdef CONFIG_BLK_DEV_INITRD
	/*
	 * Map the memory of initial ramdisk (initrd).
	 */
	area_pfn = boot_vpa_to_pa(boot_initrd_phys_base) >> PAGE_SHIFT;
	BOOT_BUG_ON(boot_initrd_size && !boot_is_pfn_valid(area_pfn), "initrd not in RAM");
#endif /* CONFIG_BLK_DEV_INITRD */

	if (boot_info->mp_table_base) {
		struct intel_mp_floating *mpf = (void *) boot_info->mp_table_base;

		/*
		 * Check MP floating specification table
		*/
		area_pfn = boot_vpa_to_pa(boot_info->mp_table_base) >> PAGE_SHIFT;
		BOOT_BUG_ON(!boot_is_pfn_valid(area_pfn), "MP floating table not in RAM");

		/*
		 * Check MP configuration table
		*/
		if (mpf->mpf_physptr) {
			area_pfn = boot_vpa_to_pa(mpf->mpf_physptr) >> PAGE_SHIFT;
			BOOT_BUG_ON(!boot_is_pfn_valid(area_pfn),
					"MP configuration table not in RAM");
		}
	}
}

/* 
 * Switch kernel execution into the physical space to execution into the
 * virtual space. This function should be coded very careful.
 * Each the function operator should be weighted, what conseguences it will
 * have.
 */

noinline void __init_recv
boot_native_switch_to_virt(bool bsp, int cpuid,
		void (*boot_init_sequel_func) (bool bsp, int cpuid, int cpus_to_sync))
{
	bootmem_areas_t *bootmem = boot_kernel_bootmem;
	e2k_psp_t psp;
	e2k_pcsp_t pcsp;
	e2k_cud_t cud;
	e2k_gd_t gd;
	e2k_usd_t usd;
	e2k_usbr_t usbr;
	e2k_psr_t psr;
	e2k_mmu_cr_t mmu_cr = MMU_CR_KERNEL;
#ifdef	CONFIG_SMP
	int cpus_to_sync = boot_cpu_to_sync_num;
	atomic_t *pv_ops_switched = boot_vp_to_pp(&boot_pv_ops_switched);
	atomic_t *error_flag_p = boot_vp_to_pp(&boot_error_flag);
#endif /* CONFIG_SMP */
#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM
	register bool flush_caches;
	register bool l3_enable = false;
	register bool do_i_flush = false;
	register int iset_ver;
	register unsigned char __iomem *node_nbsr;
#endif /* CONFIG_ONLY_HIGH_PHYS_MEM */

	/*
	 * Set all needed MMU registers before to turn on virtual addressing
	 * translation mode
	 */
	boot_set_kernel_MMU_state_before();

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should be here
	 * After synchronization BSP processor switch PV_OPS
	 */
	boot_sync_all_processors();

	/* switch PV_OPS to virtual functions */
	/* WARNING: should not be PV_OPS usage from here to completion of */
	/* virtual space switching (call function boot_init_sequel_func()) */
	if (BOOT_IS_BSP(bsp)) {
		native_boot_pv_ops_to_ops();
#ifdef	CONFIG_SMP
		boot_set_boot_event(pv_ops_switched);
	} else {
		boot_wait_for_boot_event(pv_ops_switched, error_flag_p);
#endif /* CONFIG_SMP */
	}

	/*
	 * Calculate hardware procedure and chain stacks pointers
	 */

#ifndef	CONFIG_SMP
	psp = new_psp(bootmem->boot_ps.virt, bootmem->boot_ps.size, 0);
	pcsp = new_pcsp(bootmem->boot_pcs.virt, bootmem->boot_pcs.size, 0);
#else
	psp = new_psp(bootmem->boot_ps[cpuid].virt, bootmem->boot_ps[cpuid].size, 0);
	pcsp = new_pcsp(bootmem->boot_pcs[cpuid].virt, bootmem->boot_pcs[cpuid].size, 0);
#endif /* CONFIG_SMP */

	/*
	 * Turn on virtual addressing translation mode and disable caches
	 * (write to the MMU control register enables TLB & TLU)
	 */

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM
	/* low memory kernel data remapped to equal high memory */
	/* all virtual addresses to low data point now to high memory */
	/* so need flush all caches from low physical addresses */
	flush_caches = !BOOT_LOW_MEMORY_ENABLED();
	if (flush_caches) {
		static __initdata_recv BOOT_DEFINE_NODE_LOCK(flush_lock);

		iset_ver = boot_machine.native_iset_ver;
		if (iset_ver >= E2K_ISET_V4 && boot_machine.L3_enable)
			l3_enable = true;
		if (!boot_node_lock(&flush_lock)) {
			do_i_flush = true;
			if (l3_enable)
				node_nbsr = BOOT_THE_NODE_NBSR_PHYS_BASE(0);
			boot_node_unlock(&flush_lock);
		}
	}
#endif /* CONFIG_ONLY_HIGH_PHYS_MEM */

	/*
	 * Calculate Kernel 'text/data/bss' segment registers
	 * at virtual space addresses
	 */

	cud = new_cud(bootmem->text.virt,
			CUD_SIZE( native_read_CUD_reg()), 1, 0);
	gd = new_gd(bootmem->data.virt, GD_SIZE(native_read_GD_reg()));
	/*
	 * calculate User LOcal data Stack registers at virtual space
	 */


#ifndef	CONFIG_SMP
	usbr.base = bootmem->boot_stack.virt + bootmem->boot_stack.size;
	usd = new_usd(bootmem->boot_stack.virt,
		      bootmem->boot_stack.virt_offset,
		      bootmem->boot_stack.virt_offset);
#else
	usbr.base = bootmem->boot_stack[cpuid].virt + bootmem->boot_stack[cpuid].size;
	usd = new_usd(bootmem->boot_stack[cpuid].virt,
		      bootmem->boot_stack[cpuid].virt_offset,
		      bootmem->boot_stack[cpuid].virt_offset);
#endif /* CONFIG_SMP */

	/*
	 * SYNCHRONIZATION POINT
	 * Before this synchronization all processors should calculate
	 * state of context registers and complete access to physical memory
	 * At this point all processors should be here
	 * After synchronization all variables can be accessed only from
	 * registers file
	 */
	boot_sync_all_processors();

	/*
	 * Set Procedure Stack and Procedure Chain stack registers
	 * to begining virtual stacks addresses and collapse in that way
	 * previuos useless stack frames
	 */
	NATIVE_FLUSHCPU;
	/*
	 * Switch User Stack registers to virtual kernel stack addresses
	 * The assumption is - stack allocation does not use GETSAP operation
	 * but uses SP and FP pointers and allocates stack from end.
	 * Set stack pointer to the very begining of initial stack to collapse
	 * useless previuos stack frames
	 */
	native_write_stacks(psp, pcsp, usd, usbr);

	/*
	 * Enable control of PS & PCS stack guard
	 */
	psr = native_read_PSR_reg();
	psr.sge = 1;
	native_write_PSR_reg(psr);

	/*
	 * Set Kernel 'text/data/bss' segment registers to consistent
	 * virtual addresses
	 */

	native_write_CUD_reg(cud);
	native_write_OSCUD_reg(cud);

	native_write_GD_reg(gd);
	native_write_OSGD_reg(gd);

	/*
	 * Set CPU registers to point to kernel CUT & index
	 */
	native_set_kernel_CUTD();

	__E2K_WAIT_ALL;

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM
	/* variable 'flush_caches' should be local register of function */
	if (flush_caches) {
		native_raw_write_back_CACHE_L12();
		__E2K_WAIT_ALL;
		if (l3_enable && do_i_flush)
			boot_native_flush_L3(iset_ver, node_nbsr);
	}
#endif /* CONFIG_ONLY_HIGH_PHYS_MEM */

	E2K_CLEAR_CTPRS();
	__E2K_WAIT_ALL;

	NATIVE_WRITE_MMU_CR(mmu_cr);
	__E2K_WAIT_ALL;

	/*
	 * The following call completes switching into the virtual execution.
	 * Now full virtual addressing support is enable. Should not be
	 * return here from this function.
	 */
#ifdef	CONFIG_SMP
	E2K_CALL_PTR(boot_init_sequel_func, 3, bsp, cpuid, cpus_to_sync);
#else
	E2K_CALL_PTR(boot_init_sequel_func, 3, bsp, 0, 0);
#endif
}

/* 
 * The funcrtion is fictitious, only to determine the size of previous function.
 * The function should follow previous function 'boot_switch_to_virt()'
 */

static void __init_recv boot_native_switch_to_virt_end(void)
{
}

/*
 * Map some necessary physical areas to the equal virtual addresses to
 * switch kernel execution into the physical space to execution into the
 * virtual space.
 * Sometime after turn on TLB and translation virtual addresses to physical
 * becomes inevitable, some kernel text and data should be accessed on old
 * physical addresses, which will be treated now as virtual addresses.
 */

void __init_recv
boot_native_map_needful_to_equal_virt_area(e2k_addr_t stack_top_addr)
{
	e2k_addr_t area_base;
	size_t area_size;

	/*
	 * Map the function 'boot_native_switch_to_virt()' of kernel image
	 * 'text' segments. This function will make switching to virtual
	 * space. The first part of the function is executed into the
	 * physical space without any translation virtual addresses.
	 * But second part of one is executed into the equal virtual spce.
	 */
	area_base = (e2k_addr_t) boot_vp_to_pp(&boot_native_switch_to_virt);
	area_size = (size_t) boot_native_switch_to_virt_end -
		    (size_t) boot_native_switch_to_virt;
	boot_map_to_equal_virt_area("function boot_switch_to_virt()",
			area_base, area_size, PAGE_KERNEL_SWITCHING_TEXT,
			BOOT_E2K_EQUAL_MAP_PAGE_SIZE);

	/*
	 * Map the structure 'kernel_bootmem', which contains all boot-time
	 * memory info.
	 */
	area_base = (e2k_addr_t) boot_kernel_bootmem;
	area_size = sizeof(kernel_bootmem);
	boot_map_to_equal_virt_area("structure 'kernel_bootmem'",
			area_base, area_size, PAGE_KERNEL_SWITCHING_DATA,
			BOOT_E2K_EQUAL_MAP_PAGE_SIZE);

	/*
	 * Map the top of the kernel data stack to have access to some
	 * functions locals.
	 */
	area_base = stack_top_addr - E2K_KERNEL_US_PAGE_SWITCHING_SIZE + sizeof(long);
	area_size = E2K_KERNEL_US_PAGE_SWITCHING_SIZE;
	boot_map_to_equal_virt_area("top of the kernel stack",
			area_base, area_size, PAGE_KERNEL_SWITCHING_US_STACK,
			BOOT_E2K_EQUAL_MAP_PAGE_SIZE);
}

void boot_init_mmu_support(void)
{
	e2k_core_mode_t core_mode;

	if (!boot_cpu_has(CPU_FEAT_ISET_V6)) {
		boot_printk("MMU: old legacy Page Table entries format\n");
		return;
	}
	core_mode = boot_read_CORE_MODE_reg();
	core_mode.sep_virt_space = 0;
	core_mode.pt_v6 = !!cpu_has(CPU_FEAT_PAGE_TABLE_V6);
	boot_write_CORE_MODE_reg(core_mode);

	if (core_mode.pt_v6) {
		boot_printk("Set MMU Page Table entries format to new V6 mode\n");
	} else {
		boot_printk("Set MMU Page Table entries format to old legacy mode\n");
	}
	if (core_mode.sep_virt_space) {
		boot_printk("Enable MMU Separate Page Tables mode\n");
	} else {
		boot_printk("Disable MMU Separate Page Tables mode\n");
	}
	boot_printk("CORE_MODE is set to: 0x%x\n", AW(core_mode));

	/* set flag of PT version at abstruct page table structure */
	boot_pgtable_struct_p->pt_v6 = !!cpu_has(CPU_FEAT_PAGE_TABLE_V6);
}

/*
 * Control process of boot-time initialization of Virtual memory support.
 * The main goal of the initialization is switching to further boot execution
 * on virtual memory.
 */

void __init
boot_mem_init(bool bsp, int cpuid, boot_info_t *boot_info)
{
	e2k_size_t pages_num;

	if (BOOT_IS_BSP(bsp)) {
		/*
		 * Probe the system memory and fill the structures
		 * 'nodes_phys_mem' of physical memory configuration.
		 */
		boot_probe_memory(boot_info);

		/*
		 * Create the physical memory pages maps to support
		 * simple boot-time memory allocator.
		 */
		pages_num = boot_create_physmem_maps(boot_info);
		boot_printk("The physical memory size is 0x%lx pages * 0x%x = 0x%lx bytes\n",
			    pages_num, PAGE_SIZE, pages_num * PAGE_SIZE);

		/*
		 * Bootstrap processor completed creation of simple
		 * boot-time memory allocator and all CPUs can start
		 * to reserve used physical memory
		 */
		boot_set_event(&boot_physmem_maps_ready);
	} else {
		/*
		 * Other processors are waiting for completion of creation
		 * to start reservation of used memory by each CPU
		 */
		boot_wait_for_event(&boot_physmem_maps_ready);
	}

	/*
	 * Reserve the memory used now by boot-time initialization.
	 */
	boot_reserve_all_bootmem(bsp, boot_info);

	/* define MMU type and initial setup of MMU modes */
	boot_init_mmu_support();

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete reservation of
	 * used memory and all busy physical memory is known
	 * After synchronization any processor can remap reserved area
	 * from low to high physical memory range
	 */
	boot_sync_all_processors();

	/* update common info about present physical memory */
	/* which can be changed after reserve & delete */
	if (!boot_has_high_memory(boot_info)) {
		BOOT_SET_LOW_MEMORY_ENABLED();
		boot_printk("Nothing high memory on machine, so remapping of low memory to high is impossible\n");
	}
	if (BOOT_IS_BSP(bsp) && BOOT_LOW_MEMORY_ENABLED())
		boot_update_physmem_maps(boot_info);

	/*
	 * Remap the low memory to high addresses range, if need and possible.
	 */
	boot_remap_low_memory(bsp, boot_info);

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all changes in phys_banks busy_areas are completed.
	 */
	boot_sync_all_processors();

	if (BOOT_IS_BSP(bsp))
		boot_expand_phys_banks_reserved_areas();

	/*
	 * SYNCHRONIZATION POINT
	 * At this point phys_banks busy_areas are expanded.
	 * After synchronization any processor can allocate needed physical
	 * memory.
	 */
	boot_sync_all_processors();

	/*
	 * Init the boot-time support of physical areas mapping to virtual space
	 */
	boot_init_mapping(bsp);

	/*
	 * SYNCHRONIZATION POINT
	 * Waiting for all CPUs init mapping
	 */
	boot_sync_all_processors();

	/*
	 * Map the kernel memory areas used at boot-time
	 * into the virtual space.
	 */
	boot_map_all_bootmem(bsp, boot_info);

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors should complete map all
	 * used memory for each CPU and general (shared) memory
	 * After synchronization page table is completely constructed for
	 * switching on virtual addresses.
	 */
	boot_sync_all_processors();

	/*
	 * Map some necessary physical areas to the equal virtual addresses to
	 * switch kernel execution into the physical space to execution
	 * into the virtual space.
	 */
	boot_map_needful_to_equal_virt_area(USD_PTR(boot_read_USD_reg()));

	/*
	 * SYNCHRONIZATION POINT
	 * At this point all processors maped necessary physical areas
	 * to the equal virtual addresses and bootstrap processor maped
	 * general (shared) physical areas.
	 * After synchronization all procxessors are ready to switching
	 */
	boot_sync_all_processors();

	/*
	 * Switch kernel execution into the physical space to execution
	 * into the virtual space. All following initializations will be
	 * control by 'boot_init_sequel_func()' function.
	 * Should not be return here from this function.
	 */
	boot_kernel_switch_to_virt(bsp, cpuid);
}
