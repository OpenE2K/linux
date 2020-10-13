/*
 * Written by Andrea Arcangeli <andrea@suse.de> SuSE
 * Adapted for the E2K architecture Jan 2006.
 *
 * DISCONTIG MEMERY E2K support.
 *
 */

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/bootmem.h>
#include <linux/swap.h>
#include <linux/initrd.h>
#include <linux/mmzone.h>
#include <linux/nodemask.h>

#include <asm/pgalloc.h>
#include <asm/boot_phys.h>
#include <asm/boot_init.h>
#include <asm/mmu_context.h>
#include <asm/e2k_debug.h>

#if defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM
#include <asm/boot_recovery.h>
#endif	/* CONFIG_RECOVERY && CONFIG_CNT_POINTS_NUM */

#undef	DEBUG_DISCONIG_MODE
#undef	DebugDM
#define	DEBUG_DISCONIG_MODE	0	/* discontig. memory */
#define DebugDM(...)		DebugPrint(DEBUG_DISCONIG_MODE ,##__VA_ARGS__)

#undef	DEBUG_INVALID_PAGE_MODE
#undef	DebugIP
#define	DEBUG_INVALID_PAGE_MODE	0	/* invalid pages of memory */
#define DebugIP(...)		DebugPrint(DEBUG_INVALID_PAGE_MODE ,##__VA_ARGS__)

#undef	DEBUG_PAGE_NUMBER_MODE
#undef	DebugPN
#define	DEBUG_PAGE_NUMBER_MODE	0	/* calculation pages of memory */
#define DebugPN(...)		DebugPrint(DEBUG_PAGE_NUMBER_MODE ,##__VA_ARGS__)

pg_data_t	node_data[MAX_NUMNODES];
bootmem_data_t	node_bdata[MAX_NUMNODES];
EXPORT_SYMBOL(node_data);

#ifdef	CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP
static void __init alloc_zone_mem_map(struct pglist_data *pgdat,
			unsigned long zone_type,
			unsigned long start_pfn, unsigned long spanned_pages,
			unsigned long present_pages);
#endif	/* CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP */

/*
 * Initialize the boot-time allocator and register the available physical
 * memory on the node.
 */

static void notrace __init
bootmem_node_init(int nid)
{
	e2k_addr_t 	start_pfn, end_pfn;
	e2k_addr_t	bootmap_pfn;
	e2k_size_t	bootmap_size;
	node_phys_mem_t *node_mem = &nodes_phys_mem[nid];

	if (node_mem->pfns_num == 0) {
		DebugDM("node #%d has not memory\n",
			nid);
		return;
	}
	start_pfn = node_mem->start_pfn;
	end_pfn = start_pfn + node_mem->pfns_num;
	DebugDM("started for node # %d : from addr "
		"0x%lx to addr 0x%lx\n",
		nid, start_pfn << PAGE_SHIFT, end_pfn << PAGE_SHIFT);
	if (end_pfn > max_low_pfn) {
		max_pfn = max_low_pfn = end_pfn;
	}

	/*
	 * Initialize the boot-time allocator.
	 */
	NODE_DATA(nid)->bdata = &node_bdata[nid];
	bootmap_pfn = init_node_bootmap_phys_base(nid) >> PAGE_SHIFT;
	bootmap_size = init_bootmem_node(NODE_DATA(nid), bootmap_pfn,
					start_pfn, end_pfn);
	if (PAGE_ALIGN_DOWN(bootmap_size) != init_node_bootmap_size(nid)) {
		INIT_BUG_POINT("bootmem_node_init");
		INIT_BUG("Invalid size of pages for bitmap of "
			"'linux/mm/bootmem.c' on node #%d : "
			"occupied 0x%lx != allocated 0x%lx",
			nid, bootmap_size / PAGE_SIZE,
			init_node_bootmap_size(nid) / PAGE_SIZE);
	}
	DebugDM("created bootmap on node #%d : "
		"from addr 0x%lx size 0x%lx bytes\n",
		nid, bootmap_pfn << PAGE_SHIFT, bootmap_size);
}

#ifdef	CONFIG_ARCH_POPULATES_NODE_MAP
static void notrace __init
register_node_active_ranges(int nid)
{
	node_phys_mem_t	*node_mem;
	e2k_phys_bank_t	*phys_bank = NULL;
	e2k_addr_t start_pfn;
	e2k_addr_t end_pfn;
	int bank;

	node_mem = &nodes_phys_mem[nid];
	phys_bank = node_mem->banks;
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
		if (phys_bank->pages_num == 0)
			break;	/* no more banks on node */
		start_pfn = phys_bank->base_addr >> PAGE_SHIFT;
		end_pfn = start_pfn + phys_bank->pages_num;
		add_active_range(nid, start_pfn, end_pfn);
		DebugDM("registered on node "
			"#%d : range from 0x%lx to 0x%lx\n",
			nid, start_pfn << PAGE_SHIFT, end_pfn << PAGE_SHIFT);
		phys_bank ++;
	}

}
#endif	/* CONFIG_ARCH_POPULATES_NODE_MAP */

void notrace __init
bootmem_init(void)
{
	int nid;
	unsigned long node_mask;

	/*
	 * Initialize the boot-time allocator of physical
	 * memory of all banks of memory on the node.
	 */
	nodes_clear(node_online_map);
	node_mask = 0x1;
	for (nid = 0; nid < MAX_NUMNODES; nid ++) {
		if (phys_nodes_map & node_mask) {
			if (nodes_phys_mem[nid].pfns_num > 0) {
				bootmem_node_init(nid);
#ifdef	CONFIG_ARCH_POPULATES_NODE_MAP
				register_node_active_ranges(nid);
#endif	/* CONFIG_ARCH_POPULATES_NODE_MAP */
			}
			node_set_online(nid);
		}
		node_mask <<= 1;
	}
	if (phys_nodes_num != num_online_nodes()) {
		INIT_BUG_POINT("bootmem_init");
		INIT_BUG("Number of online nodes %d is not the same as "
			"set %d",
			num_online_nodes(), phys_nodes_num);
	}
}

void __init
zone_sizes_init(e2k_size_t pages_avail)
{
	unsigned int    nid = 0;
	unsigned long	zones_size[MAX_NR_ZONES];
	unsigned long	zholes_size[MAX_NR_ZONES];
	unsigned long	max_dma;
#if defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM
	unsigned long	hole_size;
#endif	/* CONFIG_RECOVERY && CONFIG_CNT_POINTS_NUM */
	e2k_addr_t	start_pfn;
	e2k_addr_t	end_pfn;
	int		znum;

	max_dma = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
	pci_low_bound = max_dma << PAGE_SHIFT;
	phys_hi_bound_intel = 0;

	for_each_online_node(nid) {
		unsigned long phys_lo_start;
		unsigned long phys_hi_end;

		start_pfn = node_bdata[nid].node_min_pfn;
		end_pfn = node_bdata[nid].node_low_pfn;
		phys_lo_start = end_pfn;
		phys_hi_end = start_pfn;
		for (znum = 0; znum < MAX_NR_ZONES; znum ++)
			zones_size[znum] = zholes_size[znum] = 0;

		calculate_zone_sizes(nodes_phys_mem[nid].banks,
			start_pfn,
			(end_pfn < max_dma) ? end_pfn : max_dma,
			&zones_size[ZONE_DMA],
			&zholes_size[ZONE_DMA],
			NULL, &phys_hi_end);
		DebugDM("node #%d phys_hi_bound_intel 0x%lx "
			"phys_hi_end 0x%lx\n",
			nid, phys_hi_bound_intel, phys_hi_end);
		if (phys_hi_bound_intel < phys_hi_end)
			phys_hi_bound_intel = phys_hi_end;
		DebugDM("node #%d phys_hi_bound_intel 0x%lx "
			"phys_hi_end 0x%lx\n",
			nid, phys_hi_bound_intel, phys_hi_end);
		calculate_zone_sizes(nodes_phys_mem[nid].banks,
			(start_pfn > max_dma) ? start_pfn : max_dma,
			end_pfn,
			&zones_size[ZONE_NORMAL],
			&zholes_size[ZONE_NORMAL],
			&phys_lo_start, NULL);
		if (start_pfn < max_dma && end_pfn > max_dma) {
			zones_size[ZONE_DMA] += (phys_lo_start - max_dma);
			zholes_size[ZONE_DMA] += (phys_lo_start - max_dma);
			zones_size[ZONE_NORMAL] -= (phys_lo_start - max_dma);
			zholes_size[ZONE_NORMAL] -= (phys_lo_start - max_dma);
			DebugDM("new zone DMA size "
				"0x%08lx, holes 0x%08lx\n",
				zones_size[ZONE_DMA], zholes_size[ZONE_DMA]);
			DebugDM("new zone NORMAL size "
				"0x%08lx, holes 0x%08lx\n",
				zones_size[ZONE_NORMAL],
				zholes_size[ZONE_NORMAL]);
		}
#ifdef	CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP
		/*
		 * Allocate physical memory map table separately for
		 * DMA and NORMAL zone to exclude holes between them
		 */
		NODE_DATA(nid)->node_id = nid;
		if (zones_size[ZONE_DMA]) {
			alloc_zone_mem_map(NODE_DATA(nid), ZONE_DMA,
				start_pfn, zones_size[ZONE_DMA],
				phys_hi_end - start_pfn);
#if defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM
			hole_size = (zones_size[ZONE_DMA] - phys_hi_end +
				start_pfn) << PAGE_SHIFT;
			if (hole_size)
				add_nosave_area(
					phys_hi_end << PAGE_SHIFT, hole_size);
#endif	/* CONFIG_RECOVERY && CONFIG_CNT_POINTS_NUM */
		}
		if (zones_size[ZONE_NORMAL]) {
			alloc_zone_mem_map(NODE_DATA(nid), ZONE_NORMAL,
				phys_lo_start, zones_size[ZONE_NORMAL],
				end_pfn - phys_lo_start);
#if defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM
			hole_size = (zones_size[ZONE_NORMAL] - end_pfn +
				phys_lo_start) << PAGE_SHIFT;
			if (hole_size)
				add_nosave_area(
					end_pfn << PAGE_SHIFT, hole_size);
#endif	/* CONFIG_RECOVERY && CONFIG_CNT_POINTS_NUM */
		}
#endif	/* CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP */
		DebugDM("created zone for node #%d :\n",
			nid);
		if (zones_size[ZONE_DMA]) {
			DebugDM("   DMA    start 0x%08lx size 0x%08lx "
				"holes 0x%08lx\n",
				start_pfn, zones_size[ZONE_DMA],
				zholes_size[ZONE_DMA]);
		}
		if (zones_size[ZONE_NORMAL]) {
			DebugDM("   NORMAL start 0x%08lx size 0x%08lx "
				"holes 0x%08lx\n",
				start_pfn + zones_size[ZONE_DMA],
				zones_size[ZONE_NORMAL],
				zholes_size[ZONE_NORMAL]);
		}
		free_area_init_node(nid, zones_size, start_pfn, zholes_size);
		if (NODE_DATA(nid)->node_present_pages)
			node_set_state(nid, N_HIGH_MEMORY);
	}
}
void __meminit
memmap_init(unsigned long size, int nid, unsigned long zone,
			unsigned long start_pfn)
{
	memmap_init_node(size, nid, &nodes_phys_mem[nid],
					zone, start_pfn);
}

#ifdef	CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP
/*
 * Same function as at mm/page_alloc.c to allocate memory map
 * excluding zone holes
 */
static void __init
alloc_zone_mem_map(struct pglist_data *pgdat, unsigned long zone_type,
			unsigned long start_pfn, unsigned long spanned_pages,
			unsigned long present_pages)
{
	struct zone *zone;
	struct page *map;
	unsigned long start;
	unsigned long end;
	unsigned long size;

	DebugDM("started for node #%d, zone #%ld, from "
		"0x%08lx to 0x%08lx total pages, 0x%08lx present pages\n",
		pgdat->node_id, zone_type, start_pfn,
		start_pfn + spanned_pages, start_pfn + present_pages);

	zone = pgdat->node_zones + zone_type;
	zone->zone_start_pfn = start_pfn;
	zone->spanned_pages = spanned_pages;
	zone->present_pages = present_pages;

	/* Skip empty zone */

	/*
	 * The zone's endpoints aren't required to be MAX_ORDER
	 * aligned but the node_mem_map endpoints must be in order
	 * for the buddy allocator to function correctly.
	 */
	start = start_pfn & ~(MAX_ORDER_NR_PAGES - 1);
	end = start_pfn + present_pages;
	end = ALIGN(end, MAX_ORDER_NR_PAGES);
	size = (end - start) * sizeof(struct page);
	if (size == 0)
		return;
	map = alloc_remap(pgdat->node_id, size);
	if (map == NULL)
		map = alloc_bootmem_node(pgdat, size);
	zone->zone_mem_map = map + (start_pfn - start);
	pgdat->node_mem_map = zone->zone_mem_map;
	DebugDM("node #%d, zone #%ld allocated from 0x%p "
		"size 0x%lx bytes\n",
		pgdat->node_id, zone_type, map, size);
}
#endif	/* CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP */

e2k_size_t notrace __init
get_invalid_pages_num(e2k_size_t *valid_pages_num)
{
	struct zone *zone;
	e2k_size_t invalid_pages_num = 0;
	e2k_size_t zone_invalid_pfns;
	e2k_size_t zone_valid_pfns;
	int nid;
	int z;
	unsigned long i;

	*valid_pages_num = 0;
	for_each_online_node(nid) {
		if (node_spanned_pages(nid) == 0)
			continue;	/* node without memory */
		zone = NODE_DATA(nid)->node_zones;
		for (z = 0; z < MAX_NR_ZONES; z ++) {
			if (zone_spanned_pages(zone) == 0) {
				zone ++;
				continue;	/* node without memory */
			}
			DebugPN("zone %d start from "
				"0x%08lx to 0x%08lx\n",
				z, zone_start_pfn(zone), zone_end_pfn(zone));
			zone_valid_pfns = 0;
			zone_invalid_pfns = 0;
			for (i = zone_start_pfn(zone);
				i < zone_end_pfn(zone);
					i++) {
				if (pfn_valid(i)) {
					zone_valid_pfns ++;
				} else {
					zone_invalid_pfns ++;
					DebugIP("Physical memory page 0x%lx "
						"is invalid\n", i);
				}
				if (zone_valid_pfns >=
					zone_present_pages(zone)) {
					zone_invalid_pfns +=
						(zone_end_pfn(zone) - 1 - i);
					break;	/* other pages is invalid */
				}
			}
			DebugPN("zone %d valid pages "
				"0x%08lx  invalid 0x%08lx\n",
				z, zone_valid_pfns, zone_invalid_pfns);
			invalid_pages_num += zone_invalid_pfns;
			(*valid_pages_num) += zone_valid_pfns;
			zone ++;
		}
	}
	return invalid_pages_num;
}

