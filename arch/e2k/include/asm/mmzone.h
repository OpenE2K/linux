/*
 * Written by Kanoj Sarcar (kanoj@sgi.com) Aug 99
 * Adapted for the E2K architecture Jan 2006.
 */
#ifndef _E2K_MMZONE_H_
#define _E2K_MMZONE_H_

#include <linux/nodemask.h>

#include <asm/smp.h>
#include <asm/topology.h>
#include <asm/numnodes.h>

#ifndef	DEBUG_NUMA_MODE
#define	DEBUG_NUMA_MODE		0	/* NUMA nodes */
#endif	/* ! DEBUG_NODES_MODE */
#define DebugNUMA(...)		DebugPrint(DEBUG_NUMA_MODE ,##__VA_ARGS__)

/*
 * Following are macros that are specific to this platform.
 */

#ifdef CONFIG_DISCONTIGMEM

extern pg_data_t node_data[];

#define	__NODE_DATA(ndata, nid)		(&(ndata)[(nid)])
#define __zone_localnr(zone, pfn)	((pfn) - (zone)->zone_start_pfn)
#define __zone_start_pfn(zone)		((zone)->zone_start_pfn)
#define __zone_spanned_pages(zone)	((zone)->spanned_pages)
#define __zone_present_pages(zone)	((zone)->present_pages)

/*
 * Following are macros that each numa implementation must define.
 */

#define NODE_DATA(nid)		__NODE_DATA(node_data, nid)


extern int e2k_is_pfn_valid(unsigned long pfn);

#define	early_pfn_valid(pfn)	e2k_is_pfn_valid(pfn)

extern int __pfn_to_nid(unsigned long pfn, bool panic_on_miss);

static bool inline __meminit
early_pfn_in_nid(unsigned long pfn, int node)
{
	int nid;

	nid = __pfn_to_nid(pfn, 0);
	if (nid >= 0 && nid != node)
		return false;
	return true;
}

static inline struct zone *
pfn_to_zone(unsigned long pfn, int nid)
{
	pg_data_t *pgdat = NODE_DATA(nid);
	struct zone *zone;
	unsigned long zone_type;

	zone = pgdat->node_zones;
	for (zone_type = 0; zone_type < MAX_NR_ZONES; zone_type ++) {
		if (pfn >= zone->zone_start_pfn &&
			       pfn < zone->zone_start_pfn + zone->spanned_pages)
			return zone;
		zone ++;
	}
	panic("pfn_to_zone() could not detect zone of pfn 0x%08lx on node "
		"#%d from 0x%08lx to 0x%08lx\n",
		pfn, nid, pgdat->node_start_pfn,
		pgdat->node_start_pfn + pgdat->node_spanned_pages);
}

# ifdef CONFIG_NUMA
static inline int
pfn_to_nid(unsigned long pfn)
{
	return __pfn_to_nid(pfn, 1);
}
# else
#  define pfn_to_nid(pfn) (0)
# endif


/*
 * Given a kernel address, find the home node of the underlying memory.
 */
#ifdef	CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP
#define zone_localnr(pfn, zone)	__zone_localnr(zone, pfn)
#endif	/* CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP */
#define kvaddr_to_nid(kaddr)	pfn_to_nid(__pa(kaddr) >> PAGE_SHIFT)
#define zone_start_pfn(zone)	__zone_start_pfn(zone)
#define zone_spanned_pages(zone) __zone_spanned_pages(zone)
#define zone_present_pages(zone) __zone_present_pages(zone)

#define local_mapnr(kvaddr) \
      ((__pa(kvaddr) >> PAGE_SHIFT) - node_start_pfn(kvaddr_to_nid(kvaddr)))

#ifdef	CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP
#define pfn_to_page(pfn)						\
({									\
	unsigned long __pfn = pfn;					\
	int __node  = pfn_to_nid(__pfn);				\
	struct zone *__zone = pfn_to_zone(__pfn, __node);		\
	&__zone->zone_mem_map[zone_localnr(__pfn, __zone)];		\
})

#define page_to_pfn(pg)							\
({									\
	const struct page *__page = pg;					\
	struct zone *__zone = page_zone(__page);			\
	(unsigned long)(__page - __zone->zone_mem_map)			\
		+ __zone->zone_start_pfn;				\
})
#endif	/* CONFIG_ARCH_DISCONTIG_NODE_MEM_MAP */


#if defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM

#define CNTP_NODE_DATA(nid)		__NODE_DATA(cntp_node_data, nid)
#define __node_start_pfn(nid_data)	((nid_data)->node_start_pfn)
#define __node_localnr(nid_data, pfn)	((pfn) - __node_start_pfn(nid_data))
#define cntp_node_localnr(pfn, nid)	__node_localnr(CNTP_NODE_DATA(nid), pfn)
#define cntp_node_start_pfn(nid)	__node_start_pfn(CNTP_NODE_DATA(nid))
#define __node_end_pfn(nid_data)					\
({									\
	pg_data_t *__pgdat = (nid_data);				\
	__pgdat->node_start_pfn + __pgdat->node_spanned_pages;		\
})
#define	cntp_node_end_pfn(nid)		__node_end_pfn(CNTP_NODE_DATA(nid))

#define zone_pfn_to_page(zone, pfn)					\
({									\
	&((zone)->zone_mem_map[(pfn)]);					\
})

#define zone_page_to_pfn(zone, page)					\
({									\
	(unsigned long)((page) - (zone)->zone_mem_map);			\
})

#define cntp_next_pgdat(prev)						\
({									\
	int nid = next_online_node(prev->node_id);			\
	pg_data_t *next;						\
									\
	if (nid == MAX_NUMNODES)					\
		next = NULL;						\
	else								\
		next = CNTP_NODE_DATA(nid);				\
									\
	(next);								\
})

/*
 * next_zone - for control point context.
 */
#define	cntp_next_zone(zone)						\
({									\
	pg_data_t *pgdat = cntp_va((zone)->zone_pgdat, 0);		\
	pg_data_t *next_pgdat;						\
									\
	if ((zone) < ((struct zone *)(cntp_va(pgdat->node_zones, 0))) +	\
						MAX_NR_ZONES - 1) {	\
		(zone)++;						\
	} else if (next_pgdat = cntp_next_pgdat(pgdat)) {		\
		pgdat = next_pgdat;					\
		zone = cntp_va(pgdat->node_zones, 0);			\
	} else {							\
		(zone) = NULL;						\
	}								\
									\
	(zone);								\
})

#define for_each_cntp_pgdat(pgdat) \
	for (pgdat = cntp_va(cntp_node_data, 0); \
			pgdat; pgdat = cntp_va(pgdat->pgdat_next, 0))
#define for_each_cntp_zone(zone) \
	for (zone = cntp_va(((pg_data_t *)(cntp_va(cntp_node_data, 0)))	\
							->node_zones, 0);	\
				zone; zone = cntp_next_zone(zone))

#define	is_cntp_dma_zone(zone)						\
({									\
	(zone) == ((struct zone *)(cntp_va(((pg_data_t *)		\
				(cntp_va((zone)->zone_pgdat, 0)))	\
					->node_zones, 0))) + ZONE_DMA;	\
})

#endif	/* defined(CONFIG_RECOVERY) && CONFIG_CNT_POINTS_NUM */

#endif /* CONFIG_DISCONTIGMEM */

#endif /* _E2K_MMZONE_H_ */
