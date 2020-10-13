/*  $Id: init.c,v 1.55 2009/11/11 08:17:56 thay_k Exp $
 *  arch/e2k/mm/init.c
 *
 * Memory menegement initialization
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */
 
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/bootmem.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/blkdev.h>
#include <linux/swap.h>
#include <linux/initrd.h>

#include <asm/types.h>
#include <asm/boot_head.h>
#include <asm/boot_init.h>
#include <asm/boot_phys.h>
#include <asm/head.h>
#include <asm/system.h>
#include <asm/mmu_regs.h>
#include <asm/mmu_context.h>
#include <asm/page.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/process.h>
#include <asm/e2k_syswork.h>
#include <asm/sections.h>
#include <asm/tlb.h>
#include <linux/dma-mapping.h>

#ifdef CONFIG_RECOVERY
#include <asm/cnt_point.h>
#endif /* CONFIG_RECOVERY */	

#undef	DEBUG_INIT_MODE
#undef	DebugB
#define	DEBUG_INIT_MODE		0	/* Boot paging init */
#define DebugB(...)		DebugPrint(DEBUG_INIT_MODE ,##__VA_ARGS__)

#undef	DEBUG_CONTIG_MODE
#undef	DebugCM
#define	DEBUG_CONTIG_MODE	0	/* contigous memory */
#define DebugCM(...)		DebugPrint(DEBUG_CONTIG_MODE ,##__VA_ARGS__)

#undef	DEBUG_MEMMAP_INIT_MODE
#undef	DebugMI
#define	DEBUG_MEMMAP_INIT_MODE	0	/* memory mapping init */
#define DebugMI(...)		DebugPrint(DEBUG_MEMMAP_INIT_MODE ,##__VA_ARGS__)

#undef	DEBUG_ZONE_SIZE_MODE
#undef	DebugZS
#define	DEBUG_ZONE_SIZE_MODE	0	/* zone size calculation */
#define DebugZS(...)		DebugPrint(DEBUG_ZONE_SIZE_MODE ,##__VA_ARGS__)

#undef	DEBUG_PAGE_VALID_MODE
#undef	DebugPV
#define	DEBUG_PAGE_VALID_MODE	0	/* checking: is page valid */
#define DebugPV(...)		DebugPrint(DEBUG_PAGE_VALID_MODE ,##__VA_ARGS__)

#undef	DEBUG_PAGE_VALID_ERR_MODE
#undef	DebugPVE
#define	DEBUG_PAGE_VALID_ERR_MODE	0	/* checking: is page valid */
#define DebugPVE(...)		DebugPrint(DEBUG_PAGE_VALID_ERR_MODE ,##__VA_ARGS__)
#define	DEBUG_NODES_MODE	0
#undef	DebugN
#define	DebugN			DebugPV

#define	DEBUG_INVALID_PAGES_NUM	0	/* check valid and invalid pages num */

#ifndef CONFIG_SMP
pgtable_cache_struct_t	pgt_quicklists;
#endif	/* ! (CONFIG_SMP) */

//DEFINE_PER_CPU_LOCKED(struct mmu_gather, mmu_gathers);

unsigned long __read_mostly	pfn_base;
/* Various address conversion macros use this. */
EXPORT_SYMBOL(pfn_base);
static e2k_size_t __read_mostly	last_valid_pfn;

struct page __read_mostly	*zeroed_page = NULL;
/* for ext4 fs */
EXPORT_SYMBOL(zeroed_page);

u64 __read_mostly zero_page_nid_to_pfn[MAX_NUMNODES] = {
	[0 ... MAX_NUMNODES-1] = 0
};
struct page __read_mostly *zero_page_nid_to_page[MAX_NUMNODES] = {
	[0 ... MAX_NUMNODES-1] = 0
};

int	e2k_kernel_started = 0;
e2k_addr_t		pci_low_bound;
e2k_addr_t		phys_hi_bound_intel;
#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
i386_pgd_t		*empty_sec_pg_dir = NULL;
e2k_addr_t		phys_mpt_base;
e2k_addr_t		*MPT;
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

int mem_init_done = 0;
int init_bootmem_done = 0;

#define PGT_CACHE_LOW	25
#define PGT_CACHE_HIGH	50

void check_pgt_cache(void)
{
	u32 cache_size;
	unsigned long flags;

	if (raw_pgtable_cache_size <= PGT_CACHE_HIGH)
		return;

	do {
		/* Disable interrupts instead of preemption since this
		 * critical section is very short. */
		local_irq_save(flags);
		if (pgd_quicklist) {
			pgd_t *pgd = pgd_alloc_fast();
			local_irq_enable();
			free_pgd_slow(pgd);
			local_irq_disable();
		}
		if (pud_quicklist) {
			pud_t *pud = pud_alloc_one_fast();
			local_irq_enable();
			free_pud_slow(pud);
			local_irq_disable();
		}
		if (pmd_quicklist) {
			pmd_t *pmd = pmd_alloc_one_fast();
			local_irq_enable();
			free_pmd_slow(pmd);
			local_irq_disable();
		}
		if (pte_quicklist) {
			pte_t *pte = pte_alloc_one_fast();
			local_irq_enable();
			free_pte_slow(pte);
			local_irq_disable();
		}
		cache_size = pgtable_cache_size;
		local_irq_restore(flags);
	} while (cache_size > PGT_CACHE_LOW);
}

struct pfn_cache {
	struct {
		unsigned long start_pfn;
		unsigned long end_pfn;
	} valid;
	struct {
		unsigned long start_pfn;
		unsigned long end_pfn;
		int node;
	} nid;
};

____cacheline_internodealigned_in_smp
static struct pfn_cache pfn_cache[NR_CPUS];


int e2k_is_pfn_valid(e2k_size_t pfn)
{
	e2k_phys_bank_t *phys_bank;
	unsigned long flags;
	int my_node;
	int node;
	int bank;
	int nodes_num = 0;
	int banks_num = 0;
	int cpu;

	DebugPV("started on node #%d for pfn 0x%lx\n",
			numa_node_id(), pfn);

	/* Fast path */

	raw_all_irq_save(flags);
	cpu = raw_smp_processor_id();
	if (likely(pfn >= pfn_cache[cpu].valid.start_pfn &&
			pfn < pfn_cache[cpu].valid.end_pfn)) {
		raw_all_irq_restore(flags);
		DebugPV("pfn 0x%lx is valid\n", pfn);
		return 1;
	}
	my_node = cpu_to_node(cpu);
	raw_all_irq_restore(flags);

	/* Slow path */

	if (unlikely(pfn < 0 || pfn >= last_valid_pfn)) {
		return 0;
	}

	for_each_online_node_from_not_preempt(node, my_node) {
		DebugPV("will check on node #%d\n",
			node);
		nodes_num ++;
		if (nodes_phys_mem[node].pfns_num == 0) {
			DebugPV("no memory on node #%d\n",
				node);
			continue;	/* no memory on node */
		}
		phys_bank = nodes_phys_mem[node].banks;
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			e2k_addr_t	bank_pfn;
			DebugPV("will check bank #%d\n",
				bank);
			if (phys_bank->pages_num == 0) {
				DebugPV("no more memory "
					"on node #%d\n", node);
				break;	/* no more memory on node */
			}
			banks_num ++;
			bank_pfn = phys_bank->base_addr >> PAGE_SHIFT;
			DebugPV("bank #%d has pfns from "
				"0x%lx to 0x%lx\n",
				bank, bank_pfn,
				bank_pfn + phys_bank->pages_num);
			if (pfn >= bank_pfn &&
					pfn < bank_pfn + phys_bank->pages_num) {
				DebugPV("pfn 0x%lx is "
					"valid on the node #%d, bank #%d\n",
					pfn, node, bank);
				raw_all_irq_save(flags);
				cpu = raw_smp_processor_id();
				pfn_cache[cpu].valid.start_pfn = bank_pfn;
				pfn_cache[cpu].valid.end_pfn = bank_pfn +
						phys_bank->pages_num;
				raw_all_irq_restore(flags);

				return 1;
			}
			phys_bank ++;
		}
		DebugPV("pfn 0x%08lx not detected on "
			"node #%d\n", pfn, node);
	}
	DebugPVE("pfn 0x%08lx is not valid last node %d "
		"node id %d last bank %d from %d nodes %d banks\n",
		pfn, node, my_node, bank, nodes_num, banks_num);
	return 0;
}
EXPORT_SYMBOL(e2k_is_pfn_valid);

int __pfn_to_nid(unsigned long pfn, bool panic_on_miss)
{
	node_phys_mem_t *node_mem;
	unsigned long flags;
	int my_node;
	int nid;
	int bank;
	int cpu;

	/* Fast path */

	raw_all_irq_save(flags);
	cpu = raw_smp_processor_id();
	if (likely(pfn >= pfn_cache[cpu].nid.start_pfn &&
			pfn < pfn_cache[cpu].nid.end_pfn)) {
		nid = pfn_cache[cpu].nid.node;
		raw_all_irq_restore(flags);
		DebugNUMA("some bank on "
				"node #%d contains our pfn 0x%lx\n",
				nid, pfn);
		return nid;
	}
	my_node = cpu_to_node(cpu);
	raw_all_irq_restore(flags);

	/* Slow path */

	DebugNUMA("started on node #%d for pfn 0x%lx online "
		"nodes 0x%lx\n",
		my_node, pfn, node_online_map.bits[0]);
	for_each_online_node_from_not_preempt(nid, my_node) {
		DebugNUMA("current node #%d\n", nid);
		node_mem = &nodes_phys_mem[nid];
		if (node_mem->pfns_num == 0) {
			DebugNUMA("node #%d has not "
				"memory\n", nid);
			continue;	/* no memory on node */
		}
		if (pfn < node_mem->start_pfn ||
			pfn >= (node_mem->start_pfn + node_mem->pfns_num)) {
			DebugNUMA("pfn is out of node #%d "
				"memory\n", nid);
			continue;
		}
		for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
			e2k_addr_t start_pfn;
			e2k_size_t pfns;

			pfns = node_mem->banks[bank].pages_num;
			DebugNUMA("current bank #%d on "
				"node #%d has pfns 0x%lx\n",
				bank, nid, pfns);
			if (pfns == 0) {
				DebugNUMA("no more memory "
					"on node #%d\n", nid);
				break;	/* no more memory on node */
			}
			start_pfn = node_mem->banks[bank].base_addr >>
								PAGE_SHIFT;
			DebugNUMA("bank #%d on "
				"node #%d start pfns is 0x%lx\n",
				bank, nid, start_pfn);
			if (pfn >= start_pfn && pfn < start_pfn + pfns) {
				DebugNUMA("bank #%d on "
					"node #%d contains our pfn 0x%lx\n",
					bank, nid, pfn);
				raw_all_irq_save(flags);
				cpu = raw_smp_processor_id();
				pfn_cache[cpu].nid.start_pfn = start_pfn;
				pfn_cache[cpu].nid.end_pfn = start_pfn + pfns;
				pfn_cache[cpu].nid.node = nid;
				raw_all_irq_restore(flags);

				return nid;
			}
		}
	}
	DebugNUMA("pfn 0x%lx was not find\n", pfn);
	if (pfn_valid(pfn)) {
		BUG();
	}

	if (panic_on_miss)
		panic("pfn_to_nid() invalid pfn 0x%lx, could not convert "
			"to node id\n", pfn);

	return -1;
}
EXPORT_SYMBOL(__pfn_to_nid);

/* This is only called until mem_init is done. */
void __init *node_early_get_page(int node)
{
	void *p;

	if (init_bootmem_done) {
		p = alloc_bootmem_pages_node(NODE_DATA(node), PAGE_SIZE);
	} else {
		BOOT_BUG_POINT("early_get_page");
		BOOT_BUG("is not implemented for boot-time mode");
		return NULL;
	}
	return p;
}
void __init *node_early_get_zeroed_page(int nid)
{
	void *p = node_early_get_page(nid);

	if (p == NULL)
		return p;
	clear_page(p);
	return p;
}


/*
 * Initialize the boot-time allocator and register the available physical
 * memory.
 */

#ifdef CONFIG_FLATMEM
static void __init notrace 
bootmem_init(void)
{
	e2k_addr_t 	start_pfn, end_pfn;
	e2k_addr_t	bootmap_pfn;
	e2k_size_t	bootmap_size;

	start_pfn = start_of_phys_memory >> PAGE_SHIFT;
	end_pfn = end_of_phys_memory >> PAGE_SHIFT;
	pfn_base = start_pfn;
	max_pfn = max_low_pfn = end_pfn;
	DebugCM("started : memory start addr "
		"0x%lx, end addr 0x%lx\n",
		start_pfn << PAGE_SHIFT, end_pfn << PAGE_SHIFT);

	/*
	 * Initialize the boot-time allocator.
	 */
	bootmap_pfn = init_bootmap_phys_base >> PAGE_SHIFT;
	bootmap_size = init_bootmem_node(NODE_DATA(0), bootmap_pfn, start_pfn,
				end_pfn);
	if (bootmap_size != init_bootmap_size) {
		INIT_BUG_POINT("bootmem_init");
		INIT_BUG("Invalid size of pages for bitmap of "
			"'linux/mm/bootmem.c' occupied 0x%lx != allocated "
			"0x%lx",
			bootmap_size / PAGE_SIZE,
			init_bootmap_size / PAGE_SIZE);
	}
	DebugCM("created bootmap : "
		"from addr 0x%lx size 0x%lx bytes\n",
		bootmap_pfn << PAGE_SHIFT, bootmap_size);
}
#else	/* ! CONFIG_FLATMEM */
extern void bootmem_init(void);
#endif /* CONFIG_FLATMEM */

static e2k_addr_t __init notrace 
setup_memory(void)
{
	e2k_size_t	free_pages_num;

	init_change_page_attr();

	/*
	 * Initialize the boot-time allocator.
	 */
	 bootmem_init();

	/*
	 * Register the available free physical memory with the
	 * allocator.
	 */
	free_pages_num = register_free_bootmem();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_end > initrd_start) {
		initrd_start = (long) phys_to_virt(initrd_start);
		initrd_end   = (long) phys_to_virt(initrd_end);
	}
#endif

	init_bootmem_done = 1;

	return free_pages_num;
}

/*
 * Initialize zone sizes
 */

void __init
calculate_zone_sizes(e2k_phys_bank_t *node_phys_banks,
		unsigned long zone_start_pfn, unsigned long zone_end_pfn,
		unsigned long *zones_size, unsigned long *zholes_size,
		unsigned long *phys_lo_bound, unsigned long *phys_hi_bound)
{
	e2k_phys_bank_t *phys_bank;
	unsigned long bank_start_pfn, bank_end_pfn, size;
	unsigned long max_zone_size;
	int bank;

	DebugZS("started for zone from 0x%08lx to "
		"0x%08lx zone size 0x%08lx holes 0x%08lx\n",
		zone_start_pfn, zone_end_pfn, *zones_size, *zholes_size);
	size = 0;
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
		phys_bank = &node_phys_banks[bank];
		if (phys_bank->pages_num == 0)
			break;	/* no more memory on node */
		bank_start_pfn = phys_bank->base_addr >> PAGE_SHIFT;
		bank_end_pfn = bank_start_pfn + phys_bank->pages_num;
		DebugZS("bank #%d from 0x%08lx to "
			"0x%08lx\n",
			bank, bank_start_pfn, bank_end_pfn);
		if (bank_start_pfn >= zone_end_pfn ||
			bank_end_pfn <= zone_start_pfn)
			continue;
		size += (bank_end_pfn - bank_start_pfn);
		DebugZS("bank #%d size 0x%08lx\n",
			bank, size);
		if (bank_start_pfn < zone_start_pfn) {
			size -= (zone_start_pfn - bank_start_pfn);
		}
		if (bank_end_pfn > zone_end_pfn) {
			size -= (bank_end_pfn - zone_end_pfn);
		}
		DebugZS("bank #%d remainder size "
			"0x%08lx\n", bank, size);
		if (phys_lo_bound != NULL) {
			DebugZS("lo bound 0x%08lx\n",
				*phys_lo_bound);
			if (*phys_lo_bound > bank_start_pfn) {
				if (bank_start_pfn <= zone_start_pfn)
					*phys_lo_bound = zone_start_pfn;
				else
					*phys_lo_bound = bank_start_pfn;
			}
			DebugZS("new lo bound 0x%08lx\n",
				*phys_lo_bound);
		}
		if (phys_hi_bound != NULL) {
			DebugZS("hi bound 0x%08lx\n",
				*phys_hi_bound);
			if (*phys_hi_bound < bank_end_pfn) {
				if (bank_end_pfn > zone_end_pfn)
					*phys_hi_bound = zone_end_pfn;
				else
					*phys_hi_bound = bank_end_pfn;
			}
			DebugZS("new hi bound 0x%08lx\n",
				*phys_hi_bound);
		}
	}
	if (size == 0)
		return;
	max_zone_size = zone_end_pfn - zone_start_pfn;
	if (size > max_zone_size) {
		INIT_BUG_POINT("calculate_zone_sizes");
		INIT_BUG("Calculated zone size 0x%lx > zone max size 0x%lx",
			size, max_zone_size);
	}
	if (*zones_size == 0) {
		/* first memory area in the zone */
		*zones_size = max_zone_size;
		*zholes_size = max_zone_size - size;
		DebugZS("set zone size to 0x%08lx "
			"holes to 0x%08lx\n",
			*zones_size, *zholes_size);
	} else {
		if (*zholes_size < size) {
			INIT_BUG_POINT("calculate_zone_sizes");
			INIT_BUG("New area size 0x%lx > current "
				"holes size 0x%lx (memory intersection)",
				size, *zholes_size);
		}
		*zholes_size = *zholes_size - size;
		DebugZS("decrement holes size to "
			"0x%08lx\n",
			*zholes_size);
	}
	if (*zones_size < *zholes_size) {
		INIT_BUG_POINT("calculate_zone_sizes");
		INIT_BUG("Zone total size 0x%lx < zone holes size 0x%lx",
			*zones_size, *zholes_size);
	}
}

void __meminit
memmap_init_node(unsigned long size, int nid, node_phys_mem_t *node_mem,
			unsigned long zone, unsigned long start_pfn)
{
	unsigned long end_pfn;
	int bank;

	DebugMI("started on node #%d zone %ld init from "
		"pfn 0x%08lx to 0x%08lx\n",
		nid, zone, start_pfn, start_pfn + size);
	node_mem = &nodes_phys_mem[nid];
	if (node_mem->pfns_num == 0) {
		printk("memmap_init_node() node #%d has not memory\n", nid);
		return;
	}
	end_pfn = start_pfn + size;
	for (bank = 0; bank < L_MAX_NODE_PHYS_BANKS; bank ++) {
		e2k_phys_bank_t	*node_bank;
		unsigned long bank_size;
		unsigned long bank_start;
		unsigned long bank_end;

		node_bank = &node_mem->banks[bank];
		bank_size = node_bank->pages_num;
		if (bank_size == 0)
			break;	/* no more memory on node */
		bank_start = node_bank->base_addr >> PAGE_SHIFT;
		bank_end = bank_start + bank_size;
		if (bank_start >= end_pfn || bank_end <= start_pfn)
			continue;	/* bank out of mapping range */
		if (bank_start < start_pfn)
			bank_start = start_pfn;
		if (bank_end > end_pfn)
			bank_end = end_pfn;
		DebugMI("on node #%d zone %ld init from "
			"pfn 0x%08lx to 0x%08lx\n",
			nid, zone, bank_start, bank_end);
		memmap_init_zone(bank_end - bank_start, nid, zone, bank_start,
				MEMMAP_EARLY);
	}
}

#ifndef CONFIG_DISCONTIGMEM
void __meminit
memmap_init(unsigned long size, int nid, unsigned long zone,
			unsigned long start_pfn)
{
	int node;

	/*
	 * At this mode only one node #0 can be as present,
	 * but memory represented as a few discontigous nodes of memory
	 * and each of them can contain some contigous banks of memory,
	 * so all memory nodes and banks join to common system node #0
	 */
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
		cur_nodes_num ++;
		memmap_init_node(size, nid, &nodes_phys_mem[node],
					zone, start_pfn);
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
	}
}

static void __init notrace
zone_sizes_init(e2k_size_t pages_avail)
{
	e2k_phys_bank_t	*node_banks;
	unsigned long	zones_size[MAX_NR_ZONES];
	unsigned long	zholes_size[MAX_NR_ZONES];
	unsigned long	npages;
	int		znum;
	e2k_addr_t	max_dma;
	int		cur_nodes_num = 0;
	int		node;

	for (znum = 0; znum < MAX_NR_ZONES; znum ++)
		zones_size[znum] = zholes_size[znum] = 0;

	max_dma = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;
	npages = last_valid_pfn - pfn_base;
	pci_low_bound = max_dma << PAGE_SHIFT;
	phys_hi_bound_intel = 0;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
		node_banks = nodes_phys_mem[node].banks;
		if (node_banks->pages_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num++;
		calculate_zone_sizes(node_banks,
			pfn_base, max_dma,
			&zones_size[ZONE_DMA],
			&zholes_size[ZONE_DMA],
			NULL, &phys_hi_bound_intel);
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
	}
	cur_nodes_num = 0;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node ++) {
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
		node_banks = nodes_phys_mem[node].banks;
		if (node_banks->pages_num == 0)
			continue;	/* node has not memory */
		cur_nodes_num++;
		calculate_zone_sizes(node_banks, max_dma, last_valid_pfn,
			&zones_size[ZONE_NORMAL],
			&zholes_size[ZONE_NORMAL],
			NULL, NULL);
		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */
	}
	DebugCM("created zone :\n"
		"   DMA    start 0x%08lx size 0x%08lx holes 0x%08lx\n"
		"   NORMAL start 0x%08lx size 0x%08lx holes 0x%08lx\n",
		pfn_base, zones_size[ZONE_DMA], zholes_size[ZONE_DMA],
		max_dma, zones_size[ZONE_NORMAL], zholes_size[ZONE_NORMAL]);
	if (pages_avail > zones_size[ZONE_DMA] - zholes_size[ZONE_DMA] +
		zones_size[ZONE_NORMAL] - zholes_size[ZONE_NORMAL]) {
		INIT_BUG_POINT("zone_sizes_init");
		INIT_BUG("Total zones size 0x%lx < available pages 0x%lx",
			zones_size[ZONE_DMA] - zholes_size[ZONE_DMA] +
			zones_size[ZONE_NORMAL] - zholes_size[ZONE_NORMAL],
			pages_avail);
	}

	free_area_init_node(0, NODE_DATA(0), zones_size,
				pfn_base, zholes_size);
}

static e2k_size_t __init notrace
get_invalid_pages_num(e2k_size_t *valid_pages_num)
{
	e2k_size_t invalid_pages_num = 0;
	struct page *page;

	*valid_pages_num = 0;
	for (page = mem_map; (page - mem_map) < max_mapnr; page ++) {
		if (page_valid(page)) {
			(*valid_pages_num) ++;
		} else {
			invalid_pages_num ++;
			DebugB("Memory page 0x%lx is invalid\n",
				virt_to_phys(page_address(page)));
		}
	}
	return invalid_pages_num;
}

#else	/* CONFIG_DISCONTIGMEM */
extern void zone_sizes_init(e2k_size_t pages_avail);
extern e2k_size_t get_invalid_pages_num(e2k_size_t *valid_pages_num);
#endif /* ! CONFIG_DISCONTIGMEM */

/*
 * Setup the page tables
 */

void __init notrace  paging_init(void)
{
	e2k_size_t	pages_avail;
	int		node;

	/*
	 * Setup the boot-time allocator.
	 */
	DebugB("Start setup of boot-time allocator\n");
	pages_avail = setup_memory();
	last_valid_pfn = end_of_phys_memory >> PAGE_SHIFT;

	/*
	 * Initialize mem_map[]
	 */
	zone_sizes_init(pages_avail);

	for_each_node_has_dup_kernel(node) {
		unsigned long addr = (unsigned long) empty_zero_page;
		pgd_t *pgd = node_pgd_offset_kernel(node, addr);
		pud_t *pud;
		pmd_t *pmd;
		pte_t *pte;

		/*
		 * Protect the zero page from writing
		 */
		if (unlikely(pgd_none_or_clear_bad_kernel(pgd))) {
			pr_warning("zero_page: pgd_none returned 1\n");
			continue;
		}
		pud = pud_offset_kernel(pgd, addr);
		if (unlikely(pud_none_or_clear_bad_kernel(pud))) {
			pr_warning("zero_page: pud_none returned 1\n");
			continue;
		}
		pmd = pmd_offset_kernel(pud, addr);
		if (unlikely(pmd_none_or_clear_bad_kernel(pmd))) {
			pr_warning("zero_page: pmd_none returned 1\n");
			continue;
		}
		if (pmd_large(*pmd)) {
			/* We cannot protect ZERO_PAGE from writing
			 * if it is mapped as part of a large page. */
			pr_warning("WARNING zero_page is mapped with large page on node %d\n",
					node);
			continue;
		}
		pte = pte_offset_kernel(pmd, addr);

		if (unlikely(pte_none(*pte) || !pte_present(*pte))) {
			pr_warning("zero_page: pte_none returned 1\n");
			continue;
		}

		set_pte(pte, __pte(pte_val(*pte) & ~_PAGE_W));

		/*
		 * Initialize the list of zero pages
		 */
		zero_page_nid_to_pfn[node] = pte_pfn(*pte);
		zero_page_nid_to_page[node] = pte_page(*pte);

		/*
		 * clear the zero-page by empty values
		 */
		recovery_memset_8((void *) _PAGE_PFN_TO_PADDR(pte_val(*pte)),
				0, ETAGEWD, sizeof(empty_zero_page),
				MAS_STORE_PA << LDST_REC_OPC_MAS_SHIFT |
				LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT);
	}

	flush_TLB_page((unsigned long) empty_zero_page, E2K_KERNEL_CONTEXT);

	zeroed_page = phys_to_page(kernel_va_to_pa(empty_zero_page));
}

#ifdef	CONFIG_SECONDARY_SPACE_SUPPORT
static void __init notrace
secondary_space_init(void)
{
	e2k_addr_t zeroed_page_addr = kernel_va_to_pa(empty_zero_page);

	if (IS_UPT_E3S) {
		printk("No need to allocate secondary space: " 
					"machine is E3S, UPT is on.\n ");
					
		set_secondary_space_MMU_state(&init_mm, NULL);
		return;
	}

	if (zeroed_page_addr & ~_MMU_CR3_PAGE_DIR) {
		e2k_addr_t sec_zeroed_page = get_zeroed_page(__GFP_IA32);
		empty_sec_pg_dir = (i386_pgd_t *)sec_zeroed_page;
		if (empty_sec_pg_dir == NULL) {
			printk("WARHING: Could not allocate memory for empty "
				"page directory to support secondary space\n");
			return;
		}
		if (((e2k_addr_t)__pa(empty_sec_pg_dir)) & ~_MMU_CR3_PAGE_DIR) {
			panic("secondary_space_init() allocated DMA memory "
				"is not in the low memory 0x%lx > 2**32\n",
				__pa(empty_sec_pg_dir));
		}
		zeroed_page = phys_to_page(virt_to_phys(sec_zeroed_page));
		SetPageReserved(zeroed_page);
	} else {
		empty_sec_pg_dir = (i386_pgd_t *)phys_to_virt(zeroed_page_addr);
	}
	printk("Set secondary space page directory register CR3 to 0x%lx\n",
		MMU_CR3_KERNEL(empty_sec_pg_dir));
	pci_low_bound =  ALIGN_MASK_DOWN(pci_low_bound,
						_MMU_PCI_L_B_ALIGN_MASK);
	if (pci_low_bound & ~_MMU_PCI_L_B) {
		panic("secondary_space_init() PCI low bound is not "
			"correctly aligned 0x%lx != 0x%lx\n",
			pci_low_bound, pci_low_bound & _MMU_PCI_L_B);
	}
	printk("Set secondary space PCI low bound to 0x%lx\n", pci_low_bound);

	phys_hi_bound_intel <<= PAGE_SHIFT;
	phys_hi_bound_intel = ALIGN_MASK_DOWN(phys_hi_bound_intel,
						_MMU_PH_H_B_ALIGN_MASK);
	if ((phys_hi_bound_intel & ~_MMU_PH_H_B) || !phys_hi_bound_intel) {
		panic("secondary_space_init() physical memory hi bound is not "
			"correctly aligned 0x%lx != 0x%lx\n",
			phys_hi_bound_intel, phys_hi_bound_intel & _MMU_PH_H_B);
	}
	printk("Set secondary space physical memory hi bound to 0x%lx\n",
		phys_hi_bound_intel);

	/* Set MMU state and enable secondary virtual space translations */
	set_secondary_space_MMU_state(&init_mm, empty_sec_pg_dir);
	printk("Secondary virtual space translations is enabled\n");
}
#else	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */
#define	secondary_space_init()	/* Nothing to do */
#endif	/* CONFIG_SECONDARY_SPACE_SUPPORT */

void __init notrace mem_init(void)
{
	e2k_size_t total_pages_num = 0;
	e2k_size_t valid_pages_num = 0;
	e2k_size_t invalid_pages_num = 0;

#ifndef CONFIG_DISCONTIGMEM
	max_mapnr = last_valid_pfn - pfn_base;
#endif	/* ! CONFIG_DISCONTIGMEM */
	high_memory = __va(last_valid_pfn << PAGE_SHIFT);

	free_all_bootmem();

	secondary_space_init();

	mem_init_print_info(NULL);

	pr_info("Page offset: %016lx, last valid phaddr: %016lx\n",
			PAGE_OFFSET, (last_valid_pfn << PAGE_SHIFT));

	total_pages_num = (end_of_phys_memory >> PAGE_SHIFT) -
				(start_of_phys_memory >> PAGE_SHIFT);
	totalreal_mem = pages_of_phys_memory << (PAGE_SHIFT-10);

#if	DEBUG_INVALID_PAGES_NUM
	invalid_pages_num = get_invalid_pages_num(&valid_pages_num);
	if (valid_pages_num + invalid_pages_num < total_pages_num) {
		/* mapped memory can intersect between nodes */
		printk("Memory total mapped pages 0x%08lx < valid pages "
			"0x%08lx + invalid 0x%08lx\n",
			total_pages_num, valid_pages_num, invalid_pages_num);
		BUG();
	}
#else	/* DEBUG_INVALID_PAGES_NUM == 0 */
	valid_pages_num = pages_of_phys_memory;
	invalid_pages_num = total_pages_num - valid_pages_num;
#endif	/* DEBUG_INVALID_PAGES_NUM != 0 */

	pr_info("Memory total mapped pages number 0x%lx : valid 0x%lx, invalid 0x%lx\n",
		total_pages_num, valid_pages_num, invalid_pages_num);

	mem_init_done = 1;
	show_free_areas(0);
}


#if defined CONFIG_BOOT_TRACE && !defined CONFIG_RECOVERY
/* The call to BOOT_TRACEPOINT is valid since it is done
 * in the beginning, before .init section is freed. */
__ref
#endif
void free_initmem (void)
{
#ifndef CONFIG_RECOVERY
	e2k_addr_t	addr;
	e2k_addr_t	stack_start;
	e2k_size_t	stack_size;
	e2k_size_t	pages;
	int		cpuid;
#endif

#ifdef CONFIG_BOOT_TRACE
	BOOT_TRACEPOINT("Boot trace finished");
	stop_boot_trace();
#endif

	free_reserved_area(__init_text_begin, __init_text_end, -1, "init text");
	free_reserved_area(__init_data_begin, __init_data_end, -1, "init data");

#ifndef	CONFIG_RECOVERY
	if (init_bootinfo_size)
		pr_info("Freeing bootinfo memory: %ldK (%lx - %lx)\n",
			init_bootinfo_size >> 10,
			(e2k_addr_t)init_bootinfo_phys_base,
			(e2k_addr_t)init_bootinfo_phys_base +
						init_bootinfo_size);

	for (addr = (e2k_addr_t) init_bootinfo_phys_base;
			addr < (e2k_addr_t) init_bootinfo_phys_base +
					    init_bootinfo_size; 
			addr += PAGE_SIZE) {
		struct page *p = phys_to_page(addr);

		free_reserved_page(p);
	}

	/*
	 * Free boot-time hardware & sofware stacks to boot kernel
	 */
	for_each_online_cpu(cpuid) {
		stack_start = kernel_boot_stack_virt_base(cpuid);
		stack_size = kernel_boot_stack_size(cpuid);
		pages = free_reserved_area(stack_start,
					   stack_start + stack_size, -1, NULL);
		pr_info("Freeing CPU%d boot-time data stack: %ldK (%lx - %lx)\n",
			cpuid, (pages * E2K_KERNEL_US_PAGE_SIZE) >> 10,
			stack_start, stack_start + stack_size);

		stack_start = kernel_boot_ps_virt_base(cpuid);
		stack_size = kernel_boot_ps_size(cpuid);
		pages = free_reserved_area(stack_start,
					   stack_start + stack_size, -1, NULL);
		pr_info("Freeing CPU%d boot-time procedure stack: %ldK (%lx - %lx)\n",
			cpuid, (pages * E2K_KERNEL_PS_PAGE_SIZE) >> 10,
			stack_start, stack_start + stack_size);

		stack_start = kernel_boot_pcs_virt_base(cpuid);
		stack_size = kernel_boot_pcs_size(cpuid);
		pages = free_reserved_area(stack_start,
					   stack_start + stack_size, -1, NULL);
		pr_info("Freeing CPU%d boot-time chain stack: %ldK (%lx - %lx)\n",
			cpuid, (pages * E2K_KERNEL_PCS_PAGE_SIZE) >> 10,
			stack_start, stack_start + stack_size);
	}
#endif	/* ! (CONFIG_RECOVERY) */

#ifdef	CONFIG_DBG_CHAIN_STACK_PROC
	if (kernel_symtab != NULL) {
		printk("The kernel symbols table addr 0x%p size 0x%lx "
			"(0x%lx ... 0x%lx)\n",
			kernel_symtab, kernel_symtab_size,
			((long *)kernel_symtab)[0],
			((long *)kernel_symtab)[kernel_symtab_size /
							sizeof (long) - 1]);
	}
	if (kernel_strtab != NULL) {
		printk("The kernel strings table addr 0x%p size 0x%lx "
			"(0x%lx ... 0x%lx)\n",
			kernel_strtab, kernel_strtab_size,
			((long *)kernel_strtab)[0],
			((long *)kernel_strtab)[kernel_strtab_size /
							sizeof (long) - 1]);
	}
#endif	/* CONFIG_DBG_CHAIN_STACK_PROC */

	e2k_kernel_started = 1;
	ide_info(USING_DMA);
#ifdef	CONFIG_EMERGENCY_DUMP
	create_dump_point();
#endif	/* CONFIG_EMERGENCY_DUMP */
}

#ifdef CONFIG_BLK_DEV_INITRD
void free_initrd_mem(unsigned long start, unsigned long end)
{

/* Nothing to make 'free'. Init RD is now included in bootinfo data.       */
/* free_initmem() now clears the reservation flags for the bootinfo pages. */ 

#if 0 
	if (start < end)
		printk("Freeing initrd memory: %ldk freed\n",
			(end - start) >> 10);

	for (; start < end; start += PAGE_SIZE) {
		struct page *p = virt_to_page(start);

		free_reserved_page(p);
	}

#endif

}
#endif

#ifndef CONFIG_DISCONTIGMEM
void
show_mem(void)
{
	printk("Mem-info:\n");
	show_free_areas();
	printk("Free swap:       %6ldkB\n", nr_swap_pages << (PAGE_SHIFT - 10));
	printk("%ld pages of RAM\n", totalram_pages);
	printk("%d free pages\n", nr_free_pages());
	printk("%d pages in page table cache\n", pgtable_cache_size);
}
#endif	/* ! CONFIG_DISCONTIGMEM */
