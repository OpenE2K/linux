/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Memory menegement initialization
 */

#include <linux/dma-direct.h>
#include <linux/memblock.h>
#include <linux/initrd.h>
#include <linux/kthread.h>
#include <linux/smpboot.h>
#include <linux/set_memory.h>
#include <linux/sizes.h>
#include <linux/suspend.h>

#include <asm/p2v/boot_init.h>
#include <asm/p2v/boot_phys.h>
#include <asm/l-iommu.h>
#include <asm/l_timer.h>
#include <asm/mmu_context.h>
#include <asm/pgalloc.h>
#include <asm/process.h>
#include <asm/pci.h>
#include <asm/epic.h>

#undef	DEBUG_INIT_MODE
#undef	DebugB
#define	DEBUG_INIT_MODE		0	/* Boot paging init */
#define DebugB(...)		DebugPrint(DEBUG_INIT_MODE ,##__VA_ARGS__)

pgd_t swapper_pg_dir[PTRS_PER_PGD] __page_aligned_bss;

#ifdef CONFIG_NEED_MULTIPLE_NODES
pg_data_t	*node_data[MAX_NUMNODES];
EXPORT_SYMBOL(node_data);
#endif
static e2k_size_t __read_mostly	last_valid_pfn;

struct page __read_mostly	*zeroed_page = NULL;
/* for ext4 fs */
EXPORT_SYMBOL(zeroed_page);

u64 __read_mostly zero_page_nid_to_pfn[MAX_NUMNODES] = {
	[0 ... MAX_NUMNODES-1] = 0xdead1212dead1212
};
EXPORT_SYMBOL(zero_page_nid_to_pfn);

struct page __read_mostly *zero_page_nid_to_page[MAX_NUMNODES] = {
	[0 ... MAX_NUMNODES-1] = NULL
};


static void __init nodes_up(void)
{
	unsigned long node_mask = 0x1;
	int node;

	nodes_clear(node_online_map);

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		if (phys_nodes_map & node_mask) {
			node_set_online(node);
		} else {
			node_mask <<= 1;
			continue;	/* node not online */
		}

		node_mask <<= 1;
	}

	if (phys_nodes_num != num_online_nodes())
		INIT_BUG("Number of online nodes %d is not the same as set %d",
			num_online_nodes(), phys_nodes_num);
}

static void notrace __init
bootmem_init(void)
{
	int		cur_nodes_num = 0;
	int		node;

	nodes_up();

	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		node_phys_mem_t		*node_mem = &boot_phys_mem[node];
		boot_phys_bank_t	*phys_bank;
		boot_phys_bank_t	*node_banks;
		e2k_addr_t		end_pfn;
		int			bank;

		if (cur_nodes_num >= phys_mem_nodes_num)
			break;		/* no more nodes with memory */

		if (!node_mem->pfns_num)
			continue;	/* node has not memory */

		end_pfn = node_mem->start_pfn + node_mem->pfns_num;
		if (end_pfn > max_low_pfn) {
			max_pfn = end_pfn;
			max_low_pfn = end_pfn;
		}

		node_banks = node_mem->banks;
		cur_nodes_num++;

		for (bank = node_mem->first_bank; bank >= 0;
				bank = phys_bank->next) {
			e2k_addr_t		start_addr;
			e2k_size_t		size;

			phys_bank = &node_banks[bank];
			if (!phys_bank->pages_num)
				/* bank in the list has not pages */
				INIT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);

			start_addr = phys_bank->base_addr;
			size = phys_bank->pages_num * PAGE_SIZE;

			if (memblock_add_node(start_addr, size, node))
				INIT_BUG("Couldn't add node %d.", node);

			if (memblock_reserve(start_addr, size))
				INIT_BUG("Couldn't reserve node %d memory.",
					node);
		}
	}
}

#ifdef CONFIG_NEED_MULTIPLE_NODES
static void __init allocate_node_datas(void)
{
	int nid;

	for_each_online_node(nid) {
		void *vaddr;

		vaddr = memblock_alloc_try_nid(sizeof(struct pglist_data),
				SMP_CACHE_BYTES, __pa(MAX_DMA_ADDRESS),
				MEMBLOCK_ALLOC_ACCESSIBLE, nid);
		if (!vaddr)
			INIT_BUG("Cannot allocate pglist_data for node %d\n",
				 nid);

		NODE_DATA(nid) = vaddr;
		memset(NODE_DATA(nid), 0, sizeof(struct pglist_data));
	}
}
#endif

/*
 * Order the physical memory areas in the bank on increase of addresses
 */
static void __init init_check_order_bank_areas(int node_id,
					boot_phys_bank_t *phys_bank)
{
	e2k_busy_mem_t	*busy_areai = NULL;
	e2k_busy_mem_t	*busy_areaj = NULL;
	e2k_size_t	start_page;
	e2k_size_t	end_page;
	int		i;
	int		j;

	DebugB("boot_order_bank_areas() started\n");
	for (i = phys_bank->first_area; i >= 0; i = busy_areai->next) {
		busy_areai = __va(&phys_bank->busy_areas[i]);
		if (busy_areai->pages_num == 0) {
			INIT_BUG("Node #%d empty physical memory busy area #%d "
				"cannot be in the list",
				node_id, i);
			continue;
		}
		start_page = busy_areai->start_page;
		end_page = start_page + busy_areai->pages_num;
		DebugB("Node #%d the reserved area #%d from page 0x%lx "
			"to 0x%lx should be ordered\n",
			node_id, i,
			phys_bank->base_addr + (start_page << PAGE_SHIFT),
			phys_bank->base_addr + (end_page << PAGE_SHIFT));
		for (j = busy_areai->next; j >= 0; j = busy_areaj->next) {
			busy_areaj = __va(&phys_bank->busy_areas[j]);
			if (busy_areaj->pages_num == 0) {
				INIT_BUG("Node #%d empty physical memory busy "
					"area #%d cannot be in the list",
					node_id, j);
				continue;
			}
			if (start_page < busy_areaj->start_page) {
				if (end_page > busy_areaj->start_page) {
					INIT_BUG("The area #%d end page 0x%lx "
						"> start page 0x%lx of "
						"area #%d",
						i, end_page,
						busy_areaj->start_page, j);
				}
				continue;
			}
			if (start_page < busy_areaj->start_page +
						busy_areaj->pages_num) {
				INIT_BUG("The area #%d start page 0x%lx < end "
					"page 0x%lx of area #%d",
					i, start_page,
					busy_areaj->start_page +
						busy_areaj->pages_num,
					j);
			}
			INIT_BUG("The reserved area #%d with start page "
				"0x%lx should be exchanged with area #%d "
				"with start page 0x%lx, sequence error\n",
				i, start_page,
				j, busy_areaj->start_page);
#ifdef	CORRECT_SEQUENCE_ERROR
			busy_areai->start_page = busy_areaj->start_page;
			busy_areai->pages_num = busy_areaj->pages_num;
			busy_areaj->start_page = start_page;
			busy_areaj->pages_num = end_page - start_page;
			start_page = busy_areai->start_page;
			end_page = start_page + busy_areai->pages_num;
#endif	/* CORRECT_SEQUENCE_ERROR */
		}
	}
}

static void __init register_free_bootmem(void)
{
	e2k_busy_mem_t		*busy_area = NULL;
	e2k_size_t		size;
	e2k_addr_t		start_addr = -1;
	e2k_size_t		start_page;
	long			pages_num;
	int			nodes_num;
	int			cur_nodes_num = 0;
	int			node = 0;
	int			bank;
	int			area;

	nodes_num = phys_mem_nodes_num;
	for (node = 0; node < L_MAX_MEM_NUMNODES; node++) {
		node_phys_mem_t *node_mem = &boot_phys_mem[node];
		boot_phys_bank_t *node_banks;
		boot_phys_bank_t *phys_bank;

		if (cur_nodes_num >= nodes_num)
			break;	/* no more nodes with memory */
		if (node_mem->pfns_num == 0)
			continue;	/* node has not memory */
		node_banks = node_mem->banks;
		cur_nodes_num++;
		for (bank = node_mem->first_bank;
				bank >= 0;
					bank = phys_bank->next) {
			phys_bank = &node_banks[bank];

			if (phys_bank->pages_num == 0) {
				/* bank in the list has not pages */
				INIT_BUG("Node #%d bank #%d at the list "
					"has not memory pages",
					node, bank);
			}

			if (phys_bank->busy_areas_num == 0) {
				/*
				 * The bank is fully free
				 */
				start_addr = phys_bank->base_addr;
				size = phys_bank->pages_num * PAGE_SIZE;
				memblock_free(start_addr, size);
				DebugB("Node #%d bank #%d register free memory "
					"from 0x%lx to 0x%lx\n",
					node, bank,
					start_addr, start_addr + size);
				continue;
			}

			/*
			 * Scan list of all busy areas of physical memory bank
			 * and collect the holes of contiguous free pages.
			 */
			start_page = 0;
			start_addr = phys_bank->base_addr;
			init_check_order_bank_areas(node, phys_bank);
			for (area = phys_bank->first_area;
					area >= 0;
						area = busy_area->next) {
				busy_area = __va(&phys_bank->busy_areas[area]);
				if (busy_area->pages_num == 0) {
					INIT_BUG("Node #%d bank #%d empty "
						"physical memory busy area #%d "
						"cannot be in the list",
						node, bank, area);
					continue;
				}
				if (busy_area->flags &
					BOOT_RESERVED_TO_FREE_PHYS_MEM)
					/* the area was reserved to free */
					/* it now */
					continue;

				pages_num = busy_area->start_page - start_page;
				size = pages_num * PAGE_SIZE;
				if (size != 0) {
					memblock_free(start_addr, size);
					DebugB("Node #%d bank #%d register "
						"free memory from 0x%lx "
						"to 0x%lx\n",
						node, bank,
						start_addr, start_addr + size);
				}
				start_page = busy_area->start_page +
							busy_area->pages_num;
				start_addr = phys_bank->base_addr +
							start_page * PAGE_SIZE;
			}
			if (start_page < phys_bank->pages_num) {
				pages_num = phys_bank->pages_num - start_page;
				size = pages_num * PAGE_SIZE;
				memblock_free(start_addr, size);
				DebugB("Node #%d bank #%d register free "
					"memory from 0x%lx to 0x%lx\n",
					node, bank,
					start_addr, start_addr + size);
			}

			memblock_free((phys_addr_t)phys_bank->busy_areas,
				BOOT_RESERVED_AREAS_SIZE);
			DebugB("Node #%d bank #%d register free memory from 0x%lx to 0x%lx\n",
				node, bank, phys_bank->busy_areas,
				phys_bank->busy_areas +
				BOOT_RESERVED_AREAS_SIZE);
		}
	}
}

/*
 * Initialize the boot-time allocator and register the available physical
 * memory.
 */
static void __init notrace
setup_memory(void)
{
	/*
	 * Initialize the boot-time allocator.
	 */
	bootmem_init();

	/*
	 * Register the available free physical memory with the
	 * allocator.
	 */
	register_free_bootmem();

#ifdef CONFIG_BLK_DEV_INITRD
	if (initrd_end > initrd_start) {
		initrd_start = (long) phys_to_virt(initrd_start);
		initrd_end   = (long) phys_to_virt(initrd_end);
	}
#endif

	memblock_set_current_limit(end_of_phys_memory);

#ifdef CONFIG_NEED_MULTIPLE_NODES
	allocate_node_datas();
#endif

	last_valid_pfn = end_of_phys_memory >> PAGE_SHIFT;
}

static void __init
zone_sizes_init(void)
{
	unsigned long max_zone_pfns[MAX_NR_ZONES];
	unsigned long max_dma_pfn;

#if defined(CONFIG_ZONE_DMA32) || defined(CONFIG_HIGHMEM)
	BUG();
#endif

	memset(max_zone_pfns, 0, sizeof(max_zone_pfns));

	max_dma_pfn = virt_to_phys((char *)MAX_DMA_ADDRESS) >> PAGE_SHIFT;

	max_zone_pfns[ZONE_DMA] = min(max_dma_pfn, max_low_pfn);
	max_zone_pfns[ZONE_NORMAL] = max_low_pfn;

	free_area_init(max_zone_pfns);
}

#ifdef CONFIG_MEMORY_HOTPLUG
int arch_add_memory(int nid, u64 start, u64 size,
		    struct mhp_params *params)
{
	BUG();
	return 0;
}

void arch_remove_memory(int nid, u64 start, u64 size,
			struct vmem_altmap *altmap)
{
	BUG();
}

#endif

#ifdef CONFIG_SPARSEMEM_VMEMMAP
#ifdef CONFIG_MEMORY_HOTPLUG
void vmemmap_free(unsigned long start, unsigned long end,
		  struct vmem_altmap *altmap)
{
	BUG();
}
#endif

int __meminit vmemmap_populate(unsigned long start, unsigned long end, int node,
			       struct vmem_altmap *altmap)
{
	int ret;

	BUILD_BUG_ON(VMEMMAP_END > KERNEL_VPTB_BASE_ADDR ||
		     VMEMMAP_END > NATIVE_HWBUG_WRITE_MEMORY_BARRIER_ADDRESS);

	ret = vmemmap_populate_basepages(start, end, node, NULL);
	if (ret) {
		pr_err("%s(): could not populate sparse memory VMEMMAP from 0x%lx to 0x%lx, error %d\n",
				__func__, start, end, ret);
		return ret;
	}

	return 0;
}
#endif	/* CONFIG_SPARSEMEM_VMEMMAP */

/*
 * CONFIG_SPARSEMEM_VMEMMAP has a drawback: it works only in big chunks of
 * memory called "sections" with section size defined by SECTION_SIZE_BITS.
 * It cannot be set low otherwise the memory usage by the sections array
 * would be too high.
 *
 * As a result, VGA area [0xa0000-0xc0000] is reported as valid by pfn_valid()
 * and attempted to be saved and restored by hibernation code.  Work around
 * this by explicitly marking all non RAM areas as nosave.
 *
 * If pfn_valid() gets rid of legacy stuff like section_early() then this
 * workaround will probably become unnecessary.
 */
static int __init mark_nonram_nosave(void)
{
	unsigned long spfn, epfn, prev = 0;
	int i;

	for_each_mem_pfn_range(i, MAX_NUMNODES, &spfn, &epfn, NULL) {
		if (prev && prev < spfn)
			register_nosave_region(prev, spfn);

		prev = epfn;
	}
	return 0;
}

/*
 * Setup the page tables
 */
void __init notrace paging_init(void)
{
#ifdef CONFIG_NUMA
	int node;

	/* Chicken and egg problem:
	 *   sparse_init() -> pgd_populate() -> pgds_nodemask
	 *     AND
	 *   pgds_nodemask -> page_nid() -> zone_sizes_init() -> sparse_init()
	 *
	 * To solve it we first set pgds_nodemask for 0 node so pgd_populate()
	 * works. Then we use page_to_nid() to find out which node does
	 * swapper_pg_dir actually belong to. */
	node_set(0, init_mm.context.pgds_nodemask);
	init_mm.context.mm_pgd_node = 0;
#endif

#ifndef CONFIG_MMU_SEP_VIRT_SPACE_ONLY
	init_task.thread.regs.k_root_ptb = __pa(swapper_pg_dir);
#endif

	/*
	 * Setup the boot-time allocator.
	 */
	DebugB("Start setup of boot-time allocator\n");
	zone_dma_bits = 32;
	setup_memory();

	create_protection_map(protection_map);
	sparse_init();
	zone_sizes_init();

	mark_nonram_nosave();

#ifdef CONFIG_NUMA
	/* page_to_nid() works because zone_sizes_init() has finished */
	node = page_to_nid(phys_to_page(__pa(swapper_pg_dir)));
	node_clear(0, init_mm.context.pgds_nodemask);
	node_set(node, init_mm.context.pgds_nodemask);
	init_mm.context.mm_pgd_node = node;
#endif
}

static void setup_zero_pages(void)
{
	int node;

	/* Clear the zero-page */
	fast_tagged_memory_set(empty_zero_page,
			0, CLEAR_MEMORY_TAG, sizeof(empty_zero_page),
			LDST_DWORD_FMT << LDST_REC_OPC_FMT_SHIFT);

	/* It will be duplicated later when memory subsystem is initialized */
	for_each_node(node) {
		phys_addr_t pa = __pa_symbol(empty_zero_page);
		zero_page_nid_to_pfn[node] = PHYS_PFN(pa);
		zero_page_nid_to_page[node] = phys_to_page(pa);
	}

	zeroed_page = zero_page_nid_to_page[numa_node_id()];
}

static void __init preallocate_dynamic_pgds_range(
		unsigned long start, unsigned long end)
{
	unsigned long addr;

	for (addr = start; addr < end; addr += PGDIR_SIZE) {
		pgd_t *pgd = pgd_offset_k(addr);

		if (pgd_none(*pgd)) {
			pud_t *pud = pud_alloc(&init_mm, pgd, addr);
			WARN_ON(!pud);
		}
	}
}

static void __init preallocate_dynamic_pgds(void)
{
	BUG_ON(E2K_MODULES_END <= E2K_MODULES_START);

	/* User threads in !SEPARATE case use each their own pgd page
	 * with both user and kernel pgds, so we preallocate all pgds
	 * before any user threads are created. This way there wil be
	 * no page faults on vmalloc or module areas.
	 *
	 * In SEPARATE case user threads do not have kernel pgd in their
	 * page tables, hardware always uses the same pgd from init_mm
	 * and there will be no page faults on vmalloc/module areas even
	 * without preallocation. */
	if (MMU_IS_SEPARATE_PT())
		return;

	preallocate_dynamic_pgds_range(MODULES_VADDR, MODULES_END);
	preallocate_dynamic_pgds_range(VMALLOC_START, VMALLOC_END);
}

void __init notrace mem_init(void)
{
	e2k_size_t total_pages_num = 0;
	e2k_size_t valid_pages_num = 0;
	e2k_size_t invalid_pages_num = 0;

	high_memory = __va(last_valid_pfn << PAGE_SHIFT);

	this_cpu_write(u_root_ptb, __pa(mm_node_pgd(&init_mm, numa_node_id())));

	memblock_free_all();

	set_secondary_space_MMU_state();

	setup_zero_pages();

	preallocate_dynamic_pgds();

	if (cpu_has(CPU_FEAT_ISET_V6)) {
		if (MMU_IS_PT_V6()) {
			pr_info("MMU: Page Table entries new format V6 "
				"is used\n");
		} else {
			pr_info("MMU: Page Table entries old legacy format "
				"is used\n");
		}
	} else {
		pr_info("MMU: Page Table entries old format V1 is used\n");
	}
	if (MMU_IS_SEPARATE_PT()) {
		pr_info("MMU: Separate Page Tables for kernel and users\n");
		pr_info("Kernel page table virt base: 0x%lx\n",
			MMU_SEPARATE_KERNEL_VPTB);
		pr_info("User page table virt base: 0x%lx\n",
			MMU_SEPARATE_USER_VPTB);
	} else {
		pr_info("MMU: United Page Tables for kernel and user\n");
		pr_info("kernel and users page table virt base: 0x%lx\n",
			MMU_UNITED_KERNEL_VPTB);
	}
	pr_info("kernel virt base: 0x%lx, kernel virt end: 0x%lx\n",
		KERNEL_BASE, KERNEL_END);
	pr_info("linear mapping virt base: %016lx, last valid phaddr: %016lx\n",
		PAGE_OFFSET, (last_valid_pfn << PAGE_SHIFT));

	total_pages_num = (end_of_phys_memory >> PAGE_SHIFT) -
				(start_of_phys_memory >> PAGE_SHIFT);
	valid_pages_num = pages_of_phys_memory;
	invalid_pages_num = total_pages_num - valid_pages_num;

	pr_info("Memory total mapped pages number 0x%lx : valid 0x%lx, invalid 0x%lx\n",
		total_pages_num, valid_pages_num, invalid_pages_num);

	mem_init_print_info(NULL);
}

void mark_rodata_ro(void)
{
	unsigned long size = __end_ro_after_init - __start_ro_after_init;

	if (!size)
		return;

	set_memory_ro((unsigned long)__start_ro_after_init,
				size >> PAGE_SHIFT);
	kernel_image_duplicate_page_range(__start_ro_after_init, size, false);

	pr_info("Write protected %sread-only-after-init data: %luk\n",
			(IS_ENABLED(CONFIG_NUMA)) ? "and NUMA duplicated " : "",
			size >> 10);
}

/* The call to BOOT_TRACEPOINT and get_lt_timer is valid since it is done
 * in the beginning, before .init section is freed. */
__ref
void free_initmem(void)
{
#if !defined(CONFIG_RECOVERY) && !defined(CONFIG_E2K_KEXEC)
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

	if (cpu_has(CPU_HWBUG_E8C_WATCHDOG)) {
		get_lt_timer();
		lt_regs_eioh_t __iomem *lt_regs_eioh = NULL;
		if (cpu_has_epic()) {
			lt_regs_eioh = (lt_regs_eioh_t __iomem *)lt_regs;
		}
		writel(WD_EVENT, lt_regs_eioh
				? &lt_regs_eioh->wd_control
				: &((lt_regs_eioh_t __iomem *)lt_regs)->wd_control);
		writel(WD_SET_COUNTER_VAL(0), &((lt_regs_eioh_t __iomem *)lt_regs)->wd_limit);
	}

	WARN_ON(set_memory_np((unsigned long) &__init_begin,
			      ((unsigned long) &__init_end -
			       (unsigned long) &__init_begin) / PAGE_SIZE));
	free_initmem_default(POISON_FREE_INITMEM);

#if !defined(CONFIG_RECOVERY) && !defined(CONFIG_E2K_KEXEC)
	/*
	 * Free boot-time hardware & sofware stacks to boot kernel
	 */
	for_each_online_cpu(cpuid) {
		stack_start = kernel_boot_stack_virt_base(cpuid);
		stack_size = kernel_boot_stack_size(cpuid);
		pages = free_reserved_area((void *)stack_start,
					   (void *)(stack_start + stack_size),
					   -1, NULL);
		pr_info("Freeing CPU%d boot-time data stack: %ldK (%lx - %lx)\n",
			cpuid, (pages * E2K_KERNEL_US_PAGE_SIZE) >> 10,
			stack_start, stack_start + stack_size);

		stack_start = kernel_boot_ps_virt_base(cpuid);
		stack_size = kernel_boot_ps_size(cpuid);
		pages = free_reserved_area((void *)stack_start,
					   (void *)(stack_start + stack_size),
					   -1, NULL);
		pr_info("Freeing CPU%d boot-time procedure stack: %ldK (%lx - %lx)\n",
			cpuid, (pages * E2K_KERNEL_PS_PAGE_SIZE) >> 10,
			stack_start, stack_start + stack_size);

		stack_start = kernel_boot_pcs_virt_base(cpuid);
		stack_size = kernel_boot_pcs_size(cpuid);
		pages = free_reserved_area((void *)stack_start,
					   (void *)(stack_start + stack_size),
					   -1, NULL);
		pr_info("Freeing CPU%d boot-time chain stack: %ldK (%lx - %lx)\n",
			cpuid, (pages * E2K_KERNEL_PCS_PAGE_SIZE) >> 10,
			stack_start, stack_start + stack_size);
	}
#endif	/* ! (CONFIG_RECOVERY) */

#ifdef	CONFIG_DBG_CHAIN_STACK_PROC
	if (kernel_symtab != NULL) {
		printk("The kernel symbols table addr 0x%px size 0x%lx "
			"(0x%lx ... 0x%lx)\n",
			kernel_symtab, kernel_symtab_size,
			((long *)kernel_symtab)[0],
			((long *)kernel_symtab)[kernel_symtab_size /
							sizeof (long) - 1]);
	}
	if (kernel_strtab != NULL) {
		printk("The kernel strings table addr 0x%px size 0x%lx "
			"(0x%lx ... 0x%lx)\n",
			kernel_strtab, kernel_strtab_size,
			((long *)kernel_strtab)[0],
			((long *)kernel_strtab)[kernel_strtab_size /
							sizeof (long) - 1]);
	}
#endif	/* CONFIG_DBG_CHAIN_STACK_PROC */
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

/*
 * System memory should not be in /proc/iomem but various tools expect it
 * (eg kdump).
 */
static int __init add_system_ram_resources(void)
{
	struct memblock_region *reg;

	for_each_mem_region(reg) {
		struct resource *res;
		unsigned long base = reg->base;
		unsigned long size = reg->size;

		res = kzalloc(sizeof(struct resource), GFP_KERNEL);
		WARN_ON(!res);

		if (res) {
			res->name = "System RAM";
			res->start = base;
			res->end = base + size - 1;
			res->flags = IORESOURCE_SYSTEM_RAM | IORESOURCE_BUSY;
			WARN_ON(request_resource(&iomem_resource, res) < 0);
		}
	}

	return 0;
}
subsys_initcall(add_system_ram_resources);

int kern_addr_valid(unsigned long addr)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (addr >= E2K_VA_END || addr < PAGE_OFFSET)
		return 0;

	pgd = pgd_offset_k(addr);
	if (pgd_none(*pgd))
		return 0;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d))
		return 0;

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud))
		return 0;

	if (kernel_pud_huge(*pud))
		return pfn_valid(pud_pfn(*pud));

	pmd = pmd_offset(pud, addr);
	if (pmd_none(*pmd))
		return 0;

	if (kernel_pmd_huge(*pmd))
		return pfn_valid(pmd_pfn(*pmd));

	pte = pte_offset_kernel(pmd, addr);
	if (pte_none(*pte))
		return 0;

	return pfn_valid(pte_pfn(*pte));
}

__pure
bool __virt_addr_valid(unsigned long kaddr)
{
	if (likely(kaddr >= PAGE_OFFSET && kaddr < PAGE_OFFSET + MAX_PM_SIZE ||
		   kaddr >= KERNEL_BASE && kaddr < KERNEL_END))
		return pfn_valid(__pa(kaddr) >> PAGE_SHIFT);

	return false;
}
EXPORT_SYMBOL(__virt_addr_valid);

__init
static int init_trampolines_area(void)
{
	int i, nr_pages = E2K_TRAMPOLINES_SIZE / PAGE_SIZE;
	struct page *pages[nr_pages];

	/* Paravirt. guest will use hypervisor's trampolines */
	if (IS_ENABLED(CONFIG_KVM_GUEST_KERNEL))
		return 0;

	void *addr = alloc_pages_exact(E2K_TRAMPOLINES_SIZE, GFP_KERNEL | __GFP_NOFAIL);
	memcpy(addr, __trampolines_start, __trampolines_end - __trampolines_start);

	for (i = 0; i < nr_pages; i++) {
		pages[i] = virt_to_page(addr + i * PAGE_SIZE);
	}
	BUG_ON(map_kernel_range_noflush(E2K_TRAMPOLINES_START,
			E2K_TRAMPOLINES_SIZE, PAGE_USER_EXEC, pages));
	flush_cache_vmap(E2K_TRAMPOLINES_START, E2K_TRAMPOLINES_END);

	return 0;
}
arch_initcall(init_trampolines_area);
