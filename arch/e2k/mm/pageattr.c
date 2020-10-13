/*
 * Same as arch/i386/mm/pageattr.c
 *
 * Copyright 2002 Andi Kleen, SuSE Labs.
 * Thanks to Ben LaHaise for precious feedback.
 */ 

#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/pgalloc.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include <asm/e2k_debug.h>

#undef	DEBUG_CHANGE_ATTR_MODE
#undef	DebugCA
#define DEBUG_CHANGE_ATTR_MODE	0
#define DebugCA(...)		DebugPrint(DEBUG_CHANGE_ATTR_MODE ,##__VA_ARGS__)

#undef	DEBUG_CHANGE_ADDR_MODE
#undef	DebugAA
#define DEBUG_CHANGE_ADDR_MODE	0
#define DebugAA(...)		DebugPrint(DEBUG_CHANGE_ADDR_MODE ,##__VA_ARGS__)

#undef	DEBUG_PAGEALLOC_MODE
#undef	DebugPA
#define DEBUG_PAGEALLOC_MODE	0
#define DebugPA(...)		DebugPrint(DEBUG_PAGEALLOC_MODE ,##__VA_ARGS__)

#undef	DEBUG_LARGE_ATTR_MODE
#undef	DebugLA
#define DEBUG_LARGE_ATTR_MODE	0
#define DebugLA(...)		DebugPrint(DEBUG_LARGE_ATTR_MODE ,##__VA_ARGS__)

#undef	DEBUG_SPLIT_MODE
#undef	DebugSPA
#define DEBUG_SPLIT_MODE 	1
#define DebugSPA(...)		DebugPrint(DEBUG_SPLIT_MODE ,##__VA_ARGS__)

#define	PTE_PAGES_PER_LARGE_PAGE ((LARGE_PAGE_SIZE / PAGE_SIZE) / PTRS_PER_PTE)

static DEFINE_RAW_SPINLOCK(cpa_lock);
static struct list_head df_list[MAX_NUMNODES] = { LIST_HEAD_INIT(df_list[0]) };

static void set_large_pte(pte_t *kpte, pte_t pte)
{
	set_pte(kpte, pte);
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE) {
		set_pte(++ kpte, pte);
		DebugPA("set large page pmd[0] 0x%p = 0x%lx "
			"pmd[1] 0x%p = 0x%lx\n",
			-- kpte, pte_val(*kpte), ++ kpte, pte_val(*kpte));
	} else {
		DebugPA("set large page pmd[0] 0x%p = 0x%lx\n",
			kpte, pte_val(*kpte));
	}
}

static void set_small_pte(pte_t *kpte, struct page *split)
{
	pmd_t *kpmd = (pmd_t *)kpte;
	e2k_addr_t address = (e2k_addr_t)page_address(split);
	int i;

	for (i = 0; i < PTE_PAGES_PER_LARGE_PAGE; i ++) {
		pmd_set_k(kpmd, address);
		DebugAA("set ptes page pmd 0x%p = 0x%lx "
			"to addr 0x%lx\n",
			kpmd, pmd_val(*kpmd), address);
		kpmd ++;
		address += PAGE_SIZE;
	}
}

#ifndef	CONFIG_NUMA

static inline pte_t *lookup_address(e2k_addr_t address)
{ 
	pgd_t *pgd = pgd_offset_kernel(address); 
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd))
		return NULL;
	pud = pud_offset_kernel(pgd, address);
	if (pud_none(*pud))
		return NULL;
	pmd = pmd_offset_kernel(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	if (pmd_large(*pmd)) {
		pte = (pte_t *) pmd_offset_kernel(pud,
					(address & LARGE_PAGE_MASK));
		DebugAA("returns large page pte 0x%p = 0x%lx for address 0x%lx\n",
			pte, pte_val(*pte), address);
		return pte;
	}
	pte = pte_offset_kernel(pmd, address);
	DebugAA("returns page pte 0x%p = 0x%lx for address 0x%lx\n",
		pte, pte_val(*pte), address);
        return pte;
} 

static struct page *split_large_page(pte_t *kpte, e2k_addr_t address,
					pgprot_t prot)
{
	int i;
	unsigned long addr;
	struct page *kpte_page;
	pte_t *pbase;
	int pages = get_order(PTE_PAGES_PER_LARGE_PAGE * PTE_SIZE);

	raw_spin_unlock_irq(&cpa_lock);
	kpte_page = alloc_pages(GFP_KERNEL, pages);
	raw_spin_lock_irq(&cpa_lock);
	if (!pte_huge(*kpte)) {
		/* other splitted already the large page */
		pte_t *pte; 
		__free_pages(kpte_page, pages);
		kpte_page = pte_page(*kpte);
		DebugSPA("splitted already from "
			"0x%p (address 0x%p), counter is %d\n",
			kpte_page, page_address(kpte_page),
			page_count(kpte_page));
		pte = lookup_address(address);
		BUG_ON(pte == NULL);
		BUG_ON(pte_huge(*pte));
		BUG_ON(!pte_present(*pte));
		set_pte(pte, pfn_pte(address >> PAGE_SHIFT, prot));
		DebugSPA("set pte 0x%p = 0x%lx for "
			"address 0x%lx\n",
			pte, pte_val(*pte), address);
		return (struct page *) -1;
	}
	if (!kpte_page)
		return NULL;
	for (i = 0; i < PTE_PAGES_PER_LARGE_PAGE; i++) {
		DebugAA("allocated page #%d from "
			"0x%p (address 0x%p), counter is %d\n",
			i, &kpte_page[i], page_address(&kpte_page[i]),
			page_count(&kpte_page[i]));
	}

	address = __pa(address);
	addr = address & LARGE_PAGE_MASK;
	pbase = (pte_t *)page_address(kpte_page);
	for (i = 0; i < (PTRS_PER_PTE * (1<<pages)); i++, addr += PAGE_SIZE) {
		if (addr == address) {
			set_pte(&pbase[i], pfn_pte(addr >> PAGE_SHIFT, prot));
			DebugAA("set pte 0x%p = 0x%lx for "
				"address 0x%lx\n",
				&pbase[i], pte_val(pbase[i]), address);
		} else {
			set_pte(&pbase[i], pfn_pte(addr >> PAGE_SHIFT,
								PAGE_KERNEL));
			if (i % PTRS_PER_PTE == 0) {
				DebugAA("set pte 0x%p = "
					"0x%lx for address 0x%lx\n",
					&pbase[i], pte_val(pbase[i]), addr);
			}
		}
	}
	return kpte_page;
}

/*
 * No more special protections in this 4MB area - revert to a
 * large page again.
 */
static inline void revert_page(struct page *kpte_page, e2k_addr_t address)
{
	pte_t *linear = (pte_t *)
		pmd_offset_kernel(pud_offset_kernel(pgd_offset_kernel(address),
				address),
			(address & LARGE_PAGE_MASK));
	DebugAA("will revert to large page 0x%p pmd 0x%p "
		"for addr 0x%lx\n",
		kpte_page, linear, address);
	set_large_pte(linear,
		    pfn_pte((__pa(address) & LARGE_PAGE_MASK) >> PAGE_SHIFT,
			    PAGE_KERNEL_LARGE));
}

static int
__change_page_attr(struct page *page, pgprot_t prot)
{ 
	pte_t *kpte; 
	unsigned long address;
	struct page *kpte_page;

	address = (unsigned long)page_address(page);
	DebugAA("starts with page 0x%p "
		"for addr 0x%lx\n",
		page, address);

	kpte = lookup_address(address);
	if (!kpte)
		return -EINVAL;
	kpte_page = virt_to_page(((unsigned long)kpte) & PAGE_MASK);
	DebugCA("will change pte 0x%p == 0x%lx to "
		"0x%lx, kernel 0x%lx\n",
		kpte, pte_val(*kpte), pgprot_val(prot),
		pgprot_val(PAGE_KERNEL));
	if (pgprot_val(prot) != pgprot_val(PAGE_KERNEL)) {
		if (!pte_huge(*kpte)) {
			pte_t old = *kpte;
			pte_t standard = mk_pte(page, PAGE_KERNEL);
			set_pte(kpte, mk_pte(page, prot));
			if (!cpu_has(CPU_HWBUG_LARGE_PAGES))
				kpte_page = virt_to_page(
					(e2k_addr_t) lookup_address(
					address & LARGE_PAGE_MASK) & PAGE_MASK);
			if (page_count(kpte_page) != 0/*pte_same(old, standard)*/)
				get_page(kpte_page);
			DebugCA("changed pte 0x%p = 0x%lx "
				"for small page, ptes page 0x%p count is %d\n",
				kpte, pte_val(*kpte), kpte_page,
				page_count(kpte_page));
		} else {
			struct page *split;
			split = split_large_page(kpte, address, prot);
			if (split == (struct page *)-1)
				return 0;	/* already splitted */
			if (!split)
				return -ENOMEM;
			kpte_page = split;
			get_page(kpte_page);
			set_small_pte(kpte, split);
			DebugCA("splited large page, "
				"ptes page 0x%p count is %d\n",
				kpte_page, page_count(kpte_page));
		}
	} else if (!pte_huge(*kpte)) {
		set_pte(kpte, mk_pte(page, PAGE_KERNEL));
		if (!cpu_has(CPU_HWBUG_LARGE_PAGES))
			kpte_page = virt_to_page((e2k_addr_t) lookup_address(
					address & LARGE_PAGE_MASK) & PAGE_MASK);
		put_page(kpte_page);
		DebugCA("recovered pte 0x%p = 0x%lx, "
			"for small page, ptes page 0x%p count is %d\n",
			kpte, pte_val(*kpte), kpte_page,
			page_count(kpte_page));
		if (!cpu_has(CPU_HWBUG_LARGE_PAGES)
				&& page_count(kpte_page) == 1) {
			list_add(&kpte_page->lru, &df_list[numa_node_id()]);
			revert_page(kpte_page, address);
		}
	}
	return 0;
}
#else	/* CONFIG_NUMA */

static inline struct page *node_alloc_pt_pages(int nid, int order)
{
	struct page *kpt_page;
	int my_node = numa_node_id();
	struct list_head *my_df_list = &df_list[my_node];

	if (mem_init_done) {
		kpt_page = alloc_pages_node(nid, GFP_ATOMIC, order);
		if (kpt_page == NULL)
			kpt_page = alloc_pages(GFP_ATOMIC, order);
	} else {
		kpt_page = alloc_pages(GFP_ATOMIC, order);
	}
	if (kpt_page != NULL)
		return kpt_page;
	if (list_empty(my_df_list))
		return NULL;
	raw_spin_lock_irq(&cpa_lock);
	if (list_empty(my_df_list)) {
		raw_spin_unlock_irq(&cpa_lock);
		return NULL;
	}
	kpt_page = list_entry(my_df_list->prev, struct page, lru);
	list_del(&kpt_page->lru);
	raw_spin_unlock_irq(&cpa_lock);
	return kpt_page;
}

static inline pte_t *node_lookup_address(int nid, e2k_addr_t address)
{ 
	pgd_t *pgd = node_pgd_offset_kernel(nid, address); 
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd))
		return NULL;
	pud = pud_offset_kernel(pgd, address);
	if (pud_none(*pud))
		return NULL;
	pmd = pmd_offset_kernel(pud, address);
	if (pmd_none(*pmd))
		return NULL;

	if (pmd_large(*pmd)) {
		pte = (pte_t *) pmd_offset_kernel(pud,
					(address & LARGE_PAGE_MASK));
		DebugAA("returns large page pte 0x%p = 0x%lx for address 0x%lx\n",
			pte, pte_val(*pte), address);
		return pte;
	}
	pte = pte_offset_kernel(pmd, address);
	DebugAA("returns page pte 0x%p = 0x%lx for address 0x%lx\n",
		pte, pte_val(*pte), address);
        return pte;
} 

static struct page *node_split_large_page(int nid, pte_t *kpte,
				e2k_addr_t address, pgprot_t prot)
{
	int i;
	unsigned long addr;
	struct page *kpte_page;
	pte_t *pbase;
	int pages = get_order(PTE_PAGES_PER_LARGE_PAGE * PTE_SIZE);

retry:
	raw_spin_unlock_irq(&cpa_lock);
	kpte_page = node_alloc_pt_pages(nid, pages);
	raw_spin_lock_irq(&cpa_lock);
	if (!pte_huge(*kpte)) {
		/* other splitted already the large page */
		pte_t *pte; 
		raw_spin_unlock_irq(&cpa_lock);
		__free_pages(kpte_page, pages);
		raw_spin_lock_irq(&cpa_lock);
		if (pte_huge(*kpte))
			goto retry;
		kpte_page = pte_page(*kpte);
		DebugSPA("CPU #%d node_split_large_page() NODE #%d address "
			"0x%lx splitted already from page 0x%p "
			"(address 0x%p), counter is %d\n",
			smp_processor_id(), nid,
			address, kpte_page, page_address(kpte_page),
			page_count(kpte_page));
		pte = node_lookup_address(nid, address);
		BUG_ON(pte == NULL);
		BUG_ON(pte_huge(*pte));
		BUG_ON(!pte_present(*pte));
		set_pte(pte, pfn_pte(address >> PAGE_SHIFT, prot));
		get_page(kpte_page);
		DebugSPA("CPU #%d node_split_large_page() set NODE #%d pte "
			"0x%p = 0x%lx for address 0x%lx, counter is %d\n",
			smp_processor_id(), nid,
			pte, pte_val(*pte), address, page_count(kpte_page));
		return (struct page *) -1;
	}
	if (!kpte_page) {
		printk("node_split_large_page() no memory to split large "
			"page for address 0x%lx\n", address);
		return NULL;
	}
	for (i = 0; i < PTE_PAGES_PER_LARGE_PAGE; i++) {
		DebugAA("allocated page #%d from "
			"0x%p (address 0x%p), counter is %d, node #%d\n",
			i, &kpte_page[i], page_address(&kpte_page[i]),
			page_count(&kpte_page[i]), nid);
	}

	address = __pa(address);
	addr = address & LARGE_PAGE_MASK;
	pbase = (pte_t *)page_address(kpte_page);
	for (i = 0; i < (PTRS_PER_PTE * (1 << pages)); i++,
							addr += PAGE_SIZE) {
		if (addr == address) {
			set_pte(&pbase[i], pfn_pte(addr >> PAGE_SHIFT, prot));
			DebugAA("set on node #%d pte "
				"0x%p = 0x%lx for address 0x%lx\n",
				nid, &pbase[i], pte_val(pbase[i]), address);
		} else {
			set_pte(&pbase[i], pfn_pte(addr >> PAGE_SHIFT,
								PAGE_KERNEL));
			if (i % PTRS_PER_PTE == 0) {
				DebugAA("set on node "
					"#%d pte 0x%p = 0x%lx for address "
					"0x%lx\n",
					nid, &pbase[i],
					pte_val(pbase[i]), addr);
			}
		}
	}
	return kpte_page;
}

/*
 * No more special protections in this 4MB area - revert to a
 * large page again.
 */
static inline void node_revert_page(int nid,
				struct page *kpte_page, e2k_addr_t address)
{
	pte_t *linear = (pte_t *)
		pmd_offset_kernel(
			pud_offset_kernel(
				node_pgd_offset_kernel(nid, address),
				address),
			(address & LARGE_PAGE_MASK));
	DebugLA("CPU #%d node_revert_page() will revert on node #%d to large "
		"page 0x%p pmd 0x%p for addr 0x%lx\n",
		smp_processor_id(), nid, kpte_page, linear, address);
	set_large_pte(linear,
		    pfn_pte((__pa(address) & LARGE_PAGE_MASK) >> PAGE_SHIFT,
			    PAGE_KERNEL_LARGE));
}

static int
__node_change_page_attr(int nid, struct page *page, pgprot_t prot)
{ 
	pte_t *kpte; 
	unsigned long address;
	struct page *kpte_page;

	address = (unsigned long)page_address(page);
	DebugAA("starts on node #%d with page "
		"0x%p for addr 0x%lx\n",
		nid, page, address);

	kpte = node_lookup_address(nid, address);
	if (!kpte)
		return -EINVAL;
	kpte_page = virt_to_page((void *) ((unsigned long) kpte & PAGE_MASK));
	DebugCA("will change pte 0x%p == 0x%lx to "
		"0x%lx, on node #%d\n",
		kpte, pte_val(*kpte), pgprot_val(prot), nid);
	if (pgprot_val(prot) != pgprot_val(PAGE_KERNEL)) {
		if (!pte_huge(*kpte)) {
			pte_t old = *kpte;
			pte_t standard = mk_pte(page, PAGE_KERNEL);
			BUG_ON(!pte_present(old));
			set_pte(kpte, mk_pte(page, prot));
			if (!cpu_has(CPU_HWBUG_LARGE_PAGES))
				kpte_page = virt_to_page(
					(e2k_addr_t)node_lookup_address(nid,
					address & LARGE_PAGE_MASK) & PAGE_MASK);
			if (page_count(kpte_page) != 0
					/*pte_same(old, standard)*/)
				get_page(kpte_page);
			DebugCA("changed pte "
				"0x%p = 0x%lx for small page, ptes page "
				"0x%p count is %d\n",
				kpte, pte_val(*kpte), kpte_page,
				page_count(kpte_page));
		} else {
			struct page *split;

			split = node_split_large_page(nid, kpte, address,
									prot);
			if (split == (struct page *)-1) {
				return 0;	/* already splitted */
			}
			if (!split)
				return -ENOMEM;
			kpte_page = split;
			get_page(kpte_page);
			set_small_pte(kpte, split);
			DebugCA("splited large "
				"page on node #%d, ptes page 0x%p count "
				"is %d\n",
				nid, kpte_page, page_count(kpte_page));
		}
	} else if (!pte_huge(*kpte)) {
//		BUG_ON(pte_present(*kpte));
		if (pte_present(*kpte)) {
			printk("CPU #%d __node_change_page_attr() NODE #%d pte "
				"already enabled 0x%p = 0x%lx for addr 0x%lx\n",
				smp_processor_id(), nid,
				kpte, pte_val(*kpte), address);
		}
		set_pte(kpte, mk_pte(page, PAGE_KERNEL));
		if (!cpu_has(CPU_HWBUG_LARGE_PAGES))
			kpte_page = virt_to_page(
					(e2k_addr_t) node_lookup_address(nid,
					address & LARGE_PAGE_MASK) & PAGE_MASK);
		put_page(kpte_page);
		DebugCA("recovered on node #%d pte "
			"0x%p = 0x%lx, for small page, ptes page 0x%p count "
			"is %d\n",
			nid, kpte, pte_val(*kpte), kpte_page,
			page_count(kpte_page));
	}
	return 0;
}
static int
__change_page_attr(struct page *page, pgprot_t prot)
{
	int nid;
	int err = 0;

	for_each_node_has_dup_kernel(nid) {
		err |= __node_change_page_attr(nid, page, prot);
	}
	return err;
}
#endif	/* ! CONFIG_NUMA */

/*
 * Change the page attributes of an page in the linear mapping.
 *
 * This should be used when a page is mapped with a different caching policy
 * than write-back somewhere - some CPUs do not like it when mappings with
 * different caching policies exist. This changes the page attributes of the
 * in kernel linear mapping too.
 * 
 * The caller needs to ensure that there are no conflicting mappings elsewhere.
 * This function only deals with the kernel linear map.
 * 
 * Caller must call global_flush_tlb() after this.
 */
int
change_page_attr(struct page *page, int numpages, pgprot_t prot)
{
	int err = 0; 
	int i; 
	unsigned long flags;
	e2k_addr_t start = (e2k_addr_t)page_address(page);
	e2k_size_t size = numpages * PAGE_SIZE;

	DebugPA("started from addr 0x%lx to 0x%lx, "
		"set to 0x%lx\n",
		start, start + size, pgprot_val(prot));
	raw_spin_lock_irqsave(&cpa_lock, flags);
	for (i = 0; i < numpages; i++, page++) { 
		err = __change_page_attr(page, prot);
		if (err) 
			break; 
	} 	
	raw_spin_unlock_irqrestore(&cpa_lock, flags);
	return err;
}

/*
 * Start and end pfns limited by 32 bits value
 * In e2k case phys addr size = 40 bits, page number = 12 bits,
 * so pfn = 40 - 12 = 28 (can increase phys addr to 44 bits only)
 */
typedef	unsigned long	def_flush_area_t;
typedef struct def_flush_ktlb_fields {
	def_flush_area_t	start_pfn	: 32;
	def_flush_area_t	end_pfn		: 32;
} def_flush_ktlb_fields_t;
typedef union def_flush_ktlb {
	def_flush_ktlb_fields_t	fields;	/* as fields */
	def_flush_area_t	word;	/* as entire value */
} def_flush_ktlb_t;
#define	FLUSH_AREA_START_PFN	fields.start_pfn
#define	FLUSH_AREA_END_PFN	fields.end_pfn
#define	FLUSH_AREA_VALUE	word

static void flush_kernel_map_ipi(void* info)
{
	__write_back_cache_all();
	__flush_tlb_all();
}

void flush_map(void)
{
	smp_call_function(flush_kernel_map_ipi, NULL, 1);
	flush_kernel_map_ipi(NULL);
}

void node_flush_tlb(int nid)
{ 
	LIST_HEAD(l);
	struct list_head* n;

	DebugLA("CPU #%d node_flush_tlb() started for NODE #%d\n",
		smp_processor_id(), nid);

	raw_spin_lock_irq(&cpa_lock);
	list_splice_init(&df_list[nid], &l);
	raw_spin_unlock_irq(&cpa_lock);
	n = l.next;
	while (n != &l) {
		struct page *pg = list_entry(n, struct page, lru);
		n = n->next;
		DebugLA("will free page 0x%p "
			"(address 0x%p)\n",
			pg, page_address(pg));
		__free_pages(pg, get_order(PTE_PAGES_PER_LARGE_PAGE *
								PTE_SIZE));
	}
}
void global_flush_tlb(void)
{
	int nid;

	DebugLA("started\n");

	BUG_ON(irqs_disabled());

	flush_map();
	for_each_node_has_dup_kernel(nid) {
		node_flush_tlb(nid);
	}
}
static void *test_generic_alloc_page(e2k_size_t size)
{
	struct page * pages;
	int order = get_order(size);
	int numpages = 1 << order;
	int error;

	pages = alloc_pages(GFP_KERNEL, order);
	if (pages == NULL)
		return 0;

	error = change_page_attr(pages, numpages, PAGE_KERNEL_NOCACHE);
	if (error) {
		printk("test_generic_alloc_page() : change_page_attr() "
			"failed with error %d\n",
			error);
		return 0;
	}
	get_page(pages);
	__set_page_locked(pages);
	global_flush_tlb();
	return page_address(pages);
}

static void test_generic_destroy_page(void *addr, e2k_size_t size)
{
	struct page *pages;
	int order = get_order(size);
	int numpages = 1 << order;
	int error;

	if (addr == NULL)
		return;

	pages = virt_to_page(addr);
	error = change_page_attr(pages, numpages, PAGE_KERNEL);
	if (error) {
		printk("test_generic_destroy_page() : change_page_attr() "
			"failed with error %d\n",
			error);
	}
	put_page(pages);
	unlock_page(pages);
	free_pages((unsigned long)addr, order);
	global_flush_tlb();
}

#define	TEST_CHANGE_ATTR_SIZE	(PAGE_SIZE * 3)
#define	TEST_CHANGE_ATTR_LOOP	3

static void do_test_change_page_attr(void)
{
	e2k_addr_t *notcached_space = NULL;
	e2k_size_t size = TEST_CHANGE_ATTR_SIZE;
	int i;

	notcached_space = test_generic_alloc_page(size);
	if (notcached_space == NULL) {
		printk("Could not change page attributes\n");
		return;
	}
	for (i = 0; i < size / sizeof (*notcached_space); i ++) {
		notcached_space[i] = (e2k_addr_t)&notcached_space[i];
	}
	for (i = 0; i < size / sizeof (*notcached_space); i ++) {
		if (notcached_space[i] != (e2k_addr_t)&notcached_space[i]) {
			printk("test_change_page_attr(NOCACHE) failed : "
				"notcached_space[%d] 0x%016lx != 0x%016lx\n",
				i, notcached_space[i],
				(e2k_addr_t)&notcached_space[i]);
			return;
		}
	}
	test_generic_destroy_page(notcached_space, size);
	for (i = 0; i < size / sizeof (*notcached_space); i ++) {
		if (notcached_space[i] != (e2k_addr_t)&notcached_space[i]) {
			printk("test_change_page_attr(CACHE) failed : "
				"notcached_space[%d] 0x%016lx != 0x%016lx\n",
				i, notcached_space[i],
				(e2k_addr_t)&notcached_space[i]);
			return;
		}
	}
}

void test_change_page_attr(void)
{
	int i;

	for (i = 0; i < TEST_CHANGE_ATTR_LOOP; i ++) {
		do_test_change_page_attr();
	}
}

#ifdef CONFIG_DEBUG_PAGEALLOC
void kernel_map_pages(struct page *page, int numpages, int enable)
{
	e2k_addr_t start = (e2k_addr_t)page_address(page);
	e2k_addr_t end = start + (numpages * PAGE_SIZE);

	__flush_tlb_all();

	/*
	 * large pages are not disabled at boot time.
	 */
	change_page_attr(page, numpages, enable ? PAGE_KERNEL : __pgprot(0));

	/*
	 * we should perform an IPI and flush all tlbs,
	 * but that can deadlock->flush only current cpu.
	 * and call defered flush on other CPUs
	 */
	__flush_tlb_range_and_pgtables(&init_mm, start, end);
}
#endif

void __init init_change_page_attr(void)
{
	int nid;

	for (nid = 0; nid < MAX_NUMNODES; nid ++) {
		INIT_LIST_HEAD(&df_list[nid]);
	}
}

EXPORT_SYMBOL(change_page_attr);
EXPORT_SYMBOL(global_flush_tlb);
EXPORT_SYMBOL(test_change_page_attr);
