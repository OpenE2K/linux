/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2024 MCST
 */

#include <linux/dma-direct.h>
#include <linux/init_task.h>
#include <linux/kasan.h>
#include <linux/kernel.h>
#include <linux/memblock.h>
#include <linux/mmu_context.h>

#include <asm/tlbflush.h>
#include <asm/traps.h>
#include <asm/vga.h>

static pgd_t tmp_pg_dir[PTRS_PER_PGD] __initdata __aligned(PGD_TABLE_SIZE);

static phys_addr_t __init kasan_alloc_page(int node)
{
	u64 init_value = memset_pattern_u64(KASAN_SHADOW_INIT);
	u64 *p = memblock_alloc_try_nid_raw(PAGE_SIZE, PAGE_SIZE,
					     __pa(MAX_DMA_ADDRESS),
					     MEMBLOCK_ALLOC_ACCESSIBLE, node);
	BUG_ON(!p);
	for (int i = 0; i < PAGE_SIZE / sizeof(p[0]); i++)
		p[i] = init_value;
	return __pa(p);
}

static pte_t *__init kasan_pte_offset(pmd_t *pmdp, unsigned long addr, int node,
				      bool early)
{
	if (pmd_none(READ_ONCE(*pmdp))) {
		phys_addr_t pte_phys = early ? __pa(kasan_early_shadow_pte)
					     : kasan_alloc_page(node);
		set_pmd(pmdp,
			__pmd(_PAGE_PADDR_TO_PFN(pte_phys) | _PAGE_KERNEL_PTE));
	}

	return pte_offset_kernel(pmdp, addr);
}

static pmd_t *__init kasan_pmd_offset(pud_t *pudp, unsigned long addr, int node,
				      bool early)
{
	if (pud_none(READ_ONCE(*pudp))) {
		phys_addr_t pmd_phys = early ? __pa(kasan_early_shadow_pmd)
					     : kasan_alloc_page(node);
		set_pud(pudp,
			__pud(_PAGE_PADDR_TO_PFN(pmd_phys) | _PAGE_KERNEL_PMD));
	}

	return pmd_offset(pudp, addr);
}

static pud_t *__init kasan_pud_offset(p4d_t *p4dp, unsigned long addr, int node,
				      bool early)
{
	if (p4d_none(READ_ONCE(*p4dp))) {
		phys_addr_t pud_phys = early ? __pa(kasan_early_shadow_pud)
					     : kasan_alloc_page(node);
		set_p4d(p4dp, __p4d(_PAGE_PADDR_TO_PFN(pud_phys) | _PAGE_KERNEL_PUD));
	}

	return pud_offset(p4dp, addr);
}

static p4d_t *__init kasan_p4d_offset(pgd_t *pgdp, unsigned long addr, int node,
				      bool early)
{
#if CONFIG_PGTABLE_LEVELS > 4
	if (pgd_none(READ_ONCE(*pgdp))) {
		phys_addr_t p4d_phys = early ? __pa(kasan_early_shadow_p4d)
					     : kasan_alloc_page(node);
		set_pgd(pgdp, __pgd(_PAGE_PADDR_TO_PFN(p4d_phys) | _PAGE_KERNEL_PUD));
	}
#endif

	return p4d_offset(pgdp, addr);
}

static void __init kasan_pte_populate(pmd_t *pmdp, unsigned long addr,
				      unsigned long end, int node, bool early)
{
	unsigned long next;
	pte_t *ptep = kasan_pte_offset(pmdp, addr, node, early);

	do {
		phys_addr_t page_phys = early ? __pa(kasan_early_shadow_page)
					      : kasan_alloc_page(node);
		next = addr + PAGE_SIZE;
		set_pte(ptep, pfn_pte(__phys_to_pfn(page_phys), PAGE_KERNEL));
		ptep++;
		addr = next;
	} while (addr != end && pte_none(READ_ONCE(*ptep)));
}

static void __init kasan_pmd_populate(pud_t *pudp, unsigned long addr,
				      unsigned long end, int node, bool early)
{
	unsigned long next;
	pmd_t *pmdp = kasan_pmd_offset(pudp, addr, node, early);

	do {
		next = pmd_addr_end(addr, end);
		kasan_pte_populate(pmdp, addr, next, node, early);
		pmdp++;
		addr = next;
	} while (addr != end && pmd_none(READ_ONCE(*pmdp)));
}

static void __init kasan_pud_populate(p4d_t *p4dp, unsigned long addr,
				      unsigned long end, int node, bool early)
{
	unsigned long next;
	pud_t *pudp = kasan_pud_offset(p4dp, addr, node, early);

	do {
		next = pud_addr_end(addr, end);
		kasan_pmd_populate(pudp, addr, next, node, early);
		pudp++;
		addr = next;
	} while (addr != end && pud_none(READ_ONCE(*pudp)));
}

void print_address_page_tables(unsigned long address, int last_level_only);

static void __init kasan_p4d_populate(pgd_t *pgdp, unsigned long addr,
				      unsigned long end, int node, bool early)
{
	unsigned long next;
	p4d_t *p4dp = kasan_p4d_offset(pgdp, addr, node, early);

	do {
		next = p4d_addr_end(addr, end);
		kasan_pud_populate(p4dp, addr, next, node, early);
	} while (p4dp++, addr = next, addr != end);
}

static void __init kasan_pgd_populate(unsigned long addr, unsigned long end,
				      int node, bool early)
{
	unsigned long next;
	pgd_t *pgdp;

	pgdp = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		kasan_p4d_populate(pgdp, addr, next, node, early);
	} while (pgdp++, addr = next, addr != end);
}

/* The early shadow maps everything to a single page of zeroes */
void __init kasan_early_init(void)
{
	int i;
	pteval_t pte_val = __pa(kasan_early_shadow_page) | _PAGE_KERNEL;
	pmdval_t pmd_val = __pa(kasan_early_shadow_pte) | _PAGE_KERNEL_PTE;
	pudval_t pud_val = __pa(kasan_early_shadow_pmd) | _PAGE_KERNEL_PMD;

	for (i = 0; i < PTRS_PER_PTE; i++)
		kasan_early_shadow_pte[i] = __pte(pte_val);

	for (i = 0; i < PTRS_PER_PMD; i++)
		kasan_early_shadow_pmd[i] = __pmd(pmd_val);

	for (i = 0; i < PTRS_PER_PUD; i++)
		kasan_early_shadow_pud[i] = __pud(pud_val);

#if CONFIG_PGTABLE_LEVELS > 4
	p4dval_t p4d_val = __pa(kasan_early_shadow_pud) | _PAGE_KERNEL_PUD;
	for (i = 0; i < PTRS_PER_P4D; i++)
		kasan_early_shadow_p4d[i] = __p4d(p4d_val);
#endif

	kasan_pgd_populate(KASAN_SHADOW_START, KASAN_SHADOW_END, NUMA_NO_NODE, true);
	/* Remove "empty" TLB entries from semi-spec. loads */
	flush_TLB_all();
}

/* Set up full kasan mappings, ensuring that the mapped pages are zeroed */
static void __init kasan_map_populate(unsigned long start, unsigned long end, int node)
{
	kasan_pgd_populate(start & PAGE_MASK, PAGE_ALIGN(end), node, false);
}

static void __init clear_pgds(unsigned long start, unsigned long end)
{
	/*
	 * Remove references to kasan page tables from
	 * kernel_root_pt. pgd_clear() can't be used
	 * here because it's nop on 2,3-level pagetable setups
	 */
	for (; start < end; start += PGDIR_SIZE)
		set_pgd(pgd_offset_k(start), __pgd(0));
}

void __init kasan_init(void)
{
	u64 kimg_shadow_start, kimg_shadow_end;
	phys_addr_t pa_start, pa_end;
	u64 i;

	kimg_shadow_start = (u64)kasan_mem_to_shadow(_text) & PAGE_MASK;
	kimg_shadow_end = PAGE_ALIGN((u64)kasan_mem_to_shadow(_end));

	/*
	 * We are going to perform proper setup of shadow memory.
	 * At first we should unmap early shadow (clear_pgds() call bellow).
	 * However, instrumented code couldn't execute without shadow memory.
	 * tmp_pg_dir used to keep early shadow mapped until full shadow
	 * setup will be finished.
	 */
	memcpy(tmp_pg_dir, swapper_pg_dir, sizeof(tmp_pg_dir));
	set_root_pt(tmp_pg_dir);
	flush_TLB_all();

	clear_pgds(KASAN_SHADOW_START, KASAN_SHADOW_END);

	/* Populate kernel addresses from 0xe20000000000 */
	kasan_map_populate(kimg_shadow_start, kimg_shadow_end,
			   early_pfn_to_nid(virt_to_pfn(lm_alias(_text))));

	/* Populate linear mapping */
	for_each_mem_range(i, &pa_start, &pa_end) {
		void *start = __va(pa_start);
		void *end = __va(pa_end);

		if (start >= end)
			break;

		kasan_map_populate((unsigned long)kasan_mem_to_shadow(start),
				   (unsigned long)kasan_mem_to_shadow(end),
				   early_pfn_to_nid(virt_to_pfn(start)));
	}

	/* Map the early shadow over the VGA and vmemmap space */
	kasan_populate_early_shadow(kasan_mem_to_shadow((void *) VMEMMAP_START),
			kasan_mem_to_shadow((void *) VMEMMAP_END));
	void *vga_start = __va(VGA_VRAM_PHYS_BASE);
	void *vga_end = __va(VGA_VRAM_PHYS_BASE + VGA_VRAM_SIZE);
	kasan_populate_early_shadow(kasan_mem_to_shadow(vga_start),
			kasan_mem_to_shadow(vga_end));

	/* Switch to the prepared mappings */
	set_root_pt(swapper_pg_dir);
	flush_TLB_all();

	/* Data stack usage have filled kasan_early_shadow_page, clear it now */
	memset(kasan_early_shadow_page, 0, PAGE_SIZE);

	/* And remap kasan_early_shadow_page read-only, no memory
	 * can be allocated there anymore */
	for (i = 0; i < PTRS_PER_PTE; i++) {
		set_pte(&kasan_early_shadow_pte[i],
			__pte(__pa(kasan_early_shadow_page) | _PAGE_KERNEL_RO));
	}

	/* At this point kasan is fully initialized. Enable error messages */
	init_task.kasan_depth = 0;
	pr_info("KernelAddressSanitizer initialized\n");
}
