/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Boot-time support of mappings physical memory areas into
 * the kernel virtual space.
 */

#include <asm/p2v/boot_v2p.h>
#include <asm/pic.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_map.h>
#include <asm/p2v/boot_pgtable.h>
#include <asm/process.h>
#include <asm/mmu_regs_access.h>

#undef	DEBUG_BOOT_MAP_MODE
#undef	boot_printk
#define	DEBUG_BOOT_MAP_MODE	0	/* Boot map process */
#define	boot_printk		if (DEBUG_BOOT_MAP_MODE) do_boot_printk

#undef	DEBUG_MAP_EQUAL_MODE
#undef	DebugME
#define	DEBUG_MAP_EQUAL_MODE	0	/* Map equal addresses */
#define	DebugME			if (DEBUG_MAP_EQUAL_MODE) do_boot_printk

#undef	DEBUG_MAP_AREA_MODE
#undef	DebugMA
#define	DEBUG_MAP_AREA_MODE	0	/* Map physical area to virtual */
#define	DebugMA			if (DEBUG_MAP_AREA_MODE) do_boot_printk

#undef	DEBUG_MAP_VERBOSE_MODE
#undef	DebugMAV
#define	DEBUG_MAP_VERBOSE_MODE	0	/* Verbose mapping of physical area */
#define	DebugMAV		if (DEBUG_MAP_VERBOSE_MODE) do_boot_printk


static DEFINE_BOOT_SPINLOCK(boot_page_table_lock);

static inline int
boot_get_pt_level_id(const pt_level_t *pt_level)
{
	/* now PT level is number of the level */
	return get_pt_level_id(pt_level);
}

static inline bool
boot_is_pt_level_of_page_size(e2k_size_t page_size,
			const pt_struct_t *pt_struct,
			int level)
{
	return pt_struct->levels[level].page_size == page_size;
}

static inline const pt_level_t *
boot_find_pt_level_of_page_size(e2k_size_t page_size)
{
	const pt_struct_t *pt_struct = boot_pgtable_struct_p;
	int level;

	for (level = pt_struct->levels_num; level > 0; level--) {
		if (boot_is_pt_level_of_page_size(page_size, pt_struct, level))
			return &pt_struct->levels[level];
	}
	return NULL;
}

static inline bool
boot_is_huge_pte(pgprot_t *ptp, const pt_struct_t *pt_struct, int level)
{
	const pt_level_t *pt_level = &pt_struct->levels[level];
	pte_t pte = *(pte_t *)ptp;

	if (pt_level->is_huge)
		return pte_huge(pte);
	return false;
}

static inline pte_t *
boot_get_huge_pte(e2k_addr_t virt_addr, pgprot_t *ptp, const pt_level_t *pt_level)
{
	if (unlikely(!pt_level->is_huge)) {
		BOOT_BUG("Page table level #%d cannot contain page "
			"table entries (pte)\n",
			boot_get_pt_level_id(pt_level));
		return (pte_t *)-1;
	}

	return (pte_t *)ptp;
}

static inline __init_recv void
boot_set_pte(e2k_addr_t addr, pte_t *ptep, pte_t pte, const pt_level_t *pt_level,
		bool host_map)
{
	if (unlikely(!pt_level->is_pte && !pt_level->is_huge)) {
		BOOT_BUG("Page table level #%d cannot contain page "
			"table entries (pte)\n",
			boot_get_pt_level_id(pt_level));
	}

	if (pt_level->is_huge)
		pte = pte_set_large_size(pte);
	else
		pte = pte_set_small_size(pte);

	DebugMAV("boot_set_pte() will set pte 0x%px to 0x%lx for "
		"address 0x%lx %s mapping\n",
		ptep, pte_val(pte), addr,
		(host_map) ? "host" : "native");
	boot_set_pte_kernel(addr, ptep, pte);
}

/*
 * Allocate memory for first-level (high part of middle) page table directory
 */
static pud_t * __init_recv
boot_pud_alloc(void)
{
	pud_t	*pudp;
	int	entry;

	pudp = (pud_t *)boot_alloc_phys_mem(PUD_TABLE_SIZE, PAGE_SIZE,
					boot_time_data_mem_type);
	if (pudp == (pud_t *)-1) {
		BOOT_BUG("Could not allocate memory for first-level page table (PUD)");
		return (pud_t *)-1;
	}
	for (entry = 0; entry < PTRS_PER_PUD; entry++) {
		pud_clear_kernel(&pudp[entry]);
	}
	return pudp;
}

/*
 * Allocate memory for second-level (low part of middle) page table directory
 */
static pmd_t * __init_recv
boot_pmd_alloc(void)
{
	pmd_t	*pmdp;
	int	entry;

	pmdp = (pmd_t *)boot_alloc_phys_mem(PMD_TABLE_SIZE, PAGE_SIZE,
					boot_time_data_mem_type);
	if (pmdp == (pmd_t *)-1) {
		BOOT_BUG("Could not allocate memory for second-level page table (PMD)");
		return (pmd_t *)-1;
	}
	for (entry = 0; entry < PTRS_PER_PMD; entry++) {
		pmd_clear_kernel(&pmdp[entry]);

	}
	return pmdp;
}

/*
 * Allocate memory for third-level page table
 */
static pte_t * __init_recv
boot_pte_alloc(void)
{
	pte_t	*ptep;
	int	entry;

	ptep = (pte_t *)boot_alloc_phys_mem(PTE_TABLE_SIZE, PAGE_SIZE,
					boot_time_data_mem_type);
	if (ptep == (pte_t *)-1) {
		BOOT_BUG("Could not allocate memory for third-level page table (PTE)");
		return (pte_t *)-1;
	}
	for (entry = 0; entry < PTRS_PER_PTE; entry++) {
		pte_clear_kernel(&ptep[entry]);

	}
	return ptep;
}

/*
 * Get virtual address entry in the third-level page table.
 */

static pte_t * __init_recv
boot_get_pte(e2k_addr_t virt_addr, const pt_level_t *pt_level, int user, int va)
{
	const pt_struct_t *pt_struct = boot_pgtable_struct_p;
	e2k_size_t page_size = pt_level->page_size;
	int level;
	pgd_t *pgdp;
	p4d_t *p4dp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	DebugMAV("boot_get_pte() started for virt addr 0x%lx page size 0x%lx\n",
		virt_addr, page_size);

	/*
	 * Get entry in the 4-th root-level page table
	 */
	level = pt_struct->levels_num;
	pgdp = boot_pgd_offset_k(virt_addr);
	DebugMAV("boot_get_pte() pgd pointer is %px == 0x%lx\n", pgdp, pgd_val(*pgdp));
	if (boot_is_pt_level_of_page_size(page_size, pt_struct, level))
		return boot_get_huge_pte(virt_addr, (pgprot_t *)pgdp, pt_level);

	p4dp = boot_p4d_offset(pgdp, virt_addr);
	if (p4d_none(*p4dp)) {
		if (va) {
			BOOT_BUG("Could not find PGD for virtual address 0x%lx while reset",
				virt_addr);
			return (pte_t *)-1;

		}
		pudp = boot_pud_alloc();
		if (pudp == (pud_t *)-1) {
			BOOT_BUG("Could not allocate memory for PUD to map virtual address 0x%lx",
				virt_addr);
			return (pte_t *)-1;
		}
		if (user) {
			boot_p4d_set_u(p4dp, pudp);
		} else {
			boot_p4d_set_k(p4dp, pudp);
		}
	} else if (boot_is_huge_pte((pgprot_t *)p4dp, pt_struct, level)) {
		BOOT_BUG("Page table level #%d PGD 0x%lx contains already pte "
			"0x%lx of other page size not 0x%lx",
			level, p4dp, p4d_val(*p4dp), page_size);
		return (pte_t *)-1;
	}

	/*
	 * Get entry in the 3-th level (high part of middle) page table
	 */
	level--;
	pudp = boot_pud_offset(p4dp, virt_addr);
	if (boot_is_pt_level_of_page_size(page_size, pt_struct, level))
		return boot_get_huge_pte(virt_addr, (pgprot_t *)pudp, pt_level);
	if (pud_none(*pudp)) {
		if (va) {
			BOOT_BUG("Could not find PUD for virtual address 0x%lx while reset",
				virt_addr);
			return (pte_t *)-1;

		}
		pmdp = boot_pmd_alloc();
		if (pmdp == (pmd_t *)-1) {
			BOOT_BUG("Could not allocate memory for PMD to map virtual address 0x%lx",
				virt_addr);
			return (pte_t *)-1;
		}
		if (user) {
			boot_pud_set_u(pudp, pmdp);
		} else {
			boot_pud_set_k(pudp, pmdp);
		}
	} else if (boot_is_huge_pte((pgprot_t *)pudp, pt_struct, level)) {
		BOOT_BUG("Page table level #%d PUD 0x%lx contains already pte "
			"0x%lx of other page size not 0x%lx",
			level, pudp, pud_val(*pudp), page_size);
		return (pte_t *)-1;
	}

	/*
	 * Get entry in the 2-nd level (low part of middle) page table
	 */
	level--;
	pmdp = boot_pmd_offset(pudp, virt_addr);
	if (boot_is_pt_level_of_page_size(page_size, pt_struct, level))
		return boot_get_huge_pte(virt_addr, (pgprot_t *)pmdp, pt_level);
	if (pmd_none(*pmdp)) {
		if (va) {
			BOOT_BUG("Could not find PMD for virtual address 0x%lx "
				"while reset",
				virt_addr);
			return (pte_t *)-1;

		}
		ptep = boot_pte_alloc();
		if (ptep == (pte_t *)-1) {
			BOOT_BUG("Could not allocate memory for PTE to map "
				"virtual address 0x%lx",
				virt_addr);
			return (pte_t *)-1;
		}
		if (user) {
			boot_pmd_set_u(pmdp, ptep);
		} else {
			boot_pmd_set_k(pmdp, ptep);
		}
	} else if (boot_is_huge_pte((pgprot_t *)pmdp, pt_struct, level)) {
		BOOT_BUG("Page table level #%d PMD 0x%lx contains already pte "
			"0x%lx of other page size not 0x%lx",
			level, pmdp, pmd_val(*pmdp), page_size);
		return (pte_t *)-1;
	}

	/*
	 * Get entry in the 1-st-level page table
	 */
	level--;
	ptep = boot_pte_offset(pmdp, virt_addr);
	DebugMAV("boot_get_pte() pte pointer is %px == 0x%lx\n",
		ptep, pte_val(*ptep));
	return ptep;
}

/*
 * Initialization of boot-time support of physical areas mapping
 * to virtual space.
 */
void __init boot_init_mapping(int bsp)
{
	int root_pt_index;
	pgd_t *pgdp;

	/* Since V6 hardware support has been simplified
	 * and self-pointing pgd is not required anymore. */
	if (boot_machine.native_iset_ver >= E2K_ISET_V6)
		return;

	pgdp = boot_va_to_pa(swapper_pg_dir);
	root_pt_index = pgd_index(KERNEL_VPTB_BASE_ADDR);
	boot_vmlpt_pgd_set(&pgdp[root_pt_index], pgdp);
}

/*
 * Map the physical area to the kernel virtual space.
 * Function return number of mapped pages or 0, if error was detected,
 * for example if some of the pages is already mapped
 */

long __init_recv
boot_do_map_phys_area(e2k_addr_t phys_area_addr, e2k_size_t phys_area_size,
			e2k_addr_t area_virt_addr, pgprot_t prot_flags,
			const pt_level_t *pt_level,
			bool ignore_busy, bool host_map)
{
	pte_t		pte;
	pgprot_t	prot = prot_flags;
	pte_t		*ptep;
	e2k_addr_t	phys_addr;
	e2k_addr_t	virt_addr;
	e2k_size_t	page_size;
	int		pages_num;
	int		page;

	page_size = pt_level->page_size;
	if (phys_area_addr == (e2k_addr_t)-1) {
		phys_addr = 0;
		pages_num = (round_up(area_virt_addr + phys_area_size,
				      page_size) - area_virt_addr) / page_size;
		prot = pgprot_present_flag_reset(prot);
	} else {
		if ((phys_area_addr & (page_size - 1)) != 0) {
			BOOT_BUG("Physical adress 0x%lx is not page size 0x%lx "
				"aligned",
				phys_area_addr, page_size);
			return -EINVAL;
		}
		phys_addr = ALIGN_DOWN(phys_area_addr, page_size);
		pages_num = (ALIGN(phys_area_addr + phys_area_size,
				page_size) - phys_addr) / page_size;
	}
	if ((area_virt_addr & (page_size - 1)) != 0) {
		BOOT_BUG("Virtual adress 0x%lx is not page size 0x%lx aligned",
			area_virt_addr, page_size);
		return -EINVAL;
	}
	virt_addr = area_virt_addr;
	DebugMA("boot_map_phys_area() will map from phys addr 0x%lx, pages "
		"num 0x%x to virtual base 0x%lx\n",
		phys_addr, pages_num, virt_addr);

	boot_spin_lock(&boot_page_table_lock);
	for (page = 0; page < pages_num; page++) {
		ptep = boot_get_pte(virt_addr, pt_level,
					0,	/* user ? */
					0	/* va ? */);
		if (ptep == (pte_t *)-1) {
			boot_spin_unlock(&boot_page_table_lock);
			BOOT_BUG("Could not get PTE pointer to map virtual "
				"address 0x%lx",
				virt_addr);
			return 0;
		}
		if (!pte_none(*ptep)) {
			DebugMA("boot_map_phys_area() pte %px == 0x%lx is not "
				"empty\n",
				ptep, pte_val(*ptep));
			if (!ignore_busy) {
				boot_spin_unlock(&boot_page_table_lock);
				boot_printk(" pte:%px pte_Val: 0x%px\n",
					ptep,  pte_val(*ptep));
				BOOT_BUG("The PTE entry is not empty to map "
					"virtual address 0x%lx",
					virt_addr);
			}
			pte = pte_restrict_prot(*ptep, prot);
			pte = pte_reduce_prot(pte, prot);
		} else if (pgprot_present(prot)) {
			pte = mk_pte_phys(phys_addr, prot);
		} else {
			pte = mk_not_present_pte(prot);
		}
		boot_set_pte(virt_addr, ptep, pte, pt_level, host_map);
		if (phys_area_addr != (e2k_addr_t)-1)
			phys_addr += page_size;
		virt_addr += page_size;
	}
	boot_spin_unlock(&boot_page_table_lock);
	return page;
}

__init_recv
void boot_map_phys_area(const char *name, e2k_addr_t virt_phys_area_addr,
		e2k_size_t phys_area_size, e2k_addr_t area_virt_addr,
		pgprot_t prot_flags, e2k_size_t max_page_size,
		bool ignore_busy, bool host_map)
{
	const pt_level_t *pt_level;
	e2k_addr_t	phys_area_addr;
	e2k_size_t	passed_page_size = max_page_size;
	long ret;

	if (virt_phys_area_addr == (e2k_addr_t) -1) {
		phys_area_addr = virt_phys_area_addr;
	} else {
		phys_area_addr = boot_vpa_to_pa(virt_phys_area_addr);

		if (!IS_ALIGNED(phys_area_addr, max_page_size)) {
			BOOT_WARNING("%s: phys address 0x%lx isn't page size 0x%lx aligned, so page size is reduced to 4K",
					name, phys_area_addr, max_page_size);
			max_page_size = PAGE_SIZE;
		}
	}

	if (!IS_ALIGNED(area_virt_addr, max_page_size)) {
		BOOT_WARNING("%s: virt address 0x%lx isn't page size 0x%lx aligned, so page size is reduced to 4K",
				name, phys_area_addr, max_page_size);
		max_page_size = PAGE_SIZE;
	}

	if (!IS_ALIGNED(phys_area_size, max_page_size)) {
		BOOT_WARNING("%s: size 0x%lx isn't page size 0x%lx aligned, so page size is reduced to 4K",
				name, phys_area_size, max_page_size);
		max_page_size = PAGE_SIZE;
	}

	DebugMA("boot_map_phys_area() started for phys addr 0x%lx (0x%lx) "
		"virt addr 0x%lx, size 0x%lx\n",
		virt_phys_area_addr, phys_area_addr, area_virt_addr,
		phys_area_size);

	pt_level = boot_find_pt_level_of_page_size(max_page_size);
	if (pt_level == NULL) {
		BOOT_BUG("Invalid page size 0x%lx", max_page_size);
		ret = -EINVAL;
	} else {
		ret = boot_do_map_phys_area(phys_area_addr, phys_area_size,
			area_virt_addr, prot_flags, pt_level,
			ignore_busy, host_map);
	}

	BOOT_BUG_ON(ret <= 0, "Could not map kernel '%s' segment: base addr 0x%lx size 0x%lx page size 0x%x to virtual addr 0x%lx\n",
			name, virt_phys_area_addr, phys_area_size,
			passed_page_size, area_virt_addr);

	boot_printk("The kernel '%s' segment: "
		"base addr 0x%lx size 0x%lx is mapped to %d virtual "
		"page(s) base addr 0x%lx page size 0x%x\n",
		name, virt_phys_area_addr, phys_area_size, ret, area_virt_addr,
		passed_page_size);
}

/*
 * Write PTE of the virtual address to Instruction TLB.
 * This operation is not implemented for ITLB, instead of this write PTE
 * temporarly to page table entry
 */

static void __init_recv
boot_write_pte_to_pt(pte_t pte, e2k_addr_t virt_addr, const pt_level_t *pt_level)
{
	pte_t *ptep;

	DebugME("boot_write_pte_to_pt() started for address 0x%lx and pte == 0x%lx\n",
		virt_addr, pte_val(pte));
	boot_spin_lock(&boot_page_table_lock);
	ptep = boot_get_pte(virt_addr, pt_level, 0, 0);
	if (ptep == (pte_t *)-1) {
		boot_spin_unlock(&boot_page_table_lock);
		BOOT_BUG("Could not take PTE pointer to map virtual address 0x%lx",
			virt_addr);
	}
	if (pt_level->is_huge)
		pte = pte_set_large_size(pte);
	else
		pte = pte_set_small_size(pte);
	DebugME("boot_write_pte_to_pt() ptep is 0x%lx == 0x%lx to write new pte == 0x%lx\n",
		ptep, pte_val(*ptep), pte_val(pte));
	if (!pte_none(*ptep)) {
		if (pte_val(*ptep) != pte_val(pte)) {
			boot_spin_unlock(&boot_page_table_lock);
			BOOT_BUG("The PTE entry is not empty - virtual address 0x%lx has been already occupied by 0x%lx new pte is 0x%lx\n",
				virt_addr, pte_val(*ptep), pte_val(pte));
		} else {
			boot_spin_unlock(&boot_page_table_lock);
			DebugME("boot_write_pte_to_pt() new pte is the same as existing\n");
			return;
		}
	}

	boot_set_pte(virt_addr, ptep, pte, pt_level, false);

	boot_spin_unlock(&boot_page_table_lock);

	DebugME("boot_write_pte_to_pt() set ptep 0x%lx to new pte 0x%lx\n",
		ptep, pte_val(*ptep));
}

/*
 * Map the physical area to the equal virtual space.
 *	area_addr == area_phys_addr == area_virt_addr
 * PTEs of mapped pages should write only to TLB
 */
void __init_recv boot_map_to_equal_virt_area(const char *name, e2k_addr_t area_addr,
		size_t area_size, pgprot_t prot_flags, size_t max_page_size)
{
	const pt_level_t	*pt_level;
	pte_t		pte;
	pgprot_t	prot;
	e2k_addr_t	addr;
	size_t		pages_num, page;

	DebugME("boot_map_to_equal_virt_area() started for %s at addr 0x%lx size 0x%lx\n",
		name, area_addr, area_size);

	pt_level = boot_find_pt_level_of_page_size(max_page_size);
	BOOT_BUG_ON(!pt_level, "Invalid page size 0x%lx for %s", max_page_size, name);

	if (pt_level->is_huge)
		prot = pgprot_large_size_set(prot_flags);
	else
		prot = pgprot_small_size_set(prot_flags);
	addr = round_down(area_addr, max_page_size);
	pages_num = (round_up(area_addr + area_size, max_page_size) - addr) / max_page_size;
	DebugME("boot_map_to_equal_virt_area() virt addr will be 0x%lx page size is 0x%lx\n",
		addr, max_page_size);

	for (page = 0; page < pages_num; page++) {
		pte = mk_pte_phys(addr, prot);
		boot_write_pte_to_pt(pte, addr, pt_level);
		addr += max_page_size;
	}
	DebugME("boot_map_to_equal_virt_area() returns with mapped pages num %d\n", page);
}


static void __init_recv unmap_virt_to_equal_pte_range(pmd_t *pmd, unsigned long addr,
						unsigned long end)
{
	for (; addr < end; addr += PAGE_SIZE) {
		pte_t *pte = pte_offset_kernel(pmd, addr);

		if (pte_none(*pte))
			continue;

		set_pte(pte, __pte(0));
	}
}

static void __init_recv unmap_virt_to_equal_pmd_range(pud_t *pud, unsigned long addr,
						unsigned long end)
{
	unsigned long next = pmd_addr_end(addr, end);

	for (; addr < end; addr = next, next = pmd_addr_end(addr, end)) {
		pmd_t *pmd = pmd_offset(pud, addr);

		if (pmd_none(*pmd))
			continue;

		if (kernel_pmd_huge(*pmd)) {
			if (next - addr != PMD_SIZE)
				BOOT_WARNING("trying to unmap a part of pmd");
			else
				set_pmd(pmd, __pmd(0));
		} else {
			unmap_virt_to_equal_pte_range(pmd, addr, next);
			if (next - addr == PMD_SIZE)
				set_pmd(pmd, __pmd(0));
		}
	}
}

static void __init_recv unmap_virt_to_equal_pud_range(p4d_t *p4d, unsigned long addr,
						unsigned long end)
{
	unsigned long next = pud_addr_end(addr, end);

	for (; addr < end; addr = next, next = pud_addr_end(addr, end)) {
		pud_t *pud = pud_offset(p4d, addr);

		if (pud_none(*pud))
			continue;

		if (kernel_pud_huge(*pud)) {
			if (next - addr != PUD_SIZE)
				BOOT_WARNING("trying to unmap a part of pud");
			else
				set_pud(pud, __pud(0));
		} else {
			unmap_virt_to_equal_pmd_range(pud, addr, next);
			if (next - addr == PUD_SIZE)
				set_pud(pud, __pud(0));
		}
	}
}

static void __init_recv unmap_virt_to_equal_p4d_range(pgd_t *pgd, unsigned long addr,
						unsigned long end)
{
	unsigned long next = p4d_addr_end(addr, end);
	for (; addr < end; addr = next, next = p4d_addr_end(addr, end)) {
		p4d_t *p4d;

		p4d = p4d_offset(pgd, addr);

		if (p4d_none(*p4d))
			continue;

		if (kernel_p4d_huge(*p4d)) {
			if (next - addr != P4D_SIZE)
				BOOT_WARNING("trying to unmap a part of p4d");
			else
				set_p4d(p4d, __p4d(0));
		} else {
			unmap_virt_to_equal_pud_range(p4d, addr, next);
			if (next - addr == P4D_SIZE)
				set_p4d(p4d, __p4d(0));
		}
	}
}

static void __init_recv unmap_virt_to_equal_pgd_range(unsigned long addr, unsigned long end)
{
	unsigned long next = pgd_addr_end(addr, end);

	BOOT_BUG_ON(!PAGE_ALIGNED(addr) || !PAGE_ALIGNED(end), "unaligned arguments");

	for (; addr < end; addr = next, next = pgd_addr_end(addr, end)) {
		pgd_t *pgd = &swapper_pg_dir[pgd_index(addr)];

		if (pgd_none(*pgd))
			continue;

		if (kernel_pgd_huge(*pgd)) {
			if (next - addr != PGDIR_SIZE)
				BOOT_WARNING("trying to unmap a part of pgd");
			else
				set_pgd(pgd, __pgd(0));
		} else {
			unmap_virt_to_equal_p4d_range(pgd, addr, next);
			if (next - addr == PGDIR_SIZE)
				set_pgd(pgd, __pgd(0));
		}
	}
}

/* Remove mappings of physical memory into equal virtual addresses
 * now that we have switched to virtual addressing mode */
void __init_recv init_unmap_virt_to_equal_phys(bool bsp, int cpus_to_sync)
{
	/* Wait for all cpus to finish switching before clearing page tables */
	init_sync_all_processors(cpus_to_sync);

	if (bsp)
		unmap_virt_to_equal_pgd_range(0, PAGE_OFFSET);

	/* Wait for BSP to remove page tables before flushing TLB */
	init_sync_all_processors(cpus_to_sync);

	/* TODO after paravirtualizing flush_TLB_all() remove the check */
	if (!IS_ENABLED(CONFIG_KVM_GUEST_MODE))
		flush_TLB_all();

	/* See comment before flush_pte_from_ic() for why this is needed */
	__flush_icache_all();
}
