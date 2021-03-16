/* $Id: boot_map.c,v 1.24 2009/01/22 17:04:21 atic Exp $
 *
 * Boot-time support of mappings physical memory areas into
 * the kernel virtual space.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <asm/p2v/boot_v2p.h>

#include <asm/pic.h>
#include <asm/p2v/boot_phys.h>
#include <asm/p2v/boot_map.h>
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

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* Boot NUMA */
#define	DebugNUMA		if (DEBUG_NUMA_MODE) do_boot_printk

#undef	DEBUG_MAP_AREA_MODE
#undef	DebugMA
#define	DEBUG_MAP_AREA_MODE	0	/* Map physical area to virtual */
#define	DebugMA			if (DEBUG_MAP_AREA_MODE) do_boot_printk

#undef	DEBUG_MAP_VERBOSE_MODE
#undef	DebugMAV
#define	DEBUG_MAP_VERBOSE_MODE	0	/* Verbose mapping of physical area */
#define	DebugMAV		if (DEBUG_MAP_VERBOSE_MODE) do_boot_printk

/*
 * The structure to simulate TLB contents
 */
#ifndef	CONFIG_SMP
e2k_tlb_t __initdata_recv dtlb_contents;
e2k_tlb_t __initdata_recv itlb_contents;
#else
e2k_tlb_t __initdata_recv dtlb_contents[NR_CPUS];
e2k_tlb_t __initdata_recv itlb_contents[NR_CPUS];
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
static boot_spinlock_t boot_page_table_lock = __BOOT_SPIN_LOCK_UNLOCKED;
#define	boot_numa_node_spin_lock(lock)	boot_spin_lock(&(lock))
#define	boot_numa_node_spin_unlock(lock) boot_spin_unlock(&(lock))
#define	init_numa_node_spin_lock(lock)	init_spin_lock(&(lock))
#define	init_numa_node_spin_unlock(lock) init_spin_unlock(&(lock))
#else	/* CONFIG_NUMA */
static boot_spinlock_t __initdata_recv boot_page_table_lock[MAX_NUMNODES] = {
	[ 0 ... (MAX_NUMNODES-1) ] = __BOOT_SPIN_LOCK_UNLOCKED
};
#define	boot_numa_node_spin_lock(lock)	boot_dup_node_spin_lock(lock)
#define	boot_numa_node_spin_unlock(lock) boot_dup_node_spin_unlock(lock)
#define	init_numa_node_spin_lock(lock)	init_dup_node_spin_lock(lock)
#define	init_numa_node_spin_unlock(lock) init_dup_node_spin_unlock(lock)
#endif	/* ! CONFIG_NUMA */
#else	/* ! CONFIG_SMP */
#define	boot_page_table_lock
#define	boot_numa_node_spin_lock(lock)
#define	boot_numa_node_spin_unlock(lock)
#define	init_numa_node_spin_lock(lock)
#define	init_numa_node_spin_unlock(lock)
#endif	/* CONFIG_SMP */

#ifdef	CONFIG_NUMA
static boot_spinlock_t __initdata boot_node_init_map_lock[MAX_NUMNODES] = {
	[ 0 ... (MAX_NUMNODES-1) ] = __BOOT_SPIN_LOCK_UNLOCKED
};
static int __initdata node_map_inited[MAX_NUMNODES] = { 0 };
#define	boot_node_map_inited	\
		boot_get_vo_value(node_map_inited[boot_numa_node_id()])
#endif	/* CONFIG_NUMA */

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
	if (likely(pt_level->boot_get_huge_pte == NULL))
		return (pte_t *)ptp;
	return pt_level->boot_get_huge_pte(virt_addr, ptp);
}

static inline bool
init_is_pt_level_of_page_size(e2k_size_t page_size, int level)
{
	return pgtable_struct.levels[level].page_size == page_size;
}

static inline const pt_level_t *
init_find_pt_level_of_page_size(e2k_size_t page_size)
{
	int level;

	for (level = pgtable_struct.levels_num; level > 0; level--) {
		if (init_is_pt_level_of_page_size(page_size, level))
			return &pgtable_struct.levels[level];
	}
	return NULL;
}

static inline pte_t *
init_get_huge_pte(e2k_addr_t virt_addr, pgprot_t *ptp, const pt_level_t *pt_level)
{
	if (unlikely(!pt_level->is_huge)) {
		INIT_BUG("Page table level #%d cannot contain page "
			"table entries (pte)\n",
			get_pt_level_id(pt_level));
		return (pte_t *)-1;
	}
	if (likely(pt_level->init_get_huge_pte == NULL))
		return (pte_t *)ptp;
	return pt_level->init_get_huge_pte(virt_addr, ptp);
}

pte_t * __init_recv
boot_get_double_huge_pte(e2k_addr_t addr, pgprot_t *ptp)
{
	/*
	 * In this case virtual page occupied two sequential
	 * entries in page table directory level
	 */

	/* first pte is always even */
	return (pte_t *)(((e2k_addr_t)ptp) & ~((sizeof(*ptp) * 2) - 1));
}

pte_t * __init_recv
boot_get_common_huge_pte(e2k_addr_t addr, pgprot_t *ptp)
{
	return (pte_t *)ptp;
}

void __init_recv
boot_set_double_pte(e2k_addr_t addr, pte_t *ptep, pte_t pte, bool host_map)
{
	/*
	 * In this case virtual page occupied two sequential
	 * entries in page table directory level
	 * All two pte's (pmd's) should be set to identical
	 * entries
	 */
	DebugMAV("boot_set_double_pte() will set pte 0x%px to 0x%lx for "
		"address 0x%lx %s mapping\n",
		ptep, pte_val(pte), addr,
		(host_map) ? "host" : "native");

	/* first pte is always even */
	ptep = (pte_t *)(((e2k_addr_t)ptep) & ~((sizeof(*ptep) * 2) - 1));

	boot_set_pte_kernel(addr, ptep, pte);
	boot_set_pte_kernel(addr, ++ptep, pte);
}

void __init_recv
boot_set_common_pte(e2k_addr_t addr, pte_t *ptep, pte_t pte, bool host_map)
{
	DebugMAV("boot_set_common_pte() will set pte 0x%px to 0x%lx for "
		"address 0x%lx %s mapping\n",
		ptep, pte_val(pte), addr,
		(host_map) ? "host" : "native");
	boot_set_pte_kernel(addr, ptep, pte);
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
	if (pt_level->boot_set_pte != NULL) {
		pt_level->boot_set_pte(addr, ptep, pte, host_map);
	} else {
		boot_set_common_pte(addr, ptep, pte, host_map);
	}
}

pte_t * __init_recv
init_get_double_huge_pte(e2k_addr_t addr, pgprot_t *ptp)
{
	return boot_get_double_huge_pte(addr, ptp);
}

pte_t * __init_recv
init_get_common_huge_pte(e2k_addr_t addr, pgprot_t *ptp)
{
	return boot_get_common_huge_pte(addr, ptp);
}

/*
 * Get virtual address entry in the third-level page table.
 */

static pte_t * __init_recv
init_get_pte(e2k_addr_t virt_addr, const pt_level_t *pt_level)
{
	e2k_size_t page_size = pt_level->page_size;
	int level;
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	/*
	 * Get entry in the 4-th root-level page table
	 */
	DebugMAV("init_get_pte() started for virt addr 0x%lx page size 0x%lx\n",
		virt_addr, page_size);

	level = pgtable_struct.levels_num;
	pgdp = pgd_offset_k(virt_addr);
	DebugMAV("init_get_pte() pgd pointer is %px == 0x%lx\n",
		pgdp, pgd_val(*pgdp));
	if (init_is_pt_level_of_page_size(page_size, level))
		return init_get_huge_pte(virt_addr, (pgprot_t *)pgdp, pt_level);
	if (pgd_none(*pgdp))
		return NULL;

	/*
	 * Get entry in the 3-th level (high part of middle) page table
	 */
	level--;
	pudp = pud_offset(pgdp, virt_addr);
	if (init_is_pt_level_of_page_size(page_size, level))
		return init_get_huge_pte(virt_addr, (pgprot_t *)pudp, pt_level);
	if (pud_none(*pudp))
		return NULL;

	/*
	 * Get entry in the 2-nd level (low part of middle) page table
	 */
	level--;
	pmdp = pmd_offset(pudp, virt_addr);
	if (init_is_pt_level_of_page_size(page_size, level))
		return init_get_huge_pte(virt_addr, (pgprot_t *)pmdp, pt_level);
	if (pmd_none(*pmdp))
		return NULL;

	/*
	 * Get entry in the 1-st-level page table
	 */
	level--;
	ptep = pte_offset_kernel(pmdp, virt_addr);
	DebugMAV("init_get_pte() pte pointer is %px == 0x%lx\n",
		ptep, pte_val(*ptep));
	return ptep;
}

void __init_recv
init_double_pte_clear(pte_t *ptep)
{
	/*
	 * In this case virtual page occupied two sequential
	 * entries in page table directory level
	 * All two pte's (ptd's) should be cleared
	 */
	/* first pte is always even */
	ptep = (pte_t *)(((e2k_addr_t)ptep) & ~((sizeof(*ptep) * 2) - 1));

	pte_clear_kernel(ptep);
	pte_clear_kernel(++ptep);
}
void __init_recv
init_common_pte_clear(pte_t *ptep)
{
	pte_clear_kernel(ptep);
}

static void inline
init_pte_clear(pte_t *ptep, const pt_level_t *pt_level)
{
	if (unlikely(!pt_level->is_pte && !pt_level->is_huge)) {
		INIT_BUG("Page table level #%d cannot contain page "
			"table entries (pte)\n",
			get_pt_level_id(pt_level));
	}
	if (pt_level->init_pte_clear != NULL) {
		pt_level->init_pte_clear(ptep);
	} else {
		init_common_pte_clear(ptep);
	}
}

#ifdef	CONFIG_NUMA
#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT

static void __init_recv
boot_all_cpus_pgd_set(int nid, int pgd_index, pgd_t pgd)
{
	pgd_t *pgdp;
	int cpu;
	cpumask_t node_cpus;

	node_cpus = boot_node_to_cpumask(nid);
	DebugNUMA("boot_all_cpus_pgd_set() node #%d online cpu mask 0x%lx\n",
		nid, cpumask_test_cpu(0, &node_cpus));
	boot_for_each_online_cpu_of_node(nid, cpu, node_cpus) {
		pgdp = boot_node_cpu_pg_dir(nid, cpu);
		DebugNUMA("boot_all_cpus_pgd_set() set own node CPU #%d pgd "
			"entry 0x%lx to pud == 0x%lx\n",
			cpu, &pgdp[pgd_index], pgd_val(pgd));
		pgdp[pgd_index] = pgd;
	}
}

/*
 * Set specified pgd entry to point to next-level page table PUD
 * Need populate the pgd entry into follow root page tables:
 *	- all CPUs of the current node;
 *	- all CPUs of other nodes which have not own copy of kernel image
 *	  (DUP KERNEL) and use duplicated kernel of this node
 */
void __init_recv
boot_pgd_set(pgd_t *my_pgdp, pud_t *pudp, int user)
{
	pgd_t pgd;
	int pgd_index = pgd_to_index(my_pgdp);
	int my_node = boot_numa_node_id();
	int my_cpu = boot_smp_processor_id();
	int dup_node;
	int node;

	DebugNUMA("boot_pgd_set_k() set own pgd entry 0x%lx to pud 0x%lx\n",
		my_pgdp, pudp);
	if (user) {
		pgd = boot_mk_pgd_phys_u(pudp);
	} else {
		pgd = boot_mk_pgd_phys_k(pudp);
	}
	*my_pgdp = pgd;
	if (!BOOT_NODE_THERE_IS_DUP_KERNEL()) {
		DebugNUMA("boot_pgd_set_k() has not duplicated kernel, so "
			"all CPUs use BS root PT\n");
		return;
	}

	dup_node = boot_node_dup_kernel_nid(my_node);
	if (dup_node == my_node) {
		if (MMU_IS_SEPARATE_PT()) {
			BOOT_BUG_ON(my_pgdp != &boot_node_root_pt[pgd_index],
				"pgd should be on current the node\n");
			boot_node_root_pt[pgd_index] = pgd;
		} else {
			BOOT_BUG_ON(my_pgdp !=
					&boot_cpu_pg_dir(my_cpu)[pgd_index],
			"pgd should be on current the node\n");
			boot_all_cpus_pgd_set(my_node, pgd_index, pgd);
		}
	}
	if (BOOT_NODE_DUP_KERNEL_NUM() >= boot_phys_nodes_num) {
		DebugNUMA("boot_pgd_set_k() all %d nodes have duplicated "
			"kernel so own root PT\n",
			BOOT_NODE_DUP_KERNEL_NUM());
		return;
	}
	if (dup_node != my_node) {
		if (MMU_IS_SEPARATE_PT()) {
			BOOT_BUG_ON(my_pgdp == &boot_node_root_pt[pgd_index],
				"pgd cannot be on the node\n");
			boot_the_node_root_pt(dup_node)[pgd_index] = pgd;
		} else {
			BOOT_BUG_ON(my_pgdp ==
					&boot_cpu_pg_dir(my_cpu)[pgd_index],
				"pgd cannot be on the node\n");
			boot_all_cpus_pgd_set(dup_node, pgd_index, pgd);
		}
	}
	boot_for_each_node_has_not_dup_kernel(node) {
		DebugNUMA("boot_pgd_set_k() check other node #%d\n",
			node);
		if (node == my_node)
			continue;
		if (boot_node_dup_kernel_nid(node) != dup_node)
			continue;
		if (MMU_IS_SEPARATE_PT()) {
			boot_the_node_root_pt(node)[pgd_index] = pgd;
		} else {
			boot_all_cpus_pgd_set(node, pgd_index, pgd);
		}
	}
}
#else	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

/*
 * Set specified kernel pgd entry to point to next-level page table PUD
 * Need populate the pgd entry into follow root page tables:
 *	- PT of the specified node, if the node has duplicated kernel;
 *	- PT of node on which the node is duplicated
 *	- PTs of all other nodes which have not own copy of kernel image
 *	  (DUP KERNEL) and use duplicated kernel of this node or
 *	  are duplicated on the same node as this node
 */
void __init_recv
boot_pgd_set(pgd_t *my_pgdp, pud_t *pudp, int user)
{
	pgd_t pgd;
	int pgd_index = pgd_to_index(my_pgdp);
	int my_node = boot_numa_node_id();
	int dup_node;
	int node;

	DebugNUMA("boot_pgd_set_k() set own pgd entry 0x%lx to pud 0x%lx\n",
		my_pgdp, pudp);
	BOOT_BUG_ON(!MMU_IS_SEPARATE_PT(),
		"function can be call only for separate PT mode\n")
	if (user) {
		pgd = boot_mk_pgd_phys_u(pudp);
	} else {
		pgd = boot_mk_pgd_phys_k(pudp);
	}
	*my_pgdp = pgd;
	if (!BOOT_NODE_THERE_IS_DUP_KERNEL()) {
		DebugNUMA("boot_pgd_set_k() has not duplicated kernel, so "
			"all CPUs use BS root PT\n");
		return;
	}

	dup_node = boot_node_dup_kernel_nid(my_node);
	if (dup_node == my_node) {
		BOOT_BUG_ON(my_pgdp != &boot_node_root_pt[pgd_index],
			"pgd should be on current the node\n");
		boot_node_root_pt[pgd_index] = pgd;
	}
	if (BOOT_NODE_DUP_KERNEL_NUM() >= boot_phys_nodes_num) {
		DebugNUMA("boot_pgd_set_k() all %d nodes have duplicated "
			"kernel so own root PT\n",
			BOOT_NODE_DUP_KERNEL_NUM());
		return;
	}
	if (dup_node != my_node) {
		BOOT_BUG_ON(my_pgdp == &boot_node_root_pt[pgd_index],
			"pgd cannot be on the node\n");
		boot_the_node_root_pt(dup_node)[pgd_index] = pgd;
	}
	boot_for_each_node_has_not_dup_kernel(node) {
		DebugNUMA("boot_pgd_set_k() check other node #%d\n",
			node);
		if (node == my_node)
			continue;
		if (boot_node_dup_kernel_nid(node) != dup_node)
			continue;
		boot_the_node_root_pt(node)[pgd_index] = pgd;
	}
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
#endif	/* CONFIG_NUMA */

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
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	/*
	 * Get entry in the 4-th root-level page table
	 */
	DebugMAV("boot_get_pte() started for virt addr 0x%lx page size 0x%lx\n",
		virt_addr, page_size);

	level = pt_struct->levels_num;
	pgdp = boot_pgd_offset_k(virt_addr);
	DebugMAV("boot_get_pte() pgd pointer is %px == 0x%lx\n",
		pgdp, pgd_val(*pgdp));
	if (boot_is_pt_level_of_page_size(page_size, pt_struct, level))
		return boot_get_huge_pte(virt_addr, (pgprot_t *)pgdp, pt_level);
	if (pgd_none(*pgdp)) {
		if (va) {
			BOOT_BUG("Could not find PGD for virtual address 0x%lx "
				"while reset",
				virt_addr);
			return (pte_t *)-1;

		}
		pudp = boot_pud_alloc();
		if (pudp == (pud_t *)-1) {
			BOOT_BUG("Could not allocate memory for PUD to map "
				"virtual address 0x%lx",
				virt_addr);
			return (pte_t *)-1;
		}
		if (user) {
			boot_pgd_set_u(pgdp, pudp);
		} else {
			boot_pgd_set_k(pgdp, pudp);
		}
	} else if (boot_is_huge_pte((pgprot_t *)pgdp, pt_struct, level)) {
		BOOT_BUG("Page table level #%d PGD 0x%lx contains already pte "
			"0x%lx of other page size not 0x%lx",
			level, pgdp, pgd_val(*pgdp), page_size);
		return (pte_t *)-1;
	}

	/*
	 * Get entry in the 3-th level (high part of middle) page table
	 */
	level--;
	pudp = boot_pud_offset(pgdp, virt_addr);
	if (boot_is_pt_level_of_page_size(page_size, pt_struct, level))
		return boot_get_huge_pte(virt_addr, (pgprot_t *)pudp, pt_level);
	if (pud_none(*pudp)) {
		if (va) {
			BOOT_BUG("Could not find PUD for virtual address 0x%lx "
				"while reset",
				virt_addr);
			return (pte_t *)-1;

		}
		pmdp = boot_pmd_alloc();
		if (pmdp == (pmd_t *)-1) {
			BOOT_BUG("Could not allocate memory for PMD to map "
				"virtual address 0x%lx",
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
 * Init. root-level page table directory
 * All page tables is virtually mapped into the same virtual space as kernel
 * Virtually mapped linear page table base address is passed as argument.
 * The entry conforming to root page table is set to itself.
 */
static void __init
boot_pgd_init(pgd_t *pgdp, e2k_addr_t vmlpt_base)
{
	int	entry;
	int	root_pt_index;

	for (entry = 0; entry < PTRS_PER_PGD; entry ++) {
		pgd_clear_kernel(&pgdp[entry]);
	}
	root_pt_index = pgd_index(vmlpt_base);
	boot_vmlpt_pgd_set(&pgdp[root_pt_index], pgdp);
}

/*
 * Init. TLB structure to simulate it contents
 */
static void __init
boot_tlb_contents_simul_init(e2k_tlb_t *tlb)
{
	int	line;
	int	set;

	for (line = 0; line < BOOT_NATIVE_TLB_LINES_NUM; line++) {
		for (set = 0; set < BOOT_NATIVE_TLB_SETS_NUM; set++) {
			tlb->lines[line].sets[set].virt_addr = 0;
			tlb->lines[line].sets[set].valid_bit = 0;
		}
		tlb->lines[line].sets_num = 0;
	}
	tlb->entries_num = 0;
}

/*
 * Init. TLB structures (DTLB & ITLB) to simulate it contents
 */
#ifndef	CONFIG_SMP
static void __init
boot_all_tlb_contents_simul_init(void)
{
	boot_tlb_contents_simul_init(boot_dtlb_contents);
	boot_tlb_contents_simul_init(boot_itlb_contents);
}
#else	/* CONFIG_SMP */
static void __init
boot_cpu_tlb_contents_simul_init(int cpuid)
{
	boot_tlb_contents_simul_init(boot_vp_to_pp(&dtlb_contents[cpuid]));
	boot_tlb_contents_simul_init(boot_vp_to_pp(&itlb_contents[cpuid]));
}

#ifndef	CONFIG_NUMA
static void __init
boot_all_tlb_contents_simul_init(void)
{
	int	cpuid;

	for (cpuid = 0; cpuid < NR_CPUS; cpuid++) {
		if (!boot_phys_cpu_present(cpuid))
			continue;
		boot_cpu_tlb_contents_simul_init(cpuid);
	}
}
#endif	/* CONFIG_NUMA */
#endif	/* ! CONFIG_SMP */

/*
 * Initialization of boot-time support of physical areas mapping
 * to virtual space.
 */

#ifndef	CONFIG_NUMA
void __init
boot_init_mapping(void)
{
	boot_pgd_init(boot_root_pt, KERNEL_VPTB_BASE_ADDR);
	boot_all_tlb_contents_simul_init();
}
#else	/* CONFIG_NUMA */
static void __init
boot_node_one_cpu_init_mapping(void)
{
	if (BOOT_TEST_AND_SET_NODE_LOCK(boot_node_init_map_lock,
						boot_node_map_inited)) {
		boot_cpu_tlb_contents_simul_init(boot_smp_processor_id());
		DebugNUMA("boot_node_init_mapping() init mapping "
			"%s on node #%d CPU #%d\n",
			(boot_node_map_inited) ? "completed already"
						:
						"no memory",
			boot_numa_node_id(), boot_smp_processor_id());
		return;
	}
	if (!boot_node_has_dup_kernel()) {
		goto no_init_mapping;
	}
	boot_pgd_init(boot_node_root_pt, KERNEL_VPTB_BASE_ADDR);
	DebugNUMA("boot_node_init_mapping() init mapping on node #%d CPU #%d "
		"root PT 0x%lx\n",
		boot_numa_node_id(), boot_smp_processor_id(),
		boot_node_root_pt);
no_init_mapping:
	boot_cpu_tlb_contents_simul_init(boot_smp_processor_id());
	BOOT_NODE_UNLOCK(boot_node_init_map_lock, boot_node_map_inited);
}
void __init
boot_node_init_mapping(void)
{
	if (MMU_IS_SEPARATE_PT()) {
		boot_node_one_cpu_init_mapping();
	} else {
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
		boot_node_one_cpu_init_mapping();
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
		if (!BOOT_NODE_THERE_IS_DUP_KERNEL() && !BOOT_IS_BS_NODE) {
			DebugNUMA("boot_node_init_mapping() will use "
				"BS root PT 0x%lx\n",
				boot_cpu_kernel_root_pt);
			return;
		}
		boot_pgd_init(boot_cpu_kernel_root_pt, KERNEL_VPTB_BASE_ADDR);
		DebugNUMA("boot_node_init_mapping() init mapping on node #%d "
			"CPU #%d root PT 0x%lx\n",
			boot_numa_node_id(), boot_smp_processor_id(),
			boot_cpu_kernel_root_pt);
		boot_cpu_tlb_contents_simul_init(boot_smp_processor_id());
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	}
}
#endif	/* ! CONFIG_NUMA */

/*
 * Clear PTEs of kernel virtual page in the fourth-level page table.
 */

static	int  __init_recv
init_clear_ptes(e2k_addr_t virt_addr, bool ignore_absence, int pt_level_id)
{
	const pt_level_t *pt_level;
	pte_t *ptep;

	DebugME("init_clear_ptes() started for "
		"virt addr 0x%lx page table level id %d\n",
		virt_addr, pt_level_id);

	pt_level = get_pt_level_on_id(pt_level_id);

	/*
	 * Clear entry in the third-level page table
	 */
	init_numa_node_spin_lock(boot_page_table_lock);
	ptep = init_get_pte(virt_addr, pt_level);
	if (ptep == NULL || pte_none(*ptep)) {
		if (!ignore_absence) {
			init_numa_node_spin_unlock(boot_page_table_lock);
			INIT_BUG("Third level PTE[0x%lx] of virtual"
				"address 0x%lx is absent",
				(long)ptep, virt_addr);
			return (1);
		}
		DebugME("PTE[0x%lx} of virt addr 0x%lx is already clear\n",
			(long)ptep, virt_addr);
	} else {
		init_pte_clear(ptep, pt_level);
		DebugME("clear PTE[0x%lx] of virt addr 0x%lx\n",
			(long)ptep, virt_addr);
	}
	init_numa_node_spin_unlock(boot_page_table_lock);

	return 0;
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
		pages_num = (_PAGE_ALIGN_DOWN(area_virt_addr + phys_area_size,
				page_size) - area_virt_addr) / page_size;
		prot = pgprot_present_flag_reset(prot);
	} else {
		if ((phys_area_addr & (page_size - 1)) != 0) {
			BOOT_BUG("Physical adress 0x%lx is not page size 0x%lx "
				"aligned",
				phys_area_addr, page_size);
			return -EINVAL;
		}
		phys_addr = _PAGE_ALIGN_UP(phys_area_addr, page_size);
		pages_num = (_PAGE_ALIGN_DOWN(phys_area_addr + phys_area_size,
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

	boot_numa_node_spin_lock(boot_page_table_lock);
	for (page = 0; page < pages_num; page++) {
		ptep = boot_get_pte(virt_addr, pt_level,
					0,	/* user ? */
					0	/* va ? */);
		if (ptep == (pte_t *)-1) {
			boot_numa_node_spin_unlock(boot_page_table_lock);
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
				boot_numa_node_spin_unlock(
						boot_page_table_lock);
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
	boot_numa_node_spin_unlock(boot_page_table_lock);
	return page;
}

long __init_recv
boot_map_phys_area(e2k_addr_t virt_phys_area_addr, e2k_size_t phys_area_size,
	e2k_addr_t area_virt_addr, pgprot_t prot_flags,
	e2k_size_t max_page_size, bool ignore_busy, bool host_map)
{
	const pt_level_t *pt_level;
	e2k_addr_t	phys_area_addr;

	if (virt_phys_area_addr == (e2k_addr_t) -1) {
		phys_area_addr = virt_phys_area_addr;
	} else {
		phys_area_addr = boot_vpa_to_pa(virt_phys_area_addr);

		if (!IS_ALIGNED(phys_area_addr, max_page_size)) {
			BOOT_WARNING("phys address 0x%lx isn't page size 0x%lx "
				     "aligned, so page size is reduced to 4K",
				phys_area_addr, max_page_size);
			max_page_size = PAGE_SIZE;
		}
	}

	if (!IS_ALIGNED(area_virt_addr, max_page_size)) {
		BOOT_WARNING("virt address 0x%lx isn't page size 0x%lx "
			     "aligned, so page size is reduced to 4K",
			phys_area_addr, max_page_size);
		max_page_size = PAGE_SIZE;
	}

	DebugMA("boot_map_phys_area() started for phys addr 0x%lx (0x%lx) "
		"virt addr 0x%lx, size 0x%lx\n",
		virt_phys_area_addr, phys_area_addr, area_virt_addr,
		phys_area_size);

	pt_level = boot_find_pt_level_of_page_size(max_page_size);
	if (pt_level == NULL) {
		BOOT_BUG("Invalid page size 0x%lx", max_page_size);
		return -EINVAL;
	}

	return boot_do_map_phys_area(phys_area_addr, phys_area_size,
			area_virt_addr, prot_flags, pt_level,
			ignore_busy, host_map);
}

/*
 * Find the address in the list of pages currently mapped to the equal
 * virtual space into the TLB
 */

static int __init_recv
boot_find_equal_addr_tlb(e2k_addr_t address, e2k_tlb_t *tlb,
				const pt_level_t *pt_level)
{
	int		line;
	e2k_tlb_line_t	*tlb_line;
	int		set;
	int		entries = 0;
	bool		large_page_flag;

	if (pt_level->dtlb_type != COMMON_DTLB_TYPE) {
		BOOT_BUG("Pages of page table level #%d cannot be placed "
			"into common DTLB\n",
			boot_get_pt_level_id(pt_level));
	}
	large_page_flag = pt_level->is_huge;

	DebugME("boot_find_equal_addr_tlb() started for addr 0x%lx "
		"TLB pointer is 0x%lx, large page flag is %d\n",
		address, tlb, large_page_flag);
	if (tlb->entries_num == 0) {
		DebugME("boot_find_equal_addr_tlb() TLB is empty: "
			"entries_num is %d, return (1)\n", tlb->entries_num);
		return (1);
	}
	line = BOOT_VADDR_TO_TLB_LINE_NUM(address, large_page_flag);
	tlb_line = &tlb->lines[line];
	DebugME("boot_find_equal_addr_tlb() TLB line is %d\n", line);
	if (tlb_line->sets_num == 0) {
		DebugME("boot_find_equal_addr_tlb() TLB line is empty: "
			"sets_num is %d, return (1)\n", tlb_line->sets_num);
		return (1);
	}
	for (set = 0; set < NATIVE_TLB_SETS_NUM; set++) {
		if (!tlb_line->sets[set].valid_bit) {
			DebugME("boot_find_equal_addr_tlb() TLB line set "
				"#%d is not valid, continue\n", set);
			continue;
		}
		entries ++;
		DebugME("boot_find_equal_addr_tlb() entries is now %d "
			"set #%d is valid, addr == 0x%lx\n",
			entries, set, tlb_line->sets[set].virt_addr);
		if (tlb_line->sets[set].virt_addr == address) {
			DebugME("boot_find_equal_addr_tlb() set "
				"#%d addr is the same, return(0)\n", set);
			return (0);
		}
		if (entries >= tlb_line->sets_num) {
			DebugME("boot_find_equal_addr_tlb() entries %d "
				">=  tlb_line->sets_num %d, return(1)\n",
				entries, tlb_line->sets_num);
			return (1);
		}
	}
	DebugME("boot_find_equal_addr_tlb() does not find virt addr 0x%lx "
		"into TLB, return(1)\n",
		address);
	return (1);
}

/*
 * Find the address in the list of pages currently mapped to the equal
 * virtual space.
 * All these pages are located into two TLBs contents simulation structures
 */

static int __init_recv
boot_find_equal_addr(e2k_addr_t address, int tlb_mask,
				const pt_level_t *pt_level, int va)
{
	int	mask = 0;
	int	ret;

	if (tlb_mask & ITLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_find_equal_addr_tlb(address,
					&itlb_contents[boot_smp_processor_id()],
					pt_level);
#else /* !CONFIG_SMP */
			ret = boot_find_equal_addr_tlb(address,
					&itlb_contents, pt_level);
#endif /* CONFIG_SMP */
		else
			ret = boot_find_equal_addr_tlb(address,
					boot_itlb_contents, pt_level);
		if (ret == 0)
			mask |= ITLB_ACCESS_MASK;
	}
	if (tlb_mask & DTLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_find_equal_addr_tlb(address,
					&dtlb_contents[boot_smp_processor_id()],
					pt_level);
#else /* !CONFIG_SMP */
			ret = boot_find_equal_addr_tlb(address,
					&dtlb_contents, pt_level);
#endif /* CONFIG_SMP */
		else
			ret = boot_find_equal_addr_tlb(address,
					boot_dtlb_contents, pt_level);
		if (ret == 0)
			mask |= DTLB_ACCESS_MASK;
	}
	return mask;
}

/*
 * Get the TLB empty entry
 */

static int __init_recv
boot_get_tlb_empty_set(e2k_addr_t address, e2k_tlb_t *tlb,
		const pt_level_t *pt_level)
{
	int		line;
	e2k_tlb_line_t	*tlb_line;
	int		set;
	bool		large_page_flag;

	if (pt_level->dtlb_type != COMMON_DTLB_TYPE) {
		BOOT_BUG("Pages of page table level #%d cannot be placed "
			"into common DTLB\n",
			boot_get_pt_level_id(pt_level));
	}
	large_page_flag = pt_level->is_huge;

	DebugME("boot_get_tlb_empty_set() started for addr 0x%lx "
		"large page flag is %d\n",
		address, large_page_flag);
	line = BOOT_VADDR_TO_TLB_LINE_NUM(address, large_page_flag);
	tlb_line = &tlb->lines[line];
	DebugME("boot_get_tlb_empty_set() TLB line is %d occupied sets "
		"num is %d\n",
		line, tlb_line->sets_num);
	if (tlb_line->sets_num >= NATIVE_TLB_SETS_NUM)
		return (-1);
	for (set = 0; set < NATIVE_TLB_SETS_NUM; set++) {
		if (tlb_line->sets[set].virt_addr == address) {
			DebugME("boot_get_tlb_empty_set() TLB line #%d set "
				"#%d was already occupied by the specified "
				"addr 0x%lx\n",
				line, set, address);
		}
		if (tlb_line->sets[set].valid_bit) {
			DebugME("boot_get_tlb_empty_set() TLB line #%d "
				"set #%d was already occupied by addr 0x%lx\n",
				line, set, tlb_line->sets[set].virt_addr);
			continue;
		}
		if (large_page_flag && set != NATIVE_TLB_LARGE_PAGE_SET_NO) {
			DebugME("boot_get_tlb_empty_set() TLB line #%d "
				"set #%d cannot be used for large page\n",
				line, set);
			continue;
		}
		tlb_line->sets[set].virt_addr = address;
		tlb_line->sets[set].valid_bit = 1;
		tlb_line->sets[set].pt_level_id =
					boot_get_pt_level_id(pt_level);
		tlb_line->sets_num ++;
		tlb->entries_num ++;
		DebugME("boot_get_tlb_empty_set() TLB line #%d "
			"set #%d is selected for addr 0x%lx\n",
			line, set, tlb_line->sets[set].virt_addr);
		return (set);
	}
	DebugME("boot_get_tlb_empty_set() could not find empty TLB set "
		"for addr 0x%lx\n",
		address);
	return (-1);
}

/*
 * Write PTE of the virtual address to Data TLB.
 */

static int __init_recv
boot_write_pte_to_tlb(pte_t pte, tlb_tag_t prot_flags, e2k_addr_t virt_addr,
	e2k_tlb_t *tlb, const pt_level_t *pt_level)
{
	int		set_num;
	tlb_addr_t	tlb_addr;
	tlb_tag_t	tlb_tag;
	bool		large_page_flag;

	if (pt_level->dtlb_type != COMMON_DTLB_TYPE) {
		BOOT_BUG("Pages of page table level #%d cannot be placed "
			"into common DTLB\n",
			boot_get_pt_level_id(pt_level));
	}
	large_page_flag = pt_level->is_huge;
	/*
	 * Create and write tag to the matching TLB tag register 
	 */
	tlb_addr = tlb_addr_tag_access;
	tlb_addr = boot_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr,
			large_page_flag);
	set_num = boot_get_tlb_empty_set(virt_addr, tlb, pt_level);
	if (set_num < 0) {
		BOOT_BUG("Could not find empty entry set of TLB for virtual address 0x%lx",
				virt_addr);
		return (1);
	}
	tlb_addr = boot_tlb_addr_set_set_num(tlb_addr, set_num);
	tlb_tag = mk_tlb_tag_vaddr(virt_addr, prot_flags);
	write_DTLB_tag_reg(tlb_addr, tlb_tag);

	/*
	 * Write pte to the matching TLB entry register 
	 */
	tlb_addr = tlb_addr_set_entry_access(tlb_addr);
	write_DTLB_entry_reg(tlb_addr, pte_val(pte));

	return (0);
}

/*
 * Write PTE of the virtual address to Instruction TLB.
 * This operation is not implemented for ITLB, instead of this write PTE
 * temporarly to page table entry
 */

static int __init_recv
boot_write_pte_to_pt(pte_t pte, e2k_addr_t virt_addr, e2k_tlb_t *tlb,
			const pt_level_t *pt_level, int va)
{
	pte_t	*ptep;
	int	set_num;

	DebugME("boot_write_pte_to_pt() started for address 0x%lx and "
		"pte == 0x%lx\n",
		virt_addr, pte_val(pte));
	boot_numa_node_spin_lock(boot_page_table_lock);
	ptep = boot_get_pte(virt_addr, pt_level, 1, va);
	if (ptep == (pte_t *)-1) {
		boot_numa_node_spin_unlock(boot_page_table_lock);
		BOOT_BUG("Could not take PTE pointer to map virtual "
			"address 0x%lx",
			virt_addr);
		return (1);
	}
	if (pt_level->is_huge)
		pte = pte_set_large_size(pte);
	else
		pte = pte_set_small_size(pte);
	DebugME("boot_write_pte_to_pt() ptep is 0x%lx == 0x%lx to write "
		"new pte == 0x%lx\n",
		ptep, pte_val(*ptep), pte_val(pte));
	if (!pte_none(*ptep)) {
#ifdef	CONFIG_SMP
		if (pte_val(*ptep) != pte_val(pte)) {
			boot_numa_node_spin_unlock(boot_page_table_lock);
#endif	/* CONFIG_SMP */
			BOOT_BUG("The PTE entry is not empty - virtual "
				"address 0x%lx has been already occupied "
				"by 0x%lx new pte is 0x%lx",
				virt_addr, pte_val(*ptep), pte_val(pte));
			return (1);
#ifdef	CONFIG_SMP
		} else {
			set_num = boot_get_tlb_empty_set(virt_addr, tlb,
					pt_level);
			boot_numa_node_spin_unlock(boot_page_table_lock);
			if (set_num < 0)
				DebugME("Could not find empty entry set "
					"of TLB for virtual address 0x%lx",
					virt_addr);
			DebugME("boot_write_pte_to_pt() new pte is the "
				"same as existed: return\n");
			return (0);
		}
#endif	/* CONFIG_SMP */
	}
	set_num = boot_get_tlb_empty_set(virt_addr, tlb, pt_level);
	if (set_num < 0)
		DebugME("Could not find empty entry set of TLB for virtual address 0x%lx",
			virt_addr);

	boot_set_pte(virt_addr, ptep, pte, pt_level, false);

	boot_numa_node_spin_unlock(boot_page_table_lock);

	DebugME("boot_write_pte_to_pt() set ptep 0x%lx to new pte 0x%lx\n",
		ptep, pte_val(*ptep));

	return (0);
}

/*
 * Write PTE of page mapped to the equal virtual address to TLB or page table.
 * Write to ITLB is not implemented - pte is temporarly written to page table
 * entry.
 */

static int __init_recv
boot_write_equal_addr_pte(pte_t pte, tlb_tag_t prot_flags, e2k_addr_t address,
	int tlb_mask, const pt_level_t *pt_level, int va)
{
	int	ret;

	if (tlb_mask & ITLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_write_pte_to_pt(pte, address,
					&itlb_contents[boot_smp_processor_id()],
					pt_level, va);
#else /* !CONFIG_SMP */
			ret = boot_write_pte_to_pt(pte, address,
					&itlb_contents, pt_level, va);
#endif /* CONFIG_SMP */
		else
			ret = boot_write_pte_to_pt(
				pte, address, boot_itlb_contents, pt_level, va);
		if (ret != 0)
			return (ret);
	}
	if (tlb_mask & DTLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_write_pte_to_tlb(pte, prot_flags, address,
					&dtlb_contents[boot_smp_processor_id()],
					pt_level);
#else /* !CONFIG_SMP */
			ret = boot_write_pte_to_tlb(pte, prot_flags, address,
					&dtlb_contents, pt_level);
#endif /* CONFIG_SMP */
		else
			ret = boot_write_pte_to_tlb(pte, prot_flags, address,
						boot_dtlb_contents, pt_level);
		if (ret != 0)
			return (ret);
	}
	return (0);
}

/*
 * Map the physical area to the equal virtual space.
 *	area_addr == area_phys_addr == area_virt_addr
 * PTEs of mapped pages should write only to TLB
 */

int __init_recv
boot_map_to_equal_virt_area(e2k_addr_t area_addr, e2k_size_t area_size,
	pgprot_t prot_flags, tlb_tag_t tlb_prot_flags,
	e2k_size_t max_page_size, int tlb_mask, int va)
{
	const pt_level_t	*pt_level;
	pte_t		pte;
	pgprot_t	prot;
	e2k_addr_t	phys_addr;
	e2k_addr_t	virt_addr;
	int		pages_num;
	int		page;
	int		cur_tlb_mask;
	int		ret;

	DebugME("boot_map_to_equal_virt_area() started for addr 0x%lx "
		"size 0x%lx\n",
		area_addr, area_size);

	pt_level = boot_find_pt_level_of_page_size(max_page_size);
	if (pt_level == NULL) {
		BOOT_BUG("Invalid page size 0x%lx", max_page_size);
		return -EINVAL;
	}
	if (pt_level->is_huge)
		prot = pgprot_large_size_set(prot_flags);
	else
		prot = pgprot_small_size_set(prot_flags);
	phys_addr = _PAGE_ALIGN_UP(area_addr, max_page_size);
	virt_addr = phys_addr;
	pages_num = (_PAGE_ALIGN_DOWN(area_addr + area_size,
				max_page_size) - phys_addr) / max_page_size;
	DebugME("boot_map_to_equal_virt_area() virt addr will be 0x%lx "
		"page size is 0x%lx\n",
		virt_addr, max_page_size);

	for (page = 0; page < pages_num; page++) {
		ret = boot_find_equal_addr(virt_addr, tlb_mask, pt_level, va);
		DebugME("boot_map_to_equal_virt_area() "
			"boot_find_equal_addr(0x%lx) returned mask 0x%x "
			"source mask is 0x%x\n",
			virt_addr, ret, tlb_mask);
		if (ret == tlb_mask)
			continue;
		cur_tlb_mask = tlb_mask ^ ret;
		pte = mk_pte_phys(phys_addr, prot);
		DebugME("boot_map_to_equal_virt_area() will start "
			"boot_write_equal_addr_pte() for addr 0x%lx "
			"pte 0x%lx\n",
			virt_addr, pte_val(pte));
		ret = boot_write_equal_addr_pte(pte, tlb_prot_flags, virt_addr,
			cur_tlb_mask, pt_level, va);
		if (ret != 0) {
			BOOT_BUG("Could not write PTE 0x%lx of virtual "
				"addr 0x%lx to TLB",
				pte_val(pte), virt_addr);
			return 0;
		}
		phys_addr += max_page_size;
		virt_addr = phys_addr;
	}
	DebugME("boot_map_to_equal_virt_area() returns with mapped "
		"pages num %d\n", page);
	return page;
}

/*
 * Flush the TLB entries mapping the virtually mapped linear page
 * table corresponding to address.
 */
void
init_flush_tlb_pgtable(e2k_addr_t address)
{

	/* flush virtual mapping of PTE entries (third level of page table) */
	flush_TLB_kernel_page(
		pte_virt_offset(_PAGE_ALIGN_UP(address, PTE_SIZE)));

	/* flush virtual mapping of PMD entries (second level of page table) */
	flush_TLB_kernel_page(
		pmd_virt_offset(_PAGE_ALIGN_UP(address, PMD_SIZE)));

	/* flush virtual mapping of PUD entries (first level of page table) */
	flush_TLB_kernel_page(
		pud_virt_offset(_PAGE_ALIGN_UP(address, PUD_SIZE)));
}

/*
 * Clear PTE of the virtual address into the TLB.
 */

static int __init_recv
init_clear_tlb_entry(e2k_addr_t virt_addr, int tlb_mask)
{

	/*
	 * Clear TLB entry
	 */
	flush_TLB_kernel_page(virt_addr);
	init_flush_tlb_pgtable(virt_addr);

	/*
	 * Clear ICACHE lines if TLB is ITLB
	 */
	if (tlb_mask & ITLB_ACCESS_MASK) {
		flush_ICACHE_kernel_line(virt_addr);
	}

	return 0;
}

/*
 * Clear all pages which were temporarly written to TLB only
 */
static int __init_recv
init_clear_temporary_tlb(e2k_tlb_t *tlb, int tlb_mask)
{
	int		line;
	int		set;
	e2k_tlb_line_t	*tlb_line;
	int		ret;

	if (tlb->entries_num <= 0)
		return (0);
	for (line = 0; line < NATIVE_TLB_LINES_NUM; line++) {
		tlb_line = &tlb->lines[line];
		if (tlb_line->sets_num == 0)
			continue;
		for (set = 0; set < NATIVE_TLB_SETS_NUM; set++) {
			if (!tlb_line->sets[set].valid_bit)
				continue;
			ret = init_clear_tlb_entry(
				tlb_line->sets[set].virt_addr,
				tlb_mask);
			if (ret != 0) {
				BOOT_BUG("Could not clear ITLB virtual address 0x%lx from line %d set %d",
					tlb_line->sets[set].virt_addr,
					line, set);
				return (1);
			}
			tlb_line->sets[set].valid_bit = 0;
			tlb_line->sets[set].virt_addr = 0;
			tlb_line->sets[set].pt_level_id = 0;
			tlb_line->sets_num --;
			tlb->entries_num --;
			if (tlb_line->sets_num <= 0)
				break;
		}
		if (tlb->entries_num <= 0)
			break;
	}
	return (0);
}

/*
 * Clear all pages which were temporarly written to page table
 * Write to ITLB is not implemented - PTEs are temporarly written to page table
 * entries
 */
static int __init_recv
init_clear_temporary_pt(e2k_tlb_t *tlb, int tlb_mask)
{
	int		line;
	int		set;
	e2k_tlb_line_t	*tlb_line;
	int		ret;

	if (tlb->entries_num <= 0)
		return 0;
	for (line = 0; line < NATIVE_TLB_LINES_NUM; line++) {
		tlb_line = &tlb->lines[line];
		if (tlb_line->sets_num == 0)
			continue;
		for (set = 0; set < NATIVE_TLB_SETS_NUM; set++) {
			if (!tlb_line->sets[set].valid_bit)
				continue;
			ret = init_clear_ptes(tlb_line->sets[set].virt_addr,
#ifndef	CONFIG_SMP
				false,	/* do not ignore the page absence */
#else
				true,	/* ignore the page absence */
#endif	/* CONFIG_SMP */
				tlb_line->sets[set].pt_level_id);
			if (ret != 0) {
				BOOT_BUG("Could not clear PT virtual address 0x%lx from line %d set %d",
					tlb_line->sets[set].virt_addr,
					line, set);
				return 1;
			}
			ret = init_clear_tlb_entry(
				tlb_line->sets[set].virt_addr,
				tlb_mask);
			if (ret != 0) {
				BOOT_BUG("Could not clear ITLB virtual address 0x%lx from line %d set %d",
					tlb_line->sets[set].virt_addr,
					line, set);
				return (1);
			}
			tlb_line->sets[set].valid_bit = 0;
			tlb_line->sets[set].virt_addr = 0;
			tlb_line->sets[set].pt_level_id = 0;
			tlb_line->sets_num --;
			tlb->entries_num --;
			if (tlb_line->sets_num <= 0)
				break;
		}
		if (tlb->entries_num <= 0)
			break;
	}
	return (0);
}

/*
 * Clear all PTEs, which were temporarly written to TLB or page table.
 * Write to ITLB is not implemented - PTEs are temporarly written to page table
 * entries
 */

int __init_recv
init_clear_temporary_ptes(int tlb_mask, int cpuid)
{
	int	ret;

	if (tlb_mask & ITLB_ACCESS_MASK) {
#ifndef	CONFIG_SMP
		ret = init_clear_temporary_pt(&itlb_contents, ITLB_ACCESS_MASK);
#else
		ret = init_clear_temporary_pt(&itlb_contents[cpuid],
							ITLB_ACCESS_MASK);
#endif	/* CONFIG_SMP */
		if (ret != 0)
			return ret;
	}
	if (tlb_mask & DTLB_ACCESS_MASK) {
#ifndef	CONFIG_SMP
		ret = init_clear_temporary_tlb(&dtlb_contents,
							DTLB_ACCESS_MASK);
#else
		ret = init_clear_temporary_tlb(&dtlb_contents[cpuid],
							DTLB_ACCESS_MASK);
#endif	/* CONFIG_SMP */
		if (ret != 0)
			return ret;
	}
	return (0);
}
