/* $Id: boot_map.c,v 1.24 2009/01/22 17:04:21 atic Exp $
 *
 * Boot-time support of mappings physical memory areas into
 * the kernel virtual space.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <linux/mm.h>

#include <asm/types.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/lms.h>
#include <asm/page.h>
#include <asm/pgtable.h>
#include <asm/mmu_regs.h>
#include <asm/boot_head.h>
#include <asm/boot_phys.h>
#include <asm/boot_map.h>
#include <asm/boot_smp.h>
#include <asm/process.h>
#include <asm/console.h>
#include <asm/mmu_regs_access.h>

#undef	DEBUG_BOOT_MAP_MODE
#undef	boot_printk
#define	DEBUG_BOOT_MAP_MODE	0	/* Boot map process */
#define	boot_printk		if (DEBUG_BOOT_MAP_MODE) do_boot_printk

#undef	DEBUG_BOOT_MODE
#undef	DebugB
#define	DEBUG_BOOT_MODE		0	/* Init map process */
#define	DebugB			if (DEBUG_BOOT_MODE) printk

#undef	DEBUG_MAP_EQUAL_MODE
#undef	DebugME
#define	DEBUG_MAP_EQUAL_MODE	0	/* Map equal addresses */
#define	DebugME			if (DEBUG_MAP_EQUAL_MODE) do_boot_printk

#undef	DEBUG_NUMA_MODE
#undef	DebugNUMA
#define	DEBUG_NUMA_MODE		0	/* Boot NUMA */
#define	DebugNUMA		if (DEBUG_NUMA_MODE) do_boot_printk

#define BOOT_IS_HUGE_PAGE_SIZE_2M				\
		(BOOT_IS_MACHINE_E2S || BOOT_IS_MACHINE_E8C ||	\
		BOOT_IS_MACHINE_E8C2 || BOOT_IS_MACHINE_E1CP)

/*
 * The structure to simulate TLB contents
 */
#ifndef	CONFIG_SMP
e2k_tlb_t __initdata_recv	dtlb_contents;
e2k_tlb_t __initdata_recv	itlb_contents;
#else
e2k_tlb_t __initdata_recv	dtlb_contents[NR_CPUS];
e2k_tlb_t __initdata_recv	itlb_contents[NR_CPUS];
#endif	/* CONFIG_SMP */


#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
static DEFINE_RAW_SPINLOCK(boot_page_table_lock);
#else	/* CONFIG_NUMA */
static raw_spinlock_t __initdata_recv boot_page_table_lock[MAX_NUMNODES] = {
				[ 0 ... (MAX_NUMNODES-1) ] =
					__RAW_SPIN_LOCK_UNLOCKED(
						boot_page_table_lock)
			};
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */

#if defined(CONFIG_NUMA) && !defined(CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT)
static raw_spinlock_t __initdata boot_node_init_map_lock[MAX_NUMNODES] = {
				[ 0 ... (MAX_NUMNODES-1) ] =
					__RAW_SPIN_LOCK_UNLOCKED(
						boot_node_init_map_lock)
			};
static int __initdata node_map_inited[MAX_NUMNODES] = { 0 };
#define	boot_node_map_inited						\
		boot_get_vo_value(node_map_inited[boot_numa_node_id()])
#endif        /* CONFIG_NUMA && ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

static pte_t * __init_recv boot_get_pte(e2k_addr_t virt_addr, int large_page,
					int user, int va);

#ifdef	CONFIG_RECOVERY
static pte_t * boot_find_pte(e2k_addr_t virt_addr, int large_page);
#endif	/* CONFIG_RECOVERY */

static pte_t * __init_recv boot_pte_alloc(void);
static pmd_t * __init_recv boot_pmd_alloc(void);
static pud_t * __init_recv boot_pud_alloc(void);
static void __init	boot_pgd_init(pgd_t *pgdp, e2k_addr_t vmlpt_base);
static int __init_recv	init_clear_ptes(e2k_addr_t virt_addr,
					int ignore_absence, int large_page);
#ifdef	CONFIG_SMP
static void __init	boot_cpu_tlb_contents_simul_init(int cpuid);
#endif	/* CONFIG_SMP */
#ifndef	CONFIG_NUMA
static void __init	boot_all_tlb_contents_simul_init(void);
#endif	/* CONFIG_NUMA */
static void __init	boot_tlb_contents_simul_init(e2k_tlb_t *tlb);
static int __init_recv	boot_find_equal_addr(e2k_addr_t address, int tlb_mask,
					int large_page_flag, int va);
static int __init_recv	boot_find_equal_addr_tlb(e2k_addr_t address,
					e2k_tlb_t *tlb, int large_page_flag);
static int __init_recv	boot_get_tlb_empty_set(e2k_addr_t address,
					e2k_tlb_t *tlb, int large_page_flag);
static int __init_recv	boot_write_equal_addr_pte(pte_t pte,
					tlb_tag_t prot_flags,
					e2k_addr_t address, int tlb_mask,
					int va);
static int __init_recv	boot_write_pte_to_tlb(pte_t pte, tlb_tag_t prot_flags,
					e2k_addr_t virt_addr, e2k_tlb_t *tlb);
static int __init_recv	boot_write_pte_to_pt(pte_t pte, e2k_addr_t virt_addr,
					e2k_tlb_t *tlb, int va);
static int __init_recv	init_clear_temporary_tlb(e2k_tlb_t *tlb, int tlb_mask);
static int __init_recv	init_clear_temporary_pt(e2k_tlb_t *tlb, int tlb_mask);
static int __init_recv	init_clear_tlb_entry(e2k_addr_t virt_addr,
					int tlb_mask);


/*
 * Initialization of boot-time support of physical areas mapping
 * to virtual space.
 */

#ifndef	CONFIG_NUMA
void __init
boot_init_mapping(void)
{
	boot_pgd_init(boot_root_pt, KERNEL_VMLPT_BASE_ADDR);
	boot_all_tlb_contents_simul_init();
}
#else	/* CONFIG_NUMA */
void __init
boot_node_init_mapping(void)
{
#ifndef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
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
	boot_pgd_init(boot_node_root_pt, KERNEL_VMLPT_BASE_ADDR);
	DebugNUMA("boot_node_init_mapping() init mapping on node #%d CPU #%d "
		"root PT 0x%lx\n",
		boot_numa_node_id(), boot_smp_processor_id(),
		boot_node_root_pt);
no_init_mapping:
	boot_cpu_tlb_contents_simul_init(boot_smp_processor_id());
	BOOT_NODE_UNLOCK(boot_node_init_map_lock, boot_node_map_inited);
#else	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
	if (!BOOT_THERE_IS_DUP_KERNEL && !BOOT_IS_BS_NODE) {
		DebugNUMA("boot_node_init_mapping() will use "
			"BS root PT 0x%lx\n",
			boot_cpu_kernel_root_pt);
		return;
	}
	boot_pgd_init(boot_cpu_kernel_root_pt, KERNEL_VMLPT_BASE_ADDR);
	DebugNUMA("boot_node_init_mapping() init mapping on node #%d CPU #%d "
		"root PT 0x%lx\n",
		boot_numa_node_id(), boot_smp_processor_id(),
		boot_cpu_kernel_root_pt);
	boot_cpu_tlb_contents_simul_init(boot_smp_processor_id());
#endif	/* ! CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */
}
#endif	/* ! CONFIG_NUMA */

static void __init_recv inline
boot_set_pte(pte_t *ptep, pte_t pte, int large_page)
{
	if (large_page && !BOOT_IS_HUGE_PAGE_SIZE_2M) {
		/*
		 * In this case virtual page occupied two sequential
		 * entries in page table on 2-th level (PMD)
		 * All two pte's (pmd's) should be set to identical
		 * entries
		 */
		boot_printk("boot_set_pte() will set pte 0x%p to 0x%lx\n",
			ptep, pte_val(pte));
		set_pte(ptep, pte);
		set_pte(++ ptep, pte);
	} else {
		boot_printk("boot_set_pte() will set pte 0x%p to 0x%lx\n",
			ptep, pte_val(pte));
		set_pte(ptep, pte);
	}
}

static void inline
boot_pte_clear(pte_t *ptep, int large_page)
{
	if (!large_page || BOOT_IS_HUGE_PAGE_SIZE_2M) {
		pte_clear_kernel(ptep);
	} else {
		/*
		 * In this case virtual page occupied two sequential
		 * entries in page table on 2-th level (PMD)
		 * All two pte's (pmd's) should be cleared 
		 */
		pte_clear_kernel(ptep);
		pte_clear_kernel(++ ptep);
	}
}

#ifdef	CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT
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
	pgd_t *pgdp;
	int pgd_index = pgd_to_index(my_pgdp);
	int my_node = boot_numa_node_id();
	int dup_node;
	int node;
	int my_cpu = boot_smp_processor_id();
	int cpu;
	cpumask_t node_cpus;

	DebugNUMA("boot_pgd_set_k() set own pgd entry 0x%lx to pud 0x%lx\n",
		my_pgdp, pudp);
	if (user) {
		pgd = boot_mk_pgd_phys_u(pudp);
	} else {
		pgd = boot_mk_pgd_phys_k(pudp);
	}
	*my_pgdp = pgd;
	if (!BOOT_THERE_IS_DUP_KERNEL) {
		DebugNUMA("boot_pgd_set_k() has not duplicated kernel, so "
			"all CPUs use BS root PT\n");
		return;
	}
	node_cpus = boot_node_to_cpumask(my_node);
	DebugNUMA("boot_pgd_set_k() node online cpu mask 0x%lx from 0x%lx\n",
		cpus_addr(node_cpus)[0],
		cpus_addr(boot_phys_cpu_present_map)[0]);
	boot_for_each_online_cpu_of_node(my_node, cpu, node_cpus) {
		if (cpu == my_cpu)
			continue;
		pgdp = boot_cpu_pg_dir(cpu);
		DebugNUMA("boot_pgd_set_k() set own node CPU #%d pgd entry "
			"0x%lx to pud 0x%lx\n",
			cpu, &pgdp[pgd_index], pudp);
		pgdp[pgd_index] = pgd;
	}
	if (BOOT_DUP_KERNEL_NUM >= boot_phys_nodes_num) {
		DebugNUMA("boot_pgd_set_k() all %d nodes have duplicated "
			"kernel so own root PT\n",
			BOOT_DUP_KERNEL_NUM);
		return;
	}
	dup_node = boot_node_dup_kernel_nid(my_node);
	if (dup_node != my_node) {
		boot_for_each_online_cpu_of_node(dup_node, cpu, node_cpus) {
			pgdp = boot_cpu_pg_dir(cpu);
			DebugNUMA("boot_pgd_set_k() set home node #%d "
				"CPU #%d pgd entry 0x%lx to pud 0x%lx\n",
				dup_node, cpu, &pgdp[pgd_index], pudp);
			pgdp[pgd_index] = pgd;
		}
	}
	boot_for_each_node_has_not_dup_kernel(node) {
		DebugNUMA("boot_pgd_set_k() check other node #%d\n",
			node);
		if (node == my_node)
			continue;
		if (boot_node_dup_kernel_nid(node) != dup_node)
			continue;
		node_cpus = boot_node_to_cpumask(node);
		DebugNUMA("boot_pgd_set_k() node #%d online cpu mask 0x%lx\n",
			node, cpus_addr(node_cpus)[0]);
		boot_for_each_online_cpu_of_node(node, cpu, node_cpus) {
			pgdp = boot_cpu_pg_dir(cpu);
			DebugNUMA("boot_pgd_set_k() set other node #%d "
				"CPU #%d pgd entry 0x%lx to pud 0x%lx\n",
				node, cpu, &pgdp[pgd_index], pudp);
			pgdp[pgd_index] = pgd;
		}
	}
}
#endif	/* CONFIG_COPY_USER_PGD_TO_KERNEL_ROOT_PT */

/*
 * Map the physical area to the kernel virtual space.
 * Function return number of mapped pages or 0, if error was detected,
 * for example if some of the pages is already mapped
 */

int __init_recv
boot_map_phys_area(e2k_addr_t phys_area_addr, e2k_size_t phys_area_size,
	e2k_addr_t area_virt_addr, pgprot_t prot_flags, e2k_size_t page_size,
	int ignore_busy)
{
	pte_t		pte;
	pgprot_t	prot;
	pte_t		*ptep;
	e2k_addr_t	phys_addr;
	e2k_addr_t	virt_addr;
	int		pages_num;
	int		page;
	if (page_size == E2K_SMALL_PAGE_SIZE) {
		prot = pgprot_small_size_set(prot_flags);
	} else if (page_size == BOOT_E2K_LARGE_PAGE_SIZE) {
		prot = pgprot_large_size_set(prot_flags);
	} else {
		BOOT_BUG_POINT("boot_map_phys_area");
		BOOT_BUG("Invalid page size 0x%lx", page_size);
		return (0);
	}
	if ((area_virt_addr & (page_size - 1)) != 0) {
		BOOT_BUG_POINT("boot_map_phys_area");
		BOOT_BUG("Virtual adress 0x%lx is not page size 0x%lx aligned",
			area_virt_addr, page_size);
		return (0);
	} else {
		virt_addr = area_virt_addr;
	}

	if (phys_area_addr == (e2k_addr_t)-1) {
		phys_addr = 0;
		pages_num = (_PAGE_ALIGN_DOWN(area_virt_addr + phys_area_size,
				page_size) - area_virt_addr) / page_size;
		prot = pgprot_present_flag_reset(prot);
	} else {
		if ((phys_area_addr & (page_size - 1)) != 0) {
			BOOT_BUG_POINT("boot_map_phys_area");
			BOOT_BUG("Physical adress 0x%lx is not page size 0x%lx "
				"aligned",
				phys_area_addr, page_size);
			return (0);
		}
		phys_addr = _PAGE_ALIGN_UP(phys_area_addr, page_size);
		pages_num = (_PAGE_ALIGN_DOWN(phys_area_addr + phys_area_size,
				page_size) - phys_addr) / page_size;
	}

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_lock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
	boot_dup_node_spin_lock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	for (page = 0; page < pages_num; page ++) {
		ptep = boot_get_pte(virt_addr,
				page_size == BOOT_E2K_LARGE_PAGE_SIZE, 0, 0);
		if (ptep == (pte_t *)-1) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("boot_map_phys_area");
			BOOT_BUG("Could not get PTE pointer to map virtual "
				"address 0x%lx", virt_addr);
			return (0);
		}
		if (!pte_none(*ptep)) {
			if (!ignore_busy) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
				boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
				boot_dup_node_spin_unlock(
						boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
				BOOT_BUG_POINT("boot_map_phys_area");
				boot_printk(" pte:%p pte_Val: 0x%p \n",
					ptep,  pte_val(*ptep));
				BOOT_BUG("The PTE entry is not empty to map "
					"virtual address 0x%lx", virt_addr);
				return (0);
			}
			pte = pte_restrict_prot(*ptep, prot);
			pte = pte_reduce_prot(pte, prot);
		} else {
			pte = mk_pte_phys(phys_addr, prot);
		}
		boot_set_pte(ptep, pte, page_size == BOOT_E2K_LARGE_PAGE_SIZE);
		if (phys_area_addr != (e2k_addr_t)-1)
			phys_addr += page_size;
		virt_addr += page_size;
	}
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
	boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	return (page);
}

/*
 * Get virtual address entry in the third-level page table.
 */

static pte_t * __init_recv
boot_get_pte(e2k_addr_t virt_addr, int large_page, int user, int va)
{
	pgd_t	*pgdp;
	pud_t	*pudp;
	pmd_t	*pmdp;
	pte_t	*ptep;

	/*
	 * Get entry in the root-level page table
	 */
	pgdp = boot_pgd_offset_k(virt_addr);
	if (pgd_none(*pgdp)) {
		if (va) {
			BOOT_BUG_POINT("boot_get_pte");
			BOOT_BUG("Could not find PGD for virtual address "
				"0x%lx while reset", virt_addr);
			return ((pte_t *)-1);

		}
		pudp = boot_pud_alloc();
		if (pudp == (pud_t *)-1) {
			BOOT_BUG_POINT("boot_get_pte");
			BOOT_BUG("Could not allocate memory for PUD to map "
				"virtual address 0x%lx", virt_addr);
			return ((pte_t *)-1);
		}
		if (user) {
			boot_pgd_set_u(pgdp, pudp);
		} else {
			boot_pgd_set_k(pgdp, pudp);
		}
	}

	/*
	 * Get entry in the first-level (high part of middle) page table
	 */
	pudp = boot_pud_offset(pgdp, virt_addr);
	if (pud_none(*pudp)) {
		if (va) {
			BOOT_BUG_POINT("boot_get_pte");
			BOOT_BUG("Could not find PUD for virtual address "
				"0x%lx while reset", virt_addr);
			return ((pte_t *)-1);

		}
		pmdp = boot_pmd_alloc();
		if (pmdp == (pmd_t *)-1) {
			BOOT_BUG_POINT("boot_get_pte");
			BOOT_BUG("Could not allocate memory for PMD to map "
				"virtual address 0x%lx", virt_addr);
			return ((pte_t *)-1);
		}
		if (user) {
			boot_pud_set_u(pudp, pmdp);
		} else {
			boot_pud_set_k(pudp, pmdp);
		}
	}

	/*
	 * Get entry in the second-level (low part of middle) page table
	 */
	pmdp = boot_pmd_offset(pudp, virt_addr);
	if (large_page) {
		/* A large virtual page occupies two sequential
		 * entries in page table on 2-th level (PMD) */
		return ((pte_t *)pmdp);
	}
	if (pmd_none(*pmdp) || (pmd_large(*pmdp) && !large_page)) {
		if (va) {
			BOOT_BUG_POINT("boot_get_pte");
			BOOT_BUG("Could not find PMD for virtual address "
				"0x%lx while reset", virt_addr);
			return ((pte_t *)-1);

		}
		ptep = boot_pte_alloc();
		if (ptep == (pte_t *)-1) {
			BOOT_BUG_POINT("boot_get_pte");
			BOOT_BUG("Could not allocate memory for PTE to map "
				"virtual address 0x%lx", virt_addr);
			return ((pte_t *)-1);
		}
		if (user) {
			boot_pmd_set_u(pmdp, ptep);
		} else {
			boot_pmd_set_k(pmdp, ptep);
		}
	}

	/*
	 * Get entry in the third-level page table
	 */
	ptep = boot_pte_offset(pmdp, virt_addr);
	return (ptep);
}

/*
 * Find virtual address entry in the third-level page table, if exists
 */

#ifdef	CONFIG_RECOVERY
static pte_t *
boot_find_pte(e2k_addr_t virt_addr, int large_page)
{
	pgd_t	*pgdp;
	pud_t	*pudp;
	pmd_t	*pmdp;
	pte_t	*ptep;

	/*
	 * Take entry in the root-level page table
	 */
	pgdp = boot_pgd_offset_k(virt_addr);
	if (pgd_none(*pgdp)) {
		return NULL;
	}

	/*
	 * Take entry in the first-level (high part of middle) page table
	 */
	pudp = boot_pud_offset(pgdp, virt_addr);
	if (pud_none(*pudp)) {
		return NULL;
	}

	/*
	 * Take entry in the second-level (low part of middle) page table
	 */
	pmdp = boot_pmd_offset(pudp, virt_addr);
	if (large_page) {
		/* A large virtual page occupies two sequential
		 * entries in page table on 2-th level (PMD) */
		return (pte_t *)pmdp;
	}
	if (pmd_none(*pmdp)) {
		return NULL;
	}

	/*
	 * Take entry in the third-level page table
	 */
	ptep = boot_pte_offset(pmdp, virt_addr);

	return ptep;
}
#endif	/* CONFIG_RECOVERY */

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
 * Allocate memory for first-level (high part of middle) page table directory
 */
static pud_t * __init_recv
boot_pud_alloc(void)
{
	pud_t	*pudp;
	int	entry;

	pudp = (pud_t *)boot_alloc_phys_mem(PUD_TABLE_SIZE, PAGE_SIZE);
	if (pudp == (pud_t *)-1) {
		BOOT_BUG_POINT("boot_pud_alloc");
		BOOT_BUG("Could not allocate memory for first-level page "
			"table (PUD)");
		return ((pud_t *)-1);
	}
	for (entry = 0; entry < PTRS_PER_PUD; entry ++) {
		pud_clear_kernel(&pudp[entry]);
	}
	return (pudp);
}

/*
 * Allocate memory for second-level (low part of middle) page table directory
 */
static pmd_t * __init_recv
boot_pmd_alloc(void)
{
	pmd_t	*pmdp;
	int	entry;

	pmdp = (pmd_t *)boot_alloc_phys_mem(PMD_TABLE_SIZE, PAGE_SIZE);
	if (pmdp == (pmd_t *)-1) {
		BOOT_BUG_POINT("boot_pmd_alloc");
		BOOT_BUG("Could not allocate memory for second-level page "
			"table (PMD)");
		return ((pmd_t *)-1);
	}
	for (entry = 0; entry < PTRS_PER_PMD; entry ++) {
		pmd_clear_kernel(&pmdp[entry]);

	}
	return (pmdp);
}

/*
 * Allocate memory for third-level page table
 */
static pte_t * __init_recv
boot_pte_alloc(void)
{
	pte_t	*ptep;
	int	entry;

	ptep = (pte_t *)boot_alloc_phys_mem(PTE_TABLE_SIZE, PAGE_SIZE);
	if (ptep == (pte_t *)-1) {
		BOOT_BUG_POINT("boot_pte_alloc");
		BOOT_BUG("Could not allocate memory for third-level page "
			"table (PTE)");
		return ((pte_t *)-1);
	}
	for (entry = 0; entry < PTRS_PER_PTE; entry ++) {
		pte_clear_kernel(&ptep[entry]);

	}
	return (ptep);
}

/*
 * Unmap temporary mapped the virtual area into the kernel virtual space.
 * Function return number of unmapped pages or 0, if error was detected,
 * for example if some of the pages is not mapped
 */

int __init
init_unmap_virt_area(e2k_addr_t area_virt_addr, e2k_size_t area_size,
	e2k_size_t page_size, int ignore_absence)
{
	e2k_addr_t	virt_addr;
	int		pages_num;
	int		page;
	int		ret;

	if ((area_virt_addr & (page_size - 1)) != 0) {
		INIT_BUG_POINT("init_unmap_virt_area");
		INIT_BUG("Virtual adress 0x%lx is not page size 0x%lx aligned",
			area_virt_addr, page_size);
		return 0;
	} else {
		virt_addr = area_virt_addr;
	}

	pages_num = (_PAGE_ALIGN_DOWN(area_virt_addr + area_size, page_size) -
			area_virt_addr) / page_size;
	DebugB("Pages num %d virt addr 0x%lx size 0x%lx page size 0x%lx\n",
		pages_num, area_virt_addr, area_size, page_size);

	for (page = 0; page < pages_num; page ++) {
		ret = init_clear_ptes(virt_addr, ignore_absence,
					page_size == E2K_LARGE_PAGE_SIZE);
		if (ret != 0) {
			INIT_BUG_POINT("init_unmap_virt_area");
			INIT_BUG("Could not clear PTEs of virtual address "
				"0x%lx", virt_addr);
			return 0;
		}
		DebugB("virt addr 0x%lx PTEs was cleared\n", virt_addr);
		virt_addr += page_size;
	}
	return page;
}

/*
 * Clear PTEs of kernel virtual page in the four-level page table.
 */

static	int  __init_recv
init_clear_ptes(e2k_addr_t virt_addr, int ignore_absence, int large_page)
{
	pte_t	*ptep;

	DebugME("init_clear_ptes() started for "
		"virt addr 0x%lx large page flag %d\n",
		virt_addr, large_page);
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_lock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
	boot_dup_node_spin_lock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */

	/*
	 * Clear entry in the third-level page table
	 */
#ifndef	CONFIG_RECOVERY
	ptep = boot_pte_offset_k(virt_addr, large_page);
#else
	DebugME("init_clear_ptes() will start boot_find_pte() for "
		"virt addr 0x%lx large page flag %d\n",
		virt_addr, large_page);
	ptep = boot_find_pte(virt_addr, large_page);
	DebugME("init_clear_ptes() boot_find_pte() find "
		"ptep 0x%lx == 0x%lx\n",
		ptep, (ptep == NULL) ? (long)NULL : pte_val(*ptep));
#endif	/* ! (CONFIG_RECOVERY) */
	if (ptep == NULL || pte_none(*ptep)) {
		if (!ignore_absence) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("init_clear_ptes");
			BOOT_BUG("Third level PTE[0x%lx] of virtual address "
				"0x%lx is absent", (long)ptep, virt_addr);
			return (1);
		}
		DebugME("PTE[0x%lx} of virt addr 0x%lx is already clear\n",
			(long)ptep, virt_addr);
	} else {
		boot_pte_clear(ptep, large_page);
		DebugME("clear PTE[0x%lx] of virt addr 0x%lx\n",
			(long)ptep, virt_addr);
	}

	/*
	 * Clear entry in the second-level (low part of middle) page table
	 */
#if	0
	pmdp = pmd_offset_k(virt_addr);
	if (pmd_none(*pmdp)) {
		if (!ignore_absence) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("init_clear_ptes");
			BOOT_BUG("Second level PMD[0x%lx] of virtual address "
				"0x%lx is absent", (long)pmdp, virt_addr);
			return (1);
		}
		DebugB("PMD[0x%lx} of virt addr 0x%lx is already clear\n",
			(long)pmdp, virt_addr);
	} else {
		pmd_clear(pmdp);
		DebugB("clear PMD[0x%lx] of virt addr 0x%lx\n",
			(long)pmdp, virt_addr);
	}
#endif	/* 0 */

	/*
	 * Clear entry in the first-level (high part of middle) page table
	 */
#if	0
	pudp = pud_offset_k(virt_addr);
	if (pud_none(*pudp)) {
		if (!ignore_absence) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("init_clear_ptes");
			BOOT_BUG("First level PUD[0x%lx] of virtual address "
				"0x%lx is absent", (long)pudp, virt_addr);
			return (1);
		}
		DebugB("PUD[0x%lx} of virt addr 0x%lx is already clear\n",
			(long)pudp, virt_addr);
	} else {
		pud_clear(pudp);
		DebugB("clear PUD[0x%lx] of virt addr 0x%lx\n",
			(long)pudp, virt_addr);
	}
#endif	/* 0 */

	/*
	 * Clear entry in the root-level page table
	 */
#if	0
	pgdp = pgd_offset_k(virt_addr);
	if (pgd_none(*pgdp)) {
		if (!ignore_absence) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("init_clear_ptes");
			BOOT_BUG("Root level PGD[0x%lx] of virtual address "
				"0x%lx is absent", (long)pgdp, virt_addr);
			return (1);
		}
		DebugB("pgd[0x%lx] of virt addr 0x%lx is already clear\n",
			(long)pgdp, virt_addr);
	} else {
		pgd_clear(pgdp);
		DebugB("clear pgd[0x%lx] of virt addr 0x%lx\n",
			(long)pgdp, virt_addr);
	}
#endif	/* 0 */
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
	boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	boot_printk("init_clear_ptes() ret 0\n");
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
	e2k_size_t page_size, int tlb_mask, int va)
{
	pte_t		pte;
	pgprot_t	prot;
	e2k_addr_t	phys_addr;
	e2k_addr_t	virt_addr;
	int		pages_num;
	int		page;
	int		large_page_flag = 0;
	int		cur_tlb_mask;
	int		ret;

	DebugME("boot_map_to_equal_virt_area() started for addr 0x%lx "
		"size 0x%lx\n",
		area_addr, area_size);
	if (page_size == E2K_SMALL_PAGE_SIZE) {
		prot = pgprot_small_size_set(prot_flags);
	} else if (page_size == BOOT_E2K_LARGE_PAGE_SIZE) {
		prot = pgprot_large_size_set(prot_flags);
		large_page_flag = 1;
	} else {
		BOOT_BUG_POINT("boot_map_to_equal_virt_area");
		BOOT_BUG("Invalid page size 0x%lx", page_size);
		return (0);
	}
	phys_addr = _PAGE_ALIGN_UP(area_addr, page_size);
	virt_addr = phys_addr;
	pages_num = (_PAGE_ALIGN_DOWN(area_addr + area_size,
				page_size) - phys_addr) / page_size;
	DebugME("boot_map_to_equal_virt_area() virt addr will be 0x%lx "
		"large page flag is %d\n",
		virt_addr, large_page_flag);

	for (page = 0; page < pages_num; page ++) {
		ret = boot_find_equal_addr(virt_addr, tlb_mask,
							large_page_flag, va);
		DebugME("boot_map_to_equal_virt_area() "
			"boot_find_equal_addr(0x%lx) returned mask 0x%x "
			"sorce mask is 0x%x\n",
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
			cur_tlb_mask, va);
		if (ret != 0) {
			BOOT_BUG_POINT("boot_map_to_equal_virt_area");
			BOOT_BUG("Could not write PTE 0x%lx of virtual addr "
				"0x%lx to TLB",
				pte_val(pte), virt_addr);
			return (0);
		}
		phys_addr += page_size;
		virt_addr = phys_addr;
	}
	DebugME("boot_map_to_equal_virt_area() returns with mapped "
		"pages num %d\n", page);
	return (page);
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

	for (cpuid = 0; cpuid < NR_CPUS; cpuid ++) {
		if (!boot_cpu_possible(cpuid))
			continue;
		boot_cpu_tlb_contents_simul_init(cpuid);
	}
}
#endif	/* CONFIG_NUMA */
#endif	/* ! CONFIG_SMP */

/*
 * Init. TLB structure to simulate it contents
 */
static void __init
boot_tlb_contents_simul_init(e2k_tlb_t *tlb)
{
	int	line;
	int	set;

	for (line = 0; line < E2K_TLB_LINES_NUM; line ++) {
		for (set = 0; set < E2K_TLB_SETS_NUM; set ++) {
			tlb->lines[line].sets[set].virt_addr = 0;
			tlb->lines[line].sets[set].valid_bit = 0;
		}
		tlb->lines[line].sets_num = 0;
	}
	tlb->entries_num = 0;
}

/*
 * Find the address in the list of pages currently mapped to the equal
 * virtual space.
 * All these pages are located into two TLBs contents simulation structures
 */

static int __init_recv
boot_find_equal_addr(e2k_addr_t address, int tlb_mask, int large_page_flag,
	int va)
{
	int	mask = 0;
	int	ret;

	if (tlb_mask & ITLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_find_equal_addr_tlb(address,
					itlb_contents, large_page_flag);
#else /* !CONFIG_SMP */
			ret = boot_find_equal_addr_tlb(address,
					&itlb_contents, large_page_flag);
#endif /* CONFIG_SMP */               
		else
			ret = boot_find_equal_addr_tlb(address,
					boot_itlb_contents, large_page_flag);
		if (ret == 0)
			mask |= ITLB_ACCESS_MASK;
	}
	if (tlb_mask & DTLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_find_equal_addr_tlb(address,
					dtlb_contents, large_page_flag);
#else /* !CONFIG_SMP */
			ret = boot_find_equal_addr_tlb(address,
					&dtlb_contents, large_page_flag);
#endif /* CONFIG_SMP */               
		else
			ret = boot_find_equal_addr_tlb(address,
					boot_dtlb_contents, large_page_flag);
		if (ret == 0)
			mask |= DTLB_ACCESS_MASK;
	}
	return (mask);
}

/*
 * Find the address in the list of pages currently mapped to the equal
 * virtual space into the TLB
 */

static int __init_recv
boot_find_equal_addr_tlb(e2k_addr_t address, e2k_tlb_t *tlb,
	int large_page_flag)
{
	int		line;
	e2k_tlb_line_t	*tlb_line;
	int		set;
	int		entries = 0;

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
	for (set = 0; set < E2K_TLB_SETS_NUM; set ++) {
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
 * Get the TLB empty entry
 */

static int __init_recv
boot_get_tlb_empty_set(e2k_addr_t address, e2k_tlb_t *tlb, int large_page_flag)
{
	int		line;
	e2k_tlb_line_t	*tlb_line;
	int		set;

	DebugME("boot_get_tlb_empty_set() started for addr 0x%lx "
		"large page flag is %d\n",
		address, large_page_flag);
	line = BOOT_VADDR_TO_TLB_LINE_NUM(address, large_page_flag);
	tlb_line = &tlb->lines[line];
	DebugME("boot_get_tlb_empty_set() TLB line is %d occupied sets "
		"num is %d\n",
		line, tlb_line->sets_num);
	if (tlb_line->sets_num >= E2K_TLB_SETS_NUM)
		return (-1);
	for (set = 0; set < E2K_TLB_SETS_NUM; set ++) {
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
		if (large_page_flag && set != E2K_TLB_LARGE_PAGE_SET_NO) {
			DebugME("boot_get_tlb_empty_set() TLB line #%d "
				"set #%d cannot be used for large page\n",
				line, set);
			continue;
		}
		tlb_line->sets[set].virt_addr = address;
		tlb_line->sets[set].valid_bit = 1;
		tlb_line->sets[set].large_page = large_page_flag;
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
 * Write PTE of page mapped to the equal virtual address to TLB or page table.
 * Write to ITLB is not implemented - pte is temporarly written to page table
 * entry.
 */

static int __init_recv
boot_write_equal_addr_pte(pte_t pte, tlb_tag_t prot_flags, e2k_addr_t address,
	int tlb_mask, int va)
{
	int	ret;

	if (tlb_mask & ITLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_write_pte_to_pt(
					pte, address, itlb_contents, va);
#else /* !CONFIG_SMP */
			ret = boot_write_pte_to_pt(
					pte, address, &itlb_contents, va);
#endif /* CONFIG_SMP */
                
		else
			ret = boot_write_pte_to_pt(
					pte, address, boot_itlb_contents, va);
		if (ret != 0)
			return (ret);
	}
	if (tlb_mask & DTLB_ACCESS_MASK) {
		if (va)
#ifdef	CONFIG_SMP
			ret = boot_write_pte_to_tlb(pte, prot_flags, address,
								dtlb_contents);
#else /* !CONFIG_SMP */                
			ret = boot_write_pte_to_tlb(pte, prot_flags, address,
								&dtlb_contents);
#endif /* CONFIG_SMP */
		else
			ret = boot_write_pte_to_tlb(pte, prot_flags, address,
							boot_dtlb_contents);
		if (ret != 0)
			return (ret);
	}
	return (0);
}

/*
 * Write PTE of the virtual address to Data TLB.
 */

static int __init_recv
boot_write_pte_to_tlb(pte_t pte, tlb_tag_t prot_flags, e2k_addr_t virt_addr,
	e2k_tlb_t *tlb)
{
	int		set_num;
	tlb_addr_t	tlb_addr;
	tlb_tag_t	tlb_tag;

	/*
	 * Create and write tag to the matching TLB tag register 
	 */
	tlb_addr = tlb_addr_tag_access;
	tlb_addr = boot_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr,
			pte_huge(pte));
	set_num = boot_get_tlb_empty_set(virt_addr, tlb, pte_huge(pte));
	if (set_num < 0) {
		BOOT_BUG_POINT("boot_write_pte_to_tlb");
		BOOT_BUG("Could not find empty entry set of TLB for virtual "
			"address 0x%lx", virt_addr);
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
boot_write_pte_to_pt(pte_t pte, e2k_addr_t virt_addr, e2k_tlb_t *tlb, int va)
{
	pte_t	*ptep;
	int	set_num;

	DebugME("boot_write_pte_to_pt() started for address 0x%lx and "
		"pte == 0x%lx\n",
		virt_addr, pte_val(pte));
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_lock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
	boot_dup_node_spin_lock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	ptep = boot_get_pte(virt_addr, pte_huge(pte), 1, va);
	if (ptep == (pte_t *)-1) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
		boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
		boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
		BOOT_BUG_POINT("boot_write_pte_to_pt");
		BOOT_BUG("Could not take PTE pointer to map virtual "
			"address 0x%lx", virt_addr);
		return (1);
	}
	DebugME("boot_write_pte_to_pt() ptep is 0x%lx == 0x%lx to write "
		"new pte == 0x%lx\n",
		ptep, pte_val(*ptep), pte_val(pte));
	if (!pte_none(*ptep)) {
#ifdef	CONFIG_SMP
		if (pte_val(*ptep) != pte_val(pte)) {
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
			BOOT_BUG_POINT("boot_write_pte_to_pt");
			BOOT_BUG("The PTE entry is not empty - "
				"virtual address 0x%lx has been already "
				"occupied by 0x%lx new pte is 0x%lx",
				virt_addr, pte_val(*ptep), pte_val(pte));
			return (1);
#ifdef	CONFIG_SMP
		} else {
			set_num = boot_get_tlb_empty_set(virt_addr, tlb,
					pte_huge(pte));
#ifndef	CONFIG_NUMA
			boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
			boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
			if (set_num < 0) {
				BOOT_BUG_POINT("boot_write_pte_to_pt");
				BOOT_BUG("Could not find empty entry set of "
					"TLB for virtual address 0x%lx",
					virt_addr);
				return (1);
			}
			DebugME("boot_write_pte_to_pt() new pte is the "
				"same as existed: return\n");
			return (0);
		}
#endif	/* CONFIG_SMP */
	}
	set_num = boot_get_tlb_empty_set(virt_addr, tlb, pte_huge(pte));
	if (set_num < 0) {
#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
		boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
		boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
		BOOT_BUG_POINT("boot_write_pte_to_pt");
		BOOT_BUG("Could not find empty entry set of TLB for virtual "
			"address 0x%lx", virt_addr);
		return (1);
	}

	boot_set_pte(ptep, pte, pte_huge(pte));

#ifdef	CONFIG_SMP
#ifndef	CONFIG_NUMA
	boot_spin_unlock(&boot_page_table_lock);
#else	/* CONFIG_NUMA */
	boot_dup_node_spin_unlock(boot_page_table_lock);
#endif	/* ! CONFIG_NUMA */
#endif	/* CONFIG_SMP */
	DebugME("boot_write_pte_to_pt() set ptep 0x%lx to new pte 0x%lx\n",
		ptep, pte_val(*ptep));

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
			return (ret);
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
			return (ret);
	}
	return (0);
}

#ifdef	CONFIG_RECOVERY
int
boot_clear_temporary_ptes(int tlb_mask, int cpuid)
{
	int	ret;

	if (tlb_mask & ITLB_ACCESS_MASK) {
		ret = init_clear_temporary_pt(boot_itlb_contents,
							ITLB_ACCESS_MASK);
		if (ret != 0)
			return ret;
	}
	if (tlb_mask & DTLB_ACCESS_MASK) {
		ret = init_clear_temporary_tlb(boot_dtlb_contents,
							DTLB_ACCESS_MASK);
		if (ret != 0)
			return ret;
	}
	return 0;
}
#endif	/* CONFIG_RECOVERY */

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
		return (0);
	for (line = 0; line < E2K_TLB_LINES_NUM; line ++) {
		tlb_line = &tlb->lines[line];
		if (tlb_line->sets_num == 0)
			continue;
		for (set = 0; set < E2K_TLB_SETS_NUM; set ++) {
			if (!tlb_line->sets[set].valid_bit)
				continue;
			ret = init_clear_ptes(tlb_line->sets[set].virt_addr,
#ifndef	CONFIG_SMP
				0,	/* do not ignore the page absence */
#else
				1,	/* ignore the page absence */
#endif	/* CONFIG_SMP */
				tlb_line->sets[set].large_page);
			if (ret != 0) {
				BOOT_BUG_POINT("init_clear_temporary_pt");
				BOOT_BUG("Could not clear PT virtual address "
					"0x%lx from line %d set %d",
					tlb_line->sets[set].virt_addr,
					line, set);
				return (1);
			}
			ret = init_clear_tlb_entry(
				tlb_line->sets[set].virt_addr,
				tlb_mask);
			if (ret != 0) {
				BOOT_BUG_POINT("init_clear_temporary_pt");
				BOOT_BUG("Could not clear ITLB virtual address "
					"0x%lx from line %d set %d",
					tlb_line->sets[set].virt_addr,
					line, set);
				return (1);
			}
			tlb_line->sets[set].valid_bit = 0;
			tlb_line->sets[set].virt_addr = 0;
			tlb_line->sets[set].large_page = 0;
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
	for (line = 0; line < E2K_TLB_LINES_NUM; line ++) {
		tlb_line = &tlb->lines[line];
		if (tlb_line->sets_num == 0)
			continue;
		for (set = 0; set < E2K_TLB_SETS_NUM; set ++) {
			if (!tlb_line->sets[set].valid_bit)
				continue;
			ret = init_clear_tlb_entry(
				tlb_line->sets[set].virt_addr,
				tlb_mask);
			if (ret != 0) {
				BOOT_BUG_POINT("init_clear_temporary_pt");
				BOOT_BUG("Could not clear ITLB virtual address "
					"0x%lx from line %d set %d",
					tlb_line->sets[set].virt_addr,
					line, set);
				return (1);
			}
			tlb_line->sets[set].valid_bit = 0;
			tlb_line->sets[set].virt_addr = 0;
			tlb_line->sets[set].large_page = 0;
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

	return (0);
}
