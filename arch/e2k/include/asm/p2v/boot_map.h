/* $Id: boot_map.h,v 1.5 2008/12/19 12:57:15 atic Exp $
 *
 * boot-time mappings physical memory areas to viertual kernel space.
 */
#ifndef _E2K_P2V_BOOT_MAP_H
#define _E2K_P2V_BOOT_MAP_H

#include <linux/init.h>
#include <asm/types.h>
#include <asm/page.h>
#include <asm/mmu_regs.h>
#include <asm/pgtable.h>
#include <asm/p2v/boot_smp.h>

/*
 * Structures to simulate TLB contents
 */

typedef	struct e2k_tlb_item {		/* an item of TLB */
	e2k_addr_t	virt_addr;	/* virtual address - tag */
	int		valid_bit;	/* the item valid flag */
	int		pt_level_id;	/* page table level # to calculate */
					/* page size */
} e2k_tlb_item_t;
typedef	struct e2k_tlb_line {		/* a line of TLB */
	e2k_tlb_item_t	sets[NATIVE_TLB_SETS_NUM];
	int		sets_num;	/* number of valid entries in */
					/* the line */
} e2k_tlb_line_t;
typedef	struct e2k_tlb {		/* all TLB */
	e2k_tlb_line_t	lines[NATIVE_MAX_TLB_LINES_NUM];
	int		entries_num;	/* number of valid entries in */
					/* the TLB */
} e2k_tlb_t;

#ifndef	CONFIG_SMP
extern	e2k_tlb_t		dtlb_contents;
extern	e2k_tlb_t		itlb_contents;
#define	boot_dtlb_contents	boot_vp_to_pp(&dtlb_contents)
#define	boot_itlb_contents	boot_vp_to_pp(&itlb_contents)
#else
extern	e2k_tlb_t	dtlb_contents[NR_CPUS];
extern	e2k_tlb_t	itlb_contents[NR_CPUS];
#define	boot_dtlb_contents	\
		boot_vp_to_pp(&dtlb_contents[boot_smp_processor_id()])
#define	boot_itlb_contents	\
		boot_vp_to_pp(&itlb_contents[boot_smp_processor_id()])
#endif	/* CONFIG_SMP */

#define	DTLB_ACCESS_MASK	0x01
#define	ITLB_ACCESS_MASK	0x02
#define	ALL_TLB_ACCESS_MASK	(DTLB_ACCESS_MASK | ITLB_ACCESS_MASK)

/*
 * Forwards of boot-time functions to map physical areas to kernel virtual space
 */

extern void	boot_init_mapping(void);
#ifdef	CONFIG_NUMA
extern void	boot_node_init_mapping(void);
#endif	/* CONFIG_NUMA */

/* Page Tables common structure interface's functions */
extern pte_t * __init_recv
boot_get_double_huge_pte(e2k_addr_t addr, pgprot_t *ptp);
extern pte_t * __init_recv
boot_get_common_huge_pte(e2k_addr_t addr, pgprot_t *ptp);
extern void __init_recv
boot_set_double_pte(e2k_addr_t addr, pte_t *ptep, pte_t pte, bool host_map);
extern void __init_recv
boot_set_common_pte(e2k_addr_t addr, pte_t *ptep, pte_t pte, bool host_map);
extern pte_t * __init_recv
init_get_double_huge_pte(e2k_addr_t addr, pgprot_t *ptp);
extern pte_t * __init_recv
init_get_common_huge_pte(e2k_addr_t addr, pgprot_t *ptp);
extern void __init_recv
init_double_pte_clear(pte_t *ptep);
extern void __init_recv
init_common_pte_clear(pte_t *ptep);

extern long boot_map_phys_area(e2k_addr_t phys_area_addr,
			e2k_size_t phys_area_size, e2k_addr_t area_virt_addr,
			pgprot_t prot_flags, e2k_size_t page_size,
			bool ignore_busy, bool host_map);
extern long boot_do_map_phys_area(e2k_addr_t phys_area_addr,
			e2k_size_t phys_area_size, e2k_addr_t area_virt_addr,
			pgprot_t prot_flags, const pt_level_t *pt_level,
			bool ignore_busy, bool host_map);
extern int boot_map_to_equal_virt_area(e2k_addr_t area_addr,
			e2k_size_t area_size,
			pgprot_t prot_flags, tlb_tag_t tlb_prot_flags,
			e2k_size_t max_page_size, int tlb_mask, int va);
extern int init_clear_temporary_ptes(int tlb_mask, int cpuid);

#endif /* _E2K_P2V_BOOT_MAP_H */
