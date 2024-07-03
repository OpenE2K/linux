/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_PGTABLE_TYPES_H_
#define _E2K_PGTABLE_TYPES_H_

#ifndef	__ASSEMBLY__

#include <linux/types.h>
#include <asm/mmu_types.h>
#include <asm/bug.h>

#define MMU_IS_SEPARATE_PT()	cpu_has(CPU_FEAT_SEP_VIRT_SPACE)
#define MMU_IS_PT_V6()		cpu_has(CPU_FEAT_PAGE_TABLE_V6)

/* max. number of physical address bits (architected) */
#define E2K_MAX_PHYS_BITS_V3	40	/* on V1-V5 */
#define E2K_MAX_PHYS_BITS_V6	48	/* from V6-... */

/*
 * Memory types, the same as PTE.MT field values,
 * see iset 8.2.3. 1)
 */
typedef enum pte_mem_type {
	GEN_CACHE_MT		= 0,
	GEN_NON_CACHE_MT	= 1,
	EXT_PREFETCH_MT		= 4,
	EXT_NON_PREFETCH_MT	= 6,
	EXT_CONFIG_MT		= 7,
	/* This is the same as GEN_NON_CACHE_MT but with additional bit
	 * set so that track_pfn_*() functions can understand if this
	 * is EXT_PREFETCH_MT (i.e. came from pgprot_writecombine())
	 * or EXT_NON_PREFETCH_MT (i.e. came from pgprot_noncached()).
	 *
	 * This is needed to distinguish between the following cases:
	 * 1) pgprot_noncached() + vm_insert_page()
	 * 2) pgprot_writecombine() + vm_insert_page()
	 * 3) pgprot_noncached() + some other mapping function
	 * 4) pgprot_writecombine() + some other mapping function
	 *
	 * If we are mapping device ("External") then track_pfn_insert()
	 * and track_pfn_remap() functions will convert the type (cases
	 * 3 and 4).  And by default set hardware "General" type (cases 1
	 * and 2) because vm_insert_page() does not call track_pfn_*()
	 * functions, and "General" type has cache coherency properly
	 * enabled unlike "External" type. */
	GEN_NON_CACHE_ORDERED_MT = 9,
} pte_mem_type_t;

static inline char *pte_mem_type_name(enum pte_mem_type type)
{
	switch (type) {
	case GEN_CACHE_MT:
		return "GC";
	case GEN_NON_CACHE_MT:
		return "GnC";
	case EXT_PREFETCH_MT:
		return "XP";
	case EXT_NON_PREFETCH_MT:
		return "XnP";
	case EXT_CONFIG_MT:
		return "XC";
	case GEN_NON_CACHE_ORDERED_MT:
		return "GnC_ordered";
	}
	BUG();
}

static inline bool pte_mem_type_is_coherent(enum pte_mem_type type)
{
	switch (type) {
	case GEN_CACHE_MT:
	case GEN_NON_CACHE_MT:
		return true;
	case EXT_NON_PREFETCH_MT:
	case EXT_CONFIG_MT:
		return false;
	case EXT_PREFETCH_MT:
		return !cpu_has(CPU_FEAT_ISET_V6);
	case GEN_NON_CACHE_ORDERED_MT:
		return cpu_has(CPU_FEAT_ISET_V6);
	}
	BUG();
}


typedef enum pte_mem_type_rule {
	MOST_STRONG_MTCR	= 0,
	FROM_HYPERVISOR_MTCR	= 2,
	FROM_GUEST_MTCR		= 3,
} pte_mem_type_rule_t;

/* arch-independent structure of page table entries */
typedef enum uni_page_bits {
	UNI_PAGE_PRESENT_BIT,		/* Present */
	UNI_PAGE_WRITE_BIT,		/* Writable */
	UNI_PAGE_PRIV_BIT,		/* PriVileged */
	UNI_PAGE_VALID_BIT,		/* Valid */
	UNI_PAGE_PROTECT_BIT,		/* PRotected */
	UNI_PAGE_DIRTY_BIT,		/* page Dirty */
	UNI_PAGE_HUGE_BIT,		/* huge Page Size */
	UNI_PAGE_GLOBAL_BIT,		/* Global page */
	UNI_PAGE_NWA_BIT,		/* No Writable Address */
	UNI_PAGE_NON_EX_BIT,		/* NON EXecutable */
	UNI_PAGE_PROTNONE_BIT,		/* software PROTection NONE */
	UNI_PAGE_AVAIL_BIT,		/* software AVAILable */
	UNI_PAGE_SPECIAL_BIT,		/* software SPECIAL */
	UNI_PAGE_GFN_BIT,		/* software Guest page Frame Number */
	UNI_PAGE_ACCESSED_BIT,		/* page hardware/software Accessed */
	UNI_PAGE_PFN_BIT,		/* Physical Page Number field */
	UNI_PAGE_MEM_TYPE_BIT,		/* Memory Type field */
	UNI_PAGE_MEM_TYPE_RULE_BIT,	/* Memory Type Combination Rule field */
	UNI_PAGE_INTL_RD_BIT,		/* Intel Read protection */
					/* DTLB field */
	UNI_PAGE_INTL_WR_BIT,		/* Intel Write protection */
					/* DTLB field */
	UNI_DTLB_MISS_LEVEL_BIT,	/* miss level DTLB field */
	UNI_DTLB_RES_BITS_BIT,		/* reserved bits of DTLB probe */
					/* result */
} uni_page_bits_t;

typedef const unsigned long	uni_pteval_t;
typedef const unsigned long	uni_dtlb_t;

#define	UNI_PAGE_PRESENT	(uni_pteval_t)(1ULL << UNI_PAGE_PRESENT_BIT)
#define	UNI_PAGE_WRITE		(uni_pteval_t)(1ULL << UNI_PAGE_WRITE_BIT)
#define	UNI_PAGE_PRIV		(uni_pteval_t)(1ULL << UNI_PAGE_PRIV_BIT)
#define	UNI_PAGE_VALID		(uni_pteval_t)(1ULL << UNI_PAGE_VALID_BIT)
#define	UNI_PAGE_PROTECT	(uni_pteval_t)(1ULL << UNI_PAGE_PROTECT_BIT)
#define	UNI_PAGE_DIRTY		(uni_pteval_t)(1ULL << UNI_PAGE_DIRTY_BIT)
#define	UNI_PAGE_HUGE		(uni_pteval_t)(1ULL << UNI_PAGE_HUGE_BIT)
#define	UNI_PAGE_GLOBAL		(uni_pteval_t)(1ULL << UNI_PAGE_GLOBAL_BIT)
#define	UNI_PAGE_NWA		(uni_pteval_t)(1ULL << UNI_PAGE_NWA_BIT)
#define	UNI_PAGE_NON_EX		(uni_pteval_t)(1ULL << UNI_PAGE_NON_EX_BIT)
#define	UNI_PAGE_PROTNONE	(uni_pteval_t)(1ULL << UNI_PAGE_PROTNONE_BIT)
#define	UNI_PAGE_AVAIL		(uni_pteval_t)(1ULL << UNI_PAGE_AVAIL_BIT)
#define	UNI_PAGE_SPECIAL	(uni_pteval_t)(1ULL << UNI_PAGE_SPECIAL_BIT)
#define	UNI_PAGE_GFN		(uni_pteval_t)(1ULL << UNI_PAGE_GFN_BIT)
#define	UNI_PAGE_ACCESSED	(uni_pteval_t)(1ULL << UNI_PAGE_ACCESSED_BIT)
#define	UNI_PAGE_PFN		(uni_pteval_t)(1ULL << UNI_PAGE_PFN_BIT)
#define	UNI_PAGE_MEM_TYPE	(uni_pteval_t)(1ULL << UNI_PAGE_MEM_TYPE_BIT)
#define	UNI_PAGE_MEM_TYPE_RULE	\
		(uni_pteval_t)(1ULL << UNI_PAGE_MEM_TYPE_RULE_BIT)
#define	UNI_PAGE_INTL_RD	(uni_dtlb_t)(1ULL << UNI_PAGE_INTL_RD_BIT)
#define	UNI_PAGE_INTL_WR	(uni_dtlb_t)(1ULL << UNI_PAGE_INTL_WR_BIT)
#define	UNI_DTLB_MISS_LEVEL	(uni_dtlb_t)(1ULL << UNI_DTLB_MISS_LEVEL_BIT)
#define	UNI_DTLB_RES_BITS	(uni_dtlb_t)(1ULL << UNI_DTLB_RES_BITS_BIT)

/*
 * Encode and de-code a swap entry
 *
 * Format of swap pte:
 *	bits 0, _PAGE_PROTNONE : present bits (must be zero)
 *	bits 13-19: swap-type
 *	bits 20-63: swap offset (MMU PTE version dependent, see pgtable-v*.h)
 */
#define __SWP_TYPE_BITS		7
#define MAX_SWAPFILES_CHECK()	BUILD_BUG_ON(MAX_SWAPFILES_SHIFT > \
					     __SWP_TYPE_BITS)
#define __SWP_TYPE_SHIFT	(PAGE_SHIFT + 1)
#define __SWP_OFFSET_SHIFT	(__SWP_TYPE_SHIFT + __SWP_TYPE_BITS)
#define __FILE_PGOFF_SHIFT	(PAGE_SHIFT + 1)

#define __swp_type(entry)	(((entry).val >> __SWP_TYPE_SHIFT) & \
				 ((1U << __SWP_TYPE_BITS) - 1))
#define __pte_to_swp_entry(pte)	((swp_entry_t) { pte_val(pte) })
#define __pmd_to_swp_entry(pte)	((swp_entry_t) { pmd_val(pmd) })

#endif	/* ! __ASSEMBLY__ */

#endif /* _E2K_PGTABLE_TYPES_H_ */
