#ifndef _E2K_PGTABLE_TYPES_H_
#define _E2K_PGTABLE_TYPES_H_

#ifndef	__ASSEMBLY__

#include <linux/types.h>
#include <asm/mmu_types.h>

#if	CONFIG_CPU_ISET >= 6
# ifdef	CONFIG_MMU_PT_V6
#  define	MMU_IS_PT_V6()		true
# else	/* ! CONFIG_MMU_PT_V6 */
#  define	MMU_IS_PT_V6()		false
# endif	/* CONFIG_MMU_PT_V6 */
# ifdef	CONFIG_MMU_SEP_VIRT_SPACE
#  ifndef CONFIG_DYNAMIC_SEP_VIRT_SPACE
#   define	MMU_IS_SEPARATE_PT()	true
#  else	/* CONFIG_DYNAMIC_SEP_VIRT_SPACE */
#   ifdef E2K_P2V
#    define	MMU_IS_SEPARATE_PT()	(boot_machine.mmu_separate_pt)
#   else /* ! E2K_P2V */
#    define	MMU_IS_SEPARATE_PT()	(machine.mmu_separate_pt)
#   endif /* E2K_P2V */
#  endif /* ! CONFIG_DYNAMIC_SEP_VIRT_SPACE */
# else	/* ! MMU_SEP_VIRT_SPACE */
#  define	MMU_IS_SEPARATE_PT()	false
# endif	/* MMU_SEP_VIRT_SPACE */
#elif	CONFIG_CPU_ISET >= 2
#  define	MMU_IS_PT_V6()		false
#  define	MMU_IS_SEPARATE_PT()	false
#elif	CONFIG_CPU_ISET == 0
# ifdef	E2K_P2V
#  define	MMU_IS_PT_V6()		(boot_machine.mmu_pt_v6)
#  define	MMU_IS_SEPARATE_PT()	(boot_machine.mmu_separate_pt)
# else	/* ! E2K_P2V */
#  define	MMU_IS_PT_V6()		(machine.mmu_pt_v6)
#  define	MMU_IS_SEPARATE_PT()	(machine.mmu_separate_pt)
# endif	/* E2K_P2V */
#else	/* CONFIG_CPU_ISET undefined or negative */
# warning "Undefined CPU ISET VERSION #, MMU pt_v6 mode is defined dinamicaly"
# warning "Undefined CPU ISET VERSION #, MMU sep_pt mode is defined dinamicaly"
# ifdef	E2K_P2V
#  define	MMU_IS_PT_V6()		(boot_machine.mmu_pt_v6)
#  define	MMU_IS_SEPARATE_PT()	(boot_machine.mmu_separate_pt)
# else	/* ! E2K_P2V */
#  define	MMU_IS_PT_V6()		(machine.mmu_pt_v6)
#  define	MMU_IS_SEPARATE_PT()	(machine.mmu_separate_pt)
# endif	/* E2K_P2V */
#endif	/* CONFIG_CPU_ISET 0-6 */

/* max. number of physical address bits (architected) */
#define E2K_MAX_PHYS_BITS_V2	40	/* on V1-V5 */
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
	/* See comment in ioremap_cache() */
	EXT_CACHE_MT		= 8,
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
	UNI_PAGE_HW_ACCESS_BIT,		/* page hardware Accessed */
	UNI_PAGE_DIRTY_BIT,		/* page Dirty */
	UNI_PAGE_HUGE_BIT,		/* huge Page Size */
	UNI_PAGE_GLOBAL_BIT,		/* Global page */
	UNI_PAGE_NWA_BIT,		/* No Writable Address */
	UNI_PAGE_NON_EX_BIT,		/* NON EXecutable */
	UNI_PAGE_PROTNONE_BIT,		/* software PROTection NONE */
	UNI_PAGE_AVAIL_BIT,		/* software AVAILable */
	UNI_PAGE_SW_ACCESS_BIT,		/* page software Accessed */
	UNI_PAGE_SPECIAL_BIT,		/* software SPECIAL */
	UNI_PAGE_GFN_BIT,		/* software Guest page Frame Number */
	UNI_PAGE_ACCESSED_BIT,		/* page hardware/software Accessed */
	UNI_PAGE_PFN_BIT,		/* Physical Page Number field */
	UNI_PAGE_MEM_TYPE_BIT,		/* Memory Type field */
	UNI_PAGE_MEM_TYPE_RULE_BIT,	/* Memory Type Combination Rule field */
	UNI_PAGE_MEM_TYPE_MA_BIT,	/* Memory Type to memory access */
					/* DTLB field */
	UNI_PAGE_WRITE_INT_BIT,		/* Write protected physical address */
					/* DTLB field */
	UNI_PAGE_INTL_RD_BIT,		/* Intel Read protection */
					/* DTLB field */
	UNI_PAGE_INTL_WR_BIT,		/* Intel Write protection */
					/* DTLB field */
	UNI_DTLB_EP_RES_BIT,		/* DTLB entry probe result field */
					/* for successful probe completion */
	UNI_DTLB_PH_ADDR_AP_RES_BIT,	/* physical address for successful */
					/* DTLB address probe result */
	UNI_DTLB_ERROR_MASK_BIT,	/* DTLB entry probe faults mask */
					/* for unsuccessful probe completion */
	UNI_DTLB_MISS_LEVEL_BIT,	/* miss level DTLB field */
	UNI_DTLB_SUCCESSFUL_BIT,	/* seccessful translation flag */
					/* for DTLB probe operation */
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
#define	UNI_PAGE_HW_ACCESS	(uni_pteval_t)(1ULL << UNI_PAGE_HW_ACCESS_BIT)
#define	UNI_PAGE_DIRTY		(uni_pteval_t)(1ULL << UNI_PAGE_DIRTY_BIT)
#define	UNI_PAGE_HUGE		(uni_pteval_t)(1ULL << UNI_PAGE_HUGE_BIT)
#define	UNI_PAGE_GLOBAL		(uni_pteval_t)(1ULL << UNI_PAGE_GLOBAL_BIT)
#define	UNI_PAGE_NWA		(uni_pteval_t)(1ULL << UNI_PAGE_NWA_BIT)
#define	UNI_PAGE_NON_EX		(uni_pteval_t)(1ULL << UNI_PAGE_NON_EX_BIT)
#define	UNI_PAGE_PROTNONE	(uni_pteval_t)(1ULL << UNI_PAGE_PROTNONE_BIT)
#define	UNI_PAGE_AVAIL		(uni_pteval_t)(1ULL << UNI_PAGE_AVAIL_BIT)
#define	UNI_PAGE_SW_ACCESS	(uni_pteval_t)(1ULL << UNI_PAGE_SW_ACCESS_BIT)
#define	UNI_PAGE_SPECIAL	(uni_pteval_t)(1ULL << UNI_PAGE_SPECIAL_BIT)
#define	UNI_PAGE_GFN		(uni_pteval_t)(1ULL << UNI_PAGE_GFN_BIT)
#define	UNI_PAGE_ACCESSED	(uni_pteval_t)(1ULL << UNI_PAGE_ACCESSED_BIT)
#define	UNI_PAGE_PFN		(uni_pteval_t)(1ULL << UNI_PAGE_PFN_BIT)
#define	UNI_PAGE_MEM_TYPE	(uni_pteval_t)(1ULL << UNI_PAGE_MEM_TYPE_BIT)
#define	UNI_PAGE_MEM_TYPE_RULE	\
		(uni_pteval_t)(1ULL << UNI_PAGE_MEM_TYPE_RULE_BIT)
#define	UNI_PAGE_MEM_TYPE_MA	(uni_dtlb_t)(1ULL << UNI_PAGE_MEM_TYPE_MA_BIT)
#define	UNI_PAGE_WRITE_INT	(uni_dtlb_t)(1ULL << UNI_PAGE_WRITE_INT_BIT)
#define	UNI_PAGE_INTL_RD	(uni_dtlb_t)(1ULL << UNI_PAGE_INTL_RD_BIT)
#define	UNI_PAGE_INTL_WR	(uni_dtlb_t)(1ULL << UNI_PAGE_INTL_WR_BIT)
#define	UNI_DTLB_EP_RES		(uni_dtlb_t)(1ULL << UNI_DTLB_EP_RES_BIT)
#define	UNI_DTLB_PH_ADDR_AP_RES	\
		(uni_dtlb_t)(1ULL << UNI_DTLB_PH_ADDR_AP_RES_BIT)
#define	UNI_DTLB_ERROR_MASK	(uni_dtlb_t)(1ULL << UNI_DTLB_ERROR_MASK_BIT)
#define	UNI_DTLB_MISS_LEVEL	(uni_dtlb_t)(1ULL << UNI_DTLB_MISS_LEVEL_BIT)
#define	UNI_DTLB_SUCCESSFUL	(uni_dtlb_t)(1ULL << UNI_DTLB_SUCCESSFUL_BIT)
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
