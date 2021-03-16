/*
 * TDP - Two Dimensional Paging support
 * GPA -> PA page table structure and common definitions.
 *
 * Second dimension page table to translate guest physical addresses (GPA)
 * to host physical pages has same structure as native PT V6
 *
 * Copyright 2018 MCST
 */

#ifndef _ASM_E2K_KVM_PGTABLE_TDP_H
#define _ASM_E2K_KVM_PGTABLE_TDP_H

/*
 * NOTE: E2K TDP based on four levels of page tables.
 */

#include <linux/types.h>
#include <asm/pgtable-v6.h>
#include <asm/mmu_types.h>

/* max. number of physical address bits (architected) */
#define E2K_MAX_PHYS_BITS_TDP	E2K_MAX_PHYS_BITS_V6

#ifndef __ASSEMBLY__

/*
 * TDP-PTE format
 */

/* numbers of PTE's bits */
#define	_PAGE_P_BIT_TDP		_PAGE_P_BIT_V6		/* Present */
#define _PAGE_W_BIT_TDP		_PAGE_W_BIT_V6		/* Writable */
#define _PAGE_A_HW_BIT_TDP	_PAGE_A_HW_BIT_V6	/* page Accessed */
#define	_PAGE_D_BIT_TDP		_PAGE_D_BIT_V6		/* page Dirty */
#define	_PAGE_HUGE_BIT_TDP	_PAGE_HUGE_BIT_V6	/* huge Page Size */
#define	_PAGE_MTCR_SHIFT_TDP	8			/* Memory Type */
#define	_PAGE_MTCR_BITS_NUM_TDP	2			/* Combination Rule */
#define _PAGE_SW1_BIT_TDP	_PAGE_SW1_BIT_V6	/* SoftWare bit #1 */
#define _PAGE_SW2_BIT_TDP	_PAGE_SW2_BIT_V6	/* SoftWare bit #2 */
#define	_PAGE_PFN_SHIFT_TDP	_PAGE_PFN_SHIFT_V6	/* shift of Physical */
							/* Frame Number */
#define	_PAGE_MT_SHIFT_TDP	_PAGE_MT_SHIFT_V6	/* shift of Memory */
							/* Type field */
#define	_PAGE_MT_BITS_NUM_TDP	_PAGE_MT_BITS_NUM_V6	/* occupies 3 bits */
#define	_PAGE_NON_EX_BIT_TDP	_PAGE_NON_EX_BIT_V6	/* NON EXecutable */

#define _PAGE_P_TDP		(1ULL << _PAGE_P_BIT_TDP)
#define _PAGE_W_TDP		(1ULL << _PAGE_W_BIT_TDP)
#define _PAGE_A_HW_TDP		(1ULL << _PAGE_A_HW_BIT_TDP)
#define _PAGE_D_TDP		(1ULL << _PAGE_D_BIT_TDP)
#define _PAGE_HUGE_TDP		(1ULL << _PAGE_HUGE_BIT_TDP)
#define	_PAGE_MTCR_TDP		\
		(((1ULL << _PAGE_MTCR_BITS_NUM_TDP) - 1) << \
					_PAGE_MTCR_SHIFT_TDP)
#define _PAGE_SW1_TDP		(1ULL << _PAGE_SW1_BIT_TDP)
#define _PAGE_SW2_TDP		(1ULL << _PAGE_SW2_BIT_TDP)
#define _PAGE_PFN_TDP		\
		((((1ULL << E2K_MAX_PHYS_BITS_TDP) - 1) >> \
						PAGE_SHIFT) << \
							_PAGE_PFN_SHIFT_TDP)
#define	_PAGE_MT_TDP		\
		(((1ULL << _PAGE_MT_BITS_NUM_TDP) - 1) << _PAGE_MT_SHIFT_TDP)
#define _PAGE_NON_EX_TDP	(1ULL << _PAGE_NON_EX_BIT_TDP)

#define	_PAGE_MT_GET_VAL_TDP(x)		_PAGE_MT_GET_VAL(x)
#define	_PAGE_MT_SET_VAL_TDP(x, mt)	_PAGE_MT_SET_VAL(x, mt)

/* convert physical address to page frame number for PTE */
#define	_PAGE_PADDR_TO_PFN_TDP(phys_addr)	\
		_PAGE_PADDR_TO_PFN_V6(phys_addr)

/* convert the page frame number from PTE to physical address */
#define	_PAGE_PFN_TO_PADDR_TDP(pte_val)	_PAGE_PFN_TO_PADDR_V6(pte_val)

static inline pteval_t
covert_uni_pte_flags_to_pte_val_tdp(const uni_pteval_t uni_flags)
{
	pteval_t pte_flags = 0;

	if (uni_flags & UNI_PAGE_PRESENT)
		pte_flags |= (_PAGE_P_TDP);
	if (uni_flags & UNI_PAGE_WRITE)
		pte_flags |= (_PAGE_W_TDP);
	if (uni_flags & UNI_PAGE_HW_ACCESS)
		pte_flags |= (_PAGE_A_HW_TDP);
	if (uni_flags & UNI_PAGE_DIRTY)
		pte_flags |= (_PAGE_D_TDP);
	if (uni_flags & UNI_PAGE_HUGE)
		pte_flags |= (_PAGE_HUGE_TDP);
	if (uni_flags & UNI_PAGE_NON_EX)
		pte_flags |= (_PAGE_NON_EX_TDP);
	if (uni_flags & UNI_PAGE_PFN)
		pte_flags |= (_PAGE_PFN_TDP);
	if (uni_flags & UNI_PAGE_MEM_TYPE)
		pte_flags |= (_PAGE_MT_TDP);
	if (uni_flags & UNI_PAGE_MEM_TYPE_RULE)
		pte_flags |= (_PAGE_MTCR_TDP);

	BUG_ON(pte_flags == 0);

	return pte_flags;
}

static inline pteval_t
fill_pte_val_tdp_flags(const uni_pteval_t uni_flags)
{
	return covert_uni_pte_flags_to_pte_val_tdp(uni_flags);
}
static inline pteval_t
get_pte_val_tdp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & covert_uni_pte_flags_to_pte_val_tdp(uni_flags);
}
static inline bool
test_pte_val_tdp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return get_pte_val_tdp_flags(pte_val, uni_flags) != 0;
}
static inline pteval_t
set_pte_val_tdp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val | covert_uni_pte_flags_to_pte_val_tdp(uni_flags);
}
static inline pteval_t
clear_pte_val_tdp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & ~covert_uni_pte_flags_to_pte_val_tdp(uni_flags);
}

static inline unsigned int
get_pte_val_tdp_memory_type(pteval_t pte_val)
{
	return _PAGE_MT_GET_VAL_TDP(pte_val);
}
static inline pteval_t
set_pte_val_tdp_memory_type(pteval_t pte_val, unsigned int memory_type)
{
	BUG_ON(memory_type != GEN_CACHE_MT &&
		memory_type != GEN_NON_CACHE_MT &&
		memory_type != GEN_NON_CACHE_ORDERED_MT &&
		memory_type != EXT_PREFETCH_MT &&
		memory_type != EXT_NON_PREFETCH_MT &&
		memory_type != EXT_CONFIG_MT &&
		memory_type != EXT_CACHE_MT);

	return _PAGE_MT_SET_VAL_TDP(pte_val, memory_type);
}

static inline int get_tdp_root_level(void)
{
	return E2K_PT_LEVELS_NUM;
}

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _ASM_E2K_KVM_PGTABLE_TDP_H */
