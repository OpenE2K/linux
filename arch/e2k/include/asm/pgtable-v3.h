/*
 * E2K ISET V3-V5 page table structure and common definitions.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _ASM_E2K_PGTABLE_V3_H
#define _ASM_E2K_PGTABLE_V3_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K ISET V3-V5 page tables.
 * NOTE: E2K has four levels of page tables.
 */

#include <linux/types.h>
#include <asm/pgtable_types.h>

#define E2K_MAX_PHYS_BITS_V3	40	/* max. number of physical address */
					/* bits (architected) */

#ifndef __ASSEMBLY__

/*
 * PTE format
 */

#define _PAGE_W_BIT_V3		1		/* bit # of Writable */
#define	_PAGE_CD1_BIT_V3	4		/* right bit of Cache disable */
#define	_PAGE_CD2_BIT_V3	9		/* left bit of Cache disable */
#define _PAGE_A_BIT_V3		5		/* bit # of Accessed Page */
#define	_PAGE_D_BIT_V3		6		/* bit # of Page Dirty */
#define	_PAGE_HUGE_BIT_V3	7		/* bit # of Page Size */
#define _PAGE_AVAIL_BIT_V3	11		/* prog bit Page Available */
#define	_PAGE_PFN_SHIFT_V3	12		/* shift of PFN field */
#define _PAGE_SW2_BIT_V3	47		/* SoftWare bit #2 */
#define	_PAGE_CU_BITS_V3	48		/* bits # of Compilation Unit */

#define _PAGE_P_V3	0x0000000000000001ULL	/* Page Present bit */
#define _PAGE_W_V3	0x0000000000000002ULL	/* Writable (0 - only read) */
#define _PAGE_UU2_V3	0x0000000000000004ULL	/* unused bit # 2 */
#define _PAGE_PWT_V3	0x0000000000000008ULL	/* Write Through */
#define _PAGE_CD1_V3	(1UL << _PAGE_CD1_BIT_V3) /* 0x0000000000000010 */
						/* Cache disable (right bit) */
#define _PAGE_A_V3	(1UL << _PAGE_A_BIT_V3) /* Accessed Page */
#define _PAGE_D_V3	(1UL << _PAGE_D_BIT_V3)	/* Page Dirty */
#define _PAGE_HUGE_V3	0x0000000000000080ULL	/* Page Size */
#define _PAGE_G_V3	0x0000000000000100ULL	/* Global Page */
#define _PAGE_CD2_V3	(1UL << _PAGE_CD2_BIT_V3) /* 0x0000000000000200 */
						/* Cache disable (left bit) */
#define _PAGE_NWA_V3	0x0000000000000400ULL	/* Prohibit address writing */
/*
 * The _PAGE_PROTNONE bit is set only when the _PAGE_PRESENT bit
 * is cleared, so we can use almost any bits for it. Must make
 * sure though that pte_modify() will work with _PAGE_PROTNONE.
 */
#define _PAGE_PROTNONE_V3 _PAGE_NWA_V3
#define _PAGE_AVAIL_V3	(1UL << _PAGE_AVAIL_BIT_V3)
#define	_PAGE_SPECIAL_V3 _PAGE_AVAIL_V3
#define	_PAGE_GFN_V3	_PAGE_AVAIL_V3		/* Page is mapped to guest */
						/* physical memory */
#define _PAGE_PFN_V3	0x000000fffffff000ULL	/* Physical Page Number */
#define _PAGE_VALID_V3	0x0000010000000000ULL	/* Valid Page */
#define _PAGE_PV_V3	0x0000020000000000ULL	/* PriVileged Page */
#define _PAGE_INT_PR_V3	0x0000040000000000ULL	/* Integer address access */
						/* Protection */
#define _PAGE_NON_EX_V3	0x0000080000000000ULL	/* Non Executable Page */
#define _PAGE_RES_V3	0x0000f00000000000ULL	/* Reserved bits */
#define	_PAGE_RES_44_V3	0x0000100000000000ULL	/* SG bit was previously */
#define	_PAGE_SEC_MAP_V3 0x0000200000000000ULL	/* Secondary space mapping */
						/* Software only bit */
#define	_PAGE_INTL_PR_V3 0x0000400000000000ULL	/* used as Intel PR in TLB */
						/* should be 1 for Elbrus */
#define	_PAGE_INTL_WP_V3 0x0000800000000000ULL	/* used as Intel WR in TLB */
						/* should be 0 for Elbrus */
#define _PAGE_C_UNIT_V3	0xffff000000000000ULL	/* Compilation Unit */
#define	_PAGE_MMIO_SW_V3 0x0c00000000000000ULL	/* pte is MMIO software flag */
#define _PAGE_SW2_V3	(1ULL << _PAGE_SW2_BIT_V3)

/* Cache disable flags */
#define _PAGE_CD_MASK_V3	(_PAGE_CD1_V3 | _PAGE_CD2_V3)
#define	_PAGE_CD_VAL_V3(x)	((x & 0x1ULL) << _PAGE_CD1_BIT_V3 | \
				 (x & 0x2ULL) << (_PAGE_CD2_BIT_V3 - 1))
#define _PAGE_CD_EN_V3		_PAGE_CD_VAL_V3(0UL)	/* all caches enabled */
#define _PAGE_CD_D1_DIS_V3 	_PAGE_CD_VAL_V3(1UL)	/* DCACHE1 disabled */
#define _PAGE_CD_D_DIS_V3 	_PAGE_CD_VAL_V3(2UL)	/* DCACHE1, DCACHE2 disabled */
#define _PAGE_CD_DIS_V3		_PAGE_CD_VAL_V3(3UL)	/* DCACHE1, DCACHE2, ECACHE */
						/* disabled */
#define	_PAGE_PWT_DIS_V3	0UL		/* Page Write Through */
						/* disabled */
#define	_PAGE_PWT_EN_V3		_PAGE_PWT_V3	/* Page Write Through */
						/* enabled */

/* some useful PT entries protection basis values */
#define _PAGE_KERNEL_RX_NOT_GLOB_V3	\
		(_PAGE_P_V3| _PAGE_VALID_V3 | \
				_PAGE_PV_V3 | _PAGE_A_V3)
#define _PAGE_KERNEL_RO_NOT_GLOB_V3	\
		(_PAGE_KERNEL_RX_NOT_GLOB_V3 | _PAGE_NON_EX_V3)
#define _PAGE_KERNEL_RWX_NOT_GLOB_V3	\
		(_PAGE_KERNEL_RX_NOT_GLOB_V3 | \
				_PAGE_W_V3 | _PAGE_D_V3)
#define _PAGE_KERNEL_RW_NOT_GLOB_V3	\
		(_PAGE_KERNEL_RWX_NOT_GLOB_V3 | _PAGE_NON_EX_V3)
#define _PAGE_KERNEL_HUGE_RW_NOT_GLOB_V3	\
		(_PAGE_KERNEL_RW_NOT_GLOB_V3 | _PAGE_HUGE_V3)
#define _PAGE_KERNEL_RX_GLOB_V3		\
		(_PAGE_KERNEL_RX_NOT_GLOB_V3 | _PAGE_G_V3)
#define _PAGE_KERNEL_RO_GLOB_V3		\
		(_PAGE_KERNEL_RO_NOT_GLOB_V3 | _PAGE_G_V3)
#define _PAGE_KERNEL_RWX_GLOB_V3	\
		(_PAGE_KERNEL_RWX_NOT_GLOB_V3 | _PAGE_G_V3)
#define _PAGE_KERNEL_RW_GLOB_V3		\
		(_PAGE_KERNEL_RW_NOT_GLOB_V3 | _PAGE_G_V3)
#define _PAGE_KERNEL_HUGE_RW_GLOB_V3	\
		(_PAGE_KERNEL_HUGE_RW_NOT_GLOB_V3 | _PAGE_G_V3)
#ifdef	CONFIG_GLOBAL_CONTEXT
#define _PAGE_KERNEL_RX_V3	_PAGE_KERNEL_RX_GLOB_V3
#define _PAGE_KERNEL_RO_V3	_PAGE_KERNEL_RO_GLOB_V3
#define _PAGE_KERNEL_RWX_V3	_PAGE_KERNEL_RWX_GLOB_V3
#define _PAGE_KERNEL_RW_V3	_PAGE_KERNEL_RW_GLOB_V3
#define _PAGE_KERNEL_HUGE_RW_V3	_PAGE_KERNEL_HUGE_RW_GLOB_V3
#else	/* ! CONFIG_GLOBAL_CONTEXT */
#define _PAGE_KERNEL_RX_V3	_PAGE_KERNEL_RX_NOT_GLOB_V3
#define _PAGE_KERNEL_RO_V3	_PAGE_KERNEL_RO_NOT_GLOB_V3
#define _PAGE_KERNEL_RWX_V3	_PAGE_KERNEL_RWX_NOT_GLOB_V3
#define _PAGE_KERNEL_RW_V3	_PAGE_KERNEL_RW_NOT_GLOB_V3
#define _PAGE_KERNEL_HUGE_RW_V3	_PAGE_KERNEL_HUGE_RW_NOT_GLOB_V3
#endif	/* CONFIG_GLOBAL_CONTEXT */
#define _PAGE_KERNEL_V3		_PAGE_KERNEL_RW_V3
#define _PAGE_KERNEL_HUGE_V3	_PAGE_KERNEL_HUGE_RW_V3
#define _PAGE_KERNEL_IMAGE_V3	_PAGE_KERNEL_RX_V3
#define _PAGE_KERNEL_MODULE_V3	_PAGE_KERNEL_RWX_V3
#define _PAGE_USER_PT_V3	_PAGE_KERNEL_RW_NOT_GLOB_V3
/* See comment before _PAGE_KERNEL_PT */
#define _PAGE_KERNEL_PT_V3	_PAGE_KERNEL_RW_NOT_GLOB_V3

/* convert physical address to page frame number for PTE */
#define	_PAGE_PADDR_TO_PFN_V3(phys_addr)	\
		(((e2k_addr_t)phys_addr) & _PAGE_PFN_V3)

/* convert the page frame number from PTE to physical address */
#define	_PAGE_PFN_TO_PADDR_V3(pte_val)	\
		(((e2k_addr_t)(pte_val) & _PAGE_PFN_V3))

/* get/set pte Compilation Unit Index field */
#define	_PAGE_INDEX_TO_CUNIT_V3(index)	\
		(((pteval_t)(index) << _PAGE_CU_BITS_V3) & _PAGE_C_UNIT_V3)
#define	_PAGE_INDEX_FROM_CUNIT_V3(prot)	\
		(((prot) & _PAGE_C_UNIT_V3) >> _PAGE_CU_BITS_V3)
#define	SET_PAGE_CUI_V3(pte_val, cui)	\
		(((pte_val) & ~_PAGE_C_UNIT_V3) | _PAGE_INDEX_TO_CUNIT_V3(cui))

/* PTE flags mask to can update/reduce and restricted to update */
#define _PAGE_CHG_MASK_V3	(_PAGE_PFN_V3 |  _PAGE_A_V3 | _PAGE_D_V3 | \
				_PAGE_SPECIAL_V3 | _PAGE_CD1_V3 | \
				_PAGE_CD2_V3 | _PAGE_PWT_V3)
#define _HPAGE_CHG_MASK_V3	(_PAGE_CHG_MASK_V3 | _PAGE_HUGE_V3)
#define _PROT_REDUCE_MASK_V3	(_PAGE_P_V3 | _PAGE_W_V3 | _PAGE_A_V3 | \
				 _PAGE_D_V3 | _PAGE_VALID_V3 | \
				_PAGE_G_V3 | \
				_PAGE_CD_MASK_V3 | _PAGE_PWT_V3)
#define _PROT_RESTRICT_MASK_V3	(_PAGE_PV_V3 | _PAGE_NON_EX_V3 | \
				_PAGE_INT_PR_V3)
static inline pteval_t
get_pte_val_v3_changeable_mask(void)
{
	return _PAGE_CHG_MASK_V3;
}
static inline pteval_t
get_huge_pte_val_v3_changeable_mask(void)
{
	return _HPAGE_CHG_MASK_V3;
}
static inline pteval_t
get_pte_val_v3_reduceable_mask(void)
{
	return _PROT_REDUCE_MASK_V3;
}
static inline pteval_t
get_pte_val_v3_restricted_mask(void)
{
	return _PROT_RESTRICT_MASK_V3;
}

static inline pteval_t
covert_uni_pte_flags_to_pte_val_v3(const uni_pteval_t uni_flags)
{
	pteval_t pte_flags = 0;

	if (uni_flags & UNI_PAGE_PRESENT)
		pte_flags |= (_PAGE_P_V3);
	if (uni_flags & UNI_PAGE_WRITE)
		pte_flags |= (_PAGE_W_V3);
	if (uni_flags & UNI_PAGE_PRIV)
		pte_flags |= (_PAGE_PV_V3);
	if (uni_flags & UNI_PAGE_VALID)
		pte_flags |= (_PAGE_VALID_V3);
	if (uni_flags & UNI_PAGE_PROTECT)
		pte_flags |= (_PAGE_INT_PR_V3);
	if (uni_flags & UNI_PAGE_ACCESSED)
		pte_flags |= (_PAGE_A_V3);
	if (uni_flags & UNI_PAGE_DIRTY)
		pte_flags |= (_PAGE_D_V3);
	if (uni_flags & UNI_PAGE_HUGE)
		pte_flags |= (_PAGE_HUGE_V3);
	if (uni_flags & UNI_PAGE_GLOBAL)
		pte_flags |= (_PAGE_G_V3);
	if (uni_flags & UNI_PAGE_NWA)
		pte_flags |= (_PAGE_NWA_V3);
	if (uni_flags & UNI_PAGE_NON_EX)
		pte_flags |= (_PAGE_NON_EX_V3);
	if (uni_flags & UNI_PAGE_PROTNONE)
		pte_flags |= (_PAGE_PROTNONE_V3);
	if (uni_flags & UNI_PAGE_AVAIL)
		pte_flags |= (_PAGE_AVAIL_V3);
	if (uni_flags & UNI_PAGE_SPECIAL)
		pte_flags |= (_PAGE_SPECIAL_V3);
	if (uni_flags & UNI_PAGE_GFN)
		pte_flags |= (_PAGE_GFN_V3);
	if (uni_flags & UNI_PAGE_PFN)
		pte_flags |= (_PAGE_PFN_V3);
	if (uni_flags & UNI_PAGE_MEM_TYPE)
		pte_flags |= (_PAGE_CD_MASK_V3 | _PAGE_PWT_V3);

	BUG_ON(pte_flags == 0);

	return pte_flags;
}

static inline pteval_t
fill_pte_val_v3_flags(const uni_pteval_t uni_flags)
{
	return covert_uni_pte_flags_to_pte_val_v3(uni_flags);
}
static inline pteval_t
get_pte_val_v3_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & covert_uni_pte_flags_to_pte_val_v3(uni_flags);
}
static inline bool
test_pte_val_v3_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return get_pte_val_v3_flags(pte_val, uni_flags) != 0;
}
static inline pteval_t
set_pte_val_v3_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val | covert_uni_pte_flags_to_pte_val_v3(uni_flags);
}
static inline pteval_t
clear_pte_val_v3_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & ~covert_uni_pte_flags_to_pte_val_v3(uni_flags);
}

static inline pteval_t
convert_kernel_text_pte_val_v3_to_protected(pteval_t kernel_text_pte_val,
						e2k_addr_t cui)
{
	return SET_PAGE_CUI_V3(kernel_text_pte_val, cui);
}
static inline pte_mem_type_t get_pte_val_v3_memory_type(pteval_t pte_val)
{
	pteval_t caches_mask;

	caches_mask = pte_val & (_PAGE_CD_MASK_V3 | _PAGE_PWT_V3);

	/* convert old PTE style fields to new PTE memory type
	 * see iset 8.2.4. 2)
	 *
	 * Use the same default values as what was used in older
	 * kernels in pgprot_noncached()/pgprot_writecombine(). */
	if (caches_mask & _PAGE_PWT_V3)
		return EXT_CONFIG_MT;
	else if (caches_mask & _PAGE_CD_MASK_V3)
		return GEN_NON_CACHE_MT;
	else
		return GEN_CACHE_MT;
}

static inline pteval_t
set_pte_val_v3_memory_type(pteval_t pte_val, pte_mem_type_t memory_type)
{
	pteval_t caches_mask;

	/* convert new PTE style memory type to old PTE caches mask */
	/* see iset 8.2.4. 2) */
	if (memory_type == GEN_CACHE_MT)
		caches_mask = _PAGE_CD_EN_V3 | _PAGE_PWT_DIS_V3;
	else if (memory_type == GEN_NON_CACHE_MT || memory_type == EXT_PREFETCH_MT)
		caches_mask = _PAGE_CD_DIS_V3 | _PAGE_PWT_DIS_V3;
	else if (memory_type == EXT_NON_PREFETCH_MT || memory_type == EXT_CONFIG_MT ||
			memory_type == GEN_NON_CACHE_ORDERED_MT)
		caches_mask = _PAGE_CD_DIS_V3 | _PAGE_PWT_EN_V3;
	else
		BUG();
	pte_val &= ~(_PAGE_CD_MASK_V3 | _PAGE_PWT_V3);
	pte_val |= caches_mask;
	return pte_val;
}

/*
 * Encode and de-code a swap entry
 *
 * Format of swap offset:
 *	if ! (CONFIG_MAKE_ALL_PAGES_VALID):
 *		bits 20-63: swap offset
 *	else if (CONFIG_MAKE_ALL_PAGES_VALID)
 *		bits 20-39: low part of swap offset
 *		bit  40   : _PAGE_VALID (must be one)
 *		bits 41-63: hi part of swap offset
 */
#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
static inline unsigned long
get_swap_offset_v3(swp_entry_t swap_entry)
{
	return swap_entry.val >> __SWP_OFFSET_SHIFT;
}
static inline swp_entry_t
create_swap_entry_v3(unsigned long type, unsigned long offset)
{
	swp_entry_t swap_entry;

	swap_entry.val = type << __SWP_TYPE_SHIFT;
	swap_entry.val |= (offset << __SWP_OFFSET_SHIFT);

	return swap_entry;
}
static inline pte_t
convert_swap_entry_to_pte_v3(swp_entry_t swap_entry)
{
	pte_t pte;

	pte_val(pte) = swap_entry.val;
	return pte;
}
#else	/* CONFIG_MAKE_ALL_PAGES_VALID */
# define INSERT_VALID(off)	(((off) & (_PAGE_VALID_V3 - 1UL)) | \
				(((off) & ~(_PAGE_VALID_V3 - 1UL)) << 1))
# define REMOVE_VALID(off)	(((off) & (_PAGE_VALID_V3 - 1UL)) | \
				(((off >> 1) & ~(_PAGE_VALID_V3 - 1UL))))
static inline unsigned long
insert_valid_bit_to_offset(unsigned long offset)
{
	return (offset & (_PAGE_VALID_V3 - 1UL)) |
			((offset & ~(_PAGE_VALID_V3 - 1UL)) << 1);
}
static inline unsigned long
remove_valid_bit_from_entry(swp_entry_t swap_entry)
{
	unsigned long entry = swap_entry.val;

	return (entry & (_PAGE_VALID_V3 - 1UL)) |
			((entry >> 1) & ~(_PAGE_VALID_V3 - 1UL));
}
# define __swp_offset_v3(entry)	(REMOVE_VALID((entry).val) >> \
						__SWP_OFFSET_SHIFT)
# define __swp_entry_v3(type, off)	((swp_entry_t) { \
				 (((type) << __SWP_TYPE_SHIFT) | \
				 INSERT_VALID(((off) << __SWP_OFFSET_SHIFT))) })
# define __swp_entry_to_pte_v3(entry) ((pte_t) { (entry).val | _PAGE_VALID })
static inline unsigned long
get_swap_offset_v3(swp_entry_t swap_entry)
{
	unsigned long entry = remove_valid_bit_from_entry(swap_entry);

	return entry >> __SWP_OFFSET_SHIFT;
}
static inline swp_entry_t
create_swap_entry_v3(unsigned long type, unsigned long offset)
{
	swp_entry_t swap_entry;

	swap_entry.val = type << __SWP_TYPE_SHIFT;
	swap_entry.val |=
		insert_valid_bit_to_offset(offset << __SWP_OFFSET_SHIFT);

	return swap_entry;
}
static inline pte_t
convert_swap_entry_to_pte_v3(swp_entry_t swap_entry)
{
	pte_t pte;

	pte_val(pte) = swap_entry.val | _PAGE_VALID_V3;
	return pte;
}
#endif	/* ! CONFIG_MAKE_ALL_PAGES_VALID */

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _ASM_E2K_PGTABLE_V3_H */
