/*
 * E2K ISET V6 page table structure and common definitions.
 *
 * Copyright 2017 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _ASM_E2K_PGTABLE_V6_H
#define _ASM_E2K_PGTABLE_V6_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K ISET V6 page tables.
 * NOTE: E2K has four levels of page tables.
 */

#include <linux/types.h>
#include <asm/pgtable_types.h>

#ifndef __ASSEMBLY__

/*
 * PTE-V6 format
 */

/* numbers of PTE's bits */
#define	_PAGE_P_BIT_V6		0	/* Present */
#define _PAGE_W_BIT_V6		1	/* Writable */
#define	_PAGE_PV_BIT_V6		2	/* PriVileged */
#define	_PAGE_VALID_BIT_V6	3	/* Valid */
#define	_PAGE_INT_PR_BIT_V6	4	/* PRotected */
#define _PAGE_A_HW_BIT_V6	5	/* page Accessed */
#define	_PAGE_D_BIT_V6		6	/* page Dirty */
#define	_PAGE_HUGE_BIT_V6	7	/* huge Page Size */
#define	_PAGE_G_BIT_V6		8	/* Global page */
#define	_PAGE_NWA_BIT_V6	9	/* No Writable Address */
#define _PAGE_SW1_BIT_V6	10	/* SoftWare bit #1 */
#define _PAGE_SW2_BIT_V6	11	/* SoftWare bit #2 */
#define	_PAGE_PFN_SHIFT_V6	12	/* shift of Physical Page Number */
#define	_PAGE_MT_SHIFT_V6	60	/* shift of Memory Type field */
#define	_PAGE_MT_BITS_NUM_V6	 3	/* occupies 3 bits */
#define	_PAGE_NON_EX_BIT_V6	63	/* NON EXecutable */

#define _PAGE_P_V6		(1ULL << _PAGE_P_BIT_V6)
#define _PAGE_W_V6		(1ULL << _PAGE_W_BIT_V6)
#define _PAGE_PV_V6		(1ULL << _PAGE_PV_BIT_V6)
#define _PAGE_VALID_V6		(1ULL << _PAGE_VALID_BIT_V6)
#define _PAGE_INT_PR_V6		(1ULL << _PAGE_INT_PR_BIT_V6)
#define _PAGE_A_HW_V6		(1ULL << _PAGE_A_HW_BIT_V6)
#define _PAGE_D_V6		(1ULL << _PAGE_D_BIT_V6)
#define _PAGE_HUGE_V6		(1ULL << _PAGE_HUGE_BIT_V6)
#define _PAGE_G_V6		(1ULL << _PAGE_G_BIT_V6)
#define _PAGE_NWA_V6		(1ULL << _PAGE_NWA_BIT_V6)
#define _PAGE_SW1_V6		(1ULL << _PAGE_SW1_BIT_V6)
#define _PAGE_SW2_V6		(1ULL << _PAGE_SW2_BIT_V6)
#define	_PAGE_MMIO_SW_V6	0x0c00000000000000ULL	/* pte is MMIO */
							/* software flag */
#define _PAGE_PFN_V6		\
		((((1ULL << E2K_MAX_PHYS_BITS_V6) - 1) >> \
						PAGE_SHIFT) << \
							_PAGE_PFN_SHIFT_V6)
#define	_PAGE_MT_V6		\
		(((1ULL << _PAGE_MT_BITS_NUM_V6) - 1) << _PAGE_MT_SHIFT_V6)
#define _PAGE_NON_EX_V6		(1ULL << _PAGE_NON_EX_BIT_V6)

/*
 * The _PAGE_PROTNONE bit is set only when the _PAGE_PRESENT bit
 * is cleared, so we can use almost any bits for it. Must make
 * sure though that pte_modify() will work with _PAGE_PROTNONE.
 */
#define _PAGE_PROTNONE_V6	_PAGE_NWA_V6
#define _PAGE_SOFTWARE_MT	_PAGE_SW1_V6
#define _PAGE_AVAIL_V6		_PAGE_SW2_V6
#define	_PAGE_SPECIAL_V6	_PAGE_SW2_V6
#define	_PAGE_GFN_V6		_PAGE_SW2_V6	/* Page is mapped to guest */
						/* physical memory */

/*
 * Bug #76626 - hardware access bit should always be set.
 * This bug is actual for e2c/e2c+ only CPUs,
 * so CPUs based on iset v6 cannot have the bug all the more
 * and software bit can be identical to hardware one.
 * Software bit is not used in the case of V6, but is not deleted
 * for compatibility.
 */
#define _PAGE_A_SW_BIT_V6	_PAGE_A_HW_BIT_V6
#define _PAGE_A_BIT_V6		_PAGE_A_HW_BIT_V6
#define	_PAGE_A_SW_V6		_PAGE_A_HW_V6
#define _PAGE_A_V6		_PAGE_A_HW_V6

#define	_PAGE_MT_GET_VAL(x)	(((x) & _PAGE_MT_V6) >> _PAGE_MT_SHIFT_V6)
#define	_PAGE_MT_SET_VAL(x, mt)	\
		(((x) & ~_PAGE_MT_V6) | \
			(((pteval_t)(mt) << _PAGE_MT_SHIFT_V6) & _PAGE_MT_V6))

/* some useful PT entries protection basis values */
#define _PAGE_KERNEL_RX_NOT_GLOB_V6	\
		(_PAGE_P_V6 | _PAGE_VALID_V6 | \
				 _PAGE_PV_V6 | _PAGE_A_HW_V6)
#define _PAGE_KERNEL_RO_NOT_GLOB_V6	\
		(_PAGE_KERNEL_RX_NOT_GLOB_V6 | _PAGE_NON_EX_V6)
#define _PAGE_KERNEL_RWX_NOT_GLOB_V6	\
		(_PAGE_KERNEL_RX_NOT_GLOB_V6 | \
				_PAGE_W_V6 | _PAGE_D_V6)
#define _PAGE_KERNEL_RW_NOT_GLOB_V6	\
		(_PAGE_KERNEL_RWX_NOT_GLOB_V6 | _PAGE_NON_EX_V6)
#define _PAGE_KERNEL_HUGE_RW_NOT_GLOB_V6	\
		(_PAGE_KERNEL_RW_NOT_GLOB_V6 | _PAGE_HUGE_V6)
#define _PAGE_KERNEL_RX_GLOB_V6		\
		(_PAGE_KERNEL_RX_NOT_GLOB_V6 | _PAGE_G_V6)
#define _PAGE_KERNEL_RO_GLOB_V6		\
		(_PAGE_KERNEL_RO_NOT_GLOB_V6 | _PAGE_G_V6)
#define _PAGE_KERNEL_RWX_GLOB_V6	\
		(_PAGE_KERNEL_RWX_NOT_GLOB_V6 | _PAGE_G_V6)
#define _PAGE_KERNEL_RW_GLOB_V6		\
		(_PAGE_KERNEL_RW_NOT_GLOB_V6 | _PAGE_G_V6)
#define _PAGE_KERNEL_HUGE_RW_GLOB_V6	\
		(_PAGE_KERNEL_HUGE_RW_NOT_GLOB_V6 | _PAGE_G_V6)
#ifdef	CONFIG_GLOBAL_CONTEXT
#define _PAGE_KERNEL_RX_V6	_PAGE_KERNEL_RX_GLOB_V6
#define _PAGE_KERNEL_RO_V6	_PAGE_KERNEL_RO_GLOB_V6
#define _PAGE_KERNEL_RWX_V6	_PAGE_KERNEL_RWX_GLOB_V6
#define _PAGE_KERNEL_RW_V6	_PAGE_KERNEL_RW_GLOB_V6
#define _PAGE_KERNEL_HUGE_RW_V6	_PAGE_KERNEL_HUGE_RW_GLOB_V6
#else	/* ! CONFIG_GLOBAL_CONTEXT */
#define _PAGE_KERNEL_RX_V6	_PAGE_KERNEL_RX_NOT_GLOB_V6
#define _PAGE_KERNEL_RO_V6	_PAGE_KERNEL_RO_NOT_GLOB_V6
#define _PAGE_KERNEL_RWX_V6	_PAGE_KERNEL_RWX_NOT_GLOB_V6
#define _PAGE_KERNEL_RW_V6	_PAGE_KERNEL_RW_NOT_GLOB_V6
#define _PAGE_KERNEL_HUGE_RW_V6	_PAGE_KERNEL_HUGE_RW_NOT_GLOB_V6
#endif	/* CONFIG_GLOBAL_CONTEXT */
#define _PAGE_KERNEL_V6		_PAGE_KERNEL_RW_V6
#define _PAGE_KERNEL_HUGE_V6	_PAGE_KERNEL_HUGE_RW_V6
#define _PAGE_KERNEL_IMAGE_V6	_PAGE_KERNEL_RX_V6
#define _PAGE_KERNEL_MODULE_V6	_PAGE_KERNEL_RWX_V6
#define _PAGE_KERNEL_PT_V6	_PAGE_KERNEL_V6
#define _PAGE_USER_PT_V6	_PAGE_KERNEL_RW_NOT_GLOB_V6

/* convert physical address to page frame number for PTE */
#define	_PAGE_PADDR_TO_PFN_V6(phys_addr)	\
		(((e2k_addr_t)phys_addr) & _PAGE_PFN_V6)

/* convert the page frame number from PTE to physical address */
#define	_PAGE_PFN_TO_PADDR_V6(pte_val)	\
		((e2k_addr_t)(pte_val) & _PAGE_PFN_V6)

/* get/set pte Compilation Unit Index field */
/* PTE V6 has not more field CUI, so fix error */
#define	_PAGE_INDEX_TO_CUNIT_V6(index)	BUILD_BUG_ON(true)
#define	_PAGE_INDEX_FROM_CUNIT_V6(prot)	BUILD_BUG_ON(true)
#define	SET_PAGE_CUI_V6(pte_val, cui)	BUILD_BUG_ON(true)

/* PTE flags mask to can update/reduce and restricted to update */
#define _PAGE_CHG_MASK_V6	(_PAGE_PFN_V6 | _PAGE_A_V6 | _PAGE_D_V6 | \
				_PAGE_SW1_V6 | _PAGE_SW2_V6 | \
				_PAGE_MT_V6)
#define _HPAGE_CHG_MASK_V6	(_PAGE_CHG_MASK_V6 | _PAGE_HUGE_V6)
#define _PROT_REDUCE_MASK_V6	(_PAGE_P_V6 | _PAGE_W_V6 | _PAGE_A_V6 | \
				_PAGE_D_V6 | _PAGE_VALID_V6 | _PAGE_G_V6 | \
				_PAGE_MT_V6)
#define _PROT_RESTRICT_MASK_V6	(_PAGE_PV_V6 | _PAGE_NON_EX_V6 | \
				_PAGE_INT_PR_V6)
static inline pteval_t
get_pte_val_v6_changeable_mask(void)
{
	return _PAGE_CHG_MASK_V6;
}
static inline pteval_t
get_huge_pte_val_v6_changeable_mask(void)
{
	return _HPAGE_CHG_MASK_V6;
}
static inline pteval_t
get_pte_val_v6_reduceable_mask(void)
{
	return _PROT_REDUCE_MASK_V6;
}
static inline pteval_t
get_pte_val_v6_restricted_mask(void)
{
	return _PROT_RESTRICT_MASK_V6;
}

static inline pteval_t
covert_uni_pte_flags_to_pte_val_v6(const uni_pteval_t uni_flags)
{
	pteval_t pte_flags = 0;

	if (uni_flags & UNI_PAGE_PRESENT)
		pte_flags |= (_PAGE_P_V6);
	if (uni_flags & UNI_PAGE_WRITE)
		pte_flags |= (_PAGE_W_V6);
	if (uni_flags & UNI_PAGE_PRIV)
		pte_flags |= (_PAGE_PV_V6);
	if (uni_flags & UNI_PAGE_VALID)
		pte_flags |= (_PAGE_VALID_V6);
	if (uni_flags & UNI_PAGE_PROTECT)
		pte_flags |= (_PAGE_INT_PR_V6);
	if (uni_flags & UNI_PAGE_HW_ACCESS)
		pte_flags |= (_PAGE_A_HW_V6);
	if (uni_flags & UNI_PAGE_DIRTY)
		pte_flags |= (_PAGE_D_V6);
	if (uni_flags & UNI_PAGE_HUGE)
		pte_flags |= (_PAGE_HUGE_V6);
	if (uni_flags & UNI_PAGE_GLOBAL)
		pte_flags |= (_PAGE_G_V6);
	if (uni_flags & UNI_PAGE_NWA)
		pte_flags |= (_PAGE_NWA_V6);
	if (uni_flags & UNI_PAGE_NON_EX)
		pte_flags |= (_PAGE_NON_EX_V6);
	if (uni_flags & UNI_PAGE_PROTNONE)
		pte_flags |= (_PAGE_PROTNONE_V6);
	if (uni_flags & UNI_PAGE_AVAIL)
		pte_flags |= (_PAGE_SW2_V6);
	if (uni_flags & UNI_PAGE_SW_ACCESS)
		pte_flags |= (_PAGE_A_SW_V6);
	if (uni_flags & UNI_PAGE_SPECIAL)
		pte_flags |= (_PAGE_SPECIAL_V6);
	if (uni_flags & UNI_PAGE_GFN)
		pte_flags |= (_PAGE_GFN_V6);
	if (uni_flags & UNI_PAGE_ACCESSED)
		pte_flags |= (_PAGE_A_V6);
	if (uni_flags & UNI_PAGE_PFN)
		pte_flags |= (_PAGE_PFN_V6);
	if (uni_flags & UNI_PAGE_MEM_TYPE)
		pte_flags |= (_PAGE_MT_V6);

	BUG_ON(pte_flags == 0);

	return pte_flags;
}

static inline pteval_t
fill_pte_val_v6_flags(const uni_pteval_t uni_flags)
{
	return covert_uni_pte_flags_to_pte_val_v6(uni_flags);
}
static inline pteval_t
get_pte_val_v6_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & covert_uni_pte_flags_to_pte_val_v6(uni_flags);
}
static inline bool
test_pte_val_v6_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return get_pte_val_v6_flags(pte_val, uni_flags) != 0;
}
static inline pteval_t
set_pte_val_v6_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val | covert_uni_pte_flags_to_pte_val_v6(uni_flags);
}
static inline pteval_t
clear_pte_val_v6_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & ~covert_uni_pte_flags_to_pte_val_v6(uni_flags);
}

static inline pteval_t
convert_kernel_text_pte_val_v6_to_protected(pteval_t kernel_text_pte_val)
{
	return kernel_text_pte_val;
}

static inline pte_mem_type_t get_pte_val_v6_memory_type(pteval_t pte_val)
{
	int hardware_mt = _PAGE_MT_GET_VAL(pte_val);

	if (!(pte_val & _PAGE_SOFTWARE_MT))
		return hardware_mt;

	if (hardware_mt == GEN_CACHE_MT) {
		return EXT_CACHE_MT;
	} else if (hardware_mt == GEN_NON_CACHE_MT) {
		return GEN_NON_CACHE_ORDERED_MT;
	} else {
		WARN_ON_ONCE(1);
		return EXT_CACHE_MT;
	}
}

static inline pteval_t
set_pte_val_v6_memory_type(pteval_t pte_val, pte_mem_type_t memory_type)
{
	BUG_ON(memory_type != GEN_CACHE_MT &&
		memory_type != GEN_NON_CACHE_MT &&
		memory_type != GEN_NON_CACHE_ORDERED_MT &&
		memory_type != EXT_PREFETCH_MT &&
		memory_type != EXT_NON_PREFETCH_MT &&
		memory_type != EXT_CONFIG_MT &&
		memory_type != EXT_CACHE_MT);

	if (memory_type == EXT_CACHE_MT) {
		pte_val |= _PAGE_SOFTWARE_MT;
		memory_type = GEN_CACHE_MT;
	} else if (memory_type == GEN_NON_CACHE_ORDERED_MT) {
		pte_val |= _PAGE_SOFTWARE_MT;
		memory_type = GEN_NON_CACHE_MT;
	} else {
		pte_val &= ~_PAGE_SOFTWARE_MT;
	}
	return _PAGE_MT_SET_VAL(pte_val, memory_type);
}

/*
 * Encode and de-code a swap entry
 *
 * Format of swap offset:
 *	bits 20-63: swap offset
 */
static inline unsigned long
get_swap_offset_v6(swp_entry_t swap_entry)
{
	return swap_entry.val >> __SWP_OFFSET_SHIFT;
}
static inline swp_entry_t
create_swap_entry_v6(unsigned long type, unsigned long offset)
{
	swp_entry_t swap_entry;

	swap_entry.val = type << __SWP_TYPE_SHIFT;
	swap_entry.val |= (offset << __SWP_OFFSET_SHIFT);

	return swap_entry;
}
static inline pte_t
convert_swap_entry_to_pte_v6(swp_entry_t swap_entry)
{
	pte_t pte;

	pte_val(pte) = swap_entry.val;
#ifdef	CONFIG_MAKE_ALL_PAGES_VALID
	pte_val(pte) |= _PAGE_VALID_V6;
#endif	/* CONFIG_MAKE_ALL_PAGES_VALID */
	return pte;
}

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _ASM_E2K_PGTABLE_V6_H */
