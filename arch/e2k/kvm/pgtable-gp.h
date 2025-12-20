/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K guest physical page table structure and common definitions.
 * GP_* page tables are used to translate guest physical addresses and
 * as second level of TDP (Two Dimensional Paging) translations
 */

#ifndef _E2K_KVM_PGTABLE_GP_H
#define _E2K_KVM_PGTABLE_GP_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K ISET V6 guest physical page tables.
 * NOTE: E2K FP tables have four levels of page tables.
 */

#include <linux/types.h>
#include <asm/pgtable_types.h>

#ifndef __ASSEMBLY__

/*
 * PTE-GP format
 */

#define	E2K_MAX_PHYS_BITS_GP	E2K_MAX_PHYS_BITS_V6

/* numbers of PTE's bits */
#define	_PAGE_P_BIT_GP		0	/* Present */
#define _PAGE_W_BIT_GP		1	/* Writable */
#define _PAGE_A_BIT_GP		5	/* page Accessed */
#define	_PAGE_D_BIT_GP		6	/* page Dirty */
#define	_PAGE_HUGE_BIT_GP	7	/* huge Page Size */
#define	_PAGE_MTCR_SHIFT_GP	8	/* shift of Memory Type Combination */
					/* Rule field */
#define	_PAGE_MTCR_BITS_NUM_GP	2	/* and occupies 2 bits */
#define _PAGE_SW1_BIT_GP	10	/* SoftWare bit #1 */
#define _PAGE_SW2_BIT_GP	11	/* SoftWare bit #2 */
#define	_PAGE_PFN_SHIFT_GP	12	/* shift of Physical Page Number */
#define	_PAGE_MT_SHIFT_GP	60	/* shift of Memory Type field */
#define	_PAGE_MT_BITS_NUM_GP	 3	/* occupies 3 bits */

#define _PAGE_P_GP		(1ULL << _PAGE_P_BIT_GP)
#define _PAGE_W_GP		(1ULL << _PAGE_W_BIT_GP)
#define _PAGE_A_GP		(1ULL << _PAGE_A_BIT_GP)
#define _PAGE_D_GP		(1ULL << _PAGE_D_BIT_GP)
#define _PAGE_HUGE_GP		(1ULL << _PAGE_HUGE_BIT_GP)
#define	_PAGE_MTCR_GP		\
		(((1ULL << _PAGE_MTCR_BITS_NUM_GP) - 1) << _PAGE_MTCR_SHIFT_GP)
#define _PAGE_SW1_GP		(1ULL << _PAGE_SW1_BIT_GP)
#define _PAGE_SW2_GP		(1ULL << _PAGE_SW2_BIT_GP)
#define _PAGE_PFN_GP		\
		((((1ULL << E2K_MAX_PHYS_BITS_GP) - 1) >> \
				PAGE_SHIFT) << _PAGE_PFN_SHIFT_GP)
#define	_PAGE_MT_GP		\
		(((1ULL << _PAGE_MT_BITS_NUM_GP) - 1) << _PAGE_MT_SHIFT_GP)

#define	_PAGE_MMIO_SW_GP	0x0c00000000000000ULL	/* pte is MMIO */
							/* software flag */

/* Memory type and Combination rules manipulation */
#define	_PAGE_MT_GET_VAL_GP(x)	(((x) & _PAGE_MT_GP) >> _PAGE_MT_SHIFT_GP)
#define	_PAGE_MT_SET_VAL_GP(x, mt)	\
		(((x) & ~_PAGE_MT_GP) | \
			(((pteval_t)(mt) << _PAGE_MT_SHIFT_GP) & _PAGE_MT_GP))

#define	_PAGE_MTCR_GET_VAL_GP(x)	\
		(((x) & _PAGE_MTCR_GP) >> _PAGE_MTCR_SHIFT_GP)
#define	_PAGE_MTCR_SET_VAL_GP(x, mtcr)	\
		(((x) & ~_PAGE_MTCR_GP) | \
			(((pteval_t)(mtcr) << _PAGE_MTCR_SHIFT_GP) & \
							_PAGE_MTCR_GP))

/* convert physical address to page frame number for PTE */
#define	_PAGE_PADDR_TO_PFN_GP(phys_addr)	\
		(((e2k_addr_t)phys_addr) & _PAGE_PFN_GP)

/* convert the page frame number from PTE to physical address */
#define	_PAGE_PFN_TO_PADDR_GP(pte_val)	\
		((e2k_addr_t)(pte_val) & _PAGE_PFN_GP)

/* PTE flags mask to can update/reduce and restricted to update */
#define _PAGE_CHG_MASK_GP	(_PAGE_PFN_GP | _PAGE_A_GP | _PAGE_D_GP | \
				_PAGE_SW1_GP | _PAGE_SW2_GP | \
				_PAGE_MTCR_GP | _PAGE_MT_GP)
#define _HPAGE_CHG_MASK_GP	(_PAGE_CHG_MASK_GP | _PAGE_HUGE_GP)
#define _PROT_REDUCE_MASK_GP	(_PAGE_P_GP | _PAGE_W_GP | _PAGE_A_GP | \
				_PAGE_D_GP | _PAGE_MTCR_GP | _PAGE_MT_GP)
#define	_PROT_RESTRICT_MASK_GP	0ULL

/* some useful PT entries protection basis values */
#define _PAGE_KERNEL_RX_GP	\
		(_PAGE_P_GP | _PAGE_A_GP)
#define _PAGE_KERNEL_RO_GP	_PAGE_KERNEL_RX_GP
#define _PAGE_KERNEL_RW_GP	\
		(_PAGE_KERNEL_RX_GP | _PAGE_W_GP | _PAGE_D_GP)
#define _PAGE_KERNEL_RWX_GP	_PAGE_KERNEL_RW_GP
#define _PAGE_KERNEL_HUGE_RX_GP	\
		(_PAGE_KERNEL_RX_GP | _PAGE_HUGE_GP)
#define _PAGE_KERNEL_HUGE_RO_GP	_PAGE_KERNEL_HUGE_RX_GP
#define _PAGE_KERNEL_HUGE_RW_GP	\
		(_PAGE_KERNEL_HUGE_RX_GP | _PAGE_W_GP | _PAGE_D_GP)
#define _PAGE_KERNEL_HUGE_RWX_GP	_PAGE_KERNEL_HUGE_RW_GP

#define _PAGE_KERNEL_PT_GP	_PAGE_KERNEL_RW_GP

static inline pteval_t
get_pte_val_gp_changeable_mask(void)
{
	return _PAGE_CHG_MASK_GP;
}
static inline pteval_t
get_huge_pte_val_gp_changeable_mask(void)
{
	return _HPAGE_CHG_MASK_GP;
}
static inline pteval_t
get_pte_val_gp_reduceable_mask(void)
{
	return 0;
}
static inline pteval_t
get_pte_val_gp_restricted_mask(void)
{
	return _PROT_RESTRICT_MASK_GP;
}

static inline pteval_t
covert_uni_pte_flags_to_pte_val_gp(const uni_pteval_t uni_flags)
{
	pteval_t pte_flags = 0;

	if (uni_flags & UNI_PAGE_PRESENT)
		pte_flags |= (_PAGE_P_GP);
	if (uni_flags & UNI_PAGE_WRITE)
		pte_flags |= (_PAGE_W_GP);
	if (uni_flags & UNI_PAGE_MEM_TYPE_RULE)
		pte_flags |= (_PAGE_MTCR_GP);
	if (uni_flags & UNI_PAGE_ACCESSED)
		pte_flags |= (_PAGE_A_GP);
	if (uni_flags & UNI_PAGE_DIRTY)
		pte_flags |= (_PAGE_D_GP);
	if (uni_flags & UNI_PAGE_HUGE)
		pte_flags |= (_PAGE_HUGE_GP);
	if (uni_flags & UNI_PAGE_PFN)
		pte_flags |= (_PAGE_PFN_GP);
	if (uni_flags & UNI_PAGE_MEM_TYPE)
		pte_flags |= (_PAGE_MT_GP);

	BUG_ON(uni_flags & UNI_PAGE_AVAIL);
	BUG_ON(uni_flags & UNI_PAGE_SPECIAL);
	BUG_ON(uni_flags & UNI_PAGE_GFN);

	return pte_flags;
}

static inline pteval_t
fill_pte_val_gp_flags(const uni_pteval_t uni_flags)
{
	return covert_uni_pte_flags_to_pte_val_gp(uni_flags);
}
static inline pteval_t
get_pte_val_gp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & covert_uni_pte_flags_to_pte_val_gp(uni_flags);
}
static inline bool
test_pte_val_gp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return get_pte_val_gp_flags(pte_val, uni_flags) != 0;
}
static inline pteval_t
set_pte_val_gp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val | covert_uni_pte_flags_to_pte_val_gp(uni_flags);
}
static inline pteval_t
clear_pte_val_gp_flags(pteval_t pte_val, const uni_pteval_t uni_flags)
{
	return pte_val & ~covert_uni_pte_flags_to_pte_val_gp(uni_flags);
}

static inline unsigned int
get_pte_val_gp_memory_type_rule(pteval_t pte_val)
{
	return _PAGE_MTCR_GET_VAL_GP(pte_val);
}
static inline unsigned int
get_pte_val_gp_memory_type(pteval_t pte_val)
{
	return _PAGE_MT_GET_VAL_GP(pte_val);
}
static inline pteval_t
set_pte_val_gp_memory_type(pteval_t pte_val, unsigned int memory_type)
{
	return set_pte_val_v6_memory_type(pte_val, memory_type);
}
static inline pteval_t
set_pte_val_gp_memory_type_rule(pteval_t pte_val, unsigned int mtcr)
{
	BUG_ON(mtcr != MOST_STRONG_MTCR &&
		mtcr != FROM_HYPERVISOR_MTCR &&
		mtcr != FROM_GUEST_MTCR);

	return _PAGE_MTCR_SET_VAL_GP(pte_val, mtcr);
}

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _E2K_KVM_PGTABLE_GP_H */
