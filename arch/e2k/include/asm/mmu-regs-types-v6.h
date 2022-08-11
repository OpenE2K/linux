/*
 * E2K ISET V6-... MMU structure and common definitions.
 *
 * Copyright 2018 (c) MCST, Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _ASM_E2K_MMU_REGS_TYPES_V6_H
#define _ASM_E2K_MMU_REGS_TYPES_V6_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K ISET V2-V5 page tables.
 * NOTE: E2K has four levels of page tables.
 */

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/bug.h>
#include <asm/mmu_types.h>

/*
 * DTLB entry probe format
 */
#define	DTLB_ENTRY_MT_exc_SHIFT_V6	 8	/* shift of Memory Type field */
						/* for exceptions */
#define	DTLB_ENTRY_MT_BITS_NUM_V6	 3	/* occupies 3 bits */
#define	DTLB_ENTRY_MT_ma_SHIFT_V6	48	/* shift of Memory Type field */
						/* for memory access */
#define	DTLB_ENTRY_PFN_SHIFT_V6		12	/* shift of Physical Page */
						/* Number */

#define DTLB_ENTRY_ERROR_MASK_V6	0xe000000000000000ULL
#define DTLB_ENTRY_PH_BOUND_V6		0x8000000000000000ULL
#define	DTLB_ENTRY_ILLEGAL_PAGE_V6	0x4000000000000000ULL
#define DTLB_ENTRY_PAGE_MISS_V6		0x2000000000000000ULL
#define DTLB_ENTRY_PROBE_SUCCESSFUL_V6	0x0000000000000080ULL
#define DTLB_ENTRY_RES_BITS_V6		0x1000000000000000ULL
#define DTLB_ENTRY_MISS_LEVEL_MASK_V6	0x0000000000000007ULL
#define	DTLB_ENTRY_TLB_HIT_V6		0x0000000000000020ULL

#define DTLB_ENTRY_WR_exc_V6		0x0000000000000002ULL
#define DTLB_ENTRY_PV_or_U_S_V6		0x0000000000000004ULL
#define DTLB_ENTRY_VVA_V6		0x0000000000000008ULL
#define DTLB_ENTRY_INT_PR_V6		0x0000000000000010ULL
#define DTLB_ENTRY_G_V6			0x0000000000000020ULL
#define DTLB_ENTRY_D_V6			0x0000000000000040ULL
#define DTLB_ENTRY_NWA_V6		0x0000000000000080ULL
#define	DTLB_ENTRY_MT_exc_V6	/*	0x0000000000000700ULL */ \
		(((1ULL << DTLB_ENTRY_MT_BITS_NUM_V6) - 1) << \
						DTLB_ENTRY_MT_exc_SHIFT_V6)
#define DTLB_ENTRY_NON_EX_V6		0x8000000000000000ULL
#define DTLB_ENTRY_PHA_V6	/*	0x0000fffffffff000ULL */ \
		((((1ULL << E2K_MAX_PHYS_BITS_V6) - 1) >> \
					DTLB_ENTRY_PFN_SHIFT_V6) << \
							DTLB_ENTRY_PFN_SHIFT_V6)
#define	DTLB_ENTRY_MT_ma_V6	/*	0x0007000000000000ULL */ \
		(((1ULL << DTLB_ENTRY_MT_BITS_NUM_V6) - 1) << \
						DTLB_ENTRY_MT_ma_SHIFT_V6)
#define DTLB_ENTRY_WR_int_V6		0x0008000000000000ULL
#define DTLB_ENTRY_INTL_RD_V6		0x0010000000000000ULL
#define DTLB_ENTRY_INTL_WR_V6		0x0020000000000000ULL

/* MPT flags for 2/4Mb & 1Gb pages	[46:45] */
#define	DTLB_ENTRY_MPT_FLAGS_V6		0x0000600000000000ULL

#define DTLB_EP_RES_V6			0x003fffffffffffffULL
#define	DTLB_EP_FAULT_RES_V6		(~DTLB_EP_RES_V6)

/*
 * DTLB address probe result format
 */
#define PH_ADDR_AP_RES_V6	/*	0x0000ffffffffffffULL */ \
		((1ULL << E2K_MAX_PHYS_BITS_V6) - 1)
#define	DISABLE_AP_RES_V6	DISABLE_EP_RES_V6	/* AP diasble result */
							/* [62] */
#define	ILLEGAL_PAGE_AP_RES_V6	ILLEGAL_PAGE_EP_RES_V6	/* illegal page */
							/* [58] */

/* convert physical address to page frame number for DTLB */
#define	PA_TO_DTLB_ENTRY_PHA_V6(phys_addr)	\
		(((e2k_addr_t)phys_addr) & DTLB_ENTRY_PHA_V6)
/* convert the page frame number from DTLB entry to physical address */
#define	DTLB_ENTRY_PHA_TO_PA_V6(dtlb_entry)	\
		((e2k_addr_t)(dtlb_entry) & DTLB_ENTRY_PHA_V6)

/* get/set Memory Type field from/to DTLB entry */
#define	DTLB_ENTRY_MT_exc_GET_VAL(x)	\
		(((x) & DTLB_ENTRY_MT_exc_V6) >> DTLB_ENTRY_MT_exc_SHIFT_V6)
#define	DTLB_ENTRY_MT_exc_SET_VAL(x, mt)	\
		(((x) & ~DTLB_ENTRY_MT_exc_V6) | \
			(((probe_entry_t)(mt) << DTLB_ENTRY_MT_exc_SHIFT_V6) & \
							DTLB_ENTRY_MT_exc_V6))
#define	DTLB_ENTRY_MT_ma_GET_VAL(x)	\
		(((x) & DTLB_ENTRY_MT_ma_V6) >> DTLB_ENTRY_MT_ma_SHIFT_V6)
#define	DTLB_ENTRY_MT_ma_SET_VAL(x, mt)	\
		(((x) & ~DTLB_ENTRY_MT_ma_V6) | \
			(((probe_entry_t)(mt) << DTLB_ENTRY_MT_ma_SHIFT_V6) & \
							DTLB_ENTRY_MT_ma_V6))

static inline probe_entry_t
covert_uni_dtlb_flags_to_dtlb_val_v6(const uni_dtlb_t uni_flags)
{
	probe_entry_t dtlb_flags = 0;

	if (uni_flags & UNI_PAGE_WRITE)
		dtlb_flags |= (DTLB_ENTRY_WR_exc_V6);
	if (uni_flags & UNI_PAGE_PRIV)
		dtlb_flags |= (DTLB_ENTRY_PV_or_U_S_V6);
	if (uni_flags & UNI_PAGE_VALID)
		dtlb_flags |= (DTLB_ENTRY_VVA_V6);
	if (uni_flags & UNI_PAGE_PROTECT)
		dtlb_flags |= (DTLB_ENTRY_INT_PR_V6);
	if (uni_flags & UNI_PAGE_GLOBAL)
		dtlb_flags |= (DTLB_ENTRY_G_V6);
	if (uni_flags & UNI_PAGE_DIRTY)
		dtlb_flags |= (DTLB_ENTRY_D_V6);
	if (uni_flags & UNI_PAGE_NWA)
		dtlb_flags |= (DTLB_ENTRY_NWA_V6);
	if (uni_flags & UNI_PAGE_MEM_TYPE)
		dtlb_flags |= (DTLB_ENTRY_MT_exc_V6);
	if (uni_flags & UNI_PAGE_NON_EX)
		dtlb_flags |= (DTLB_ENTRY_NON_EX_V6);
	if (uni_flags & UNI_PAGE_PFN)
		dtlb_flags |= (DTLB_ENTRY_PHA_V6);
	if (uni_flags & UNI_PAGE_MEM_TYPE_MA)
		dtlb_flags |= (DTLB_ENTRY_MT_ma_V6);
	if (uni_flags & UNI_PAGE_WRITE_INT)
		dtlb_flags |= (DTLB_ENTRY_WR_int_V6);
	if (uni_flags & UNI_PAGE_INTL_RD)
		dtlb_flags |= (DTLB_ENTRY_INTL_RD_V6);
	if (uni_flags & UNI_PAGE_INTL_WR)
		dtlb_flags |= (DTLB_ENTRY_INTL_WR_V6);
	if (uni_flags & UNI_DTLB_EP_RES)
		dtlb_flags |= (DTLB_EP_RES_V6);
	if (uni_flags & UNI_DTLB_PH_ADDR_AP_RES)
		dtlb_flags |= (PH_ADDR_AP_RES_V6);
	if (uni_flags & UNI_DTLB_ERROR_MASK)
		dtlb_flags |= (DTLB_ENTRY_ERROR_MASK_V6);
	if (uni_flags & UNI_DTLB_MISS_LEVEL)
		dtlb_flags |= (DTLB_ENTRY_MISS_LEVEL_MASK_V6);
	if (uni_flags & UNI_DTLB_SUCCESSFUL)
		dtlb_flags |= (DTLB_ENTRY_PROBE_SUCCESSFUL_V6);
	if (uni_flags & UNI_DTLB_RES_BITS)
		dtlb_flags |= (DTLB_ENTRY_RES_BITS_V6);

	BUILD_BUG_ON(dtlb_flags == 0);

	return dtlb_flags;
}

static inline probe_entry_t
fill_dtlb_val_v6_flags(const uni_dtlb_t uni_flags)
{
	return covert_uni_dtlb_flags_to_dtlb_val_v6(uni_flags);
}
static inline probe_entry_t
get_dtlb_val_v6_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return dtlb_val & covert_uni_dtlb_flags_to_dtlb_val_v6(uni_flags);
}
static inline bool
test_dtlb_val_v6_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return get_dtlb_val_v6_flags(dtlb_val, uni_flags) != 0;
}
static inline probe_entry_t
set_dtlb_val_v6_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return dtlb_val | covert_uni_dtlb_flags_to_dtlb_val_v6(uni_flags);
}
static inline probe_entry_t
clear_dtlb_val_v6_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return dtlb_val & ~covert_uni_dtlb_flags_to_dtlb_val_v6(uni_flags);
}

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _ASM_E2K_MMU_REGS_TYPES_V6_H */
