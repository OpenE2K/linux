/*
 * E2K ISET V3-V5 MMU structure and common definitions.
 *
 * Copyright 2018 (c) MCST, Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _ASM_E2K_MMU_REGS_TYPES_V3_H
#define _ASM_E2K_MMU_REGS_TYPES_V3_H

/* Avoid header dependency loop of probe_entry_t and DTLB_ENTRY_PH_BOUND_V3 */
#ifndef _E2K_TLB_REGS_TYPES_H_
# error Do not include <asm/mmu-regs-types-v3.h> directly, use <asm/tlb_regs_types.h> instead
#endif

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K ISET V3-V5 page tables.
 * NOTE: E2K has four levels of page tables.
 */

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <linux/bug.h>
#include <asm/mmu_types.h>

/*
 * DTLB entry probe format
 */

#define DTLB_ENTRY_ERROR_MASK_V3	0xbe00000000000000ULL
#define DTLB_ENTRY_PH_BOUND_V3		0x8000000000000000ULL
#define	DTLB_ENTRY_ILLEGAL_PAGE_V3	0x4000000000000000ULL
#define DTLB_ENTRY_PAGE_MISS_V3		0x2000000000000000ULL
#define DTLB_ENTRY_PROBE_DISABLED_V3	0x0400000000000000ULL
#define DTLB_ENTRY_RES_BITS_V3		0x0200000000000000ULL
#define DTLB_ENTRY_MISS_LEVEL_MASK_V3	0x1800000000000000ULL

#define DTLB_ENTRY_WR_V3		0x0000000000000002ULL
#define DTLB_ENTRY_NON_EX_U_S_V3	0x0000000000000004ULL
#define DTLB_ENTRY_PWT_V3		0x0000000000000008ULL
#define DTLB_ENTRY_PCD1_V3		0x0000000000000010ULL
#define DTLB_ENTRY_D_V3			0x0000000000000040ULL
#define DTLB_ENTRY_G_V3			0x0000000000000100ULL
#define DTLB_ENTRY_PCD2_V3		0x0000000000000200ULL
#define DTLB_ENTRY_NWA_V3		0x0000000000000400ULL
#define DTLB_ENTRY_PHA_V3		0x000000fffffff000ULL /* phys address */
#define DTLB_ENTRY_VVA_V3		0x0000010000000000ULL /* VVA bit */
#define DTLB_ENTRY_PV_V3		0x0000020000000000ULL
#define DTLB_ENTRY_INT_PR_NON_EX_V3	0x0000040000000000ULL
#define DTLB_ENTRY_INTL_RD_V3		0x0000200000000000ULL
#define DTLB_ENTRY_INTL_WR_V3		0x0000400000000000ULL
#define DTLB_ENTRY_WP_V3		0x0000800000000000ULL
#define DTLB_ENTRY_UC_V3		0x0001000000000000ULL

/* MPT flags for 2/4Mb & 1Gb pages	[46:45] */
#define	DTLB_ENTRY_MPT_FLAGS_V3		0x0000600000000000ULL

#define DTLB_EP_RES_V3			0x0001ffffffffffffULL
#define	DTLB_EP_FAULT_RES_V3		(~DTLB_EP_RES_V3)

/*
 * DTLB address probe result format
 */
#define	PH_ADDR_AP_RES_V3	0x000000ffffffffffULL	/* Physical address */
							/* normal result of */
							/* AP [39: 0] */
#define	DISABLE_AP_RES_V3	DISABLE_EP_RES_V3	/* AP diasble result */
							/* [62] */
#define	ILLEGAL_PAGE_AP_RES_V3	ILLEGAL_PAGE_EP_RES_V3	/* illegal page */
							/* [58] */

/* convert physical address to page frame number for DTLB */
#define	PA_TO_DTLB_ENTRY_PHA_V3(phys_addr)	\
		(((e2k_addr_t)phys_addr) & DTLB_ENTRY_PHA_V3)
/* convert the page frame number from DTLB entry to physical address */
#define	DTLB_ENTRY_PHA_TO_PA_V3(dtlb_entry)	\
		((e2k_addr_t)(dtlb_entry) & DTLB_ENTRY_PHA_V3)

static inline probe_entry_t
covert_uni_dtlb_flags_to_dtlb_val_v3(const uni_dtlb_t uni_flags)
{
	probe_entry_t dtlb_flags = 0;

	if (uni_flags & UNI_PAGE_WRITE)
		dtlb_flags |= (DTLB_ENTRY_WR_V3);
	if (uni_flags & UNI_PAGE_PRIV)
		dtlb_flags |= (DTLB_ENTRY_PV_V3);
	if (uni_flags & UNI_PAGE_VALID)
		dtlb_flags |= (DTLB_ENTRY_VVA_V3);
	if (uni_flags & UNI_PAGE_PROTECT)
		dtlb_flags |= (DTLB_ENTRY_INT_PR_NON_EX_V3);
	if (uni_flags & UNI_PAGE_GLOBAL)
		dtlb_flags |= (DTLB_ENTRY_G_V3);
	if (uni_flags & UNI_PAGE_DIRTY)
		dtlb_flags |= (DTLB_ENTRY_D_V3);
	if (uni_flags & UNI_PAGE_NWA)
		dtlb_flags |= (DTLB_ENTRY_NWA_V3);
	if (uni_flags & UNI_PAGE_MEM_TYPE)
		dtlb_flags |= (DTLB_ENTRY_PCD1_V3 | DTLB_ENTRY_PCD2_V3 |
				DTLB_ENTRY_PWT_V3);
	if (uni_flags & UNI_PAGE_NON_EX)
		dtlb_flags |= (DTLB_ENTRY_NON_EX_U_S_V3);
	if (uni_flags & UNI_PAGE_PFN)
		dtlb_flags |= (DTLB_ENTRY_PHA_V3);
	if (uni_flags & UNI_PAGE_MEM_TYPE_MA)
		dtlb_flags |= (DTLB_ENTRY_PCD1_V3 | DTLB_ENTRY_PCD2_V3 |
				DTLB_ENTRY_PWT_V3);
	if (uni_flags & UNI_PAGE_WRITE_INT)
		dtlb_flags |= (DTLB_ENTRY_WP_V3);
	if (uni_flags & UNI_PAGE_INTL_RD)
		dtlb_flags |= (DTLB_ENTRY_INTL_RD_V3);
	if (uni_flags & UNI_PAGE_INTL_WR)
		dtlb_flags |= (DTLB_ENTRY_INTL_WR_V3);
	if (uni_flags & UNI_DTLB_EP_RES)
		dtlb_flags |= (DTLB_EP_RES_V3);
	if (uni_flags & UNI_DTLB_PH_ADDR_AP_RES)
		dtlb_flags |= (PH_ADDR_AP_RES_V3);
	if (uni_flags & UNI_DTLB_ERROR_MASK)
		dtlb_flags |= (DTLB_ENTRY_ERROR_MASK_V3);
	if (uni_flags & UNI_DTLB_MISS_LEVEL)
		dtlb_flags |= (DTLB_ENTRY_MISS_LEVEL_MASK_V3);
	if (uni_flags & UNI_DTLB_SUCCESSFUL)
		dtlb_flags |= (DTLB_ENTRY_PROBE_DISABLED_V3);
	if (uni_flags & UNI_DTLB_RES_BITS)
		dtlb_flags |= (DTLB_ENTRY_RES_BITS_V3);

	BUILD_BUG_ON(dtlb_flags == 0);

	return dtlb_flags;
}

static inline probe_entry_t
fill_dtlb_val_v3_flags(const uni_dtlb_t uni_flags)
{
	return covert_uni_dtlb_flags_to_dtlb_val_v3(uni_flags);
}
static inline probe_entry_t
get_dtlb_val_v3_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return dtlb_val & covert_uni_dtlb_flags_to_dtlb_val_v3(uni_flags);
}
static inline bool
test_dtlb_val_v3_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return get_dtlb_val_v3_flags(dtlb_val, uni_flags) != 0;
}
static inline probe_entry_t
set_dtlb_val_v3_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return dtlb_val | covert_uni_dtlb_flags_to_dtlb_val_v3(uni_flags);
}
static inline probe_entry_t
clear_dtlb_val_v3_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return dtlb_val & ~covert_uni_dtlb_flags_to_dtlb_val_v3(uni_flags);
}

#endif	/* ! __ASSEMBLY__ */

#endif /* ! _ASM_E2K_MMU_REGS_TYPES_V3_H */
