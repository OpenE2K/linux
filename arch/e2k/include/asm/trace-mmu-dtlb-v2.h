#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_MMU_DTLB_V2_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_MMU_DTLB_V2_H

#include <asm/mmu-regs-types-v2.h>

#define E2K_TRACE_PRINT_DTLB_ENTRY_V2(entry) \
	((entry & DTLB_ENTRY_ERROR_MASK_V2) ? \
		__print_flags(entry & DTLB_ENTRY_ERROR_MASK_V2, "|", \
				{ DTLB_ENTRY_PH_BOUND_V2, "ph_bound" }, \
				{ DTLB_ENTRY_PAGE_MISS_V2, "page_miss" }, \
				{ DTLB_ENTRY_PROBE_DISABLED_V2, \
						"DTLB probe disabled" }, \
				{ DTLB_ENTRY_RES_BITS_V2, "res_bits" } \
			) : \
		__print_flags(entry & ~DTLB_ENTRY_PHA_V2, "|", \
				{ DTLB_ENTRY_WR_V2, "writable" }, \
				{ DTLB_ENTRY_NON_EX_U_S_V2, "Non_ex-U_S" }, \
				{ DTLB_ENTRY_PWT_V2, "PWT" }, \
				{ DTLB_ENTRY_PCD1_V2, "CD1" }, \
				{ DTLB_ENTRY_PCD2_V2, "CD2" }, \
				{ DTLB_ENTRY_D_V2, "dirty" }, \
				{ DTLB_ENTRY_G_V2, "global" }, \
				{ DTLB_ENTRY_NWA_V2, "NWA" }, \
				{ DTLB_ENTRY_VVA_V2, "valid" }, \
				{ DTLB_ENTRY_PV_V2, "privileged" }, \
				{ DTLB_ENTRY_INT_PR_NON_EX_V2, \
						"int_pr-non_ex" }, \
				{ DTLB_ENTRY_INTL_RD_V2, "intl_rd" }, \
				{ DTLB_ENTRY_INTL_WR_V2, "intl_wr" }, \
				{ DTLB_ENTRY_WP_V2, "WP" }, \
				{ DTLB_ENTRY_UC_V2, "UC" } \
			))

#endif /* _TRACE_E2K_MMU_DTLB_V2_H */
