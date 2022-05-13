#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_MMU_DTLB_V3_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_MMU_DTLB_V3_H

#define E2K_TRACE_PRINT_DTLB_ENTRY_V3(entry) \
	((entry & DTLB_ENTRY_ERROR_MASK_V3) ? \
		__print_flags(entry & DTLB_ENTRY_ERROR_MASK_V3, "|", \
				{ DTLB_ENTRY_PH_BOUND_V3, "ph_bound" }, \
				{ DTLB_ENTRY_PAGE_MISS_V3, "page_miss" }, \
				{ DTLB_ENTRY_PROBE_DISABLED_V3, \
						"DTLB probe disabled" }, \
				{ DTLB_ENTRY_RES_BITS_V3, "res_bits" } \
			) : \
		__print_flags(entry & ~DTLB_ENTRY_PHA_V3, "|", \
				{ DTLB_ENTRY_WR_V3, "writable" }, \
				{ DTLB_ENTRY_NON_EX_U_S_V3, "Non_ex-U_S" }, \
				{ DTLB_ENTRY_PWT_V3, "PWT" }, \
				{ DTLB_ENTRY_PCD1_V3, "CD1" }, \
				{ DTLB_ENTRY_PCD2_V3, "CD2" }, \
				{ DTLB_ENTRY_D_V3, "dirty" }, \
				{ DTLB_ENTRY_G_V3, "global" }, \
				{ DTLB_ENTRY_NWA_V3, "NWA" }, \
				{ DTLB_ENTRY_VVA_V3, "valid" }, \
				{ DTLB_ENTRY_PV_V3, "privileged" }, \
				{ DTLB_ENTRY_INT_PR_NON_EX_V3, \
						"int_pr-non_ex" }, \
				{ DTLB_ENTRY_INTL_RD_V3, "intl_rd" }, \
				{ DTLB_ENTRY_INTL_WR_V3, "intl_wr" }, \
				{ DTLB_ENTRY_WP_V3, "WP" }, \
				{ DTLB_ENTRY_UC_V3, "UC" } \
			))

#endif /* _TRACE_E2K_MMU_DTLB_V3_H */
