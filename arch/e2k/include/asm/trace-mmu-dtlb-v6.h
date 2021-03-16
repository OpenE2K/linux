#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_MMU_DTLB_V6_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_MMU_DTLB_V6_H

#include <asm/mmu-regs-types-v6.h>

#define E2K_TRACE_PRINT_DTLB_ENTRY_V6(entry) \
	((entry & DTLB_ENTRY_ERROR_MASK_V6) ? \
		__print_flags(entry & DTLB_ENTRY_ERROR_MASK_V6, "|", \
				{ DTLB_ENTRY_PH_BOUND_V6, "ph_bound" }, \
				{ DTLB_ENTRY_PAGE_MISS_V6, "page_miss" }, \
				{ DTLB_ENTRY_PROBE_SUCCESSFUL_V6, \
						"DTLB probe successful" }, \
				{ DTLB_ENTRY_RES_BITS_V6, "res_bits" } \
			) : \
		({ __print_flags(entry & ~DTLB_ENTRY_PHA_V6, "|", \
				{ DTLB_ENTRY_WR_exc_V6, "writable" }, \
				{ DTLB_ENTRY_PV_or_U_S_V6, "Priv/U_S" }, \
				{ DTLB_ENTRY_D_V6, "dirty" }, \
				{ DTLB_ENTRY_G_V6, "global" }, \
				{ DTLB_ENTRY_NWA_V6, "NWA" }, \
				{ DTLB_ENTRY_VVA_V6, "valid" }, \
				{ DTLB_ENTRY_NON_EX_V6, "non_ex" }, \
				{ DTLB_ENTRY_INT_PR_V6, "int_pr" }, \
				{ DTLB_ENTRY_INTL_RD_V6, "intl_rd" }, \
				{ DTLB_ENTRY_INTL_WR_V6, "intl_wr" }, \
				{ DTLB_ENTRY_WR_int_V6, "WR_int" } \
			); \
		__print_symbolic(DTLB_ENTRY_MT_exc_GET_VAL(entry), \
			{ GEN_CACHE_MT,		"General Cacheable" }, \
			{ GEN_NON_CACHE_MT,	"General nonCacheable" }, \
			{ EXT_PREFETCH_MT,	"External Prefetchable" }, \
			{ EXT_NON_PREFETCH_MT,	"External nonPrefetchable" }, \
			{ EXT_CONFIG_MT,	"External Configuration" }, \
			{ 2,			"Reserved-2" }, \
			{ 3,			"Reserved-3" }, \
			{ 5,			"Reserved-5" }); \
		}))

#endif /* _TRACE_E2K_MMU_DTLB_V6_H */
