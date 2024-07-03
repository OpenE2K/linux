/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_MMU_DTLB_V6_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_MMU_DTLB_V6_H

/* Workaround libtraceevent - use magic number */
#define E2K_DTLB_ENTRY_V6__SUCCESSFULL_MT_PHA_MPT	0x7000fffffffffc80ULL
#define E2K_DTLB_ENTRY_V6__PT_LEV__NOSUCCESS_IGNORED	0x0fffffffffffff5fULL

#define E2K_TRACE_PRINT_DTLB_ENTRY_V6_FLAGS(entry, print) \
	((print) \
		? ((entry & DTLB_ENTRY_SUCCESSFUL_V6) \
			? __print_flags(entry & ~E2K_DTLB_ENTRY_V6__SUCCESSFULL_MT_PHA_MPT, \
					"|", \
					{ DTLB_ENTRY_W_V6, "writable" }, \
					{ DTLB_ENTRY_PV_or_U_S_V6, "priv/U_S" }, \
					{ DTLB_ENTRY_VVA_V6, "valid" }, \
					{ DTLB_ENTRY_INT_PR_V6, "int_pr" }, \
					{ DTLB_ENTRY_TLB_HIT_V6, "tlb_hit" }, \
					{ DTLB_ENTRY_D_V6, "dirty" }, \
					{ DTLB_ENTRY_G_V6, "global" }, \
					{ DTLB_ENTRY_NWA_V6, "nwa" }, \
					{ DTLB_ENTRY_NON_EX_V6, "non_ex" } \
				) \
			: __print_flags(entry & ~E2K_DTLB_ENTRY_V6__PT_LEV__NOSUCCESS_IGNORED, \
					"|", \
					{ DTLB_ENTRY_TLB_HIT_V6, "tlb_hit" }, \
					{ DTLB_ENTRY_RES_BITS_V6, "res_bits" }, \
					{ DTLB_ENTRY_PAGE_MISS_V6, "page_miss" }, \
					{ DTLB_ENTRY_ILLEGAL_PAGE_V6, "illegal_page" },\
					{ DTLB_ENTRY_PH_BOUND_V6, "ph_bound" } \
				)) \
		: "(not read)")

#define E2K_TRACE_PRINT_DTLB_ENTRY_V6_MT(entry, print) \
	(((print) && (entry & DTLB_ENTRY_SUCCESSFUL_V6)) \
		? __print_symbolic(DTLB_ENTRY_MT_GET_VAL(entry), \
				{ GEN_CACHE_MT,		"|GC" }, \
				{ GEN_NON_CACHE_MT,	"|GnC" }, \
				{ EXT_PREFETCH_MT,	"|XP" }, \
				{ EXT_NON_PREFETCH_MT,	"|XnP" }, \
				{ EXT_CONFIG_MT,	"|XC" }, \
				{ 2,			"|Reserved-2" }, \
				{ 3,			"|Reserved-3" }, \
				{ 5,			"|Reserved-5" } \
			) \
		: "")

#endif /* _TRACE_E2K_MMU_DTLB_V6_H */
