/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#if !defined(_TRACE_E2K_PGTABLE_V6_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_PGTABLE_V6_H

#include <asm/pgtable-v6.h>

/* Workaround libtraceevent - use magic number */
#define E2K_PT_ALL_FLAGS_V6 0x8000000000000fffULL

#define E2K_TRACE_PRINT_PT_V6_FLAGS(entry, print) \
	((print) ? __print_flags(entry & E2K_PT_ALL_FLAGS_V6, "|", \
			{ _PAGE_P_V6 ,		"present" }, \
			{ _PAGE_VALID_V6 ,	"valid" }, \
			{ _PAGE_HUGE_V6,	"large" }, \
			{ _PAGE_G_V6,		"global" }, \
			{ _PAGE_NWA_V6,		"nwa" }, \
			{ _PAGE_SW1_V6,		"OS-1" }, \
			{ _PAGE_SW2_V6,		"OS-2" }, \
			{ _PAGE_INT_PR_V6,	"int_pr" }, \
			{ _PAGE_PV_V6,		"priv" }, \
			{ _PAGE_NON_EX_V6,	"non_ex" }, \
			{ _PAGE_W_V6,		"writable" }, \
			{ _PAGE_D_V6,		"dirty" }, \
			{ _PAGE_A_V6,		"accessed" } \
		) : "(none)")

#define E2K_TRACE_PRINT_PT_V6_MT(entry, print) \
	((print && (entry & ~_PAGE_VALID_V6)) ? \
		__print_symbolic(_PAGE_MT_GET_VAL(entry), \
			{ GEN_CACHE_MT,		"|GC" }, \
			{ GEN_NON_CACHE_MT,	"|GnC" }, \
			{ GEN_NON_CACHE_ORDERED_MT, \
				"|GnC Ordered (same as GnC in hardware)" }, \
			{ EXT_PREFETCH_MT,	"|XP" }, \
			{ EXT_NON_PREFETCH_MT,	"|XnP" }, \
			{ EXT_CONFIG_MT,	"|XC" }, \
			{ 2,			"|Reserved-2" }, \
			{ 3,			"|Reserved-3" }, \
			{ 5,			"|Reserved-5" }) \
		: "")

#endif /* _TRACE_E2K_PGTABLE_V6_H */
