/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#if !defined(_TRACE_E2K_PGTABLE_V3_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_PGTABLE_V3_H

#include <asm/pgtable-v3.h>

/* Workaround libtraceevent - use magic number */
#define E2K_PT_ALL_FLAGS_V3 0x00000f0000000de3ULL

#define E2K_TRACE_PRINT_PT_V3_FLAGS(entry, print) \
	((print) ? (__print_flags(entry & E2K_PT_ALL_FLAGS_V3, "|", \
			{ _PAGE_P_V3,		"present" }, \
			{ _PAGE_VALID_V3,	"valid" }, \
			{ _PAGE_HUGE_V3,	"large" }, \
			{ _PAGE_G_V3,		"global" }, \
			{ _PAGE_NWA_V3,		"nwa" }, \
			{ _PAGE_AVAIL_V3,	"OS" }, \
			{ _PAGE_INT_PR_V3,	"int_pr" }, \
			{ _PAGE_PV_V3,		"priv" }, \
			{ _PAGE_NON_EX_V3,	"non_ex" }, \
			{ _PAGE_W_V3,		"writable" }, \
			{ _PAGE_D_V3,		"dirty" }, \
			{ _PAGE_A_V3,		"accessed" } \
		)) : "(none)")

#define E2K_TRACE_PRINT_PT_V3_MT(entry, print) \
	((print && (entry & ~_PAGE_VALID_V3)) ? \
			(((entry & _PAGE_CD_MASK_V3) != _PAGE_CD_MASK_V3) ? \
					"|cacheable" \
				: ((entry & _PAGE_PWT_V3) ? \
					"|uncacheable" : "|write_combine")) \
		: "")

#endif /* _TRACE_E2K_PGTABLE_V3_H */
