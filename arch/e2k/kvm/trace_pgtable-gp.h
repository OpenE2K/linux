/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_PGTABLE_GP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_PGTABLE_GP_H

#include "pgtable-gp.h"

#define E2K_TRACE_PRINT_PT_GP_FLAGS(entry, print) \
	(print) ? (__print_flags(entry & (_PAGE_P_GP | _PAGE_HUGE_GP | \
					  _PAGE_SW1_GP | _PAGE_SW2_GP), "|", \
			{ _PAGE_P_GP ,		"present" }, \
			{ _PAGE_HUGE_GP,	"large" }, \
			{ _PAGE_SW1_GP,		"OS-1" }, \
			{ _PAGE_SW2_GP,		"OS-2" } \
		)) : "(none)", \
	(print) ? (__print_flags(entry & (_PAGE_W_GP | _PAGE_D_GP | \
					  _PAGE_A_HW_GP), "|", \
			{ _PAGE_W_GP,		"writable" }, \
			{ _PAGE_D_GP,		"dirty" }, \
			{ _PAGE_A_HW_GP,	"accessed" } \
		)) : "(none)", \
	(print && entry != -1ULL && (entry & _PAGE_P_GP)) ? \
		(__print_symbolic(_PAGE_MTCR_GET_VAL_GP(entry), \
			{ MOST_STRONG_MTCR,	"Most Strong MT" }, \
			{ FROM_HYPERVISOR_MTCR,	"Hypervisor MT" }, \
			{ FROM_GUEST_MTCR,	"Guest MT" }, \
			{ 1,			"Reserved-1" })) \
		: "" \
	(print && entry != -1ULL && (entry & _PAGE_P_GP)) ? \
		(__print_symbolic(_PAGE_MT_GET_VAL(entry), \
			{ GEN_CACHE_MT,		"GC" }, \
			{ GEN_NON_CACHE_MT,	"GnC" }, \
			{ GEN_NON_CACHE_ORDERED_MT, \
				"GnC Ordered (same as GnC in hardware)" }, \
			{ EXT_PREFETCH_MT,	"XP" }, \
			{ EXT_NON_PREFETCH_MT,	"XnP" }, \
			{ EXT_CONFIG_MT,	"XC" }, \
			{ 2,			"Reserved-2" }, \
			{ 3,			"Reserved-3" }, \
			{ 5,			"Reserved-5" })) \
		: ""

#endif /* _TRACE_E2K_PGTABLE_GP_H */
