#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_PGTABLE_V6_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_PGTABLE_V6_H

#include <asm/pgtable-v6.h>

#define E2K_TRACE_PRINT_PT_V6_FLAGS(entry, print) \
	(print) ? (__print_flags(entry & (_PAGE_P_V6 | _PAGE_VALID_V6 | \
					  _PAGE_HUGE_V6 | _PAGE_G_V6 | \
					  _PAGE_NWA_V6 | \
					  _PAGE_SW1_V6 | _PAGE_SW2_V6 | \
					  _PAGE_INT_PR_V6), "|", \
			{ _PAGE_P_V6 ,		"present" }, \
			{ _PAGE_VALID_V6 ,	"valid" }, \
			{ _PAGE_HUGE_V6,	"large" }, \
			{ _PAGE_G_V6,		"global" }, \
			{ _PAGE_NWA_V6,		"not_write_address" }, \
			{ _PAGE_SW1_V6,		"OS-1" }, \
			{ _PAGE_SW2_V6,		"OS-2" }, \
			{ _PAGE_INT_PR_V6,	"integer_protect" } \
		)) : "(none)", \
	(print) ? (__print_flags(entry & (_PAGE_PV_V6 | _PAGE_NON_EX_V6 | \
					  _PAGE_W_V6 | _PAGE_D_V6 | \
					  _PAGE_A_HW_V6), "|", \
			{ _PAGE_PV_V6,		"privileged" }, \
			{ _PAGE_NON_EX_V6,	"non_executable" }, \
			{ _PAGE_W_V6,		"writable" }, \
			{ _PAGE_D_V6,		"dirty" }, \
			{ _PAGE_A_HW_V6,	"accessed" } \
		)) : "(none)", \
	(print && entry != -1ULL && (entry & ~_PAGE_VALID_V6)) ? \
		(__print_symbolic(_PAGE_MT_GET_VAL(entry), \
			{ GEN_CACHE_MT,		"General Cacheable" }, \
			{ GEN_NON_CACHE_MT,	"General nonCacheable" }, \
			{ GEN_NON_CACHE_ORDERED_MT, \
				"General nonCacheable Ordered (same as GnC in hardware)" }, \
			{ EXT_PREFETCH_MT,	"External Prefetchable" }, \
			{ EXT_NON_PREFETCH_MT,	"External nonPrefetchable" }, \
			{ EXT_CONFIG_MT,	"External Configuration" }, \
			{ EXT_CACHE_MT,		"External Cached (same as GC in hardware)" }, \
			{ 2,			"Reserved-2" }, \
			{ 3,			"Reserved-3" }, \
			{ 5,			"Reserved-5" })) \
		: "" \

#endif /* _TRACE_E2K_PGTABLE_V6_H */
