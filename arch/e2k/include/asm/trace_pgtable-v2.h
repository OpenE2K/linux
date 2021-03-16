#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_PGTABLE_V2_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_PGTABLE_V2_H

#include <asm/pgtable-v2.h>

#define E2K_TRACE_PRINT_PT_V2_FLAGS(entry, print) \
	(print) ? (__print_flags(entry & (_PAGE_P_V2 | _PAGE_VALID_V2 | \
					  _PAGE_HUGE_V2 | _PAGE_G_V2 | \
					  _PAGE_NWA_V2 | _PAGE_AVAIL_V2 | \
					  _PAGE_INT_PR_V2), "|", \
			{ _PAGE_P_V2 ,		"present" }, \
			{ _PAGE_VALID_V2 ,	"valid" }, \
			{ _PAGE_HUGE_V2,	"large" }, \
			{ _PAGE_G_V2,		"global" }, \
			{ _PAGE_NWA_V2,		"not_write_address" }, \
			{ _PAGE_AVAIL_V2,	"OS" }, \
			{ _PAGE_INT_PR_V2,	"integer_protect" } \
		)) : "(none)", \
	(print) ? (__print_flags(entry & (_PAGE_PV_V2 | _PAGE_NON_EX_V2 | \
					  _PAGE_W_V2 | _PAGE_D_V2 | \
					  _PAGE_A_HW_V2), "|", \
			{ _PAGE_PV_V2,		"privileged" }, \
			{ _PAGE_NON_EX_V2,	"non_executable" }, \
			{ _PAGE_W_V2,		"writable" }, \
			{ _PAGE_D_V2,		"dirty" }, \
			{ _PAGE_A_HW_V2,	"accessed" } \
		)) : "(none)", \
	(print && entry != -1ULL && (entry & ~_PAGE_VALID_V2)) ? \
			(((entry & _PAGE_CD_MASK_V2) != _PAGE_CD_MASK_V2) ? \
					"|cacheable" \
				: ((entry & _PAGE_PWT_V2) ? \
					"|uncacheable" : "|write_combine")) \
		: "" \

#endif /* _TRACE_E2K_PGTABLE_V2_H */
