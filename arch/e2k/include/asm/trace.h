/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_H

#include <linux/tracepoint.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_types.h>
#include <asm/page.h>
#include <asm/pgtable_def.h>
#include <asm/trace_pgtable-v3.h>
#include <asm/trace_pgtable-v6.h>
#include <asm/trace-mmu-dtlb-v3.h>
#include <asm/trace-mmu-dtlb-v6.h>
#include <asm/trap_def.h>
#include <asm/trace-defs.h>

TRACE_EVENT(
	trap_cellar,

	TP_PROTO(const trap_cellar_t *tc, int nr),

	TP_ARGS(tc, nr),

	TP_STRUCT__entry(
		__field(	int,	nr		)
		__field(	u64,	address		)
		__field(	u64,	data_val	)
		__field(	u64,	data_ext_val	)
		__field(	u8,	data_tag	)
		__field(	u8,	data_ext_tag	)
		__field(	u64,	condition	)
		__field(	u64,	mask		)
	),

	TP_fast_assign(
		__entry->nr = nr;
		__entry->address = tc->address;
		load_value_and_tagd(&tc->data,
				&__entry->data_val, &__entry->data_tag);
		load_value_and_tagd(&tc->data_ext,
				&__entry->data_ext_val, &__entry->data_ext_tag);
		__entry->condition = AW(tc->condition);
		__entry->mask = AW(tc->mask);
	),

	TP_printk("\n"
		"Entry %d: address 0x%llx   data %hhx 0x%llx   data_ext %hhx 0x%llx\n"
		"Register: address=0x%02llx, vl=%lld, vr=%lld\n"
		"Opcode:  fmt=%lld, n_prot=%lld, fmtc=%lld\n"
		"Info1:   chan=%lld, mas=0x%02llx, miss_lvl=%lld, rcv=%lld, dst_rcv=0x%03llx\n"
		"Info2:   %s\n"
		"Ftype:   %s",
		__entry->nr, __entry->address, __entry->data_tag,
		__entry->data_val, __entry->data_ext_tag, __entry->data_ext_val,
		E2K_TC_COND_ADDRESS(__entry->condition),
		E2K_TC_COND_VL(__entry->condition),
		E2K_TC_COND_VR(__entry->condition),
		E2K_TC_COND_FMT(__entry->condition),
		E2K_TC_COND_NPSP(__entry->condition),
		E2K_TC_COND_FMTC(__entry->condition),
		E2K_TC_COND_CHAN(__entry->condition),
		E2K_TC_COND_MAS(__entry->condition),
		E2K_TC_COND_MISS_LVL(__entry->condition),
		E2K_TC_COND_RCV(__entry->condition),
		E2K_TC_COND_DST_RCV(__entry->condition),
		__print_flags(__entry->condition & E2K_TC_TYPE, "|",
				{ E2K_TC_TYPE_STORE, "store" },
				{ E2K_TC_TYPE_S_F, "s_f" },
				{ E2K_TC_TYPE_ROOT, "root" },
				{ E2K_TC_TYPE_SCAL, "scal" },
				{ E2K_TC_TYPE_SRU, "sru" },
				{ E2K_TC_TYPE_SPEC, "spec" },
				{ E2K_TC_TYPE_PM, "pm" },
				{ E2K_TC_TYPE_NUM_ALIGN, "num_align" },
				{ E2K_TC_TYPE_EMPT, "empt" },
				{ E2K_TC_TYPE_CLW, "clw" }
			),
		__print_flags(E2K_TC_COND_FTYPE(__entry->condition), "|",
				{ E2K_FTYPE_GLOBAL_SP, "global_sp" },
				{ E2K_FTYPE_EXC_MEM_LOCK__ILLEGAL_SMPH,
						"exc_mem_lock.illegal_smph" },
				{ E2K_FTYPE_EXC_MEM_LOCK__MEM_LOCK,
						"exc_mem_lock.mem_lock" },
				{ E2K_FTYPE_PH_PR_PAGE, "ph_pr_page" },
				{ E2K_FTYPE_IO_PAGE, "io_page" },
				{ E2K_FTYPE_ISYS_PAGE, "isys_page" },
				{ E2K_FTYPE_PROT_PAGE, "prot_page" },
				{ E2K_FTYPE_PRIV_PAGE, "priv_page" },
				{ E2K_FTYPE_ILLEGAL_PAGE, "illegal_page" },
				{ E2K_FTYPE_NWRITE_PAGE, "nwrite_page" },
				{ E2K_FTYPE_PAGE_MISS, "page_miss" },
				{ E2K_FTYPE_PH_BOUND, "ph_bound" },
				{ E2K_FTYPE_INTL_RES_BITS, "intl_res_bits" }
			))
);

DECLARE_EVENT_CLASS(address_pt_dtlb,
	TP_PROTO(unsigned long address, enum pt_dtlb_translation_mode mode),
	TP_ARGS(address, mode),

	TP_STRUCT__entry(
		__field(	u64,		address		)
		__field(	u64,		dtlb_entry	)
		__field(	u64,		dtlb_pud	)
		__field(	u64,		dtlb_pmd	)
		__field(	u64,		dtlb_pte	)
		__field(	pgd_t *,	pgdp		)
		__field(	pgdval_t,	pgd		)
		__field(	pudval_t,	pud		)
		__field(	pmdval_t,	pmd		)
		__field(	pteval_t,	pte		)
		__field(	int,		pt_level	)
		__field(	u8,		is_pt_v6	)
		__field(	u8,		is_dtlb_v6	)
		__field(	u8,		separate_tlu_cache	)
		__field(	u8,		print_user_only	)
		__field(	u8,		print_kernel_only	)
	),

	TP_fast_assign(
		__entry->address = (u64) address;
		if (mode == PT_DTLB_TRANSLATION_USER) {
			__entry->print_kernel_only = 0;
			__entry->print_user_only = 1;
		} else if (mode == PT_DTLB_TRANSLATION_KERNEL) {
			__entry->print_kernel_only = 1;
			__entry->print_user_only = 0;
		} else {
			__entry->print_kernel_only = 0;
			__entry->print_user_only = 0;
		}
		__entry->is_pt_v6 = MMU_IS_PT_V6();
		__entry->is_dtlb_v6 = MMU_IS_DTLB_V6();
		__entry->separate_tlu_cache = cpu_has(CPU_FEAT_SEPARATE_TLU_CACHE);

		trace_get_va_translation(current->mm, address,
			&__entry->pgd, &__entry->pud, &__entry->pmd,
			&__entry->pte, &__entry->pt_level, &__entry->pgdp, mode);

		/*
		 * Save DTLB entries.
		 *
		 * Do not access not existing entries to avoid
		 * creating "empty" records in DTLB for no reason.
		 */
		trace_get_dtlb_translation(current->mm, address,
			&__entry->dtlb_entry, &__entry->dtlb_pud,
			&__entry->dtlb_pmd, &__entry->dtlb_pte,
			__entry->pt_level, mode);
	),

	TP_printk("\n"
		"Address 0x%llx is from *%s* space%s%s\n"
		"Page table (all f's if entry hasn't been read)\n"
		"  pgd 0x%lx: %s%s (@0x%lx)\n"
		"  pud 0x%lx: %s%s\n"
		"  pmd 0x%lx: %s%s\n"
		"  pte 0x%lx: %s%s\n"
		"Probed DTLB entries:\n"
		"  pud 0x%llx: %s%s\n"
		"  pmd 0x%llx: %s%s\n"
		"  pte 0x%llx: %s%s\n"
		" addr 0x%llx: %s%s",
		__entry->address,
		(__entry->address < TASK_SIZE) ? "user" : "kernel",
		(__entry->print_user_only)
			? ", showing *user* page tables and DTLB" : "",
		(__entry->print_kernel_only)
			? ", showing *kernel* page tables and DTLB" : "",
		(__entry->pt_level <= E2K_PGD_LEVEL_NUM) ? __entry->pgd : -1UL,
		mmu_print_pt_flags(__entry->pgd,
				__entry->pt_level <= E2K_PGD_LEVEL_NUM, __entry->is_pt_v6),
		(unsigned long) __entry->pgdp,
		(__entry->pt_level <= E2K_PUD_LEVEL_NUM) ? __entry->pud : -1UL,
		mmu_print_pt_flags(__entry->pud,
				__entry->pt_level <= E2K_PUD_LEVEL_NUM, __entry->is_pt_v6),
		(__entry->pt_level <= E2K_PMD_LEVEL_NUM) ? __entry->pmd : -1UL,
		mmu_print_pt_flags(__entry->pmd,
				__entry->pt_level <= E2K_PMD_LEVEL_NUM, __entry->is_pt_v6),
		(__entry->pt_level <= E2K_PTE_LEVEL_NUM) ? __entry->pte : -1UL,
		mmu_print_pt_flags(__entry->pte,
				__entry->pt_level <= E2K_PTE_LEVEL_NUM, __entry->is_pt_v6),
		(__entry->pt_level <= E2K_PUD_LEVEL_NUM || __entry->separate_tlu_cache)
				? __entry->dtlb_pud : -1UL,
		mmu_print_dtlb_entry(__entry->dtlb_pud,
				     (__entry->pt_level <= E2K_PUD_LEVEL_NUM ||
				      __entry->separate_tlu_cache), __entry->is_dtlb_v6),
		(__entry->pt_level <= E2K_PMD_LEVEL_NUM || __entry->separate_tlu_cache)
				? __entry->dtlb_pmd : -1UL,
		mmu_print_dtlb_entry(__entry->dtlb_pmd,
				     (__entry->pt_level <= E2K_PMD_LEVEL_NUM ||
				      __entry->separate_tlu_cache), __entry->is_dtlb_v6),
		(__entry->pt_level <= E2K_PTE_LEVEL_NUM || __entry->separate_tlu_cache)
				? __entry->dtlb_pte : -1UL,
		mmu_print_dtlb_entry(__entry->dtlb_pte,
				     (__entry->pt_level <= E2K_PTE_LEVEL_NUM ||
				      __entry->separate_tlu_cache), __entry->is_dtlb_v6),
		__entry->dtlb_entry,
		mmu_print_dtlb_entry(__entry->dtlb_entry, 1 /* true */, __entry->is_dtlb_v6))
);

DEFINE_EVENT(address_pt_dtlb, unhandled_page_fault,
		TP_PROTO(unsigned long address, enum pt_dtlb_translation_mode mode),
		TP_ARGS(address, mode));

DEFINE_EVENT(address_pt_dtlb, trap_cellar_pt_dtlb,
		TP_PROTO(unsigned long address, enum pt_dtlb_translation_mode mode),
		TP_ARGS(address, mode));

TRACE_EVENT(
	tir,

	TP_PROTO(u64 tir_lo, u64 tir_hi),

	TP_ARGS(tir_lo, tir_hi),

	TP_STRUCT__entry(
		__field(	u64,	tir_lo	)
		__field(	u64,	tir_hi	)
	),

	TP_fast_assign(
		__entry->tir_lo = tir_lo;
		__entry->tir_hi = tir_hi;
	),

	TP_printk("TIR%lld ip=%pS als=0x%llx exc=%s",
		__entry->tir_hi >> 56, (void *) (__entry->tir_lo & E2K_VA_MASK),
		E2K_TIR_HI_ALS(__entry->tir_hi),
		E2K_TRACE_PRINT_TIR_HI(__entry->tir_hi))
);

/* How many last IPs are saved in hardware TIR_lo trace for debugging */
#define TIR_HW_TRACE_LENGTH 512
/* How many IPs to save to ring buffer in one event. Limited because:
 * 1) It is assumed by ring buffer internals that events are small.
 * 2) When dumping events with [ftrace_dump_on_oops] we are limited
 *    by printk() which outputs ~1000 symbols (LOG_LINE_MAX) at maximum. */
#define TIR_TRACE_LENGTH 16
#define TIR_TRACE_PARTS 32

/* Output last IPs executed before a trap _without_
 * regions that executed with frozen TIRs (i.e.
 * without trap entry up to UNFREEZE_TIRs() call). */
TRACE_EVENT(
	tir_ip_trace,

	TP_PROTO(int part),

	TP_ARGS(part),

	TP_STRUCT__entry(
		__field(int,	part)
		__array(void *, ip,	TIR_TRACE_LENGTH)
	),

	TP_fast_assign(
		int i;

		BUILD_BUG_ON(TIR_TRACE_PARTS * TIR_TRACE_LENGTH != TIR_HW_TRACE_LENGTH);
		BUG_ON(part < 1 || part > TIR_TRACE_PARTS);
		__entry->part = part;

		for (i = 0; i < TIR_TRACE_LENGTH; i++) {
			e2k_tir_lo_t tir_lo;

			/* Read additional debug TIRs */
			NATIVE_READ_TIR_HI_REG();
			tir_lo = NATIVE_READ_TIR_LO_REG();

			__entry->ip[i] = (void *) tir_lo.TIR_lo_ip;
		}

		/* For TP_printk below */
		BUILD_BUG_ON(TIR_TRACE_LENGTH != 16);
	),

	TP_printk("last %d IPs (part %d/%d):\n"
		"  %pS %pS %pS %pS\n"
		"  %pS %pS %pS %pS\n"
		"  %pS %pS %pS %pS\n"
		"  %pS %pS %pS %pS\n",
		TIR_TRACE_LENGTH * TIR_TRACE_PARTS, __entry->part, TIR_TRACE_PARTS,
		__entry->ip[0], __entry->ip[1], __entry->ip[2], __entry->ip[3],
		__entry->ip[4], __entry->ip[5], __entry->ip[6], __entry->ip[7],
		__entry->ip[8], __entry->ip[9], __entry->ip[10], __entry->ip[11],
		__entry->ip[12], __entry->ip[13], __entry->ip[14], __entry->ip[15]
		)
);

/* Trace `struct page` remapping to WC/UC
 * in drivers (usually video and sound). */
TRACE_EVENT(
	pfn_remap,

	TP_PROTO(phys_addr_t start, phys_addr_t end, bool check, const char *type),

	TP_ARGS(start, end, check, type),

	TP_STRUCT__entry(
		__field(phys_addr_t, start)
		__field(phys_addr_t, end)
		__field(bool, check)
		__field(const char *, type)
	),

	TP_fast_assign(
		__entry->start = start;
		__entry->end = end;
		__entry->check = check;
		__entry->type = type;
	),

	TP_printk("[mem 0x%llx-0x%llx] caching type %s %s",
			__entry->start, __entry->end - 1,
			(__entry->check) ? "checked against" : "changed to",
			__entry->type)
);

#endif /* _TRACE_E2K_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
