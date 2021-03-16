#undef TRACE_SYSTEM
#define TRACE_SYSTEM e2k

#if !defined(_TRACE_E2K_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_E2K_H

#include <linux/tracepoint.h>
#include <linux/hugetlb.h>
#include <asm/mmu_fault.h>
#include <asm/mmu_types.h>
#include <asm/page.h>
#include <asm/pgtable_def.h>
#include <asm/trace_pgtable-v2.h>
#include <asm/trace_pgtable-v6.h>
#include <asm/trace-mmu-dtlb-v2.h>
#include <asm/trace-mmu-dtlb-v6.h>
#include <asm/trap_def.h>

#define E2K_TC_TYPE_STORE	(1ULL << 17)
#define E2K_TC_TYPE_S_F		(1ULL << 19)
#define E2K_TC_TYPE_ROOT	(1ULL << 27)
#define E2K_TC_TYPE_SCAL	(1ULL << 28)
#define E2K_TC_TYPE_SRU		(1ULL << 29)
#define E2K_TC_TYPE_SPEC	(1ULL << 30)
#define E2K_TC_TYPE_PM		(1ULL << 31)
#define E2K_TC_TYPE_NUM_ALIGN	(1ULL << 50)
#define E2K_TC_TYPE_EMPT	(1ULL << 51)
#define E2K_TC_TYPE_CLW		(1ULL << 52)

#define E2K_TC_TYPE (E2K_TC_TYPE_STORE | E2K_TC_TYPE_S_F | E2K_TC_TYPE_ROOT | \
		     E2K_TC_TYPE_SCAL | E2K_TC_TYPE_SRU | E2K_TC_TYPE_SPEC | \
		     E2K_TC_TYPE_PM | E2K_TC_TYPE_NUM_ALIGN | \
		     E2K_TC_TYPE_EMPT | E2K_TC_TYPE_CLW)

#define E2K_FAULT_TYPE_GLOBAL_SP	(1ULL << 0)
#define E2K_FAULT_TYPE_PAGE_BOUND	(1ULL << 1)
#define E2K_FAULT_TYPE_EXC_MEM_LOCK	(1ULL << 2)
#define E2K_FAULT_TYPE_PH_PR_PAGE	(1ULL << 3)
#define E2K_FAULT_TYPE_IO_PAGE		(1ULL << 4)
#define E2K_FAULT_TYPE_ISYS_PAGE	(1ULL << 5)
#define E2K_FAULT_TYPE_PROT_PAGE	(1ULL << 6)
#define E2K_FAULT_TYPE_PRIV_PAGE	(1ULL << 7)
#define E2K_FAULT_TYPE_ILLEGAL_PAGE	(1ULL << 8)
#define E2K_FAULT_TYPE_NWRITE_PAGE	(1ULL << 9)
#define E2K_FAULT_TYPE_PAGE_MISS	(1ULL << 10)
#define E2K_FAULT_TYPE_PH_BOUND		(1ULL << 11)
#define E2K_FAULT_TYPE_INTL_RES_BITS	(1ULL << 12)

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
		"Register: address=0x%02hhx, vl=%d, vr=%d\n"
		"Opcode:  fmt=%d, n_prot=%d, fmtc=%d\n"
		"Info1:   chan=%d, mas=0x%02hhx, miss_lvl=%d, rcv=%d, dst_rcv=0x%03x\n"
		"Info2:   %s\n"
		"Ftype:   %s"
		,
		__entry->nr, __entry->address, __entry->data_tag,
		__entry->data_val, __entry->data_ext_tag, __entry->data_ext_val,
		AS((tc_cond_t) __entry->condition).address,
		AS((tc_cond_t) __entry->condition).vl,
		AS((tc_cond_t) __entry->condition).vr,
		AS((tc_cond_t) __entry->condition).fmt,
		AS((tc_cond_t) __entry->condition).npsp,
		AS((tc_cond_t) __entry->condition).fmtc,
		AS((tc_cond_t) __entry->condition).chan,
		AS((tc_cond_t) __entry->condition).mas,
		AS((tc_cond_t) __entry->condition).miss_lvl,
		AS((tc_cond_t) __entry->condition).rcv,
		AS((tc_cond_t) __entry->condition).dst_rcv,
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
		__print_flags(AS((tc_cond_t) __entry->condition).fault_type, "|",
				{ E2K_FAULT_TYPE_GLOBAL_SP, "global_sp" },
				{ E2K_FAULT_TYPE_PAGE_BOUND, "page_bound" },
				{ E2K_FAULT_TYPE_EXC_MEM_LOCK, "exc_mem_lock" },
				{ E2K_FAULT_TYPE_PH_PR_PAGE, "ph_pr_page" },
				{ E2K_FAULT_TYPE_IO_PAGE, "io_page" },
				{ E2K_FAULT_TYPE_ISYS_PAGE, "isys_page" },
				{ E2K_FAULT_TYPE_PROT_PAGE, "prot_page" },
				{ E2K_FAULT_TYPE_PRIV_PAGE, "priv_page" },
				{ E2K_FAULT_TYPE_ILLEGAL_PAGE, "illegal_page" },
				{ E2K_FAULT_TYPE_NWRITE_PAGE, "nwrite_page" },
				{ E2K_FAULT_TYPE_PAGE_MISS, "page_miss" },
				{ E2K_FAULT_TYPE_PH_BOUND, "ph_bound" },
				{ E2K_FAULT_TYPE_INTL_RES_BITS, "intl_res_bits" }
			))
);

#define	mmu_print_pt_flags(entry, print, mmu_pt_v6) \
		(mmu_pt_v6) ? E2K_TRACE_PRINT_PT_V6_FLAGS(entry, print) \
				: \
				E2K_TRACE_PRINT_PT_V2_FLAGS(entry, print)
#define	print_pt_flags(entry, print)	\
		mmu_print_pt_flags(entry, print, MMU_IS_PT_V6())

#define	E2K_TRACE_PRINT_PT_FLAGS(entry, print)	print_pt_flags(entry, print)


#define	mmu_print_dtlb_entry(entry, mmu_dtlb_v6) \
		((mmu_dtlb_v6) ? E2K_TRACE_PRINT_DTLB_ENTRY_V2(entry) \
				: \
				E2K_TRACE_PRINT_DTLB_ENTRY_V6(entry))
#define	print_dtlb_entry(entry)	\
		mmu_print_dtlb_entry(entry, MMU_IS_DTLB_V6())

#define	E2K_TRACE_PRINT_DTLB(entry)	print_dtlb_entry(entry)

TRACE_EVENT(
	unhandled_page_fault,

	TP_PROTO(unsigned long address),

	TP_ARGS(address),

	TP_STRUCT__entry(
		__field(	unsigned long,	address		)
		__field(	u64,		dtlb_entry	)
		__field(	u64,		dtlb_pud	)
		__field(	u64,		dtlb_pmd	)
		__field(	u64,		dtlb_pte	)
		__field(	u64,		pgd		)
		__field(	u64,		pud		)
		__field(	u64,		pmd		)
		__field(	u64,		pte		)
		__field(	int,		pt_level	)
	),

	TP_fast_assign(
		pgd_t *pgdp;
		pud_t *pudp;
		pmd_t *pmdp;
		pte_t *ptep;

		__entry->address = address;

		/*
		 * Save page table entries
		 */
		__entry->pt_level = 0;

		if (address < TASK_SIZE) {
			struct mm_struct *mm = current->mm;

			pgdp = pgd_offset(mm, address);

			__entry->pgd = pgd_val(*pgdp);
			__entry->pt_level = 1;

			if (!pgd_huge(*pgdp) && !pgd_none(*pgdp) &&
			    !pgd_bad(*pgdp)) {
				pudp = pud_offset(pgdp, address);

				__entry->pud = pud_val(*pudp);
				__entry->pt_level = 2;

				if (!pud_huge(*pudp) && !pud_none(*pudp) &&
				    !pud_bad(*pudp)) {
					pmdp = pmd_offset(pudp, address);

					__entry->pmd = pmd_val(*pmdp);
					__entry->pt_level = 3;

					if (!pmd_huge(*pmdp) &&
					    !pmd_none(*pmdp) &&
					    !pmd_bad(*pmdp)) {
						ptep = pte_offset_map(pmdp,
								address);

						__entry->pte = pte_val(*ptep);
						__entry->pt_level = 4;
					}
				}
			}
		} else {
			pgdp = pgd_offset_k(address);

			__entry->pgd = pgd_val(*pgdp);
			__entry->pt_level = 1;

			if (!kernel_pgd_huge(*pgdp) &&
			    !pgd_none(*pgdp) && !pgd_bad(*pgdp)) {
				pudp = pud_offset(pgdp, address);

				__entry->pud = pud_val(*pudp);
				__entry->pt_level = 2;

				if (!kernel_pud_huge(*pudp) &&
				    !pud_none(*pudp) && !pud_bad(*pudp)) {
					pmdp = pmd_offset(pudp, address);

					__entry->pmd = pmd_val(*pmdp);
					__entry->pt_level = 3;

					if (!kernel_pmd_huge(*pmdp) &&
					    !pmd_none(*pmdp) &&
					    !pmd_bad(*pmdp)) {
						ptep = pte_offset_kernel(pmdp,
								address);

						__entry->pte = pte_val(*ptep);
						__entry->pt_level = 4;
					}
				}
			}
		}

		/*
		 * Save DTLB entries.
		 *
		 * Do not access not existing entries to avoid
		 * creating "empty" records in DTLB for no reason.
		 */
		__entry->dtlb_entry = get_MMU_DTLB_ENTRY(address);

		if (__entry->pt_level >= 2)
			__entry->dtlb_pud = get_MMU_DTLB_ENTRY(
					pud_virt_offset(address));

		if (__entry->pt_level >= 3)
			__entry->dtlb_pmd = get_MMU_DTLB_ENTRY(
					pmd_virt_offset(address));

		if (__entry->pt_level >= 4)
			__entry->dtlb_pte = get_MMU_DTLB_ENTRY(
					pte_virt_offset(address));
	),

	TP_printk("\n"
		"Page table for address 0x%lx (all f's are returned if the entry has not been read)\n"
		"  pgd 0x%llx: %s\n"
		"    Access mode: %s%s\n"
		"  pud 0x%llx: %s\n"
		"    Access mode: %s%s\n"
		"  pmd 0x%llx: %s\n"
		"    Access mode: %s%s\n"
		"  pte 0x%llx: %s\n"
		"    Access mode: %s%s\n"
		"Probed DTLB entries:\n"
		"  pud address entry 0x%llx: %s\n"
		"  pmd address entry 0x%llx: %s\n"
		"  pte address entry 0x%llx: %s\n"
		"      address entry 0x%llx: %s"
		,
		__entry->address,
		(__entry->pt_level >= 1) ? __entry->pgd : -1ULL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->pgd, __entry->pt_level >= 1),
		(__entry->pt_level >= 2) ? __entry->pud : -1ULL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->pud, __entry->pt_level >= 2),
		(__entry->pt_level >= 3) ? __entry->pmd : -1ULL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->pmd, __entry->pt_level >= 3),
		(__entry->pt_level >= 4) ? __entry->pte : -1ULL,
		E2K_TRACE_PRINT_PT_FLAGS(__entry->pte, __entry->pt_level >= 4),
		(__entry->pt_level >= 2) ? __entry->dtlb_pud : -1ULL,
		(__entry->pt_level >= 2) ?
			E2K_TRACE_PRINT_DTLB(__entry->dtlb_pud) : "(not read)",
		(__entry->pt_level >= 3) ? __entry->dtlb_pmd : -1ULL,
		(__entry->pt_level >= 3) ?
			E2K_TRACE_PRINT_DTLB(__entry->dtlb_pmd) : "(not read)",
		(__entry->pt_level >= 4) ? __entry->dtlb_pte : -1ULL,
		(__entry->pt_level >= 4) ?
			E2K_TRACE_PRINT_DTLB(__entry->dtlb_pte) : "(not read)",
		__entry->dtlb_entry,
		E2K_TRACE_PRINT_DTLB(__entry->dtlb_entry))
);

#define TIRHI_EXC_MASK		0x00000fffffffffffULL
#define TIRHI_ALS_MASK		0x0003f00000000000ULL
#define TIRHI_ALS_SHIFT		44ULL
#define TIRHI_MOVA_MASK		0x00f0000000000000ULL
#define TIRHI_MOVA0_MASK	0x0010000000000000ULL
#define TIRHI_MOVA1_MASK	0x0020000000000000ULL
#define TIRHI_MOVA2_MASK	0x0040000000000000ULL
#define TIRHI_MOVA3_MASK	0x0080000000000000ULL

#define E2K_TRACE_PRINT_TIR_HI(entry) \
	(entry & (TIRHI_EXC_MASK | TIRHI_MOVA_MASK)) ? \
		__print_flags(entry & (TIRHI_EXC_MASK | TIRHI_MOVA_MASK), "|", \
			{ TIRHI_MOVA0_MASK, "mova0" }, \
			{ TIRHI_MOVA1_MASK, "mova1" }, \
			{ TIRHI_MOVA2_MASK, "mova2" }, \
			{ TIRHI_MOVA3_MASK, "mova3" }, \
			{ exc_illegal_opcode_mask, "illegal_opcode" }, \
			{ exc_priv_action_mask, "priv_action" }, \
			{ exc_fp_disabled_mask, "fp_disabled" }, \
			{ exc_fp_stack_u_mask, "fp_stack_u" }, \
			{ exc_d_interrupt_mask, "d_interrupt" }, \
			{ exc_diag_ct_cond_mask, "diag_ct_cond" }, \
			{ exc_diag_instr_addr_mask, "diag_instr_addr" }, \
			{ exc_illegal_instr_addr_mask, "illegal_instr_addr" }, \
			{ exc_instr_debug_mask, "instr_debug" }, \
			{ exc_window_bounds_mask, "window_bounds" }, \
			{ exc_user_stack_bounds_mask, "user_stack_bounds" }, \
			{ exc_proc_stack_bounds_mask, "proc_stack_bounds" }, \
			{ exc_chain_stack_bounds_mask, "chain_stack_bounds" }, \
			{ exc_fp_stack_o_mask, "fp_stack_o" }, \
			{ exc_diag_cond_mask, "diag_cond" }, \
			{ exc_diag_operand_mask, "diag_operand" }, \
			{ exc_illegal_operand_mask, "illegal_operand" }, \
			{ exc_array_bounds_mask, "array_bounds" }, \
			{ exc_access_rights_mask, "access_rights" }, \
			{ exc_addr_not_aligned_mask, "addr_not_aligned" }, \
			{ exc_instr_page_miss_mask, "instr_page_miss" }, \
			{ exc_instr_page_prot_mask, "instr_page_prot" }, \
			{ exc_ainstr_page_miss_mask, "ainstr_page_miss" }, \
			{ exc_ainstr_page_prot_mask, "ainstr_page_prot" }, \
			{ exc_last_wish_mask, "last_wish" }, \
			{ exc_base_not_aligned_mask, "base_not_aligned" }, \
			{ exc_software_trap_mask, "software_trap" }, \
			{ exc_data_debug_mask, "data_debug" }, \
			{ exc_data_page_mask, "data_page" }, \
			{ exc_recovery_point_mask, "recovery_point" }, \
			{ exc_interrupt_mask, "interrupt" }, \
			{ exc_nm_interrupt_mask, "nm_interrupt" }, \
			{ exc_div_mask, "div" }, \
			{ exc_fp_mask, "fp" }, \
			{ exc_mem_lock_mask, "mem_lock" }, \
			{ exc_mem_lock_as_mask, "mem_lock_as" }, \
			{ exc_mem_error_out_cpu_mask, "mem_error_out_cpu" }, \
			{ exc_mem_error_MAU_mask, "mem_error_MAU" }, \
			{ exc_mem_error_L2_mask, "mem_error_L2" }, \
			{ exc_mem_error_L1_35_mask, "mem_error_L1_35" }, \
			{ exc_mem_error_L1_02_mask, "mem_error_L1_02" }, \
			{ exc_mem_error_ICACHE_mask, "mem_error_ICACHE" } \
			) : "(none)"

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

	TP_printk("\n"
		"TIR%lld: ip 0x%llx, als 0x%llx\n"
		"      exceptions: %s"
		,
		__entry->tir_hi >> 56,
		__entry->tir_lo & E2K_VA_MASK,
		(__entry->tir_hi & TIRHI_ALS_MASK) >> TIRHI_ALS_SHIFT,
		E2K_TRACE_PRINT_TIR_HI(__entry->tir_hi)
		)
);


#endif /* _TRACE_E2K_H */

/* This part must be outside protection */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../arch/e2k/include/asm
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace
#include <trace/define_trace.h>
