/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_TRACE_DEFS_H_
#define _E2K_TRACE_DEFS_H_

#include <linux/types.h>
#include <linux/hugetlb.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>


/* Workaround libtraceevent - use the simplest math possible */
#define E2K_TRACE_GET_FIELD(value, lo, size) \
	(((value) >> lo) & ((1ULL << size) - 1))
#define E2K_TC_COND_ADDRESS(cond)	E2K_TRACE_GET_FIELD(cond, 0, 8)
#define E2K_TC_COND_VR(cond)		E2K_TRACE_GET_FIELD(cond, 8, 1)
#define E2K_TC_COND_VL(cond)		E2K_TRACE_GET_FIELD(cond, 9, 1)
#define E2K_TC_COND_FMT(cond)		E2K_TRACE_GET_FIELD(cond, 10, 3)
#define E2K_TC_COND_NPSP(cond)		E2K_TRACE_GET_FIELD(cond, 13, 1)
#define E2K_TC_COND_FMTC(cond)		E2K_TRACE_GET_FIELD(cond, 14, 2)
#define E2K_TC_COND_MAS(cond)		E2K_TRACE_GET_FIELD(cond, 20, 7)
#define E2K_TC_COND_CHAN(cond)		E2K_TRACE_GET_FIELD(cond, 32, 2)
#define E2K_TC_COND_FTYPE(cond)		E2K_TRACE_GET_FIELD(cond, 35, 13)
#define E2K_TC_COND_MISS_LVL(cond)	E2K_TRACE_GET_FIELD(cond, 48, 2)
#define E2K_TC_COND_DST_RCV(cond)	E2K_TRACE_GET_FIELD(cond, 53, 10)
#define E2K_TC_COND_RCV(cond)		E2K_TRACE_GET_FIELD(cond, 63, 1)

#define E2K_TC_TYPE_STORE	_BITULL(17)
#define E2K_TC_TYPE_S_F		_BITULL(19)
#define E2K_TC_TYPE_ROOT	_BITULL(27)
#define E2K_TC_TYPE_SCAL	_BITULL(28)
#define E2K_TC_TYPE_SRU		_BITULL(29)
#define E2K_TC_TYPE_SPEC	_BITULL(30)
#define E2K_TC_TYPE_PM		_BITULL(31)
#define E2K_TC_TYPE_NUM_ALIGN	_BITULL(50)
#define E2K_TC_TYPE_EMPT	_BITULL(51)
#define E2K_TC_TYPE_CLW		_BITULL(52)

/* libtraceevent failed in parsing OR of all 'E2K_TC_TYPE_*' above,
 * so there is no other way but to define magical constant. */
#define E2K_TC_TYPE 0x1c0000f80a0000

#define E2K_FTYPE_GLOBAL_SP		_BITULL(0)
#define E2K_FTYPE_EXC_MEM_LOCK__ILLEGAL_SMPH _BITULL(1)
#define E2K_FTYPE_EXC_MEM_LOCK__MEM_LOCK  _BITULL(2)
#define E2K_FTYPE_PH_PR_PAGE		_BITULL(3)
#define E2K_FTYPE_IO_PAGE		_BITULL(4)
#define E2K_FTYPE_ISYS_PAGE		_BITULL(5)
#define E2K_FTYPE_PROT_PAGE		_BITULL(6)
#define E2K_FTYPE_PRIV_PAGE		_BITULL(7)
#define E2K_FTYPE_ILLEGAL_PAGE		_BITULL(8)
#define E2K_FTYPE_NWRITE_PAGE		_BITULL(9)
#define E2K_FTYPE_PAGE_MISS		_BITULL(10)
#define E2K_FTYPE_PH_BOUND		_BITULL(11)
#define E2K_FTYPE_INTL_RES_BITS		_BITULL(12)

/* See E2K_TC_TYPE above... */
#define TIRHI_EXC_MOVA_MASK	0x00f00fffffffffffULL
#define E2K_TIR_HI_ALS(tir_hi)	E2K_TRACE_GET_FIELD(tir_hi, 44, 6)
#define TIRHI_MOVA0_MASK	_BITULL(44)
#define TIRHI_MOVA1_MASK	_BITULL(45)
#define TIRHI_MOVA2_MASK	_BITULL(46)
#define TIRHI_MOVA3_MASK	_BITULL(47)

#define E2K_TRACE_PRINT_TIR_HI(entry) \
	__print_flags(entry & (TIRHI_EXC_MOVA_MASK), "|", \
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
		{ exc_mem_error_ICACHE_mask, "mem_error_ICACHE" })

enum pt_dtlb_translation_mode {
	PT_DTLB_TRANSLATION_AUTO,
	PT_DTLB_TRANSLATION_USER,
	PT_DTLB_TRANSLATION_KERNEL
};

static inline void
trace_get_va_translation(struct mm_struct *mm, e2k_addr_t address,
		pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte,
		int *pt_level, pgd_t **return_pgdp,
		enum pt_dtlb_translation_mode mode)
{
	bool user = (mode == PT_DTLB_TRANSLATION_USER ||
		     mode == PT_DTLB_TRANSLATION_AUTO && address < TASK_SIZE);
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	if (user) {
		pgdp = pgd_offset(mm, address);
		if (return_pgdp) {
			*return_pgdp = pgdp;
		}
		*pgd = pgd_val(*pgdp);
		*pt_level = E2K_PGD_LEVEL_NUM;

		if (!pgd_huge(*pgdp) && !pgd_none(*pgdp) && !pgd_bad(*pgdp)) {
			pudp = pud_offset(pgdp, address);

			*pud = pud_val(*pudp);
			*pt_level = E2K_PUD_LEVEL_NUM;

			if (!user_pud_huge(*pudp) && !pud_none(*pudp) &&
					!pud_bad(*pudp)) {
				pmdp = pmd_offset(pudp, address);

				*pmd = pmd_val(*pmdp);
				*pt_level = E2K_PMD_LEVEL_NUM;

				if (!user_pmd_huge(*pmdp) && !pmd_none(*pmdp) &&
						!pmd_bad(*pmdp)) {
					ptep = pte_offset_map(pmdp, address);

					*pte = pte_val(*ptep);
					*pt_level = E2K_PTE_LEVEL_NUM;
				}
			}
		}
		return;
	}

	pgdp = mm_node_pgd(&init_mm, numa_node_id()) + pgd_index(address);
	if (return_pgdp) {
		*return_pgdp = pgdp;
	}
	*pgd = pgd_val(*pgdp);
	*pt_level = E2K_PGD_LEVEL_NUM;

	if (!kernel_pgd_huge(*pgdp) && !pgd_none(*pgdp) && !pgd_bad(*pgdp)) {
		pudp = pud_offset(pgdp, address);
		*pud = pud_val(*pudp);
		*pt_level = E2K_PUD_LEVEL_NUM;

		if (!kernel_pud_huge(*pudp) && !pud_none(*pudp) &&
				!pud_bad(*pudp)) {
			pmdp = pmd_offset(pudp, address);
			*pmd = pmd_val(*pmdp);
			*pt_level = E2K_PMD_LEVEL_NUM;

			if (!kernel_pmd_huge(*pmdp) && !pmd_none(*pmdp) &&
					!pmd_bad(*pmdp)) {
				ptep = pte_offset_kernel(pmdp, address);
				*pte = pte_val(*ptep);
				*pt_level = E2K_PTE_LEVEL_NUM;
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
static inline void
trace_get_dtlb_translation(struct mm_struct *mm, e2k_addr_t address,
		u64 *dtlb_entry, u64 *dtlb_pud, u64 *dtlb_pmd, u64 *dtlb_pte,
		int pt_level, enum pt_dtlb_translation_mode mode)
{
	unsigned long request;
	bool user = (mode == PT_DTLB_TRANSLATION_USER ||
		     mode == PT_DTLB_TRANSLATION_AUTO && IS_USER_VPTB_ADDR(address));

	/* On CPUs with separate TLU cache we can safely access
	 * all entries without the risk of creating false
	 * PMD->PTE links for huge pages. */
	if (cpu_has(CPU_FEAT_SEPARATE_TLU_CACHE))
		pt_level = E2K_PAGES_LEVEL_NUM;

	if (user)
		uaccess_enable();

	*dtlb_entry = get_MMU_DTLB_ENTRY(address);

	if (pt_level <= E2K_PUD_LEVEL_NUM) {
		request = (user) ? pud_virt_offset_u(address) : pud_virt_offset_k(address);
		*dtlb_pud = get_MMU_DTLB_ENTRY(request);
	}

	if (pt_level <= E2K_PMD_LEVEL_NUM) {
		request = (user) ? pmd_virt_offset_u(address) : pmd_virt_offset_k(address);
		*dtlb_pmd = get_MMU_DTLB_ENTRY(request);
	}

	if (pt_level <= E2K_PTE_LEVEL_NUM) {
		request = (user) ? pte_virt_offset_u(address) : pte_virt_offset_k(address);
		*dtlb_pte = get_MMU_DTLB_ENTRY(request);
	}

	if (user)
		uaccess_disable();
}

#define	mmu_print_pt_flags(entry, print, mmu_pt_v6) \
		((mmu_pt_v6) ? E2K_TRACE_PRINT_PT_V6_FLAGS(entry, print) \
			     : E2K_TRACE_PRINT_PT_V3_FLAGS(entry, print)), \
		((mmu_pt_v6) ? E2K_TRACE_PRINT_PT_V6_MT(entry, print) \
			     : E2K_TRACE_PRINT_PT_V3_MT(entry, print))

#define	mmu_print_dtlb_entry(entry, print, mmu_dtlb_v6) \
		((mmu_dtlb_v6) ? E2K_TRACE_PRINT_DTLB_ENTRY_V6_FLAGS(entry, print) \
			       : E2K_TRACE_PRINT_DTLB_ENTRY_V3_FLAGS(entry, print)), \
		((mmu_dtlb_v6) ? E2K_TRACE_PRINT_DTLB_ENTRY_V6_MT(entry, print) \
			       : E2K_TRACE_PRINT_DTLB_ENTRY_V3_MT(entry, print))

#endif /* _E2K_TRACE_DEFS_H_ */
