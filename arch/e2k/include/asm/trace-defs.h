#ifndef _E2K_TRACE_DEFS_H_
#define _E2K_TRACE_DEFS_H_

#include <linux/types.h>
#include <linux/hugetlb.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>

enum pt_dtlb_translation_mode {
	PT_DTLB_TRANSLATION_AUTO,
	PT_DTLB_TRANSLATION_USER,
	PT_DTLB_TRANSLATION_KERNEL
};

static inline void
trace_get_va_translation(struct mm_struct *mm, e2k_addr_t address,
		pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte,
		int *pt_level, enum pt_dtlb_translation_mode mode)
{
	bool user = (mode == PT_DTLB_TRANSLATION_USER ||
		     mode == PT_DTLB_TRANSLATION_AUTO && address < TASK_SIZE);
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	if (user) {
		pgdp = pgd_offset(mm, address);

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
#define	print_pt_flags(entry, print)	\
		mmu_print_pt_flags(entry, print, MMU_IS_PT_V6())

#define	E2K_TRACE_PRINT_PT_FLAGS(entry, print)	print_pt_flags(entry, print)


#define	mmu_print_dtlb_entry(entry, print, mmu_dtlb_v6) \
		((mmu_dtlb_v6) ? E2K_TRACE_PRINT_DTLB_ENTRY_V6_FLAGS(entry, print) \
			       : E2K_TRACE_PRINT_DTLB_ENTRY_V3_FLAGS(entry, print)), \
		((mmu_dtlb_v6) ? E2K_TRACE_PRINT_DTLB_ENTRY_V6_MT(entry, print) \
			       : E2K_TRACE_PRINT_DTLB_ENTRY_V3_MT(entry, print))
#define	print_dtlb_entry(entry, print)	\
		mmu_print_dtlb_entry(entry, (print), MMU_IS_DTLB_V6())

#define	E2K_TRACE_PRINT_DTLB(entry, print)	print_dtlb_entry(entry, (print))

#endif /* _E2K_TRACE_DEFS_H_ */
