#ifndef _E2K_TRACE_DEFS_H_
#define _E2K_TRACE_DEFS_H_

#include <linux/types.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>

static inline void
trace_get_va_translation(struct mm_struct *mm, e2k_addr_t address,
	pgdval_t *pgd, pudval_t *pud, pmdval_t *pmd, pteval_t *pte, int *pt_level)
{
	pgd_t *pgdp;
	pud_t *pudp;
	pmd_t *pmdp;
	pte_t *ptep;

	if (likely(address < TASK_SIZE)) {
		pgdp = pgd_offset(mm, address);

		*pgd = pgd_val(*pgdp);
		*pt_level = E2K_PGD_LEVEL_NUM;

		if (!pgd_huge(*pgdp) && !pgd_none(*pgdp) && !pgd_bad(*pgdp)) {
			pudp = pud_offset(pgdp, address);

			*pud = pud_val(*pudp);
			*pt_level = E2K_PUD_LEVEL_NUM;

			if (!pud_huge(*pudp) && !pud_none(*pudp) &&
					!pud_bad(*pudp)) {
				pmdp = pmd_offset(pudp, address);

				*pmd = pmd_val(*pmdp);
				*pt_level = E2K_PMD_LEVEL_NUM;

				if (!pmd_huge(*pmdp) && !pmd_none(*pmdp) &&
						!pmd_bad(*pmdp)) {
					ptep = pte_offset_map(pmdp, address);

					*pte = pte_val(*ptep);
					*pt_level = E2K_PTE_LEVEL_NUM;
				}
			}
		}
		return;
	}

	pgdp = pgd_offset_k(address);
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
	u64 *dtlb_pgd, u64 *dtlb_pud, u64 *dtlb_pmd, u64 *dtlb_pte, int pt_level)
{
	*dtlb_pgd = get_MMU_DTLB_ENTRY(address);

	if (pt_level <= E2K_PUD_LEVEL_NUM)
		*dtlb_pud = get_MMU_DTLB_ENTRY(pud_virt_offset(address));

	if (pt_level <= E2K_PMD_LEVEL_NUM)
		*dtlb_pmd = get_MMU_DTLB_ENTRY(pmd_virt_offset(address));

	if (pt_level <= E2K_PTE_LEVEL_NUM)
		*dtlb_pte = get_MMU_DTLB_ENTRY(pte_virt_offset(address));
}

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

#endif /* _E2K_TRACE_DEFS_H_ */
