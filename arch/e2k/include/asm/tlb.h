#ifndef _E2K_TLB_H
#define _E2K_TLB_H

struct mmu_gather;

#define tlb_flush tlb_flush
static void tlb_flush(struct mmu_gather *tlb);

#include <asm-generic/tlb.h>

static inline void tlb_flush(struct mmu_gather *tlb)
{
	if (tlb->fullmm || tlb->need_flush_all) {
		flush_tlb_mm(tlb->mm);
	} else if (tlb->end) {
		unsigned long stride = tlb_get_unmap_size(tlb);
		u32 levels_mask = E2K_PAGES_LEVEL_MASK;

		if (tlb->freed_tables) {
			/* Note: if we ever have 5-level page tables then
			 * we'll have to unconditinally add P4D_LEVEL
			 * here since there is no corresponding bit in
			 * [struct mmu_gather] (or add the bit). */
			if (tlb->cleared_pmds)
				levels_mask |= E2K_PTE_LEVEL_MASK;
			if (tlb->cleared_puds)
				levels_mask |= E2K_PMD_LEVEL_MASK;
			if (tlb->cleared_p4ds)
				levels_mask |= E2K_PUD_LEVEL_MASK;
		}

		flush_tlb_mm_range(tlb->mm, tlb->start, tlb->end,
				   stride, levels_mask);
	}
}

#define __pud_free_tlb(tlb, pudp, start)	pud_free((tlb)->mm, pudp)
#define __pmd_free_tlb(tlb, pmdp, start)	pmd_free((tlb)->mm, pmdp)
#define __pte_free_tlb(tlb, ptep, addr)		pte_free((tlb)->mm, ptep)

#endif /* _E2K_TLB_H */
