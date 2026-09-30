/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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

		/* Not possible to check strictly whether there was a _huge_
		 * pud change, but clearing puds is a rare enough event that
		 * this flush shouldn't affect performance. */
		if (cpu_has(CPU_HWBUG_GIGANTIC_FLUSH) && tlb->cleared_puds)
			flush_tlb_mm_page(tlb->mm, 0ul);
	}
}

static inline void __pud_free_tlb(struct mmu_gather *tlb, pud_t *pudp,
				  unsigned long address)
{
	tlb_remove_page(tlb, virt_to_page(pudp));
}

static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmdp,
				  unsigned long address)
{
	struct page *page = virt_to_page(pmdp);

	pgtable_pmd_page_dtor(page);
	tlb_remove_page(tlb, page);
}

static inline void __pte_free_tlb(struct mmu_gather *tlb, struct page *pte,
				  unsigned long address)
{
	pgtable_pte_page_dtor(pte);
	tlb_remove_page(tlb, pte);
}

#endif /* _E2K_TLB_H */
