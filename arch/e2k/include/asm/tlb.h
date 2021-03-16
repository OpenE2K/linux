#ifndef _E2K_TLB_H
#define _E2K_TLB_H

#include <linux/swap.h>


static inline void __tlb_remove_table(void *_table)
{
	free_page_and_swap_cache((struct page *)_table);
}

#define tlb_flush(tlb)							\
{									\
	if (!(tlb)->fullmm && !(tlb)->need_flush_all)			\
		flush_tlb_mm_range((tlb)->mm, (tlb)->start, (tlb)->end); \
	else								\
		flush_tlb_mm((tlb)->mm);				\
}

#define tlb_start_vma(tlb, vma) \
do {				\
} while (0)

#define tlb_end_vma(tlb, vma)	\
do {				\
} while (0)

#define __tlb_remove_tlb_entry(tlb, ptep, address) \
	do { } while (0)

#include <asm-generic/tlb.h>

#define __pud_free_tlb(tlb, pudp, start)	pud_free((tlb)->mm, pudp)
#define __pmd_free_tlb(tlb, pmdp, start)	pmd_free((tlb)->mm, pmdp)
#define __pte_free_tlb(tlb, ptep, addr)		pte_free((tlb)->mm, ptep)

#endif /* _E2K_TLB_H */
