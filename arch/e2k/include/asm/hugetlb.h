#ifndef _ASM_E2K_HUGETLB_H_
#define _ASM_E2K_HUGETLB_H_

#include <linux/mm.h>

#include <asm/e2k.h>
#include <asm/mman.h>
#include <asm/tlbflush.h>


extern void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
					pte_t *ptep, pte_t pte);
extern pte_t huge_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
					pte_t *ptep);


static inline void arch_clear_hugepage_flags(struct page *page)
{
}

static inline int is_hugepage_only_range(struct mm_struct *mm,
					 unsigned long addr,
					 unsigned long len) 
{
	return 0;
}

#define __HAVE_ARCH_HUGE_PTEP_CLEAR_FLUSH
static inline void huge_ptep_clear_flush(struct vm_area_struct *vma,
					 unsigned long addr, pte_t *ptep)
{
}

#define __HAVE_ARCH_HUGE_PTE_NONE
static inline int huge_pte_none(pte_t pte)
{
#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
	return _PAGE_CLEAR(pte_val(pte), UNI_PAGE_HUGE) == 0;
#else	/* CONFIG_MAKE_ALL_PAGES_VALID */
	return _PAGE_CLEAR(pte_val(pte), UNI_PAGE_VALID | UNI_PAGE_HUGE) == 0;
#endif	/* !CONFIG_MAKE_ALL_PAGES_VALID */
}

#define __HAVE_ARCH_HUGE_PTEP_SET_WRPROTECT
static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	ptep_set_wrprotect(mm, addr, ptep);
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
		ptep_set_wrprotect(mm, addr, ++ptep);
}

#define __HAVE_ARCH_HUGE_PTEP_SET_ACCESS_FLAGS
static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
					     unsigned long addr, pte_t *ptep,
					     pte_t pte, int dirty)
{
	int changed = !pte_same(*ptep, pte);
	if (changed) {
		set_pte_at(vma->vm_mm, addr, ptep, pte);
		if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
			set_pte_at(vma->vm_mm, addr, ++ptep, pte);
		flush_tlb_range(vma, addr, addr + PMD_SIZE);
	}
	return changed;
}

#define __HAVE_ARCH_HUGE_PTE_CLEAR
static inline void huge_pte_clear(struct mm_struct *mm, unsigned long address,
				  pte_t *page_table, unsigned long sz)
{
	/*
	 * In this case virtual page occupied two sequential entries in
	 * page table on 2-th level (PMD).
	 * All two pte's (pmd's) should be cleared.
	 */
	pte_clear(mm, address, page_table);
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
		pte_clear(mm, address, (++page_table));
}

#define __HAVE_ARCH_HUGE_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT
#define __HAVE_ARCH_HUGE_PTEP_GET_AND_CLEAR
#define __HAVE_ARCH_HUGE_SET_HUGE_PTE_AT

#include <asm-generic/hugetlb.h>

#endif /* _ASM_E2K_HUGETLB_H_ */
