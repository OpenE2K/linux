#ifndef _HUGETLB_H_
#define _HUGETLB_H_

#include <asm/page.h>
#include <asm/e2k.h>

void set_huge_pte_at(struct mm_struct *mm, unsigned long addr,
		     pte_t *ptep, pte_t pte);

pte_t huge_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
			      pte_t *ptep);

static inline void hugetlb_prefault_arch_hook(struct mm_struct *mm)
{
}

static inline void arch_clear_hugepage_flags(struct page *page)
{
}

static inline int is_hugepage_only_range(struct mm_struct *mm,
					 unsigned long addr,
					 unsigned long len) 
{
	return 0;
}

static inline int prepare_hugepage_range(struct file *file,
			unsigned long addr, unsigned long len)
{
	if (len & ~HPAGE_MASK)
		return -EINVAL;
	if (addr & ~HPAGE_MASK)
		return -EINVAL;
	return 0;
}

static inline void hugetlb_free_pgd_range(struct mmu_gather *tlb,
					  unsigned long addr, unsigned long end,
					  unsigned long floor,
					  unsigned long ceiling)
{
	free_pgd_range(tlb, addr, end, floor, ceiling);
}

static inline void huge_ptep_clear_flush(struct vm_area_struct *vma,
					 unsigned long addr, pte_t *ptep)
{
}

static inline int huge_pte_none(pte_t pte)
{
#ifndef	CONFIG_MAKE_ALL_PAGES_VALID
	return pte_none(pte);
#else	/* CONFIG_MAKE_ALL_PAGES_VALID */
#ifndef CONFIG_SECONDARY_SPACE_SUPPORT
	return ((pte_val(pte) & ~(_PAGE_VALID | _PAGE_HUGE)) == 0);
#else	/* CONFIG_SECONDARY_SPACE_SUPPORT */
	return ((pte_val(pte) &
			~(_PAGE_VALID | _PAGE_HUGE | _PAGE_SEC_MAP)) == 0);
#endif	/* !CONFIG_SECONDARY_SPACE_SUPPORT */
#endif	/* !CONFIG_MAKE_ALL_PAGES_VALID */
}

static inline pte_t huge_pte_wrprotect(pte_t pte)
{
	return pte_wrprotect(pte);
}

static inline void huge_ptep_set_wrprotect(struct mm_struct *mm,
					   unsigned long addr, pte_t *ptep)
{
	ptep_set_wrprotect(mm, addr, ptep);
	if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
		ptep_set_wrprotect(mm, addr, ++ptep);
}

static inline int huge_ptep_set_access_flags(struct vm_area_struct *vma,
					     unsigned long addr, pte_t *ptep,
					     pte_t pte, int dirty)
{
	int changed = !pte_same(*ptep, pte);
	if (changed) {
		set_pte_at(vma->vm_mm, addr, ptep, pte);
		if (E2K_LARGE_PAGE_SIZE == E2K_4M_PAGE_SIZE)
			set_pte_at(vma->vm_mm, addr, ++ptep, pte);
	}
	return changed;
}

static inline pte_t huge_ptep_get(pte_t *ptep)
{
	return *ptep;
}

static inline int arch_prepare_hugepage(struct page *page)
{
	return 0;
}

static inline void arch_release_hugepage(struct page *page)
{
}

static inline pte_t mk_huge_pte(struct page *page, pgprot_t pgprot)
{
	return mk_pte(page, pgprot);
}

static inline int huge_pte_write(pte_t pte)
{
	return pte_write(pte);
}

static inline int huge_pte_dirty(pte_t pte)
{
	return pte_dirty(pte);
}

static inline pte_t huge_pte_mkwrite(pte_t pte)
{
	return pte_mkwrite(pte);
}

static inline pte_t huge_pte_mkdirty(pte_t pte)
{
	return pte_mkdirty(pte);
}

static inline pte_t huge_pte_modify(pte_t pte, pgprot_t newprot)
{
	return pte_modify(pte, newprot);
}

static inline void huge_pte_clear(struct mm_struct *mm, unsigned long address,
				  pte_t *page_table)
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


#endif /* _HUGETLB_H_ */
