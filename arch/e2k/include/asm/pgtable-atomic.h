/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * E2K page table operations.
 */

#ifndef _E2K_PGTABLE_ATOMIC_H
#define _E2K_PGTABLE_ATOMIC_H

/*
 * atomic versions of the some PTE manipulations:
 */

#ifdef	CONFIG_TRACE_PT_ATOMIC
extern pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep);
extern int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
				     pte_t *ptep);
extern void ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr,
			       pte_t *ptep);
extern pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr,
				     pmd_t *pmdp);
extern pud_t pudp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr,
				     pud_t *pudp);
extern int pmdp_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pmd_t *pmdp);
extern int pudp_test_and_clear_young(struct vm_area_struct *vma,
				     unsigned long addr, pud_t *pudp);
extern void pmdp_set_wrprotect(struct mm_struct *mm,
			       unsigned long addr, pmd_t *pmdp);
extern pmd_t pmdp_establish(struct vm_area_struct *vma, unsigned long address,
			    pmd_t *pmdp, pmd_t pmd);

#else	/* !CONFIG_TRACE_PT_ATOMIC */

#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pte_t *ptep)
{
	int mm_users = atomic_read(&mm->mm_users);
	pte_t oldpte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
	if (mm == &init_mm) {
		/* In kernel there is no swap or thp, valid page
		 * is always mapped, so do not keep the valid bit.
		 * This is important because in kernel we cannot
		 * tolerate spurious page faults from h.-s. loads. */
		oldpte = __pte(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) ptep));
	} else {
		oldpte = __pte(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) ptep));
	}

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (mm_users != 0 && pte_present_and_exec(oldpte))
		flush_pte_from_ic(oldpte);

	return oldpte;
}
#else
static inline pte_t ptep_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pte_t *ptep)
{
	prefetch_offset(ptep, PREFETCH_STRIDE);
	if (mm == &init_mm) {
		/* In kernel there is no swap or thp, valid page
		 * is always mapped, so do not keep the valid bit. */
		return __pte(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) ptep));
	} else {
		return __pte(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) ptep));
	}
}
#endif

static inline int
ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
				pte_t *ptep)
{
	pte_t pte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
	pte_val(pte) = pt_clear_young_atomic(vma->vm_mm, addr,
						(pgprot_t *)ptep);
	return pte_young(pte);
}

static inline void
ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	prefetch_offset(ptep, PREFETCH_STRIDE);
	pt_set_wrprotect_atomic(mm, addr, (pgprot_t *) ptep);
}

#if defined CONFIG_TRANSPARENT_HUGEPAGE
# if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pmd_t *pmdp)
{
	int mm_users = atomic_read(&mm->mm_users);
	pmd_t oldpmd;

	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		oldpmd = __pmd(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pmdp));
	} else {
		oldpmd = __pmd(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pmdp));
	}

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (mm_users != 0 && pmd_present_and_exec_and_huge(oldpmd))
		flush_pmd_from_ic(oldpmd);

	return oldpmd;
}

static inline pud_t pudp_huge_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pud_t *pudp)
{
	int mm_users = atomic_read(&mm->mm_users);
	pud_t oldpud;

	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		oldpud = __pud(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pudp));
	} else {
		oldpud = __pud(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pudp));
	}

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (mm_users != 0 && pud_present_and_exec_and_huge(oldpud))
		flush_pud_from_ic(oldpud);

	return oldpud;
}
# else	/* CONFIG_BOOT_E2K || E2K_P2V */
static inline pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pmd_t *pmdp)
{
	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		return __pmd(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pmdp));
	} else {
		return __pmd(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pmdp));
	}
}

static inline pud_t pudp_huge_get_and_clear(struct mm_struct *mm,
		unsigned long addr, pud_t *pudp)
{
	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		return __pud(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pudp));
	} else {
		return __pud(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pudp));
	}
}
# endif
#endif	/* CONFIG_TRANSPARENT_HUGEPAGE */

static inline int pmdp_test_and_clear_young(struct vm_area_struct *vma,
					    unsigned long addr, pmd_t *pmdp)
{
	pmd_t pmd = __pmd(pt_clear_young_atomic(vma->vm_mm, addr, (pgprot_t *) pmdp));
	return pmd_young(pmd);
}

static inline int pudp_test_and_clear_young(struct vm_area_struct *vma,
					    unsigned long addr, pud_t *pudp)
{
	pud_t pud = __pud(pt_clear_young_atomic(vma->vm_mm, addr, (pgprot_t *) pudp));
	return pud_young(pud);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long addr, pmd_t *pmdp)
{
	pt_set_wrprotect_atomic(mm, addr, (pgprot_t *)pmdp);
}

#define pmdp_establish pmdp_establish
static inline pmd_t pmdp_establish(struct vm_area_struct *vma,
		unsigned long address, pmd_t *pmdp, pmd_t pmd)
{
	return __pmd(pt_get_and_xchg_relaxed(vma->vm_mm, address,
					     pmd_val(pmd), (pgprot_t *)pmdp));
}
#else	/* !CONFIG_TRANSPARENT_HUGEPAGE */
static inline void pmdp_set_wrprotect(struct mm_struct *mm,
				      unsigned long address, pmd_t *pmdp)
{
	BUILD_BUG();
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */

#endif	/* CONFIG_TRACE_PT_ATOMIC */

#endif /* !_E2K_PGTABLE_ATOMIC_H */
