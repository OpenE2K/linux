/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K page tables.
 * NOTE: E2K has four levels of page tables, while Linux assumes that
 * there are three levels of page tables.
 */

#include <linux/kernel.h>
#include <linux/spinlock.h>

#include <asm/pgtable_def.h>
#include <asm/system.h>
#include <asm/cpu_regs_access.h>
#include <asm/head.h>
#include <asm/bitops.h>
#include <asm/p2v/boot_head.h>
#include <asm/machdep.h>
#include <asm/secondary_space.h>
#include <asm/mmu_regs_access.h>
#include <asm/tlb_regs_access.h>
#include <asm/pgatomic.h>
#include <asm/pgtable.h>

#include <asm-generic/5level-fixup.h>

#include <asm/trace-pt-atomic.h>

#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
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
		trace_pt_atomic_update(mm, addr, (pgprot_t *)ptep,
				pte_val(oldpte), ATOMIC_GET_AND_XCHG);
	} else {
		oldpte = __pte(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) ptep));
		trace_pt_atomic_update(mm, addr, (pgprot_t *)ptep,
				pte_val(oldpte), ATOMIC_GET_AND_CLEAR);
	}

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (mm_users != 0 && pte_present_and_exec(oldpte))
		flush_pte_from_ic(oldpte);

	return oldpte;
}
#else	/* CONFIG_BOOT_E2K || E2K_P2V */
pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	pte_t oldpte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
	if (mm == &init_mm) {
		/* In kernel there is no swap or thp, valid page
		 * is always mapped, so do not keep the valid bit. */
		oldpte = __pte(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) ptep));
	} else {
		oldpte = __pte(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) ptep));
	}
	return oldpte;
}
#endif	/* !CONFIG_BOOT_E2K && !E2K_P2V */

int ptep_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr,
			      pte_t *ptep)
{
	pte_t pte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
	pte_val(pte) = pt_clear_young_atomic(vma->vm_mm, addr,
						(pgprot_t *)ptep);
	trace_pt_atomic_update(vma->vm_mm, addr, (pgprot_t *)ptep,
			pte_val(pte), ATOMIC_TEST_AND_CLEAR_YOUNG);
	return pte_young(pte);
}

void ptep_set_wrprotect(struct mm_struct *mm, unsigned long addr, pte_t *ptep)
{
	pte_t oldpte, newpte;

	prefetch_offset(ptep, PREFETCH_STRIDE);
	oldpte = *ptep;
	pte_val(newpte) = pt_set_wrprotect_atomic(mm, addr, (pgprot_t *) ptep);
	trace_pt_atomic_update(mm, addr, (pgprot_t *)ptep,
			pte_val(oldpte), ATOMIC_SET_WRPROTECT);
}

#if defined CONFIG_TRANSPARENT_HUGEPAGE
# if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)
pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp)
{
	int mm_users = atomic_read(&mm->mm_users);
	pmd_t oldpmd;

	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		oldpmd = __pmd(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pmdp));
		trace_pt_atomic_update(mm, addr, (pgprot_t *)pmdp,
				pmd_val(oldpmd), ATOMIC_GET_AND_XCHG);
	} else {
		oldpmd = __pmd(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pmdp));
		trace_pt_atomic_update(mm, addr, (pgprot_t *)pmdp,
				pmd_val(oldpmd), ATOMIC_GET_AND_CLEAR);
	}

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (mm_users != 0 && pmd_present_and_exec_and_huge(oldpmd))
		flush_pmd_from_ic(oldpmd);

	return oldpmd;
}

pud_t pudp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr, pud_t *pudp)
{
	int mm_users = atomic_read(&mm->mm_users);
	pud_t oldpud;

	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		oldpud = __pud(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pudp));
		trace_pt_atomic_update(mm, addr, (pgprot_t *)pudp,
				pud_val(oldpud), ATOMIC_GET_AND_XCHG);
	} else {
		oldpud = __pud(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pudp));
		trace_pt_atomic_update(mm, addr, (pgprot_t *)pudp,
				pud_val(oldpud), ATOMIC_GET_AND_CLEAR);
	}

	/* mm_users check is for the fork() case: we do not
	 * want to spend time flushing when we are exiting. */
	if (mm_users != 0 && pud_present_and_exec_and_huge(oldpud))
		flush_pud_from_ic(oldpud);

	return oldpud;
}
# else	/* CONFIG_BOOT_E2K || E2K_P2V */
pmd_t pmdp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp)
{
	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		return __pmd(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pmdp));
	} else {
		return __pmd(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pmdp));
	}
}

pud_t pudp_huge_get_and_clear(struct mm_struct *mm, unsigned long addr, pud_t *pudp)
{
	if (mm == &init_mm) {
		/* See comment in ptep_get_and_clear() */
		return __pud(pt_get_and_xchg_atomic(mm, addr, 0ull, (pgprot_t *) pudp));
	} else {
		return __pud(pt_get_and_clear_atomic(mm, addr, (pgprot_t *) pudp));
	}
}
# endif	/* !CONFIG_BOOT_E2K && !E2K_P2V */
#endif	/* CONFIG_TRANSPARENT_HUGEPAGE*/

int pmdp_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr, pmd_t *pmdp)
{
	pmd_t pmd = __pmd(pt_clear_young_atomic(vma->vm_mm, addr, (pgprot_t *) pmdp));
	trace_pt_atomic_update(vma->vm_mm, addr, (pgprot_t *)pmdp,
			pmd_val(pmd), ATOMIC_TEST_AND_CLEAR_YOUNG);
	return pmd_young(pmd);
}

int pudp_test_and_clear_young(struct vm_area_struct *vma, unsigned long addr, pud_t *pudp)
{
	pud_t pud = __pud(pt_clear_young_atomic(vma->vm_mm, addr, (pgprot_t *) pudp));
	trace_pt_atomic_update(vma->vm_mm, addr, (pgprot_t *)pudp,
			pud_val(pud), ATOMIC_TEST_AND_CLEAR_YOUNG);
	return pud_young(pud);
}

#ifdef CONFIG_TRANSPARENT_HUGEPAGE
void pmdp_set_wrprotect(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp)
{
	pmd_t oldpmd, newpmd;

	oldpmd = *pmdp;
	pmd_val(newpmd) = pt_set_wrprotect_atomic(mm, addr, (pgprot_t *)pmdp);
	trace_pt_atomic_update(mm, addr, (pgprot_t *)pmdp,
			pmd_val(oldpmd), ATOMIC_SET_WRPROTECT);
}

pmd_t pmdp_establish(struct vm_area_struct *vma, unsigned long address,
		     pmd_t *pmdp, pmd_t pmd)
{
	pmd_t oldpmd;

	oldpmd = __pmd(pt_get_and_xchg_relaxed(vma->vm_mm, address,
					       pmd_val(pmd), (pgprot_t *)pmdp));
	trace_pt_atomic_update(vma->vm_mm, address, (pgprot_t *)pmdp,
			pmd_val(oldpmd), ATOMIC_TEST_AND_CLEAR_RELAXED);
	return oldpmd;
}
#else	/* !CONFIG_TRANSPARENT_HUGEPAGE */
void pmdp_set_wrprotect(struct mm_struct *mm, unsigned long address, pmd_t *pmdp)
{
	BUILD_BUG();
}
#endif /* CONFIG_TRANSPARENT_HUGEPAGE */
