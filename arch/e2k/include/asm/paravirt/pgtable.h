#ifndef __ASM_PARAVIRT_PGTABLE_H
#define __ASM_PARAVIRT_PGTABLE_H

#ifdef __KERNEL__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline void
pv_write_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval,
			bool only_validate, bool to_move)
{
	pv_mmu_ops.write_pte_at(mm, addr, ptep, pteval, only_validate, to_move);
}
static inline void
pv_set_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval)
{
	pv_write_pte_at(mm, addr, ptep, pteval, false, false);
}
static inline void
pv_validate_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval)
{
	pv_write_pte_at(mm, addr, ptep, pteval, true, false);
}
static inline void boot_pv_set_pte_at(unsigned long addr,
				pte_t *ptep, pte_t pteval)
{
	BOOT_PARAVIRT_GET_MMU_FUNC(boot_set_pte_at)(addr, ptep, pteval);
}
/* private case set pte for guest kernel address */
static inline void pv_set_pte(pte_t *ptep, pte_t pteval)
{
	pv_mmu_ops.set_pte(ptep, pteval);
}

static inline void
pv_write_pmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmdval,
			bool only_validate)
{
	pv_mmu_ops.write_pmd_at(mm, addr, pmdp, pmdval, only_validate);
}
static inline void
pv_set_pmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmdval)
{
	pv_write_pmd_at(mm, addr, pmdp, pmdval, false);
}
static inline void
pv_validate_pmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmdval)
{
	pv_write_pmd_at(mm, addr, pmdp, pmdval, true);
}

static inline void
pv_write_pud_at(struct mm_struct *mm, unsigned long addr,
			pud_t *pudp, pud_t pudval,
			bool only_validate)
{
	pv_mmu_ops.write_pud_at(mm, addr, pudp, pudval, only_validate);
}
static inline void
pv_set_pud_at(struct mm_struct *mm, unsigned long addr,
			pud_t *pudp, pud_t pudval)
{
	pv_write_pud_at(mm, addr, pudp, pudval, false);
}
static inline void
pv_validate_pud_at(struct mm_struct *mm, unsigned long addr,
			pud_t *pudp, pud_t pudval)
{
	pv_write_pud_at(mm, addr, pudp, pudval, true);
}

static inline void
pv_write_pgd_at(struct mm_struct *mm, unsigned long addr,
			pgd_t *pgdp, pgd_t pgdval,
			bool only_validate)
{
	pv_mmu_ops.write_pgd_at(mm, addr, pgdp, pgdval, only_validate);
}
static inline void
pv_set_pgd_at(struct mm_struct *mm, unsigned long addr,
			pgd_t *pgdp, pgd_t pgdval)
{
	pv_write_pgd_at(mm, addr, pgdp, pgdval, false);
}
static inline void
pv_validate_pgd_at(struct mm_struct *mm, unsigned long addr,
			pgd_t *pgdp, pgd_t pgdval)
{
	pv_write_pgd_at(mm, addr, pgdp, pgdval, true);
}

static inline pte_t pv_ptep_get_and_clear(struct mm_struct *mm,
				unsigned long addr, pte_t *ptep)
{
	return pv_mmu_ops.ptep_get_and_clear(mm, addr, ptep, false);
}
static inline void pv_ptep_wrprotect_atomic(struct mm_struct *mm,
						e2k_addr_t addr, pte_t *ptep)
{
	if (pv_mmu_ops.ptep_wrprotect_atomic)
		pv_mmu_ops.ptep_wrprotect_atomic(mm, addr, ptep);
}

static inline pte_t pv_get_pte_for_address(struct vm_area_struct *vma,
					e2k_addr_t address)
{
	return pv_mmu_ops.get_pte_for_address(vma, address);
}

#ifdef	CONFIG_PARAVIRT_GUEST

#include <asm/paravirt/pv_info.h>

#define set_pte_not_present_at set_pte_at
static inline void
set_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval)
{
	pv_set_pte_at(mm, addr, ptep, pteval);
}
static inline void
validate_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval)
{
	pv_validate_pte_at(mm, addr, ptep, pteval);
}
static inline void boot_set_pte_at(unsigned long addr,
					pte_t *ptep, pte_t pteval)
{
	boot_pv_set_pte_at(addr, ptep, pteval);
}
static inline void set_pte(pte_t *ptep, pte_t pteval)
{
	pv_set_pte(ptep, pteval);
}

static inline void
set_pmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmdval)
{
	pv_set_pmd_at(mm, addr, pmdp, pmdval);
}
static inline void
validate_pmd_at(struct mm_struct *mm, unsigned long addr, pmd_t *pmdp,
		pmd_t pmdval)
{
	pv_validate_pmd_at(mm, addr, pmdp, pmdval);
}

static inline void
set_pud_at(struct mm_struct *mm, unsigned long addr,
			pud_t *pudp, pud_t pudval)
{
	pv_set_pud_at(mm, addr, pudp, pudval);
}
static inline void
validate_pud_at(struct mm_struct *mm, unsigned long addr, pud_t *pudp)
{
	pv_validate_pud_at(mm, addr, pudp, __pud(_PAGE_INIT_VALID));
}
static inline void
invalidate_pud_at(struct mm_struct *mm, unsigned long addr, pud_t *pudp)
{
	pv_validate_pud_at(mm, addr, pudp, __pud(0));
}

static inline void
set_pgd_at(struct mm_struct *mm, unsigned long addr,
			pgd_t *pgdp, pgd_t pgdval)
{
	pv_set_pgd_at(mm, addr, pgdp, pgdval);
}
static inline void
validate_pgd_at(struct mm_struct *mm, unsigned long addr, pgd_t *pgdp)
{
	pv_validate_pgd_at(mm, addr, pgdp, __pgd(_PAGE_INIT_VALID));
}
static inline void
invalidate_pgd_at(struct mm_struct *mm, unsigned long addr, pgd_t *pgdp)
{
	pv_validate_pgd_at(mm, addr, pgdp, __pgd(0));
}

static inline pte_t ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep)
{
	return pv_ptep_get_and_clear(mm, addr, ptep);
}
static inline void ptep_wrprotect_atomic(struct mm_struct *mm,
						e2k_addr_t addr, pte_t *ptep)
{
	pv_ptep_wrprotect_atomic(mm, addr, ptep);
}

static inline pte_t get_pte_for_address(struct vm_area_struct *vma,
						e2k_addr_t address)
{
	return pv_get_pte_for_address(vma, address);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __KERNEL__ */

#endif	/* __ASM_PARAVIRT_PGTABLE_H */
