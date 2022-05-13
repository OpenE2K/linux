/*
 * E2K page table atomic update operations.
 *
 * Copyright 2018 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_KVM_GUEST_PGATOMIC_H
#define _E2K_KVM_GUEST_PGATOMIC_H

#include <linux/types.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>
#include <asm/kvm/hypervisor.h>

#ifdef	CONFIG_KVM_SHADOW_PT
extern pgprot_t kvm_pt_atomic_update(struct mm_struct *mm,
			unsigned long addr, pgprot_t *ptp,
			pt_atomic_op_t atomic_op, pgprotval_t prot_mask);
extern pgprot_t kvm_pt_atomic_clear_relaxed(pgprotval_t ptot_mask,
							pgprot_t *pgprot);

extern pte_t kvm_get_pte_for_address(struct vm_area_struct *vma,
					e2k_addr_t address);

static inline pgprotval_t
kvm_pt_set_wrprotect_atomic(struct mm_struct *mm,
				unsigned long addr, pgprot_t *pgprot)
{
	if (IS_HV_MMU_TDP()) {
		return native_pt_set_wrprotect_atomic(&pgprot->pgprot);
	} else {
		return pgprot_val(kvm_pt_atomic_update(mm, addr, pgprot,
				ATOMIC_SET_WRPROTECT, _PAGE_INIT_WRITEABLE));
	}
}

static inline pgprotval_t
kvm_pt_get_and_clear_atomic(struct mm_struct *mm,
				unsigned long addr, pgprot_t *pgprot)
{
	if (IS_HV_MMU_TDP()) {
		return native_pt_get_and_clear_atomic(&pgprot->pgprot);
	} else {
		return pgprot_val(kvm_pt_atomic_update(mm, addr, pgprot,
				ATOMIC_GET_AND_CLEAR, _PAGE_INIT_VALID));
	}
}

static inline pgprotval_t
kvm_pt_get_and_xchg_atomic(struct mm_struct *mm, unsigned long addr,
			pgprotval_t newval, pgprot_t *pgprot)
{
	if (IS_HV_MMU_TDP()) {
		return native_pt_get_and_xchg_atomic(newval, &pgprot->pgprot);
	} else {
		return pgprot_val(kvm_pt_atomic_update(mm, addr, pgprot,
				ATOMIC_GET_AND_XCHG, newval));
	}
}

static inline pgprotval_t
kvm_pt_get_and_xchg_relaxed(struct mm_struct *mm, unsigned long addr,
			pgprotval_t newval, pgprot_t *pgprot)
{
	if (IS_HV_MMU_TDP()) {
		return native_pt_get_and_xchg_relaxed(newval, &pgprot->pgprot);
	} else {
		return pgprot_val(kvm_pt_atomic_update(mm, addr, pgprot,
				ATOMIC_GET_AND_XCHG, newval));
	}
}

static inline pgprotval_t
kvm_pt_clear_relaxed_atomic(pgprotval_t prot_mask, pgprot_t *pgprot)
{
	if (IS_HV_MMU_TDP()) {
		return native_pt_clear_relaxed_atomic(prot_mask,
							&pgprot->pgprot);
	} else {
		return pgprot_val(kvm_pt_atomic_clear_relaxed(prot_mask,
								pgprot));
	}
}

static inline pgprotval_t
kvm_pt_clear_young_atomic(struct mm_struct *mm,
				unsigned long addr, pgprot_t *pgprot)
{
	if (IS_HV_MMU_TDP()) {
		return native_pt_clear_young_atomic(&pgprot->pgprot);
	} else {
		return pgprot_val(kvm_pt_atomic_update(mm, addr, pgprot,
					ATOMIC_TEST_AND_CLEAR_YOUNG,
					_PAGE_INIT_ACCESSED));
	}
}
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
 #error	"CONFIG_KVM_SHADOW_PT should be set for guest paravirtualized kernel"
#endif	/* CONFIG_KVM_SHADOW_PT */

#if	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is native guest kernel (without paravirtualization on pv_ops) */

static inline pgprotval_t
pt_set_wrprotect_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return kvm_pt_set_wrprotect_atomic(mm, addr, pgprot);
}

static inline pgprotval_t
pt_get_and_clear_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return kvm_pt_get_and_clear_atomic(mm, addr, pgprot);
}

static inline pgprotval_t
pt_get_and_xchg_atomic(struct mm_struct *mm, unsigned long addr,
				pgprotval_t newval, pgprot_t *pgprot)
{
	return kvm_pt_get_and_xchg_atomic(mm, addr, newval, pgprot);
}

static inline pgprotval_t
pt_get_and_xchg_relaxed(struct mm_struct *mm, unsigned long addr,
				pgprotval_t newval, pgprot_t *pgprot)
{
	return kvm_pt_get_and_xchg_relaxed(mm, addr, newval, pgprot);
}

static inline pgprotval_t
pt_clear_relaxed_atomic(pgprotval_t mask, pgprot_t *pgprot)
{
	return kvm_pt_clear_relaxed_atomic(mask, pgprot);
}

static inline pgprotval_t
pt_clear_young_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return kvm_pt_clear_young_atomic(mm, addr, pgprot);
}

static inline pte_t get_pte_for_address(struct vm_area_struct *vma,
						e2k_addr_t address)
{
	return kvm_get_pte_for_address(vma, address);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_KVM_GUEST_PGATOMIC_H */
