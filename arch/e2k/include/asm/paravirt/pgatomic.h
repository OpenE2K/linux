/*
 * E2K paravirtualized page table atomic operations.
 *
 * Copyright 2018 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PARAVIRT_PGATOMIC_H
#define _E2K_PARAVIRT_PGATOMIC_H

#include <linux/types.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>
#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/pgatomic.h>

static inline pgprotval_t
pv_pt_set_wrprotect_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	if (paravirt_enabled()) {
		return kvm_pt_set_wrprotect_atomic(mm, addr, pgprot);
	} else {
		return native_pt_set_wrprotect_atomic(&pgprot->pgprot);
	}
}

static inline pgprotval_t
pv_pt_get_and_clear_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	if (paravirt_enabled()) {
		return kvm_pt_get_and_clear_atomic(mm, addr, pgprot);
	} else {
		return native_pt_get_and_clear_atomic(&pgprot->pgprot);
	}
}

static inline pgprotval_t
pv_pt_get_and_xchg_atomic(struct mm_struct *mm, unsigned long addr,
				pgprotval_t newval, pgprot_t *pgprot)
{
	if (paravirt_enabled()) {
		return kvm_pt_get_and_xchg_atomic(mm, addr, newval, pgprot);
	} else {
		return native_pt_get_and_xchg_atomic(newval, &pgprot->pgprot);
	}
}

static inline pgprotval_t
pv_pt_clear_relaxed_atomic(pgprotval_t mask, pgprot_t *pgprot)
{
	if (paravirt_enabled()) {
		return kvm_pt_clear_relaxed_atomic(mask, pgprot);
	} else {
		return native_pt_clear_relaxed_atomic(mask, &pgprot->pgprot);
	}
}

static inline pgprotval_t
pv_pt_clear_young_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	if (paravirt_enabled()) {
		return kvm_pt_clear_young_atomic(mm, addr, pgprot);
	} else {
		return native_pt_clear_young_atomic(&pgprot->pgprot);
	}
}

static inline pgprotval_t
pv_pt_modify_prot_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	if (paravirt_enabled()) {
		return kvm_pt_modify_prot_atomic(mm, addr, pgprot);
	} else {
		return native_pt_modify_prot_atomic(&pgprot->pgprot);
	}
}

#if	defined(CONFIG_PARAVIRT_GUEST)
/* It is paravirtualized host and guest kernel */

static inline pgprotval_t
pt_set_wrprotect_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return pv_pt_set_wrprotect_atomic(mm, addr, pgprot);
}

static inline pgprotval_t
pt_get_and_clear_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return pv_pt_get_and_clear_atomic(mm, addr, pgprot);
}

static inline pgprotval_t
pt_get_and_xchg_atomic(struct mm_struct *mm, unsigned long addr,
				pgprotval_t newval, pgprot_t *pgprot)
{
	return pv_pt_get_and_xchg_atomic(mm, addr, newval, pgprot);
}

static inline pgprotval_t
pt_clear_relaxed_atomic(pgprotval_t mask, pgprot_t *pgprot)
{
	return pv_pt_clear_relaxed_atomic(mask, pgprot);
}

static inline pgprotval_t
pt_clear_young_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return pv_pt_clear_young_atomic(mm, addr, pgprot);
}

static inline pgprotval_t
pt_modify_prot_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return pv_pt_modify_prot_atomic(mm, addr, pgprot);
}
#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* ! _E2K_PARAVIRT_PGATOMIC_H */
