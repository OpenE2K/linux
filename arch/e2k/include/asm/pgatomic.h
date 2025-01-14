/*
 * E2K page table atomic update operations.
 *
 * Copyright 2001-2018 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PGATOMIC_H
#define _E2K_PGATOMIC_H

/*
 * This file contains the functions and defines necessary to modify and
 * use the E2K page tables.
 * NOTE: E2K has four levels of page tables, while Linux assumes that
 * there are three levels of page tables.
 */

#include <linux/types.h>

#include <asm/mmu_types.h>
#include <asm/pgtable_def.h>
#include <asm/atomic_api.h>

/*
 * Atomic operations under page table items.
 * WARNING: these values should be agreed with guest kernel because of
 * are used by hypercall to support atomic modifications on guest.
 * So do not change/delete the values, only can add new operations and values.
 */
typedef enum pt_atomic_op {
	ATOMIC_GET_AND_XCHG,
	ATOMIC_GET_AND_CLEAR,
	ATOMIC_SET_WRPROTECT,
	ATOMIC_TEST_AND_CLEAR_YOUNG,
	ATOMIC_TEST_AND_CLEAR_RELAXED,
} pt_atomic_op_t;

#define PTE_ATOMIC_OP_NAME						\
	{ ATOMIC_GET_AND_XCHG,		"Get and Exchange" },		\
	{ ATOMIC_GET_AND_CLEAR,		"Get and Clear" },		\
	{ ATOMIC_SET_WRPROTECT,		"Set Write Protect" },		\
	{ ATOMIC_TEST_AND_CLEAR_YOUNG,	"Test and Clear Young" },	\
	{ ATOMIC_TEST_AND_CLEAR_RELAXED, "Test and Clear Relaxed" }

static inline pgprotval_t
native_pt_set_wrprotect_atomic(pgprotval_t *pgprot)
{
	pgprotval_t newval = __api_atomic_op(_PAGE_INIT_WRITEABLE, pgprot,
					     d, "andnd", RELAXED_MB);
	trace_pt_update("pt_set_wrprotect: entry at 0x%lx: -> 0x%lx\n",
			pgprot, newval);
	return newval;
}

static inline pgprotval_t
native_pt_get_and_clear_atomic(pgprotval_t *pgprot)
{
	pgprotval_t oldval = __api_atomic_fetch_op(_PAGE_INIT_VALID, pgprot,
						   d, "andd", RELAXED_MB);
	trace_pt_update("pt_get_and_clear: entry at 0x%lx: 0x%lx -> 0x%lx\n",
			pgprot, oldval, oldval & _PAGE_INIT_VALID);
	return oldval;
}

static inline pgprotval_t
native_pt_get_and_xchg_atomic(pgprotval_t newval, pgprotval_t *pgprot)
{
	pgprotval_t oldval = __api_xchg_return(newval, pgprot, d, RELAXED_MB);
	trace_pt_update("pt_get_and_xchg: entry at 0x%lx: 0x%lx -> 0x%lx\n",
			pgprot, oldval, newval);
	return oldval;
}

static inline pgprotval_t
native_pt_get_and_xchg_relaxed(pgprotval_t newval, pgprotval_t *pgprot)
{
	pgprotval_t oldval = xchg_relaxed(pgprot, newval);
	trace_pt_update("pt_get_and_xchg_relaxed: entry at 0x%lx: 0x%lx -> 0x%lx\n",
			pgprot, oldval, newval);
	return oldval;
}

static inline pgprotval_t
native_pt_clear_relaxed_atomic(pgprotval_t mask, pgprotval_t *pgprot)
{
	pgprotval_t oldval = __api_atomic_fetch_op(mask, pgprot, d,
						   "andnd", RELAXED_MB);
	trace_pt_update("pt_clear: entry at 0x%lx: 0x%lx -> 0x%lx\n",
			pgprot, oldval, oldval & ~mask);
	return oldval;
}

static inline pgprotval_t
native_pt_clear_young_atomic(pgprotval_t *pgprot)
{
	pgprotval_t oldval = __api_atomic_fetch_op(_PAGE_INIT_ACCESSED, pgprot,
						   d, "andnd", RELAXED_MB);
	trace_pt_update("pt_clear_young: entry at 0x%lx: 0x%lx -> 0x%lx\n",
			pgprot, oldval, oldval & ~_PAGE_INIT_ACCESSED);
	return oldval;
}

#if	defined(CONFIG_KVM_GUEST_KERNEL)
/* It is native guest kernel (without paravirtualization on pv_ops) */
#include <asm/kvm/guest/pgatomic.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* paravirtualized host and guest kernel on pv_ops */
#include <asm/paravirt/pgatomic.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* native kernel without virtualization support */
/* host kernel with virtualization support */

static inline pgprotval_t
pt_set_wrprotect_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return native_pt_set_wrprotect_atomic(&pgprot->pgprot);
}

static inline pgprotval_t
pt_get_and_clear_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return native_pt_get_and_clear_atomic(&pgprot->pgprot);
}

static inline pgprotval_t
pt_get_and_xchg_atomic(struct mm_struct *mm, unsigned long addr,
				pgprotval_t newval, pgprot_t *pgprot)
{
	return native_pt_get_and_xchg_atomic(newval, &pgprot->pgprot);
}

static inline pgprotval_t
pt_get_and_xchg_relaxed(struct mm_struct *mm, unsigned long addr,
				pgprotval_t newval, pgprot_t *pgprot)
{
	return native_pt_get_and_xchg_relaxed(newval, &pgprot->pgprot);
}

static inline pgprotval_t
pt_clear_relaxed_atomic(pgprotval_t mask, pgprot_t *pgprot)
{
	return native_pt_clear_relaxed_atomic(mask, &pgprot->pgprot);
}

static inline pgprotval_t
pt_clear_young_atomic(struct mm_struct *mm,
			unsigned long addr, pgprot_t *pgprot)
{
	return native_pt_clear_young_atomic(&pgprot->pgprot);
}
#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! _E2K_PGATOMIC_H */
