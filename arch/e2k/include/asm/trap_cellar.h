/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 MCST
 */

#include <asm/cpu_features.h>
#include <asm/mas.h>
#include <asm/mmu_types.h>

/*
 * Helpers for decoding instruction type from trap cellar
 */

static inline int tc_cond_fmt_full(tc_cond_t c)
{
	return c.fmt | (c.fmtc << 3);
}

static inline e2k_mas_t tc_cond_mas(tc_cond_t c)
{
	return (e2k_mas_t) { .word = c.mas };
}

/* "check" load */
static inline bool tc_cond_is_check(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && !c.spec && !c.store && !mas.masf2.m1 && mas.masf2.mod == 2 &&
		(c.chan == 1 || c.chan == 3 || c.fmt == LDST_QWORD_FMT);
}

/* "check & unlock" load */
static inline bool tc_cond_is_check_unlock(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && !c.spec && !c.store && !mas.masf2.m1 && mas.masf2.mod == 3 &&
		(c.chan == 1 || c.chan == 3 || c.fmt == LDST_QWORD_FMT);
}

/* "fill operation" load */
static inline bool tc_cond_is_fill_operation(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && !c.spec && !c.store && !mas.masf2.m1 && mas.masf2.mod == 4;
}

/* "lock check" load */
static inline bool tc_cond_is_lock_check(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && c.spec && !c.store &&
		(!mas.masf2.m1 && mas.masf2.mod == 4 ||
		 cpu_has(CPU_FEAT_ISET_V6) && mas.v6.masf4.m1 && mas.v6.masf4.m2 == 1) &&
		(c.chan == 0 || c.chan == 2 || c.fmt == LDST_QWORD_FMT);
}

/* "lock wait" and "lock wait 1" loads */
static inline bool tc_cond_is_lock_wait(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);

	return !c.root && !c.spec && !c.store && !mas.masf2.m1 &&
		(mas.masf2.mod == 7 && c.chan == 0 && c.fmt != LDST_QWORD_FMT ||
		 cpu_has(CPU_FEAT_ISET_V5) && mas.masf2.mod == 5 &&
			(c.chan == 0 || c.chan == 1 && c.fmt == LDST_QWORD_FMT));
}

/* "normal" load or store */
static inline bool tc_cond_is_normal(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && !c.spec &&
		(!mas.masf2.m1 && mas.masf2.mod == 0 ||
		 cpu_has(CPU_FEAT_ISET_V6) && mas.v6.masf4.m1 && mas.v6.masf4.m2 == 0);
}

/* "semi-speculative" load */
static inline bool tc_cond_is_semi_speculative(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && c.spec && !c.store &&
		(!mas.masf2.m1 && mas.masf2.mod == 0 ||
		 cpu_has(CPU_FEAT_ISET_V6) && mas.v6.masf4.m1 && mas.v6.masf4.m2 == 0);
}

/* "secondary lock wait" load */
static inline bool tc_cond_is_secondary_lock_wait(tc_cond_t c)
{
	return c.root && !c.spec && !c.store && c.mas == 0x78;
}

/* "secondary lock trap on store" load */
static inline bool tc_cond_is_secondary_lock_trap_on_store(tc_cond_t c)
{
	return c.root && !c.spec && !c.store && (c.mas & 3) == 1 &&
			(c.chan == 0 || c.chan == 1 && c.fmt == LDST_QWORD_FMT);
}

/* "secondary lock trap on load/store" load */
static inline bool tc_cond_is_secondary_lock_trap_on_load_store(tc_cond_t c)
{
	return c.root && !c.spec && !c.store && (c.mas & 3) == 2 &&
			(c.chan == 0 || c.chan == 1 && c.fmt == LDST_QWORD_FMT);
}

/* "secondary store & unlock" store */
static inline bool tc_cond_is_secondary_store_unlock(tc_cond_t c)
{
	return c.root && c.store && (c.mas & 3) == 1 &&
		(c.chan <= 2 || c.fmt == LDST_QWORD_FMT);
}

/* "secondary unlock" store */
static inline bool tc_cond_is_secondary_unlock(tc_cond_t c)
{
	int fmt_full = tc_cond_fmt_full(c);
	return c.root && c.store && (c.mas & 3) == 2 &&
		(c.chan <= 2 || c.fmt == LDST_QWORD_FMT ||
		 fmt_full == TC_FMT_DWORD_Q || fmt_full == TC_FMT_DWORD_QP);
}

/* "special MMU/AAU" loads and stores */
static inline bool tc_cond_is_special_mmu_aau(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	if (unlikely(mas.masf1.mod == 7 &&
		     (c.store || !c.store && !c.spec && (c.chan == 1 || c.chan == 3))))
		return true;

	return false;
}

/* "spec lock check" load */
static inline bool tc_cond_is_spec_lock_check(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && c.spec && !c.store &&
		(!mas.masf2.m1 && mas.masf2.mod == 7 ||
		 cpu_has(CPU_FEAT_ISET_V6) && mas.v6.masf4.m1 && mas.v6.masf4.m2 == 3) &&
		(c.chan == 0 || c.chan == 2 || c.fmt == LDST_QWORD_FMT);
}

/* "speculative" load; this is _different_ from semi-speculative loads! */
static inline bool tc_cond_is_speculative(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	return !c.root && c.spec && !c.store &&
		(!mas.masf2.m1 && mas.masf2.mod == 3 ||
		 cpu_has(CPU_FEAT_ISET_V6) && mas.v6.masf4.m1 && mas.v6.masf4.m2 == 2);
}

/* "unlock" store */
static inline bool tc_cond_is_unlock(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);
	int fmt_full = tc_cond_fmt_full(c);
	return !c.root && c.store && !mas.masf2.m1 && mas.masf2.mod == 5 &&
		(c.chan <= 2 || c.fmt == LDST_QWORD_FMT ||
		 fmt_full == TC_FMT_DWORD_Q || fmt_full == TC_FMT_DWORD_QP);
}

/* "watch for modification" loads */
static inline bool tc_cond_is_watch_for_modification(tc_cond_t c)
{
	e2k_mas_t mas = tc_cond_mas(c);

	return cpu_has(CPU_FEAT_ISET_V6) && !c.root && !c.spec && !c.store &&
		mas.v6.masf4.m1 && mas.v6.masf4.m2 == 1 &&
		(c.chan == 0 || c.chan == 1 && c.fmt == LDST_QWORD_FMT);
}

static inline bool tc_cond_is_big_endian(tc_cond_t c)
{
	if (tc_cond_is_special_mmu_aau(c) || c.root)
		return false;

	/* MASF1 ("special MMU/AAU") has been handled so this is MASF{2-4} */
	return tc_cond_mas(c).masf2.be;
}

static inline bool tc_cond_is_vector_aau(tc_cond_t cond)
{
	/* We use bitwise OR for performance */
	return !(cond.scal | cond.sru | cond.clw);
}

/*
 * Caveat: for qword accesses this will return 16 bytes for
 * the first entry in trap cellar and 8 bytes for the second one.
 */
static inline int tc_cond_to_size(tc_cond_t cond)
{
	const int fmt = tc_cond_fmt_full(cond);
	int size;

	if (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q) {
		size = 16;
	} else if (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP) {
		if (cond.chan == 0 || cond.chan == 2)
			size = 16;
		else
			size = 8;
	} else if (fmt == TC_FMT_DWORD_Q || fmt == TC_FMT_DWORD_QP) {
		size = 8;
#ifdef CONFIG_KVM_PARAVIRTUALIZATION
	} else if (tc_test_is_as_kvm_injected(cond)) {
		/* format is fake value, set size to 1 byte */
		size = 1;
#endif /* CONFIG_KVM_PARAVIRTUALIZATION */
	} else {
		size = 1 << ((fmt & 0x7) - 1);
	}

	return size;
}

static inline bool tc_cond_check_reserved_fmt(tc_cond_t condition)
{
	const int fmt = tc_cond_fmt_full(condition);

	return tc_fmt_check_reserved(fmt);
}

/*
 * Returns if this is a store instruction or a load instruction that
 * requires write permission (e.g. as part of atomic operation).
 */
static inline bool tc_cond_is_store(tc_cond_t condition)
{
	if (condition.store && condition.mas != MAS_CACHE_LINE_FLUSH)
		return true;

	return tc_cond_is_lock_wait(condition) ||
	       tc_cond_is_secondary_lock_wait(condition) ||
	       tc_cond_is_secondary_lock_trap_on_load_store(condition);
}