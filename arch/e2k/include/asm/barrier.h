/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_BARRIER_H
#define _ASM_E2K_BARRIER_H

#include <linux/compiler.h>

#include <asm/e2k_api.h>
#include <asm/atomic_api.h>

#if CONFIG_CPU_ISET_MIN >= 6
/* Cannot use this on V5 because of load-after-store dependencies -
 * compiled kernel won't honour them */
# define mb()	E2K_WAIT(_st_c | _ld_c | _sas | _sal | _las | _lal)
#else
# define mb()	E2K_WAIT(_st_c | _ld_c)
#endif
#define wmb()	E2K_WAIT(_st_c | _sas)
#define rmb()	E2K_WAIT(_ld_c | _lal)

/*
 * For smp_* variants add _mt modifier
 */
#if CONFIG_CPU_ISET_MIN >= 6
/* Cannot use this on V5 because of load-after-store dependencies -
 * compiled kernel won't honour them */
# define __smp_mb() E2K_WAIT(_st_c | _ld_c | _sas | _sal | _las | _lal | _mt)
#else
# define __smp_mb() E2K_WAIT(_st_c | _ld_c)
#endif
#define __smp_wmb() E2K_WAIT(_st_c | _sas | _mt)
#define __smp_rmb() E2K_WAIT(_ld_c | _lal | _mt)

#define dma_rmb() __smp_rmb()
#define dma_wmb() __smp_wmb()

#define __smp_read_barrier_depends()	NATIVE_HWBUG_AFTER_LD_ACQ()


#if CONFIG_CPU_ISET_MIN >= 5
/* New CPUs with relaxed atomics (e8c2 and later). */
# define __smp_mb__after_atomic()	__smp_mb()
# define __smp_mb__before_atomic()	__smp_mb()
#elif defined CONFIG_E2K_E2S && defined CONFIG_NUMA
/* e4c with NUMA.
 * See MB_BEFORE_ATOMIC for an explanation. */
# define __smp_mb__after_atomic()	E2K_WAIT(_st_c|_ma_c)
# define __smp_mb__before_atomic()	E2K_WAIT(_st_c|_ma_c)
#elif defined CONFIG_E2K_MACHINE
/* Older CPUs (before e8c2).
 * Atomic operations are fully serializing. */
# define __smp_mb__after_atomic() \
do { \
	barrier(); \
	NATIVE_HWBUG_AFTER_LD_ACQ(); \
} while (0)
# define __smp_mb__before_atomic()	barrier()
#else
/* Generic kernel: combine all of the above */
# define __smp_mb__after_atomic()	__smp_mb()
# define __smp_mb__before_atomic()	__smp_mb()
#endif

extern int __smp_store_release_bad(void) __attribute__((noreturn));
#if CONFIG_CPU_ISET_MIN >= 6
# define smp_store_release_mt(p, v, mt) \
do { \
	__typeof__(*(p)) __ssr_v = (v); \
	int mas_mt = (mt) ? MAS_MT_1 : MAS_MT_0; \
	switch (sizeof(*p)) { \
	case 1: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(mas_mt), b, "memory"); break; \
	case 2: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(mas_mt), h, "memory"); break; \
	case 4: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(mas_mt), w, "memory"); break; \
	case 8: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(mas_mt), d, "memory"); break; \
	default: __smp_store_release_bad(); break; \
	} \
} while (0)
#else
# define smp_store_release_mt(p, v, mt) \
do { \
	compiletime_assert(sizeof(*p) == 1 || sizeof(*p) == 2 || \
			sizeof(*p) == 4 || sizeof(*p) == 8, \
			"Need native word sized stores/loads for atomicity."); \
	E2K_WAIT(_st_c | _sas | _ld_c | _sal | ((mt) ? _mt : 0)); \
	WRITE_ONCE(*(p), (v)); \
} while (0)
#endif /* CONFIG_CPU_ISET_MIN >= 6 */

#define __smp_store_release(p, v)	smp_store_release_mt((p), (v), true)
#define store_release(p, v)		smp_store_release_mt((p), (v), false)


#ifdef __CHECKER__
/* sparse does not understand macro magic trickery */
#elif CONFIG_CPU_ISET_MIN >= 6
extern int __smp_load_acquire_bad(void) __attribute__((noreturn));
# ifdef CONFIG_CC_IS_LCC
#  define __smp_load_acquire(p) \
({ \
	__unqual_scalar_typeof(*(p)) __ret_la; \
	typeof(p) __p = (p); \
	compiletime_assert_atomic_type(*p); \
	switch (sizeof(*p)) { \
	case 1: LOAD_NV_MAS(__p, __ret_la, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), b, "memory"); \
		break; \
	case 2: LOAD_NV_MAS(__p, __ret_la, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), h, "memory"); \
		break; \
	case 4: LOAD_NV_MAS(__p, __ret_la, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), w, "memory"); \
		break; \
	case 8: LOAD_NV_MAS(__p, __ret_la, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), d, "memory"); \
		break; \
	default: __smp_load_acquire_bad(); break; \
	} \
	__ret_la; \
})
# else
#  define __smp_load_acquire(p) \
({ \
	union { __unqual_scalar_typeof(*p) __val; char __c[1]; } __u; \
	typeof(p) __p = (p); \
	compiletime_assert_atomic_type(*p); \
	switch (sizeof(*p)) { \
	case 1: LOAD_NV_MAS(__p, *(u8 *) __u.__c, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), b, "memory"); \
		break; \
	case 2: LOAD_NV_MAS(__p, *(u16 *) __u.__c, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), h, "memory"); \
		break; \
	case 4: LOAD_NV_MAS(__p, *(u32 *) __u.__c, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), w, "memory"); \
		break; \
	case 8: LOAD_NV_MAS(__p, *(u64 *) __u.__c, MAS_LOAD_ACQUIRE_V6(MAS_MT_1), d, "memory"); \
		break; \
	default: __smp_load_acquire_bad(); break; \
	} \
	(typeof(*p))__u.__val; \
})
# endif /* CONFIG_CC_IS_LCC */
#else
# define __smp_load_acquire(p) \
({ \
	typeof(*(p)) ___p1 = READ_ONCE(*(p)); \
	compiletime_assert(sizeof(*p) == 1 || sizeof(*p) == 2 || \
			sizeof(*p) == 4 || sizeof(*p) == 8, \
			"Need native word sized stores/loads for atomicity."); \
	E2K_RF_WAIT_LOAD(___p1); \
	___p1; \
})
#endif /* CONFIG_CPU_ISET_MIN >= 6 */

/*
 * e2k is in-order architecture, thus loads are not speculated by hardware
 * and we only have to protect against compiler optimizations
 */
#define smp_acquire__after_ctrl_dep() barrier()

/**
 * array_index_mask_nospec - hide 'index' from compiler so that
 * it does not try to load array speculatively across this point
 *
 * On e2k there is no hardware speculation, only software, so the
 * trick with mask is not needed.
 */
#define array_index_mask_nospec array_index_mask_nospec
static inline unsigned long array_index_mask_nospec(unsigned long index,
						    unsigned long size)
{
	OPTIMIZER_HIDE_VAR(index);

	return -1UL;
}

#define smp_mb__after_spinlock() smp_mb()

#include <asm-generic/barrier.h>

#endif /* _ASM_E2K_BARRIER_H */
