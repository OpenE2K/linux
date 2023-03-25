#ifndef _ASM_E2K_BARRIER_H
#define _ASM_E2K_BARRIER_H

#include <linux/compiler.h>

#include <asm/e2k_api.h>
#include <asm/atomic_api.h>

#if CONFIG_CPU_ISET >= 6
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
#if CONFIG_CPU_ISET >= 6
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


#if CONFIG_CPU_ISET >= 5
# define __smp_mb__after_atomic()	barrier()
# define __smp_mb__before_atomic()	E2K_WAIT(_st_c | _las | _ld_c | _lal | _mt)
#elif CONFIG_CPU_ISET >= 3
/* Atomic operations are serializing since e2s */
# define __smp_mb__after_atomic() \
do { \
	barrier(); \
	NATIVE_HWBUG_AFTER_LD_ACQ(); \
} while (0)
# define __smp_mb__before_atomic()	barrier()
#else
# define __smp_mb__after_atomic()	E2K_WAIT(_st_c)
# define __smp_mb__before_atomic()	barrier()
#endif

extern int __smp_store_release_bad(void) __attribute__((noreturn));
#if CONFIG_CPU_ISET >= 6
# define __smp_store_release(p, v) \
do { \
	__typeof__(*(p)) __ssr_v = (v); \
	switch (sizeof(*p)) { \
	case 1: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(MAS_MT_1), b, "memory"); break; \
	case 2: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(MAS_MT_1), h, "memory"); break; \
	case 4: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(MAS_MT_1), w, "memory"); break; \
	case 8: STORE_NV_MAS((p), __ssr_v, MAS_STORE_RELEASE_V6(MAS_MT_1), d, "memory"); break; \
	default: __smp_store_release_bad(); break; \
	} \
} while (0)
#else
# define __smp_store_release(p, v) \
do { \
	compiletime_assert(sizeof(*p) == 1 || sizeof(*p) == 2 || \
			sizeof(*p) == 4 || sizeof(*p) == 8, \
			"Need native word sized stores/loads for atomicity."); \
	E2K_WAIT(_st_c | _sas | _ld_c | _sal | _mt); \
	WRITE_ONCE(*(p), (v)); \
} while (0)
#endif /* CONFIG_CPU_ISET >= 6 */

/*
 * store_release() - same as __smp_store_release but acts on device accesses too
 */
#define store_release_v3 __smp_store_release
#define store_release_v6(p, v) \
do { \
	__typeof__(*(p)) __sr6_v = (v); \
	switch (sizeof(*p)) { \
	case 1: STORE_NV_MAS((p), __sr6_v, MAS_STORE_RELEASE_V6(MAS_MT_0), b, "memory"); break; \
	case 2: STORE_NV_MAS((p), __sr6_v, MAS_STORE_RELEASE_V6(MAS_MT_0), h, "memory"); break; \
	case 4: STORE_NV_MAS((p), __sr6_v, MAS_STORE_RELEASE_V6(MAS_MT_0), w, "memory"); break; \
	case 8: STORE_NV_MAS((p), __sr6_v, MAS_STORE_RELEASE_V6(MAS_MT_0), d, "memory"); break; \
	default: __smp_store_release_bad(); break; \
	} \
} while (0)
#define store_release(p, v) \
do { \
	if (cpu_has(CPU_FEAT_ISET_V6)) \
		store_release_v6((p), (v)); \
	else \
		store_release_v3((p), (v)); \
} while (0)

#if CONFIG_CPU_ISET >= 6
extern int __smp_load_acquire_bad(void) __attribute__((noreturn));
# define __smp_load_acquire(p) \
({ \
	union { typeof(*(p)) __ret_la; char __c[1]; } __u; \
	switch (sizeof(*p)) { \
	case 1: LOAD_NV_MAS((p), (*(__u8 *)__u.__c), MAS_LOAD_ACQUIRE_V6(MAS_MT_1), b, "memory"); \
		break; \
	case 2: LOAD_NV_MAS((p), (*(__u16 *)__u.__c), MAS_LOAD_ACQUIRE_V6(MAS_MT_1), h, "memory"); \
		break; \
	case 4: LOAD_NV_MAS((p), (*(__u32 *)__u.__c), MAS_LOAD_ACQUIRE_V6(MAS_MT_1), w, "memory"); \
		break; \
	case 8: LOAD_NV_MAS((p), (*(__u64 *)__u.__c), MAS_LOAD_ACQUIRE_V6(MAS_MT_1), d, "memory"); \
		break; \
	default: __smp_load_acquire_bad(); break; \
	} \
	__u.__ret_la; \
})
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
#endif

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

/*
 * Follow the example of RISC-V and forbid IO crossing of scheduling
 * boundary by using mb() instead of smp_mb().  This should not have
 * any measurable performance impact on e2k.  The bad case is when
 * task is preempted after writeX() and migrated to another CPU fast
 * enough so that the CPU it was preempted on has not called any
 * spin_unlock()'s yet.
 */
#define smp_mb__after_spinlock() mb()

#include <asm-generic/barrier.h>

#endif /* _ASM_E2K_BARRIER_H */
