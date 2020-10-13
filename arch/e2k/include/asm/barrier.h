#ifndef _ASM_E2K_BARRIER_H
#define _ASM_E2K_BARRIER_H

#include <asm/e2k_api.h>

#define mb()	E2K_WAIT(_st_c | _ld_c)
#define wmb()	E2K_WAIT(_st_c)
#define rmb()	E2K_WAIT(_ld_c)

#define read_barrier_depends()		do { } while (0)
#define smp_read_barrier_depends()	do { } while (0)

#ifdef CONFIG_SMP
#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()
#else
#define smp_mb()	barrier()
#define smp_rmb()	barrier()
#define smp_wmb()	barrier()
#endif

#define smp_mb__before_spinlock()	barrier()

#define smp_store_release(p, v) \
do { \
	compiletime_assert_atomic_type(*p); \
	smp_mb(); \
	ACCESS_ONCE(*p) = (v); \
} while (0)

#define smp_load_acquire(p) \
({ \
	typeof(*(p)) ___p1 = ACCESS_ONCE(*(p)); \
	compiletime_assert_atomic_type(*(p)); \
	E2K_RF_WAIT_LOAD(___p1); \
	___p1; \
})

#endif /* _ASM_E2K_BARRIER_H */
