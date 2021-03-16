/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __SPARC64_BARRIER_H
#define __SPARC64_BARRIER_H

#define membar_sync() do{__asm__ __volatile__("membar #Sync\n\t");}while(0)

#ifdef	CONFIG_E90S
#define membar_sync() do{__asm__ __volatile__("membar #Sync\n\t");}while(0)
#define membar_safe(type) \
do {	__asm__ __volatile__( \
			     " membar	" type "\n" \
			     : : : "memory"); \
} while (0)

#else /*CONFIG_E90S*/
/* These are here in an effort to more fully work around Spitfire Errata
 * #51.  Essentially, if a memory barrier occurs soon after a mispredicted
 * branch, the chip can stop executing instructions until a trap occurs.
 * Therefore, if interrupts are disabled, the chip can hang forever.
 *
 * It used to be believed that the memory barrier had to be right in the
 * delay slot, but a case has been traced recently wherein the memory barrier
 * was one instruction after the branch delay slot and the chip still hung.
 * The offending sequence was the following in sym_wakeup_done() of the
 * sym53c8xx_2 driver:
 *
 *	call	sym_ccb_from_dsa, 0
 *	 movge	%icc, 0, %l0
 *	brz,pn	%o0, .LL1303
 *	 mov	%o0, %l2
 *	membar	#LoadLoad
 *
 * The branch has to be mispredicted for the bug to occur.  Therefore, we put
 * the memory barrier explicitly into a "branch always, predicted taken"
 * delay slot to avoid the problem case.
 */

#define membar_safe(type) \
do {	__asm__ __volatile__("ba,pt	%%xcc, 1f\n\t" \
			     " membar	" type "\n" \
			     "1:\n" \
			     : : : "memory"); \
} while (0)
#endif /*CONFIG_E90S*/

#ifndef	CONFIG_RMO
/* The kernel always executes in TSO memory model these days,
 * and furthermore most sparc64 chips implement more stringent
 * memory ordering than required by the specifications.
 */
#define mb()	membar_safe("#StoreLoad")
#define rmb()	__asm__ __volatile__("":::"memory")
#define wmb()	__asm__ __volatile__("":::"memory")
#else	/* CONFIG_RMO */
#define mb()	\
	membar_safe("#LoadLoad | #LoadStore | #StoreStore | #StoreLoad")
#define rmb()	\
	membar_safe("#LoadLoad")
#define wmb()	\
	membar_safe("#StoreStore")
#define membar_storeload() \
	membar_safe("#StoreLoad")
#define membar_storeload_storestore() \
	membar_safe("#StoreLoad | #StoreStore")
#define membar_storeload_loadload() \
	membar_safe("#StoreLoad | #LoadLoad")
#define membar_storestore_loadstore() \
	membar_safe("#StoreStore | #LoadStore")
#endif	/* CONFIG_RMO */

#define dma_rmb()	rmb()
#define dma_wmb()	wmb()

#define read_barrier_depends()		do { } while(0)
#ifndef	CONFIG_RMO
#define set_mb(__var, __value) \
	do { __var = __value; membar_safe("#StoreLoad"); } while(0)
#else	/* CONFIG_RMO */
#define set_mb(__var, __value) \
	do { __var = __value; membar_storeload_storestore(); } while(0)
#endif	/* CONFIG_RMO */

#ifdef	CONFIG_RMO
#ifdef CONFIG_SMP
#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()
#else
#define smp_mb()	__asm__ __volatile__("":::"memory")
#define smp_rmb()	__asm__ __volatile__("":::"memory")
#define smp_wmb()	__asm__ __volatile__("":::"memory")
#endif
#define smp_store_mb(__var, __value)	set_mb(__var, __value)



#define __smp_store_release(p, v)						\
do {									\
	compiletime_assert_atomic_type(*p);				\
	membar_storeload_storestore();					\
	WRITE_ONCE(*p, v);						\
} while (0)

#define __smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	membar_storeload_loadload();					\
	___p1;								\
})

#define __smp_mb__before_atomic()	membar_storeload_loadload()
#define __smp_mb__after_atomic()	membar_storeload_storestore()

#else	/* CONFIG_RMO */
#define smp_store_mb(__var, __value) \
	do { WRITE_ONCE(__var, __value); membar_safe("#StoreLoad"); } while(0)

#ifdef CONFIG_SMP
#define smp_mb()	mb()
#define smp_rmb()	rmb()
#define smp_wmb()	wmb()
#else
#define smp_mb()	__asm__ __volatile__("":::"memory")
#define smp_rmb()	__asm__ __volatile__("":::"memory")
#define smp_wmb()	__asm__ __volatile__("":::"memory")
#endif

#define read_barrier_depends()		do { } while (0)
#define smp_read_barrier_depends()	do { } while (0)

#define __smp_store_release(p, v)						\
do {									\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	WRITE_ONCE(*p, v);						\
} while (0)

#define __smp_load_acquire(p)						\
({									\
	typeof(*p) ___p1 = READ_ONCE(*p);				\
	compiletime_assert_atomic_type(*p);				\
	barrier();							\
	___p1;								\
})

#define __smp_mb__before_atomic()	barrier()
#define __smp_mb__after_atomic()	barrier()
#endif	/* CONFIG_RMO */

#include <asm-generic/barrier.h>

#endif /* !(__SPARC64_BARRIER_H) */
