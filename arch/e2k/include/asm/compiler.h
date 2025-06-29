/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_COMPILER_H
#define _ASM_COMPILER_H

#include <asm/glob_regs.h>

#undef barrier
#undef barrier_data
#undef RELOC_HIDE

#if defined(CONFIG_ARCH_USE_BUILTIN_BSWAP) && !defined(__CHECKER__)
#if GCC_VERSION >= 40400
/* builtin version has better throughput but worse latency */
#undef __HAVE_BUILTIN_BSWAP32__
#endif
#endif

#define __PREEMPTION_CLOBBERS_1(cpu_greg, offset_greg) \
	"g" #cpu_greg, "g" #offset_greg
#define __PREEMPTION_CLOBBERS(cpu_greg, offset_greg) \
	__PREEMPTION_CLOBBERS_1(cpu_greg, offset_greg)
/* If a compiler barrier is used in loop, these clobbers will
 * force the compiler to always access *current* per-cpu area
 * instead of moving its address calculation out from the loop.
 *
 * The same goes for preemption-disabled sections: these clobbers
 * will forbid compiler to move per-cpu area address calculation out
 * from them. Since disabling interrupts also disables preemption,
 * we also need these clobbers when writing PSR/UPSR.
 *
 * And of course operations on preempt_count must not be moved
 * out of/into preemption disabled sections. */
#define PREEMPTION_CLOBBERS __PREEMPTION_CLOBBERS(SMP_CPU_ID_GREG, MY_CPU_OFFSET_GREG)

#ifdef CONFIG_DEBUG_LCC_VOLATILE_ATOMIC
#define NOT_VOLATILE volatile
#else
#define NOT_VOLATILE
#endif

#ifdef __CHECKER__
/*
 * VM_PRIVILEGED address space used for hardware stacks, CUT, signal_stack
 */
# define __priv	__attribute__((noderef, address_space(__priv)))
static inline void __chk_priv_ptr(const volatile void __priv *ptr) { }
#else
# define __priv
# define __chk_priv_ptr(x)	(void)0
#endif

/* See bug #89623, bug #94946, bug #139069 */
#define barrier() \
do { \
	int unused; \
	_Pragma("asm_length(0)") \
	__asm__ NOT_VOLATILE("" : "=r" (unused) : : "memory", PREEMPTION_CLOBBERS);\
} while (0)

#ifndef CONFIG_PREEMPTION
# define barrier_preemption()
#else
/*
 * Used in READ_ONCE() to prevent lcc from moving per-cpu address calculation
 * out of loop, such move can lead to problems if all of the following
 * conditions are met:
 *    - the loop is reading two per-cpu variables and comparing them;
 *    - lcc moved one per-cpu variable address calculation out of the loop;
 *    - preemption happened and the task has been moved to another CPU after
 *      address calculation but before actual access.
 *
 * As a result one per-cpu variable will be constantly read from current
 * CPU and another variable will be read from some other CPU.  An example
 * of this can be seen at the beginning of do_slab_free().
 *
 * This barrier can also be moved from READ_ONCE() to arch_raw_cpu_ptr() but
 * raw_cpu_ptr() is used too often - so the barrier there degrades performance.
 *
 * Barrier is not needed on PREEMPT_NONE (obviously) and on PREEMPT_VOLUNTARY
 * since there preemption is done with an explicit function call so lcc
 * will assume that __my_cpu_offset might change and will not apply the
 * optimization.
 */
# define barrier_preemption() \
do { \
	int unused; \
	_Pragma("asm_length(0)") \
	__asm__ NOT_VOLATILE("" : "=r" (unused) : : PREEMPTION_CLOBBERS); \
} while (0)
#endif

#define barrier_data(ptr) \
do { \
	_Pragma("asm_length(0)") \
	__asm__ NOT_VOLATILE("" : : "r"(ptr) : "memory", PREEMPTION_CLOBBERS); \
} while (0)

#define RELOC_HIDE(ptr, off)	((typeof(ptr)) ((unsigned long) (ptr) + (off)))

#ifdef CONFIG_CC_IS_LCC
# define builtin_expect_wrapper(x, val)	__builtin_expect_with_probability((x), (val), 0.9999)
#else
#  define builtin_expect_wrapper(x, val) __builtin_expect((x), (val))
#endif

#endif /* _ASM_COMPILER_H */
