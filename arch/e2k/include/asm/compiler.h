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

/*
 * Ugly macro magic to calculate argument for _Pragma("asm_length")
 */
#define __CONCAT(a, b) a ## b
#define CONCATENATE(a, b) __CONCAT(a, b)
#define ADD_1_0		1
#define ADD_1_1		2
#define ADD_1_2		3
#define ADD_1_3		4
#define ADD_1_4		5
#define ADD_1_5		6
#define ADD_1_6		7
#define ADD_1_7		8
#define ADD_1_8		9
#define ADD_1_9		10
#define ADD_1_10	11
#define ADD_2_0		2
#define ADD_2_1		3
#define ADD_2_2		4
#define ADD_2_3		5
#define ADD_2_4		6
#define ADD_2_5		7
#define ADD_2_6		8
#define ADD_2_7		9
#define ADD_2_8		10
#define ADD_2_9		11
#define ADD_2_10	12

# define __no_asm_inline_nolength _Pragma("no_asm_inline")

#define ASM_LENGTH_0	_Pragma("asm_length(0)")
#define ASM_LENGTH_1	_Pragma("asm_length(1)")
#define ASM_LENGTH_2	_Pragma("asm_length(2)")
#define ASM_LENGTH_3	_Pragma("asm_length(3)")
#define ASM_LENGTH_4	_Pragma("asm_length(4)")
#define ASM_LENGTH_5	_Pragma("asm_length(5)")
#define ASM_LENGTH_6	_Pragma("asm_length(6)")
#define ASM_LENGTH_7	_Pragma("asm_length(7)")
#define ASM_LENGTH_8	_Pragma("asm_length(8)")
#define ASM_LENGTH_9	_Pragma("asm_length(9)")
#define ASM_LENGTH_10	_Pragma("asm_length(10)")
#define ASM_LENGTH_11	_Pragma("asm_length(11)")
#define ASM_LENGTH_12	_Pragma("asm_length(12)")
#define ASM_LENGTH_13	_Pragma("asm_length(13)")
#define ASM_LENGTH_14	_Pragma("asm_length(14)")
/* 14 is the maximum supported value */
#define ASM_LENGTH_15	_Pragma("asm_length(14)")
#define ASM_LENGTH_16	_Pragma("asm_length(14)")
#define ASM_LENGTH_17	_Pragma("asm_length(14)")
#define ASM_LENGTH_18	_Pragma("asm_length(14)")
#define ASM_LENGTH_30	_Pragma("asm_length(14)")

#define __asm_length(len) CONCATENATE(ASM_LENGTH_,len)

#ifndef CONFIG_E2K_MACHINE
/* For generic kernels we cannot choose */
# define ASM_LENGTH_V4_V5(len_v4, len_v5)
# define ASM_LENGTH_ADD_V4_V5(len_v4, len_v5, add)
#elif CONFIG_CPU_ISET_MIN < 5
# define ASM_LENGTH_V4_V5(len_v4, len_v5) CONCATENATE(ASM_LENGTH_, len_v4)
# define ASM_LENGTH_ADD_V4_V5(len_v4, len_v5, add) CONCATENATE(ASM_LENGTH_, ADD_##add##_##len_v4)
#else /* CONFIG_CPU_ISET_MIN >= 5 */
# define ASM_LENGTH_V4_V5(len_v4, len_v5) CONCATENATE(ASM_LENGTH_, len_v5)
# define ASM_LENGTH_ADD_V4_V5(len_v4, len_v5, add) CONCATENATE(ASM_LENGTH_, ADD_##add##_##len_v5)
#endif

#ifndef CONFIG_E2K_MACHINE
/* For generic kernels we cannot choose */
# define ASM_LENGTH_V5_V6(len_v5, len_v6)
# define ASM_LENGTH_ADD_V5_V6(len_v5, len_v6, add)
#elif CONFIG_CPU_ISET_MIN < 6
# define ASM_LENGTH_V5_V6(len_v5, len_v6) CONCATENATE(ASM_LENGTH_, len_v5)
# define ASM_LENGTH_ADD_V5_V6(len_v5, len_v6, add) CONCATENATE(ASM_LENGTH_, ADD_##add##_##len_v5)
#else /* CONFIG_CPU_ISET_MIN >= 6 */
# define ASM_LENGTH_V5_V6(len_v5, len_v6) CONCATENATE(ASM_LENGTH_, len_v6)
# define ASM_LENGTH_ADD_V5_V6(len_v5, len_v6, add) CONCATENATE(ASM_LENGTH_, ADD_##add##_##len_v6)
#endif

#ifndef CONFIG_E2K_MACHINE
/* For generic kernels we cannot choose */
# define ASM_LENGTH_V6_V7(len_v6, len_v7)
# define ASM_LENGTH_ADD_V6_V7(len_v6, len_v7, add)
#elif CONFIG_CPU_ISET_MIN < 7
# define ASM_LENGTH_V6_V7(len_v6, len_v7) CONCATENATE(ASM_LENGTH_, len_v6)
# define ASM_LENGTH_ADD_V6_V7(len_v6, len_v7, add) CONCATENATE(ASM_LENGTH_, ADD_##add##_##len_v6)
#else /* CONFIG_CPU_ISET_MIN >= 7 */
# define ASM_LENGTH_V6_V7(len_v6, len_v7) CONCATENATE(ASM_LENGTH_, len_v7)
# define ASM_LENGTH_ADD_V6_V7(len_v6, len_v7, add) CONCATENATE(ASM_LENGTH_, ADD_##add##_##len_v7)
#endif

#define __no_asm_inline(length) __no_asm_inline_nolength __asm_length(length)

#if defined(CONFIG_ARCH_USE_BUILTIN_BSWAP) && !defined(__CHECKER__)
#if !defined GCC_VERSION || GCC_VERSION >= 40400
/* builtin version has better throughput but worse latency */
#undef __HAVE_BUILTIN_BSWAP32__
#endif
#endif

#define __PREEMPTION_CLOBBERS_1(cpu_greg, offset_greg, context_greg) \
	"g" #cpu_greg, "g" #offset_greg, "g" #context_greg
#define __PREEMPTION_CLOBBERS(cpu_greg, offset_greg, context_greg) \
	__PREEMPTION_CLOBBERS_1(cpu_greg, offset_greg, context_greg)
/* If a compiler barrier is used in loop, these clobbers will
 * force the compiler to always access *current* per-cpu area
 * instead of moving its address calculation out from the loop.
 *
 * The same goes for preemption-disabled sections: these clobbers
 * will forbid compiler to move per-cpu area address calculation out
 * from them. Since disabling interrupts also disables preemption,
 * we also need these clobbers when writing PSR/UPSR.
 *
 * `current_mmu_context` can also change e.g. when task is migrated.
 *
 * And of course operations on preempt_count must not be moved
 * out of/into preemption disabled sections. */
#define PREEMPTION_CLOBBERS \
	__PREEMPTION_CLOBBERS(SMP_CPU_ID_GREG, MY_CPU_OFFSET_GREG, CURRENT_MMU_CONTEXT_GREG)

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
	__asm_length(0) \
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
	__asm_length(0) \
	__asm__ NOT_VOLATILE("" : "=r" (unused) : : PREEMPTION_CLOBBERS); \
} while (0)
#endif

#define barrier_data(ptr) \
do { \
	__asm_length(0) \
	__asm__ NOT_VOLATILE("" : : "r"(ptr) : "memory", PREEMPTION_CLOBBERS); \
} while (0)

/* Protects against function calls and `disp %ctpr` */
#define barrier_calls() \
do { \
	__no_asm_inline(0) \
	__asm__ volatile ("" : : : "call", "memory"); \
} while (0)

#define RELOC_HIDE(ptr, off)	((typeof(ptr)) ((unsigned long) (ptr) + (off)))

#ifdef CONFIG_CC_IS_LCC
# define builtin_expect_wrapper(x, val)	__builtin_expect_with_probability((x), (val), 0.9999)
#else
#  define builtin_expect_wrapper(x, val) __builtin_expect((x), (val))
#endif

#ifdef CONFIG_CC_IS_CLANG
/* TODO bug 163804 - replace optnone with needed options only */
# define __no_semispec __attribute__((optnone))
#elif CONFIG_CC_IS_LCC
# if __LCC__ == 131 && __LCC_MINOR__ >= 5 || __LCC__ > 131
#  define __no_semispec __attribute__((optimize("-fno-semi-spec-ld"))) \
		       __attribute__((optimize("-fno-loop-apb")))
# else
#  define __no_semispec __attribute__((optimize("O1")))
# endif
#endif

#endif /* _ASM_COMPILER_H */
