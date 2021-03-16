/* SPDX-License-Identifier: GPL-2.0 */
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
 * we also need these clobbers when writing PSR/UPSR. */
#define PREEMPTION_CLOBBERS __PREEMPTION_CLOBBERS(SMP_CPU_ID_GREG, MY_CPU_OFFSET_GREG)

#ifdef CONFIG_DEBUG_LCC_VOLATILE_ATOMIC
#define NOT_VOLATILE volatile
#else
#define NOT_VOLATILE
#endif

/* See bug #89623, bug #94946 */
#define barrier() \
do { \
	int unused; \
	__asm__ NOT_VOLATILE("" : "=r" (unused) : : "memory", PREEMPTION_CLOBBERS);\
} while (0)

/* See comment before PREEMPTION_CLOBBERS */
#define barrier_preemption() \
do { \
	int unused; \
	__asm__ NOT_VOLATILE("" : "=r" (unused) : : PREEMPTION_CLOBBERS);\
} while (0)

#define barrier_data(ptr) \
do { \
	__asm__ NOT_VOLATILE("" : : "r"(ptr) : "memory", PREEMPTION_CLOBBERS); \
} while (0)

#define RELOC_HIDE(ptr, off)						\
({									\
	unsigned long __ptr;						\
	__asm__ ("" : "=r"(__ptr) : "0"(ptr));				\
	(typeof(ptr)) (__ptr + (off));					\
})

#if defined(__LCC__) && (__LCC__ > 125 || __LCC__ == 125 && __LCC_MINOR__ >= 9)
# define builtin_expect_wrapper(x, val)	__builtin_expect_with_probability((x), (val), 0.9999)
#else
#  define builtin_expect_wrapper(x, val) __builtin_expect((x), (val))
#endif

#endif /* _ASM_COMPILER_H */
