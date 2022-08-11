#ifndef _E2K_PERCPU_H_
#define _E2K_PERCPU_H_

#ifndef CONFIG_SMP
# define set_my_cpu_offset(off)
#else

# include <asm/glob_regs.h>
# include <asm/e2k_api.h>

# define __my_cpu_offset __my_cpu_offset
register unsigned long __my_cpu_offset DO_ASM_GET_GREG_MEMONIC(
							MY_CPU_OFFSET_GREG);

# define set_my_cpu_offset(off) do {__my_cpu_offset = (off); } while (0)

# define this_cpu_read_1(pcp) __arch_this_cpu_read((pcp), "b")
# define this_cpu_read_2(pcp) __arch_this_cpu_read((pcp), "h")
# define this_cpu_read_4(pcp) __arch_this_cpu_read((pcp), "w")
# define this_cpu_read_8(pcp) __arch_this_cpu_read((pcp), "d")

# define this_cpu_write_1(pcp, val) __arch_this_cpu_write((pcp), (val), "b")
# define this_cpu_write_2(pcp, val) __arch_this_cpu_write((pcp), (val), "h")
# define this_cpu_write_4(pcp, val) __arch_this_cpu_write((pcp), (val), "w")
# define this_cpu_write_8(pcp, val) __arch_this_cpu_write((pcp), (val), "d")

/* Use relaxed atomics if they are available */
# if CONFIG_CPU_ISET >= 5
#  define this_cpu_xchg_1(pcp, nval) __arch_pcpu_atomic_xchg((nval), (pcp), "b")
#  define this_cpu_xchg_2(pcp, nval) __arch_pcpu_atomic_xchg((nval), (pcp), "h")
#  define this_cpu_xchg_4(pcp, nval) __arch_pcpu_atomic_xchg((nval), (pcp), "w")
#  define this_cpu_xchg_8(pcp, nval) __arch_pcpu_atomic_xchg((nval), (pcp), "d")

#  define this_cpu_cmpxchg_1(pcp, oval, nval) \
		__arch_pcpu_atomic_cmpxchg((oval), (nval), (pcp), "b", 0x4)
#  define this_cpu_cmpxchg_2(pcp, oval, nval) \
		__arch_pcpu_atomic_cmpxchg((oval), (nval), (pcp), "h", 0x5)
#  define this_cpu_cmpxchg_4(pcp, oval, nval) \
		__arch_pcpu_atomic_cmpxchg_word((oval), (nval), (pcp))
#  define this_cpu_cmpxchg_8(pcp, oval, nval) \
		__arch_pcpu_atomic_cmpxchg_dword((oval), (nval), (pcp))

#  define this_cpu_and_1(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "b", "ands"))
#  define this_cpu_and_2(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "h", "ands"))
#  define this_cpu_and_4(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "w", "ands"))
#  define this_cpu_and_8(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "d", "andd"))

#  define this_cpu_or_1(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "b", "ors"))
#  define this_cpu_or_2(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "h", "ors"))
#  define this_cpu_or_4(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "w", "ors"))
#  define this_cpu_or_8(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "d", "ord"))

#  define this_cpu_add_1(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "b", "adds"))
#  define this_cpu_add_2(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "h", "adds"))
#  define this_cpu_add_4(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "w", "adds"))
#  define this_cpu_add_8(pcp, val) ((void) __arch_pcpu_atomic_op((val), (pcp), "d", "addd"))

#  define this_cpu_add_return_1(pcp, val) __arch_pcpu_atomic_op((val), (pcp), "b", "adds")
#  define this_cpu_add_return_2(pcp, val) __arch_pcpu_atomic_op((val), (pcp), "h", "adds")
#  define this_cpu_add_return_4(pcp, val) __arch_pcpu_atomic_op((val), (pcp), "w", "adds")
#  define this_cpu_add_return_8(pcp, val) __arch_pcpu_atomic_op((val), (pcp), "d", "addd")
# endif

#endif

#include <asm-generic/percpu.h>

/* For EARLY_PER_CPU_* definitions */
#include <asm-l/percpu.h>

DECLARE_PER_CPU(unsigned long, cpu_loops_per_jiffy);

#endif /* _E2K_PERCPU_H_ */

