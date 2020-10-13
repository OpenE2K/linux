#ifndef _E2K_PERCPU_H_
#define _E2K_PERCPU_H_

#if defined CONFIG_SMP && !defined CONFIG_E2S_CPU_RF_BUG
# define __my_cpu_offset __my_cpu_offset
register unsigned long __my_cpu_offset __asm__ ("%g18");

# define set_my_cpu_offset(off) do {__my_cpu_offset = (off); } while (0)
#else
# define set_my_cpu_offset(off)
#endif

#include <asm-generic/percpu.h>

/* For EARLY_PER_CPU_* definitions */
#include <asm-l/percpu.h>

DECLARE_PER_CPU(unsigned long, cpu_loops_per_jiffy);

#endif /* _E2K_PERCPU_H_ */

