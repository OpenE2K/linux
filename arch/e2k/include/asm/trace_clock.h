#ifndef _ASM_E2K_TRACE_CLOCK_H
#define _ASM_E2K_TRACE_CLOCK_H

#include <linux/compiler.h>
#include <linux/types.h>

extern notrace u64 trace_clock_e2k_clkr(void);

#define ARCH_TRACE_CLOCKS \
	{ trace_clock_e2k_clkr, "e2k-clkr", .in_ns = 0 },

#endif  /* _ASM_E2K_TRACE_CLOCK_H */
