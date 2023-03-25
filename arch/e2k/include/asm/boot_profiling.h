#ifndef _ASM_E2K_BOOT_PROFILING_H
#define _ASM_E2K_BOOT_PROFILING_H

#include <linux/time.h>
#include <asm-l/boot_profiling.h>

#ifdef CONFIG_BOOT_TRACE
extern void notrace boot_add_boot_trace_event(char *name);

/* EARLY_BOOT_TRACEPOINT should be used if virtual memory
 * is not working yet. It does not support formatted strings. */
# define EARLY_BOOT_TRACEPOINT(name) \
		boot_add_boot_trace_event(name)

#ifdef CONFIG_RECOVERY
/* Clears boot trace data (needed to trace recovery times). */
void reinitialize_boot_trace_data(void);
#endif	/* CONFIG_RECOVERY */

#define boot_trace_get_cycles  get_cycles

/* Convert boot counter cycles to ms */
static inline u64 boot_cycles_to_ms(u64 cycles)
{
	u64 cpu_hz = cpu_data[0].proc_freq;

	return MSEC_PER_SEC * cycles / cpu_hz;
}
#else	/* !CONFIG_BOOT_TRACE */
# define EARLY_BOOT_TRACEPOINT(name)
#endif	/* CONFIG_BOOT_TRACE */

#endif /* _ASM_E2K_BOOT_PROFILING_H */

