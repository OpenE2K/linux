#ifndef _ASM_L_BOOT_PROFILING_H
#define _ASM_L_BOOT_PROFILING_H

#ifdef CONFIG_BOOT_TRACE

#include <linux/list.h>

extern void notrace add_boot_trace_event(const char *fmt, ...);
extern struct boot_tracepoint *boot_trace_prev_event(int cpu,
			struct boot_tracepoint *event);
extern struct boot_tracepoint *boot_trace_next_event(int cpu,
			struct boot_tracepoint *event);
extern void stop_boot_trace(void);

# define BOOT_TRACE_ARRAY_SIZE (1500 + 20 * NR_CPUS)

struct boot_tracepoint {
 	char		name[81];
	unsigned int	cpu;
	u64		cycles;
	struct list_head	list;
};

extern struct boot_tracepoint	boot_trace_events[BOOT_TRACE_ARRAY_SIZE];
extern struct list_head		boot_trace_cpu_events_list[];
extern atomic_t			boot_trace_top_event;
extern int			boot_trace_enabled;
# define BOOT_TRACEPOINT(...) add_boot_trace_event(__VA_ARGS__)

#else	/* !CONFIG_BOOT_TRACE */
# define BOOT_TRACEPOINT(...) do { } while(0)
#endif	/* CONFIG_BOOT_TRACE */

#endif /* _ASM_L_BOOT_PROFILING_H */

