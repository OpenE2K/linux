#ifndef _ASM_E2K_PERF_EVENT_H
#define _ASM_E2K_PERF_EVENT_H

#include <linux/percpu.h>
#include <asm/regs_state.h>

static inline void set_perf_event_pending(void) {}
static inline void clear_perf_event_pending(void) {}

#define PERF_EVENT_INDEX_OFFSET 0

#ifdef CONFIG_PERF_EVENTS
int perf_data_overflow_handle(struct pt_regs *);
int perf_instr_overflow_handle(struct pt_regs *);

# define perf_arch_fetch_caller_regs perf_arch_fetch_caller_regs
static __always_inline void perf_arch_fetch_caller_regs(struct pt_regs *regs,
							unsigned long ip)
{
	SAVE_STACK_REGS(regs, current_thread_info(), false, false);
	WARN_ON_ONCE(instruction_pointer(regs) != ip);
}
#else
static inline int perf_data_overflow_handle(struct pt_regs *regs)
{
	return 0;
}
static inline int perf_instr_overflow_handle(struct pt_regs *regs)
{
	return 0;
}
#endif

#define ARCH_PERFMON_EVENT_MASK	0xffff
#define ARCH_PERFMON_OS		(1 << 16)
#define ARCH_PERFMON_USR	(1 << 17)
#define ARCH_PERFMON_ENABLED	(1 << 18)

#endif
