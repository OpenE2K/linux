#ifndef _ASM_E2K_PERF_EVENT_H
#define _ASM_E2K_PERF_EVENT_H

#include <linux/percpu.h>
#include <asm/process.h>
#include <asm/regs_state.h>

static inline void set_perf_event_pending(void) {}
static inline void clear_perf_event_pending(void) {}

#define PERF_EVENT_INDEX_OFFSET 0

int perf_data_overflow_handle(struct pt_regs *);
int perf_instr_overflow_handle(struct pt_regs *);
void dimtp_overflow(struct perf_event *event);

#define perf_arch_fetch_caller_regs perf_arch_fetch_caller_regs
static __always_inline void perf_arch_fetch_caller_regs(struct pt_regs *regs,
							unsigned long ip)
{
	SAVE_STACK_REGS(regs, current_thread_info(), false, false);
	WARN_ON_ONCE(instruction_pointer(regs) != ip);
}

#define ARCH_PERFMON_EVENT_MASK	0xffff
#define ARCH_PERFMON_OS		(1 << 16)
#define ARCH_PERFMON_USR	(1 << 17)
#define ARCH_PERFMON_ENABLED	(1 << 18)


DECLARE_PER_CPU(struct perf_event * [4], cpu_events);

/*
 * Bitmask for perf_monitors_used
 *
 * DIM0 has all counters from DIM1 and some more. So events for
 * DIM1 are marked with DIM0_DIM1, and the actual used monitor
 * will be determined at runtime.
 */
enum {
	_DDM0 = 0,
	_DDM1,
	_DIM0,
	_DIM1,
	_DDM0_DDM1,
	_DIM0_DIM1,
	MAX_HW_MONITORS
};
#define DDM0 (1 << _DDM0)
#define DDM1 (1 << _DDM1)
#define DIM0 (1 << _DIM0)
#define DIM1 (1 << _DIM1)
#define DDM0_DDM1 (1 << _DDM0_DDM1)
#define DIM0_DIM1 (1 << _DIM0_DIM1)

#endif
