#pragma once

#include <linux/percpu.h>
#include <asm/ptrace.h>

#define ARCH_PERFMON_OS		(1 << 16)
#define ARCH_PERFMON_USR	(1 << 17)

DECLARE_PER_CPU(struct perf_event * [4], cpu_events);

#ifdef	CONFIG_PERF_EVENTS
DECLARE_PER_CPU(u8, perf_monitors_used);
DECLARE_PER_CPU(u8, perf_bps_used);
# define perf_read_monitors_used()	__this_cpu_read(perf_monitors_used)
# define perf_read_bps_used()		__this_cpu_read(perf_bps_used)
#else	/* ! CONFIG_PERF_EVENTS */
# define perf_read_monitors_used()	0
# define perf_read_bps_used()		0
#endif	/* CONFIG_PERF_EVENTS */

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
