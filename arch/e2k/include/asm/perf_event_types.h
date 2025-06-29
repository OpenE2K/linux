/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/percpu.h>
#include <asm/ptrace.h>


/*
 * Configuration for core events saved in `hw_perf_event.config`.
 */
union core_event_config {
	struct {
		/* Either set immediately by user in old rMMEE (M - monitor,
		 * E - event) format, or is updated dynamically based on `mask`
		 * field if user used new rMM00EE (M - mask, E - event) format */
		u8 monitor;

		u8 event_id;
		union {
			struct {
				u8 ddm0 : 1;
				u8 ddm1 : 1;
				u8 ddm2 : 1;
				u8 ddm3 : 1;
				u8 dim0 : 1;
				u8 dim1 : 1;
				u8 dim2 : 1;
				u8 dim3 : 1;
			};
			u8 mask;
		};

		/* Is this instruction or data monitor? */
		u8 instruction : 1;

		/* Monitor privileged mode? */
		u8 system   : 1;

		/* Monitor unprivileged mode? */
		u8 user : 1;
	};
	u64 word;
};

DECLARE_PER_CPU(struct perf_event * [8], cpu_events);

#ifdef	CONFIG_PERF_EVENTS
DECLARE_PER_CPU(u16, perf_monitors_used);
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
 *
 * Part of perf ABI so do not change order of fields.
 */
enum {
	DDM0 = 0,
	DDM1,
	DIM0,
	DIM1,
	DDM0_DDM1,
	DIM0_DIM1,
	DDM2,
	DDM3,
	DIM2,
	DIM3,
	MAX_HW_MONITORS
};

extern bool hw_event_supported(u8 monitor, u8 event_id);
