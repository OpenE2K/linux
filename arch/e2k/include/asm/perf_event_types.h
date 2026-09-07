/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#include <linux/percpu.h>
#include <asm/ptrace.h>


/*
 * Bitmask for perf_monitors_used
 *
 * DIM0 has all counters from DIM1 and some more. So events for
 * DIM1 are marked with DIM0_DIM1, and the actual used monitor
 * will be determined at runtime.
 *
 * Part of perf ABI so do not change order of fields.
 */
enum cpu_monitor {
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

/**
 * config_has_monitor - does monitor configuration have particular counter?
 * @config: configuration to check
 * @monitor: counter to look for
 */
static inline bool config_has_monitor(union core_event_config config, enum cpu_monitor monitor)
{
	switch (monitor) {
	case DDM0:
		return config.ddm0 || config.monitor == DDM0 || config.monitor == DDM0_DDM1;
	case DDM1:
		return config.ddm1 || config.monitor == DDM1 || config.monitor == DDM0_DDM1;
	case DDM2:
		return config.ddm2 || config.monitor == DDM2;
	case DDM3:
		return config.ddm3 || config.monitor == DDM3;
	case DIM0:
		return config.dim0 || config.monitor == DIM0 || config.monitor == DIM0_DIM1;
	case DIM1:
		return config.dim1 || config.monitor == DIM1 || config.monitor == DIM0_DIM1;
	case DIM2:
		return config.dim2 || config.monitor == DIM2;
	case DIM3:
		return config.dim3 || config.monitor == DIM3;
	case DDM0_DDM1:
		return config.ddm0 || config.ddm1 || config.monitor == DDM0 ||
		       config.monitor == DDM1 || config.monitor == DDM0_DDM1;
	case DIM0_DIM1:
		return config.dim0 || config.dim1 || config.monitor == DIM0 ||
		       config.monitor == DIM1 || config.monitor == DIM0_DIM1;
	default:
		WARN_ONCE(1, "perf: unhandled monitor %d\n", monitor);
	}

	return false;
}

/**
 * config_has_event - does monitor configuration have particular event enabled?
 * @config: configuration to check
 * @monitor: monitor to look for
 * @event_id: event to look for
 */
static inline bool config_has_event(union core_event_config config,
		enum cpu_monitor monitor, int event_id)
{
	return config.event_id == event_id && config_has_monitor(config, monitor);
}

/**
 * config_to_hwc_idx - get `hw_perf_event.idx` value for event
 * @monitor: hardware monitor
 */
static inline int config_to_hwc_idx(union core_event_config config)
{
	/*
	 * Note that with the new `config.mask` format and also with old
	 * DDM0_DDM1/DIM0_DIM1 format idx will be initialized later dynamically.
	 */
	return (config.monitor == DIM3 || config.monitor == DDM3) ? 3 :
	       (config.monitor == DIM2 || config.monitor == DDM2) ? 2 :
	       (config.monitor == DIM1 || config.monitor == DDM1) ? 1 :
	       0;
}

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

extern bool hw_event_supported(u8 monitor, u8 event_id);
