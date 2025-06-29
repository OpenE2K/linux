/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <string.h>
#include <linux/perf_event.h>
#include <linux/zalloc.h>

#include "../../util/debug.h"
#include "../../util/e2k-dimtp.h"
#include "../../util/pmu.h"
#include "../../util/util.h"

#ifdef HAVE_AUXTRACE_SUPPORT
struct perf_event_attr
*perf_pmu__get_default_config(struct perf_pmu *pmu __maybe_unused)
{
	struct perf_event_attr *attr;

	if (strcmp(pmu->name, E2K_DIMTP_PMU_NAME))
		return NULL;

	attr = zalloc(sizeof(struct perf_event_attr));
	if (!attr) {
		pr_err("dimtp default config cannot allocate a perf_event_attr\n");
		return NULL;
	}

	/*
	 * Only constant period is supported, set default value
	 */
	attr->sample_period = 4096;

	return attr;
}
#endif
