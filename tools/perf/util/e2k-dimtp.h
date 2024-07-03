/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#pragma once

#define E2K_DIMTP_PMU_NAME "dimtp_trace"

enum {
	E2K_DIMTP_PMU_TYPE,
	E2K_DIMTP_AUXTRACE_PRIV_MAX,
};

#define E2K_DIMTP_AUXTRACE_PRIV_SIZE (E2K_DIMTP_AUXTRACE_PRIV_MAX * sizeof(u64))

union perf_event;
struct perf_session;

int e2k_dimtp_process_auxtrace_info(union perf_event *event,
				  struct perf_session *session);
