/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#include <linux/types.h>

void freeze_sched_clock(void);
void unfreeze_sched_clock(void);

void save_sched_clock_state(void);
void restore_sched_clock_state(void);