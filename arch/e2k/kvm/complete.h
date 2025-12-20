/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_COMPLETE_H
#define __KVM_E2K_COMPLETE_H

#include <linux/types.h>
#include <linux/sched/debug.h>

extern int kvm_wait_for_completion_interruptible(struct completion *x);

#endif	/* __KVM_E2K_COMPLETE_H */
