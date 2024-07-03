/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_KVM_TIME_H
#define __ASM_KVM_TIME_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/clocksource.h>

struct clock_event_device;

extern u64 kvm_clocksource_read(void);
extern void clockevents_shutdown(struct clock_event_device *dev);

#endif	/* __KERNEL__ */

#endif	/* __ASM_KVM_TIME_H */
