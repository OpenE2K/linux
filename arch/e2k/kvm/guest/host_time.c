/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest time implementation.
 *
 * This is implemented in terms of a clocksource driver which uses
 * the hypervisor clock as a nanosecond timebase, and a clockevent
 * driver which uses the hypervisor's timer mechanism.
 *
 * Based on Xen implementation: arch/x86/xen/time.c
 */
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/clocksource.h>
#include <linux/clockchips.h>
#include <linux/kernel_stat.h>

#include <asm/kvm/guest.h>
#include "kvm_time.h"

/*
 * Time.
 *
 * It would be far better for everyone if the Guest had its own clock, but
 * until then the Host time on every guest running start.
 */

static void kvm_read_wallclock(struct timespec *ts)
{
	kvm_time_t *time_info = get_vcpu_time_info();
	long sec;

	do {
		sec = time_info->tv_sec;
		ts->tv_sec = sec;
		ts->tv_nsec = time_info->tv_nsec;
	} while (sec != time_info->tv_sec);
}

unsigned long kvm_get_rtc_time(void)
{
	struct timespec ts;

	kvm_read_wallclock(&ts);
	return ts.tv_sec;
}

int kvm_set_rtc_time(unsigned long now)
{
	/* do nothing for domU */
	return -1;
}
