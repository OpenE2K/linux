/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __KVM_E2K_TIME_H
#define __KVM_E2K_TIME_H

#include <linux/kvm_host.h>
#include <asm/cpu_regs.h>
#include <asm/trap_table.h>
#include <asm/time.h>

/*
 * VCPU state structure contains time structure of VCPU.
 * The structure is common for host and guest and can (and should)
 * be accessed by both.
 * Guest access do through global pointer which should be load on some global
 * register (GUEST_VCPU_STATE_GREG) or on special CPU register GD.
 * But GD can be used only if guest kernel run as protected task
 */

/*
 * Basic functions to access to time structure (see asm/kvm/guest.h) on host.
 */
static inline long
kvm_get_guest_time(struct kvm *kvm, kvm_timespec_t *vcpu_ts,
		   struct timespec64 *ts)
{
	long secs, nsecs;

	/* read time in consistent state */
	raw_spin_lock(&kvm->arch.time_state_lock);
	secs = vcpu_ts->tv_sec;
	nsecs = vcpu_ts->tv_nsec;
	raw_spin_unlock(&kvm->arch.time_state_lock);

	ts->tv_sec = secs;
	ts->tv_nsec = nsecs;
	return secs * NSEC_PER_SEC + nsecs;
}

static inline void
kvm_set_guest_time(struct kvm *kvm, kvm_timespec_t *kvm_ts,
		   struct timespec64 *ts)
{
	long secs, nsecs;

	nsecs = ts->tv_nsec;
	secs = ts->tv_sec;

	raw_spin_lock(&kvm->arch.time_state_lock);
	kvm_ts->tv_nsec = nsecs;
	kvm_ts->tv_sec = secs;
	raw_spin_unlock(&kvm->arch.time_state_lock);
}

static inline long
kvm_get_guest_system_time(struct kvm *kvm, struct timespec64 *ts)
{
	kvm_timespec_t *sys_time;

	sys_time = &(kvm->arch.kmap_host_info->time.sys_time);
	return kvm_get_guest_time(kvm, sys_time, ts);
}

static inline void
kvm_set_guest_system_time(struct kvm *kvm, struct timespec64 *ts)
{
	kvm_timespec_t *sys_time;

	sys_time = &(kvm->arch.kmap_host_info->time.sys_time);
	kvm_set_guest_time(kvm, sys_time, ts);
}

static inline long
kvm_get_guest_wall_time(struct kvm *kvm, struct timespec64 *ts)
{
	kvm_timespec_t *wall_time;

	wall_time = &(kvm->arch.kmap_host_info->time.wall_time);
	return kvm_get_guest_time(kvm, wall_time, ts);
}

static inline void
kvm_set_guest_wall_time(struct kvm *kvm, struct timespec64 *ts)
{
	kvm_timespec_t *wall_time;

	wall_time = &(kvm->arch.kmap_host_info->time.wall_time);
	kvm_set_guest_time(kvm, wall_time, ts);
}

static inline void
kvm_update_guest_wall_time(struct kvm *kvm)
{
	struct timespec64 ts;

	ts.tv_sec = mach_get_wallclock();
	ts.tv_nsec = 0;
	kvm_set_guest_wall_time(kvm, &ts);
}

static inline void
kvm_update_guest_system_time(struct kvm *kvm)
{
	struct timespec64 ts;

	ktime_get_ts64(&ts);
	kvm_set_guest_system_time(kvm, &ts);
}

static inline void
kvm_update_guest_time(struct kvm *kvm)
{
	kvm_update_guest_wall_time(kvm);
	kvm_update_guest_system_time(kvm);
}
#endif	/* __KVM_E2K_TIME_H */
