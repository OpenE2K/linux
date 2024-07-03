/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements the arch-dependent parts of kvm guest
 * boot-time spinlock()/spinunlock() slow part
 */

#include <asm/p2v/boot_v2p.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/module.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/boot_spinlock.h>

#include "cpu.h"

#undef	DEBUG_BOOT_SPINLOCK_MODE
#undef	DebugBSL
#define	DEBUG_BOOT_SPINLOCK_MODE	0	/* boot-time spinlocks */
						/* debugging */
#define	DebugBSL(fmt, args...)						\
({									\
	if (DEBUG_BOOT_SPINLOCK_MODE)					\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

/*
 * Slowpath of a guest spinlock: goto hypervisor to wait for spin unlocking
 */

static inline void do_arch_boot_spin_lock_slow(void *lock, bool check_unlock)
{
	int err;

	DebugBSL("started on vcpu #%d for lock %px\n",
		boot_smp_processor_id(), lock);
	err = HYPERVISOR_boot_spin_lock_slow(lock, check_unlock);
	if (err) {
		BOOT_BUG("HYPERVISOR_guest_boot_spin_lock_slow() failed "
			"(error %d)\n",
			err);
	}
}

void kvm_arch_boot_spin_lock_slow(void *lock)
{
	do_arch_boot_spin_lock_slow(lock, true);
}

static inline void do_arch_boot_spin_locked_slow(void *lock)
{
	int err;

	DebugBSL("%s (%d) started for lock %px\n",
		boot_smp_processor_id(), lock);
	err = HYPERVISOR_boot_spin_locked_slow(lock);
	if (err) {
		BOOT_BUG("HYPERVISOR_guest_spin_locked_slow() failed "
			"(error %d)\n",
			err);
	}
}
void kvm_arch_boot_spin_locked_slow(void *lock)
{
	do_arch_boot_spin_locked_slow(lock);
}

/*
 * Slowpath of a guest spinunlock: goto hypervisor to wake up proccesses
 * which are waiting on this lock
 */
static inline void do_arch_boot_spin_unlock_slow(void *lock, bool add_to_unlock)
{
	int err;

	DebugBSL("%s (%d) started for lock %px add to unlock list %d\n",
		boot_smp_processor_id(), lock, add_to_unlock);
	err = HYPERVISOR_boot_spin_unlock_slow(lock, add_to_unlock);
	if (err) {
		BOOT_BUG("HYPERVISOR_guest_boot_spin_unlock_slow() failed "
			"(error %d)\n",
			err);
	}
}
void kvm_arch_boot_spin_unlock_slow(void *lock)
{
	do_arch_boot_spin_unlock_slow(lock, true);
}
