/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements the arch-dependent parts of kvm guest
 * spinlock()/spinunlock() slow part
 */

#include <linux/types.h>
#include <linux/sched.h>
#include <linux/spinlock.h>
#include <linux/export.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/spinlock.h>

#include "cpu.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_RW_MODE
#undef	DebugKVMRW
#define	DEBUG_KVM_RW_MODE	1	/* RW spinlocks debugging */
#define	DebugKVMRW(fmt, args...)					\
({									\
	if (DEBUG_KVM_RW_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/*
 * Slowpath of a guest spinlock: goto hypervisor to wait for spin unlocking
 */

static inline void do_arch_spin_lock_slow(void *lock, bool check_unlock)
{
	int err;

	DebugKVM("%s (%d) started for lock %px\n",
		current->comm, current->pid, lock);
	err = HYPERVISOR_guest_spin_lock_slow(lock, check_unlock);
	if (err == -EINTR) {
		DebugKVM("hypercall was interrupted to handle "
			"pending VIRQs\n");
	}
	if (err && err != -EINTR) {
		panic("HYPERVISOR_guest_spin_lock_slow() failed (error %d)\n",
			err);
	}
}

void kvm_arch_spin_lock_slow(void *lock)
{
	do_arch_spin_lock_slow(lock, true);
}
EXPORT_SYMBOL(kvm_arch_spin_lock_slow);

void kvm_wait_read_lock_slow(arch_rwlock_t *rw)
{
	do_arch_spin_lock_slow(rw, true);
}
EXPORT_SYMBOL(kvm_wait_read_lock_slow);

void kvm_wait_write_lock_slow(arch_rwlock_t *rw)
{
	do_arch_spin_lock_slow(rw, true);
}
EXPORT_SYMBOL(kvm_wait_write_lock_slow);

static inline void do_arch_spin_locked_slow(void *lock)
{
	int err;

	DebugKVM("%s (%d) started for lock %px\n",
		current->comm, current->pid, lock);
	do {
		err = HYPERVISOR_guest_spin_locked_slow(lock);
		if (err == -EINTR) {
			DebugKVM("hypercall was interrupted to handle "
				"pending VIRQs\n");
		}
	} while (err == -EINTR);
	if (err) {
		panic("HYPERVISOR_guest_spin_locked_slow() failed (error %d)\n",
			err);
	}
}
void kvm_arch_spin_locked_slow(void *lock)
{
	do_arch_spin_locked_slow(lock);
}
void kvm_arch_read_locked_slow(arch_rwlock_t *rw)
{
	do_arch_spin_locked_slow(rw);
}
EXPORT_SYMBOL(kvm_arch_read_locked_slow);

void kvm_arch_write_locked_slow(arch_rwlock_t *rw)
{
	do_arch_spin_locked_slow(rw);
}
EXPORT_SYMBOL(kvm_arch_write_locked_slow);

/*
 * Slowpath of a guest spinunlock: goto hypervisor to wake up proccesses
 * which are waiting on this lock
 */
static inline void do_arch_spin_unlock_slow(void *lock, bool add_to_unlock)
{
	int err;

	DebugKVM("%s (%d) started for lock %px add to unlock list %d\n",
		current->comm, current->pid, lock, add_to_unlock);
	err = HYPERVISOR_guest_spin_unlock_slow(lock, add_to_unlock);
	if (err) {
		panic("kvm_arch_spin_unlock_slow() failed (error %d)\n",
			err);
	}
}
void kvm_arch_spin_unlock_slow(void *lock)
{
	do_arch_spin_unlock_slow(lock, true);
}
EXPORT_SYMBOL(kvm_arch_spin_unlock_slow);

void kvm_arch_read_unlock_slow(arch_rwlock_t *rw)
{
	do_arch_spin_unlock_slow(rw, true);
}
EXPORT_SYMBOL(kvm_arch_read_unlock_slow);

void kvm_arch_write_unlock_slow(arch_rwlock_t *rw)
{
	do_arch_spin_unlock_slow(rw, true);
}
EXPORT_SYMBOL(kvm_arch_write_unlock_slow);
