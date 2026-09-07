/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements the arch-dependent parts of kvm guest
 * boot-time spin_lock()/spin_unlock() fast and slow part
 */

#ifndef __ASM_KVM_GUEST_BOOT_SPINLOCK_H
#define __ASM_KVM_GUEST_BOOT_SPINLOCK_H

#include <linux/types.h>
#include <linux/spinlock_types.h>

extern void kvm_arch_boot_spin_lock_slow(void *lock);
extern void kvm_arch_boot_spin_locked_slow(void *lock);
extern void kvm_arch_boot_spin_unlock_slow(void *lock);

/* native guest kernel */

#define arch_spin_relax(lock)	kvm_cpu_relax()
#define arch_read_relax(lock)	kvm_cpu_relax()
#define arch_write_relax(lock)	kvm_cpu_relax()

static inline void boot_arch_spin_lock_slow(boot_spinlock_t *lock)
{
	kvm_arch_boot_spin_lock_slow(lock);
}
static inline void boot_arch_spin_locked_slow(boot_spinlock_t *lock)
{
	kvm_arch_boot_spin_locked_slow(lock);
}
static inline void boot_arch_spin_unlock_slow(boot_spinlock_t *lock)
{
	kvm_arch_boot_spin_unlock_slow(lock);
}

#define arch_boot_spin_unlock kvm_boot_spin_unlock
static inline void kvm_boot_spin_unlock(boot_spinlock_t *lock)
{
	boot_spinlock_t val;
	u16 ticket, ready;

	wmb();	/* wait for all store completion */
	val.lock = __api_atomic16_add_return32_lock(
			1 << BOOT_SPINLOCK_HEAD_SHIFT, &lock->lock);
	ticket = val.tail;
	ready = val.head;

	if (unlikely(ticket != ready)) {
		/* spinlock has more user(s): so activate it(s) */
		boot_arch_spin_unlock_slow(lock);
	}
}

#endif	/* __ASM_KVM_GUEST_BOOT_SPINLOCK_H */
