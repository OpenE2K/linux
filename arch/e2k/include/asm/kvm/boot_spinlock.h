/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * This file implements the arch-dependent parts of kvm guest
 * boot time spin_lock()/spin_unlock() slow part
 */

#ifndef __ASM_E2K_KVM_BOOT_SPINLOCK_H
#define __ASM_E2K_KVM_BOOT_SPINLOCK_H

#include <linux/types.h>
#include <linux/spinlock_types.h>

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is virtualized guest kernel */
#include <asm/kvm/guest/boot_spinlock.h>
#else	/* !CONFIG_KVM_GUEST_KERNEL */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST_KERNEL */

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

#endif	/* __ASM_E2K_KVM_BOOT_SPINLOCK_H */
