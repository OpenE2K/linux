#ifndef __ASM_KVM_GUEST_BOOT_SPINLOCK_H
#define __ASM_KVM_GUEST_BOOT_SPINLOCK_H
/*
 * This file implements the arch-dependent parts of kvm guest
 * boot-time spin_lock()/spin_unlock() fast and slow part
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>

extern void kvm_arch_boot_spin_lock_slow(void *lock);
extern void kvm_arch_boot_spin_locked_slow(void *lock);
extern void kvm_arch_boot_spin_unlock_slow(void *lock);

#ifdef	CONFIG_KVM_GUEST_KERNEL
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

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASM_KVM_GUEST_BOOT_SPINLOCK_H */
