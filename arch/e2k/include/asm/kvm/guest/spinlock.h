#ifndef __ASM_KVM_GUEST_SPINLOCK_H
#define __ASM_KVM_GUEST_SPINLOCK_H
/*
 * This file implements the arch-dependent parts of kvm guest
 * spin_lock()/spin_unlock() fast and slow part
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>

extern void kvm_arch_spin_lock_slow(void *lock);
extern void kvm_wait_read_lock_slow(arch_rwlock_t *rw);
extern void kvm_wait_write_lock_slow(arch_rwlock_t *rw);
extern void kvm_arch_spin_locked_slow(void *lock);
extern void kvm_arch_read_locked_slow(arch_rwlock_t *rw);
extern void kvm_arch_write_locked_slow(arch_rwlock_t *rw);
extern void kvm_arch_spin_unlock_slow(void *lock);
extern void kvm_arch_read_unlock_slow(arch_rwlock_t *lock);
extern void kvm_arch_write_unlock_slow(arch_rwlock_t *lock);

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* native guest kernel */

#define arch_spin_relax(lock)	kvm_cpu_relax()
#define arch_read_relax(lock)	kvm_cpu_relax()
#define arch_write_relax(lock)	kvm_cpu_relax()

static inline void
ord_wait_read_lock_slow(arch_rwlock_t *rw)
{
	kvm_wait_read_lock_slow(rw);
}
static inline void
ord_wait_write_lock_slow(arch_rwlock_t *rw)
{
	kvm_wait_write_lock_slow(rw);
}
static inline void
ord_arch_read_locked_slow(arch_rwlock_t *rw)
{
	kvm_arch_read_locked_slow(rw);
}
static inline void
ord_arch_write_locked_slow(arch_rwlock_t *rw)
{
	kvm_arch_write_locked_slow(rw);
}
static inline void
ord_arch_read_unlock_slow(arch_rwlock_t *rw)
{
	kvm_arch_read_unlock_slow(rw);
}
static inline void
ord_arch_write_unlock_slow(arch_rwlock_t *rw)
{
	kvm_arch_write_unlock_slow(rw);
}

static inline void arch_spin_lock_slow(arch_spinlock_t *lock)
{
	kvm_arch_spin_lock_slow(lock);
}
static inline void arch_spin_locked_slow(arch_spinlock_t *lock)
{
	kvm_arch_spin_locked_slow(lock);
}
static inline void arch_spin_unlock_slow(arch_spinlock_t *lock)
{
	kvm_arch_spin_unlock_slow(lock);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif	/* __ASM_KVM_GUEST_SPINLOCK_H */
