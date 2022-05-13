#ifndef __ASM_PARAVIRT_SPINLOCK_H
#define __ASM_PARAVIRT_SPINLOCK_H
/*
 * This file implements the arch-dependent parts of kvm guest
 * spin_lock()/spin_unlock() fast and slow part
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
 */

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

static inline void
pv_arch_spin_lock_slow(arch_spinlock_t *lock)
{
	pv_cpu_ops.arch_spin_lock_slow(lock);
}
static inline void
pv_arch_spin_locked_slow(arch_spinlock_t *lock)
{
	pv_cpu_ops.arch_spin_locked_slow(lock);
}
static inline void
pv_arch_spin_unlock_slow(arch_spinlock_t *lock)
{
	pv_cpu_ops.arch_spin_unlock_slow(lock);
}

static inline void
pv_ord_wait_read_lock_slow(arch_rwlock_t *rw)
{
	if (pv_cpu_ops.ord_wait_read_lock_slow)
		pv_cpu_ops.ord_wait_read_lock_slow(rw);
}
static inline void
pv_ord_wait_write_lock_slow(arch_rwlock_t *rw)
{
	if (pv_cpu_ops.ord_wait_write_lock_slow)
		pv_cpu_ops.ord_wait_write_lock_slow(rw);
}
static inline void
pv_ord_arch_read_locked_slow(arch_rwlock_t *rw)
{
	if (pv_cpu_ops.ord_arch_read_locked_slow)
		pv_cpu_ops.ord_arch_read_locked_slow(rw);
}
static inline void
pv_ord_arch_write_locked_slow(arch_rwlock_t *rw)
{
	if (pv_cpu_ops.ord_arch_write_locked_slow)
		pv_cpu_ops.ord_arch_write_locked_slow(rw);
}
static inline void
pv_ord_arch_read_unlock_slow(arch_rwlock_t *rw)
{
	if (pv_cpu_ops.ord_arch_read_unlock_slow)
		pv_cpu_ops.ord_arch_read_unlock_slow(rw);
}
static inline void
pv_ord_arch_write_unlock_slow(arch_rwlock_t *rw)
{
	if (pv_cpu_ops.ord_arch_write_unlock_slow)
		pv_cpu_ops.ord_arch_write_unlock_slow(rw);
}

static inline void
boot_pv_arch_spin_lock_slow(arch_spinlock_t *lock)
{
	BOOT_PARAVIRT_GET_CPU_FUNC(arch_spin_lock_slow)(lock);
}
static inline void
boot_pv_arch_spin_locked_slow(arch_spinlock_t *lock)
{
	BOOT_PARAVIRT_GET_CPU_FUNC(arch_spin_locked_slow)(lock);
}
static inline void
boot_pv_arch_spin_unlock_slow(arch_spinlock_t *lock)
{
	BOOT_PARAVIRT_GET_CPU_FUNC(arch_spin_unlock_slow)(lock);
}

#ifdef	CONFIG_PARAVIRT_GUEST
/* it is paravirtualized host and guest kernel */

#define arch_spin_relax(lock)	pv_cpu_relax()
#define arch_read_relax(lock)	pv_cpu_relax()
#define arch_write_relax(lock)	pv_cpu_relax()

static inline void
arch_spin_lock_slow(arch_spinlock_t *lock)
{
	pv_arch_spin_lock_slow(lock);
}
static inline void
arch_spin_locked_slow(arch_spinlock_t *lock)
{
	pv_arch_spin_locked_slow(lock);
}
static inline void
arch_spin_unlock_slow(arch_spinlock_t *lock)
{
	pv_arch_spin_unlock_slow(lock);
}
/* boot-time functions */
static inline void boot_arch_spin_lock_slow(arch_spinlock_t *lock)
{
	boot_pv_arch_spin_lock_slow(lock);
}
static inline void boot_arch_spin_locked_slow(arch_spinlock_t *lock)
{
	boot_pv_arch_spin_locked_slow(lock);
}
static inline void boot_arch_spin_unlock_slow(arch_spinlock_t *lock)
{
	boot_pv_arch_spin_unlock_slow(lock);
}

static inline void
ord_wait_read_lock_slow(arch_rwlock_t *rw)
{
	pv_ord_wait_read_lock_slow(rw);
}
static inline void
ord_wait_write_lock_slow(arch_rwlock_t *rw)
{
	pv_ord_wait_write_lock_slow(rw);
}
static inline void
ord_arch_read_locked_slow(arch_rwlock_t *rw)
{
	pv_ord_arch_read_locked_slow(rw);
}
static inline void
ord_arch_write_locked_slow(arch_rwlock_t *rw)
{
	pv_ord_arch_write_locked_slow(rw);
}
static inline void
ord_arch_read_unlock_slow(arch_rwlock_t *rw)
{
	pv_ord_arch_read_unlock_slow(rw);
}
static inline void
ord_arch_write_unlock_slow(arch_rwlock_t *rw)
{
	pv_ord_arch_write_unlock_slow(rw);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif	/* __ASM_PARAVIRT_SPINLOCK_H */
