#pragma once

#include <asm/p2v/boot_spinlock_types.h>
#include <asm/atomic.h>


# if defined(CONFIG_PARAVIRT_GUEST) || defined(CONFIG_KVM_GUEST_KERNEL)
/* it is paravirtualized host and guest kernel */
/* or native guest kernel */
#  include <asm/kvm/boot_spinlock.h>
#  define arch_boot_spin_lock_slow(lock)	\
		kvm_arch_boot_spin_lock_slow((lock))
#  define arch_boot_spin_locked_slow(lock)	\
		kvm_arch_boot_spin_locked_slow((lock))
# else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
#  define arch_boot_spin_lock_slow(lock)	do { } while (0)
#  define arch_boot_spin_locked_slow(lock)	do { } while (0)
# endif	/* CONFIG_PARAVIRT_GUEST || CONFIG_KVM_GUEST_KERNEL */


static inline void boot_native_spin_unlock_wait(boot_spinlock_t *lock)
{
	boot_spinlock_t val;
	u16 next;

	val.lock = READ_ONCE(lock->lock);

	if (likely(val.head == val.tail))
		return;

	next = val.tail;

	do {
		val.lock = READ_ONCE(lock->lock);
	} while (val.head != val.tail && ((s16) (next - val.head) > 0));
}

static inline int boot_native_spin_is_locked(boot_spinlock_t *lock)
{
	boot_spinlock_t val;

	val.lock = READ_ONCE(lock->lock);

	return val.head != val.tail;
}

static __always_inline int boot_native_spin_value_unlocked(boot_spinlock_t lock)
{
	return lock.head == lock.tail;
}

static inline int boot_native_spin_is_contended(boot_spinlock_t *lock)
{
	boot_spinlock_t val;

	val.lock = READ_ONCE(lock->lock);

	return val.tail - val.head > 1;
}

static inline int arch_boot_spin_trylock(boot_spinlock_t *lock)
{
	return __api_atomic_ticket_trylock(&lock->lock,
			BOOT_SPINLOCK_TAIL_SHIFT);
}

static inline void arch_boot_spin_lock(boot_spinlock_t *lock)
{
	boot_spinlock_t val;
	u16 ticket, ready;

	/* Tail must be in the high 16 bits, otherwise this atomic
	 * addition will corrupt head. */
	val.lock = __api_atomic32_add_oldval_lock(1 << BOOT_SPINLOCK_TAIL_SHIFT,
			&lock->lock);
	ticket = val.tail;
	ready = val.head;

	if (likely(ticket == ready))
		return;

	do {
		arch_boot_spin_lock_slow(lock);
	} while (unlikely(ticket != (ready = READ_ONCE(lock->head))));

	arch_boot_spin_locked_slow(lock);
}

#ifndef arch_boot_spin_unlock
#define arch_boot_spin_unlock arch_boot_spin_unlock
static inline void arch_boot_spin_unlock(boot_spinlock_t *lock)
{
	smp_store_release(&lock->head, lock->head + 1);
}
#endif
