/*
 * SMP spinlock mechanism. 1 - unlock state for basic spinlocks
 * (i386 architecture basis).
 * RW_LOCK_BIAS - read/write spinlocks initial state allowing
 * 2^24 readers and only one writer.
 */


#ifndef __ASM_SPINLOCK_H
#define __ASM_SPINLOCK_H

#include <asm/atomic.h>
#include <asm/head.h>
#include <asm/e2k_api.h>
#include <asm/processor.h>

/*
 * Simple spin lock operations.  There are two variants, one clears IRQ's
 * on the local processor, one does not.
 *
 * (the type definitions are in asm/spinlock_types.h)
 */

static inline void arch_spin_unlock_wait(arch_spinlock_t *lock)
{
	arch_spinlock_t val;
	u16 next;

	val.lock = ACCESS_ONCE(lock->lock);

	if (likely(val.head == val.tail))
		return;

	next = val.tail;

	do {
		val.lock = ACCESS_ONCE(lock->lock);
	} while (val.head != val.tail && ((s16) (next - val.head) > 0));
}

static inline int arch_spin_is_locked(arch_spinlock_t *lock)
{
	arch_spinlock_t val;

	val.lock = ACCESS_ONCE(lock->lock);

	return val.head != val.tail;
}

static __always_inline int arch_spin_value_unlocked(arch_spinlock_t lock)
{
	return lock.head == lock.tail;
}

#define arch_spin_is_contended arch_spin_is_contended
static inline int arch_spin_is_contended(arch_spinlock_t *lock)
{
	arch_spinlock_t val;

	val.lock = ACCESS_ONCE(lock->lock);

	return val.tail - val.head > 1;
}

/*
 * This works. Despite all the confusion.
 */

static inline int arch_spin_trylock(arch_spinlock_t *lock)
{
	return __api_atomic_ticket_trylock(&lock->lock,
			ARCH_SPINLOCK_TAIL_SHIFT);
}

static inline void arch_spin_lock(arch_spinlock_t *lock)
{
	arch_spinlock_t val;
	u16 ticket, ready;

	/* Tail must be in the high 16 bits, otherwise this atomic
	 * addition will corrupt head. */
	val.lock = __api_atomic32_add_oldval(1 << ARCH_SPINLOCK_TAIL_SHIFT,
			&lock->lock);
	ticket = val.tail;
	ready = val.head;

	while (unlikely(ticket != ready))
		ready = ACCESS_ONCE(lock->head);
}

static inline void arch_spin_unlock(arch_spinlock_t *lock)
{
	/* Let critical section finish execution */
	smp_mb();
	++lock->head;
}

/*
 * arch_spin_lock_flags() is the same as arch_spin_lock()
 * but spins with interrupts enabled (note that preemption
 * is still disabled). Also note that only *_lock_irqsave
 * functions use arch_spin_lock_flags().
 */
static inline void arch_spin_lock_flags(arch_spinlock_t *const lock,
		const unsigned long flags)
{
	arch_spinlock_t val;
	u16 ticket, ready;

	/* Fast path */
	if (likely(arch_spin_trylock(lock)))
		return;

	/* Slow path */
	if (!raw_irqs_disabled_flags(flags)) {
		unsigned long disabled_flags;

		val.lock = ACCESS_ONCE(lock->lock);

		disabled_flags = arch_local_save_flags();

		if (val.tail - val.head == 1) {
			/* We use FIFO queue which does not allow removal.
			 * This means that we cannot enable interrupts after
			 * adding ourselves to the queue.
			 *
			 * So we use a compromise: only the first and
			 * uncontended wait is with enabled interrupts, */
			u16 next = val.tail;
			raw_local_irq_restore(flags);
			do {
				val.lock = ACCESS_ONCE(lock->lock);
			} while (val.head != val.tail &&
				 ((s16) (next - val.head) > 0));
			raw_local_irq_restore(disabled_flags);
		}
	}

	/* Tail must be in the high 16 bits, otherwise this atomic
	 * addition will corrupt head. */
	val.lock = __api_atomic32_add_oldval(1 << ARCH_SPINLOCK_TAIL_SHIFT,
			&lock->lock);
	ticket = val.tail;
	ready = val.head;

	while (unlikely(ticket != ready))
		ready = ACCESS_ONCE(lock->head);
}

/*
 * Read-write spinlocks, allowing multiple readers but only one writer.
 *
 * NOTE! it is quite common to have readers in interrupts but no interrupt
 * writers.
 * For those circumstances we can "mix" irq-safe locks - any writer needs
 * to get a irq-safe write-lock, but readers can get non-irqsafe read-locks.
 *
 * On e2k as on x86, we implement read-write locks as a 32-bit counter
 * with the high bit (sign) being the "contended" bit.
 *
 * The inline assembly is non-obvious. Think about it.
 *
 * Changed to use the same technique as rw semaphores.  See
 * semaphore.h for details.  -ben
 */

/**
 * read_can_lock - would read_trylock() succeed?
 * @lock: the rwlock in question.
 */
static inline int arch_read_can_lock(arch_rwlock_t *lock)
{
	return (int)(lock)->lock > 0;
}

/**
 * write_can_lock - would write_trylock() succeed?
 * @lock: the rwlock in question.
 */
static inline int arch_write_can_lock(arch_rwlock_t *lock)
{
	return (lock)->lock == RW_LOCK_BIAS;
}

static inline void
arch_read_lock(arch_rwlock_t *rw)
{
	int count;

	do {
		count = atomic_dec_return((atomic_t *)rw);
		if (count >= 0) break;
		atomic_inc((atomic_t *)rw);
		while (*(volatile int *)&(rw->lock) <= 0);
	} while(1);
}

static inline void
arch_write_lock(arch_rwlock_t *rw)
{
	int count;

	do {
		count = atomic_sub_return(RW_LOCK_BIAS, (atomic_t *)rw);
		if (!count) break;
		atomic_add(RW_LOCK_BIAS, (atomic_t *)rw);
		while (*(volatile int *)&(rw->lock) != RW_LOCK_BIAS);
	} while(1);
}

static inline void
arch_read_unlock(arch_rwlock_t *rw)
{
	atomic_t *count = (atomic_t *) rw;
	smp_mb__before_atomic_inc();
	atomic_inc(count);
}

static inline void
arch_write_unlock(arch_rwlock_t *rw)
{
	smp_mb__before_atomic_inc();
	atomic_add(RW_LOCK_BIAS, (atomic_t *)rw);
}

static inline int
arch_read_trylock(arch_rwlock_t *lock)
{
	atomic_t *count = (atomic_t *)lock;
	atomic_dec(count);
	if (atomic_read(count) >= 0) {
		smp_mb__after_atomic_dec();
		return 1;
	}
	atomic_inc(count);
	return 0;
}

static inline int
arch_write_trylock(arch_rwlock_t *lock)
{
	atomic_t *count = (atomic_t *)lock;
	if (atomic_sub_and_test(RW_LOCK_BIAS, count))
		return 1;
	atomic_add(RW_LOCK_BIAS, count);
	return 0;
}

#define arch_read_lock_flags(lock, flags) arch_read_lock(lock)
#define arch_write_lock_flags(lock, flags) arch_write_lock(lock)

#define arch_spin_relax(lock)	cpu_relax()
#define arch_read_relax(lock)	cpu_relax()
#define arch_write_relax(lock)	cpu_relax()

/* The {read|write|spin}_lock() are full memory barriers on e2k. */
#define smp_mb__after_lock()	do { } while (0)
#define ARCH_HAS_SMP_MB_AFTER_LOCK

#endif        /* __ASM_SPINLOCK_H */
