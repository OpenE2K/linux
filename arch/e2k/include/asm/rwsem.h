/* rwsem.h: R/W semaphores implemented using XADD/CMPXCHG
 *
 * Written by David Howells (dhowells@redhat.com).
 *
 * Derived from asm-x86/semaphore.h
 *
 *
 * The MSW of the count is the negated number of active writers and waiting
 * lockers, and the LSW is the total number of active locks
 *
 * The lock count is initialized to 0 (no active and no waiting lockers).
 *
 * When a writer subtracts WRITE_BIAS, it'll get 0xffff0001 for the case of an
 * uncontended lock. This can be determined because XADD returns the old value.
 * Readers increment by 1 and see a positive value when uncontended, negative
 * if there are writers (and maybe) readers waiting (in which case it goes to
 * sleep).
 *
 * The value of WAITING_BIAS supports up to 32766 waiting processes. This can
 * be extended to 65534 by manually checking the whole MSW rather than relying
 * on the S flag.
 *
 * The value of ACTIVE_BIAS supports up to 65535 active processes.
 *
 * This should be totally fair - if anything is waiting, a process that wants a
 * lock will go to the back of the queue. When the currently active lock is
 * released, if there's a writer at the front of the queue, then that and only
 * that will be woken up; if there's a bunch of consequtive readers at the
 * front, then they'll all be woken up, but no other readers will be.
 */

#ifndef _E2K_RWSEM_H
#define _E2K_RWSEM_H

#ifndef _LINUX_RWSEM_H
#error "please don't include asm/rwsem.h directly, use linux/rwsem.h instead"
#endif

#ifdef __KERNEL__

#include <linux/list.h>
#include <linux/spinlock.h>

#define RWSEM_UNLOCKED_VALUE		0L
#define RWSEM_ACTIVE_BIAS		1L
#define RWSEM_ACTIVE_MASK		0x00000000ffffffffL
#define RWSEM_WAITING_BIAS		(-RWSEM_ACTIVE_MASK-1)
#define RWSEM_ACTIVE_READ_BIAS		RWSEM_ACTIVE_BIAS
#define RWSEM_ACTIVE_WRITE_BIAS		(RWSEM_WAITING_BIAS + RWSEM_ACTIVE_BIAS)

/*
 * lock for reading
 */

static inline int ___down_read(struct rw_semaphore *sem)
{
	long newcount;

#ifndef CONFIG_SMP
	newcount = sem->count.counter + RWSEM_ACTIVE_READ_BIAS;
	sem->count.counter = newcount;
#else
	newcount = __api_atomic_op(RWSEM_ACTIVE_READ_BIAS,
				   &sem->count, d, "addd", LOCK_MB);
#endif

	return (newcount <= 0);
}

static inline void __down_read(struct rw_semaphore *sem)
{
	if (unlikely(___down_read(sem)))
		rwsem_down_read_failed(sem);
}

static inline int __down_read_killable(struct rw_semaphore *sem)
{
	if (unlikely(___down_read(sem)))
		if (IS_ERR(rwsem_down_read_failed_killable(sem)))
			return -EINTR;

	return 0;
}

/*
 * trylock for reading -- returns 1 if successful, 0 if contention
 */
static inline int __down_read_trylock(struct rw_semaphore *sem)
{
	long newcount;

#ifndef CONFIG_SMP
	if (sem->count.counter >= 0)
		sem->count.counter += RWSEM_ACTIVE_READ_BIAS;
	newcount = sem->count.counter;
#else
	newcount = __api_atomic64_add_if_not_negative(RWSEM_ACTIVE_READ_BIAS,
			&sem->count, LOCK_MB);
#endif

	return newcount > 0;
}

/*
 * lock for writing
 */
static inline long  ___down_write(struct rw_semaphore *sem)
{
	long newcount;

#ifndef CONFIG_SMP
	newcount = sem->count.counter + RWSEM_ACTIVE_WRITE_BIAS;
	sem->count.counter = newcount;
#else
	newcount = __api_atomic_op(RWSEM_ACTIVE_WRITE_BIAS,
				   &sem->count, d, "addd", LOCK_MB);
#endif
	return newcount;
}

static inline void __down_write(struct rw_semaphore *sem)
{
	if (unlikely(___down_write(sem) != RWSEM_ACTIVE_WRITE_BIAS))
		rwsem_down_write_failed(sem);
}

static inline int __down_write_killable(struct rw_semaphore *sem)
{
	if (unlikely(___down_write(sem) != RWSEM_ACTIVE_WRITE_BIAS))
		if (IS_ERR(rwsem_down_write_failed_killable(sem)))
			return -EINTR;
	return 0;
}

/*
 * trylock for writing -- returns 1 if successful, 0 if contention
 */
static inline int __down_write_trylock(struct rw_semaphore *sem)
{
	long oldcount;

#ifndef CONFIG_SMP
	oldcount = sem->count.counter;
	if (oldcount == RWSEM_UNLOCKED_VALUE)
		sem->count.counter = RWSEM_ACTIVE_WRITE_BIAS;
#else
	oldcount = atomic_long_cmpxchg(&sem->count, RWSEM_UNLOCKED_VALUE,
			RWSEM_ACTIVE_WRITE_BIAS);
#endif

	return oldcount == RWSEM_UNLOCKED_VALUE;
}

/*
 * unlock after reading
 */
static inline void __up_read(struct rw_semaphore *sem)
{
	long newcount;

#ifndef CONFIG_SMP
	sem->count.counter -= RWSEM_ACTIVE_READ_BIAS;
	newcount = sem->count.counter;
#else
	newcount = __api_atomic_op(RWSEM_ACTIVE_READ_BIAS,
				   &sem->count, d, "subd", RELEASE_MB);
#endif

	if (unlikely(newcount < -1))
		if ((newcount & RWSEM_ACTIVE_MASK) == 0)
			rwsem_wake(sem);
}

/*
 * unlock after writing
 */
static inline void __up_write(struct rw_semaphore *sem)
{
	long newcount;

#ifndef CONFIG_SMP
	sem->count.counter -= RWSEM_ACTIVE_WRITE_BIAS;
	newcount = sem->count.counter;
#else
	newcount = __api_atomic_op(RWSEM_ACTIVE_WRITE_BIAS,
				   &sem->count, d, "subd", RELEASE_MB);
#endif
	if (unlikely(newcount < 0))
		rwsem_wake(sem);
}

/*
 * downgrade write lock to read lock
 */
static inline void __downgrade_write(struct rw_semaphore *sem)
{
	long newcount;

#ifndef CONFIG_SMP
	newcount = sem->count.counter - RWSEM_WAITING_BIAS;
	sem->count.counter = newcount;
#else
	newcount = __api_atomic_op(RWSEM_WAITING_BIAS,
				   &sem->count, d, "subd", RELEASE_MB);
#endif

	if (unlikely(newcount < 0))
		rwsem_downgrade_wake(sem);
}

#endif /* __KERNEL__ */
#endif /* _E2K_RWSEM_H */
