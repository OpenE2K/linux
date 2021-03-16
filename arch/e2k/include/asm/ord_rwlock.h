/*
 * New SMP ordered read/write spinlock mechanism.
 * Locking is ordered and later readers cannot outrun former writers.
 * Locking order based on coupons (tickets) received while first try to get
 * lock, if lock is already taken by other.
 *
 * read/write spinlocks initial state allowing 2^32 active readers and
 * only one active writer. But coupon discipline allows simultaniously
 * have only 2^16 registered users of the lock: active + waiters
*/


#ifndef __ASM_ORD_RWLOCK_H
#define __ASM_ORD_RWLOCK_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/host_printk.h>

#undef	DEBUG_RWLOCK_MODE
#undef	DebugRW
#define	DEBUG_RWLOCK_MODE	0	/* RW spinlocks debugging */
#define	DebugRW(fmt, args...)						\
({									\
	if (DEBUG_RWLOCK_MODE)						\
		host_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_SLOW_RWLOCK_MODE
#undef	DebugSLRW
#define	DEBUG_SLOW_RWLOCK_MODE	0	/* RW spinlocks slow path debugging */
#define	DebugSLRW(fmt, args...)						\
({									\
	if (DEBUG_SLOW_RWLOCK_MODE)					\
		host_printk("%s(): " fmt, __func__, ##args); \
})

/*
 * Read-write spinlocks, allowing multiple readers but only one writer.
 */

static inline void
native_ord_wait_read_lock_slow(arch_rwlock_t *rw)
{
	/* waiting always on CPU, so nothing do some more */
}
static inline void
native_ord_wait_write_lock_slow(arch_rwlock_t *rw)
{
	/* waiting always on CPU, so nothing do some more */
}
static inline void
native_ord_arch_read_locked_slow(arch_rwlock_t *rw)
{
	/* waiting always on CPU, so nothing do some more */
}
static inline void
native_ord_arch_write_locked_slow(arch_rwlock_t *rw)
{
	/* waiting always on CPU, so nothing do some more */
}
static inline void
native_ord_arch_read_unlock_slow(arch_rwlock_t *rw)
{
	/* waiting always on CPU, so nothing do some more */
}
static inline void
native_ord_arch_write_unlock_slow(arch_rwlock_t *rw)
{
	/* waiting always on CPU, so nothing do some more */
}

#if	defined(CONFIG_PARAVIRT_GUEST) || defined(CONFIG_KVM_GUEST_KERNEL)
/* it is paravirtualized host and guest kernel */
/* or native guest kernel */
#include <asm/kvm/spinlock.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel */
/* or native kernel with virtualization support */

static inline void
ord_wait_read_lock_slow(arch_rwlock_t *rw)
{
	native_ord_wait_read_lock_slow(rw);
}
static inline void
ord_wait_write_lock_slow(arch_rwlock_t *rw)
{
	native_ord_wait_write_lock_slow(rw);
}
static inline void
ord_arch_read_locked_slow(arch_rwlock_t *rw)
{
	native_ord_arch_read_locked_slow(rw);
}
static inline void
ord_arch_write_locked_slow(arch_rwlock_t *rw)
{
	native_ord_arch_write_locked_slow(rw);
}
static inline void
ord_arch_read_unlock_slow(arch_rwlock_t *rw)
{
	native_ord_arch_read_unlock_slow(rw);
}
static inline void
ord_arch_write_unlock_slow(arch_rwlock_t *rw)
{
	native_ord_arch_write_unlock_slow(rw);
}

#endif	/* CONFIG_PARAVIRT_GUEST || CONFIG_KVM_GUEST_KERNEL */

/*
 * would read_trylock() succeed?
 * @rw: the rwlock in question.
 */
static inline bool
ord_arch_read_can_lock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	bool success;

	rwlock.lock = __api_atomic_can_lock_reader(rw, success);

	DebugRW("source lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
	if (likely(success)) {
		DebugRW("lock can be taken\n");
	} else {
		DebugRW("lock can not be taken\n");
	}
	return success;
}

/*
 * would write_trylock() succeed?
 * @rw: the rwlock in question.
 */
static inline bool
ord_arch_write_can_lock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	bool success;

	rwlock.lock = __api_atomic_can_lock_writer(rw, success);

	DebugRW("source lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
	if (likely(success)) {
		DebugRW("lock can be taken\n");
	} else {
		DebugRW("lock can not be taken\n");
	}
	return success;
}

static inline void
ord_arch_read_lock_slow(arch_rwlock_t *rw, rwlock_val_t coupon)
{
	arch_rwlock_t rwcoupon;
	arch_rwlock_t rwlock;
	u16 ticket;
	bool success;

	rwcoupon.lock = coupon;
	ticket = rwcoupon.ticket;
	DebugSLRW("coupon value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwcoupon.lock, ticket, rwcoupon.head, rwcoupon.count);

	do {
		/* wait for waking up after some unlocking */
		ord_wait_read_lock_slow(rw);
		/* try lock again */
		rwlock.lock = __api_atomic_add_slow_reader(rw, ticket, success);
		DebugSLRW("current lock value 0x%lx: ticket 0x%x head 0x%x "
			"count %d\n",
			rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
		if (!likely(success)) {
			DebugSLRW("lock is not taken again\n");
		}
	} while (!success);
	DebugSLRW("lock is taken\n");
	if (rwlock.ticket != rwlock.head) {
		/* there are other waiters to take the lock */
		/* probably the next on queue is reader and it can */
		/* take lock too */
		DebugSLRW("ticket 0x%x head 0x%x there are other waiters "
			"to wake up\n",
			rwlock.ticket, rwlock.head);
	}
	if (rwlock.count < -1) {
		/* there is previous active reader and it wake up alredy */
		/* the folowing readers and does not wait for notification */
		/* from activated readers */
		DebugSLRW("count %d there is previous active reader, so do "
			"not wake once again, enter to critical immediately\n",
			rwlock.count);
		return;
	}
	ord_arch_read_locked_slow(rw);
	DebugSLRW("enter to critical section\n");
}

static inline void
ord_arch_read_lock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	bool success;

	rwlock.lock = __api_atomic_add_new_reader(rw, success);

	DebugRW("source lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
	if (likely(success)) {
		DebugRW("lock is taken\n");
		return;
	}
	DebugRW("lock is not taken, goto slow path\n");

	/* slow path to take read spinlock (as mutex) */
	ord_arch_read_lock_slow(rw, rwlock.lock);
}

static inline bool
ord_arch_read_trylock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	bool success;

	rwlock.lock = __api_atomic_try_add_new_reader(rw, success);

	DebugRW("source lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
	if (likely(success)) {
		DebugRW("lock is taken\n");
	} else {
		DebugRW("lock is not taken\n");
	}
	return success;
}

static inline void
ord_arch_read_unlock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	u16 ticket, head;
	int count;

	rwlock.lock = __api_atomic_free_lock_reader(rw);

	ticket = rwlock.ticket;
	head = rwlock.head;
	count = rwlock.count;
	DebugRW("current lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, ticket, head, count);
	if (count < 0) {
		DebugRW("there are other %d readers, do not wake up now\n",
			-count);
		return;
	} else if (count != 0) {
		pr_err("%s(): not zero readers lock counter %d\n",
			__func__, count);
		BUG_ON(true);
		return;
	}
	if (ticket == head) {
		DebugRW("there are not other waiters, nothing to wake up\n");
		return;
	}
	DebugSLRW("there are other waiters, wake up now\n");

	/* slow path to unlock read spinlock */
	/* need wake up other threads waiting for unlocking */
	ord_arch_read_unlock_slow(rw);
}

static inline void
ord_arch_write_lock_slow(arch_rwlock_t *rw, rwlock_val_t coupon)
{
	arch_rwlock_t rwcoupon;
	arch_rwlock_t rwlock;
	u16 ticket;
	bool success;

	rwcoupon.lock = coupon;
	ticket = rwcoupon.ticket;
	DebugSLRW("coupon value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwcoupon.lock, ticket, rwcoupon.head, rwcoupon.count);

	do {
		/* wait for waking up after some unlocking */
		ord_wait_write_lock_slow(rw);
		/* try lock again */
		rwlock.lock = __api_atomic_add_slow_writer(rw, ticket, success);
		DebugSLRW("current lock value 0x%lx: ticket 0x%x "
			"head 0x%x count %d\n",
			rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
		if (!likely(success)) {
			DebugSLRW("lock is not taken again\n");
		}
	} while (!success);
	DebugSLRW("lock is taken\n");
	if (rwlock.ticket != rwlock.head) {
		/* there are other waiters to take the lock */
		DebugSLRW("there are other waiters to wake up\n");
	}
	ord_arch_write_locked_slow(rw);
	DebugSLRW("enter to critical section\n");
}

static inline void
ord_arch_write_lock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	bool success;

	rwlock.lock = __api_atomic_add_new_writer(rw, success);

	DebugRW("source lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
	if (likely(success)) {
		DebugRW("lock is taken\n");
		return;
	}
	DebugRW("lock is not taken, goto slow path\n");

	/* slow path to take read spinlock (as mutex) */
	ord_arch_write_lock_slow(rw, rwlock.lock);
}

static inline bool
ord_arch_write_trylock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	bool success;

	rwlock.lock = __api_atomic_try_add_new_writer(rw, success);

	DebugRW("source lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, rwlock.ticket, rwlock.head, rwlock.count);
	if (likely(success)) {
		DebugRW("lock is taken\n");
	} else {
		DebugRW("lock is not taken\n");
	}
	return success;
}

static inline void
ord_arch_write_unlock(arch_rwlock_t *rw)
{
	arch_rwlock_t rwlock;
	u16 ticket, head;
	int count;

	rwlock.lock = __api_atomic_free_lock_writer(rw);

	ticket = rwlock.ticket;
	head = rwlock.head;
	count = rwlock.count;
	DebugRW("current lock value 0x%lx: ticket 0x%x head 0x%x count %d\n",
		rwlock.lock, ticket, head, count);
	if (count != 0) {
		pr_err("%s(): not zero writers counters %d\n",
			__func__, count);
		BUG_ON(true);
		return;
	}
	if (ticket == head) {
		DebugRW("ticket 0x%x head 0x%x there are not other waiters, "
			"nothing to wake up\n",
			ticket, head);
		return;
	}
	DebugSLRW("ticket 0x%x head 0x%x there are other waiters, "
		"wake up its now\n",
		ticket, head);

	/* slow path to unlock read spinlock */
	/* need wake up other threads waiting for unlocking */
	ord_arch_write_unlock_slow(rw);
}

#define	arch_read_can_lock(rw)	ord_arch_read_can_lock(rw)
#define	arch_write_can_lock(rw)	ord_arch_write_can_lock(rw)
#define	arch_read_lock(rw)	ord_arch_read_lock(rw)
#define	arch_write_lock(rw)	ord_arch_write_lock(rw)

#define	arch_read_unlock(rw)	ord_arch_read_unlock(rw)
#define	arch_write_unlock(rw)	ord_arch_write_unlock(rw)
#define	arch_read_trylock(rw)	ord_arch_read_trylock(rw)
#define	arch_write_trylock(rw)	ord_arch_write_trylock(rw)

#endif /* ! __ASSEMBLY__ */

#endif	/* ! __ASM_ORD_RWLOCK_H */
