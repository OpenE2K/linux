#ifndef _ASM_E2K_ATOMIC_API_H_
#define _ASM_E2K_ATOMIC_API_H_

#include <linux/types.h>
#include <asm/e2k_api.h>
#include <asm/native_cpu_regs_access.h>
#include <asm/native_dcache_regs_access.h>

#ifdef	__KERNEL__

#ifndef	__ASSEMBLY__

/*
 * Special page that is accessible for reading by every user
 * process is used for hardware bug #89242 workaround.
 */
#define NATIVE_HWBUG_WRITE_MEMORY_BARRIER_ADDRESS 0xff6000000000UL

#if !defined(CONFIG_BOOT_E2K) && !defined(E2K_P2V)

# define NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS	\
		NATIVE_HWBUG_WRITE_MEMORY_BARRIER_ADDRESS
# define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS		\
		virt_cpu_has(CPU_HWBUG_WRITE_MEMORY_BARRIER)
# ifdef E2K_FAST_SYSCALL
#  define NATIVE_HWBUG_AFTER_LD_ACQ_CPU NATIVE_GET_DSREG_OPEN(clkr)
# else
#  ifndef __ASSEMBLY__
# include <asm/glob_regs.h>
register unsigned long long __cpu_preempt_reg DO_ASM_GET_GREG_MEMONIC(SMP_CPU_ID_GREG);
#  endif
#  define NATIVE_HWBUG_AFTER_LD_ACQ_CPU ((unsigned int) __cpu_preempt_reg)
# endif

#elif defined(E2K_P2V)

# define NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS	\
		(NATIVE_READ_IP_REG_VALUE() & ~0x3fUL)
# define NATIVE_HWBUG_AFTER_LD_ACQ_CPU 0
# if !defined(CONFIG_E2K_MACHINE) || defined(CONFIG_E2K_E8C)
#  define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS 1
# else
#  define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS 0
# endif

#else /* CONFIG_BOOT_E2K */

# define NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS	\
		(NATIVE_READ_IP_REG_VALUE() & ~0x3fUL)
# define NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS 0
# define NATIVE_HWBUG_AFTER_LD_ACQ_CPU 0

#endif

#if !defined CONFIG_E2K_MACHINE || defined CONFIG_E2K_E8C
/* Define these here to avoid include hell... */
# define _UPSR_IE      0x20U
# define _UPSR_NMIE    0x80U
# define NATIVE_HWBUG_AFTER_LD_ACQ() \
do { \
	unsigned long long __reg1, __reg2; \
	if (NATIVE_HAS_HWBUG_AFTER_LD_ACQ_ADDRESS) { \
		unsigned long __hwbug_cpu = NATIVE_HWBUG_AFTER_LD_ACQ_CPU; \
		unsigned long __hwbug_address = \
				NATIVE_HWBUG_AFTER_LD_ACQ_ADDRESS + \
				(__hwbug_cpu & 0x3) * 4096; \
		unsigned long __hwbug_atomic_flags; \
		__hwbug_atomic_flags = NATIVE_NV_READ_UPSR_REG_VALUE(); \
		NATIVE_SET_UPSR_IRQ_BARRIER( \
			__hwbug_atomic_flags & ~(_UPSR_IE | _UPSR_NMIE)); \
		NATIVE_CLEAN_LD_ACQ_ADDRESS(__reg1, __reg2, __hwbug_address); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 0 * 4096 + 0 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 0 * 4096 + 4 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 8 * 4096 + 1 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 8 * 4096 + 5 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 16 * 4096 + 2 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 16 * 4096 + 6 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 24 * 4096 + 3 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		NATIVE_WRITE_MAS_D(__hwbug_address + 24 * 4096 + 7 * 64, 0UL, \
				MAS_DCACHE_LINE_FLUSH); \
		__E2K_WAIT(_fl_c); \
		NATIVE_SET_UPSR_IRQ_BARRIER(__hwbug_atomic_flags); \
	} \
} while (0)
#else
# define NATIVE_HWBUG_AFTER_LD_ACQ()	do { } while (0)
#endif

/* FIXME: here will be paravirtualized only hardware bugs workaround macroses */
/* but in guest general case these bugs can be workarounded only on host and */
/* guest should call appropriate hypercalls to make all atomic */
/* sequence on host, because of they contain privileged actions */

#if	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/atomic_api.h>
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not virtualized based on pv_ops */
#include <asm/kvm/guest/atomic_api.h>
#else	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */
/* it is native kernel with or without virtualization support */

/* examine bare hardware bugs */
#define	virt_cpu_has(hwbug)		cpu_has(hwbug)

#define	VIRT_HWBUG_AFTER_LD_ACQ()	NATIVE_HWBUG_AFTER_LD_ACQ()
#endif	/* CONFIG_PARAVIRT_GUEST */

#define VIRT_HWBUG_AFTER_LD_ACQ_STRONG_MB	VIRT_HWBUG_AFTER_LD_ACQ
#define VIRT_HWBUG_AFTER_LD_ACQ_LOCK_MB		VIRT_HWBUG_AFTER_LD_ACQ
#define VIRT_HWBUG_AFTER_LD_ACQ_ACQUIRE_MB	VIRT_HWBUG_AFTER_LD_ACQ
#define VIRT_HWBUG_AFTER_LD_ACQ_RELEASE_MB()
#define VIRT_HWBUG_AFTER_LD_ACQ_RELAXED_MB()


#define virt_api_atomic32_add_if_not_negative(val, addr, mem_model) \
({ \
	register int rval; \
	NATIVE_ATOMIC32_ADD_IF_NOT_NEGATIVE(val, addr, rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define virt_api_atomic64_add_if_not_negative(val, addr, mem_model) \
({ \
	register long long rval; \
	NATIVE_ATOMIC64_ADD_IF_NOT_NEGATIVE(val, addr, rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

/* Atomically add to 16 low bits and return the new 32 bits value */
#define virt_api_atomic16_add_return32_lock(val, addr) \
({ \
	register int	rval, tmp;	\
	NATIVE_ATOMIC16_ADD_RETURN32_LOCK(val, addr, rval, tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

/* Atomically add two 32 bits values packed into one 64 bits value */
/* and return the new 64 bits value */
#define virt_api_atomic32_pair_add_return64_lock(val_lo, val_hi, addr) \
({ \
	register long	rval, tmp1, tmp2, tmp3; \
	NATIVE_ATOMIC32_PAIR_ADD_RETURN64_LOCK(val_lo, val_hi, addr, rval, \
						tmp1, tmp2, tmp3); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

/* Atomically sub two 32 bits values packed into one 64 bits value */
/* and return the new 64 bits value */
#define virt_api_atomic32_pair_sub_return64_lock(val_lo, val_hi, addr) \
({ \
	register long	rval, tmp1, tmp2, tmp3; \
	NATIVE_ATOMIC32_PAIR_SUB_RETURN64_LOCK(val_lo, val_hi, addr, rval, \
						tmp1, tmp2, tmp3); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic_ticket_trylock(spinlock, tail_shift) \
({ \
 	register int	__rval;	\
	register int	__val; \
	register int	__head; \
	register int	__tail; \
	NATIVE_ATOMIC_TICKET_TRYLOCK(spinlock, tail_shift, \
				__val, __head, __tail, __rval); \
	VIRT_HWBUG_AFTER_LD_ACQ_LOCK_MB(); \
	__rval; \
})

/*
 * Atomic support of new read/write spinlock mechanism.
 * Locking is ordered and later readers cannot outrun former writers.
 * Locking order based on coupons (tickets) received while first try to get
 * lock, if lock is already taken by other.
 *
 * read/write spinlocks initial state allowing 2^32 active readers and
 * only one active writer. But coupon discipline allows simultaniously
 * have only 2^16 registered users of the lock: active + waiters
 */

/*
 * It is test: is read/write lock can be now taken by reader
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - locking can be successful'
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_can_lock_reader(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = rw->lock;
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	return src_lock.lock;
}
 */
#define virt_api_atomic_can_lock_reader(__rw_addr, __success) \
({ \
	register unsigned int	__head; \
	register unsigned int	__ticket; \
	register int		__count; \
	register unsigned long	__src; \
 \
	NATIVE_ATOMIC_CAN_LOCK_READER(__rw_addr, __success, \
				__head, __ticket, __count, __src); \
	__src; \
})

/*
 * It is test: is read/write lock can be now taken by writer
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - locking can be successful'
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_can_lock_writer(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = rw->lock;
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	return src_lock.lock;
}
 */
#define virt_api_atomic_can_lock_writer(__rw_addr, __success) \
({ \
	register unsigned int	__head; \
	register unsigned int	__ticket; \
	register int		__count; \
	register unsigned long	__src; \
 \
	NATIVE_ATOMIC_CAN_LOCK_WRITER(__rw_addr, __success, \
				__head, __ticket, __count, __src); \
	__src; \
})

/*
 * The first try to take read spinlock.
 * Successful locking increment # of ticket and head, decrement active
 * readers counter (negative counter)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise reader receives coupon and
 * should be queued as waiter similar mutex implementation
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_new_reader(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	dst_lock.ticket = ticket + 1;
	if (success) {
		// take lock: increment readers (negative value),
		// increment head to enable follow readers
		count = count - 1;
		head = head + 1;
	}
	dst_lock.count = count;
	dst_lock.head = head;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define virt_api_atomic_add_new_reader(__rw_addr, __success) \
({ \
	register unsigned int	__head; \
	register unsigned int	__ticket; \
	register int		__count; \
	register unsigned long	__tmp; \
	register unsigned long	__src; \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_ADD_NEW_READER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__src; \
})

/*
 * Only try to take read spinlock.
 * Successful locking increment # of ticket and head, decrement active
 * readers counter (negative counter)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise 'success' is false and
 * nothing are not changed
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_try_add_new_reader(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	if (success) {
		// take lock: increment readers (negative value),
		// increment head to enable follow readers
		// increment ticket number for next users
		dst_lock.ticket = ticket + 1;
		dst_lock.count = count - 1;
		dst_lock.head = head + 1;
	} else {
		dst_lock.lock = src_lock.lock;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define virt_api_atomic_try_add_new_reader(__rw_addr, __success) \
({ \
	register unsigned int	__head; \
	register unsigned int	__ticket; \
	register int		__count; \
	register unsigned long	__tmp; \
	register unsigned long	__src; \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_TRY_ADD_NEW_READER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__src; \
})

/*
 * The slow try to take read spinlock according to erlier received # of coupon
 * Successful locking increment # of head, decrement active readers counter
 * (negative counter)
 * Macros return current updated state of read/write lock and set bypassed
 * boolean value 'success - lockin is successful', otherwise reader should be
 * queued again
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_slow_reader(arch_rwlock_t *rw, u16 ticket, bool success)
{
	arch_rwlock_t dst_lock;
	u16 head;
	s32 count;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active writers
	success = (ticket == head) && (count-1 < 0);
	if (success) {
		// take lock: increment readers (negative value),
		// increment head to enable follow readers
		count = count - 1;
		head = head + 1;
		dst_lock.count = count;
		dst_lock.head = head;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define virt_api_atomic_add_slow_reader(__rw_addr, __ticket, __success) \
({ \
	register unsigned int	__head; \
	register int		__count; \
	register unsigned long	__tmp; \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_ADD_SLOW_READER(__rw_addr, __success, \
			__head, __ticket, __count, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__dst; \
})

/*
 * Unlocking of read spinlock.
 * Need only increment active readers counter (negative counter)
 * Macros return current updated state of read/write lock.
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_free_lock_reader(arch_rwlock_t *rw)
{
	arch_rwlock_t dst_lock;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	dst_lock.count++;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define virt_api_atomic_free_lock_reader(__rw_addr) \
({ \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_FREE_LOCK_READER(__rw_addr, __dst); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__dst; \
})

/*
 * The first try to take write spinlock.
 * Successful locking increment # of ticket and active writers counter
 * (positive value - can be only one active writer, so set counter to 1)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise writer receives coupon and
 * should be queued as waiter similar mutex implementation
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_new_writer(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	dst_lock.head = head;
	dst_lock.ticket = ticket + 1;
	if (success) {
		// take lock: increment writerss,
		count = count + 1;
	}
	dst_lock.count = count;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define virt_api_atomic_add_new_writer(__rw_addr, __success) \
({ \
	register unsigned int	__head; \
	register unsigned int	__ticket; \
	register int		__count; \
	register unsigned long	__tmp; \
	register unsigned long	__src; \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_ADD_NEW_WRITER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__src; \
})

/*
 * Only try to take write spinlock.
 * Successful locking increment # of ticket and active writers counter
 * (positive value - can be only one active writer, so set counter to 1)
 * Macros return source state of read/write lock and set bypassed boolean value
 * 'success - lockin is successful', otherwise 'success' is set to false and
 * nothing are not changed
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_try_add_new_writer(arch_rwlock_t *rw, bool success // bypassed)
{
	arch_rwlock_t src_lock;
	arch_rwlock_t dst_lock;
	u16 ticket;
	u16 head;
	s32 count;

	src_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	ticket = src_lock.ticket;
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	if (success) {
		// take lock: increment writers counter,
		// increment ticket number for next readers/writers
		dst_lock.head = head;
		dst_lock.ticket = ticket + 1;
		dst_lock.count = count + 1;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return src_lock.lock;
}
 */
#define virt_api_atomic_try_add_new_writer(__rw_addr, __success) \
({ \
	register unsigned int	__head; \
	register unsigned int	__ticket; \
	register int		__count; \
	register unsigned long	__tmp; \
	register unsigned long	__src; \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_TRY_ADD_NEW_WRITER(__rw_addr, __success, \
			__head, __ticket, __count, __src, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__src; \
})

/*
 * The slow try to take write spinlock according to erlier received # of coupon
 * Successful locking increment active writers counter
 * (positive counter - can be only one active writer, so set counter to 1)
 * Macros return current updated state of read/write lock and set bypassed
 * boolean value 'success - lockin is successful', otherwise writer should be
 * queued again
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_add_slow_writer(arch_rwlock_t *rw, u16 ticket, bool success)
{
	arch_rwlock_t dst_lock;
	u16 head;
	s32 count;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	head = src_lock.head;
	count = src_lock.count;
	// can lock: none waiters and active readers and writers
	success = (ticket == head) && (count == 0);
	if (success) {
		// take lock: increment writers,
		count = count + 1;
		dst_lock.count = count;
	}
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define virt_api_atomic_add_slow_writer(__rw_addr, __ticket, __success) \
({ \
	register unsigned int	__head; \
	register int		__count; \
	register unsigned long	__tmp; \
	register unsigned long	__dst; \
 \
	NATIVE_ATOMIC_ADD_SLOW_WRITER(__rw_addr, __success, \
			__head, __ticket, __count, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__dst; \
})

/*
 * Unlocking of write spinlock.
 * Need only increment # of queue head and decrement active writers counter
 * (positive counter - can be only one writer, so set counter to 0)
 * Macros return current updated state of read/write lock.
 *
 * C equivalent:
 *
static rwlock_val_t
atomic_free_lock_writer(arch_rwlock_t *rw)
{
	arch_rwlock_t dst_lock;

	dst_lock.lock = E2K_ATOMIC_LBRACKET_D(rw, MAS_WAIT_LOCK, 0);
	dst_lock.count++;
	dst_lock.head++;
	E2K_ATOMIC_RBRACKET_D(rw, dst_lock.lock, MAS_WAIT_UNLOCK, 0);
	return dst_lock.lock;
}
 */
#define virt_api_atomic_free_lock_writer(__rw_addr) \
({ \
	register unsigned long	__dst; \
	register unsigned int	__head; \
	register int		__count; \
	register unsigned long	__tmp; \
 \
	NATIVE_ATOMIC_FREE_LOCK_WRITER(__rw_addr, \
			__head, __count, __dst, __tmp); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	__dst; \
})

#define virt_api_atomic_op(val, addr, size_letter, op, mem_model) \
({ \
	typeof(val) rval; \
	NATIVE_ATOMIC_OP(val, addr, rval, size_letter, op, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define virt_api_atomic_fetch_op(val, addr, size_letter, op, mem_model) \
({ \
	typeof(val) rval, stored_val; \
	NATIVE_ATOMIC_FETCH_OP(val, addr, rval, stored_val, \
			       size_letter, op, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})


/*
 * Atomic operations with return value and acquire/release semantics
 */

#define virt_api_atomic32_fetch_inc_unless_negative(addr) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1, addr, 0, tmp, rval, \
			w, "adds", "~ ", "adds", "", "cmplsb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic64_fetch_inc_unless_negative(addr) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1ull, addr, 0ull, tmp, rval, \
			d, "addd", "~ ", "addd", "", "cmpldb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic32_fetch_dec_unless_positive(addr) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1, addr, 0, tmp, rval, \
			w, "subs", "", "adds", "~ ", "cmplesb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic64_fetch_dec_unless_positive(addr) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1ull, addr, 0ull, tmp, rval, \
			d, "subd", "", "addd", "~ ", "cmpledb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic32_fetch_dec_if_positive(addr) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1, addr, 0, tmp, rval, \
			w, "subs", "~ ", "adds", "", "cmplesb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic64_fetch_dec_if_positive(addr) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(1ull, addr, 0ull, tmp, rval, \
			d, "subd", "~ ", "addd", "", "cmpledb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic32_fetch_add_unless(val, addr, unless) \
({ \
	register int rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(val, addr, unless, tmp, rval, \
			w, "adds", "~ ", "adds", "", "cmpesb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define virt_api_atomic64_fetch_add_unless(val, addr, unless) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_OP_UNLESS(val, addr, unless, tmp, rval, \
			d, "addd", "~ ", "addd", "", "cmpedb", STRONG_MB); \
	VIRT_HWBUG_AFTER_LD_ACQ(); \
	rval; \
})

#define __api_atomic64_fetch_xchg_if_below(val, addr, mem_model) \
({ \
	register long long rval, tmp; \
	NATIVE_ATOMIC_FETCH_XCHG_UNLESS(val, addr, tmp, rval, d, \
			"merged", "cmpbdb", mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define virt_api_xchg_return(val, addr, size_letter, mem_model) \
({ \
 	register long	rval;	\
	NATIVE_ATOMIC_XCHG_RETURN(val, addr, rval, size_letter, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define virt_api_cmpxchg_return(old, new, addr, size_letter, \
				sxt_size, mem_model) \
({ \
 	register long	rval;	\
	register long	stored_val; \
	NATIVE_ATOMIC_CMPXCHG_RETURN(old, new, addr, stored_val, rval, \
					size_letter, sxt_size, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define virt_api_cmpxchg_word_return(old, new, addr, mem_model) \
({ \
	int rval, stored_val; \
	NATIVE_ATOMIC_CMPXCHG_WORD_RETURN(old, new, addr, \
					  stored_val, rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define virt_api_cmpxchg_dword_return(old, new, addr, mem_model) \
({ \
	long long rval, stored_val; \
	NATIVE_ATOMIC_CMPXCHG_DWORD_RETURN(old, new, addr, stored_val, \
					   rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

/*
 * implementation of cmpxchg_double for 64-bit pairs
 * and activates the logic required for the SLUB
 *
 * C equivalent:
 *
static int
atomic_cmpxchg_double(struct page page, void *freelist_old,
			unsigned long counters_old,
			void *freelist_new, unsigned long counters_new)
{
		unsigned long flags;

		local_irq_save(flags);
		slab_lock(page);
		if (page->freelist == freelist_old &&
					page->counters == counters_old) {
			page->freelist = freelist_new;
			set_page_slub_counters(page, counters_new);
			slab_unlock(page);
			local_irq_restore(flags);
			return true;
		}
		slab_unlock(page);
		local_irq_restore(flags);
		return false;
}
 */

#define virt_api_cmpxchg_double(addr1, addr2, old1, old2, new1, new2, \
							mem_model) \
({ \
	register long	rval;	\
	NATIVE_ATOMIC_CMPXCHG_DWORD_PAIRS(addr1, old1, old2, new1, new2,\
				   rval, mem_model); \
	VIRT_HWBUG_AFTER_LD_ACQ_##mem_model(); \
	rval; \
})

#define __api_cmpxchg_double(addr1, addr2, old1, old2, new1, new2) \
		virt_api_cmpxchg_double(addr1, addr2, old1, old2, \
				       new1, new2, STRONG_MB)

#define __api_futex_atomic32_op(insn, oparg, uaddr) \
		virt_api_atomic_fetch_op(oparg, uaddr, w, insn, STRONG_MB)

#define __api_atomic32_add_if_not_negative \
		virt_api_atomic32_add_if_not_negative

#define __api_atomic64_add_if_not_negative \
		virt_api_atomic64_add_if_not_negative

/* Atomically add and return the old value */
#define __api_atomic32_add_oldval(val, addr) \
		virt_api_atomic_fetch_op(val, addr, w, "adds", STRONG_MB)

#define __api_atomic32_add_oldval_lock(val, addr) \
		virt_api_atomic_fetch_op(val, addr, w, "adds", LOCK_MB)

/* Atomically add to 16 low bits and return the new 32 bits value */
#define __api_atomic16_add_return32_lock(val, addr) \
		virt_api_atomic16_add_return32_lock(val, addr)

/* Atomically add two 32 bits values packed into one 64 bits value */
/* and return the new 64 bits value */
#define __api_atomic32_pair_add_return64_lock(val_lo, val_hi, addr) \
		virt_api_atomic32_pair_add_return64_lock(val_lo, val_hi, addr)

/* Atomically sub two 32 bits values packed into one 64 bits value */
/* and return the new 64 bits value */
#define __api_atomic32_pair_sub_return64_lock(val_lo, val_hi, addr) \
		virt_api_atomic32_pair_sub_return64_lock(val_lo, val_hi, addr)

#define __api_atomic_ticket_trylock(spinlock, tail_shift) \
		virt_api_atomic_ticket_trylock(spinlock, tail_shift)
#define __api_atomic_can_lock_reader(__rw_addr, __success) \
		virt_api_atomic_can_lock_reader(__rw_addr, __success)
#define __api_atomic_can_lock_writer(__rw_addr, __success) \
		virt_api_atomic_can_lock_writer(__rw_addr, __success)
#define __api_atomic_add_new_reader(__rw_addr, __success) \
		virt_api_atomic_add_new_reader(__rw_addr, __success)
#define __api_atomic_try_add_new_reader(__rw_addr, __success) \
		virt_api_atomic_try_add_new_reader(__rw_addr, __success)
#define __api_atomic_add_slow_reader(__rw_addr, __ticket, __success) \
		virt_api_atomic_add_slow_reader(__rw_addr, __ticket, __success)
#define __api_atomic_free_lock_reader(__rw_addr) \
		virt_api_atomic_free_lock_reader(__rw_addr)
#define __api_atomic_add_new_writer(__rw_addr, __success) \
		virt_api_atomic_add_new_writer(__rw_addr, __success)
#define __api_atomic_try_add_new_writer(__rw_addr, __success) \
		virt_api_atomic_try_add_new_writer(__rw_addr, __success)
#define __api_atomic_add_slow_writer(__rw_addr, __ticket, __success) \
		virt_api_atomic_add_slow_writer(__rw_addr, __ticket, \
							__success)
#define __api_atomic_free_lock_writer(__rw_addr) \
		virt_api_atomic_free_lock_writer(__rw_addr)

#define __api_atomic_op virt_api_atomic_op
#define __api_atomic_fetch_op virt_api_atomic_fetch_op

/*
 * Atomic operations with return value and acquire/release semantics
 */
#define __api_atomic32_fetch_add_unless(val, addr, unless) \
		virt_api_atomic32_fetch_add_unless(val, addr, unless)
#define __api_atomic64_fetch_add_unless(val, addr, unless) \
		virt_api_atomic64_fetch_add_unless(val, addr, unless)

#define __api_atomic32_fetch_dec_if_positive	 virt_api_atomic32_fetch_dec_if_positive
#define __api_atomic64_fetch_dec_if_positive	 virt_api_atomic64_fetch_dec_if_positive
#define __api_atomic32_fetch_dec_unless_positive virt_api_atomic32_fetch_dec_unless_positive
#define __api_atomic64_fetch_dec_unless_positive virt_api_atomic64_fetch_dec_unless_positive
#define __api_atomic32_fetch_inc_unless_negative virt_api_atomic32_fetch_inc_unless_negative
#define __api_atomic64_fetch_inc_unless_negative virt_api_atomic64_fetch_inc_unless_negative

#define __api_xchg_return virt_api_xchg_return

#define __api_cmpxchg_return virt_api_cmpxchg_return

#define __api_cmpxchg_word_return virt_api_cmpxchg_word_return

#define __api_cmpxchg_dword_return virt_api_cmpxchg_dword_return

#endif /* ! __ASSEMBLY__ */

#endif /* __KERNEL__ */

#endif /* _ASM_E2K_ATOMIC_API_H_ */
