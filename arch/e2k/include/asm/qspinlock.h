#ifndef _ASM_E2K_QSPINLOCK_H
#define _ASM_E2K_QSPINLOCK_H

#include <asm-generic/qspinlock_types.h>
#include <asm/p2v/boot_v2p.h>

/*
 * Ideally, the spinning time should be at least a few times
 * the typical cacheline load time from memory (~100 cycles on e2k),
 * and atomic_cond_read_relaxed() iteration takes ~20 cycles.
 */
#define _Q_PENDING_LOOPS	(1 << 5)

#ifndef CONFIG_PARAVIRT_SPINLOCKS

# define queued_spin_unlock queued_spin_unlock
/**
 * queued_spin_unlock - release a queued spinlock
 * @lock : Pointer to queued spinlock structure
 *
 * A store_release() on the least-significant byte that also
 * acts as a hardware memory barrier on device writes (in place
 * of dropped mmiowb()).
 */
static inline void queued_spin_unlock(struct qspinlock *lock)
{
	store_release(&lock->locked, 0);
}

#else

#include <asm/kvm/hypercall.h>
#include <asm/machdep.h>

#include <asm/param.h>
#include <asm/cpu_regs.h>

static __always_inline void pv_wait(u8 *ptr, u8 val)
{
	if (IS_HV_GM() && READ_ONCE(*ptr) == val)
		HYPERVISOR_pv_wait();
}


static __always_inline void pv_kick(int cpu)
{
	if (IS_HV_GM())
		HYPERVISOR_pv_kick(cpu);
}

extern void __pv_init_lock_hash(void);

/**
 * queued_spin_unlock - release a queued spinlock
 * @lock : Pointer to queued spinlock structure
 *
 * A store_release() on the least-significant byte that also
 * acts as a hardware memory barrier on device writes (in place
 * of dropped mmiowb()).
 */
static inline void native_queued_spin_unlock(struct qspinlock *lock)
{
	store_release(&lock->locked, 0);
}

extern void __pv_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
extern void native_queued_spin_lock_slowpath(struct qspinlock *lock, u32 val);
static inline void queued_spin_lock_slowpath(struct qspinlock *lock, u32 val)
{
	if (IS_HV_GM())
		__pv_queued_spin_lock_slowpath(lock, val);
	else
		native_queued_spin_lock_slowpath(lock, val);
}

extern void __pv_queued_spin_unlock(struct qspinlock *lock);

# define queued_spin_unlock queued_spin_unlock
static inline void queued_spin_unlock(struct qspinlock *lock)
{
	if (IS_HV_GM())
		__pv_queued_spin_unlock(lock);
	else
		native_queued_spin_unlock(lock);
}

#endif /* !CONFIG_PARAVIRT_SPINLOCKS */

#include <asm-generic/qspinlock.h>

#endif /* _ASM_E2K_QSPINLOCK_H */
