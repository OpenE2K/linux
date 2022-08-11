#ifndef _ASM_E2K_SPINLOCK_H
#define _ASM_E2K_SPINLOCK_H

/* How long a lock should spin before we consider blocking */
#define SPIN_THRESHOLD	(1 << 11)

#include <asm/qspinlock.h>

/*
 * Read-write spinlocks, allowing multiple readers
 * but only one writer.
 *
 * NOTE! it is quite common to have readers in interrupts
 * but no interrupt writers. For those circumstances we
 * can "mix" irq-safe locks - any writer needs to get a
 * irq-safe write-lock, but readers can get non-irqsafe
 * read-locks.
 */

#include <asm/qrwlock.h>

#endif        /* _ASM_E2K_SPINLOCK_H */
