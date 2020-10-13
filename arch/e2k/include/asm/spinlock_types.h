#ifndef __ASM_SPINLOCK_TYPES_H
#define __ASM_SPINLOCK_TYPES_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

#include <linux/types.h>

#define ARCH_SPINLOCK_TAIL_SHIFT 16
typedef union {
	u32 lock;
	struct {
		u16 head;
		u16 tail;
	};
} arch_spinlock_t;

#define __ARCH_SPIN_LOCK_UNLOCKED	{ .lock = 0 }

typedef struct {
	volatile u32 lock;
} arch_rwlock_t;

#define	RW_LOCK_BIAS			0x01000000

#define __ARCH_RW_LOCK_UNLOCKED		{ RW_LOCK_BIAS }

#endif
