#pragma once

#include <linux/types.h>

#define BOOT_SPINLOCK_HEAD_SHIFT 0
#define BOOT_SPINLOCK_TAIL_SHIFT 16
typedef union {
	u32 lock;
	struct {
		u16 head;
		u16 tail;
	};
} boot_spinlock_t;

#define __BOOT_SPIN_LOCK_UNLOCKED (boot_spinlock_t) { .lock = 0 }
