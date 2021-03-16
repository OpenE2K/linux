#ifndef __ASM_ORD_RWLOCK_TYPES_H
#define __ASM_ORD_RWLOCK_TYPES_H

#ifndef __LINUX_SPINLOCK_TYPES_H
# error "please don't include this file directly"
#endif

#include <linux/types.h>

typedef unsigned long	rwlock_val_t;
typedef struct {
	union {
		rwlock_val_t	lock;	/* as a single whole atomic value */
		struct {		/* fields of lock value; */
					/* all or each of fields should be */
					/* updated only in atomic style: */
			u16 head;	/* current # of active user of lock */
			u16 ticket;	/* last # of potential (active or */
					/* waiting) user of the lock */
			s32 count;	/* current counter of active users */
					/* readers is negative value and can */
					/* be from 0, -1, -2, ... max */
					/* negative value */
					/* writers can be only 0 or 1 */
		};
	};
} arch_rwlock_t;
#define __ARCH_RW_LOCK_UNLOCKED		{			\
	{							\
		.lock = 0					\
	}							\
}

#endif	/* __ASM_ORD_RWLOCK_TYPES_H */
