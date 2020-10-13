#ifndef _EL_POSIX__H_
#define _EL_POSIX__H_

#include <linux/mcst_rt.h>
#ifdef __KERNEL__
#include <linux/kref.h>
#include <linux/plist.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>
#else
#include <limits.h>
#include <pthread.h>
#endif

/* Modes for posix work */
#define WAKEUP_MUTEX_ONE  1  // only one thread from mutex queue else all

/*
 * Requests for posix (see sys_el_posix);
 */

#define PTHREAD_MAIN_INIT	1 + PTHREAD_INTRF_START
#define PTHREAD_MUTEX_INIT	2  + PTHREAD_INTRF_START
#define PTHREAD_COND_INIT	3  + PTHREAD_INTRF_START
#define PTHREAD_MUTEX_LOCK	4  + PTHREAD_INTRF_START
#define PTHREAD_MUTEX_UNLOCK	5  + PTHREAD_INTRF_START
#define PTHREAD_COND_WAIT	6  + PTHREAD_INTRF_START
#define PTHREAD_COND_TIMEDWAIT	7  + PTHREAD_INTRF_START
#define PTHREAD_COND_BROADCAST	8  + PTHREAD_INTRF_START
#define PTHREAD_COND_SIGNAL	9  + PTHREAD_INTRF_START
#define EL_PTHREAD_WAIT		10 + PTHREAD_INTRF_START
#define EL_WAKEUP_PTHREAD_COND	11 + PTHREAD_INTRF_START
#define EL_PCOND_UNLOCK_WAIT	12 + PTHREAD_INTRF_START
#define PTHREAD_SET_KERNEL_IMPL 13 + PTHREAD_INTRF_START

#define POSIX_MAIN_INIT		20 + PTHREAD_INTRF_START
#define POSIX_OBJECT_INIT_FINI	21 + PTHREAD_INTRF_START
#define POSIX_SEM_POST		22 + PTHREAD_INTRF_START
#define POSIX_SEM_TIMEDWAIT	23 + PTHREAD_INTRF_START
#define POSIX_MUTEX_TIMEDLOCK	24 + PTHREAD_INTRF_START
#define POSIX_MUTEX_UNLOCK	25 + PTHREAD_INTRF_START
#define POSIX_COND_TIMEDWAIT	26 + PTHREAD_INTRF_START
#define POSIX_COND_WAKE		27 + PTHREAD_INTRF_START
#define POSIX_BARRIER_WAIT	28 + PTHREAD_INTRF_START
#define POSIX_CANCEL		29 + PTHREAD_INTRF_START
#define POSIX_COLLECT_SHARED	30 + PTHREAD_INTRF_START
#define POSIX_SEM_GET_VALUE	31 + PTHREAD_INTRF_START
#define POSIX_MUTEX_SET_CEILING	32 + PTHREAD_INTRF_START
#define POSIX_MUTEX_CONSISTENT	33 + PTHREAD_INTRF_START
#define POSIX_SET_PARAMETER	34 + PTHREAD_INTRF_START
#define POSIX_GET_PRIO_PROTECT	35 + PTHREAD_INTRF_START

/* Options for POSIX_SET_PARAMETER */
#define POSIX_UNSAFE_SHARED	1

/* Flags in mutex attr.  */
#define PTHREAD_MUTEXATTR_PROTOCOL_SHIFT	28
#define PTHREAD_MUTEXATTR_PROTOCOL_MASK		0x30000000
#define PTHREAD_MUTEXATTR_PRIO_CEILING_SHIFT	12
#define PTHREAD_MUTEXATTR_PRIO_CEILING_MASK	0x00fff000
#define PTHREAD_MUTEXATTR_FLAG_INITIALIZED	0x01000000
#define PTHREAD_MUTEXATTR_FLAG_ROBUST		0x40000000
#define PTHREAD_MUTEXATTR_FLAG_PSHARED		0x80000000
#define PTHREAD_MUTEXATTR_FLAG_BITS \
		(PTHREAD_MUTEXATTR_FLAG_INITIALIZED \
		| PTHREAD_MUTEXATTR_FLAG_PSHARED \
		| PTHREAD_MUTEXATTR_FLAG_ROBUST \
		| PTHREAD_MUTEXATTR_PROTOCOL_MASK \
		| PTHREAD_MUTEXATTR_PRIO_CEILING_MASK)

/* Flags in cond attr */
#define PTHREAD_CONDATTR_CLOCK_ID_SHIFT		0
#define PTHREAD_CONDATTR_CLOCK_ID_MASK		0x00000003
#define PTHREAD_CONDATTR_FLAG_INITIALIZED	0x00000004
#define PTHREAD_CONDATTR_FLAG_PSHARED		0x00000008

/* Four kinds of descriptors. */
enum types {
	MUTEX = 1,
	CONDITION,
	BARRIER,
	SEMAPHORE,
#ifdef __KERNEL__
	/* Since condition variables, barriers and semaphores
	 * share the same pool they have special designator "OTHER". */
	OTHER,
#endif
};

struct pthread_mutex_s {
	int __m_lock;
	int __m_desc;
	int __m_owner;
	/* KIND must stay at this position in the structure
	 * to maintain binary compatibility. */
#ifdef __KERNEL__
	int __m_kind;
	unsigned int __m_spins;
#else
# ifndef __WORDSIZE
#  define __WORDSIZE 64
# endif
# if  __WORDSIZE == 64
	unsigned int __m_spins;
	int __m_kind;
# else
	int __m_kind;
	unsigned int __m_spins;
# endif
#endif
	unsigned int __m_count;
};

struct pthread_cond_s {
#ifdef __KERNEL__
	union {
		struct pthread_mutex_s *__c_mutex;
		u64 __pad;
	};
#else
	unsigned long long __c_mutex;
#endif
	int __c_desc;
	int __c_value;
};

struct pthread_barrier_s {
	int __b_desc;
	unsigned int __b_required;
};

struct posix_sem_s {
	int __s_value;
	int __s_waiters;
	int __s_desc;
};

#ifdef __KERNEL__
struct barr_desc;
/* This structure is used for waiting on barriers */
struct el_barrier_waiter {
	int state;
	struct plist_node list_entry;
	struct task_struct *task;
	/* Points to descriptor if task is waiting on a barrier */
	struct barr_desc *b_desc;
};

struct allocated_private_mutex_descs;
struct allocated_private_other_descs;
struct el_waiter;
struct el_posix_data {
	struct list_head pi_mutex_list;
	struct el_waiter *pi_blocked_on;
	struct plist_head pi_waiters;
	/* Used solely by PTHREAD_PRIO_PROTECT mutexes to boost priority. */
	struct plist_node pi_list_entry;
	struct el_barrier_waiter barr_waiter;
	struct plist_head pp_mutex_list;
};

struct task_struct;

struct el_wait_queue_head {
	ktime_t wuc_time; /* Moment of call of wake up function */
	struct task_struct *task;
	struct list_head task_list;
};

struct el_timerfd_ctx {
	raw_spinlock_t lock;
	int locked;		/* To combine raw_spinlock with irqsafe flag.
				 * It protects all excluding queue and ticks;
				 * for manipulating with them lock is enough */
	struct el_wait_queue_head wqh;	/* Protected by "->lock" */
	ktime_t tintv;
	struct hrtimer tmr;
	u64 ticks, handled_ticks; /* all and handled by user */
	ktime_t run_time;	  /* Moment of __run_hrtimer call */
        ktime_t cb_timeout;       /* Callback timeout */
	ktime_t expiried;         /* When the timer has expiried */
};

struct mm_struct;
struct user_struct;
struct inode;

extern int el_posix_getprio(struct task_struct *, const int);
extern void el_posix_adjust_pi(struct task_struct *);
extern void el_posix_init(struct task_struct *);
extern void el_posix_lock(unsigned long);
extern void el_posix_unlock(unsigned long);
extern void el_posix_switch_user(struct user_struct *, struct user_struct *);
extern int dup_mm_el_posix(struct mm_struct *, struct mm_struct *,
		unsigned long);
extern void exit_el_posix(struct task_struct *);
extern void el_posix_inode_free(struct inode *);
extern void el_posix_mm_destroy(struct mm_struct *);

#ifdef CONFIG_HAVE_EL_POSIX_SYSCALL
# define INIT_EL_POSIX(tsk) \
	.el_posix = { \
		.pi_mutex_list = LIST_HEAD_INIT(tsk.el_posix.pi_mutex_list), \
		.pp_mutex_list = PLIST_HEAD_INIT(tsk.el_posix.pp_mutex_list), \
		.pi_list_entry = PLIST_NODE_INIT(tsk.el_posix.pi_list_entry, \
						 MAX_PRIO-1), \
		.pi_waiters    = PLIST_HEAD_INIT(tsk.el_posix.pi_waiters), \
	},
#else
# define INIT_EL_POSIX(tsk)
#endif


#else /* ifdef __KERNEL__ */

/* additional sig to posix restart
 * It is asm-e2k.h depended
 */
#define SIGPRESTART 33

int posix_init(void);
int pthread_wakeup(pthread_cond_t *cond, pthread_t pthr);
int pthread_wait(pthread_cond_t *cond);
int pthread_unlock_wait(pthread_cond_t *cond, pthread_mutex_t *mutex);

#endif /* ifdef __KERNEL__ */

#ifndef STANDALONE
#ifdef CONFIG_MCST_RT
#ifdef CONFIG_E90
#define do_postpone_tick(a)	do {} while (0)
#else
extern void do_postpone_tick(int to_netxt_inrt_ns);
#endif
#endif
#endif

#endif /* _EL_POSIX__H_ */

