#ifndef _EL_POSIX__H_
#define _EL_POSIX__H_

#include <linux/kref.h>
#include <linux/plist.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/hrtimer.h>

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
	ktime_t cb_timeout;       /* Callback timeout */
	ktime_t run_time;	  /* Moment of __run_hrtimer call */
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

#ifndef STANDALONE
#ifdef CONFIG_MCST
#ifdef CONFIG_E90
#define do_postpone_tick(a)	do {} while (0)
#else
extern void do_postpone_tick(int to_netxt_inrt_ns);
#endif
#endif
#endif

#endif /* _EL_POSIX__H_ */

